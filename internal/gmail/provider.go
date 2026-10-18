// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The Gmail provider (DS7.4). Provider holds the account, the REST
// client, the label cache and the wall clock. State holds the caches
// that the Factory keeps for each account, so that two sessions share
// them (G6). Folders gives the labels that are folders, with a role
// and the counts. Modify and ModifyDetail change messages through their
// labels (DS7.4, DS78.5), and Caps gives the report of DS78.4.

package gmail

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// labelFanout is the number of labels.get calls that run at the same
// time. One call after the other went past the client timeout (E2).
const labelFanout = 10

// The bounds of Search and Thread (DS7.4).
const (
	// messageFanout is the number of messages.get calls of one search
	// page that run at the same time (DS7.4).
	messageFanout = 10
	// defaultLimit and maxLimit bound one search page, as on IMAP.
	defaultLimit = 20
	maxLimit     = 100
	// maxThread is how many messages one conversation gives back, the
	// newest ones, as on IMAP.
	maxThread = 50
)

// metadataHeaders are the headers that a search row needs (DS7.4).
var metadataHeaders = []string{"From", "To", "Cc", "Subject", "Date", "Message-ID"}

// State holds the caches of one Gmail account that live longer than
// one Provider: the labels of DS7.4 and the send-as addresses of DS7.5.
// The Factory keeps one State for each alias and gives it to each new
// Provider, so two sessions share the caches (G6). The zero value is
// empty and ready to use.
type State struct {
	labels labelCache
	sendAs sendAsCache
}

// Provider reads and changes the mail of one Gmail account through the
// Gmail REST API (DS7.4). It is made for each call, as the IMAP
// provider is; the caches live in the State of the account.
type Provider struct {
	alias  string
	acct   config.Account
	api    *API
	labels *labelCache      // name to id, id to name; labelTTL (DS7.4)
	sendAs *sendAsCache     // verified send-as addresses; sendAsTTL (DS7.5)
	now    func() time.Time // wall time only
}

// NewProvider gives the provider of the Gmail account alias. It calls
// the API through api and keeps its caches in st (G6). A nil st gives
// the provider caches of its own.
func NewProvider(alias string, acct config.Account, api *API, st *State) *Provider {
	if st == nil {
		st = &State{}
	}
	return &Provider{
		alias:  alias,
		acct:   acct,
		api:    api,
		labels: &st.labels,
		sendAs: &st.sendAs,
		now:    wallNow,
	}
}

// wallNow is time.Now without the monotonic reading. On Linux the
// monotonic clock stops during suspend; the wall clock counts the
// sleep, so a cache does not stay fresh over a night (as imap.wallNow).
func wallNow() time.Time { return time.Now().Round(0) }

// Folders gives the labels that are folders, in the order of
// labels.list (DS7.4). STARRED, UNREAD, IMPORTANT, CHAT and the
// CATEGORY_* labels are marks and not folders. INBOX, SENT, DRAFT,
// TRASH and SPAM have a role (inbox, sent, drafts, trash, junk); a user
// label has none. labels.list gives no counts, so Folders calls
// labels.get for each folder, labelFanout calls at a time (E2). The
// first call that fails stops the others and fails Folders, as a
// failed STATUS does on IMAP. The labels.list answer goes into the
// label cache.
//
// arch: DS7.4, E2, E5
func (p *Provider) Folders(ctx context.Context) ([]mail.Folder, error) {
	tab, err := p.listLabels(ctx)
	if err != nil {
		return nil, err
	}
	var out []mail.Folder
	var ids []string
	for _, l := range tab.list {
		if notFolder(l.ID) {
			continue
		}
		out = append(out, mail.Folder{Name: l.Name, Role: roles[l.ID]})
		ids = append(ids, l.ID)
	}

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(labelFanout)
	for i, id := range ids {
		g.Go(func() error {
			var l label
			if err := p.api.Get(gctx, "labels/"+url.PathEscape(id), nil, &l); err != nil {
				return err
			}
			out[i].Total = l.MessagesTotal
			out[i].Unread = l.MessagesUnread
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// metaHeader is one entry of payload.headers.
type metaHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// metaMessage is a message resource of messages.get or threads.get
// with format=metadata or format=minimal.
type metaMessage struct {
	ID           string   `json:"id"`
	ThreadID     string   `json:"threadId"`
	LabelIDs     []string `json:"labelIds"`
	Snippet      string   `json:"snippet"`
	InternalDate string   `json:"internalDate"` // ms since the epoch, as a decimal string
	SizeEstimate int64    `json:"sizeEstimate"`
	Payload      struct {
		Headers []metaHeader `json:"headers"`
	} `json:"payload"`
}

// header gives the value of the first header with the name, in any
// case, or "".
func (m *metaMessage) header(name string) string {
	for _, h := range m.Payload.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// pickHeaders gives the values of the headers that names asks for,
// for Message.Headers (DS9.2). headers is payload.headers of a
// format=full answer, which holds every header of the message. A
// header matches a name without regard to case; each instance gives
// one entry, in message order, keyed by the first spelling of the
// name in names. A value is unfolded and trimmed, never decoded. A
// name with no instance has no key; the map is nil when nothing
// matches.
//
// arch: DS9.2
func pickHeaders(headers []metaHeader, names []string) map[string][]string {
	var keys []string
	for _, n := range names {
		if n != "" && !slices.ContainsFunc(keys, func(k string) bool { return strings.EqualFold(k, n) }) {
			keys = append(keys, n)
		}
	}
	var out map[string][]string
	for _, h := range headers {
		for _, k := range keys {
			if !strings.EqualFold(h.Name, k) {
				continue
			}
			if out == nil {
				out = make(map[string][]string)
			}
			out[k] = append(out[k], unfold(h.Value))
			break
		}
	}
	return out
}

// unfold joins the lines of a folded header value with one space and
// trims the ends, as the IMAP header read does (DS9.2).
func unfold(v string) string {
	var parts []string
	for _, line := range strings.Split(v, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, " ")
}

// checkMsgID refuses an id that is not a Gmail id before it goes into a
// URL path. A Gmail id holds letters, digits, "-" and "_" only.
func checkMsgID(id string) error {
	if id == "" || len(id) > 256 || strings.ContainsFunc(id, func(r rune) bool { return !isAttachmentIDRune(r) }) {
		return fmt.Errorf("%w: %q", mail.ErrInvalidID, id)
	}
	return nil
}

// metadataQuery gives the query of a format=metadata call with the six
// headers of a row.
func metadataQuery() url.Values {
	return url.Values{"format": {"metadata"}, "metadataHeaders": metadataHeaders}
}

// labelID gives the label id of the folder name: the name when it is a
// label id, else the label with the name in any case (DS7.4a). A name
// that the cached table does not know gets one new labels.list call,
// because the label can be new. It gives the table that it used last.
func (p *Provider) labelID(ctx context.Context, tab *labelTable, name string) (string, *labelTable, error) {
	if id, ok := tab.lookup(name); ok {
		return id, tab, nil
	}
	tab, err := p.listLabels(ctx)
	if err != nil {
		return "", nil, err
	}
	if id, ok := tab.lookup(name); ok {
		return id, tab, nil
	}
	return "", nil, fmt.Errorf("gmail: the account has no folder %q", name)
}

// lookup gives the id of name in t: name itself when it is an id of t,
// else the id of the label with the name in any case.
func (t *labelTable) lookup(name string) (string, bool) {
	if _, ok := t.byID[name]; ok {
		return name, true
	}
	id, ok := t.byName[strings.ToLower(name)]
	return id, ok
}

// rowFolder gives the folder name of a row: the label prefer when the
// message has it, else the first of TRASH, SPAM, INBOX, SENT and DRAFT
// that it has, else the user label with the first name. A message with
// none of these (archived) has no folder.
func rowFolder(ids []string, prefer string, tab *labelTable) string {
	if prefer != "" && slices.Contains(ids, prefer) {
		return tab.byID[prefer]
	}
	for _, sys := range []string{labelTrash, labelSpam, labelInbox, labelSent, labelDraft} {
		if slices.Contains(ids, sys) {
			return tab.byID[sys]
		}
	}
	var names []string
	for _, id := range ids {
		if _, sys := roles[id]; sys || notFolder(id) {
			continue
		}
		if n, ok := tab.byID[id]; ok {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}
	slices.Sort(names)
	return names[0]
}

// row gives the mail.Message of a search or thread row (DS7.4): the
// date is internalDate, the server time, and never the Date header;
// the snippet comes HTML-escaped and goes through html.UnescapeString
// (E7) before the preview rules of §3.10. prefer is the label of the
// search folder, or "".
func row(m *metaMessage, prefer string, tab *labelTable) mail.Message {
	msg := mail.Message{
		ID:        m.ID,
		Folder:    rowFolder(m.LabelIDs, prefer, tab),
		To:        addressList(m.header("To")),
		Cc:        addressList(m.header("Cc")),
		Subject:   mime.DecodeHeaderText(m.header("Subject")),
		Preview:   mime.Preview([]byte(html.UnescapeString(m.Snippet)), "text/plain; charset=utf-8", ""),
		Flags:     flagsOf(m.LabelIDs),
		Size:      m.SizeEstimate,
		MessageID: strings.TrimSpace(m.header("Message-ID")),
	}
	if from := addressList(m.header("From")); len(from) > 0 {
		msg.From = from[0]
	}
	if ms, err := strconv.ParseInt(m.InternalDate, 10, 64); err == nil {
		msg.Date = time.UnixMilli(ms).UTC()
	}
	return msg
}

// addressList parses an address-list header. A value that does not
// parse gives one address with the decoded raw text as the name, so
// the row still shows it (§3.14, C22).
func addressList(v string) []mail.Address {
	list, err := mime.ParseAddressList(v)
	if err != nil {
		return []mail.Address{{Name: mime.DecodeHeaderText(v)}}
	}
	out := make([]mail.Address, 0, len(list))
	for _, a := range list {
		out = append(out, mail.Address{Name: a.Name, Address: a.Address})
	}
	return out
}

// Search runs one page of a search (DS7.4, DS7.6): messages.list with
// q, labelIds, maxResults and pageToken, then messages.get with
// format=metadata and the six row headers for each id, messageFanout
// calls at a time. The rows keep the order of messages.list. A
// message that is gone (404) between the two calls is left out; any
// other failed call stops the others and fails the search, so the
// tool layer can report this account and go on with the others
// (IS78.5). The cursor Position is the nextPageToken. With
// Query.IDsOnly the page holds the ids of messages.list only, in its
// order, and Search sends no messages.get (DS9.4); a message that is
// gone between the two calls then stays in the page.
//
// arch: DS7.4, DS7.6, IS78.5, DS9.4
func (p *Provider) Search(ctx context.Context, q mail.Query) (mail.Page, error) {
	cur, err := mail.ValidateCursor(q.Cursor, q)
	if err != nil {
		return mail.Page{}, err
	}
	sq, err := translateQuery(mail.ParseQuery(q.Raw), q.Since)
	if err != nil {
		return mail.Page{}, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxLimit)

	tab, err := p.cachedLabels(ctx)
	if err != nil {
		return mail.Page{}, err
	}
	names := sq.folders
	if q.Folder != "" {
		names = append([]string{q.Folder}, names...)
	}
	var labelIDs []string
	for _, n := range names {
		var id string
		if id, tab, err = p.labelID(ctx, tab, n); err != nil {
			return mail.Page{}, err
		}
		if !slices.Contains(labelIDs, id) {
			labelIDs = append(labelIDs, id)
		}
	}

	args := url.Values{"maxResults": {strconv.Itoa(limit)}}
	if sq.q != "" {
		args.Set("q", sq.q)
	}
	if len(labelIDs) > 0 {
		args["labelIds"] = labelIDs
	}
	if cur.Position != "" {
		// A cursor holds a place inside the result set that the query
		// already bounds, never a right of access (§3.9).
		args.Set("pageToken", cur.Position)
	}
	var list struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
		NextPageToken string `json:"nextPageToken"`
	}
	if err := p.api.Get(ctx, "messages", args, &list); err != nil {
		return mail.Page{}, err
	}

	for _, m := range list.Messages {
		if err := checkMsgID(m.ID); err != nil {
			return mail.Page{}, err
		}
	}
	var page mail.Page
	if list.NextPageToken != "" {
		page.NextCursor = mail.EncodeCursor(mail.Cursor{
			Position:  list.NextPageToken,
			QueryHash: mail.HashQuery(q),
		})
	}
	if q.IDsOnly {
		// Every term of a Gmail query runs on the server (DS7.6), so
		// the ids of messages.list are the whole match set of the page
		// and no metadata get is needed (DS9.4).
		for _, m := range list.Messages {
			page.Messages = append(page.Messages, mail.Message{ID: m.ID})
		}
		return page, nil
	}

	got := make([]*metaMessage, len(list.Messages))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(messageFanout)
	for i, m := range list.Messages {
		g.Go(func() error {
			var mm metaMessage
			err := p.api.Get(gctx, "messages/"+m.ID, metadataQuery(), &mm)
			if ae, ok := errors.AsType[*APIError](err); ok && ae.Status == http.StatusNotFound {
				return nil
			}
			if err != nil {
				return err
			}
			got[i] = &mm
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return mail.Page{}, err
	}

	prefer := ""
	if len(labelIDs) > 0 {
		prefer = labelIDs[0]
	}
	for _, mm := range got {
		if mm != nil {
			page.Messages = append(page.Messages, row(mm, prefer, tab))
		}
	}
	return page, nil
}

// Thread gives the conversation of the message id (DS7.4): one
// messages.get with format=minimal gives the threadId, and threads.get
// with format=metadata gives the messages, oldest first, as rows of
// Search. Only the newest maxThread messages come back.
//
// arch: DS7.4
func (p *Provider) Thread(ctx context.Context, id string) (mail.ThreadResult, error) {
	threadID, err := p.threadOf(ctx, id)
	if err != nil {
		return mail.ThreadResult{}, err
	}
	var th struct {
		Messages []metaMessage `json:"messages"`
	}
	if err := p.api.Get(ctx, "threads/"+threadID, metadataQuery(), &th); err != nil {
		return mail.ThreadResult{}, err
	}
	tab, err := p.cachedLabels(ctx)
	if err != nil {
		return mail.ThreadResult{}, err
	}
	msgs := th.Messages
	if len(msgs) > maxThread {
		msgs = msgs[len(msgs)-maxThread:]
	}
	out := mail.ThreadResult{Messages: make([]*mail.Message, len(msgs))}
	for i := range msgs {
		r := row(&msgs[i], "", tab)
		out.Messages[i] = &r
	}
	return out, nil
}

// The bounds of Modify (DS7.4).
const (
	// modifyFanout is the number of messages.get calls of the read
	// before a change that run at the same time.
	modifyFanout = 10
	// batchModifyMax is the most ids that one messages.batchModify
	// call takes (E3).
	batchModifyMax = 1000
)

// labelDelta is a change as label ids: the ids to add and to remove,
// and the names of the new labels to create and add.
type labelDelta struct {
	add, remove []string
	create      []string
}

// empty reports whether d changes nothing.
func (d labelDelta) empty() bool {
	return len(d.add) == 0 && len(d.remove) == 0 && len(d.create) == 0
}

// apply gives the label ids of a message after d: before, plus add,
// minus remove.
func (d labelDelta) apply(before []string) []string {
	out := make([]string, 0, len(before)+len(d.add))
	for _, id := range before {
		if !slices.Contains(d.remove, id) {
			out = append(out, id)
		}
	}
	for _, id := range d.add {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// deltaOf gives c as label ids (DS7.4): read removes UNREAD, unread
// adds UNREAD; starred adds or removes STARRED; archive removes INBOX;
// trash adds TRASH and removes INBOX; move_to X adds X and removes
// INBOX, TRASH and SPAM (each one that is not X), as "Move to" of the
// web client does, so a move takes a message out of Trash and Spam;
// add_labels and remove_labels are label names or ids (DS7.4a).
// add_labels and move_to name a user label that the account does not
// have in d.create; ModifyDetail creates it just before batchModify. A
// label that the change both adds and removes is refused: the caller
// asked for two opposite things. RestoreFolders is for a provider with
// mailbox lists; a Gmail move is undone through the labels (DS78.5).
func (p *Provider) deltaOf(ctx context.Context, c mail.Change) (labelDelta, error) {
	if len(c.RestoreFolders) > 0 {
		return labelDelta{}, errors.New("gmail: a folder list restore is not a Gmail change; undo of a Gmail move works through the labels")
	}
	var d labelDelta
	add := func(id string) {
		if !slices.Contains(d.add, id) {
			d.add = append(d.add, id)
		}
	}
	remove := func(id string) {
		if !slices.Contains(d.remove, id) {
			d.remove = append(d.remove, id)
		}
	}
	// isNew reports whether name is in d.create, in any case.
	isNew := func(name string) bool {
		return slices.ContainsFunc(d.create, func(n string) bool { return strings.EqualFold(n, name) })
	}
	// addNamed adds the label id, or names the new label to create.
	addNamed := func(id, name string) {
		switch {
		case id != "":
			add(id)
		case !isNew(name):
			d.create = append(d.create, name)
		}
	}
	if c.Read != nil {
		if *c.Read {
			remove(labelUnread)
		} else {
			add(labelUnread)
		}
	}
	if c.Starred != nil {
		if *c.Starred {
			add(labelStarred)
		} else {
			remove(labelStarred)
		}
	}
	if c.Archive {
		remove(labelInbox)
	}
	if c.Trash {
		add(labelTrash)
		remove(labelInbox)
	}
	if c.MoveTo == "" && len(c.AddLabels) == 0 && len(c.RemoveLabels) == 0 {
		return d, nil
	}

	tab, err := p.cachedLabels(ctx)
	if err != nil {
		return labelDelta{}, err
	}
	if c.MoveTo != "" {
		var id string
		if id, tab, err = p.resolveLabel(ctx, tab, c.MoveTo, true); err != nil {
			return labelDelta{}, err
		}
		addNamed(id, c.MoveTo)
		for _, from := range []string{labelInbox, labelTrash, labelSpam} {
			if id != from {
				remove(from)
			}
		}
	}
	for _, n := range c.AddLabels {
		var id string
		if id, tab, err = p.resolveLabel(ctx, tab, n, true); err != nil {
			return labelDelta{}, err
		}
		addNamed(id, n)
	}
	for _, n := range c.RemoveLabels {
		if isNew(n) {
			return labelDelta{}, fmt.Errorf("gmail: the change both adds and removes the label %q", n)
		}
		var id string
		if id, tab, err = p.resolveLabel(ctx, tab, n, false); err != nil {
			return labelDelta{}, err
		}
		remove(id)
	}
	for _, id := range d.add {
		if slices.Contains(d.remove, id) {
			return labelDelta{}, fmt.Errorf("gmail: the change both adds and removes the label %q", tab.byID[id])
		}
	}
	return d, nil
}

// Modify applies one change to a set of messages and gives one row per
// message that changed (DS7.4). It gives the rows of ModifyDetail.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.5, IS8.4
func (p *Provider) Modify(ctx context.Context, ids []string, c mail.Change) ([]mail.Applied, error) {
	res, err := p.ModifyDetail(ctx, ids, c)
	return res.Applied, err
}

// ModifyDetail applies one change and names the gone messages (DS7.4).
// The change becomes label ids first (deltaOf), so an unknown label
// stops the call before a message changes. Then messages.get with
// format=minimal reads the labelIds of each id, modifyFanout calls at
// a time; an id that gives 404 is in Gone and has no row (D5.4). When
// at least one id is there, the new labels of the change are created.
// Then messages.batchModify changes the other ids, batchModifyMax ids for
// each call (E3). The state after is the state before with the change
// applied; Before and After are flagsOf those label ids (DS7.4b), so a
// move is a label difference that undo reverses (DS78.5, IS8.4). A
// Gmail message keeps its id and has no second copy, so NewID,
// FoldersBefore, FoldersAfter and ExpungePending stay empty.
//
// An empty change sends no batchModify: each row then has the current
// flags in Before and After, the state read of undo. When a
// batchModify call fails, the rows of the calls before it come back
// with the error, so the undo journal records what changed (DRV.11).
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.5, IS8.4, E3, D5.4
func (p *Provider) ModifyDetail(ctx context.Context, ids []string, c mail.Change) (mail.ModifyResult, error) {
	if len(ids) == 0 {
		return mail.ModifyResult{}, errors.New("gmail: modify needs at least one message id")
	}
	var uniq []string
	for _, id := range ids {
		if err := checkMsgID(id); err != nil {
			return mail.ModifyResult{}, err
		}
		if !slices.Contains(uniq, id) {
			uniq = append(uniq, id)
		}
	}
	d, err := p.deltaOf(ctx, c)
	if err != nil {
		return mail.ModifyResult{}, err
	}

	before := make([][]string, len(uniq))
	found := make([]bool, len(uniq))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(modifyFanout)
	for i, id := range uniq {
		g.Go(func() error {
			var mm metaMessage
			err := p.api.Get(gctx, "messages/"+id, url.Values{"format": {"minimal"}}, &mm)
			if ae, ok := errors.AsType[*APIError](err); ok && ae.Status == http.StatusNotFound {
				return nil
			}
			if err != nil {
				return err
			}
			before[i], found[i] = mm.LabelIDs, true
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return mail.ModifyResult{}, err
	}

	var res mail.ModifyResult
	var present []int // indexes into uniq of the ids that are there
	for i, id := range uniq {
		if !found[i] {
			res.Gone = append(res.Gone, id)
			continue
		}
		present = append(present, i)
	}
	if d.empty() {
		for _, i := range present {
			f := flagsOf(before[i])
			res.Applied = append(res.Applied, mail.Applied{ID: uniq[i], Before: f, After: f})
		}
		return res, nil
	}
	if len(present) == 0 {
		return res, nil
	}
	// A new label is created only now, after the checks and the read,
	// so a change that stops before the write leaves no empty label.
	for _, name := range d.create {
		id, err := p.createLabel(ctx, name)
		if err != nil {
			return res, err
		}
		if !slices.Contains(d.add, id) {
			d.add = append(d.add, id)
		}
	}

	for start := 0; start < len(present); start += batchModifyMax {
		chunk := present[start:min(start+batchModifyMax, len(present))]
		body := struct {
			IDs    []string `json:"ids"`
			Add    []string `json:"addLabelIds,omitempty"`
			Remove []string `json:"removeLabelIds,omitempty"`
		}{Add: d.add, Remove: d.remove}
		for _, i := range chunk {
			body.IDs = append(body.IDs, uniq[i])
		}
		if err := p.api.Post(ctx, "messages/batchModify", nil, body, nil); err != nil {
			return res, err
		}
		for _, i := range chunk {
			res.Applied = append(res.Applied, mail.Applied{
				ID:     uniq[i],
				Before: flagsOf(before[i]),
				After:  flagsOf(d.apply(before[i])),
			})
		}
	}
	return res, nil
}

// Caps gives the capability report of DS78.4: Kind "gmail" and the
// lines "api: ok", "labels: <n>" (every label of labels.list) and
// "send-as: <k> verified" (the primary address and each send-as
// address with verificationStatus "accepted", DS7.5). The calls are
// labels.list (1 quota unit) and settings/sendAs; both answers go into
// the caches of the account.
//
// arch: DS78.4, DS7.4, DS7.5
func (p *Provider) Caps(ctx context.Context) (mail.Caps, error) {
	tab, err := p.listLabels(ctx)
	if err != nil {
		return mail.Caps{}, err
	}
	sendAs, err := p.listSendAs(ctx)
	if err != nil {
		return mail.Caps{}, err
	}
	return mail.Caps{Kind: "gmail", Lines: []string{
		"api: ok",
		fmt.Sprintf("labels: %d", len(tab.list)),
		fmt.Sprintf("send-as: %d verified", len(sendAs)),
	}}, nil
}
