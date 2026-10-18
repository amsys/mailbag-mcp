// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The JMAP provider (DS8.2). Provider holds the account, the client,
// the mailbox and identity caches of 10 minutes and the auth hook of
// the Factory. Folders, Search, Read, Thread, Raw and Attachment each
// send one batch of method calls; Raw and Attachment then get one blob
// through the blob client and its cap (DS8.3). SaveDraft and
// SendDraft write drafts and submit them (DS8.2, DS8.2a). Modify and
// ModifyDetail change keywords and mailboxes with Email/set and record
// the mailboxes before and after a move (DS8.2c, DS78.5). The folder
// writes use Mailbox/set, and Caps gives the report of DS78.4.

package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	stdmime "mime"
	gomail "net/mail"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

const (
	// mailboxTTL is the life of the mailbox cache on the wall clock
	// (DS8.2).
	mailboxTTL = 10 * time.Minute
	// identityTTL is the life of the identity cache on the wall clock
	// (DS8.2a).
	identityTTL = 10 * time.Minute
	// defaultLimit and maxLimit bound one search page, as on IMAP.
	defaultLimit = 20
	maxLimit     = 100
	// maxThread is how many messages one conversation gives back, the
	// newest ones (§3.10, as on IMAP).
	maxThread = 50
	// maxBodyValueBytes caps each body value that Read asks for
	// (DS8.2). The server cuts a longer value and marks it
	// isTruncated.
	maxBodyValueBytes = mime.MaxPartBytes
	// maxPathDepth stops the walk up the parent chain of a mailbox
	// tree that a server gives with a loop.
	maxPathDepth = 64
)

// listProperties are the Email properties of a search row (DS8.2).
var listProperties = []string{
	"id", "mailboxIds", "keywords", "from", "to", "cc",
	"subject", "receivedAt", "size", "preview",
}

// The header properties of Read (DS8.2). The Raw form is the default
// of a header property (RFC 8621 §4.1.2). Authentication-Results asks
// for every instance (":all"): the DKIM check reads the whole block, as
// the IMAP header fetch gives it, and the last instance alone is the
// one that the first hop added. Content-Type gives the smime-type
// parameter of D7.3.
const (
	headerMessageID   = "header:Message-ID"
	headerReferences  = "header:References"
	headerAuthResults = "header:Authentication-Results:asRaw:all"
	headerContentType = "header:Content-Type"
)

// readProperties are the Email properties of Read: the row, the body
// lists and values, the structure and the headers of DS8.2.
var readProperties = append(slices.Clone(listProperties),
	"replyTo", "bodyStructure", "textBody", "htmlBody", "attachments", "bodyValues",
	headerMessageID, headerReferences, headerAuthResults, headerContentType,
)

// partProperties are the EmailBodyPart properties that Read and
// Attachment ask for. subParts lets Read walk bodyStructure.
var partProperties = []string{"partId", "blobId", "size", "name", "type", "charset", "disposition", "subParts"}

// errNoMessage is the error of an id that the account does not hold.
// It does not repeat the id, which is caller text.
var errNoMessage = errors.New("jmap: no message with this id in the account; search again")

// Provider reads the mail of one JMAP account (DS8.2). It is made for
// each call, as the IMAP provider is.
type Provider struct {
	acct   config.Account
	c      *Client
	boxes  *mailboxCache    // id to path, roles; mailboxTTL
	idents *identityCache   // Identity/get; identityTTL
	onAuth func(error)      // the Factory: note a refused login (DRV.10)
	now    func() time.Time // wall time only
}

// NewProvider gives the provider of the JMAP account acct. It calls
// the server through c and gives each *AuthError to onAuth (DS78.3).
// A nil onAuth reports nothing.
func NewProvider(acct config.Account, c *Client, onAuth func(error)) *Provider {
	if onAuth == nil {
		onAuth = func(error) {}
	}
	return &Provider{
		acct:   acct,
		c:      c,
		boxes:  &mailboxCache{},
		idents: &identityCache{},
		onAuth: onAuth,
		now:    wallNow,
	}
}

// wallNow is time.Now without the monotonic reading, so that a cache
// does not stay fresh over a suspend (as gmail.wallNow).
func wallNow() time.Time { return time.Now().Round(0) }

// report gives err to onAuth when it is a refused login, and gives err
// back.
func (p *Provider) report(err error) error {
	var ae *AuthError
	if errors.As(err, &ae) {
		p.onAuth(err)
	}
	return err
}

// accountID gives the primary mail account of the session.
func (p *Provider) accountID(ctx context.Context) (string, error) {
	s, err := p.c.Session(ctx)
	if err != nil {
		return "", p.report(err)
	}
	return s.AccountID, nil
}

// call sends one batch of method calls.
func (p *Provider) call(ctx context.Context, calls ...Invocation) (*Response, error) {
	r, err := p.c.Call(ctx, calls...)
	if err != nil {
		return nil, p.report(err)
	}
	return r, nil
}

// result decodes the arguments of the response to the call id into
// out. A method error of that call gives *MethodError.
func result(r *Response, id, name string, out any) error {
	for _, inv := range r.MethodResponses {
		if inv.ID != id {
			continue
		}
		if err := inv.Err(); err != nil {
			return err
		}
		if inv.Name != name {
			continue
		}
		b, err := json.Marshal(inv.Args)
		if err != nil {
			return fmt.Errorf("jmap: %s: %w", name, err)
		}
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("jmap: decode the %s answer: %w", name, err)
		}
		return nil
	}
	return fmt.Errorf("jmap: the answer has no %s response", name)
}

// resultRef gives a ResultReference (RFC 8620 §3.7) to the response of the
// call id with the method name, at path.
func resultRef(id, name, path string) map[string]any {
	return map[string]any{"resultOf": id, "name": name, "path": path}
}

// checkID refuses an id that is not a JMAP Id (RFC 8620 §1.2): 1 to
// 255 characters of A-Z, a-z, 0-9, "-" and "_".
func checkID(id string) error {
	if id == "" || len(id) > 255 {
		return fmt.Errorf("%w: %q", mail.ErrInvalidID, id)
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return fmt.Errorf("%w: %q", mail.ErrInvalidID, id)
		}
	}
	return nil
}

// mailbox is one Mailbox object (RFC 8621 §2).
type mailbox struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ParentID     string `json:"parentId"`
	Role         string `json:"role"`
	TotalEmails  int    `json:"totalEmails"`
	UnreadEmails int    `json:"unreadEmails"`
}

// mailboxTable is one Mailbox/get answer with its indexes. It does not
// change after newMailboxTable, so more than one goroutine can read
// it.
type mailboxTable struct {
	list   []mailbox
	path   map[string]string // id to the path: the parent names and the name, joined by "/"
	byPath map[string]string // path to id; "" when two mailboxes have the path
	inbox  string            // the id with the role inbox, or ""
}

// newMailboxTable indexes the mailboxes of one Mailbox/get answer. The
// path of a mailbox joins the names of its parents and its own name
// with "/" (DS8.2). A parent that is not in the list, or a loop, ends
// the walk.
func newMailboxTable(list []mailbox) *mailboxTable {
	t := &mailboxTable{
		list:   list,
		path:   make(map[string]string, len(list)),
		byPath: make(map[string]string, len(list)),
	}
	byID := make(map[string]mailbox, len(list))
	for _, m := range list {
		byID[m.ID] = m
	}
	for _, m := range list {
		names := []string{m.Name}
		seen := map[string]bool{m.ID: true}
		for parent := m.ParentID; parent != "" && len(names) < maxPathDepth; {
			pm, ok := byID[parent]
			if !ok || seen[parent] {
				break
			}
			seen[parent] = true
			names = append(names, pm.Name)
			parent = pm.ParentID
		}
		slices.Reverse(names)
		path := strings.Join(names, "/")
		t.path[m.ID] = path
		if _, dup := t.byPath[path]; dup {
			t.byPath[path] = ""
		} else {
			t.byPath[path] = m.ID
		}
		if strings.EqualFold(m.Role, "inbox") && t.inbox == "" {
			t.inbox = m.ID
		}
	}
	return t
}

// resolve gives the id of the mailbox with the path name. "INBOX" in
// any case also names the mailbox with the role inbox. ok is false
// when no mailbox has the path; err is set when two have it.
func (t *mailboxTable) resolve(name string) (id string, ok bool, err error) {
	if id, found := t.byPath[name]; found {
		if id == "" {
			return "", true, fmt.Errorf("jmap: the folder name %q is not unique in the account", name)
		}
		return id, true, nil
	}
	if strings.EqualFold(name, "INBOX") && t.inbox != "" {
		return t.inbox, true, nil
	}
	return "", false, nil
}

// folderOf gives the folder of a message row: prefer when the message
// is in that mailbox, else the first path in sort order of the
// mailboxes of the message. A mailbox that the table does not know is
// left out.
func (t *mailboxTable) folderOf(ids map[string]bool, prefer string) string {
	if prefer != "" && ids[prefer] {
		return t.path[prefer]
	}
	var paths []string
	for id, in := range ids {
		if p, ok := t.path[id]; in && ok {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return ""
	}
	slices.Sort(paths)
	return paths[0]
}

// roleID gives the id of the first mailbox with the JMAP role, in any
// case, or "".
func (t *mailboxTable) roleID(role string) string {
	for _, m := range t.list {
		if strings.EqualFold(m.Role, role) {
			return m.ID
		}
	}
	return ""
}

// mailboxCache keeps the last mailboxTable for mailboxTTL on the wall
// clock. The zero value is empty and ready to use.
type mailboxCache struct {
	mu  sync.Mutex
	at  time.Time
	tab *mailboxTable
}

// get gives the table when it is younger than mailboxTTL at now, else
// nil. A negative age means the wall clock stepped back, so the table
// counts as old.
func (c *mailboxCache) get(now time.Time) *mailboxTable {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tab == nil {
		return nil
	}
	if age := now.Sub(c.at); age < 0 || age >= mailboxTTL {
		return nil
	}
	return c.tab
}

// put keeps tab as the answer of Mailbox/get at now.
func (c *mailboxCache) put(tab *mailboxTable, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tab = tab
	c.at = now
}

// drop empties the cache after a change of the mailbox tree.
func (c *mailboxCache) drop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tab = nil
}

// listMailboxes calls Mailbox/get, keeps the answer in the mailbox
// cache and gives it.
func (p *Provider) listMailboxes(ctx context.Context) (*mailboxTable, error) {
	acc, err := p.accountID(ctx)
	if err != nil {
		return nil, err
	}
	r, err := p.call(ctx, Invocation{Name: "Mailbox/get", ID: "m", Args: map[string]any{
		"accountId":  acc,
		"ids":        nil,
		"properties": []string{"id", "name", "parentId", "role", "totalEmails", "unreadEmails"},
	}})
	if err != nil {
		return nil, err
	}
	var ans struct {
		List []mailbox `json:"list"`
	}
	if err := result(r, "m", "Mailbox/get", &ans); err != nil {
		return nil, err
	}
	tab := newMailboxTable(ans.List)
	p.boxes.put(tab, p.now())
	return tab, nil
}

// cachedMailboxes gives the mailbox table from the cache while it is
// younger than mailboxTTL, else from a new Mailbox/get call.
func (p *Provider) cachedMailboxes(ctx context.Context) (*mailboxTable, error) {
	if tab := p.boxes.get(p.now()); tab != nil {
		return tab, nil
	}
	return p.listMailboxes(ctx)
}

// mailboxID gives the id of the folder name. When the cached table
// does not know the name, it asks the server once more, because the
// folder can be younger than the cache.
func (p *Provider) mailboxID(ctx context.Context, name string) (string, *mailboxTable, error) {
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return "", nil, err
	}
	id, ok, err := tab.resolve(name)
	if !ok && err == nil {
		if tab, err = p.listMailboxes(ctx); err != nil {
			return "", nil, err
		}
		id, ok, err = tab.resolve(name)
	}
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", nil, fmt.Errorf("jmap: the account has no folder %q", name)
	}
	return id, tab, nil
}

// Folders gives every mailbox of the account, sorted by path (DS8.2).
// The name is the path: the parent names and the name, joined by "/".
// The role comes from the JMAP role, and the counts from totalEmails
// and unreadEmails. The answer goes into the mailbox cache.
//
// arch: DS8.2
func (p *Provider) Folders(ctx context.Context) ([]mail.Folder, error) {
	tab, err := p.listMailboxes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]mail.Folder, 0, len(tab.list))
	for _, m := range tab.list {
		out = append(out, mail.Folder{
			Name:   tab.path[m.ID],
			Role:   roleOf(m.Role),
			Total:  m.TotalEmails,
			Unread: m.UnreadEmails,
		})
	}
	slices.SortStableFunc(out, func(a, b mail.Folder) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// emailWire is an Email object (RFC 8621 §4.1) with the properties
// that this provider asks for.
type emailWire struct {
	ID            string               `json:"id"`
	ThreadID      string               `json:"threadId"`
	MailboxIDs    map[string]bool      `json:"mailboxIds"`
	Keywords      map[string]bool      `json:"keywords"`
	From          []emailAddress       `json:"from"`
	To            []emailAddress       `json:"to"`
	Cc            []emailAddress       `json:"cc"`
	ReplyTo       []emailAddress       `json:"replyTo"`
	Subject       string               `json:"subject"`
	ReceivedAt    time.Time            `json:"receivedAt"`
	Size          int64                `json:"size"`
	Preview       string               `json:"preview"`
	BlobID        string               `json:"blobId"`
	BodyStructure *bodyPart            `json:"bodyStructure"`
	TextBody      []bodyPart           `json:"textBody"`
	HTMLBody      []bodyPart           `json:"htmlBody"`
	Attachments   []bodyPart           `json:"attachments"`
	BodyValues    map[string]bodyValue `json:"bodyValues"`
	MessageID     string               `json:"header:Message-ID"`
	References    string               `json:"header:References"`
	ContentType   string               `json:"header:Content-Type"`
}

// bodyPart is one EmailBodyPart (RFC 8621 §4.1.4).
type bodyPart struct {
	PartID      string     `json:"partId"`
	BlobID      string     `json:"blobId"`
	Size        int64      `json:"size"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Disposition string     `json:"disposition"`
	SubParts    []bodyPart `json:"subParts"`
}

// bodyValue is one EmailBodyValue (RFC 8621 §4.1.4).
type bodyValue struct {
	Value       string `json:"value"`
	IsTruncated bool   `json:"isTruncated"`
}

// row gives the mail.Message of a search row. prefer is the mailbox
// that the search ran in, or "".
func row(w emailWire, tab *mailboxTable, prefer string) mail.Message {
	return mail.Message{
		ID:      w.ID,
		Folder:  tab.folderOf(w.MailboxIDs, prefer),
		From:    firstAddress(w.From),
		To:      addresses(w.To),
		Cc:      addresses(w.Cc),
		Date:    w.ReceivedAt,
		Subject: w.Subject,
		Preview: mime.Preview([]byte(w.Preview), "text/plain; charset=utf-8", ""),
		Flags:   flagsOf(w.Keywords),
		Size:    w.Size,
	}
}

// getRows calls Email/get for ids with the row properties and gives
// the rows in the order of ids. An id that the answer lacks is left
// out: the message went away between the two calls.
func (p *Provider) getRows(ctx context.Context, acc string, ids []string, tab *mailboxTable) ([]mail.Message, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	r, err := p.call(ctx, Invocation{Name: "Email/get", ID: "g", Args: map[string]any{
		"accountId": acc, "ids": ids, "properties": listProperties,
	}})
	if err != nil {
		return nil, err
	}
	var ans struct {
		List []emailWire `json:"list"`
	}
	if err := result(r, "g", "Email/get", &ans); err != nil {
		return nil, err
	}
	return orderRows(ids, ans.List, tab, ""), nil
}

// orderRows gives the rows of list in the order of ids. Email/get does
// not promise the order of its list.
func orderRows(ids []string, list []emailWire, tab *mailboxTable, prefer string) []mail.Message {
	byID := make(map[string]emailWire, len(list))
	for _, w := range list {
		byID[w.ID] = w
	}
	out := make([]mail.Message, 0, len(ids))
	for _, id := range ids {
		if w, ok := byID[id]; ok {
			out = append(out, row(w, tab, prefer))
		}
	}
	return out
}

// Search runs Email/query (DS8.4) and Email/get in one batch: the get
// takes the ids of the query through the #ids back-reference (DS8.2).
// The sort is receivedAt descending. The cursor holds the position of
// the next page. When the server gives total, a next page exists while
// position plus the page is below total; else while the page is full.
// An empty Folder searches INBOX, as the search tool and the other
// providers do (03-design.md, SearchIn.Folder). With Query.IDsOnly the batch
// holds the Email/query only, and each row carries its ID only: every
// term of a JMAP query runs on the server (termCondition refuses any
// other), so the match set is exact and Page.Partial stays false
// (DS9.4, S9-GAP1). The cursor is the same as for a full page.
//
// arch: DS8.2, DS8.4, DS9.4
func (p *Provider) Search(ctx context.Context, q mail.Query) (mail.Page, error) {
	cur, err := mail.ValidateCursor(q.Cursor, q)
	if err != nil {
		return mail.Page{}, err
	}
	position := 0
	if cur.Position != "" {
		// A cursor holds a position inside a result set, never a right
		// of access: the query bounds what the page can hold (§3.9).
		n, err := strconv.Atoi(cur.Position)
		if err != nil || n < 0 {
			return mail.Page{}, fmt.Errorf("jmap: search: %w", mail.ErrCursorInvalid)
		}
		position = n
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxLimit)

	folder := q.Folder
	if folder == "" {
		folder = "INBOX"
	}
	mailboxID, tab, err := p.mailboxID(ctx, folder)
	if err != nil {
		return mail.Page{}, err
	}
	args, err := queryArgs(mail.ParseQuery(q.Raw), mailboxID, q.Since, p.now(), position, limit)
	if err != nil {
		return mail.Page{}, err
	}
	acc, err := p.accountID(ctx)
	if err != nil {
		return mail.Page{}, err
	}
	args["accountId"] = acc
	calls := []Invocation{{Name: "Email/query", ID: "q", Args: args}}
	if !q.IDsOnly {
		calls = append(calls, Invocation{Name: "Email/get", ID: "g", Args: map[string]any{
			"accountId":  acc,
			"#ids":       resultRef("q", "Email/query", "/ids"),
			"properties": listProperties,
		}})
	}
	r, err := p.call(ctx, calls...)
	if err != nil {
		return mail.Page{}, err
	}
	var qa struct {
		IDs      []string `json:"ids"`
		Position int      `json:"position"`
		Total    *int     `json:"total"`
	}
	if err := result(r, "q", "Email/query", &qa); err != nil {
		return mail.Page{}, err
	}
	var page mail.Page
	if q.IDsOnly {
		page.Messages = make([]mail.Message, 0, len(qa.IDs))
		for _, id := range qa.IDs {
			page.Messages = append(page.Messages, mail.Message{ID: id})
		}
	} else {
		var ga struct {
			List []emailWire `json:"list"`
		}
		if err := result(r, "g", "Email/get", &ga); err != nil {
			return mail.Page{}, err
		}
		page.Messages = orderRows(qa.IDs, ga.List, tab, mailboxID)
	}
	next := qa.Position + len(qa.IDs)
	more := len(qa.IDs) == limit
	if qa.Total != nil {
		more = next < *qa.Total
	}
	if more && len(qa.IDs) > 0 {
		page.NextCursor = mail.EncodeCursor(mail.Cursor{
			Position:  strconv.Itoa(next),
			QueryHash: mail.HashQuery(q),
		})
	}
	return page, nil
}

// getOne calls Email/get for the one id with args added, and gives the
// email.
func (p *Provider) getOne(ctx context.Context, id string, args map[string]any) (emailWire, error) {
	w, _, err := p.getOneJSON(ctx, id, args)
	return w, err
}

// getOneJSON is getOne that also gives the JSON object of the email,
// for the properties that emailWire has no field for: the headers of
// ReadOpts.Headers (DS9.2).
func (p *Provider) getOneJSON(ctx context.Context, id string, args map[string]any) (emailWire, json.RawMessage, error) {
	if err := checkID(id); err != nil {
		return emailWire{}, nil, err
	}
	acc, err := p.accountID(ctx)
	if err != nil {
		return emailWire{}, nil, err
	}
	args["accountId"] = acc
	args["ids"] = []string{id}
	r, err := p.call(ctx, Invocation{Name: "Email/get", ID: "e", Args: args})
	if err != nil {
		return emailWire{}, nil, err
	}
	var ans struct {
		List []json.RawMessage `json:"list"`
	}
	if err := result(r, "e", "Email/get", &ans); err != nil {
		return emailWire{}, nil, err
	}
	for _, raw := range ans.List {
		var w emailWire
		if err := json.Unmarshal(raw, &w); err != nil {
			return emailWire{}, nil, fmt.Errorf("jmap: decode the Email/get answer: %w", err)
		}
		if w.ID == id {
			return w, raw, nil
		}
	}
	return emailWire{}, nil, errNoMessage
}

// headerProperty gives the Email property of the raw value of each
// instance of the header name, in message order (RFC 8621 §4.1.3).
//
// arch: DS9.2
func headerProperty(name string) string {
	return "header:" + name + ":asRaw:all"
}

// checkHeaderNames refuses a header name that is not an RFC 5322 field
// name (printable ASCII except the colon). The name goes into a
// property name, so a colon would change the form of the property.
//
// arch: DS9.2
func checkHeaderNames(names []string) error {
	for _, n := range names {
		if n == "" {
			return fmt.Errorf("jmap: read: a header name is empty")
		}
		for i := 0; i < len(n); i++ {
			if n[i] < 33 || n[i] > 126 || n[i] == ':' {
				return fmt.Errorf("jmap: read: header name %q is not a field name", n)
			}
		}
	}
	return nil
}

// uniqueNames gives a new slice with each header name once. Names that
// differ only in case are one name, and the first spelling stays, so a
// repeated name never gives each value twice (DS9.2).
//
// arch: DS9.2
func uniqueNames(names []string) []string {
	var out []string
	for _, n := range names {
		if !slices.ContainsFunc(out, func(o string) bool { return strings.EqualFold(o, n) }) {
			out = append(out, n)
		}
	}
	return out
}

// headerValues reads the header properties of names from the JSON
// object of an email into one entry per instance, keyed by the name
// the caller asked for. A server can give the property name in another
// case than the request (the header name is not case-sensitive), so a
// key that matches only without regard to case counts when the exact
// key is absent. A value is unfolded and trimmed, never decoded. A name
// with no instance has no key; no instance at all gives nil.
//
// arch: DS9.2
func headerValues(obj map[string]json.RawMessage, keys []string, names []string) (map[string][]string, error) {
	var out map[string][]string
	for _, name := range names {
		values, err := headerInstances(obj, keys, name)
		if err != nil {
			return nil, err
		}
		for _, s := range values {
			if out == nil {
				out = make(map[string][]string)
			}
			out[name] = append(out[name], unfold(s))
		}
	}
	return out, nil
}

// headerInstances gives the raw value of each instance of the header
// name from the JSON object of an email, as the server sent it. keys
// holds the keys of obj, sorted. asRaw is the default form of RFC 8621
// §4.1.3, so a server can give the property without it: Stalwart
// answers header:<Name>:all to a request for header:<Name>:asRaw:all.
// The exact key counts first; then a key of either form that matches
// without regard to case. No key gives nil.
//
// arch: DS9.2
func headerInstances(obj map[string]json.RawMessage, keys []string, name string) ([]string, error) {
	prop := headerProperty(name)
	v, ok := obj[prop]
	if !ok {
		short := "header:" + name + ":all"
		i := slices.IndexFunc(keys, func(k string) bool { return strings.EqualFold(k, prop) || strings.EqualFold(k, short) })
		if i < 0 {
			return nil, nil
		}
		v = obj[keys[i]]
	}
	var values []string
	if err := json.Unmarshal(v, &values); err != nil {
		return nil, fmt.Errorf("jmap: decode the Email/get answer: %s: %w", prop, err)
	}
	return values, nil
}

// Read gets one message with its text body, its attachment list and
// the headers of a reply and of the DKIM check (DS8.2). It asks for
// the values of textBody and htmlBody, each cut by the server at
// maxBodyValueBytes. The plain text comes from the text/plain parts of
// textBody, and the HTML from the text/html parts of htmlBody, so an
// HTML-only message, whose textBody holds its HTML part, never shows
// HTML source as text (F3). mime.PickBody then makes the choice of
// D4.2, as on IMAP. A value that the server marks isTruncated is a
// cut: SignedHint is then not SignedNo, because the text after the cut
// can hold a signature marker (DRV.4). SignedHint comes from the types
// in bodyStructure first (D6.2). Email/get does not set $seen, so the
// read changes nothing (C2). Each name of ReadOpts.Headers adds one
// header:<Name>:asRaw:all property to the same Email/get, and the
// values fill Message.Headers; a read with no names asks for nothing
// more (DS9.2).
//
// arch: DS8.2, D4.2, D6.2, DRV.4, F3, DS9.2
func (p *Provider) Read(ctx context.Context, id string, o mail.ReadOpts) (*mail.Message, error) {
	if err := checkHeaderNames(o.Headers); err != nil {
		return nil, err
	}
	names := uniqueNames(o.Headers)
	props := readProperties
	if len(names) > 0 {
		// A copy, so the shared readProperties never grows.
		props = slices.Clone(readProperties)
		for _, n := range names {
			if prop := headerProperty(n); !slices.Contains(props, prop) {
				props = append(props, prop)
			}
		}
	}
	w, raw, err := p.getOneJSON(ctx, id, map[string]any{
		"properties":          props,
		"bodyProperties":      partProperties,
		"fetchTextBodyValues": true,
		"fetchHTMLBodyValues": true,
		"maxBodyValueBytes":   maxBodyValueBytes,
	})
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("jmap: decode the Email/get answer: %w", err)
	}
	keys := slices.Sorted(maps.Keys(obj))
	auth, err := headerInstances(obj, keys, "Authentication-Results")
	if err != nil {
		return nil, err
	}
	var headers map[string][]string
	if len(names) > 0 {
		if headers, err = headerValues(obj, keys, names); err != nil {
			return nil, err
		}
	}
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return nil, err
	}
	msg := row(w, tab, "")
	msg.ReplyTo = addresses(w.ReplyTo)
	msg.MessageID = firstMessageID(w.MessageID)
	msg.References = mail.MessageIDs(w.References)
	msg.AuthResults = authBlock(auth)
	msg.Headers = headers
	for _, a := range w.Attachments {
		msg.Attachments = append(msg.Attachments, mail.Attachment{
			Ref:         a.PartID,
			Filename:    a.Name,
			ContentType: a.Type,
			Size:        a.Size,
		})
	}
	params := map[string]string{}
	if w.ContentType != "" {
		if _, ps, err := stdmime.ParseMediaType(unfold(w.ContentType)); err == nil {
			params = ps
		}
	}
	if w.BodyStructure != nil {
		msg.MediaType = strings.ToLower(w.BodyStructure.Type)
		for k, v := range params {
			if strings.EqualFold(k, "smime-type") {
				msg.SMIMEType = v
			}
		}
	}

	body := pickBody(w, o.Format)
	msg.HiddenRemoved = body.removed
	msg.PartsDiffer = body.differ
	switch {
	case w.BodyStructure == nil:
		// No structure arrived, so this provider did not look for a
		// signature. read checks the source itself (D6.2).
		msg.SignedHint = mail.SignedUnknown
	case signedStructure(w.BodyStructure, params) || body.marker:
		msg.SignedHint = mail.SignedYes
	case !body.cut && allTextDecoded(w.BodyStructure, body.decoded):
		msg.SignedHint = mail.SignedNo
	default:
		msg.SignedHint = mail.SignedUnknown
	}
	msg.Body = mail.CutBody(body.text, o.Offset, o.MaxChars)
	return &msg, nil
}

// readBody is the body that pickBody gives, with the values that Read
// needs for the signed hint.
type readBody struct {
	text    string
	removed int
	differ  bool
	marker  bool            // a decoded value holds the inline PGP marker
	cut     bool            // a value is isTruncated, or the answer lacks it
	decoded map[string]bool // the partIds of the values that arrived
}

// pickBody joins the values of the text/plain parts of textBody and of
// the text/html parts of htmlBody, and makes the choice of D4.2 with
// mime.PickBody (F3).
func pickBody(w emailWire, format string) readBody {
	b := readBody{decoded: map[string]bool{}}
	collect := func(parts []bodyPart, typ string) (string, bool) {
		var vals []string
		for _, part := range parts {
			if !strings.EqualFold(part.Type, typ) {
				continue
			}
			v, ok := w.BodyValues[part.PartID]
			if !ok {
				b.cut = true
				continue
			}
			if v.IsTruncated {
				b.cut = true
			}
			if mail.HasInlinePGP(v.Value) {
				b.marker = true
			}
			b.decoded[part.PartID] = true
			vals = append(vals, v.Value)
		}
		return strings.Join(vals, "\n"), len(vals) > 0
	}
	plain, hasPlain := collect(w.TextBody, "text/plain")
	html, hasHTML := collect(w.HTMLBody, "text/html")
	b.text, b.removed, b.differ = mime.PickBody(plain, html, hasPlain, hasHTML, strings.EqualFold(format, "html"))
	return b
}

// signedStructure reports whether the structure shows a signature that
// only the whole source can settle: a multipart/signed part, or an
// application/(x-)pkcs7-mime part, at any depth (D6.2). One shape is
// out: a message that is one top-level pkcs7-mime part that
// mail.SMIMEKindOf names SMIMEEnveloped, with params from the
// Content-Type header (DR1G.7). Any other pkcs7-mime part counts, so
// the check fails closed (IR1G.3).
func signedStructure(bs *bodyPart, params map[string]string) bool {
	if len(bs.SubParts) == 0 && mail.SMIMEKindOf(bs.Type, params) == mail.SMIMEEnveloped {
		return false
	}
	var walk func(*bodyPart) bool
	walk = func(part *bodyPart) bool {
		switch strings.ToLower(part.Type) {
		case "multipart/signed", "application/pkcs7-mime", "application/x-pkcs7-mime":
			return true
		}
		for i := range part.SubParts {
			if walk(&part.SubParts[i]) {
				return true
			}
		}
		return false
	}
	return walk(bs)
}

// allTextDecoded reports whether every text/plain and text/html leaf
// of the structure that is not an attachment is in decoded (DRV.4).
// Only then can Read say SignedNo.
func allTextDecoded(bs *bodyPart, decoded map[string]bool) bool {
	if len(bs.SubParts) > 0 {
		for i := range bs.SubParts {
			if !allTextDecoded(&bs.SubParts[i], decoded) {
				return false
			}
		}
		return true
	}
	switch strings.ToLower(bs.Type) {
	case "text/plain", "text/html":
	default:
		return true
	}
	if mime.IsAttachment(bs.Disposition, bs.Name) {
		return true
	}
	return decoded[bs.PartID]
}

// unfold joins the lines of a folded raw header value (RFC 5322
// §2.2.3) and trims it.
func unfold(raw string) string {
	return strings.TrimSpace(strings.NewReplacer("\r\n", "", "\n", "").Replace(raw))
}

// firstMessageID gives the first "<...>" token of a raw Message-ID
// value, or "".
func firstMessageID(raw string) string {
	if ids := mail.MessageIDs(raw); len(ids) > 0 {
		return ids[0]
	}
	return ""
}

// authBlock gives the Authentication-Results instances as header text,
// one "Authentication-Results:" field for each, as the IMAP header
// fetch gives it to the DKIM check (D6.2).
func authBlock(values []string) string {
	var b strings.Builder
	for _, v := range values {
		b.WriteString("Authentication-Results:")
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	return b.String()
}

// Thread gives the conversation of one message, oldest first, the
// newest maxThread messages at most (DS8.2). One batch gets the
// threadId of the message and, through a back-reference, the Thread;
// a second Email/get gives the rows, as Search does.
//
// arch: DS8.2
func (p *Provider) Thread(ctx context.Context, id string) (mail.ThreadResult, error) {
	if err := checkID(id); err != nil {
		return mail.ThreadResult{}, err
	}
	acc, err := p.accountID(ctx)
	if err != nil {
		return mail.ThreadResult{}, err
	}
	r, err := p.call(ctx,
		Invocation{Name: "Email/get", ID: "e", Args: map[string]any{
			"accountId": acc, "ids": []string{id}, "properties": []string{"threadId"},
		}},
		Invocation{Name: "Thread/get", ID: "t", Args: map[string]any{
			"accountId": acc, "#ids": resultRef("e", "Email/get", "/list/*/threadId"),
		}},
	)
	if err != nil {
		return mail.ThreadResult{}, err
	}
	var ea struct {
		List []emailWire `json:"list"`
	}
	if err := result(r, "e", "Email/get", &ea); err != nil {
		return mail.ThreadResult{}, err
	}
	if len(ea.List) == 0 {
		return mail.ThreadResult{}, errNoMessage
	}
	var ta struct {
		List []struct {
			ID       string   `json:"id"`
			EmailIDs []string `json:"emailIds"`
		} `json:"list"`
	}
	if err := result(r, "t", "Thread/get", &ta); err != nil {
		return mail.ThreadResult{}, err
	}
	ids := []string{id}
	for _, th := range ta.List {
		if th.ID == ea.List[0].ThreadID && len(th.EmailIDs) > 0 {
			ids = th.EmailIDs
		}
	}
	if len(ids) > maxThread {
		ids = ids[len(ids)-maxThread:]
	}
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return mail.ThreadResult{}, err
	}
	rows, err := p.getRows(ctx, acc, ids, tab)
	if err != nil {
		return mail.ThreadResult{}, err
	}
	out := mail.ThreadResult{Messages: make([]*mail.Message, len(rows))}
	for i := range rows {
		out.Messages[i] = &rows[i]
	}
	return out, nil
}

// Raw gives the whole RFC 5322 source, for export and for forward. It
// gets the blob of the email through the blob client, whose cap is
// MaxBlobBody (DS8.3). A message that the server says is larger fails
// before the download.
//
// arch: DS8.2, DS8.3
func (p *Provider) Raw(ctx context.Context, id string) ([]byte, error) {
	w, err := p.getOne(ctx, id, map[string]any{"properties": []string{"id", "blobId", "size"}})
	if err != nil {
		return nil, err
	}
	if w.Size > MaxBlobBody {
		return nil, fmt.Errorf("jmap: this message is larger than the limit of %d MB", MaxBlobBody>>20)
	}
	if w.BlobID == "" {
		return nil, errors.New("jmap: the server gave no blobId for this message")
	}
	rc, _, err := p.c.Download(ctx, w.BlobID, "message.eml", "message/rfc822")
	if err != nil {
		return nil, p.report(err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("jmap: download the message: %w", err)
	}
	return data, nil
}

// Attachment opens one attachment of a message. ref is the partId of
// the part, or its file name (C19). The blob comes through the blob
// client and its cap (DS8.3). The caller closes the reader.
//
// arch: DS8.2, DS8.3, C19
func (p *Provider) Attachment(ctx context.Context, id, ref string) (io.ReadCloser, mail.AttachmentInfo, error) {
	if ref == "" {
		return nil, mail.AttachmentInfo{}, errors.New("jmap: no attachment ref")
	}
	w, err := p.getOne(ctx, id, map[string]any{
		"properties":     []string{"id", "attachments"},
		"bodyProperties": partProperties,
	})
	if err != nil {
		return nil, mail.AttachmentInfo{}, err
	}
	part, ok := findPart(w.Attachments, ref)
	if !ok {
		return nil, mail.AttachmentInfo{}, errors.New("jmap: the message has no attachment with this ref; read the message for the list")
	}
	if part.BlobID == "" {
		return nil, mail.AttachmentInfo{}, errors.New("jmap: the server gave no blobId for this attachment")
	}
	name, typ := part.Name, part.Type
	if name == "" {
		name = "attachment"
	}
	if typ == "" {
		typ = "application/octet-stream"
	}
	rc, _, err := p.c.Download(ctx, part.BlobID, name, typ)
	if err != nil {
		return nil, mail.AttachmentInfo{}, p.report(err)
	}
	return rc, mail.AttachmentInfo{Filename: part.Name, ContentType: part.Type, Size: part.Size}, nil
}

// findPart gives the part with the partId ref, else the first part with
// the file name ref (C19).
func findPart(parts []bodyPart, ref string) (bodyPart, bool) {
	for _, part := range parts {
		if part.PartID == ref {
			return part, true
		}
	}
	for _, part := range parts {
		if part.Name != "" && part.Name == ref {
			return part, true
		}
	}
	return bodyPart{}, false
}

// identity is one Identity object (RFC 8621 §6). An Email of "*@d"
// allows each address in the domain d.
type identity struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// identityCache keeps the last Identity/get list for identityTTL on
// the wall clock. The zero value is empty and ready to use.
type identityCache struct {
	mu   sync.Mutex
	at   time.Time
	list []identity
	ok   bool
}

// get gives the list when it is younger than identityTTL at now. ok is
// false when the cache is empty or old. A negative age means the wall
// clock stepped back, so the list counts as old.
func (c *identityCache) get(now time.Time) ([]identity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ok {
		return nil, false
	}
	if age := now.Sub(c.at); age < 0 || age >= identityTTL {
		return nil, false
	}
	return c.list, true
}

// put keeps list as the answer of Identity/get at now.
func (c *identityCache) put(list []identity, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = list
	c.at = now
	c.ok = true
}

// listIdentities calls Identity/get, keeps the answer in the identity
// cache and gives it. The batch carries the submission capability
// (F1, IS8.3).
func (p *Provider) listIdentities(ctx context.Context) ([]identity, error) {
	acc, err := p.accountID(ctx)
	if err != nil {
		return nil, err
	}
	r, err := p.call(ctx, Invocation{Name: "Identity/get", ID: "i", Args: map[string]any{
		"accountId":  acc,
		"ids":        nil,
		"properties": []string{"id", "name", "email"},
	}})
	if err != nil {
		return nil, err
	}
	var ans struct {
		List []identity `json:"list"`
	}
	if err := result(r, "i", "Identity/get", &ans); err != nil {
		return nil, err
	}
	p.idents.put(ans.List, p.now())
	return ans.List, nil
}

// pickIdentity gives the identity whose email equals addr, in any
// case. When no email is equal, it gives the first identity "*@d"
// whose domain d equals the domain of addr.
func pickIdentity(list []identity, addr string) (identity, bool) {
	for _, id := range list {
		if strings.EqualFold(id.Email, addr) {
			return id, true
		}
	}
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return identity{}, false
	}
	for _, id := range list {
		if domain, ok := strings.CutPrefix(id.Email, "*@"); ok && strings.EqualFold(domain, addr[at+1:]) {
			return id, true
		}
	}
	return identity{}, false
}

// identityFor gives the identity of the from address addr (DS8.2a).
// It looks in the identity cache first. When the cached list has no
// match, it asks the server once more, because the identity can be
// younger than the cache. The error lists the identity emails
// (§3.13).
//
// arch: DS8.2a, IS8.3
func (p *Provider) identityFor(ctx context.Context, addr string) (identity, error) {
	list, cached := p.idents.get(p.now())
	if !cached {
		var err error
		if list, err = p.listIdentities(ctx); err != nil {
			return identity{}, err
		}
	}
	id, ok := pickIdentity(list, addr)
	if !ok && cached {
		var err error
		if list, err = p.listIdentities(ctx); err != nil {
			return identity{}, err
		}
		id, ok = pickIdentity(list, addr)
	}
	if ok {
		return id, nil
	}
	if len(list) == 0 {
		return identity{}, errors.New("jmap: the account has no sending identity on the server")
	}
	emails := make([]string, len(list))
	for i, id := range list {
		emails[i] = id.Email
	}
	return identity{}, fmt.Errorf("jmap: %q is not an identity of this account; the identities are: %s", addr, strings.Join(emails, ", "))
}

// fromAddress gives the from address of an outgoing message. An empty
// from means the account address.
func (p *Provider) fromAddress(from string) (emailAddress, error) {
	if strings.TrimSpace(from) == "" {
		if p.acct.Email == "" {
			return emailAddress{}, errors.New("jmap: this account has no email address; add one to accounts.toml")
		}
		return emailAddress{Email: p.acct.Email}, nil
	}
	a, err := gomail.ParseAddress(from)
	if err != nil {
		return emailAddress{}, fmt.Errorf("jmap: from address: %w", err)
	}
	return emailAddress{Name: a.Name, Email: a.Address}, nil
}

// setError is one SetError of a /set answer (RFC 8620 §5.3). Its
// description is free text of the server, so no error text shows it.
type setError struct {
	Type string `json:"type"`
}

// reason gives the type when it is an identifier (safeType).
func (e setError) reason() string {
	if t := safeType(e.Type); t != "" {
		return t
	}
	return "no reason given"
}

// setAnswer is the part of a /set answer (RFC 8620 §5.3) that
// SaveDraft and SendDraft read. A value of updated can be null.
type setAnswer struct {
	Created map[string]struct {
		ID string `json:"id"`
	} `json:"created"`
	NotCreated   map[string]setError `json:"notCreated"`
	Updated      map[string]any      `json:"updated"`
	NotUpdated   map[string]setError `json:"notUpdated"`
	Destroyed    []string            `json:"destroyed"`
	NotDestroyed map[string]setError `json:"notDestroyed"`
}

// readAttachment reads one attachment file. The read stops after
// guard.MaxAttachBytes, because the file can grow after
// guard.AttachPath checked it (M11).
func readAttachment(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: tools.callerAttachments checks a caller path with guard.AttachPath; addForward writes the other paths in its own temp dir
	if err != nil {
		return nil, fmt.Errorf("jmap: attachment: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, guard.MaxAttachBytes+1))
	if err != nil {
		return nil, fmt.Errorf("jmap: attachment: %w", err)
	}
	if len(data) > guard.MaxAttachBytes {
		return nil, fmt.Errorf("jmap: attachment %s is larger than the limit of %d MB", filepath.Base(path), guard.MaxAttachBytes>>20)
	}
	return data, nil
}

// attachmentType gives the media type of a file name from its
// extension, without parameters, else application/octet-stream (as
// mime.Build does for IMAP).
func attachmentType(name string) string {
	if guess := stdmime.TypeByExtension(filepath.Ext(name)); guess != "" {
		if t, _, err := stdmime.ParseMediaType(guess); err == nil {
			return t
		}
	}
	return "application/octet-stream"
}

// uploadAttachments uploads each file as a blob with its media type
// (F6, RFC 8620 §6.1) and gives the EmailBodyPart of each for the
// attachments of Email/set create. The file name is the base name of
// the path that guard.AttachPath gave, never caller text (§3.14).
//
// arch: DS8.2, F6
func (p *Provider) uploadAttachments(ctx context.Context, paths []string) ([]map[string]any, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	s, err := p.c.Session(ctx)
	if err != nil {
		return nil, p.report(err)
	}
	out := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		data, err := readAttachment(path)
		if err != nil {
			return nil, err
		}
		name := filepath.Base(path)
		if s.MaxSizeUpload > 0 && int64(len(data)) > s.MaxSizeUpload {
			return nil, fmt.Errorf("jmap: attachment %s is larger than the upload limit of the server (%d bytes)", name, s.MaxSizeUpload)
		}
		typ := attachmentType(name)
		blobID, err := p.c.Upload(ctx, typ, bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, p.report(err)
		}
		out = append(out, map[string]any{
			"blobId":      blobID,
			"type":        typ,
			"name":        name,
			"disposition": "attachment",
		})
	}
	return out, nil
}

// draftObject gives the Email object of Email/set create for m
// (DS8.2): the mailbox with the role drafts, the keywords $draft and
// $seen ($seen keeps the draft out of the unread count, as on IMAP),
// the addresses, the subject, the reply headers and the body as
// textBody and htmlBody with their values (RFC 8621 §4.6).
func draftObject(m *mail.Outgoing, from emailAddress, to, cc, bcc []emailAddress, drafts string, atts []map[string]any) map[string]any {
	obj := map[string]any{
		"mailboxIds": map[string]bool{drafts: true},
		"keywords":   map[string]bool{keywordDraft: true, keywordSeen: true},
		"from":       []emailAddress{from},
		"subject":    m.Subject,
	}
	for key, list := range map[string][]emailAddress{"to": to, "cc": cc, "bcc": bcc} {
		if len(list) > 0 {
			obj[key] = list
		}
	}
	if ids := bareMessageIDs([]string{m.InReplyTo}); len(ids) > 0 {
		obj["inReplyTo"] = ids
	}
	if ids := bareMessageIDs(m.References); len(ids) > 0 {
		obj["references"] = ids
	}
	values := map[string]any{}
	if m.Text != "" || m.HTML == "" {
		obj["textBody"] = []map[string]any{{"partId": "text", "type": "text/plain"}}
		values["text"] = map[string]any{"value": m.Text}
	}
	if m.HTML != "" {
		obj["htmlBody"] = []map[string]any{{"partId": "html", "type": "text/html"}}
		values["html"] = map[string]any{"value": m.HTML}
	}
	obj["bodyValues"] = values
	if len(atts) > 0 {
		obj["attachments"] = atts
	}
	return obj
}

// SaveDraft stores one message as a draft and gives its id (DS8.2).
// The from check of DS8.2a runs first, and nothing goes to the server
// before it passes. Then each attachment goes up as a blob (F6), and
// one Email/set creates the draft in the mailbox with the role drafts,
// with the keywords $draft and $seen. replaceID is the draft that this
// one takes the place of, or "": it must carry $draft, and the same
// Email/set destroys it. When the destroy fails, the error names the
// new id, because the text is saved and the older draft is still
// there (as on IMAP).
//
// arch: DS8.2, DS8.2a, IS8.3, F6
func (p *Provider) SaveDraft(ctx context.Context, m *mail.Outgoing, replaceID string) (string, error) {
	if m == nil {
		return "", errors.New("jmap: save draft: no message")
	}
	from, err := p.fromAddress(m.From)
	if err != nil {
		return "", err
	}
	ident, err := p.identityFor(ctx, from.Email)
	if err != nil {
		return "", err
	}
	if from.Name == "" {
		from.Name = ident.Name
	}
	var lists [3][]emailAddress
	for i, in := range [][]string{m.To, m.Cc, m.Bcc} {
		if lists[i], err = wireAddresses(in); err != nil {
			return "", err
		}
	}
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return "", err
	}
	drafts := tab.roleID("drafts")
	if drafts == "" {
		return "", errors.New("jmap: the account has no mailbox with the role drafts")
	}
	if replaceID != "" {
		old, err := p.getOne(ctx, replaceID, map[string]any{"properties": []string{"id", "keywords"}})
		if err != nil {
			return "", err
		}
		if !flagsOf(old.Keywords).Draft {
			return "", fmt.Errorf("jmap: message %s is not a draft", replaceID)
		}
	}
	atts, err := p.uploadAttachments(ctx, m.Attachments)
	if err != nil {
		return "", err
	}
	acc, err := p.accountID(ctx)
	if err != nil {
		return "", err
	}
	args := map[string]any{
		"accountId": acc,
		"create":    map[string]any{"draft": draftObject(m, from, lists[0], lists[1], lists[2], drafts, atts)},
	}
	if replaceID != "" {
		args["destroy"] = []string{replaceID}
	}
	r, err := p.call(ctx, Invocation{Name: "Email/set", ID: "s", Args: args})
	if err != nil {
		return "", err
	}
	var ans setAnswer
	if err := result(r, "s", "Email/set", &ans); err != nil {
		return "", err
	}
	created, ok := ans.Created["draft"]
	if !ok || created.ID == "" {
		return "", fmt.Errorf("jmap: the server did not save the draft (%s)", ans.NotCreated["draft"].reason())
	}
	if e, failed := ans.NotDestroyed[replaceID]; replaceID != "" && failed {
		return "", fmt.Errorf("jmap: the draft is saved as %s, but the older draft %s did not go away (%s)", created.ID, replaceID, e.reason())
	}
	return created.ID, nil
}

// SendDraft sends a draft that SaveDraft or another client stored
// (DS8.2). The message must carry $draft. Its first from address must
// be the email of an identity (DS8.2a, the 10-minute identity cache).
// One EmailSubmission/set creates the submission with that identityId
// (IS8.3); its onSuccessUpdateEmail takes the email out of the mailbox
// with the role drafts, puts it into the one with the role sent and
// drops $draft (F2). The server sends the message and files it, so no
// second copy goes up. With no sent mailbox, the patch only drops
// $draft, so the email keeps one mailbox at least (IS8.2), and the
// result has a warning. SendResult.ID is the email id.
//
// arch: DS8.2, DS8.2a, IS8.3, IS8.2, F1, F2
func (p *Provider) SendDraft(ctx context.Context, id string) (mail.SendResult, error) {
	w, err := p.getOne(ctx, id, map[string]any{"properties": []string{"id", "from", "keywords", "mailboxIds"}})
	if err != nil {
		return mail.SendResult{}, err
	}
	if !flagsOf(w.Keywords).Draft {
		return mail.SendResult{}, fmt.Errorf("jmap: message %s is not a draft", id)
	}
	if len(w.From) == 0 || w.From[0].Email == "" {
		return mail.SendResult{}, errors.New("jmap: this draft has no from address")
	}
	ident, err := p.identityFor(ctx, w.From[0].Email)
	if err != nil {
		return mail.SendResult{}, err
	}
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return mail.SendResult{}, err
	}
	sent := tab.roleID("sent")
	patch := map[string]any{"keywords/" + keywordDraft: nil}
	if sent != "" {
		patch["mailboxIds/"+sent] = true
		if drafts := tab.roleID("drafts"); drafts != "" {
			patch["mailboxIds/"+drafts] = nil
		}
	}
	acc, err := p.accountID(ctx)
	if err != nil {
		return mail.SendResult{}, err
	}
	r, err := p.call(ctx, Invocation{Name: "EmailSubmission/set", ID: "s", Args: map[string]any{
		"accountId":            acc,
		"create":               map[string]any{"send": map[string]any{"identityId": ident.ID, "emailId": id}},
		"onSuccessUpdateEmail": map[string]any{"#send": patch},
	}})
	if err != nil {
		return mail.SendResult{}, err
	}
	var sa setAnswer
	if err := result(r, "s", "EmailSubmission/set", &sa); err != nil {
		return mail.SendResult{}, err
	}
	if _, ok := sa.Created["send"]; !ok {
		return mail.SendResult{}, fmt.Errorf("jmap: the server did not send the draft (%s)", sa.NotCreated["send"].reason())
	}
	// The mail left. Nothing below changes Sent (M3).
	res := mail.SendResult{ID: id, Sent: true}
	if sent == "" {
		res.Warning = "the message was sent, but the account has no mailbox with the role sent, so it stays where the draft was"
		return res, nil
	}
	// RFC 8621 §7.5: the update comes back as an Email/set answer with
	// the call id of the submission.
	var ea setAnswer
	switch err := result(r, "s", "Email/set", &ea); {
	case err != nil:
		res.Warning = "the message was sent, but the server did not report the move to Sent"
	case ea.NotUpdated[id].Type != "":
		res.Warning = "the message was sent, but the server did not move it to Sent (" + ea.NotUpdated[id].reason() + ")"
	default:
		if _, ok := ea.Updated[id]; ok {
			res.SavedToSent = true
		} else {
			res.Warning = "the message was sent, but the server did not report the move to Sent"
		}
	}
	return res, nil
}

// modifyProperties are the Email properties that Modify reads before
// and after a change (DS8.2).
var modifyProperties = []string{"id", "keywords", "mailboxIds"}

// errNoMailbox is the fixed text of IS8.2: the change would leave the
// message in no mailbox. A JMAP message that is in no mailbox is lost
// to every client, so the patch does not go to the server.
var errNoMailbox = errors.New("jmap: this change would leave the message in no mailbox; a JMAP message stays in one mailbox at least, so nothing changed")

// getAnswer is the part of an Email/get answer that Modify reads.
type getAnswer struct {
	List []emailWire `json:"list"`
}

// Modify applies one change to a set of messages and gives one row per
// message that changed (DS8.2). It gives the rows of ModifyDetail.
//
// arch: DS8.2, DS8.2c, DS78.5, IS8.2
func (p *Provider) Modify(ctx context.Context, ids []string, c mail.Change) ([]mail.Applied, error) {
	res, err := p.ModifyDetail(ctx, ids, c)
	return res.Applied, err
}

// ModifyDetail applies one change and names the gone messages (DS8.2).
// One batch holds three calls: Email/get of the keywords and the
// mailboxIds before, Email/set update with one patch for each id, and
// Email/get after. read and starred set or clear $seen and $flagged; a
// label is a keyword (DS8.2b). archive and trash set mailboxIds to
// exactly the mailbox with the role archive or trash, move_to to
// exactly the mailbox of that folder, and RestoreFolders (undo) to
// exactly the mailboxes in it that the account still has. So a patch
// always names one mailbox at least; a patch with no mailbox is
// refused with errNoMailbox before the server sees it (DS8.2c, IS8.2).
//
// The id stays the same on a move, so each row of a mailbox change has
// FoldersBefore and FoldersAfter: the sorted mailbox ids (DS78.5,
// IS8.4). An empty change sends no Email/set; each row then has the
// current flags in Before and After and the current mailboxes in
// FoldersAfter, the state read of undo (G3). An id that Email/get or
// Email/set does not find is in Gone and has no row (D5.4). When the
// server refuses the update of one id for another reason, the rows of
// the other ids come back with the error, so the undo journal records
// what changed (IRV.9). When the read after the change does not give
// an id that changed, its row has the state that the patch gives.
//
// A move out of the junk mailbox or into it also changes $junk and
// $notjunk (DS8.2d). That rule needs the mailboxes of each message
// before the patch, so the Email/get before then goes alone, and
// Email/set and the Email/get after follow in a second request.
//
// arch: DS8.2, DS8.2b, DS8.2c, DS8.2d, DS78.5, IS8.2, IS8.4, D5.4
func (p *Provider) ModifyDetail(ctx context.Context, ids []string, c mail.Change) (mail.ModifyResult, error) {
	if len(ids) == 0 {
		return mail.ModifyResult{}, errors.New("jmap: modify needs at least one message id")
	}
	var uniq []string
	for _, id := range ids {
		if err := checkID(id); err != nil {
			return mail.ModifyResult{}, err
		}
		if !slices.Contains(uniq, id) {
			uniq = append(uniq, id)
		}
	}
	patch, moves, err := p.patchOf(ctx, c)
	if err != nil {
		return mail.ModifyResult{}, err
	}
	acc, err := p.accountID(ctx)
	if err != nil {
		return mail.ModifyResult{}, err
	}
	get := func(callID string) Invocation {
		return Invocation{Name: "Email/get", ID: callID, Args: map[string]any{
			"accountId": acc, "ids": uniq, "properties": modifyProperties,
		}}
	}
	junk, err := p.junkOf(ctx, c, patch)
	if err != nil {
		return mail.ModifyResult{}, err
	}
	// patches holds the patch of each id. It is patch, plus the junk
	// keywords for a message that the junk rule touches (DS8.2d).
	patches := make(map[string]map[string]any, len(uniq))
	setCalls := func(beforeOf map[string]emailWire) []Invocation {
		update := make(map[string]any, len(uniq))
		for _, id := range uniq {
			patches[id] = junk.patch(patch, beforeOf[id])
			update[id] = patches[id]
		}
		return []Invocation{
			{Name: "Email/set", ID: "s", Args: map[string]any{"accountId": acc, "update": update}},
			get("a"),
		}
	}
	// The junk rule needs the mailboxes of each message before the
	// patch, so the read before goes to the server on its own. Else
	// one batch holds the three calls.
	calls := []Invocation{get("b")}
	if patch != nil && !junk.on {
		calls = append(calls, setCalls(nil)...)
	}
	r, err := p.call(ctx, calls...)
	if err != nil {
		return mail.ModifyResult{}, err
	}
	var before getAnswer
	if err := result(r, "b", "Email/get", &before); err != nil {
		return mail.ModifyResult{}, err
	}
	beforeOf := make(map[string]emailWire, len(before.List))
	for _, w := range before.List {
		beforeOf[w.ID] = w
	}
	if patch != nil && junk.on {
		if r, err = p.call(ctx, setCalls(beforeOf)...); err != nil {
			return mail.ModifyResult{}, err
		}
	}

	var res mail.ModifyResult
	if patch == nil {
		for _, id := range uniq {
			w, ok := beforeOf[id]
			if !ok {
				res.Gone = append(res.Gone, id)
				continue
			}
			f := flagsOf(w.Keywords)
			res.Applied = append(res.Applied, mail.Applied{ID: id, Before: f, After: f, FoldersAfter: mailboxList(w.MailboxIDs)})
		}
		return res, nil
	}

	var set setAnswer
	if err := result(r, "s", "Email/set", &set); err != nil {
		return mail.ModifyResult{}, err
	}
	// A failed read after the change leaves afterOf empty: each row
	// then has the state that the patch gives.
	var after getAnswer
	_ = result(r, "a", "Email/get", &after)
	afterOf := make(map[string]emailWire, len(after.List))
	for _, w := range after.List {
		afterOf[w.ID] = w
	}
	var failed []string
	for _, id := range uniq {
		b, ok := beforeOf[id]
		if !ok {
			res.Gone = append(res.Gone, id)
			continue
		}
		if e, refused := set.NotUpdated[id]; refused {
			if e.Type == "notFound" {
				res.Gone = append(res.Gone, id)
			} else {
				failed = append(failed, id+" ("+e.reason()+")")
			}
			continue
		}
		if _, done := set.Updated[id]; !done {
			failed = append(failed, id+" (no answer)")
			continue
		}
		a, ok := afterOf[id]
		if !ok {
			a = patched(b, patches[id])
		}
		row := mail.Applied{ID: id, Before: flagsOf(b.Keywords), After: flagsOf(a.Keywords)}
		if moves {
			row.FoldersBefore = mailboxList(b.MailboxIDs)
			row.FoldersAfter = mailboxList(a.MailboxIDs)
		}
		res.Applied = append(res.Applied, row)
	}
	if len(failed) > 0 {
		return res, fmt.Errorf("jmap: the server did not change %s", strings.Join(failed, ", "))
	}
	return res, nil
}

// patchOf gives the PatchObject of c (RFC 8620 §5.3), or nil when c
// changes nothing. moves is true when the patch sets mailboxIds. Only
// one of move_to, archive, trash and RestoreFolders is taken: a silent
// choice between two targets would file mail where nobody asked. For
// the same reason, a label in add_labels and in remove_labels, in any
// case, is refused with the Gmail text.
//
// arch: DS8.2, DS8.2b, DS8.2c, IS8.2
func (p *Provider) patchOf(ctx context.Context, c mail.Change) (patch map[string]any, moves bool, err error) {
	n := 0
	for _, on := range []bool{c.MoveTo != "", c.Archive, c.Trash, len(c.RestoreFolders) > 0} {
		if on {
			n++
		}
	}
	if n > 1 {
		return nil, false, errors.New("jmap: modify takes one of move_to, archive or trash, not more")
	}
	patch = map[string]any{}
	set := func(key string, on bool) {
		if on {
			patch["keywords/"+key] = true
		} else {
			patch["keywords/"+key] = nil
		}
	}
	if c.Read != nil {
		set(keywordSeen, *c.Read)
	}
	if c.Starred != nil {
		set(keywordFlagged, *c.Starred)
	}
	for _, label := range c.RemoveLabels {
		if slices.ContainsFunc(c.AddLabels, func(a string) bool { return strings.EqualFold(a, label) }) {
			return nil, false, fmt.Errorf("jmap: the change both adds and removes the label %q", label)
		}
	}
	for i, labels := range [][]string{c.AddLabels, c.RemoveLabels} {
		for _, label := range labels {
			key, err := labelKeyword(label)
			if err != nil {
				return nil, false, err
			}
			set(key, i == 0)
		}
	}
	var target []string
	switch {
	case c.Archive, c.Trash:
		role := "archive"
		if c.Trash {
			role = "trash"
		}
		id, err := p.roleMailbox(ctx, role)
		if err != nil {
			return nil, false, err
		}
		target = []string{id}
	case c.MoveTo != "":
		id, _, err := p.mailboxID(ctx, c.MoveTo)
		if err != nil {
			return nil, false, err
		}
		target = []string{id}
	case len(c.RestoreFolders) > 0:
		if target, err = p.knownMailboxes(ctx, c.RestoreFolders); err != nil {
			return nil, false, err
		}
	}
	if n == 1 {
		if len(target) == 0 {
			return nil, false, errNoMailbox
		}
		boxes := make(map[string]bool, len(target))
		for _, id := range target {
			boxes[id] = true
		}
		patch["mailboxIds"] = boxes
	}
	if len(patch) == 0 {
		return nil, false, nil
	}
	return patch, n == 1, nil
}

// junkMove is the junk rule of one change (DS8.2d): the junk and
// trash mailboxes and the target of the move. on is false when the
// rule touches no message of the change.
type junkMove struct {
	c                 mail.Change
	junkBox, trashBox string
	target            string
	on                bool
}

// junkOf gives the junk rule of c, whose PatchObject is patch. The rule
// is on only for a move (move_to, archive or trash) on an account
// with a junk mailbox, and only when mail.JunkRule can set a verdict
// for one source at least. An undo (RestoreFolders) never has it on.
//
// arch: DS8.2d
func (p *Provider) junkOf(ctx context.Context, c mail.Change, patch map[string]any) (junkMove, error) {
	boxes, ok := patch["mailboxIds"].(map[string]bool)
	if !ok || len(c.RestoreFolders) > 0 {
		return junkMove{}, nil
	}
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return junkMove{}, err
	}
	j := junkMove{c: c, junkBox: tab.roleID("junk"), trashBox: tab.roleID("trash")}
	if j.junkBox == "" {
		return junkMove{}, nil
	}
	for id := range boxes {
		j.target = id
	}
	toJunk, toTrash := j.target == j.junkBox, j.target == j.trashBox
	_, fromJunk := mail.JunkRule(c, true, toJunk, toTrash)
	_, fromOther := mail.JunkRule(c, false, toJunk, toTrash)
	j.on = fromJunk || fromOther
	return j, nil
}

// patch gives the patch of one message: base, plus the junk keywords
// when the rule sets a verdict for the message w. It gives base itself
// when the rule is off or sets nothing, and a copy when it adds keys.
//
// arch: DS8.2d
func (j junkMove) patch(base map[string]any, w emailWire) map[string]any {
	if !j.on {
		return base
	}
	junk, set := mail.JunkRule(j.c, w.MailboxIDs[j.junkBox], j.target == j.junkBox, j.target == j.trashBox)
	if !set {
		return base
	}
	out := make(map[string]any, len(base)+2)
	for k, v := range base {
		out[k] = v
	}
	on, off := mail.KeywordJunk, mail.KeywordNotJunk
	if !junk {
		on, off = off, on
	}
	out["keywords/"+on] = true
	out["keywords/"+off] = nil
	return out
}

// roleMailbox gives the id of the mailbox with the JMAP role. When the
// cached table has none, it asks the server once more. With no such
// mailbox the error gives a hint (F8).
//
// arch: DS8.2, F8
func (p *Provider) roleMailbox(ctx context.Context, role string) (string, error) {
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return "", err
	}
	if id := tab.roleID(role); id != "" {
		return id, nil
	}
	if tab, err = p.listMailboxes(ctx); err != nil {
		return "", err
	}
	if id := tab.roleID(role); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("jmap: the account has no mailbox with the role %s; give the folder with move_to, or give a mailbox the role %s in a mail client", role, role)
}

// knownMailboxes gives the ids of list that the account has, sorted
// and without repeats. When the cached table does not know an id, it
// asks the server once more. An id that the account no longer has is
// left out: undo puts the message back into the mailboxes that are
// still there. An empty result makes patchOf refuse (IS8.2).
//
// arch: DS78.5, IS8.2
func (p *Provider) knownMailboxes(ctx context.Context, list []string) ([]string, error) {
	for _, id := range list {
		if err := checkID(id); err != nil {
			return nil, err
		}
	}
	tab, err := p.cachedMailboxes(ctx)
	if err != nil {
		return nil, err
	}
	known := func(tab *mailboxTable) []string {
		var out []string
		for _, id := range list {
			if _, ok := tab.path[id]; ok && !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
		slices.Sort(out)
		return out
	}
	out := known(tab)
	if len(out) < len(list) {
		if tab, err = p.listMailboxes(ctx); err != nil {
			return nil, err
		}
		out = known(tab)
	}
	return out, nil
}

// patched gives w with patch applied: the keywords of the paths
// "keywords/<key>" and the whole mailboxIds. It is the state of a row
// when the read after the change does not give the email.
func patched(w emailWire, patch map[string]any) emailWire {
	kw := make(map[string]bool, len(w.Keywords))
	for k, v := range w.Keywords {
		kw[k] = v
	}
	for path, v := range patch {
		if key, ok := strings.CutPrefix(path, "keywords/"); ok {
			if v == nil {
				delete(kw, pointerUnescape.Replace(key))
			} else {
				kw[pointerUnescape.Replace(key)] = true
			}
		}
	}
	w.Keywords = kw
	if boxes, ok := patch["mailboxIds"].(map[string]bool); ok {
		w.MailboxIDs = boxes
	}
	return w
}

// splitPath gives the parent path and the last name of a folder path
// with "/" between the names. Each name must hold text.
func splitPath(name string) (parent, leaf string, err error) {
	for _, part := range strings.Split(name, "/") {
		if strings.TrimSpace(part) == "" {
			return "", "", fmt.Errorf("jmap: the folder name %q needs a name between each /", name)
		}
	}
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[:i], name[i+1:], nil
	}
	return "", name, nil
}

// parentID gives the id of the parent folder path, or nil for the top
// level.
func parentID(tab *mailboxTable, parent string) (any, error) {
	if parent == "" {
		return nil, nil
	}
	id, ok, err := tab.resolve(parent)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("jmap: the account has no folder %q; create it first", parent)
	}
	return id, nil
}

// mailboxSet sends one Mailbox/set and gives its answer. The mailbox
// cache is dropped after the call, because the tree can have changed.
func (p *Provider) mailboxSet(ctx context.Context, args map[string]any) (setAnswer, error) {
	acc, err := p.accountID(ctx)
	if err != nil {
		return setAnswer{}, err
	}
	args["accountId"] = acc
	r, err := p.call(ctx, Invocation{Name: "Mailbox/set", ID: "m", Args: args})
	p.boxes.drop()
	if err != nil {
		return setAnswer{}, err
	}
	var ans setAnswer
	if err := result(r, "m", "Mailbox/set", &ans); err != nil {
		return setAnswer{}, err
	}
	return ans, nil
}

// CreateFolder makes one mailbox with Mailbox/set create (DS8.2). The
// name is a path with "/" between the names; the parent path must
// exist.
//
// arch: DS8.2
func (p *Provider) CreateFolder(ctx context.Context, name string) error {
	parent, leaf, err := splitPath(name)
	if err != nil {
		return err
	}
	tab, err := p.listMailboxes(ctx)
	if err != nil {
		return err
	}
	if _, ok, _ := tab.resolve(name); ok {
		return fmt.Errorf("jmap: the account already has a folder %q", name)
	}
	pid, err := parentID(tab, parent)
	if err != nil {
		return err
	}
	ans, err := p.mailboxSet(ctx, map[string]any{
		"create": map[string]any{"new": map[string]any{"name": leaf, "parentId": pid}},
	})
	if err != nil {
		return err
	}
	if _, ok := ans.Created["new"]; !ok {
		return fmt.Errorf("jmap: the server did not create the folder %q (%s)", name, ans.NotCreated["new"].reason())
	}
	return nil
}

// RenameFolder gives one mailbox a new name and parent with
// Mailbox/set update (DS8.2). The mailbox keeps its id and its role,
// so a move record of undo stays good.
//
// arch: DS8.2
func (p *Provider) RenameFolder(ctx context.Context, from, to string) error {
	parent, leaf, err := splitPath(to)
	if err != nil {
		return err
	}
	tab, err := p.listMailboxes(ctx)
	if err != nil {
		return err
	}
	src, ok, err := tab.resolve(from)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("jmap: the account has no folder %q", from)
	}
	if _, ok, _ := tab.resolve(to); ok {
		return fmt.Errorf("jmap: the account already has a folder %q", to)
	}
	pid, err := parentID(tab, parent)
	if err != nil {
		return err
	}
	ans, err := p.mailboxSet(ctx, map[string]any{
		"update": map[string]any{src: map[string]any{"name": leaf, "parentId": pid}},
	})
	if err != nil {
		return err
	}
	if _, ok := ans.Updated[src]; !ok {
		return fmt.Errorf("jmap: the server did not rename the folder %q (%s)", from, ans.NotUpdated[src].reason())
	}
	return nil
}

// DeleteFolder removes one empty mailbox with Mailbox/set destroy
// (DS8.2). It refuses a mailbox with a role, because the send and
// modify tools write into it, and a mailbox that holds messages,
// because a delete cannot be undone. onDestroyRemoveEmails is false,
// so the server also refuses a mailbox that got a message since the
// read.
//
// arch: DS8.2
func (p *Provider) DeleteFolder(ctx context.Context, name string) error {
	tab, err := p.listMailboxes(ctx)
	if err != nil {
		return err
	}
	id, ok, err := tab.resolve(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("jmap: the account has no folder %q", name)
	}
	for _, m := range tab.list {
		if m.ID != id {
			continue
		}
		if m.Role != "" {
			return fmt.Errorf("jmap: %q has a role (%s), and a mailbox with a role is not deleted", name, setError{Type: m.Role}.reason())
		}
		if m.TotalEmails > 0 {
			return fmt.Errorf("jmap: %q holds %d messages; move them out first, because a delete cannot be undone", name, m.TotalEmails)
		}
	}
	ans, err := p.mailboxSet(ctx, map[string]any{
		"destroy":               []string{id},
		"onDestroyRemoveEmails": false,
	})
	if err != nil {
		return err
	}
	if !slices.Contains(ans.Destroyed, id) {
		return fmt.Errorf("jmap: the server did not delete the folder %q (%s)", name, ans.NotDestroyed[id].reason())
	}
	return nil
}

// capabilityNames are the session capabilities that the report names,
// in the order of DS78.4.
var capabilityNames = []struct{ uri, name string }{
	{usingCore, "core"},
	{usingMail, "mail"},
	{usingSubmission, "submission"},
}

// Caps gives the capability report of DS78.4: Kind "jmap" and one fact
// on each line. The facts come from the session, Mailbox/get and
// Identity/get. Without the submission capability no Identity/get is
// sent, because the server would refuse the whole call.
//
// arch: DS78.4, DS8.2
func (p *Provider) Caps(ctx context.Context) (mail.Caps, error) {
	s, err := p.c.Session(ctx)
	if err != nil {
		return mail.Caps{}, p.report(err)
	}
	var names []string
	for _, c := range capabilityNames {
		if _, ok := s.Capabilities[c.uri]; ok {
			names = append(names, c.name)
		}
	}
	tab, err := p.listMailboxes(ctx)
	if err != nil {
		return mail.Caps{}, err
	}
	idents := "identities: none (the server has no submission capability)"
	if _, ok := s.Capabilities[usingSubmission]; ok {
		list, err := p.listIdentities(ctx)
		if err != nil {
			return mail.Caps{}, err
		}
		idents = fmt.Sprintf("identities: %d", len(list))
	}
	upload := "maxSizeUpload: not given"
	if s.MaxSizeUpload > 0 {
		upload = fmt.Sprintf("maxSizeUpload: %d", s.MaxSizeUpload)
	}
	return mail.Caps{Kind: "jmap", Lines: []string{
		"session: ok",
		"capabilities: " + strings.Join(names, ", "),
		fmt.Sprintf("mailboxes: %d", len(tab.list)),
		idents,
		upload,
	}}, nil
}
