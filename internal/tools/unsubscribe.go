// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The unsubscribe tool of S9 (DS9.3). It reads the RFC 2369
// List-Unsubscribe header of each message id and does one of four
// things: an RFC 8058 one-click POST through the guarded client, a
// draft for a mailto URL, a link for the person, or nothing. It never
// sends mail (G19, IS9.6) and never makes a GET (IS9.1). A one-click
// POST goes out only after the human accepts one question for the
// call, through elicitation or MRTR (DU8.1).

package tools

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	netmail "net/mail"
	"net/url"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// MaxUnsubscribeIDs is the id limit of one unsubscribe call (DS9.3).
const MaxUnsubscribeIDs = 50

// unsubMaxIDsText is the public text of a call with more ids than
// [MaxUnsubscribeIDs]. A test holds its number equal to the limit.
//
// arch: DU6.2, DU12.3
const unsubMaxIDsText = "ids: one call takes 50 ids at most"

// UnsubscribeIn is the input of the unsubscribe tool. The model gives
// message ids only, never a URL: every URL comes from a header of one
// of these messages (IS9.1).
//
// arch: DS9.3
type UnsubscribeIn struct {
	Account string   `json:"account"`
	IDs     []string `json:"ids" jsonschema:"max 50"`
}

// UnsubscribeRow is the result for one id. Method is one of
// one_click, draft, link or none. Status is one of done, draft_saved,
// see_link, not_authenticated, no_header, declined or failed. Both are
// words of the strict kind word (no space, no hyphen). declined is a
// one-click row whose POST the human did not accept (DU8.1).
//
// Zones (DU5.1, DU5.6): Index (the place of the id in the input), ID
// (only when [normalizeID] accepts it, in its new form), Method,
// Status, DraftID and Note are outside. URL is sender text, so it
// sits in one fence in the named field Untrusted. It is not an
// embedded struct: jsonschema-go flattens an embedded struct with a
// JSON tag, and the SDK then refuses the output (DU12.2).
//
// arch: DS9.3, DU5.1, DU5.6, DU3.2, DU12.2
type UnsubscribeRow struct {
	Index     int            `json:"index"`
	ID        string         `json:"id,omitempty" strict:"id"`
	Method    string         `json:"method" strict:"word"`
	Status    string         `json:"status" strict:"word"`
	DraftID   string         `json:"draft_id,omitempty" strict:"id"`
	Note      string         `json:"note,omitempty" strict:"note"`
	Untrusted UnsubUntrusted `json:"untrusted,omitzero"`
}

// UnsubUntrusted is the untrusted zone of a row: the URL of a
// List-Unsubscribe header, in a fence of the nonce of the response.
//
// arch: DU5.1, DU5.6
type UnsubUntrusted struct {
	URL string `json:"url,omitempty"`
}

// UnsubscribeOut is the result of the unsubscribe tool: one row for
// each id, in input order. Head is outside; every row has the zones
// of [UnsubscribeRow].
//
// arch: DS9.3, DU5.1
type UnsubscribeOut struct {
	Head
	Rows []UnsubscribeRow `json:"rows"`
}

// The words of UnsubscribeRow.Method and UnsubscribeRow.Status.
const (
	unsubMethodOneClick = "one_click"
	unsubMethodDraft    = "draft"
	unsubMethodLink     = "link"
	unsubMethodNone     = "none"

	unsubStatusDone     = "done"
	unsubStatusDraft    = "draft_saved"
	unsubStatusSeeLink  = "see_link"
	unsubStatusNoAuth   = "not_authenticated"
	unsubStatusNoHeader = "no_header"
	unsubStatusFailed   = "failed"
	unsubStatusDeclined = "declined"
)

// The two header names that the tool reads (RFC 2369, RFC 8058).
const (
	hdrListUnsubscribe     = "List-Unsubscribe"
	hdrListUnsubscribePost = "List-Unsubscribe-Post"
)

// oneClickBody is the only RFC 8058 POST body and the only value of
// List-Unsubscribe-Post that permits a POST.
const oneClickBody = "List-Unsubscribe=One-Click"

// The fixed notes of a row. None of them holds sender text.
const (
	unsubNoteNoAuth     = "the message has no dkim=pass from the configured authserv_id for the From domain, so no one-click POST was sent; open the link if you trust it"
	unsubNoteNoURL      = "the List-Unsubscribe header has no https or mailto URL"
	unsubNoteReadFailed = "the message could not be read"
	unsubNoteDraftFail  = "the mailto URL could not be made into a draft"
	unsubNotePostFailed = "the one-click POST failed or was redirected; open the link"
	unsubNoteTimeUp     = "the call ran out of time before this id; run it again for this id"
	unsubNoteDraftSend  = "the draft is not sent; send it with the send tool"
	unsubNoteDeclined   = "not sent: the human did not confirm; open the link"
)

// errUnsubNoElicitation is the fixed refusal for a client that cannot
// ask the human about a one-click POST. Like [errBulkNoElicitation],
// it does not name the config key, because the model reads this text
// and only the human may turn the question off.
//
// arch: DU8.1
var errUnsubNoElicitation = public("refused", "this client cannot ask the human to confirm a one-click unsubscribe, so nothing was sent and no draft was saved; the human can open the unsubscribe link in a mail program")

// unsubSchema is the requested schema of the one-click question. It
// has the field apply of the bulk question, so [bulkOutcome] reads the
// answer. It has no remember field: no session grant covers a POST.
//
// arch: DU8.1
var unsubSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		bulkField: map[string]any{
			"type":        "boolean",
			"title":       "Send the unsubscribe requests",
			"description": "Set to true to send the one-click POSTs above.",
		},
	},
	"required": []string{bulkField},
}

// unsubscribeTool holds the handler and its two seams. client is the
// guarded client that post uses in production; it is a field so that
// TestUnsubscribe_ProductionClientIsGuarded can check it (DS9.12).
// pending keeps each open one-click question of the MRTR path
// (DU8.1); its zero value works.
type unsubscribeTool struct {
	mail    Mail
	draft   *draftTool
	client  *http.Client
	post    func(ctx context.Context, rawURL string) (status int, err error)
	dkim    func(msg *mail.Message, cfg verify.Config) bool
	pending pendingStore[pendingUnsub]
}

// pendingUnsub is the record of one open one-click question on the
// MRTR path. The retry must give the same session, account and ids.
// steps is the plan that the question showed, so the retry posts to
// the URLs that the human saw and reads no message again. The steps
// hold plain URLs with no fence, so the record keeps no fence and no
// nonce (INV-6).
//
// arch: DU8.1, INV-6
type pendingUnsub struct {
	session *mcp.ServerSession
	account string
	ids     []string
	steps   []unsubStep
}

// unsubStep is the plan of one id: the row as far as the read decides
// it, and the URL of the row. A step whose row has no status still has
// its action to run: a one-click POST (method one_click) or a mailto
// draft (method draft). A link step keeps its URL for the fence of the
// response. u is plain sender text with no fence.
//
// arch: DS9.3, DU8.1
type unsubStep struct {
	row UnsubscribeRow
	u   *url.URL
}

// unsubConfirm asks about the one-click POSTs of steps and gives a
// confirm outcome of send.go. message is the text of the question.
type unsubConfirm func(ctx context.Context, acct config.Account, steps []unsubStep, message string) (string, error)

// unsubClaim is the claim step of the MRTR retry. It gets the alias
// that OpenWriter gave and gives the steps of the record.
type unsubClaim func(account string) ([]unsubStep, error)

// newUnsubscribeTool builds the production tool: post goes through
// guard.NewHTTPClient (HTTPS only, the dial-time address check, no
// redirect, 10 s, 64 KiB), and dkim is the reader that read uses.
//
// arch: DS9.3, DS9.12, IS9.1
func newUnsubscribeTool(m Mail) *unsubscribeTool {
	c := guard.NewHTTPClient()
	return &unsubscribeTool{
		mail:   m,
		draft:  &draftTool{mail: m},
		client: c,
		post:   oneClickPost(c),
		dkim:   dkimPass,
	}
}

// AddUnsubscribe adds the "unsubscribe" tool to srv. The level of the
// whole tool is draft (G18).
//
// arch: DS9.3
func AddUnsubscribe(srv *mcp.Server, logger *slog.Logger, m Mail) {
	addUnsubscribe(srv, logger, newUnsubscribeTool(m))
}

func addUnsubscribe(srv *mcp.Server, logger *slog.Logger, h *unsubscribeTool) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "unsubscribe",
		Description: "Unsubscribe from the lists of messages by id: a one-click POST, a draft, or the link.",
	}, WrapReq(logger, "unsubscribe", DefaultTimeout, h.handleReq))
}

// handleReq is the handler that [addUnsubscribe] registers. It uses
// [WrapReq], because it asks the human through the session of the
// call, as bulk does (DU8.1).
//
// A session on a protocol before [elicitCutoffProtocol] asks the human
// through the session of req. Such a session that gives a request
// state gets [errConfirmStale].
//
// A session on [elicitCutoffProtocol] or later uses the MRTR path. A
// call with no request state is the first call: when the plan has a
// one-click POST, it gives the question as an [inputRequired] value
// and does nothing else. A call with a request state is the retry: it
// takes the record of that state and runs the stored plan with the
// answer.
//
// arch: DU8.1, DS14.1, DS14.6, DS14.7, DS14.8
func (t *unsubscribeTool) handleReq(ctx context.Context, req *mcp.CallToolRequest, in UnsubscribeIn) (UnsubscribeOut, error) {
	ss := sessionOf(req)
	state, answers := retryOf(req)
	if !newProtocol(ss) {
		if state != "" {
			return UnsubscribeOut{}, errConfirmStale
		}
		return t.run(ctx, in, nil, unsubAsk(ss))
	}
	if state == "" {
		return t.run(ctx, in, nil, func(_ context.Context, acct config.Account, steps []unsubStep, message string) (string, error) {
			return t.askFirst(ss, acct, in, steps, message)
		})
	}
	claim := func(account string) ([]unsubStep, error) {
		return t.claimPending(ss, state, account, in)
	}
	return t.run(ctx, in, claim, func(context.Context, config.Account, []unsubStep, string) (string, error) {
		return bulkAnswer(answers), nil
	})
}

// handle runs one call with no session. A call whose plan has a
// one-click POST is refused, unless the account has [unsubscribe]
// allow_without_elicitation = true (DU8.1).
//
// arch: DS9.3, DU8.1
func (t *unsubscribeTool) handle(ctx context.Context, in UnsubscribeIn) (UnsubscribeOut, error) {
	return t.run(ctx, in, nil, unsubAsk(nil))
}

// unsubNoAsk is the rule for a client that cannot ask: the account key
// [unsubscribe] allow_without_elicitation gives
// [confirmNoElicitAllowed]; else the call gets
// [errUnsubNoElicitation] (DU8.1, the rule of bulk in DS14.2).
func unsubNoAsk(acct config.Account) (string, error) {
	if acct.UnsubscribeAllowWithoutElicitation {
		return confirmNoElicitAllowed, nil
	}
	return confirmNoElicitRefused, errUnsubNoElicitation
}

// unsubAsk gives the question of one call on the session ss. A nil ss
// has no way to ask, so it follows [unsubNoAsk]. The wait for the
// answer is the wait of [askConfirm].
//
// arch: DU8.1, D5.2
func unsubAsk(ss *mcp.ServerSession) unsubConfirm {
	return func(ctx context.Context, acct config.Account, _ []unsubStep, message string) (string, error) {
		if !canElicit(ss) {
			return unsubNoAsk(acct)
		}
		return askConfirm(ctx, ss, acct, message, unsubSchema, errNotConfirmed)
	}
}

// askFirst is the question of the first call on the MRTR path. It
// keeps a record of the plan and gives the question as an
// [inputRequired] value with the outcome [confirmPending]. A full
// store or a full session share gives its fixed refusal, and nobody is
// asked. A repeat first call with the same session, account and ids
// takes the place of the open record and gets a new state, so the old
// state is then stale (DS14.13).
//
// arch: DU8.1, DS14.3, DS14.6, DS14.12, DS14.13
func (t *unsubscribeTool) askFirst(ss *mcp.ServerSession, acct config.Account, in UnsubscribeIn, steps []unsubStep, message string) (string, error) {
	if !canElicit(ss) {
		return unsubNoAsk(acct)
	}
	place, _, err := t.pending.hold(ss, func(r pendingUnsub) bool {
		return r.session == ss && r.account == acct.Alias && slices.Equal(r.ids, in.IDs)
	})
	if err != nil {
		return "", err
	}
	state, err := place.fill(pendingUnsub{
		session: ss,
		account: acct.Alias,
		ids:     slices.Clone(in.IDs),
		steps:   slices.Clone(steps),
	})
	if err != nil {
		return "", err
	}
	return confirmPending, &inputRequired{
		requests: mcp.InputRequestMap{confirmInputID: &mcp.ElicitParams{
			Mode:            "form",
			Message:         message,
			RequestedSchema: unsubSchema,
		}},
		state: state,
	}
}

// claimPending is the claim step of the retry. It takes the record of
// state, so the state works one time only. It gives [errConfirmStale]
// when the store has no open record of state, or when the session, the
// account or the ids of the record differ from the retry.
//
// arch: DU8.1, DS14.7, IS14.2
func (t *unsubscribeTool) claimPending(ss *mcp.ServerSession, state, account string, in UnsubscribeIn) ([]unsubStep, error) {
	rec, ok := t.pending.take(state)
	if !ok || rec.session != ss || rec.account != account || !slices.Equal(rec.ids, in.IDs) {
		return nil, errConfirmStale
	}
	return rec.steps, nil
}

// run runs one call: the access check and the checks of the ids, then
// the plan of each id (or the plan of the record on the MRTR retry),
// then one question when the plan has a one-click POST, then the
// POSTs and drafts. Nothing leaves and no draft is saved before the
// answer. Only an accept, or a client that cannot ask on an account
// with the config key, lets a POST out; any other answer gives each
// one-click row the status declined and its link.
//
// arch: DS9.3, DU8.1, G18, G19, IS9.1, IS9.6, D5.2
func (t *unsubscribeTool) run(ctx context.Context, in UnsubscribeIn, claim unsubClaim, ask unsubConfirm) (UnsubscribeOut, error) {
	f := fencer(ctx)
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return UnsubscribeOut{}, err
	}
	if err := guard.Require(acct, guard.LevelDraft); err != nil {
		return UnsubscribeOut{}, err
	}
	if len(in.IDs) == 0 {
		return UnsubscribeOut{}, public("invalid_input", "ids: name at least one message; the search tool gives the ids")
	}
	if len(in.IDs) > MaxUnsubscribeIDs {
		return UnsubscribeOut{}, publicDetail("limit", unsubMaxIDsText, fmt.Sprintf("%d ids", len(in.IDs)))
	}
	var steps []unsubStep
	if claim != nil {
		if steps, err = claim(acct.Alias); err != nil {
			return UnsubscribeOut{}, err
		}
	} else {
		var cfg verify.Config
		if src, ok := t.mail.(verifyConfigSource); ok {
			cfg = src.VerifyConfig()
		}
		steps = t.plan(ctx, p, cfg, acct.Provider, in.IDs)
	}
	post := false
	if oneClickCount(steps) > 0 {
		outcome, err := ask(ctx, acct, steps, unsubQuestion(in.Account, steps))
		if err != nil {
			return UnsubscribeOut{}, err
		}
		switch outcome {
		case confirmAccept, confirmAcceptSession:
			// An accept with remember true is only an accept: no
			// grant covers a POST. D5.2: the wait for the human does
			// not count against the tool deadline, so the POSTs and
			// drafts get a full deadline of their own.
			post = true
			if wait, timeout, ok := untimed(ctx); ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(wait, timeout)
				defer cancel()
				ctx = withFencer(ctx, f)
			}
		case confirmNoElicitAllowed:
			// No wait came first; the POSTs keep the tool deadline.
			post = true
		}
	}
	return t.execute(ctx, f, in.Account, steps, post), nil
}

// plan reads each id and gives its step, in input order. It sends no
// POST and saves no draft, so a question can come between the plan
// and [unsubscribeTool.execute].
//
// arch: DS9.3, DU8.1
func (t *unsubscribeTool) plan(ctx context.Context, p Writer, cfg verify.Config, kind string, ids []string) []unsubStep {
	steps := make([]unsubStep, 0, len(ids))
	for i, id := range ids {
		if ctx.Err() != nil {
			row := UnsubscribeRow{Index: i, ID: rowID(kind, id)}
			row.Method, row.Status, row.Note = unsubMethodNone, unsubStatusFailed, unsubNoteTimeUp
			steps = append(steps, unsubStep{row: row})
			continue
		}
		steps = append(steps, t.planOne(ctx, p, cfg, kind, i, id))
	}
	return steps
}

// planOne gives the step of one id, in the order of DS9.3: one-click,
// then mailto, then the link, then nothing.
func (t *unsubscribeTool) planOne(ctx context.Context, p Writer, cfg verify.Config, kind string, index int, id string) unsubStep {
	row := UnsubscribeRow{Index: index, ID: rowID(kind, id)}
	m, err := p.Read(ctx, id, mail.ReadOpts{Headers: []string{hdrListUnsubscribe, hdrListUnsubscribePost}})
	if err != nil || m == nil {
		row.Method, row.Status, row.Note = unsubMethodNone, unsubStatusFailed, unsubNoteReadFailed
		return unsubStep{row: row}
	}
	lists := m.Headers[hdrListUnsubscribe]
	if len(lists) == 0 {
		row.Method, row.Status = unsubMethodNone, unsubStatusNoHeader
		return unsubStep{row: row}
	}
	httpsURL, mailtoURL := unsubscribeURLs(lists)
	postOK := len(lists) == 1 && oneClickHeader(m.Headers[hdrListUnsubscribePost])
	if httpsURL != nil && postOK && t.dkim(m, cfg) {
		row.Method = unsubMethodOneClick
		return unsubStep{row: row, u: httpsURL}
	}
	if mailtoURL != nil {
		row.Method = unsubMethodDraft
		return unsubStep{row: row, u: mailtoURL}
	}
	if httpsURL != nil {
		row.Method, row.Status = unsubMethodLink, unsubStatusSeeLink
		if postOK {
			// Only the DKIM rule stopped the POST (G18).
			row.Status, row.Note = unsubStatusNoAuth, unsubNoteNoAuth
		}
		return unsubStep{row: row, u: httpsURL}
	}
	row.Method, row.Status, row.Note = unsubMethodNone, unsubStatusNoHeader, unsubNoteNoURL
	return unsubStep{row: row}
}

// pendingAction reports whether s still has its action to run: a
// one-click POST or a mailto draft.
func (s unsubStep) pendingAction() bool {
	return s.row.Status == ""
}

// oneClickCount gives the number of one-click POSTs of steps.
func oneClickCount(steps []unsubStep) int {
	n := 0
	for _, s := range steps {
		if s.pendingAction() && s.row.Method == unsubMethodOneClick {
			n++
		}
	}
	return n
}

// execute gives the row of each step. A step that the read decided
// keeps its row; a link row gets its URL in a fence of f. A one-click
// step sends its POST when post is true, and else gets the status
// declined and its link. A mailto step saves its draft. When ctx ends,
// each step that is left gives the time-up row; the rows before it may
// hold a POST that was sent, so the call gives them, not an error.
//
// arch: DS9.3, DU8.1, DU5.1
func (t *unsubscribeTool) execute(ctx context.Context, f guard.Fencer, account string, steps []unsubStep, post bool) UnsubscribeOut {
	out := UnsubscribeOut{Rows: make([]UnsubscribeRow, 0, len(steps))}
	for _, s := range steps {
		row := s.row
		switch {
		case !s.pendingAction():
			if row.Method == unsubMethodLink {
				row.Untrusted.URL = f.Wrap(s.u.String())
			}
		case ctx.Err() != nil:
			row.Method, row.Status, row.Note = unsubMethodNone, unsubStatusFailed, unsubNoteTimeUp
		case row.Method == unsubMethodOneClick && !post:
			row.Status, row.Note = unsubStatusDeclined, unsubNoteDeclined
			row.Untrusted.URL = f.Wrap(s.u.String())
		case row.Method == unsubMethodOneClick:
			row = t.oneClick(ctx, f, row, s.u)
		default:
			row = t.mailto(ctx, row, account, s.u)
		}
		out.Rows = append(out.Rows, row)
	}
	return out
}

// unsubQuestion is the text that the human accepts (DU8.1): the count
// of one-click POSTs, the account, and the host of each POST URL, one
// line for each POST in row order. The path and the query of a URL are
// not shown, because they can hold a token of the list. The question
// goes to the human through elicitation or MRTR, so it holds no fence
// marker and no nonce (INV-7): the alias is model text and loses its
// hidden characters and fence markers (serverText); each host is
// sender text and also passes [plainLine], and its links are defanged
// after it (D4.1), as in [bulkQuestion].
//
// arch: DU8.1, INV-7, D4.1
func unsubQuestion(account string, steps []unsubStep) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Send %s for account %s? Each POST asks a mailing list to stop its mail to this account, and it cannot be undone here. The host of each POST:",
		plural(oneClickCount(steps), "one-click unsubscribe POST"), serverText(account))
	for _, s := range steps {
		if s.pendingAction() && s.row.Method == unsubMethodOneClick {
			b.WriteString("\n- ")
			b.WriteString(mime.DefangLinks(plainLine(serverText(s.u.Hostname()))))
		}
	}
	return b.String()
}

// rowID gives the id of a row in the form [normalizeID] writes, or the
// empty string when the id does not pass (DU5.6).
func rowID(kind, id string) string {
	n, _ := normalizeID(kind, id)
	return n
}

// oneClick sends the RFC 8058 POST. A 2xx is done; a refused redirect,
// any other status or an error gives the link.
func (t *unsubscribeTool) oneClick(ctx context.Context, f guard.Fencer, row UnsubscribeRow, u *url.URL) UnsubscribeRow {
	row.Method = unsubMethodOneClick
	status, err := t.post(ctx, u.String())
	if err == nil && status >= 200 && status < 300 {
		row.Status = unsubStatusDone
		return row
	}
	row.Status = unsubStatusSeeLink
	row.Untrusted.URL = f.Wrap(u.String())
	row.Note = unsubNotePostFailed
	if err == nil {
		row.Note = fmt.Sprintf("the one-click POST got status %d; open the link", status)
	}
	return row
}

// mailto makes a draft from a mailto URL through the draft tool. The
// person sends it with the send tool (G19, IS9.6).
func (t *unsubscribeTool) mailto(ctx context.Context, row UnsubscribeRow, account string, u *url.URL) UnsubscribeRow {
	row.Method = unsubMethodDraft
	addr, err := url.PathUnescape(u.Opaque)
	if err == nil {
		_, err = netmail.ParseAddress(addr)
	}
	if err != nil {
		row.Status, row.Note = unsubStatusFailed, unsubNoteDraftFail
		return row
	}
	q := u.Query()
	subject, body := q.Get("subject"), q.Get("body")
	if subject == "" {
		subject = "unsubscribe"
	}
	if body == "" {
		body = "unsubscribe"
	}
	out, err := t.draft.handle(ctx, DraftIn{Account: account, To: []string{addr}, Subject: subject, Body: body})
	if err != nil {
		row.Status, row.Note = unsubStatusFailed, unsubNoteDraftFail
		return row
	}
	row.Status, row.DraftID, row.Note = unsubStatusDraft, out.DraftID, unsubNoteDraftSend
	return row
}

// unsubscribeURLs parses the List-Unsubscribe values (RFC 2369: URLs
// in angle brackets, comma separated, left to right) and gives the
// first https URL with a host and the first mailto URL. Text outside
// the brackets is a comment and is ignored, and white space inside
// the brackets is removed. An http URL is never kept (IS9.1).
//
// arch: DS9.3, IS9.1
func unsubscribeURLs(values []string) (httpsURL, mailtoURL *url.URL) {
	for _, v := range values {
		for {
			start := strings.IndexByte(v, '<')
			if start < 0 {
				break
			}
			end := strings.IndexByte(v[start:], '>')
			if end < 0 {
				break
			}
			raw := strings.Join(strings.Fields(v[start+1:start+end]), "")
			v = v[start+end+1:]
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			switch strings.ToLower(u.Scheme) {
			case "https":
				if httpsURL == nil && u.Host != "" && u.Opaque == "" {
					httpsURL = u
				}
			case "mailto":
				if mailtoURL == nil && u.Opaque != "" {
					mailtoURL = u
				}
			}
		}
	}
	return httpsURL, mailtoURL
}

// oneClickHeader reports whether the List-Unsubscribe-Post values are
// exactly one "List-Unsubscribe=One-Click", case and white space
// ignored (RFC 8058 section 3.1). Two instances fail.
func oneClickHeader(values []string) bool {
	if len(values) != 1 {
		return false
	}
	return strings.EqualFold(strings.Join(strings.Fields(values[0]), ""), oneClickBody)
}

// oneClickPost gives the RFC 8058 POST through c: the form body
// List-Unsubscribe=One-Click, no cookie (c has no jar), no
// authorization (the user part of the URL is dropped) and never a GET.
// The body of the answer is read up to the cap of c and dropped.
//
// arch: DS9.3, IS9.1
func oneClickPost(c *http.Client) func(ctx context.Context, rawURL string) (int, error) {
	return func(ctx context.Context, rawURL string) (int, error) {
		u, err := url.Parse(rawURL)
		if err != nil {
			return 0, err
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return 0, public("refused", "unsubscribe: the one-click URL is not https")
		}
		u.User = nil
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(oneClickBody))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}
}

// dkimPass is the production dkim seam. It reads the DKIM result the
// way read does: verify.Check on the Authentication-Results block of
// the message (authHeaderRaw) with the [verify] keys of the Mail. It
// is true only for dkim=pass from the configured authserv_id with
// header.d equal to the From domain. No authserv_id gives false (fail
// closed, G18).
//
// arch: DS9.3, G18, IS9.1
func dkimPass(m *mail.Message, cfg verify.Config) bool {
	if strings.TrimSpace(cfg.AuthservID) == "" || strings.TrimSpace(m.AuthResults) == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), verify.Timeout)
	defer cancel()
	s := verify.Check(ctx, authHeaderRaw(m.AuthResults), m.From.Address, cfg)
	return s != nil && s.Type == verify.TypeDKIM && s.Verdict == verify.VerdictVerified && s.SignerMatchesFrom
}
