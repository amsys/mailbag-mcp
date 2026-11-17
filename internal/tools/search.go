// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The search tool: one account or all of them, newest first. Each row
// has two zones (DU5.2). This file also holds the row helpers that
// read shares: the flag words, the label fences and the error detail.

package tools

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/errgroup"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// Fan-out limits of §3.16 and A8: a search over many accounts runs
// them at the same time, searchFanout at most, with searchPerAccount
// for each. One mailbox that fails never fails the call.
const (
	searchFanout     = 8
	searchPerAccount = 20 * time.Second
)

// Page limits of §3.16.
const (
	searchDefaultLimit = 20
	searchMaxLimit     = 100
)

// SearchIn is the input of the search tool (App B). Account is the
// one alias field that may be absent: an absent account searches
// every configured account.
type SearchIn struct {
	Account string `json:"account,omitempty"`
	Query   string `json:"query,omitempty" jsonschema:"from: to: cc: subject: body: has:attachment is:unread|read|starred in:FOLDER|folder_ref before:|after:YYYY-MM-DD newer_than:7d larger:5M -term \"phrase\". Terms join with AND. Empty = newest."`
	Folder  string `json:"folder,omitempty" jsonschema:"name or folder_ref; default INBOX"`
	Since   string `json:"since,omitempty" jsonschema:"RFC 3339; newer only"`
	Limit   int    `json:"limit,omitempty" jsonschema:"default 20, max 100"`
	Cursor  string `json:"cursor,omitempty" jsonschema:"next_cursor; one account only"`
}

// SearchRow is one result line (DU5.2). The outside zone holds only
// strings that this server writes in a closed grammar: the id, the
// account alias, the folder ref, the date and the flag words. Every
// string that a sender, a person or a mail server chose sits under
// Untrusted, each in its own fence (DU5.1): the from line, the
// subject, the preview, the folder name and the labels.
type SearchRow struct {
	ID        string `json:"id" strict:"id"`
	Account   string `json:"account" strict:"alias"`
	FolderRef string `json:"folder_ref,omitempty" strict:"folder"`
	Date      string `json:"date,omitempty" strict:"date"`
	Flags     string `json:"flags,omitempty" strict:"flags"`
	Size      int64  `json:"size,omitempty"`
	// Untrusted holds the fenced fields of the row (DU5.1).
	Untrusted SearchUntrusted `json:"untrusted"`
	// Hidden is the count of hidden characters taken out of the from
	// line, the subject and the preview (§3.15). It stays outside the
	// fence, because the server counted them, not the sender.
	Hidden int `json:"hidden_removed,omitempty"`
}

// SearchUntrusted is the untrusted zone of one row. Each field is one
// fence of the nonce of the response; Labels has one fence for each
// label or keyword (DU3.4).
type SearchUntrusted struct {
	From    string   `json:"from,omitempty"`
	Subject string   `json:"subject,omitempty"`
	Preview string   `json:"preview,omitempty"`
	Folder  string   `json:"folder,omitempty"`
	Labels  []string `json:"labels,omitempty"`
}

// AccountError names one account whose search failed (§3.16). Error is
// the class word of DU6.2. The error text can quote a stranger, so it
// goes to Untrusted.Detail in a fence.
type AccountError struct {
	Account   string  `json:"account" strict:"alias"`
	Error     string  `json:"error" strict:"word"`
	Untrusted *Detail `json:"untrusted,omitempty"`
}

// Detail is the untrusted zone of an object that can carry text of
// unknown origin, for example a provider error (DU3.5, DU6.2). Detail
// is one fence of the nonce of the response.
type Detail struct {
	Detail string `json:"detail,omitempty"`
}

// SearchOut is the search tool result (§3.16, DU5.2). Head gives the
// nonce first. Rows, the cursor, the account errors, Partial and Note
// are outside; each row and each account error has its own untrusted
// zone.
type SearchOut struct {
	Head
	Rows       []SearchRow    `json:"rows"`
	NextCursor string         `json:"next_cursor,omitempty" strict:"cursor"`
	Errors     []AccountError `json:"errors,omitempty"`
	// Partial is true when an account failed, the deadline ran out, or
	// a row was left out because its id did not pass normalizeID. The
	// rows that did arrive are still in Rows (A8, DU3.2).
	Partial bool `json:"partial,omitempty"`
	// Note carries a provider's caller-visible note, such as "the
	// newest 500 matching messages were checked" (DRV.12). It passes
	// the note registry (DU3.5). Like NextCursor, it belongs to one
	// provider's result set, so only a single-account search carries
	// one.
	Note string `json:"note,omitempty" strict:"note"`
}

// AddSearch adds the "search" tool to srv (§3.16): read level, an
// optional account, no change to the mailbox.
//
// arch: T4.5, §3.16, §3.9, §3.15, A8, A12, G10
func AddSearch(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &searchTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "search",
		Description: "Search one account, or all when account is omitted. Newest first; preview fenced.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, Wrap(logger, "search", DefaultTimeout, h.handle))
}

type searchTool struct{ mail Mail }

// handle runs the search over one account or over every account.
//
// A8: each account gets searchPerAccount, searchFanout run together,
// and the call returns the rows that arrived plus one error line for
// each account that failed. It never fails the whole call because one
// mailbox failed. A bad query term also arrives as an account error,
// with the text the provider wrote (§3.9): the grammar has no
// operators, so "OR" or a bad date says so instead of coming back as
// an empty page.
//
// The handler takes the Fencer of the call once, before the fan-out.
// Each goroutine gets it as an argument and only reads it (DU2.2).
//
// arch: T4.5, §3.16, §3.9, §3.15, A8, G10, A12, DU2.2, DU5.2
func (t *searchTool) handle(ctx context.Context, in SearchIn) (SearchOut, error) {
	f := fencer(ctx)
	q, err := buildQuery(in)
	if err != nil {
		return SearchOut{}, err
	}
	aliases, err := t.targets(ctx, in.Account)
	if err != nil {
		return SearchOut{}, err
	}

	out := SearchOut{Rows: []SearchRow{}}
	dropped := false
	var mu sync.Mutex

	// errgroup, not errgroup.WithContext: the first failure must not
	// cancel the other accounts (§3.16).
	var g errgroup.Group
	g.SetLimit(searchFanout)
	for _, alias := range aliases {
		g.Go(func() error {
			actx, cancel := context.WithTimeout(ctx, searchPerAccount)
			defer cancel()

			res, err := t.one(actx, f, alias, q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// The error text can quote a stranger. The class word
				// stays outside; the text goes into a fence after the
				// redactor (§3.15, B4, DH2.5, DU6.2).
				out.Errors = append(out.Errors, accountError(f, alias, err))
				return nil
			}
			out.Rows = append(out.Rows, res.rows...)
			dropped = dropped || res.dropped
			if len(aliases) == 1 {
				// A cursor, and a provider's note, are tied to one
				// result set (§3.9, DRV.12). Neither can describe a
				// merged list, so only a single-account search
				// carries one.
				out.NextCursor = res.next
				out.Note = res.note
			}
			return nil
		})
	}
	_ = g.Wait() // every goroutine returns nil; failures are in out.Errors

	sortRows(out.Rows)
	if len(out.Rows) > q.Limit {
		out.Rows = out.Rows[:q.Limit]
		if len(aliases) > 1 {
			out.NextCursor = ""
		}
	}
	sortErrors(out.Errors)
	out.Partial = len(out.Errors) > 0 || ctx.Err() != nil || dropped
	return out, nil
}

// accountResult is the part of the result that one account gives.
type accountResult struct {
	rows    []SearchRow
	next    string
	note    string
	dropped bool // a message was left out: its id did not pass normalizeID
}

// one searches a single account. A message whose id does not pass
// normalizeID for the provider kind is left out, because the outside
// zone cannot hold its id and a row with no id cannot be read or
// changed (DU3.2). A cursor that does not match the strict kind cursor
// is not written, and a note passes the note registry (DU3.5).
func (t *searchTool) one(ctx context.Context, f guard.Fencer, alias string, q mail.Query) (accountResult, error) {
	p, acct, err := t.mail.Open(ctx, alias)
	if err != nil {
		return accountResult{}, err
	}
	page, err := p.Search(ctx, q)
	if err != nil {
		return accountResult{}, err
	}
	res := accountResult{rows: make([]SearchRow, 0, len(page.Messages))}
	for i := range page.Messages {
		row, ok := toSearchRow(f, acct.Provider, alias, page.Messages[i])
		if !ok {
			res.dropped = true
			continue
		}
		res.rows = append(res.rows, row)
	}
	if page.NextCursor != "" && guard.Strict("cursor", page.NextCursor) {
		res.next = page.NextCursor
	}
	res.note, _ = strictNote(page.Note)
	return res, nil
}

// targets gives the accounts to search. An alias that the config does
// not hold fails the call here, before any network work (G10).
func (t *searchTool) targets(ctx context.Context, account string) ([]string, error) {
	if account != "" {
		if _, _, err := t.mail.Open(ctx, account); err != nil {
			return nil, err
		}
		return []string{account}, nil
	}
	aliases, err := t.mail.Aliases()
	if err != nil {
		return nil, err
	}
	if len(aliases) == 0 {
		return nil, public("not_found", addAccountHint)
	}
	return aliases, nil
}

// buildQuery turns the tool input into a provider query. A bad since
// time, a bad folder ref or a cursor on a multi-account search fails
// the call: each is wrong before any mailbox is asked.
//
// The folder field passes folderArg, so it takes a name or a
// folder_ref (DU3.3). The in: word of the query stays in Raw: each
// provider reads it with mail.ParseQuery, which gives the name that a
// valid ref holds. An in: value that is not a valid ref stays as the
// model wrote it, and the provider reports the folder as unknown.
//
// arch: §3.9, DU3.3, DU6.2
func buildQuery(in SearchIn) (mail.Query, error) {
	folder, err := folderArg(in.Folder)
	if err != nil {
		return mail.Query{}, err
	}
	q := mail.Query{Raw: in.Query, Folder: folder, Limit: in.Limit, Cursor: in.Cursor}
	if q.Limit <= 0 {
		q.Limit = searchDefaultLimit
	}
	if q.Limit > searchMaxLimit {
		q.Limit = searchMaxLimit
	}
	if in.Since != "" {
		ts, err := time.Parse(time.RFC3339, in.Since)
		if err != nil {
			return mail.Query{}, publicDetail("invalid_input", "since is not an RFC 3339 time such as 2026-09-01T00:00:00Z", in.Since)
		}
		q.Since = ts
	}
	if in.Cursor != "" && in.Account == "" {
		return mail.Query{}, public("invalid_input", "a cursor belongs to one account; give the account it came from")
	}
	return q, nil
}

// errNote gives the text of a provider error for a result field. A
// provider error can quote a stranger, so the text goes through
// Sanitize. Redact runs first, so NFKC cannot hide a token from it.
//
// arch: DH2.5
func errNote(err error) string {
	return guard.Sanitize(guard.Redact(err.Error()))
}

// accountError gives the error line of one account (DU5.2, DU6.2):
// the class word outside, and the error text in a fence after the
// redactor. Redact runs before the Sanitize of Wrap, so NFKC cannot
// hide a token from it.
//
// arch: DU5.2, DU6.2, DH2.5
func accountError(f guard.Fencer, alias string, err error) AccountError {
	return AccountError{Account: alias, Error: classOf(err), Untrusted: errDetail(f, err)}
}

// errDetail gives the untrusted detail of an error: its text after
// guard.Redact, in one fence of f. It is the two-zone twin of errNote:
// a note outside ends with the class word, and this detail carries the
// text (DU3.5).
//
// arch: DU3.5, DU6.2, DH2.5
func errDetail(f guard.Fencer, err error) *Detail {
	return &Detail{Detail: f.Wrap(guard.Redact(err.Error()))}
}

// wrapIf gives the fence of s, or "" when s is empty, so an empty
// field with omitempty stays out of the result (DU4.1).
//
// arch: DU5.1
func wrapIf(f guard.Fencer, s string) string {
	if s == "" {
		return ""
	}
	return f.Wrap(s)
}

// flagWords writes the flags of a row in the closed set of DU3.4. It
// is the two-zone twin of flagText: it writes the words of the four
// system flags only, and never a label or a keyword. Those go to
// labelFences. An empty string means a read message with no other
// flag.
//
// arch: DU3.4
func flagWords(fl mail.Flags) string {
	var parts []string
	if !fl.Seen {
		parts = append(parts, "unread")
	}
	if fl.Flagged {
		parts = append(parts, "starred")
	}
	if fl.Answered {
		parts = append(parts, "answered")
	}
	if fl.Draft {
		parts = append(parts, "draft")
	}
	return strings.Join(parts, " ")
}

// labelFences gives one fence for each label or keyword name (DU3.4).
// A person or a sender can choose a label name, so it never goes
// outside. Each name gets its own fence, so the escaper sees each name
// alone and finds a turn prefix at its start. An empty name is left
// out.
//
// arch: DU3.4, DU5.1
func labelFences(f guard.Fencer, labels []string) []string {
	var out []string
	for _, l := range labels {
		if l != "" {
			out = append(out, f.Wrap(l))
		}
	}
	return out
}

// dateText writes the server time t in the strict kind date. A zero
// time, or a time that the kind cannot hold, gives "", and the field
// is then omitted (DU3.1).
//
// arch: DU3.1
func dateText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	s := t.UTC().Format(time.RFC3339)
	if !guard.Strict("date", s) {
		return ""
	}
	return s
}

// toSearchRow builds one two-zone result line (DU5.2). The id passes
// normalizeID for the provider kind; ok is false when it does not, and
// the caller leaves the row out (DU3.2). The folder is outside as a
// ref and inside as a name (DU3.3). The flags are closed words, and
// each label is a fence (DU3.4).
//
// The display name, subject and preview are defanged again after
// guard.Sanitize. Sanitize runs NFKC and removes hidden characters,
// and that can make a live link from a full-width or split link that
// went in unchanged (D4.1 item 3). A search row shows a link target
// only in its defanged form; read gives the real URL. Hidden counts
// the hidden characters of the raw from line, subject and preview.
//
// arch: D4.1, DU5.1, DU5.2, DU3.2, DU3.3, DU3.4
func toSearchRow(f guard.Fencer, kind, alias string, m mail.Message) (SearchRow, bool) {
	id, ok := normalizeID(kind, m.ID)
	if !ok {
		return SearchRow{}, false
	}
	shown := func(s string) string {
		if s == "" {
			return ""
		}
		return f.Wrap(mime.DefangLinks(guard.Sanitize(s)))
	}
	from := addressText(m.From)
	hidden := 0
	for _, raw := range []string{from, m.Subject, m.Preview} {
		_, n := guard.StripInvisible(raw)
		hidden += n
	}
	return SearchRow{
		ID:        id,
		Account:   alias,
		FolderRef: folderRef(m.Folder),
		Date:      dateText(m.Date),
		Flags:     flagWords(m.Flags),
		Size:      m.Size,
		Untrusted: SearchUntrusted{
			From:    shown(from),
			Subject: shown(m.Subject),
			Preview: shown(m.Preview),
			Folder:  wrapIf(f, m.Folder),
			Labels:  labelFences(f, m.Flags.Labels),
		},
		Hidden: hidden,
	}, true
}

// addressText writes one address as "Name <user@host>", or just the
// address when there is no name.
func addressText(a mail.Address) string {
	if a.Name == "" {
		return a.Address
	}
	return a.Name + " <" + a.Address + ">"
}

// flagText writes the flags a model acts on. An empty string means a
// read message with no other flag. Each label word comes from the
// server and is cleaned alone, so a turn prefix at the start of a word
// is found.
//
// arch: DH2.5
func flagText(f mail.Flags) string {
	var parts []string
	if !f.Seen {
		parts = append(parts, "unread")
	}
	if f.Flagged {
		parts = append(parts, "starred")
	}
	if f.Answered {
		parts = append(parts, "answered")
	}
	if f.Draft {
		parts = append(parts, "draft")
	}
	for _, l := range f.Labels {
		parts = append(parts, guard.CleanServerName(l))
	}
	return strings.Join(parts, " ")
}

// sortRows puts the newest message first. Two messages with the same
// date fall back to the id, so the order is the same on every run.
func sortRows(rows []SearchRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Date != rows[j].Date {
			return rows[i].Date > rows[j].Date
		}
		return rows[i].ID < rows[j].ID
	})
}

// sortErrors puts the account errors in alias order, so two runs of
// the same failing search give the same result bytes.
func sortErrors(errs []AccountError) {
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Account < errs[j].Account })
}
