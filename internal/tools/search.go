// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
	"fmt"
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
	Query   string `json:"query,omitempty" jsonschema:"from: to: cc: subject: body: has:attachment is:unread|read|starred in:FOLDER before:|after:YYYY-MM-DD newer_than:7d larger:5M -term \"phrase\". Terms join with AND. Empty = newest."`
	Folder  string `json:"folder,omitempty" jsonschema:"default INBOX"`
	Since   string `json:"since,omitempty" jsonschema:"RFC 3339; newer only"`
	Limit   int    `json:"limit,omitempty" jsonschema:"default 20, max 100"`
	Cursor  string `json:"cursor,omitempty" jsonschema:"next_cursor; one account only"`
}

// SearchRow is one result line. §3.15: server data stays outside the
// fence and every sender-controlled field sits inside one fence for
// the row, which keeps the cost low.
type SearchRow struct {
	ID      string `json:"id"`
	Account string `json:"account"`
	Folder  string `json:"folder"`
	Date    string `json:"date"`
	Flags   string `json:"flags,omitempty"`
	Size    int64  `json:"size,omitempty"`
	// Email holds from, subject and preview inside the fence markers
	// the server instructions explain (App C).
	Email string `json:"email"`
	// Hidden is the count of hidden characters taken out of Email
	// (§3.15). It stays outside the fence, because the server counted
	// them, not the sender.
	Hidden int `json:"hidden_removed,omitempty"`
}

// AccountError names one account whose search failed (§3.16).
type AccountError struct {
	Account string `json:"account"`
	Error   string `json:"error"`
}

// SearchOut is the search tool result (§3.16).
type SearchOut struct {
	Rows       []SearchRow    `json:"rows"`
	NextCursor string         `json:"next_cursor,omitempty"`
	Errors     []AccountError `json:"errors,omitempty"`
	// Partial is true when an account failed or the deadline ran out.
	// The rows that did arrive are still in Rows (A8).
	Partial bool `json:"partial,omitempty"`
	// Note carries a provider's caller-visible note, such as "only
	// the newest 500 matching messages were checked" (DRV.12). Like
	// NextCursor, it belongs to one provider's result set, so only a
	// single-account search carries one.
	Note string `json:"note,omitempty"`
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
// arch: T4.5, §3.16, §3.9, §3.15, A8, G10, A12
func (t *searchTool) handle(ctx context.Context, in SearchIn) (SearchOut, error) {
	q, err := buildQuery(in)
	if err != nil {
		return SearchOut{}, err
	}
	aliases, err := t.targets(ctx, in.Account)
	if err != nil {
		return SearchOut{}, err
	}

	out := SearchOut{Rows: []SearchRow{}}
	var mu sync.Mutex

	// errgroup, not errgroup.WithContext: the first failure must not
	// cancel the other accounts (§3.16).
	var g errgroup.Group
	g.SetLimit(searchFanout)
	for _, alias := range aliases {
		g.Go(func() error {
			actx, cancel := context.WithTimeout(ctx, searchPerAccount)
			defer cancel()

			rows, next, note, err := t.one(actx, alias, q)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// The structured result does not pass through the
				// redactor of Wrap, which only sees the error text of
				// a failed call. Redact here (§3.15, B4).
				out.Errors = append(out.Errors, AccountError{Account: alias, Error: guard.Redact(err.Error())})
				return nil
			}
			out.Rows = append(out.Rows, rows...)
			if len(aliases) == 1 {
				// A cursor, and a provider's note, are tied to one
				// result set (§3.9, DRV.12). Neither can describe a
				// merged list, so only a single-account search
				// carries one.
				out.NextCursor = next
				out.Note = note
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
	out.Partial = len(out.Errors) > 0 || ctx.Err() != nil
	return out, nil
}

// one searches a single account.
func (t *searchTool) one(ctx context.Context, alias string, q mail.Query) ([]SearchRow, string, string, error) {
	p, _, err := t.mail.Open(ctx, alias)
	if err != nil {
		return nil, "", "", err
	}
	page, err := p.Search(ctx, q)
	if err != nil {
		return nil, "", "", err
	}
	rows := make([]SearchRow, 0, len(page.Messages))
	for i := range page.Messages {
		rows = append(rows, toRow(alias, page.Messages[i]))
	}
	return rows, page.NextCursor, page.Note, nil
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
		return nil, errors.New(addAccountHint)
	}
	return aliases, nil
}

// buildQuery turns the tool input into a provider query. A bad since
// time or a cursor on a multi-account search fails the call: both are
// wrong before any mailbox is asked.
func buildQuery(in SearchIn) (mail.Query, error) {
	q := mail.Query{Raw: in.Query, Folder: in.Folder, Limit: in.Limit, Cursor: in.Cursor}
	if q.Limit <= 0 {
		q.Limit = searchDefaultLimit
	}
	if q.Limit > searchMaxLimit {
		q.Limit = searchMaxLimit
	}
	if in.Since != "" {
		ts, err := time.Parse(time.RFC3339, in.Since)
		if err != nil {
			return mail.Query{}, fmt.Errorf("since %q is not an RFC 3339 time such as 2026-09-01T00:00:00Z", in.Since)
		}
		q.Since = ts
	}
	if in.Cursor != "" && in.Account == "" {
		return mail.Query{}, errors.New("a cursor belongs to one account; give the account it came from")
	}
	return q, nil
}

// toRow builds one result line. Everything the sender controls goes
// inside one fence; the id, account, folder, date, flags and size
// stay outside it (§3.15).
//
// The display name, subject and preview are defanged again after
// guard.Sanitize. Sanitize runs NFKC and removes hidden characters,
// and that can make a live link from a full-width or split link that
// went in unchanged (D4.1 item 3). A search row shows a link target
// only in its defanged form; read gives the real URL. Hidden counts
// the characters of the raw text.
//
// arch: D4.1
func toRow(alias string, m mail.Message) SearchRow {
	head := "from: " + addressText(m.From) + "\nsubject: " + m.Subject
	raw := head
	body := mime.DefangLinks(guard.Sanitize(head))
	if m.Preview != "" {
		raw += "\npreview: " + m.Preview
		body += "\npreview: " + mime.DefangLinks(guard.Sanitize(m.Preview))
	}
	_, hidden := guard.StripInvisible(raw)
	return SearchRow{
		ID:      m.ID,
		Account: alias,
		Folder:  m.Folder,
		Date:    m.Date.UTC().Format(time.RFC3339),
		Flags:   flagText(m.Flags),
		Size:    m.Size,
		Email:   guard.Fence("EMAIL", body),
		Hidden:  hidden,
	}
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
// read message with no other flag.
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
	parts = append(parts, f.Labels...)
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
