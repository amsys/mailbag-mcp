// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The unsubscribe tool of S9 (DS9.3). It reads the RFC 2369
// List-Unsubscribe header of each message id and does one of four
// things: an RFC 8058 one-click POST through the guarded client, a
// draft for a mailto URL, a link for the person, or nothing. It never
// sends mail (G19, IS9.6) and never makes a GET (IS9.1).

package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	netmail "net/mail"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// MaxUnsubscribeIDs is the id limit of one unsubscribe call (DS9.3).
const MaxUnsubscribeIDs = 50

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
// one-click, draft, link or none. Status is one of done, draft saved,
// see link, not authenticated, no header or failed. URL is sender
// text, so it is fenced. Note is text this server wrote.
//
// arch: DS9.3
type UnsubscribeRow struct {
	ID      string `json:"id"`
	Method  string `json:"method"`
	Status  string `json:"status"`
	DraftID string `json:"draft_id,omitempty"`
	URL     string `json:"url,omitempty"`
	Note    string `json:"note,omitempty"`
}

// UnsubscribeOut is the result of the unsubscribe tool: one row for
// each id, in input order.
//
// arch: DS9.3
type UnsubscribeOut struct {
	Rows []UnsubscribeRow `json:"rows"`
}

// The words of UnsubscribeRow.Method and UnsubscribeRow.Status.
const (
	unsubMethodOneClick = "one-click"
	unsubMethodDraft    = "draft"
	unsubMethodLink     = "link"
	unsubMethodNone     = "none"

	unsubStatusDone     = "done"
	unsubStatusDraft    = "draft saved"
	unsubStatusSeeLink  = "see link"
	unsubStatusNoAuth   = "not authenticated"
	unsubStatusNoHeader = "no header"
	unsubStatusFailed   = "failed"
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
)

// unsubscribeTool holds the handler and its two seams. client is the
// guarded client that post uses in production; it is a field so that
// TestUnsubscribe_ProductionClientIsGuarded can check it (DS9.12).
type unsubscribeTool struct {
	mail   Mail
	draft  *draftTool
	client *http.Client
	post   func(ctx context.Context, rawURL string) (status int, err error)
	dkim   func(msg *mail.Message, cfg verify.Config) bool
}

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
	}, Wrap(logger, "unsubscribe", DefaultTimeout, h.handle))
}

// handle runs the access check first, then one row for each id.
//
// arch: DS9.3, G18, G19, IS9.1, IS9.6
func (t *unsubscribeTool) handle(ctx context.Context, in UnsubscribeIn) (UnsubscribeOut, error) {
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return UnsubscribeOut{}, err
	}
	if err := guard.Require(acct, guard.LevelDraft); err != nil {
		return UnsubscribeOut{}, err
	}
	if len(in.IDs) == 0 {
		return UnsubscribeOut{}, errors.New("ids: name at least one message; the search tool gives the ids")
	}
	if len(in.IDs) > MaxUnsubscribeIDs {
		return UnsubscribeOut{}, fmt.Errorf("ids: %d ids, and one call takes %d at most", len(in.IDs), MaxUnsubscribeIDs)
	}
	var cfg verify.Config
	if src, ok := t.mail.(verifyConfigSource); ok {
		cfg = src.VerifyConfig()
	}
	out := UnsubscribeOut{Rows: make([]UnsubscribeRow, 0, len(in.IDs))}
	for _, id := range in.IDs {
		if ctx.Err() != nil {
			// The rows before this one may hold a POST that was sent,
			// so the call gives them, not an error.
			out.Rows = append(out.Rows, UnsubscribeRow{ID: id, Method: unsubMethodNone, Status: unsubStatusFailed, Note: unsubNoteTimeUp})
			continue
		}
		out.Rows = append(out.Rows, t.one(ctx, p, cfg, in.Account, id))
	}
	return out, nil
}

// one gives the row of one id, in the order of DS9.3: one-click, then
// mailto, then the link, then nothing.
func (t *unsubscribeTool) one(ctx context.Context, p Writer, cfg verify.Config, account, id string) UnsubscribeRow {
	row := UnsubscribeRow{ID: id}
	m, err := p.Read(ctx, id, mail.ReadOpts{Headers: []string{hdrListUnsubscribe, hdrListUnsubscribePost}})
	if err != nil || m == nil {
		row.Method, row.Status, row.Note = unsubMethodNone, unsubStatusFailed, unsubNoteReadFailed
		return row
	}
	lists := m.Headers[hdrListUnsubscribe]
	if len(lists) == 0 {
		row.Method, row.Status = unsubMethodNone, unsubStatusNoHeader
		return row
	}
	httpsURL, mailtoURL := unsubscribeURLs(lists)
	postOK := len(lists) == 1 && oneClickHeader(m.Headers[hdrListUnsubscribePost])
	if httpsURL != nil && postOK {
		if t.dkim(m, cfg) {
			return t.oneClick(ctx, row, httpsURL)
		}
	}
	if mailtoURL != nil {
		return t.mailto(ctx, row, account, mailtoURL)
	}
	if httpsURL != nil {
		row.Method, row.Status = unsubMethodLink, unsubStatusSeeLink
		row.URL = guard.Fence("URL", httpsURL.String())
		if postOK {
			// Only the DKIM rule stopped the POST (G18).
			row.Status, row.Note = unsubStatusNoAuth, unsubNoteNoAuth
		}
		return row
	}
	row.Method, row.Status, row.Note = unsubMethodNone, unsubStatusNoHeader, unsubNoteNoURL
	return row
}

// oneClick sends the RFC 8058 POST. A 2xx is done; a refused redirect,
// any other status or an error gives the link.
func (t *unsubscribeTool) oneClick(ctx context.Context, row UnsubscribeRow, u *url.URL) UnsubscribeRow {
	row.Method = unsubMethodOneClick
	status, err := t.post(ctx, u.String())
	if err == nil && status >= 200 && status < 300 {
		row.Status = unsubStatusDone
		return row
	}
	row.Status = unsubStatusSeeLink
	row.URL = guard.Fence("URL", u.String())
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
			return 0, errors.New("unsubscribe: the one-click URL is not https")
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
