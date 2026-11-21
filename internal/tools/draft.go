// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The draft tool: it builds one message and saves it in the Drafts
// folder. Its result has two zones (DU5.1, DU5.5).

package tools

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// DraftIn is the input of the draft tool (D5.1). It holds the message
// content that the send tool took before R1-C. Each json tag is the
// tag the same field had on SendIn, and each optional field has
// omitempty (D10.3).
//
// arch: D5.1, D10.3
type DraftIn struct {
	Account     string   `json:"account"`
	To          []string `json:"to,omitempty"`
	Cc          []string `json:"cc,omitempty"`
	Bcc         []string `json:"bcc,omitempty"`
	Subject     string   `json:"subject,omitempty"`
	Body        string   `json:"body,omitempty"`
	HTML        string   `json:"html,omitempty"`
	Attachments []string `json:"attachments,omitempty" jsonschema:"absolute paths"`
	ReplyToID   string   `json:"reply_to_id,omitempty" jsonschema:"fills to, subject"`
	ReplyAll    bool     `json:"reply_all,omitempty"`
	ForwardID   string   `json:"forward_id,omitempty" jsonschema:"with its attachments"`
	Quote       *bool    `json:"quote,omitempty" jsonschema:"default true"`
	From        string   `json:"from,omitempty" jsonschema:"an account identity"`
	DraftID     string   `json:"draft_id,omitempty" jsonschema:"replace this draft"`
}

// DraftOut is the result of the draft tool: the account and the id of
// the saved draft. The send tool takes that id.
//
// Zones (DU5.1, DU5.5):
//   - Outside: Head, Account (kind alias), DraftID (kind id, in the
//     form that [normalizeID] writes) and Note (texts of the note
//     registry, DU3.5).
//   - Untrusted: Detail, the picked From address and the identity of
//     a draft in identity mode (DI2.3). The picked address can be a
//     catch-all address from the original, so a sender chose it.
//
// arch: D5.1, D10.3, DU5.1, DU5.5, DU3.5
type DraftOut struct {
	Head
	Account string `json:"account" strict:"alias"`
	DraftID string `json:"draft_id" strict:"id"`
	// Note is text this server wrote, one or more registry texts
	// joined with "; " (DU12.1 item 3). It tells how many items the
	// HTML allowlist removed (D5.5), and it tells an account below the
	// send level how to permit sending. It can also give the number of
	// the pick rule (DI2.2, DI2.3) and the fixed Reply-To sentence
	// (DH5.1). It holds no address.
	Note string `json:"note,omitempty" strict:"note"`
	// Untrusted holds the picked address in a fence of the nonce of
	// the response.
	Untrusted *Detail `json:"untrusted,omitempty"`
}

// AddDraft adds the "draft" tool to srv. The tool builds one message
// and saves it in the Drafts folder. It never sends: the send tool
// sends a saved draft by its id (D5.1).
//
// The tool gets [DefaultTimeout] (§3.1). It claims no annotation,
// for the same reason as the send tool: a saved draft is a change to
// the mailbox.
//
// arch: D5.1, D10.3, §3.16
func AddDraft(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &draftTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "draft",
		Description: "Save a new, reply or forward draft. mailbag adds the signature.",
	}, Wrap(logger, "draft", DefaultTimeout, h.handle))
}

type draftTool struct {
	mail Mail
}

// handle builds one message and saves it as a draft. With draft_id,
// the new message replaces that draft.
//
// The draft level is the floor of this tool: a read account cannot
// write a draft to a mailbox (§3.17, D5.1).
//
// The html field goes through [mime.AllowHTML] before the message is
// built (D5.5). A field that nests allowlist elements too deep for
// the send summary to show in full is refused here, and nothing is
// saved (errHTMLNested, D5.2, I8). The send tool refuses HTML that is
// not clean for any other reason, so a draft of this tool can always
// go to the confirmation.
//
// The result names the draft by the id that [normalizeID] writes for
// the provider kind (DU3.2). A saved draft whose id does not pass
// gives errDraftIDForm, because the send tool could not take it. The
// note names the pick rule by its number only; the picked address
// goes to untrusted.detail (DU3.5, DU5.5).
//
// arch: D5.1, D5.5, D5.2, D10.3, §3.14, §3.17, DI2.3, DH5.1, DU5.1, DU5.5, DU3.5, DU6.2
func (t *draftTool) handle(ctx context.Context, in DraftIn) (DraftOut, error) {
	f := fencer(ctx)
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return DraftOut{}, err
	}
	if err := guard.Require(acct, guard.LevelDraft); err != nil {
		return DraftOut{}, err
	}
	if in.ReplyToID != "" && in.ForwardID != "" {
		return DraftOut{}, errReplyAndForward
	}
	var removed int
	in.HTML, removed = mime.AllowHTML(in.HTML)
	if !in.hasContent() {
		// An empty message would replace a stored draft with
		// nothing, or save a draft that nobody can send. The check
		// reads the html field after the cut, so html that the cut
		// empties is no content (R16-L4).
		return DraftOut{}, errDraftEmpty
	}
	if _, nested := mime.HTMLToTextCount(in.HTML); nested > 0 {
		// AllowHTML keeps an allowlist element at any nest depth, but
		// the send summary's text view stops after a depth limit
		// (D5.5, D5.2, I8). Text past that limit would leave with no
		// line in the summary, so the draft is refused, not saved.
		return DraftOut{}, errHTMLNested
	}

	m, cn, cleanup, err := t.compose(ctx, p, acct, in)
	defer cleanup()
	if err != nil {
		return DraftOut{}, err
	}
	raw, err := p.SaveDraft(ctx, m, in.DraftID)
	if err != nil {
		return DraftOut{}, err
	}
	id, ok := normalizeID(acct.Provider, raw)
	if !ok {
		return DraftOut{}, errDraftIDForm
	}
	out := DraftOut{Account: acct.Alias, DraftID: id}
	if removed > 0 {
		out.Note = fmt.Sprintf(htmlCutNote, removed)
	}
	if guard.Require(acct, guard.LevelSend) != nil {
		out.Note = joinNote(out.Note, draftInsteadNote(acct.Alias, acct, id))
	}
	if cn.note != "" {
		// compose gives the rule number of the identity pick in
		// identity mode only (DI2.0, DI2.3). In either mode, compose
		// can also give the fixed Reply-To sentence of a reply (DH5.1).
		out.Note = joinNote(out.Note, cn.note)
	}
	if cn.detail != "" {
		out.Untrusted = &Detail{Detail: f.Wrap(cn.detail)}
	}
	return out, nil
}

// htmlCutNote is the note of the draft tool when the HTML allowlist
// removed items from the html field (D5.5). It names the allowlist,
// so the model can write HTML that stays whole.
const htmlCutNote = "%d items removed from html. Only p, br, b, strong, i, em, u, ul, ol, li, blockquote, and a with an http, https or mailto href stay."

// errHTMLNested is the fixed refusal of D5.5 for an html field that
// nests allowlist elements so deep that the send confirmation cannot
// show all of the text in full (D5.2, I8). AllowHTML keeps such text
// at any depth, but the summary's text view stops after a fixed
// depth, so nothing is saved.
//
// arch: D5.5, DU6.2
var errHTMLNested = public("invalid_input", "the html field nests elements too deep for the send confirmation to show in full; use less nesting")

// errReplyAndForward refuses a call that sets both reply_to_id and
// forward_id.
//
// arch: D5.1, DU6.2
var errReplyAndForward = public("invalid_input", "reply_to_id and forward_id cannot both be set; one draft is one message")

// errDraftEmpty refuses a call with no message content (R16-L4).
//
// arch: D5.1, DU6.2
var errDraftEmpty = public("invalid_input", "the draft has no content; give recipients, a subject, a body, attachments, reply_to_id or forward_id")

// errDraftIDForm is the error of a saved draft whose id does not pass
// [normalizeID] for the provider kind (DU3.2). The id is not written,
// and the send tool could not take it, so the call gives no result.
//
// arch: DU3.2, DU5.5, DU6.2, INV-10
var errDraftIDForm = public("error", "the draft was saved, but the mail server gave it an id in a form that this server does not accept; the send tool cannot use it")

// hasContent reports whether the call carries message text of its
// own. A call with none has nothing to save.
func (in DraftIn) hasContent() bool {
	return len(in.To) > 0 || len(in.Cc) > 0 || len(in.Bcc) > 0 ||
		in.Subject != "" || in.Body != "" || in.HTML != "" ||
		len(in.Attachments) > 0 || in.ReplyToID != "" || in.ForwardID != ""
}
