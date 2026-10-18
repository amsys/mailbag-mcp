// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"errors"
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
// Every field is text this server wrote or an id a server gave, so
// none of it is fenced (§3.15).
//
// arch: D5.1, D10.3
type DraftOut struct {
	Account string `json:"account"`
	DraftID string `json:"draft_id"`
	// Note is text this server wrote. It tells how many items the
	// HTML allowlist removed (D5.5), and it tells an account below the
	// send level how to permit sending.
	Note string `json:"note,omitempty"`
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
// arch: D5.1, D5.5, D5.2, D10.3, §3.14, §3.17, DI2.3
func (t *draftTool) handle(ctx context.Context, in DraftIn) (DraftOut, error) {
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return DraftOut{}, err
	}
	if err := guard.Require(acct, guard.LevelDraft); err != nil {
		return DraftOut{}, err
	}
	if in.ReplyToID != "" && in.ForwardID != "" {
		return DraftOut{}, errors.New("reply_to_id and forward_id cannot both be set; one draft is one message")
	}
	var removed int
	in.HTML, removed = mime.AllowHTML(in.HTML)
	if !in.hasContent() {
		// An empty message would replace a stored draft with
		// nothing, or save a draft that nobody can send. The check
		// reads the html field after the cut, so html that the cut
		// empties is no content (R16-L4).
		return DraftOut{}, errors.New("the draft has no content; give recipients, a subject, a body, attachments, reply_to_id or forward_id")
	}
	if _, nested := mime.HTMLToTextCount(in.HTML); nested > 0 {
		// AllowHTML keeps an allowlist element at any nest depth, but
		// the send summary's text view stops after a depth limit
		// (D5.5, D5.2, I8). Text past that limit would leave with no
		// line in the summary, so the draft is refused, not saved.
		return DraftOut{}, errHTMLNested
	}

	m, pickSentence, cleanup, err := t.compose(ctx, p, acct, in)
	defer cleanup()
	if err != nil {
		return DraftOut{}, err
	}
	id, err := p.SaveDraft(ctx, m, in.DraftID)
	if err != nil {
		return DraftOut{}, err
	}
	out := DraftOut{Account: in.Account, DraftID: id}
	if removed > 0 {
		out.Note = fmt.Sprintf(htmlCutNote, removed)
	}
	if guard.Require(acct, guard.LevelSend) != nil {
		if out.Note != "" {
			out.Note += " "
		}
		out.Note += draftInsteadNote(in.Account, acct, id)
	}
	if pickSentence != "" {
		// Identity mode only (DI2.0, DI2.3): the sentence names the
		// From address, the identity and the pick rule.
		if out.Note != "" {
			out.Note += " "
		}
		out.Note += pickSentence
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
var errHTMLNested = errors.New("the html field nests elements too deep for the send confirmation to show in full; use less nesting")

// hasContent reports whether the call carries message text of its
// own. A call with none has nothing to save.
func (in DraftIn) hasContent() bool {
	return len(in.To) > 0 || len(in.Cc) > 0 || len(in.Bcc) > 0 ||
		in.Subject != "" || in.Body != "" || in.HTML != "" ||
		len(in.Attachments) > 0 || in.ReplyToID != "" || in.ForwardID != ""
}
