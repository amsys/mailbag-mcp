// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Note registry: the closed forms of every text that a tool or a
// provider puts in a `note` field. A note is outside every fence, so
// it holds only server text with closed slots. Provider error text, an
// address from a message, a folder or label name and model input go to
// `untrusted.detail` instead.

package tools

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// noteSep joins the registry texts of one note. No form contains it,
// so a split on it gives the parts back (DU12.1 item 3).
const noteSep = "; "

// noteWithheld replaces a note that matches no form. It is a form
// itself, so strictNote gives the same result when it runs again.
const noteWithheld = "note withheld"

// noteSlots gives the capture pattern of each slot of a form, and the
// guard.Strict kind that checks the captured text. An empty kind means
// the pattern alone is the check. No capture pattern with a kind holds
// a space, a dot or a closing bracket, so the literal text after such
// a slot ends it and Strict gets the whole slot text.
var noteSlots = map[string]struct{ re, kind string }{
	"n":      {`[0-9]{1,19}`, ""},
	"alias":  {`[A-Za-z0-9_-]{1,64}`, "alias"},
	"word":   {`[a-z0-9_]{1,32}`, "word"},
	"id":     {`[A-Za-z0-9_-]+`, "id"},
	"folder": {`=[0-9a-f]+`, "folder"},
	"date":   {`[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z`, "date"},
	// actions is the change list of an undo summary: closed action
	// words, joined with ", ". A label or folder name is never in it.
	"actions": {`(?:read|unread|starred|not starred|trash|archive|move|add [0-9]{1,10} labels?|remove [0-9]{1,10} labels?)` +
		`(?:, (?:read|unread|starred|not starred|trash|archive|move|add [0-9]{1,10} labels?|remove [0-9]{1,10} labels?))*`, ""},
}

// noteTexts is the registry. Each entry is one form: literal text
// with slots in braces, for example "{n}". A note is one form, or
// several forms joined with noteSep. A text that has ";" between two
// clauses today is two forms here, so the tool keeps its text.
//
// A form that ends in ": {word}" names a class word of DU6.2; the
// text of the error goes to `untrusted.detail` of the same object.
var noteTexts = []string{
	noteWithheld,

	// IMAP search pages (internal/imap/search.go); read and export
	// give the preview note too.
	"the newest {n} messages were scanned",
	"more could match further back",
	"the newest {n} matching messages were checked",
	"a term of this query is checked on the client, so the match set can be incomplete",
	"previews are missing for {n} message(s)",

	// read and decrypt.
	"mark_read could not be applied: {word}",
	"the signature was not checked: the source could not be fetched",
	"the signature was not checked: the check did not finish",
	"this message is encrypted",
	"the decrypt tool can open it when decryption is on",
	"the body is empty: content sits outside the signature and the signed part has no text that this server can show",
	"the body is empty: the signed part has no text that this server can show",
	"the conversation could not be read: {word}",
	"the conversation may be longer than {n} messages",
	"only the newest {n} are shown",
	"{n} folder(s) could not be searched",
	"the conversation may be incomplete",
	"the decrypted message has no text part that can be shown",

	// export.
	"the conversation could not be read",
	"only the message itself is exported: {word}",
	"only the newest {n} were exported",

	// modify and bulk undo.
	"this account has no recorded operation",
	"the change stopped part of the way: {word}",
	"only the messages in applied changed",
	"no message changed",
	"every id is gone, because another client expunged or moved the message",
	"the change is done",
	"this operation has no undo token, because the server gave no new id for the move, and undo cannot find the message again by its old id",
	"this operation has no undo token, because the journal could not be written",
	"{n} of the {n} messages needed no change to go back",
	"the operation is marked reversed",
	"no message needed a change to go back",
	"{n} messages changed or gone since the operation were left as they are",

	// folders: a create, rename or delete whose list read failed after
	// the change gives "the change is done" and this form (DU12.4
	// item 4).
	"the folder list could not be read: {word}",

	// bulk.
	"dry run: nothing changed",
	"the set stops at max = {n}",
	"more messages can match",
	"more messages can match, and a second bulk call takes them",
	"nothing matches",
	"no change",
	"declined",
	"nothing changed",
	"the human allowed later bulk changes on this account with no question until the client reconnects",
	"no question: the human allowed bulk changes on this account until the client reconnects",
	"{n} of the {n} messages changed",
	"the server could not remove the old copies of the moved messages, so they are in two folders",
	"undo record {id} holds the first {n} messages",
	"the journal could not be written for every chunk",
	"the undo token reverses {n} of the {n} messages that changed",

	// UndoRow.Summary of modify and bulk: closed action words and a
	// count. The names of labels and folders go to untrusted.detail.
	"{actions} on {n} message",
	"{actions} on {n} messages",
	"bulk: {actions}",
	"{n} message matched",
	"{n} messages matched",

	// draft. The identity note names the rule of DI2.2 only; the
	// picked address goes to untrusted.detail.
	"{n} items removed from html. Only p, br, b, strong, i, em, u, ul, ol, li, blockquote, and a with an http, https or mailto href stay.",
	`account {alias} has access={word}. The message is saved as a draft (id {id}). Set access = "send" in accounts.toml to permit sending.`,
	"the From address was picked by rule {n}",
	"signature added",
	"no signature",
	"the reply goes to the Reply-To address of the message, which differs from its From address",
	"check the To line before you send",

	// send. A provider warning is a fixed sentence and a class word;
	// the provider text goes to untrusted.detail (DU12.1 item 2).
	"not sent: the human did not confirm",
	"the message was sent, but the draft could not be removed: {word}",
	"the message was sent, but the Sent copy was stored but not found again: {word}",
	"the message was sent, but the copy in the Sent folder failed: {word}",
	"the message was sent, but the server did not move it to Sent: {word}",
	"the message was sent, but the account has no mailbox with the role sent, so it stays where the draft was",
	"the message was sent, but the server did not report the move to Sent",

	// unsubscribe.
	"the message has no dkim=pass from the configured authserv_id for the From domain, so no one-click POST was sent",
	"open the link if you trust it",
	"the List-Unsubscribe header has no https or mailto URL",
	"the message could not be read",
	"the mailto URL could not be made into a draft",
	"the one-click POST failed or was redirected",
	"open the link",
	"the one-click POST got status {n}",
	"the call ran out of time before this id",
	"run it again for this id",
	"the draft is not sent",
	"send it with the send tool",

	// templates.
	"{n} of {n} templates shown.",
	"{n} templates could not be read: each is not a regular file in the templates directory.",
	"{n} templates are not shown: each name has more than {n} characters.",

	// accounts: the add hint (addAccountHint) is two forms.
	"no account yet",
	"add one in a terminal with `mailbag-mcp account add`",

	// gmail_settings.
	"gmail_settings works for Gmail accounts only",
	"{alias} uses {word}",
	"the account has no filters",
	"the address has no signature",
	"filter created",
	"filter deleted",
	"vacation reply on",
	"vacation reply off",
	"signature saved",
}

// noteForm is one compiled form: an anchored pattern, and the Strict
// kind of each capture group in order.
type noteForm struct {
	text  string
	re    *regexp.Regexp
	kinds []string
}

// noteForms holds the compiled registry.
var noteForms = compileNoteForms(noteTexts)

// noteSlotRe finds a slot in a form text.
var noteSlotRe = regexp.MustCompile(`\{([a-z]+)\}`)

// compileNoteForms compiles each form text. It panics on a form that
// names an unknown slot or holds noteSep, because the registry is
// fixed at build time and a test runs it.
func compileNoteForms(texts []string) []noteForm {
	forms := make([]noteForm, 0, len(texts))
	for _, text := range texts {
		forms = append(forms, compileNoteForm(text))
	}
	return forms
}

// compileNoteForm compiles one form text to an anchored pattern.
func compileNoteForm(text string) noteForm {
	if strings.Contains(text, noteSep) || strings.ContainsAny(text, "\r\n") {
		panic(fmt.Sprintf("note form holds a separator: %q", text))
	}
	var b strings.Builder
	var kinds []string
	b.WriteString("^")
	last := 0
	for _, m := range noteSlotRe.FindAllStringSubmatchIndex(text, -1) {
		slot, ok := noteSlots[text[m[2]:m[3]]]
		if !ok {
			panic(fmt.Sprintf("note form names an unknown slot: %q", text))
		}
		b.WriteString(regexp.QuoteMeta(text[last:m[0]]))
		b.WriteString("(" + slot.re + ")")
		kinds = append(kinds, slot.kind)
		last = m[1]
	}
	b.WriteString(regexp.QuoteMeta(text[last:]))
	b.WriteString("$")
	return noteForm{text: text, re: regexp.MustCompile(b.String()), kinds: kinds}
}

// match reports whether part is this form, with each slot text valid
// for its Strict kind.
func (f noteForm) match(part string) bool {
	m := f.re.FindStringSubmatch(part)
	if m == nil {
		return false
	}
	for i, kind := range f.kinds {
		if kind != "" && !guard.Strict(kind, m[i+1]) {
			return false
		}
	}
	return true
}

// isNoteForm reports whether part matches one form of the registry.
func isNoteForm(part string) bool {
	for _, f := range noteForms {
		if f.match(part) {
			return true
		}
	}
	return false
}

// strictNote checks a note against the registry. It splits s on
// noteSep, and each part must match one form. A note that passes comes
// back as it is, with true. Any other note gives noteWithheld and
// false; the output gate fails on false in tests. An empty note is no
// note and passes; the gate applies the omitempty rule to it.
//
// arch: DU3.5, DU12.1
func strictNote(s string) (note string, ok bool) {
	if s == "" {
		return "", true
	}
	for _, part := range strings.Split(s, noteSep) {
		if !isNoteForm(part) {
			return noteWithheld, false
		}
	}
	return s, true
}
