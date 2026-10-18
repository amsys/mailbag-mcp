// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the signature step of the draft tool (DI3): the own-text
// checks, the text part layout, the HTML-only caller and the HTML
// part.
package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// ownerSig is the signature shape of the owner, with the empty line
// that the 2026-10-15 incident lost.
const ownerSig = "Thanking you in anticipation,\n\nYours faithfully,\nAnn Example"

// ownerSigLost is ownerSig with the empty line lost: a near copy.
const ownerSigLost = "Thanking you in anticipation,\nYours faithfully,\nAnn Example"

// sigTOML gives an account in identity mode with one identity that has
// ownerSig. extra is put into the identity table as more keys.
func sigTOML(extra string) string {
	return `secrets = "file"

[accounts.work]
provider = "imap"
email = "me@example.test"
imap = "127.0.0.1:1"
smtp = "127.0.0.1:2"

[[accounts.work.identity]]
email = "me@example.test"
name = "Ann Example"
signature = "Thanking you in anticipation,\n\nYours faithfully,\nAnn Example"
` + extra
}

// sigOrig is an original message that ends with the owner's own
// signature, so a reply quote and a forward block both hold a copy
// (I10).
func sigOrig() *mail.Message {
	return &mail.Message{
		ID:        "1",
		MessageID: "<orig@example.test>",
		From:      mail.Address{Name: "Ann", Address: "ann@other.test"},
		To:        []mail.Address{{Address: "me@example.test"}},
		Date:      internalDate,
		Subject:   "order",
		Body:      "where is it\n\n-- \n" + ownerSig,
	}
}

// quoteOf is the quote block that addReply builds for orig.
func quoteOf(orig *mail.Message) string {
	return mime.QuoteText(orig.Date, fromMailbox(addressText(orig.From)), orig.Body)
}

// forwardOf is the forward block that addForward builds for orig.
func forwardOf(orig *mail.Message) string {
	return mime.ForwardBody(fromMailbox(addressText(orig.From)), orig.Date,
		fromMailbox(orig.Subject), bareList(orig.To), orig.Body)
}

// saveDraft runs the draft tool over sigTOML(extra) and orig, and
// gives the one saved message and the Note.
func saveDraft(t *testing.T, extra string, orig *mail.Message, in DraftIn) (*mail.Outgoing, string) {
	t.Helper()
	h, rec := identityDraft(t, sigTOML(extra), orig)
	in.Account = "work"
	out, err := h.handle(context.Background(), in)
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	if len(rec.drafts) != 1 {
		t.Fatalf("drafts = %d, want 1", len(rec.drafts))
	}
	return rec.drafts[0], out.Note
}

// refuseDraft runs the draft tool and wants errSignatureInBody with
// nothing saved.
func refuseDraft(t *testing.T, extra string, orig *mail.Message, in DraftIn) {
	t.Helper()
	h, rec := identityDraft(t, sigTOML(extra), orig)
	in.Account = "work"
	_, err := h.handle(context.Background(), in)
	if !errors.Is(err, errSignatureInBody) {
		t.Fatalf("err = %v, want errSignatureInBody", err)
	}
	if len(rec.drafts) != 0 {
		t.Fatalf("a refused draft reached SaveDraft %d times", len(rec.drafts))
	}
}

// builtParts builds m as mime.Build writes it and reads it back
// through bodyParts, the reader of the send summary. It gives the text
// part with CRLF as LF, and the HTML part as text ("" when there is
// none).
func builtParts(t *testing.T, m *mail.Outgoing) (text, html string) {
	t.Helper()
	from := m.From
	if from == "" {
		from = "me@example.test"
	}
	var buf bytes.Buffer
	in := mime.Input{From: from, To: m.To, Cc: m.Cc, Subject: m.Subject, Text: m.Text, HTML: m.HTML}
	if err := mime.Build(&buf, in, time.Unix(0, 0), bytes.NewReader(make([]byte, 64))); err != nil {
		t.Fatalf("build: %v", err)
	}
	parts, _, err := bodyParts(buf.Bytes())
	if err != nil {
		t.Fatalf("bodyParts: %v", err)
	}
	for _, p := range parts {
		if p.html {
			html = p.text
		} else {
			text = strings.ReplaceAll(p.text, "\r\n", "\n")
		}
	}
	return text, html
}

// TestCleanOwn holds DI3.2: an exact copy at the end of the own text
// is cut, a near copy or any other delimiter line is refused, and text
// with no copy stays as it is.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestCleanOwn(t *testing.T) {
	cases := []struct {
		name, own, sig, want string
		refused              bool
	}{
		{name: "no copy", own: "Hello\n\nsee you", sig: ownerSig, want: "Hello\n\nsee you"},
		{name: "crlf", own: "Hello\r\nsee you", sig: ownerSig, want: "Hello\nsee you"},
		{name: "exact with delimiter", own: "Hello\n\n-- \n" + ownerSig + "\n\n", sig: ownerSig, want: "Hello"},
		{name: "exact without delimiter", own: "Hello\n \n\n" + ownerSig, sig: ownerSig, want: "Hello"},
		{name: "exact in crlf", own: "Hello\r\n\r\n-- \r\n" + strings.ReplaceAll(ownerSig, "\n", "\r\n"), sig: ownerSig, want: "Hello"},
		{name: "only the copy", own: "-- \n" + ownerSig, sig: ownerSig, want: ""},
		{name: "trailing space of the signature", own: "Hi\n\n-- \nAnn", sig: "Ann  ", want: "Hi"},
		{name: "owner near copy, lost empty line", own: "Hello\n\n" + ownerSigLost, sig: ownerSig, refused: true},
		{name: "owner near copy with delimiter", own: "Hello\n\n-- \n" + ownerSigLost, sig: ownerSig, refused: true},
		{name: "near copy, folded onto one line", own: "Hello Thanking you in anticipation, Yours faithfully, Ann Example", sig: ownerSig, refused: true},
		{name: "copy not at the end", own: ownerSig + "\n\nP.S. more", sig: ownerSig, refused: true},
		{name: "copy inside a line", own: "Hello\n\nx" + ownerSig, sig: ownerSig, refused: true},
		{name: "two exact copies", own: "Hi\n\n" + ownerSig + "\n\n" + ownerSig, sig: ownerSig, refused: true},
		{name: "other delimiter line", own: "Hello\n-- \nother sig", sig: ownerSig, refused: true},
		{name: "bare dashes", own: "Hello\n--\t\nother", sig: ownerSig, refused: true},
		{name: "delimiter without space before the copy", own: "Hello\n--\n" + ownerSig, sig: ownerSig, refused: true},
		{name: "dashes in text", own: "a -- b\n---\n-- x", sig: ownerSig, want: "a -- b\n---\n-- x"},
		{name: "blank signature checks no copy", own: "Hello world", sig: " ", want: "Hello world"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cleanOwn(tc.own, tc.sig)
			if tc.refused {
				if !errors.Is(err, errSignatureInBody) {
					t.Fatalf("cleanOwn = %q, %v; want errSignatureInBody", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("cleanOwn: %v", err)
			}
			if got != tc.want {
				t.Errorf("cleanOwn = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestTextToHTML holds DI3.5: the HTML that textToHTML builds escapes
// &, < and >, splits paragraphs at empty lines, turns a single newline
// into br, and passes AllowHTML and the nesting check unchanged.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestTextToHTML(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"Hi", "<p>Hi</p>"},
		{"a\nb", "<p>a<br>b</p>"},
		{"a\n\n\nb", "<p>a</p><p>b</p>"},
		{"a\r\nb", "<p>a<br>b</p>"},
		{"x < y & z > w", "<p>x &lt; y &amp; z &gt; w</p>"},
		{"&amp; 'q' \"d\"", "<p>&amp;amp; 'q' \"d\"</p>"},
		{ownerSig, "<p>Thanking you in anticipation,</p><p>Yours faithfully,<br>Ann Example</p>"},
	}
	for _, tc := range cases {
		got := textToHTML(tc.in)
		if got != tc.want {
			t.Errorf("textToHTML(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if clean, removed := mime.AllowHTML(got); clean != got || removed != 0 {
			t.Errorf("AllowHTML changed %q to %q (%d removed)", got, clean, removed)
		}
		if _, nested := mime.HTMLToTextCount(got); nested != 0 {
			t.Errorf("HTMLToTextCount(%q) reports %d", got, nested)
		}
	}
}

// TestSignature_NotIdentityMode holds I2 for DI3: an account with no
// identity table adds no signature and runs no own-text check, so a
// body with a delimiter line saves as it is.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestSignature_NotIdentityMode(t *testing.T) {
	body := "Hello\n\n-- \n" + ownerSigLost
	h, rec := identityDraft(t, plainTOML, sigOrig())
	for _, in := range []DraftIn{
		{Account: "work", To: []string{"ann@other.test"}, Body: body},
		{Account: "work", ReplyToID: "1", Body: body},
		{Account: "work", ForwardID: "1", Body: body},
	} {
		if _, err := h.handle(context.Background(), in); err != nil {
			t.Fatalf("draft: %v", err)
		}
	}
	wants := []string{
		body,
		body + "\n\n" + quoteOf(sigOrig()),
		body + "\n\n" + forwardOf(sigOrig()),
	}
	for i, want := range wants {
		if got := rec.drafts[i].Text; got != want {
			t.Errorf("draft %d text = %q, want %q", i, got, want)
		}
		if rec.drafts[i].HTML != "" {
			t.Errorf("draft %d has an HTML part %q", i, rec.drafts[i].HTML)
		}
	}
}

// TestDraft_SignatureNew holds DI3.1 and DI3.3 for a new draft: the
// text part is O, then "-- \n" + Signature byte for byte, and the
// Note says so. With signature_on_new = false no signature is added,
// but the own-text check still runs.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestDraft_SignatureNew(t *testing.T) {
	m, note := saveDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, Subject: "hi", Body: "Hello Ann"})
	want := "Hello Ann\n\n-- \n" + ownerSig
	if m.Text != want {
		t.Errorf("text = %q, want %q", m.Text, want)
	}
	if text, html := builtParts(t, m); text != want || html != "" {
		t.Errorf("built text part = %q, html %q; want %q and no HTML part", text, html, want)
	}
	if m.HTML != "" {
		t.Errorf("HTML = %q, want no HTML part (compose_html is false)", m.HTML)
	}
	if !strings.Contains(note, "Signature added.") {
		t.Errorf("Note = %q", note)
	}

	m, note = saveDraft(t, "signature_on_new = false\n", nil, DraftIn{To: []string{"ann@other.test"}, Body: "Hello Ann"})
	if m.Text != "Hello Ann" {
		t.Errorf("text = %q, want the own text alone", m.Text)
	}
	if !strings.Contains(note, "No signature.") {
		t.Errorf("Note = %q", note)
	}
	refuseDraft(t, "signature_on_new = false\n", nil, DraftIn{To: []string{"ann@other.test"}, Body: "Hello\n\n" + ownerSigLost})
}

// TestDraft_SignatureOwnerNearCopy holds I5 for the 2026-10-15
// incident: the owner's signature retyped with its empty line lost is
// refused, with and without a delimiter, on a new draft, a reply and a
// replace.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestDraft_SignatureOwnerNearCopy(t *testing.T) {
	for _, body := range []string{
		"Dear Ann,\n\nplease find the quote.\n\n" + ownerSigLost,
		"Dear Ann,\n\nplease find the quote.\n\n-- \n" + ownerSigLost,
	} {
		refuseDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, Body: body})
		refuseDraft(t, "", sigOrig(), DraftIn{ReplyToID: "1", Body: body})
		refuseDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, Body: body, DraftID: "d0"})
	}
}

// TestDraft_SignatureReplaceExactCopy holds I5 on the replace path: a
// draft_id call whose body is the text of the earlier draft, with its
// exact signature, saves with one delimiter and one signature.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestDraft_SignatureReplaceExactCopy(t *testing.T) {
	first, _ := saveDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, Body: "Hello Ann"})
	again, _ := saveDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, Body: first.Text + "\n", DraftID: "d1"})
	if again.Text != first.Text {
		t.Errorf("replace text = %q, want %q", again.Text, first.Text)
	}
	if n := strings.Count(again.Text, "-- \n"); n != 1 {
		t.Errorf("replace text has %d delimiters, want 1", n)
	}
	// The same copy with no delimiter is also cut.
	again, _ = saveDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, Body: "Hello Ann\n\n" + ownerSig, DraftID: "d1"})
	if again.Text != first.Text {
		t.Errorf("replace text = %q, want %q", again.Text, first.Text)
	}
}

// TestDraft_SignatureReplyLayout holds DI3.3 for a reply: the three
// placements of reply_above_quote and signature_below_quote, and the
// quote off. The original ends with the owner's own signature, and the
// quote stays whole and unchecked (I10).
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestDraft_SignatureReplyLayout(t *testing.T) {
	orig := sigOrig()
	q := quoteOf(orig)
	s := "-- \n" + ownerSig
	o := "On its way."
	off := false
	cases := []struct {
		name, extra string
		quote       *bool
		want        string
	}{
		{"defaults", "", nil, o + "\n\n" + s + "\n\n" + q},
		{"signature below quote", "signature_below_quote = true\n", nil, o + "\n\n" + q + "\n\n" + s},
		{"reply below quote", "reply_above_quote = false\n", nil, q + "\n\n" + o + "\n\n" + s},
		{"reply below, signature below", "reply_above_quote = false\nsignature_below_quote = true\n", nil, q + "\n\n" + o + "\n\n" + s},
		{"quote off", "signature_below_quote = true\n", &off, o + "\n\n" + s},
		{"no signature on reply", "signature_on_reply = false\n", nil, o + "\n\n" + q},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := saveDraft(t, tc.extra, orig, DraftIn{ReplyToID: "1", Body: o, Quote: tc.quote})
			if m.Text != tc.want {
				t.Errorf("text =\n%q\nwant\n%q", m.Text, tc.want)
			}
			if text, _ := builtParts(t, m); text != tc.want {
				t.Errorf("built text part =\n%q\nwant\n%q", text, tc.want)
			}
		})
	}
	// A reply with no own text: the signature and the quote only.
	m, _ := saveDraft(t, "", orig, DraftIn{ReplyToID: "1"})
	if want := s + "\n\n" + q; m.Text != want {
		t.Errorf("text = %q, want %q", m.Text, want)
	}
}

// TestDraft_SignatureForward holds DI3.1 and DI3.3 for a forward: no
// signature by default (signature_on_forward = false), and O, S, F
// when it is on. The forward block holds the owner's signature and
// stays whole (I10).
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestDraft_SignatureForward(t *testing.T) {
	orig := sigOrig()
	f := forwardOf(orig)
	m, note := saveDraft(t, "", orig, DraftIn{ForwardID: "1", To: []string{"bob@other.test"}, Body: "FYI"})
	if want := "FYI\n\n" + f; m.Text != want {
		t.Errorf("text = %q, want %q", m.Text, want)
	}
	if !strings.Contains(note, "No signature.") {
		t.Errorf("Note = %q", note)
	}
	m, note = saveDraft(t, "signature_on_forward = true\n", orig, DraftIn{ForwardID: "1", To: []string{"bob@other.test"}, Body: "FYI"})
	if want := "FYI\n\n-- \n" + ownerSig + "\n\n" + f; m.Text != want {
		t.Errorf("text = %q, want %q", m.Text, want)
	}
	if !strings.Contains(note, "Signature added.") {
		t.Errorf("Note = %q", note)
	}
}

// TestDraft_SignatureHTMLOnly holds DI3.4 and DI3.5 for a caller that
// gives html and no body: the text part is the text of that HTML, the
// signature and the quote; the HTML part is the caller HTML and the
// HTML signature, with no quote. A copy of the signature in the HTML
// is refused, never cut.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestDraft_SignatureHTMLOnly(t *testing.T) {
	orig := sigOrig()
	html := "<p>On <b>its</b> way.</p>"
	m, _ := saveDraft(t, "", orig, DraftIn{ReplyToID: "1", HTML: html})
	wantText := "On its way.\n\n-- \n" + ownerSig + "\n\n" + quoteOf(orig)
	if m.Text != wantText {
		t.Errorf("text = %q, want %q", m.Text, wantText)
	}
	wantHTML := html + "<p>-- </p>" + textToHTML(ownerSig)
	if m.HTML != wantHTML {
		t.Errorf("HTML = %q, want %q", m.HTML, wantHTML)
	}
	text, htmlText := builtParts(t, m)
	if text != wantText {
		t.Errorf("built text part = %q, want %q", text, wantText)
	}
	if !strings.Contains(htmlText, "-- \nThanking you in anticipation,") || strings.Contains(htmlText, "where is it") {
		t.Errorf("HTML part as text = %q, want the signature and no quote", htmlText)
	}

	refuseDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"},
		HTML: "<p>Hi</p><p>Thanking you in anticipation,</p><p>Yours faithfully,<br>Ann Example</p>"})
	refuseDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, HTML: "<p>Hi</p><p>-- <br>Bob</p>"})
	// With a body too, the HTML is still only checked, never cut.
	refuseDraft(t, "", nil, DraftIn{To: []string{"ann@other.test"}, Body: "Hi",
		HTML: "<p>Hi</p><p>-- </p>" + textToHTML(ownerSig)})
}

// TestDraft_SignatureComposeHTML holds DI3.5 with compose_html: a body
// alone gets an HTML part built from O, plus the HTML signature; the
// signature_html of the identity wins over the derived form; the
// built message passes the HTML check of the send summary (I4).
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestDraft_SignatureComposeHTML(t *testing.T) {
	m, _ := saveDraft(t, "compose_html = true\n", sigOrig(), DraftIn{ReplyToID: "1", Body: "On its way.\nSoon & safe."})
	wantHTML := "<p>On its way.<br>Soon &amp; safe.</p><p>-- </p>" + textToHTML(ownerSig)
	if m.HTML != wantHTML {
		t.Errorf("HTML = %q, want %q", m.HTML, wantHTML)
	}
	_, htmlText := builtParts(t, m)
	if strings.Contains(htmlText, "where is it") {
		t.Errorf("HTML part as text = %q holds the quote", htmlText)
	}

	sigHTML := `<p><b>Ann Example</b><br><a href="https://example.test">example</a></p>`
	extra := fmt.Sprintf("compose_html = true\nsignature_html = %q\n", sigHTML)
	m, _ = saveDraft(t, extra, nil, DraftIn{To: []string{"ann@other.test"}, Body: "Hello"})
	if want := "<p>Hello</p><p>-- </p>" + sigHTML; m.HTML != want {
		t.Errorf("HTML = %q, want %q", m.HTML, want)
	}
	if want := "Hello\n\n-- \n" + ownerSig; m.Text != want {
		t.Errorf("text = %q, want the text signature %q", m.Text, want)
	}
	builtParts(t, m)

	// compose_html with no body builds no HTML part.
	m, _ = saveDraft(t, "compose_html = true\n", nil, DraftIn{To: []string{"ann@other.test"}, Subject: "hi"})
	if m.HTML != "" {
		t.Errorf("HTML = %q, want none with no body", m.HTML)
	}
	if want := "-- \n" + ownerSig; m.Text != want {
		t.Errorf("text = %q, want %q", m.Text, want)
	}
}

// TestSignature_PlaceRefusesUnclean holds the fail-closed rule of
// DI3.5: an HTML part that AllowHTML would change is refused.
//
// arch: DI2.0, DI3.1, DI3.2, DI3.3, DI3.4, DI3.5
func TestSignature_PlaceRefusesUnclean(t *testing.T) {
	acct := loadAccount(t, sigTOML(""))
	id := acct.Default()
	id.SignatureHTML = `<p style="color:red">x</p>`
	m := &mail.Outgoing{HTML: "<p>Hi</p>"}
	err := placeSignature(m, id, DraftIn{}, ownBody{add: true}, "")
	if !errors.Is(err, errComposedHTML) {
		t.Fatalf("err = %v, want errComposedHTML", err)
	}
}

// TestDraft_SignatureNearCopyForwardAndTemplates holds I5 on the
// forward path and on the templates draft action: the near copy is
// refused and nothing is saved.
//
// arch: DI3.2, I5
func TestDraft_SignatureNearCopyForwardAndTemplates(t *testing.T) {
	for _, body := range []string{
		"FYI\n\n" + ownerSigLost,
		"FYI\n\n-- \n" + ownerSigLost,
	} {
		refuseDraft(t, "signature_on_forward = true\n", sigOrig(),
			DraftIn{ForwardID: "1", To: []string{"bob@other.test"}, Body: body})
	}

	templatesHome(t)
	rec := &readRecorder{writeProvider: &writeProvider{msg: &mail.Message{}, draftID: "d1"}}
	h := &templatesTool{mail: &identityMail{prov: rec, acct: loadAccount(t, sigTOML(""))}}
	ctx := context.Background()
	if _, err := h.handle(ctx, TemplatesIn{
		Account: "work", Action: "save", Name: "near",
		Subject: "quote", Body: "Dear Ann,\n\n" + ownerSigLost,
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	_, err := h.handle(ctx, TemplatesIn{
		Account: "work", Action: "draft", Name: "near", To: []string{"ann@other.test"},
	})
	if !errors.Is(err, errSignatureInBody) {
		t.Fatalf("templates draft err = %v, want errSignatureInBody", err)
	}
	if len(rec.drafts) != 0 {
		t.Fatalf("a refused template draft reached SaveDraft %d times", len(rec.drafts))
	}
}

// TestDraft_SignatureNotAddedExactCopyRefused holds L1: when the
// identity does not add its signature, an exact copy in the text is
// refused. It is not cut without a sign.
//
// arch: DI3.1, DI3.2
func TestDraft_SignatureNotAddedExactCopyRefused(t *testing.T) {
	for _, body := range []string{"FYI\n\n-- \n" + ownerSig, "FYI\n\n" + ownerSig} {
		refuseDraft(t, "signature_on_forward = false\n", sigOrig(),
			DraftIn{ForwardID: "1", To: []string{"bob@other.test"}, Body: body})
	}
	refuseDraft(t, "signature_on_new = false\n", nil,
		DraftIn{To: []string{"ann@other.test"}, Body: "Hello\n\n" + ownerSig})
}

// TestCheckOwn_OneLineSignature holds L2: a one-line signature is a
// near copy at the end of the text only, and a multi-line signature
// is a near copy anywhere, also when a P.S. follows.
//
// arch: DI3.2, I5
func TestCheckOwn_OneLineSignature(t *testing.T) {
	if err := checkOwn("Ann will call you", "Ann"); err != nil {
		t.Errorf("one-line signature inside a sentence: %v, want no error", err)
	}
	if _, err := cleanOwn("Ann will call you tomorrow.", "Ann"); err != nil {
		t.Errorf("cleanOwn one-line signature in a sentence: %v, want no error", err)
	}
	if err := checkOwn("Thanks, Ann", "Ann"); !errors.Is(err, errSignatureInBody) {
		t.Errorf("one-line signature at the end: %v, want errSignatureInBody", err)
	}
	if err := checkOwn("Ann", "Ann"); !errors.Is(err, errSignatureInBody) {
		t.Errorf("one-line signature as the whole text: %v, want errSignatureInBody", err)
	}
	if err := checkOwn("Can you look at it, please EDIT", "IT"); err != nil {
		t.Errorf("one-line signature at the end of a word: %v, want no error", err)
	}
	for _, body := range []string{
		ownerSigLost,
		"Hello\n\n" + ownerSigLost + "\n\nP.S. more",
	} {
		if err := checkOwn(body, ownerSig); !errors.Is(err, errSignatureInBody) {
			t.Errorf("checkOwn(%q) = %v, want errSignatureInBody", body, err)
		}
	}
}
