// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of Gmail Read, Raw and Attachment against fakeGmail (DS7.4,
// DS7.9): the part walk with text/plain first and then text/html, the
// base64url data with no padding (E8), the large part that comes
// through the attachment call (E9), the signed hint from the MIME
// tree, the attachment found by its partId, and the raw source.

package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// b64url gives s as base64url with no padding, as Gmail sends body
// data (E8).
func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// leaf gives a leaf part with the media type, the Content-Type header
// ct and the data s in the answer.
func leaf(partID, mimeType, ct, s string) msgPart {
	return msgPart{
		PartID:   partID,
		MimeType: mimeType,
		Headers:  []metaHeader{{Name: "Content-Type", Value: ct}},
		Body:     partBody{Size: int64(len(s)), Data: b64url(s)},
	}
}

// node gives a multipart node with the children.
func node(partID, mimeType string, parts ...msgPart) msgPart {
	return msgPart{
		PartID:   partID,
		MimeType: mimeType,
		Headers:  []metaHeader{{Name: "Content-Type", Value: mimeType + `; boundary="x"`}},
		Parts:    parts,
	}
}

// fullBody gives a format=full answer for id with the payload. The
// payload gets the From and Subject headers of a row.
func fullBody(t *testing.T, id string, payload msgPart) string {
	t.Helper()
	payload.Headers = append([]metaHeader{
		{Name: "From", Value: "Alice Example <alice@example.com>"},
		{Name: "Subject", Value: "Test"},
	}, payload.Headers...)
	m := fullMessage{Payload: payload}
	m.ID, m.ThreadID = id, id
	m.LabelIDs = []string{"INBOX"}
	m.InternalDate = "1791892800000"
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode the answer: %v", err)
	}
	return string(b)
}

// readFake gives a fake that answers labels.list and labels.get from
// the fixtures, messages.get of id with full, and the routes of extra.
func readFake(t *testing.T, id, full string, extra map[string]step) *fakeGmail {
	t.Helper()
	m := labelRoutes(t)
	m["GET messages/"+id] = step{status: 200, body: full}
	for k, v := range extra {
		m[k] = v
	}
	return newFakeGmailRoutes(t, routes(m))
}

// readOne calls Read of id on f with the options o.
func readOne(t *testing.T, f *fakeGmail, id string, o mail.ReadOpts) *mail.Message {
	t.Helper()
	p, _ := f.provider(nil)
	msg, err := p.Read(context.Background(), id, o)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return msg
}

// TestGmail_ReadTextThenHTML holds the Read row of DS7.4: one
// messages.get with format=full; the row fields come from
// payload.headers and internalDate; the body is the text/plain part
// when its words are those of the text/html part, the text of the
// HTML part (through mime.HTMLToText) when they differ or when there
// is no plain part, and the HTML source for format "html". The
// attachment list holds the partId as Ref.
//
// arch: DS7.4, DS7.9
func TestGmail_ReadTextThenHTML(t *testing.T) {
	const id = "18f0a1b2c3d4e5f7"
	full := fixture(t, "messages.full.json")
	f := readFake(t, id, full, nil)
	msg := readOne(t, f, id, mail.ReadOpts{})

	if want := "Hello Bob,\r\nsee you at 5.\r\n"; msg.Body != want {
		t.Errorf("Body = %q, want the plain part %q", msg.Body, want)
	}
	if msg.PartsDiffer || msg.HiddenRemoved != 0 {
		t.Errorf("PartsDiffer = %v, HiddenRemoved = %d, want false, 0", msg.PartsDiffer, msg.HiddenRemoved)
	}
	if msg.ID != id || msg.Subject != "Plans" || msg.From.Address != "alice@example.com" {
		t.Errorf("row = %q %q %q", msg.ID, msg.Subject, msg.From.Address)
	}
	if want := time.UnixMilli(1791892800000).UTC(); !msg.Date.Equal(want) {
		t.Errorf("Date = %v, want internalDate %v", msg.Date, want)
	}
	if msg.Folder != "INBOX" || msg.Flags.Seen {
		t.Errorf("Folder = %q, Seen = %v, want INBOX, false", msg.Folder, msg.Flags.Seen)
	}
	if msg.MessageID != "<full-1@example.com>" {
		t.Errorf("MessageID = %q", msg.MessageID)
	}
	if want := []string{"<root-1@example.com>", "<full-0@example.com>"}; !reflect.DeepEqual(msg.References, want) {
		t.Errorf("References = %q, want %q", msg.References, want)
	}
	if len(msg.ReplyTo) != 1 || msg.ReplyTo[0].Address != "team@example.com" {
		t.Errorf("ReplyTo = %+v", msg.ReplyTo)
	}
	if want := "Authentication-Results: mx.example.com; dkim=pass header.d=example.com\r\n"; msg.AuthResults != want {
		t.Errorf("AuthResults = %q, want %q", msg.AuthResults, want)
	}
	if msg.MediaType != "multipart/mixed" {
		t.Errorf("MediaType = %q", msg.MediaType)
	}
	wantAtt := []mail.Attachment{{Ref: "1", Filename: "report.pdf", ContentType: "application/pdf", Size: 11}}
	if !reflect.DeepEqual(msg.Attachments, wantAtt) {
		t.Errorf("Attachments = %+v, want %+v", msg.Attachments, wantAtt)
	}
	var full1 bool
	for _, r := range f.requests() {
		if r.Path == apiPrefix+"messages/"+id {
			q, _ := url.ParseQuery(r.RawQuery)
			if q.Get("format") != "full" {
				t.Errorf("messages.get format = %q, want full", q.Get("format"))
			}
			full1 = true
		}
		if strings.Contains(r.Path, "/attachments/") {
			t.Errorf("Read fetched an attachment: %s", r.Path)
		}
	}
	if !full1 {
		t.Error("Read made no messages.get call")
	}

	// The words differ: the body is the text of the HTML part.
	differ := node("", "multipart/alternative",
		leaf("0", "text/plain", "text/plain; charset=UTF-8", "Old text"),
		leaf("1", "text/html", "text/html; charset=UTF-8", "<p>New <b>text</b></p>"))
	msg = readOne(t, readFake(t, id, fullBody(t, id, differ), nil), id, mail.ReadOpts{})
	if !msg.PartsDiffer || strings.TrimSpace(msg.Body) != "New text" {
		t.Errorf("differ: Body = %q, PartsDiffer = %v, want the HTML text", msg.Body, msg.PartsDiffer)
	}

	// No plain part: the HTML part goes through mime.HTMLToText.
	htmlOnly := leaf("", "text/html", "text/html; charset=UTF-8", "<div>Only <i>HTML</i></div>")
	msg = readOne(t, readFake(t, id, fullBody(t, id, htmlOnly), nil), id, mail.ReadOpts{})
	if got, want := msg.Body, mime.HTMLToText("<div>Only <i>HTML</i></div>"); got != want || strings.Contains(got, "<") {
		t.Errorf("html only: Body = %q, want %q", got, want)
	}

	// format "html" gives the HTML source.
	msg = readOne(t, readFake(t, id, full, nil), id, mail.ReadOpts{Format: "html"})
	if want := "<p>Hello Bob,</p><p>see you at 5.</p>"; msg.Body != want {
		t.Errorf("format html: Body = %q, want %q", msg.Body, want)
	}

	// Offset and MaxChars cut the body in characters.
	msg = readOne(t, readFake(t, id, full, nil), id, mail.ReadOpts{Offset: 6, MaxChars: 3})
	if msg.Body != "Bob" {
		t.Errorf("Offset 6, MaxChars 3: Body = %q, want Bob", msg.Body)
	}
}

// TestGmail_Base64URLNoPadding holds E8: body data is base64url with
// no padding; Read and Raw strip any "=" and decode with
// base64.RawURLEncoding. The text uses the two characters that differ
// from standard base64 ("-" and "_") and a length that needs padding.
// The charset of the Content-Type header applies after the decode.
//
// arch: DS7.4, DS7.9
func TestGmail_Base64URLNoPadding(t *testing.T) {
	const id = "18f0a1b2c3d4e5f8"
	text := "ÿû?>~ ok"
	enc := b64url(text)
	if !strings.ContainsAny(enc, "-_") || len(enc)%4 == 0 {
		t.Fatalf("test data %q does not show the base64url case", enc)
	}
	for _, data := range []string{enc, base64.URLEncoding.EncodeToString([]byte(text))} {
		part := leaf("", "text/plain", "text/plain; charset=UTF-8", text)
		part.Body.Data = data
		msg := readOne(t, readFake(t, id, fullBody(t, id, part), nil), id, mail.ReadOpts{})
		if msg.Body != text {
			t.Errorf("data %q: Body = %q, want %q", data, msg.Body, text)
		}
	}

	// A Latin-1 part: the bytes decode first, then the charset.
	latin := leaf("", "text/plain", "text/plain; charset=ISO-8859-1", "")
	latin.Body.Data = base64.RawURLEncoding.EncodeToString([]byte{'C', 'a', 'f', 0xE9, 0xFF, 0xFB})
	msg := readOne(t, readFake(t, id, fullBody(t, id, latin), nil), id, mail.ReadOpts{})
	if want := "Caféÿû"; msg.Body != want {
		t.Errorf("Latin-1: Body = %q, want %q", msg.Body, want)
	}

	// Data that is not base64url fails the call.
	bad := leaf("", "text/plain", "text/plain", "")
	bad.Body.Data = "a+b/"
	p, _ := readFake(t, id, fullBody(t, id, bad), nil).provider(nil)
	if _, err := p.Read(context.Background(), id, mail.ReadOpts{}); err == nil {
		t.Error("Read of standard base64 data: no error")
	}
}

// TestGmail_LargePartViaAttachment holds E9: a text part with
// body.attachmentId and no body.data is read through
// messages/{id}/attachments/{attachmentId}. A part above
// mime.MaxPartBytes is cut there, and the signed hint is then
// SignedUnknown, because the text after the cut can hold a marker
// (DRV.4).
//
// arch: DS7.4, DS7.9
func TestGmail_LargePartViaAttachment(t *testing.T) {
	const id = "18f0a1b2c3d4e5f9"
	const attID = "ANGjdJ_large-part_1"
	text := strings.Repeat("Large text line.\r\n", 100)
	part := leaf("", "text/plain", "text/plain; charset=UTF-8", "")
	part.Body = partBody{AttachmentID: attID, Size: int64(len(text))}
	attPath := "GET messages/" + id + "/attachments/" + attID
	f := readFake(t, id, fullBody(t, id, part), map[string]step{
		attPath: {status: 200, body: `{"size":` + itoa(len(text)) + `,"data":"` + b64url(text) + `"}`},
	})
	msg := readOne(t, f, id, mail.ReadOpts{})
	if msg.Body != text {
		t.Errorf("Body = %d bytes, want the %d bytes of the attachment call", len(msg.Body), len(text))
	}
	if msg.SignedHint != mail.SignedNo {
		t.Errorf("SignedHint = %v, want SignedNo: the whole part was read", msg.SignedHint)
	}
	if len(msg.Attachments) != 0 {
		t.Errorf("Attachments = %+v, want none: the part is the body", msg.Attachments)
	}
	n := 0
	for _, r := range f.requests() {
		if r.Path == apiPrefix+"messages/"+id+"/attachments/"+attID {
			n++
		}
	}
	if n != 1 {
		t.Errorf("attachment calls = %d, want 1", n)
	}

	// Above the part cap: the text is cut and the hint is unknown.
	big := strings.Repeat("a", int(mime.MaxPartBytes)+10)
	part.Body.Size = int64(len(big))
	f = readFake(t, id, fullBody(t, id, part), map[string]step{
		attPath: {status: 200, body: `{"size":` + itoa(len(big)) + `,"data":"` + b64url(big) + `"}`},
	})
	msg = readOne(t, f, id, mail.ReadOpts{})
	if int64(len(msg.Body)) != mime.MaxPartBytes {
		t.Errorf("Body = %d bytes, want the cap %d", len(msg.Body), mime.MaxPartBytes)
	}
	if msg.SignedHint != mail.SignedUnknown {
		t.Errorf("cut part: SignedHint = %v, want SignedUnknown", msg.SignedHint)
	}
}

// itoa gives n in decimal.
func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestGmail_SignedHint holds the SignedHint rule of DS7.4: the hint
// comes from the MIME tree with mail.SMIMEKindOf (D6.2). A
// multipart/signed or a pkcs7-mime node at any depth gives SignedYes;
// so does the inline PGP marker in the text. One top-level
// enveloped-data part is out (DR1G.7). A plain text that Read decoded
// in full gives SignedNo.
//
// arch: DS7.4, DS7.9
func TestGmail_SignedHint(t *testing.T) {
	const id = "18f0a1b2c3d4e600"
	plain := leaf("1", "text/plain", "text/plain; charset=UTF-8", "Hello")
	sig := leaf("2", "application/pkcs7-signature", "application/pkcs7-signature; name=smime.p7s", "sig")
	sig.Filename = "smime.p7s"
	enveloped := leaf("", "application/pkcs7-mime", `application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m`, "x")
	innerEnv := enveloped
	innerEnv.PartID = "1"
	signedData := enveloped
	signedData.Headers = []metaHeader{{Name: "Content-Type", Value: "application/pkcs7-mime; smime-type=signed-data"}}
	pgp := leaf("", "text/plain", "text/plain", "Intro\r\n"+mail.InlinePGPMarker+"\r\nHash: SHA256\r\n")
	both := node("", "multipart/alternative",
		leaf("0", "text/plain", "text/plain", "a"),
		leaf("1", "text/html", "text/html", "<p>a</p>"),
	)

	cases := []struct {
		name    string
		payload msgPart
		want    mail.SignedState
	}{
		{"multipart/signed", node("", "multipart/signed", plain, sig), mail.SignedYes},
		{"nested signed", node("", "multipart/mixed", node("0", "multipart/signed", plain, sig)), mail.SignedYes},
		{"pkcs7 in multipart", node("", "multipart/mixed", plain, innerEnv), mail.SignedYes},
		{"top-level signed-data", signedData, mail.SignedYes},
		{"inline PGP", pgp, mail.SignedYes},
		{"top-level enveloped", enveloped, mail.SignedNo},
		{"plain only", leaf("", "text/plain", "text/plain", "Hello"), mail.SignedNo},
		{"plain and html", both, mail.SignedNo},
		{"second plain part", node("", "multipart/mixed", plain, leaf("3", "text/plain", "text/plain", "b")), mail.SignedUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := readOne(t, readFake(t, id, fullBody(t, id, c.payload), nil), id, mail.ReadOpts{})
			if msg.SignedHint != c.want {
				t.Errorf("SignedHint = %v, want %v", msg.SignedHint, c.want)
			}
		})
	}

	msg := readOne(t, readFake(t, id, fullBody(t, id, enveloped), nil), id, mail.ReadOpts{})
	if msg.MediaType != "application/pkcs7-mime" || msg.SMIMEType != "enveloped-data" {
		t.Errorf("MediaType, SMIMEType = %q, %q", msg.MediaType, msg.SMIMEType)
	}
}

// TestGmail_AttachmentByPartID holds the Attachment row of DS7.4: Ref
// is the partId, which stays the same; the attachmentId changes on
// each fetch (R§7.2), so Attachment calls messages.get with
// format=full and uses the attachmentId of that answer. A file name
// is also a ref (C19); an unknown ref fails with a fixed text.
//
// arch: DS7.4, DS7.9
func TestGmail_AttachmentByPartID(t *testing.T) {
	const id = "18f0a1b2c3d4e5f7"
	const content = "%PDF-1.4 ok"
	full := fixture(t, "messages.full.json")
	labels := labelRoutes(t)

	var mu sync.Mutex
	fetches := 0
	gen := func(n int) string { return "ANGjdJ_gen-" + itoa(n) }
	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		path := strings.TrimPrefix(r.URL.Path, apiPrefix)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case path == "messages/"+id && r.URL.Query().Get("format") == "full":
			fetches++
			return step{status: 200, body: strings.Replace(full, "ATTACHMENT_ID", gen(fetches), 1)}
		case path == "messages/"+id+"/attachments/"+gen(fetches):
			return step{status: 200, body: `{"size":11,"data":"` + b64url(content) + `"}`}
		}
		return routes(labels)(r)
	})
	p, _ := f.provider(nil)
	ctx := context.Background()

	msg, err := p.Read(ctx, id, mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(msg.Attachments) != 1 || msg.Attachments[0].Ref != "1" {
		t.Fatalf("Attachments = %+v, want Ref 1", msg.Attachments)
	}
	for _, ref := range []string{msg.Attachments[0].Ref, "report.pdf"} {
		rc, info, err := p.Attachment(ctx, id, ref)
		if err != nil {
			t.Fatalf("Attachment(%q): %v", ref, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || string(data) != content {
			t.Errorf("Attachment(%q) = %q, %v, want %q", ref, data, err, content)
		}
		want := mail.AttachmentInfo{Filename: "report.pdf", ContentType: "application/pdf", Size: int64(len(content))}
		if info != want {
			t.Errorf("Attachment(%q) info = %+v, want %+v", ref, info, want)
		}
	}
	var atts []string
	for _, r := range f.requests() {
		if i := strings.Index(r.Path, "/attachments/"); i >= 0 {
			atts = append(atts, r.Path[i+len("/attachments/"):])
		}
	}
	if want := []string{gen(2), gen(3)}; !reflect.DeepEqual(atts, want) {
		t.Errorf("attachment calls = %q, want the id of each new fetch %q", atts, want)
	}

	if _, _, err := p.Attachment(ctx, id, "9"); err == nil || !strings.Contains(err.Error(), "no attachment with this ref") {
		t.Errorf("unknown ref: err = %v", err)
	}
	if _, _, err := p.Attachment(ctx, id, ""); err == nil {
		t.Error("empty ref: no error")
	}
}

// TestGmail_RawDecodes holds the Raw row of DS7.4: messages.get with
// format=raw, and the raw field decodes from base64url (E8) to the
// exact source bytes.
//
// arch: DS7.4, DS7.9
func TestGmail_RawDecodes(t *testing.T) {
	const id = "18f0a1b2c3d4e601"
	src := "From: Alice Example <alice@example.com>\r\nTo: me@example.com\r\nSubject: Raw\r\n" +
		"Message-ID: <raw-1@example.com>\r\n\r\nbody \xff\xfb?>~\r\n"
	enc := b64url(src)
	if !strings.ContainsAny(enc, "-_") {
		t.Fatalf("test data %q does not show the base64url case", enc)
	}
	f := newFakeGmailRoutes(t, routes(map[string]step{
		"GET messages/" + id: {status: 200, body: `{"id":"` + id + `","raw":"` + enc + `"}`},
	}))
	p, _ := f.provider(nil)
	got, err := p.Raw(context.Background(), id)
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if string(got) != src {
		t.Errorf("Raw = %q, want %q", got, src)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	if q, _ := url.ParseQuery(reqs[0].RawQuery); q.Get("format") != "raw" {
		t.Errorf("format = %q, want raw", q.Get("format"))
	}
	if _, err := p.Raw(context.Background(), "../labels"); err == nil {
		t.Error("Raw of an id with a slash: no error")
	}
}
