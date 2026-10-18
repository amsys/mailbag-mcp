// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	gomessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
)

// fixedTime is the Date header value every test uses, so golden files
// hold no wall-clock noise.
var fixedTime = time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)

// fixedRand feeds a constant byte pattern to Build's Message-ID
// generator, so a golden file holds the same id on every run.
func fixedRand() io.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{0xAB, 0xCD}, 8))
}

// boundaryRe finds the random multipart boundary go-message generates
// (60 lowercase hex characters, textproto.randomBoundary). It matches
// the same string wherever it appears: in the Content-Type parameter
// and in each "--boundary" delimiter line.
var boundaryRe = regexp.MustCompile(`[0-9a-f]{60}`)

// compareGolden normalizes the random boundary out of got, then
// compares it against testdata/eml/<name>. Set MAILBAG_UPDATE_GOLDEN=1
// to (re)write the golden file from got.
func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	norm := boundaryRe.ReplaceAll(got, []byte("BOUNDARY"))
	path := filepath.Join("..", "..", "testdata", "eml", name)

	if os.Getenv("MAILBAG_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, norm, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	want, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the test, not from a user
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if !bytes.Equal(norm, want) {
		t.Errorf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, norm, want)
	}
}

// arch: T3.2, §3.14, M4
func TestBuild_AlwaysMessageID(t *testing.T) {
	in := Input{
		From:    "work@example.com",
		To:      []string{"a@example.com"},
		Subject: "hello",
		Text:    "hi there\n",
	}

	var buf bytes.Buffer
	if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := buf.String()

	for _, want := range []string{
		"Message-Id: <abcdabcdabcdabcdabcdabcdabcdabcd@example.com>\r\n",
		"Date: Sat, 19 Sep 2026 10:00:00 +0000\r\n",
		"Mime-Version: 1.0\r\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}

	compareGolden(t, "always_message_id.eml", buf.Bytes())
}

// arch: T3.2, §3.14, M8
func TestBuild_NonASCIISubjectAndFilename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "résumé café.pdf")
	if err := os.WriteFile(path, []byte("attachment body"), 0o600); err != nil {
		t.Fatalf("write attachment: %v", err)
	}

	in := Input{
		From:        "work@example.com",
		To:          []string{"a@example.com"},
		Subject:     "Café ☕ update",
		Text:        "plain body",
		Attachments: []string{path},
	}

	var buf bytes.Buffer
	if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
		t.Fatalf("Build: %v", err)
	}

	// The raw header must not carry the UTF-8 bytes verbatim: the
	// library encodes them (M8).
	if strings.Contains(buf.String(), "Café") {
		t.Errorf("subject was not encoded, raw UTF-8 leaked into headers:\n%s", buf.String())
	}

	// Round trip: the encoded form must decode back to the original.
	entity, err := gomessage.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse built message: %v", err)
	}
	subject, err := entity.Header.Text("Subject")
	if err != nil {
		t.Fatalf("decode subject: %v", err)
	}
	if subject != in.Subject {
		t.Errorf("subject round trip: got %q, want %q", subject, in.Subject)
	}

	var filename, attachType string
	mr := entity.MultipartReader()
	if mr == nil {
		t.Fatal("message is not multipart/mixed")
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("next part: %v", err)
		}
		disp, _, _ := part.Header.ContentDisposition()
		if disp != "attachment" {
			continue
		}
		ah := gomail.AttachmentHeader{Header: part.Header}
		filename, _ = ah.Filename()
		attachType, _, _ = part.Header.ContentType()
	}
	if filename != "résumé café.pdf" {
		t.Errorf("attachment filename round trip: got %q, want %q", filename, "résumé café.pdf")
	}
	// application/pdf differs from go-message's own default of
	// "text/plain" for an unset Content-Type, so this check catches a
	// SetContentType call that silently wrote an empty value.
	if attachType != "application/pdf" {
		t.Errorf("attachment content type = %q, want application/pdf", attachType)
	}

	compareGolden(t, "nonascii_subject_and_filename.eml", buf.Bytes())
}

// arch: T3.2, §3.14, M9
func TestBuild_Alternative(t *testing.T) {
	in := Input{
		From:    "work@example.com",
		To:      []string{"a@example.com"},
		Subject: "two formats",
		Text:    "Hello there",
		HTML:    "<p>Hello <b>there</b></p>",
	}

	var buf bytes.Buffer
	if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
		t.Fatalf("Build: %v", err)
	}

	entity, err := gomessage.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse built message: %v", err)
	}
	mediaType, _, _ := entity.Header.ContentType()
	if mediaType != "multipart/alternative" {
		t.Fatalf("content-type = %q, want multipart/alternative", mediaType)
	}

	mr := entity.MultipartReader()
	var texts, htmls int
	var order []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("next part: %v", err)
		}
		pt, _, _ := part.Header.ContentType()
		order = append(order, pt)
		body, err := io.ReadAll(part.Body)
		if err != nil {
			t.Fatalf("read part body: %v", err)
		}
		switch pt {
		case "text/plain":
			texts++
			if string(body) != in.Text {
				t.Errorf("text part = %q, want %q", body, in.Text)
			}
		case "text/html":
			htmls++
			if string(body) != in.HTML {
				t.Errorf("html part = %q, want %q", body, in.HTML)
			}
		}
	}
	if texts != 1 || htmls != 1 {
		t.Fatalf("got %d text/plain and %d text/html parts, want 1 each", texts, htmls)
	}
	if len(order) != 2 || order[0] != "text/plain" || order[1] != "text/html" {
		t.Errorf("part order = %v, want [text/plain text/html]", order)
	}

	compareGolden(t, "alternative.eml", buf.Bytes())
}

// arch: T3.2, §3.14, M16
func TestBuild_LongLines(t *testing.T) {
	longLine := strings.Repeat("A", 2000)
	in := Input{
		From:    "work@example.com",
		To:      []string{"a@example.com"},
		Subject: "long line",
		Text:    longLine,
	}

	var buf bytes.Buffer
	if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
		t.Fatalf("Build: %v", err)
	}

	for _, line := range strings.Split(buf.String(), "\r\n") {
		if len(line) > 998 {
			t.Errorf("line of %d characters exceeds the 998 limit: %q", len(line), line)
		}
	}

	entity, err := gomessage.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse built message: %v", err)
	}
	body, err := io.ReadAll(entity.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != longLine {
		t.Errorf("body round trip lost data: got %d chars, want %d", len(body), len(longLine))
	}

	compareGolden(t, "long_lines.eml", buf.Bytes())
}

// TestBuild_ThreadHeaders is finding 1 (S3-judge.md): In-Reply-To and
// References must reach the wire, and stay off it when a message is
// not a reply.
//
// arch: T3.2, §3.14, M5
func TestBuild_ThreadHeaders(t *testing.T) {
	t.Run("reply carries both headers", func(t *testing.T) {
		in := Input{
			From:       "work@example.com",
			To:         []string{"a@example.com"},
			Subject:    "Re: hello",
			Text:       "reply body",
			InReplyTo:  "<orig@example.com>",
			References: []string{"<a@example.com>", "<orig@example.com>"},
		}

		var buf bytes.Buffer
		if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
			t.Fatalf("Build: %v", err)
		}

		entity, err := gomessage.Read(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("parse built message: %v", err)
		}
		if got := entity.Header.Get("In-Reply-To"); got != in.InReplyTo {
			t.Errorf("In-Reply-To = %q, want %q", got, in.InReplyTo)
		}
		wantRefs := strings.Join(in.References, " ")
		if got := entity.Header.Get("References"); got != wantRefs {
			t.Errorf("References = %q, want %q", got, wantRefs)
		}
	})

	t.Run("non-reply carries neither header", func(t *testing.T) {
		in := Input{
			From:    "work@example.com",
			To:      []string{"a@example.com"},
			Subject: "hello",
			Text:    "body",
		}

		var buf bytes.Buffer
		if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
			t.Fatalf("Build: %v", err)
		}
		got := buf.String()
		if strings.Contains(got, "In-Reply-To") {
			t.Errorf("In-Reply-To header present with no InReplyTo set:\n%s", got)
		}
		if strings.Contains(got, "References") {
			t.Errorf("References header present with no References set:\n%s", got)
		}
	})
}

// TestBuild_HTMLOnlyUsesHTMLToText is finding 2 (S3-judge.md): the
// text/plain half of an HTML-only message must come from HTMLToText,
// not the removed stripTags placeholder, so CSS, script source and
// line breaks are handled correctly.
//
// arch: T3.2, §3.14, M9
func TestBuild_HTMLOnlyUsesHTMLToText(t *testing.T) {
	in := Input{
		From:    "work@example.com",
		To:      []string{"a@example.com"},
		Subject: "html only",
		HTML: `<html><head><style>.a{color:red}</style></head><body>` +
			`<p>Hello</p><p>World</p><a href="http://x.test">link</a>` +
			`<script>alert('secret')</script></body></html>`,
	}

	var buf bytes.Buffer
	if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
		t.Fatalf("Build: %v", err)
	}

	entity, err := gomessage.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse built message: %v", err)
	}
	mr := entity.MultipartReader()
	if mr == nil {
		t.Fatal("message is not multipart/alternative")
	}
	var text string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("next part: %v", err)
		}
		pt, _, _ := part.Header.ContentType()
		if pt == "text/plain" {
			body, err := io.ReadAll(part.Body)
			if err != nil {
				t.Fatalf("read text part: %v", err)
			}
			text = string(body)
		}
	}

	if strings.Contains(text, "color:red") {
		t.Errorf("text/plain part leaked CSS: %q", text)
	}
	if strings.Contains(text, "alert(") {
		t.Errorf("text/plain part leaked script source: %q", text)
	}
	// The wire form uses CRLF; normalize before checking for the line
	// break itself so this test does not depend on that encoding detail.
	if !strings.Contains(strings.ReplaceAll(text, "\r\n", "\n"), "Hello\nWorld") {
		t.Errorf("text/plain part lost the line break between Hello and World: %q", text)
	}
}

// TestBuild_ReplyIDHeaderOnlyWhenSet checks DR1G.18.6: Build writes
// ReplyIDHeader only when Input.ReplyID is not empty. A plain ASCII id
// goes out as it is. An id with a folder name that is not ASCII goes
// out as RFC 2047 words, so the header block stays 7-bit, and it
// decodes to the same id.
//
// arch: DR1G.8, DR1G.18, IR1G.9
func TestBuild_ReplyIDHeaderOnlyWhenSet(t *testing.T) {
	base := Input{
		From:    "work@example.com",
		To:      []string{"a@example.com"},
		Subject: "Re: hello",
		Text:    "the answer\n",
	}

	t.Run("no reply id gives no header", func(t *testing.T) {
		var buf bytes.Buffer
		if err := Build(&buf, base, fixedTime, fixedRand()); err != nil {
			t.Fatalf("Build: %v", err)
		}
		if strings.Contains(strings.ToLower(buf.String()), strings.ToLower(ReplyIDHeader)) {
			t.Errorf("the message holds %s, want none:\n%s", ReplyIDHeader, buf.String())
		}
	})

	cases := []struct {
		name, id, wantLine string
	}{
		{"an ASCII id goes out as it is", "7.42.INBOX", ReplyIDHeader + ": 7.42.INBOX\r\n"},
		{"an id with a space in the folder", "7.42.Old Mail", ReplyIDHeader + ": 7.42.Old Mail\r\n"},
		{"an id with a folder that is not ASCII", "7.42.Entwürfe/Größe", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			in.ReplyID = c.id
			var buf bytes.Buffer
			if err := Build(&buf, in, fixedTime, fixedRand()); err != nil {
				t.Fatalf("Build: %v", err)
			}
			got := buf.String()
			if c.wantLine != "" && !strings.Contains(got, c.wantLine) {
				t.Errorf("output missing %q\ngot:\n%s", c.wantLine, got)
			}
			head, _, _ := strings.Cut(got, "\r\n\r\n")
			for i := 0; i < len(head); i++ {
				if head[i] >= 0x80 {
					t.Fatalf("the header block holds a byte that is not ASCII at %d:\n%s", i, head)
				}
			}
			e, err := gomessage.Read(strings.NewReader(got))
			if err != nil {
				t.Fatalf("read the message back: %v", err)
			}
			if n := len(e.Header.Values(ReplyIDHeader)); n != 1 {
				t.Fatalf("%s occurs %d times, want 1", ReplyIDHeader, n)
			}
			dec, err := e.Header.Text(ReplyIDHeader)
			if err != nil {
				t.Fatalf("decode %s: %v", ReplyIDHeader, err)
			}
			if dec != c.id {
				t.Errorf("%s decodes to %q, want %q", ReplyIDHeader, dec, c.id)
			}
		})
	}
}
