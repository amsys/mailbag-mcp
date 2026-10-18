// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// wrapBase64Lines inserts a CRLF every width characters, the way a real
// message wraps a base64 body (§3.10).
func wrapBase64Lines(s string, width int) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteString("\r\n")
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}

// comparePreviewGolden compares got against testdata/preview/<name>.
// Set MAILBAG_UPDATE_GOLDEN=1 to (re)write the golden file from got.
func comparePreviewGolden(t *testing.T, name string, got string) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "preview", name)

	if os.Getenv("MAILBAG_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	want, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the test, not from a user
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	if got != string(want) {
		t.Errorf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// TestPreview_Golden covers the table of C20: html, newsletter, cut
// base64, cut quoted-printable, empty.
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestPreview_Golden(t *testing.T) {
	longPlain := "Testing base64 truncation in the preview pipeline end to end, well past the cut."
	fullB64 := base64.StdEncoding.EncodeToString([]byte(longPlain))
	// Cut 3 characters off the end of a 4-aligned base64 string, so
	// the fetch lands mid-group, the way §3.10's <0.2048> byte range
	// can.
	truncatedB64 := fullB64[:len(fullB64)-3]

	// Ordinary wire base64 is wrapped at 76 characters per line with a
	// CRLF, unlike the single unbroken line above. Cut mid-line, at a
	// byte offset that lands inside an interior base64 group, the way
	// §3.10's <0.2048> byte range can land on any message.
	wrappedPlain := "This paragraph is long enough to span several base64-encoded lines once " +
		"wrapped at the standard seventy-six character width, so a byte-range fetch can " +
		"land in the middle of an interior line rather than only at the very end."
	wrappedB64 := wrapBase64Lines(base64.StdEncoding.EncodeToString([]byte(wrappedPlain)), 76)
	truncatedWrappedB64 := wrappedB64[:len(wrappedB64)/2+3]

	tests := []struct {
		name             string
		golden           string
		body             []byte
		contentType      string
		transferEncoding string
	}{
		{
			name:   "html",
			golden: "html.golden",
			body: []byte(`<html><head><style>body{color:red}</style></head><body>` +
				`<h1>Welcome</h1><p>Hello <b>world</b>, visit <a href="https://example.com/page">our site</a> today.</p>` +
				`<script>track();</script></body></html>`),
			contentType: "text/html; charset=utf-8",
		},
		{
			name:   "newsletter",
			golden: "newsletter.golden",
			body: []byte("Big Sale This Weekend!\r\n----------\r\n" +
				"Save 20% storewide. Shop now (https://track.example.com/click?id=abc123&x=1) before it ends.\r\n" +
				"* * * * *\r\nUnsubscribe (https://track.example.com/unsub?id=abc123)\r\n"),
			contentType: "text/plain; charset=utf-8",
		},
		{
			name:             "cut_base64",
			golden:           "cut_base64.golden",
			body:             []byte(truncatedB64),
			contentType:      "text/plain; charset=utf-8",
			transferEncoding: "base64",
		},
		{
			name:             "cut_base64_wrapped",
			golden:           "cut_base64_wrapped.golden",
			body:             []byte(truncatedWrappedB64),
			contentType:      "text/plain; charset=utf-8",
			transferEncoding: "base64",
		},
		{
			name:             "cut_quoted_printable",
			golden:           "cut_quoted_printable.golden",
			body:             []byte("This line has plain text and then a broken escape at the very end=3"),
			contentType:      "text/plain; charset=utf-8",
			transferEncoding: "quoted-printable",
		},
		{
			name:        "empty",
			golden:      "empty.golden",
			body:        []byte{},
			contentType: "text/plain; charset=utf-8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Preview(tc.body, tc.contentType, tc.transferEncoding)
			comparePreviewGolden(t, tc.golden, got)
		})
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestPreview_CutAt200Chars(t *testing.T) {
	body := []byte(strings.Repeat("word ", 100)) // 500 chars
	got := Preview(body, "text/plain; charset=utf-8", "")
	if n := len([]rune(got)); n != previewChars {
		t.Errorf("Preview length = %d runes, want %d", n, previewChars)
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestPreview_SeparatorLineRemoved(t *testing.T) {
	body := []byte("keep this line\n===============\nand this one")
	got := Preview(body, "text/plain; charset=utf-8", "")
	if strings.Contains(got, "=") {
		t.Errorf("Preview kept the separator line: %q", got)
	}
}

// TestHTMLToText_UnclosedHead: real mail often leaves <head> open and
// starts <body> at once. The body text must still come through.
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15, DRV.13
func TestHTMLToText_UnclosedHead(t *testing.T) {
	cases := map[string]string{
		`<html><head><meta charset="utf-8"><title>T</title><body><p>Hello</p></body></html>`: "Hello",
		`<head><style>x{}</style><body>Visible</body>`:                                       "Visible",
		// No </head> and no <body> at all: the head must still end at
		// the first non-head tag (§3.14, trap C20, S3-judge.md finding
		// 8a). Before the fix this returned "" — the whole document.
		// "hidden" is loose text directly in the open head, not inside
		// a head element: it ends the head on its own first character
		// and becomes body text, as an HTML5 browser reads it (ORV.4,
		// DRV.13). It is no longer swallowed.
		`<head>hidden<p>visible`: "hidden\nvisible",
	}
	for in, want := range cases {
		if got := HTMLToText(in); got != want {
			t.Errorf("HTMLToText(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHTMLToText_TableCells is finding 9 (S3-judge.md): td and th must
// start a new line like the other block elements, or a table's cell
// text runs together.
//
// arch: T3.3, §3.14, §3.10, C20
func TestHTMLToText_TableCells(t *testing.T) {
	got := HTMLToText("<table><tr><td>c1</td><td>c2</td></tr></table>")
	if strings.Contains(got, "c1c2") {
		t.Errorf("HTMLToText table cells ran together: %q", got)
	}
}

// TestPreview_DecodeFailureEmpty: §3.10 says any failure gives an empty
// preview. A body that breaks the transfer decoder must not show its
// raw encoded bytes.
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestPreview_DecodeFailureEmpty(t *testing.T) {
	if got := Preview([]byte("!!!! not base64 ####"), "text/plain", "base64"); got != "" {
		t.Errorf("Preview(bad base64) = %q, want empty", got)
	}
}

// TestPreview_CutSoftBreak: a fetch cut between the "=" and the LF of
// a soft line break leaves "=\r". Preview drops it like any other
// broken escape at the end.
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestPreview_CutSoftBreak(t *testing.T) {
	if got := Preview([]byte("hello world=\r"), "text/plain", "quoted-printable"); got != "hello world" {
		t.Errorf("Preview = %q, want %q", got, "hello world")
	}
}

// TestPreview_DefangsLinksNotFullRead holds D4.1 item 3. The preview
// defangs each link form a chat client makes live. The full read
// (DecodePart, then HTMLToText) keeps the real URL, so a working link
// stays working.
//
// arch: D4.1
func TestPreview_DefangsLinksNotFullRead(t *testing.T) {
	// The defanged text must fit the 200-character preview cut.
	body := []byte(`<p><a href="https://ev.co/login">HTTPS://ev.co/login</a> ` +
		`http://pl.org/a.html ftp://fi.net/x www.ba.io ` +
		`mailto:b@c.com <a href="https://li.co/p">x</a></p>`)
	ct := "text/html; charset=utf-8"

	got := Preview(body, ct, "")
	if len([]rune(got)) >= previewChars {
		t.Fatalf("fixture reached the preview cut, shorten it: %q", got)
	}
	live := regexp.MustCompile(`(?i)(https?|ftp)://|mailto:|www\.|\.(co|com|org|net|io|html)`)
	if m := live.FindString(got); m != "" {
		t.Errorf("preview holds live link text %q: %q", m, got)
	}
	for _, want := range []string{
		"hxxps[://]ev[.]co/login",
		"hxxp[://]pl[.]org/a[.]html",
		"fxp[://]fi[.]net/x",
		"www[.]ba[.]io",
		"mailto[:]b@c[.]com",
		"hxxps[://]li[.]co/p",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("preview lacks %q: %q", want, got)
		}
	}

	full := HTMLToText(DecodePart(body, ct, ""))
	for _, want := range []string{
		"https://ev.co/login",
		"http://pl.org/a.html",
		"ftp://fi.net/x",
		"www.ba.io",
		"mailto:b@c.com",
		"https://li.co/p",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("full read lost real URL %q: %q", want, full)
		}
	}
	if strings.Contains(full, "[.]") || strings.Contains(full, "hxxp") {
		t.Errorf("full read is defanged: %q", full)
	}
}
