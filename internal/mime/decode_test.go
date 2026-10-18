// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/text/encoding/charmap"
)

// TestDecodedSize_MatchesDecodePart holds the one invariant
// DecodedSize exists for (DR1G.9): its count, read from body as a
// stream, always equals len(DecodePart(body, ...)) of the media type
// with no charset parameter. DecodedSize does no charset step
// (REVIEW-2026-10-16 L14), so the two charset rows count the source
// bytes, not a UTF-8 copy. The table covers every rule DecodePart
// itself documents: a plain 7bit body, a clean base64 body, a base64
// body cut mid-group (DRV.13's clean-prefix rule), a quoted-printable
// body, a text part in a non-UTF-8 charset, and a part with an
// unknown charset (§3.14's raw-bytes rule).
//
// arch: DR1G.9, IR1G.6, R16-L14
func TestDecodedSize_MatchesDecodePart(t *testing.T) {
	latin2, err := charmap.ISO8859_2.NewEncoder().String("Příliš žluťoučký kůň úpěl ďábelské ódy.")
	if err != nil {
		t.Fatalf("encode fixture as iso-8859-2: %v", err)
	}
	fullB64 := base64.StdEncoding.EncodeToString([]byte("hello decode prefix world, cut before the end"))

	tests := []struct {
		name             string
		body             string
		contentType      string
		transferEncoding string
	}{
		{"7bit", "plain ascii body", "text/plain; charset=utf-8", "7bit"},
		{"base64", "aGVsbG8gYmFzZTY0", "text/plain; charset=utf-8", "base64"},
		{"base64 cut mid-group", fullB64[:len(fullB64)-3], "text/plain; charset=utf-8", "base64"},
		{"quoted-printable", "caf=E9", "text/plain; charset=iso-8859-1", "quoted-printable"},
		{"latin-2 text", latin2, "text/plain; charset=iso-8859-2", ""},
		{"unknown charset", "plain ascii body, unaffected by the bogus charset name", "text/plain; charset=x-mailbag-bogus", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mediaType, _, _ := strings.Cut(tc.contentType, ";")
			want := len(DecodePart([]byte(tc.body), mediaType, tc.transferEncoding))
			got := DecodedSize(strings.NewReader(tc.body), tc.contentType, tc.transferEncoding)
			if got != want {
				t.Errorf("DecodedSize(%q) = %d, want %d (len of DecodePart's result)", tc.body, got, want)
			}
		})
	}
}

// TestDecodedSize_NoCharsetStep proves that DecodedSize counts the
// bytes of the file, not a UTF-8 copy. A text attachment of 300 bytes
// in windows-1250 is 300 bytes, also when it comes as base64. The
// attachment tool saves these bytes with no charset step.
//
// arch: DR1G.9, R16-L14
func TestDecodedSize_NoCharsetStep(t *testing.T) {
	file := strings.Repeat("\x9e\xe8", 150) // "žč" in windows-1250, 300 bytes
	tests := []struct {
		name, body, transferEncoding string
	}{
		{"8bit", file, ""},
		{"base64", base64.StdEncoding.EncodeToString([]byte(file)), "base64"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodedSize(strings.NewReader(tc.body), "text/plain; charset=windows-1250", tc.transferEncoding)
			if got != len(file) {
				t.Errorf("DecodedSize = %d, want %d, the byte count of the file", got, len(file))
			}
		})
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestDecode_Latin2(t *testing.T) {
	want := "Příliš žluťoučký kůň úpěl ďábelské ódy."
	raw, err := charmap.ISO8859_2.NewEncoder().String(want)
	if err != nil {
		t.Fatalf("encode fixture as iso-8859-2: %v", err)
	}

	got := DecodePart([]byte(raw), "text/plain; charset=iso-8859-2", "")
	if got != want {
		t.Errorf("DecodePart = %q, want %q", got, want)
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestDecode_UnknownCharsetNoError(t *testing.T) {
	raw := "plain ascii body, unaffected by the bogus charset name"

	got := DecodePart([]byte(raw), "text/plain; charset=x-mailbag-bogus", "")
	if got != raw {
		t.Errorf("DecodePart = %q, want the raw bytes back unchanged: %q", got, raw)
	}
}

// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func TestDecode_Base64(t *testing.T) {
	// "hello base64" base64-encoded.
	got := DecodePart([]byte("aGVsbG8gYmFzZTY0"), "text/plain; charset=utf-8", "base64")
	if got != "hello base64" {
		t.Errorf("DecodePart = %q, want %q", got, "hello base64")
	}
}

// TestDecodePart_TruncatedBase64KeepsPrefix: a base64 part cut
// mid-group by a fetch window must keep the text it can decode, not
// the still-encoded bytes (DRV.13).
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15, DRV.13
func TestDecodePart_TruncatedBase64KeepsPrefix(t *testing.T) {
	plain := "hello decode prefix world, cut before the end"
	full := base64.StdEncoding.EncodeToString([]byte(plain))
	trunc := full[:len(full)-3] // cut mid-group, as a fetch window can

	got := DecodePart([]byte(trunc), "text/plain; charset=utf-8", "base64")

	if got == trunc {
		t.Fatalf("DecodePart(%q) = %q, still the raw base64", trunc, got)
	}
	if got == "" || !strings.HasPrefix(plain, got) {
		t.Errorf("DecodePart(%q) = %q, want a prefix of %q", trunc, got, plain)
	}
}

// FuzzPartDecode checks that DecodePart never panics on any byte body
// paired with any content type or transfer encoding string — the
// preview and read paths call it on bytes a sender fully controls.
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func FuzzPartDecode(f *testing.F) {
	f.Add([]byte("hello world"), "text/plain; charset=utf-8", "")
	f.Add([]byte("aGVsbG8="), "text/plain; charset=utf-8", "base64")
	f.Add([]byte("caf=E9"), "text/plain; charset=iso-8859-1", "quoted-printable")
	f.Add([]byte{0xFF, 0xFE, 0x00}, "text/plain; charset=bogus", "base64")
	f.Add([]byte(""), "", "")

	f.Fuzz(func(_ *testing.T, body []byte, contentType, transferEncoding string) {
		_ = DecodePart(body, contentType, transferEncoding)
	})
}
