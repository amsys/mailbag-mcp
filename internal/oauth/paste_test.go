// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"strings"
	"testing"
)

// TestPaste_ParsesRedirectURL checks the happy path, a state
// mismatch, a missing code and a provider-reported refusal.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestPaste_ParsesRedirectURL(t *testing.T) {
	const state = "state-xyz"

	t.Run("matching state and code", func(t *testing.T) {
		code, err := ParsePastedRedirect("http://localhost:12345/callback?state="+state+"&code=the-code", state)
		if err != nil {
			t.Fatalf("ParsePastedRedirect: %v", err)
		}
		if code != "the-code" {
			t.Fatalf("code = %q, want %q", code, "the-code")
		}
	})

	t.Run("leading and trailing whitespace from a paste", func(t *testing.T) {
		code, err := ParsePastedRedirect("  http://localhost:12345/callback?state="+state+"&code=the-code\n", state)
		if err != nil {
			t.Fatalf("ParsePastedRedirect: %v", err)
		}
		if code != "the-code" {
			t.Fatalf("code = %q, want %q", code, "the-code")
		}
	})

	t.Run("state mismatch is rejected", func(t *testing.T) {
		_, err := ParsePastedRedirect("http://localhost:12345/callback?state=other&code=the-code", state)
		if err == nil {
			t.Fatalf("ParsePastedRedirect: want an error on state mismatch")
		}
	})

	t.Run("missing code", func(t *testing.T) {
		_, err := ParsePastedRedirect("http://localhost:12345/callback?state="+state, state)
		if err == nil {
			t.Fatalf("ParsePastedRedirect: want an error when there is no code")
		}
	})

	t.Run("provider reported a refusal", func(t *testing.T) {
		_, err := ParsePastedRedirect("http://localhost:12345/callback?state="+state+"&error=access_denied&error_description=user+cancelled", state)
		if err == nil {
			t.Fatalf("ParsePastedRedirect: want an error when the provider reports error=")
		}
		if !strings.Contains(err.Error(), "access_denied") {
			t.Fatalf("error = %v, want it to name access_denied", err)
		}
	})

	t.Run("not a URL", func(t *testing.T) {
		_, err := ParsePastedRedirect("not a url at all \x7f", state)
		if err == nil {
			t.Fatalf("ParsePastedRedirect: want an error on unparsable input")
		}
	})
}

// TestPaste_BadInputNotEchoed checks that a paste which fails to parse
// as a URL does not echo the pasted text back in the error. url.Parse's
// own errors quote the input, and that input can carry the single-use,
// PKCE-bound authorization code.
//
// arch: S6-close-judge L5, §3.6
func TestPaste_BadInputNotEchoed(t *testing.T) {
	const marker = "code=SECRETMARKER"
	_, err := ParsePastedRedirect("not a url at all \x7f?"+marker, "state-xyz")
	if err == nil {
		t.Fatalf("ParsePastedRedirect: want an error on unparsable input")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("error = %v, want it not to echo the pasted text (%q)", err, marker)
	}
	if strings.Contains(err.Error(), "\x7f") {
		t.Fatalf("error = %q, want it not to echo the pasted text", err)
	}
}
