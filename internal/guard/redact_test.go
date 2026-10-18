// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"testing"
)

// TestRedact_Patterns checks the four token and header shapes of
// §3.15 are replaced and that ordinary text passes through unchanged.
//
// arch: T1.4, §3.1, §3.19, §3.15, A2, A3, A4, A5, A6, A7, A9
func TestRedact_Patterns(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{ //nolint:gosec // G101: fake token that tests the redaction pattern
			name: "google oauth token",
			in:   "token=ya29.a0ARrdaM_verylongvalue-here end",
			want: "token=<redacted> end",
		},
		{
			name: "jwt",
			in:   "id_token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U end",
			want: "id_token <redacted> end",
		},
		{
			name: "bearer header",
			in:   "Authorization: Bearer abc123.def-456_ghi",
			want: "Authorization: <redacted>",
		},
		{
			name: "basic header",
			in:   "Authorization: Basic dXNlcjpwYXNz",
			want: "Authorization: <redacted>",
		},
		{
			name: "no secret shape",
			in:   "search folder=INBOX limit=20",
			want: "search folder=INBOX limit=20",
		},
		{
			name: "several matches in one line",
			in:   "a=Bearer aaa b=Bearer bbb",
			want: "a=<redacted> b=<redacted>",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Redact(tc.in); got != tc.want {
				t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedact_Values checks RegisterSecret values of at least 6 chars
// are replaced by Redact, shorter values are dropped, and the caller's
// home directory is replaced with "~".
//
// arch: T2.2, §3.15, G5, B6, §10.3
func TestRedact_Values(t *testing.T) {
	t.Run("registered value redacted", func(t *testing.T) {
		RegisterSecret("hunter2pass")
		got := Redact("password=hunter2pass end")
		want := "password=<redacted> end"
		if got != want {
			t.Errorf("Redact = %q, want %q", got, want)
		}
	})

	t.Run("short value not registered", func(t *testing.T) {
		RegisterSecret("abc12")
		got := Redact("code=abc12 end")
		want := "code=abc12 end"
		if got != want {
			t.Errorf("Redact = %q, want %q", got, want)
		}
	})

	t.Run("longer value wins over its prefix", func(t *testing.T) {
		RegisterSecret("secretA")
		RegisterSecret("secretAB")
		got := Redact("value=secretAB end")
		want := "value=<redacted> end"
		if got != want {
			t.Errorf("Redact = %q, want %q", got, want)
		}
	})

	t.Run("home directory replaced with tilde", func(t *testing.T) {
		t.Setenv("HOME", "/home/testuser")
		got := Redact("/home/testuser/mail/attach.txt")
		want := "~/mail/attach.txt"
		if got != want {
			t.Errorf("Redact = %q, want %q", got, want)
		}
	})
}

// TestRedact_ValuesBeforePatterns checks that a registered secret is
// replaced whole, even when part of it also matches a pattern shape.
// Running the patterns first would replace only the matching part and
// leave the rest of the secret in the output (S2 judge finding 10).
//
// arch: T2.2, §3.15, G5, B6, §10.3
func TestRedact_ValuesBeforePatterns(t *testing.T) {
	secret := "Basic dXNlcjpwYXNz-tail-not-base64" //nolint:gosec // G101: fake credential that tests value redaction
	RegisterSecret(secret)
	got := Redact("Authorization: " + secret + " end")
	want := "Authorization: <redacted> end"
	if got != want {
		t.Errorf("Redact(%q) = %q, want %q", secret, got, want)
	}
}

// TestRedact_HomeBoundary checks that redactHome only replaces the
// home directory at a word boundary, and that a colon still counts as
// one. Without the first check, home "/home/alice" turns
// "/home/alicez" into "~ez" and leaks part of a different name.
// Without the second, Go's path-error wrapping ("stat %s: %s") would
// leave the home directory unredacted (S2 judge finding 10;
// 03-design.md:759).
//
// arch: T2.2, §3.15, G5, B6, §10.3
func TestRedact_HomeBoundary(t *testing.T) {
	t.Setenv("HOME", "/home/alice")

	got := Redact("/home/alicez/file and /home/alice/mail")
	want := "/home/alicez/file and ~/mail"
	if got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}

	got = Redact("stat /home/alice: no such file or directory")
	want = "stat ~: no such file or directory"
	if got != want {
		t.Errorf("Redact = %q, want %q", got, want)
	}
}
