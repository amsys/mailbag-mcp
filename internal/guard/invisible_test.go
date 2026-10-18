// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"strings"
	"testing"
)

// TestInvisible_Table walks the character list of §3.15 and checks
// that each hidden character is removed and counted once, while `\n`
// and `\t` stay (G4).
//
// arch: T2.1, §3.15, G4, §10.4
func TestInvisible_Table(t *testing.T) {
	cases := []struct {
		name string
		r    rune
	}{
		{"C0 bell", 0x07},
		{"DEL", 0x7F},
		{"C1", 0x85},
		{"Arabic letter mark", 0x061C},
		{"zero width space", 0x200B},
		{"zero width joiner", 0x200F},
		{"bidi embedding", 0x202A},
		{"bidi override", 0x202E},
		{"word joiner", 0x2060},
		{"bidi isolate", 0x2066},
		{"byte order mark", 0xFEFF},
		{"interlinear annotation", 0xFFF9},
		{"tag character (lower)", 0xE0000},
		{"tag character (upper)", 0xE007F},
		{"variation selector supp (lower)", 0xE0100},
		{"variation selector supp (upper)", 0xE01EF},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := "a" + string(c.r) + "b"
			out, n := StripInvisible(in)
			if out != "ab" {
				t.Fatalf("%U: want %q, got %q", c.r, "ab", out)
			}
			if n != 1 {
				t.Fatalf("%U: want count 1, got %d", c.r, n)
			}
		})
	}

	t.Run("newline and tab kept", func(t *testing.T) {
		out, n := StripInvisible("a\nb\tc")
		if out != "a\nb\tc" || n != 0 {
			t.Fatalf("want unchanged with count 0, got %q count %d", out, n)
		}
	})

	t.Run("CRLF normalised before stripping", func(t *testing.T) {
		out, n := StripInvisible("a\r\nb")
		if out != "a\nb" || n != 0 {
			t.Fatalf("want CRLF turned into LF with count 0, got %q count %d", out, n)
		}
	})

	t.Run("ordinary text untouched", func(t *testing.T) {
		out, n := StripInvisible("hello, world! 123")
		if out != "hello, world! 123" || n != 0 {
			t.Fatalf("want unchanged, got %q count %d", out, n)
		}
	})
}

// oracleInvisible is a second, independently written check for the
// hidden-character ranges of §3.15. It is copied straight from the
// spec text, not from isInvisible, so FuzzInvisible does not end up
// checking the code under test against itself (S2 judge finding 11).
func oracleInvisible(r rune) bool {
	switch {
	case r < 0x20:
		return r != '\n' && r != '\t'
	case r == 0x7F:
		return true
	case r >= 0x80 && r <= 0x9F:
		return true
	case r == 0x061C:
		return true
	case r >= 0x200B && r <= 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r == 0x2060:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0xFEFF:
		return true
	case r >= 0xFFF9 && r <= 0xFFFB:
		return true
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	case r >= 0xE0100 && r <= 0xE01EF:
		return true
	}
	return false
}

// FuzzInvisible checks that, for arbitrary text, StripInvisible's
// output holds no hidden character and its removal count matches how
// many the input held, judged against the independent oracle above,
// not against isInvisible (G4).
//
// arch: T2.1, §3.15, G4, §10.4
func FuzzInvisible(f *testing.F) {
	seeds := []string{
		"",
		"plain text",
		"a\u200bb\u200cc",
		"\x00\x1f\x7f",
		"line1\r\nline2\r\n",
		"tag\U000E0001block",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, n := StripInvisible(s)
		for _, r := range out {
			if oracleInvisible(r) {
				t.Fatalf("output still holds hidden char %U: %q", r, out)
			}
		}
		normalized := strings.ReplaceAll(s, "\r\n", "\n")
		want := 0
		for _, r := range normalized {
			if oracleInvisible(r) {
				want++
			}
		}
		if n != want {
			t.Fatalf("count mismatch: got %d want %d for %q", n, want, s)
		}
	})
}
