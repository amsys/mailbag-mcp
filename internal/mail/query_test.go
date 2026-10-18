// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mail

import (
	"strings"
	"testing"
)

// TestQuery_EmptyListsRecent checks that an empty query and the
// literal "*" both list the newest messages, and never become a real
// search for the text "*" (§3.9, C6: "The query `*` went to the server
// as the text `*`").
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestQuery_EmptyListsRecent(t *testing.T) {
	cases := []string{"", "*", "  ", " * "}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			pq := ParseQuery(raw)
			if !pq.Empty {
				t.Fatalf("ParseQuery(%q).Empty = false, want true", raw)
			}
			if len(pq.Terms) != 0 {
				t.Fatalf("ParseQuery(%q).Terms = %v, want none", raw, pq.Terms)
			}
		})
	}

	notEmpty := []string{"a", "*x", "x*", "from:a@example.com"}
	for _, raw := range notEmpty {
		if pq := ParseQuery(raw); pq.Empty {
			t.Errorf("ParseQuery(%q).Empty = true, want false", raw)
		}
	}
}

// TestQuery_FieldTerms checks that each recognized "field:value"
// prefix of §3.9 becomes one QueryTerm, and that an unrecognized
// prefix (an address, a "Re:" subject line) stays a bare word instead.
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestQuery_FieldTerms(t *testing.T) {
	cases := []struct {
		raw  string
		want QueryTerm
	}{
		{"from:a@example.com", QueryTerm{Field: "from", Value: "a@example.com"}},
		{"has:attachment", QueryTerm{Field: "has", Value: "attachment"}},
		{"is:unread", QueryTerm{Field: "is", Value: "unread"}},
		{"newer_than:7d", QueryTerm{Field: "newer_than", Value: "7d"}},
		{"larger:5M", QueryTerm{Field: "larger", Value: "5M"}},
		{"FROM:A@EXAMPLE.COM", QueryTerm{Field: "from", Value: "A@EXAMPLE.COM"}},
		{"j@x:8025", QueryTerm{Field: "text", Value: "j@x:8025"}},
		{"Re:", QueryTerm{Field: "text", Value: "Re:"}},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			pq := ParseQuery(c.raw)
			if len(pq.Terms) != 1 || pq.Terms[0] != c.want {
				t.Fatalf("ParseQuery(%q).Terms = %v, want [%v]", c.raw, pq.Terms, c.want)
			}
		})
	}
}

// TestQuery_NegationAndPhrase checks the leading "-" for NOT and a
// quoted phrase that holds internal spaces (§3.9).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestQuery_NegationAndPhrase(t *testing.T) {
	pq := ParseQuery(`-is:read "a phrase" -word subject:"annual report"`)
	want := []QueryTerm{
		{Field: "is", Value: "read", Not: true},
		{Field: "text", Value: "a phrase"},
		{Field: "text", Value: "word", Not: true},
		{Field: "subject", Value: "annual report"},
	}
	if len(pq.Terms) != len(want) {
		t.Fatalf("got %d terms %v, want %d terms %v", len(pq.Terms), pq.Terms, len(want), want)
	}
	for i, term := range pq.Terms {
		if term != want[i] {
			t.Errorf("term %d = %v, want %v", i, term, want[i])
		}
	}
}

// TestQuery_AllTermsANDed documents that ParseQuery itself applies no
// operator between terms: every term it returns is one AND-ed
// condition, which matches §3.9 ("All terms are joined with AND"); OR
// is a gmail-only feature that bypasses ParseQuery entirely, because a
// gmail Query sends Raw to the server unchanged.
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestQuery_AllTermsANDed(t *testing.T) {
	pq := ParseQuery("from:a@example.com has:attachment")
	if len(pq.Terms) != 2 {
		t.Fatalf("got %d terms, want 2 (both parsed, joined by the caller with AND)", len(pq.Terms))
	}
}

// FuzzQuery checks that ParseQuery never panics, that its Empty flag
// exactly matches the "" and "*" rule of C6 for arbitrary input, and
// that an Empty query never also carries terms.
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func FuzzQuery(f *testing.F) {
	seeds := []string{
		"", "*", "  ", "**",
		"from:a@example.com",
		`-has:attachment "quoted phrase"`,
		`subject:"unterminated`,
		"newer_than:7d -is:read larger:5M",
		strings.Repeat("x ", 200),
		"\x00\x01 field:\"\x02\"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		pq := ParseQuery(raw)
		trimmed := strings.TrimSpace(raw)
		wantEmpty := trimmed == "" || trimmed == "*"
		if pq.Empty != wantEmpty {
			t.Fatalf("ParseQuery(%q).Empty = %v, want %v", raw, pq.Empty, wantEmpty)
		}
		if pq.Empty && len(pq.Terms) != 0 {
			t.Fatalf("ParseQuery(%q) is Empty but also has terms: %v", raw, pq.Terms)
		}
	})
}
