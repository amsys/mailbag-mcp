// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests for the Strict grammars of the outside zone.

package guard

import (
	"strings"
	"testing"
)

// TestStrict_Grammars checks one accepted and several refused strings
// for each kind.
//
// arch: DU3.1
func TestStrict_Grammars(t *testing.T) {
	hex512 := strings.Repeat("ab", 512)
	cases := []struct {
		kind, s string
		want    bool
	}{
		{"nonce", "0123456789abcdef", true},
		{"nonce", "0123456789ABCDEF", false},
		{"nonce", "0123456789abcde", false},
		{"nonce", "0123456789abcdef\n", false},
		{"id", "1-2-6162", true},
		{"id", "1-2-616", true}, // odd hex: still the plain form
		{"id", "1-2-" + strings.Repeat("a", 300) + "b", false},
		{"id", "1-2-" + hex512, true},
		{"id", "1-2-" + hex512 + "00", false},
		{"id", "abc_DEF-1", true},
		{"id", "1.2.INBOX", false},
		{"id", "", false},
		{"id", strings.Repeat("a", 257), false},
		{"folder", "=494e424f58", true},
		{"folder", "494e424f58", false},
		{"folder", "=", false},
		{"folder", "=4", false},
		{"ref", "1.2", true},
		{"ref", "=6162", true},
		{"ref", "1.2a", false},
		{"ref", strings.Repeat("1", 65), false},
		{"date", "2026-11-17T10:20:30Z", true},
		{"date", "2026-11-17T10:20:30+00:00", false},
		{"date", "2026-11-17", false},
		{"day", "2026-11-17", true},
		{"day", "2026-11-17T10:20:30Z", false},
		{"alias", "work_1-a", true},
		{"alias", strings.Repeat("a", 64), true},
		{"alias", strings.Repeat("a", 65), false},
		{"alias", "a b", false},
		{"alias", "", false},
		{"word", "signed_ok", true},
		{"word", "Signed", false},
		{"word", strings.Repeat("a", 33), false},
		{"flags", "unread starred", true},
		{"flags", "unread  starred", false},
		{"flags", "unread $Phishing", false},
		{"flags", " unread", false},
		{"flags", "", false},
		{"hex", "deadbeef", true},
		{"hex", "dead", false},
		{"hex", strings.Repeat("a", 129), false},
		{"cursor", "abc-_123", true},
		{"cursor", "ab+c", false},
		{"cursor", strings.Repeat("a", 4097), false},
		{"msgid", "<a.b@example.com>", true},
		{"msgid", "a.b@example.com", false},
		{"msgid", "<a b@example.com>", false},
		{"owner", "me@example.com", true},
		{"owner", "me\x00@example.com", false},
		{"owner", "a​b", false},
		{"owner", "[UNTRUSTED_x]", false},
		{"owner", "", false},
		{"note", "anything", false},
		{"nosuchkind", "abc", false},
	}
	for _, c := range cases {
		if got := Strict(c.kind, c.s); got != c.want {
			t.Errorf("Strict(%q, %.40q) = %v, want %v", c.kind, c.s, got, c.want)
		}
	}
}
