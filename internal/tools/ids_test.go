// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import "testing"

// TestNormalizeID checks each provider kind: the old imap form leaves
// in the new form, gmail and jmap ids pass the strict grammar, and bad
// ids and unknown kinds give false.
//
// arch: DU3.2, DU12.1
func TestNormalizeID(t *testing.T) {
	cases := []struct {
		kind, id, want string
		ok             bool
	}{
		{"imap", "7.9.INBOX", "7-9-494e424f58", true},
		{"outlook", "7-9-494e424f58", "7-9-494e424f58", true},
		{"imap", "7-9-zz", "", false},
		{"imap", "", "", false},
		{"gmail", "18c2f0a1b2c3d4e5", "18c2f0a1b2c3d4e5", true},
		{"gmail", "[UNTRUSTED]", "", false},
		{"jmap", "Mabc_123", "Mabc_123", true},
		{"jmap", "a b", "", false},
		{"other", "abc", "", false},
	}
	for _, c := range cases {
		got, ok := normalizeID(c.kind, c.id)
		if got != c.want || ok != c.ok {
			t.Errorf("normalizeID(%q, %q) = (%q, %v), want (%q, %v)", c.kind, c.id, got, ok, c.want, c.ok)
		}
	}
}
