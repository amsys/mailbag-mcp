// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mail

import "testing"

// TestID_RoundTrip checks that ParseIMAPID reads back exactly what
// FormatIMAPID wrote, including a folder name that itself holds a dot,
// which SplitN(id, ".", 3) must leave intact in the third field
// (§3.8).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestID_RoundTrip(t *testing.T) {
	cases := []struct {
		name        string
		uidValidity uint32
		uid         uint32
		folder      string
	}{
		{"plain folder", 1699999999, 4211, "INBOX"},
		{"folder with a dot", 1699999999, 4211, "INBOX.Sub"},
		{"folder with two dots", 1, 1, "Archive.2026.09"},
		{"zero uid and uidvalidity", 0, 0, "INBOX"},
		{"max uint32 fields", 4294967295, 4294967295, "INBOX"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id := FormatIMAPID(c.uidValidity, c.uid, c.folder)
			gotV, gotU, gotF, err := ParseIMAPID(id)
			if err != nil {
				t.Fatalf("ParseIMAPID(%q): %v", id, err)
			}
			if gotV != c.uidValidity || gotU != c.uid || gotF != c.folder {
				t.Fatalf("ParseIMAPID(%q) = (%d, %d, %q), want (%d, %d, %q)",
					id, gotV, gotU, gotF, c.uidValidity, c.uid, c.folder)
			}
		})
	}
}

// TestID_ParseRejectsGarbage checks that ParseIMAPID refuses a
// malformed id instead of guessing at a repair: an id is valid only
// together with its account, so a caller must never patch one up
// (§3.8).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func TestID_ParseRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"18c2f0a1b2c3d4e5", // a gmail id, no dots at all
		"1.2",              // only two fields
		"1.2.",             // empty folder
		"a.2.INBOX",        // uidvalidity not a number
		"1.b.INBOX",        // uid not a number
		"..INBOX",
	}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			if _, _, _, err := ParseIMAPID(id); err == nil {
				t.Fatalf("ParseIMAPID(%q): want an error, got none", id)
			}
		})
	}
}

// FuzzIDCodec checks that FormatIMAPID and ParseIMAPID round-trip for
// every uidvalidity, uid and non-empty folder name, including folder
// names a real fuzzer would not think to try (embedded dots, control
// bytes, invalid UTF-8) (§3.8).
//
// arch: T3.1, §3.7, §3.8, §3.9, C6
func FuzzIDCodec(f *testing.F) {
	f.Add(uint32(1699999999), uint32(4211), "INBOX")
	f.Add(uint32(0), uint32(0), "INBOX.Sub")
	f.Add(uint32(1), uint32(1), "a.b.c")
	f.Fuzz(func(t *testing.T, uidValidity, uid uint32, folder string) {
		if folder == "" {
			return // FormatIMAPID("", ...) has no valid inverse; see TestID_ParseRejectsGarbage
		}
		id := FormatIMAPID(uidValidity, uid, folder)
		gotV, gotU, gotF, err := ParseIMAPID(id)
		if err != nil {
			t.Fatalf("round trip failed for (%d, %d, %q): %v", uidValidity, uid, folder, err)
		}
		if gotV != uidValidity || gotU != uid || gotF != folder {
			t.Fatalf("round trip mismatch for (%d, %d, %q): got (%d, %d, %q)",
				uidValidity, uid, folder, gotV, gotU, gotF)
		}
	})
}
