// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

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

// TestNormalizeID_LongFolderRefused holds DU12.3 item 6: an imap or
// outlook id whose formatted form fails the strict grammar "id" gives
// false. A folder name of 512 bytes still passes; one of 513 bytes, in
// the new form and in the old dot form, gives false, so no caller
// writes an id that the output gate refuses.
//
// arch: DU12.3, DU3.2
func TestNormalizeID_LongFolderRefused(t *testing.T) {
	long := strings.Repeat("x", 512)
	for _, kind := range []string{"imap", "outlook"} {
		id := mail.FormatIMAPID(7, 9, long)
		got, ok := normalizeID(kind, id)
		if !ok || got != id || !guard.Strict("id", got) {
			t.Errorf("%s: 512-byte folder: normalizeID = (%d bytes, %v), want the id and true", kind, len(got), ok)
		}
		for _, in := range []string{
			mail.FormatIMAPID(7, 9, long+"y"),
			"7.9." + long + "y",
			"7.9." + strings.Repeat("Z", 600),
		} {
			if got, ok := normalizeID(kind, in); ok || got != "" {
				t.Errorf("%s: %d-byte id: normalizeID = (%d bytes, %v), want (\"\", false)", kind, len(in), len(got), ok)
			}
		}
	}
}

// TestSearch_LongFolderRowDropped holds DU12.3 item 6 through search:
// a row whose folder name is longer than 512 bytes is dropped and the
// result sets partial, as for an id that does not parse (DU12.3 item
// 8). The other row stays, and the result passes the output gate. It
// is not output_refused.
//
// arch: DU12.3, DU3.2, DU4.1
func TestSearch_LongFolderRowDropped(t *testing.T) {
	f := testFencer(t)
	when := time.Unix(1700000000, 0)
	long := msg("1.3."+strings.Repeat("L", 600), "long", when)
	long.Folder = strings.Repeat("L", 600)
	fm := &fakeMail{provs: map[string]*fakeProvider{"work": {page: mail.Page{
		Messages: []mail.Message{msg("1.2.INBOX", "ok", when), long},
	}}}}
	out, err := (&searchTool{mail: fm}).handle(withFencer(context.Background(), f), SearchIn{Account: "work"})
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(out.Rows) != 1 || out.Rows[0].ID != "1-2-494e424f58" {
		t.Fatalf("rows = %+v, want the one INBOX row with id 1-2-494e424f58", out.Rows)
	}
	if !out.Partial {
		t.Error("Partial = false, want true for a dropped row")
	}
	out.Fence = f.Nonce()
	if err := checkOut(f, out); err != nil {
		t.Errorf("checkOut: %v", err)
	}
}
