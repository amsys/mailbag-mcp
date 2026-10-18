// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import "testing"

// TestIsAttachment checks the §3.10 rule: a disposition of
// "attachment" in any case, or a file name, makes an attachment.
//
// arch: DRV.3
func TestIsAttachment(t *testing.T) {
	cases := []struct {
		disp, name string
		want       bool
	}{
		{"", "", false},
		{"inline", "", false},
		{"attachment", "", true},
		{"ATTACHMENT", "", true},
		{"", "notes.txt", true},
		{"inline", "notes.txt", true},
	}
	for _, c := range cases {
		if got := IsAttachment(c.disp, c.name); got != c.want {
			t.Errorf("IsAttachment(%q, %q) = %v, want %v", c.disp, c.name, got, c.want)
		}
	}
}

// TestPickBody checks the D4.2 part choice.
//
// arch: DRV.3
func TestPickBody(t *testing.T) {
	const html = "<p>invoice B</p>"
	cases := []struct {
		name                        string
		plain, html                 string
		hasPlain, hasHTML, wantHTML bool
		text                        string
		differ                      bool
	}{
		{"nothing", "", "", false, false, false, "", false},
		{"plain only", "invoice A", "", true, false, false, "invoice A", false},
		{"html only", "", html, false, true, false, "invoice B", false},
		{"html format", "invoice A", html, true, true, true, html, false},
		{"html format, plain only", "invoice A", "", true, false, true, "invoice A", false},
		{"same words", "invoice\n  B", html, true, true, false, "invoice\n  B", false},
		{"differ", "invoice A", html, true, true, false, "invoice B", true},
	}
	for _, c := range cases {
		text, _, differ := PickBody(c.plain, c.html, c.hasPlain, c.hasHTML, c.wantHTML)
		if text != c.text || differ != c.differ {
			t.Errorf("%s: PickBody = %q, %v; want %q, %v", c.name, text, differ, c.text, c.differ)
		}
	}
}
