// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the junk rule of a move (DS8.2d): which moves change the
// junk keywords of a message, and in which direction.

package mail

import "testing"

// TestJunkRule holds DS8.2d: a move out of the junk folder into a
// folder that is not junk or trash marks the message not junk; a move
// into the junk folder marks it junk; every other change leaves the
// junk keywords as they are. An undo move and a call that names a
// junk keyword itself also leave them.
//
// arch: DS8.2d
func TestJunkRule(t *testing.T) {
	cases := []struct {
		name                      string
		ch                        Change
		fromJunk, toJunk, toTrash bool
		wantSet, wantJunk         bool
	}{
		{"out of junk to a folder", Change{MoveTo: "Work"}, true, false, false, true, false},
		{"out of junk to the archive", Change{Archive: true}, true, false, false, true, false},
		{"out of junk to the trash", Change{Trash: true}, true, false, true, false, false},
		{"into junk", Change{MoveTo: "Junk"}, false, true, false, true, true},
		{"junk to junk", Change{MoveTo: "Junk"}, true, true, false, false, false},
		{"between two folders", Change{MoveTo: "Work"}, false, false, false, false, false},
		{"no move", Change{AddLabels: []string{"work"}}, true, false, false, false, false},
		{"undo move", Change{MoveTo: "Junk", KeepJunkKeywords: true}, false, true, false, false, false},
		{"undo restore", Change{RestoreFolders: []string{"mb-junk"}}, false, true, false, false, false},
		{"call names $junk", Change{MoveTo: "Work", RemoveLabels: []string{"$Junk"}}, true, false, false, false, false},
		{"call names $notjunk", Change{MoveTo: "Junk", AddLabels: []string{"$NotJunk"}}, false, true, false, false, false},
	}
	for _, tc := range cases {
		junk, set := JunkRule(tc.ch, tc.fromJunk, tc.toJunk, tc.toTrash)
		if set != tc.wantSet || (set && junk != tc.wantJunk) {
			t.Errorf("%s: JunkRule = (junk %v, set %v), want (junk %v, set %v)", tc.name, junk, set, tc.wantJunk, tc.wantSet)
		}
	}
}
