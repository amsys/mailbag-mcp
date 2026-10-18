// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The junk rule of a move (DS8.2d). Mail clients and server spam
// filters read a move out of the junk folder as "not spam", and a
// move into it as "spam". The keywords $junk and $notjunk carry that
// verdict (RFC 5788 registry). The IMAP and JMAP providers use this
// rule to change the keywords in the same server step as the move.

package mail

import "strings"

// The keywords of the junk verdict. IMAP and JMAP keywords ignore
// case, so one spelling matches both.
const (
	KeywordJunk    = "$junk"
	KeywordNotJunk = "$notjunk"
)

// JunkRule gives the junk verdict that ch sets on one message. fromJunk
// is true when the message is in the junk folder before the change.
// toJunk and toTrash are true when the target folder of the move has
// the role junk or trash. set is false when the change must not touch
// the junk keywords. When set is true, junk true means "add $junk and
// remove $notjunk", and junk false means the reverse.
//
// The rule:
//
//   - A move out of junk into a folder that is not junk or trash sets
//     "not junk". Trash is not a verdict.
//   - A move into junk from a different folder sets "junk".
//   - An undo (KeepJunkKeywords, or RestoreFolders) changes nothing:
//     its labels give the old keywords back exactly.
//   - A change that names $junk or $notjunk in its labels changes
//     nothing more: the caller already said what it wants.
//
// arch: DS8.2d
func JunkRule(ch Change, fromJunk, toJunk, toTrash bool) (junk, set bool) {
	if ch.KeepJunkKeywords || (ch.MoveTo == "" && !ch.Archive && !ch.Trash) {
		return false, false
	}
	for _, l := range append(append([]string(nil), ch.AddLabels...), ch.RemoveLabels...) {
		if strings.EqualFold(l, KeywordJunk) || strings.EqualFold(l, KeywordNotJunk) {
			return false, false
		}
	}
	switch {
	case toJunk && !fromJunk:
		return true, true
	case fromJunk && !toJunk && !toTrash:
		return false, true
	}
	return false, false
}
