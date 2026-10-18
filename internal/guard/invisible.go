// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import "strings"

// isInvisible reports whether r is one of the hidden characters listed
// in §3.15: control characters (kept: \n, \t), bidi and zero-width
// marks, and the tag-character blocks that can carry hidden
// instructions.
//
// arch: T2.1, §3.15, G4, §10.4
func isInvisible(r rune) bool {
	switch {
	case r < 0x20 && r != '\n' && r != '\t':
		return true // C0, minus the two kept whitespace characters
	case r == 0x7F:
		return true // DEL
	case r >= 0x80 && r <= 0x9F:
		return true // C1
	case r == 0x061C:
		return true // Arabic letter mark
	case r >= 0x200B && r <= 0x200F:
		return true // zero width space/joiners, marks
	case r >= 0x202A && r <= 0x202E:
		return true // bidi embedding/override
	case r == 0x2060:
		return true // word joiner
	case r >= 0x2066 && r <= 0x2069:
		return true // bidi isolates
	case r == 0xFEFF:
		return true // byte order mark
	case r >= 0xFFF9 && r <= 0xFFFB:
		return true // interlinear annotation
	case r >= 0xE0000 && r <= 0xE007F:
		return true // tag characters
	case r >= 0xE0100 && r <= 0xE01EF:
		return true // variation selectors supplement
	}
	return false
}

// StripInvisible removes the hidden characters of §3.15 from s, after
// changing `\r\n` to `\n`. It returns the cleaned text and the count
// of characters removed, so the caller can add the
// `note: N hidden characters removed` line (§3.15).
//
// arch: T2.1, §3.15, G4, §10.4
func StripInvisible(s string) (string, int) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	for _, r := range s {
		if isInvisible(r) {
			n++
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), n
}
