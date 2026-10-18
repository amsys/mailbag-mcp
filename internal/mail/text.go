// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Text helpers of Read that the imap, gmail and jmap providers share: the
// cut of the body, the Message-ID tokens of a header value and the
// check for an inline OpenPGP block.

package mail

import "strings"

// HasInlinePGP reports whether text holds an inline clearsigned
// OpenPGP block. The caller passes the full decoded text, before the
// cut of offset and max_chars (D6.2).
func HasInlinePGP(text string) bool {
	return strings.HasPrefix(text, InlinePGPMarker) ||
		strings.Contains(text, "\n"+InlinePGPMarker)
}

// CutBody applies the offset and the character limit of the read tool
// (§3.16). Both count characters, so a cut never splits a rune.
func CutBody(s string, offset, maxChars int) string {
	if offset > 0 {
		r := []rune(s)
		if offset >= len(r) {
			return ""
		}
		s = string(r[offset:])
	}
	if maxChars > 0 {
		r := []rune(s)
		if len(r) > maxChars {
			s = string(r[:maxChars])
		}
	}
	return s
}

// MessageIDs gives each "<...>" token of a raw header value, in order,
// with the angle brackets kept (§3.14).
func MessageIDs(raw string) []string {
	var out []string
	for _, f := range strings.Fields(raw) {
		f = strings.Trim(f, ",;")
		if len(f) > 2 && strings.HasPrefix(f, "<") && strings.HasSuffix(f, ">") {
			out = append(out, f)
		}
	}
	return out
}
