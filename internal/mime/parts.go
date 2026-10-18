// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import "strings"

// MaxPartBytes caps every text part that a caller decodes, before the
// bytes reach DecodePart. Mail has no size limit of its own, and
// DecodePart holds a whole part in memory, so a 25 MB text part would
// become a 25 MB string. 1 MB of text is far more than any person or
// model reads (§3.10).
//
// arch: DRV.3, §3.10
const MaxPartBytes int64 = 1 << 20

// IsAttachment is the attachment rule of §3.10 for one single part.
// A part is an attachment when its disposition is "attachment" (any
// case) or when it has a file name. The IMAP provider and the read
// tool both call it, so a body and an attachment list never disagree
// about one part.
//
// arch: DRV.3, §3.10
func IsAttachment(disposition, filename string) bool {
	return strings.EqualFold(disposition, "attachment") || filename != ""
}

// PickBody is the part choice of D4.2. plain is the decoded text/plain
// part and html is the decoded text/html source. hasPlain and hasHTML
// tell which of the two exist.
//
// With wantHTML, the result is the HTML source, with no run removed.
// With one part only, the result is that part as text. With both
// parts, the plain text and the text of the HTML part are compared
// after spaces and line breaks are collapsed. When they differ, the
// result is the HTML text and differ is true, because a mail program
// with HTML shows that part. Otherwise the result is the plain part.
// removed counts the hidden HTML runs taken out of the result.
//
// arch: DRV.3, D4.2
func PickBody(plain, html string, hasPlain, hasHTML, wantHTML bool) (text string, removed int, differ bool) {
	switch {
	case wantHTML && hasHTML:
		return html, 0, false
	case wantHTML || !hasHTML:
		if !hasPlain {
			return "", 0, false
		}
		return plain, 0, false
	case !hasPlain:
		text, removed = HTMLToTextCount(html)
		return text, removed, false
	}
	htmlText, removed := HTMLToTextCount(html)
	if collapseSpace(plain) != collapseSpace(htmlText) {
		return htmlText, removed, true
	}
	return plain, 0, false
}

// collapseSpace makes each run of spaces and line breaks one space and
// cuts the space at the two ends, so that the text part and the HTML
// part compare by their words only (D4.2).
func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
