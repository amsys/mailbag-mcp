// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// fwdPrefixPattern matches a subject that already carries a Fwd:
// prefix. Anchored the same way as rePrefixPattern (M15).
var fwdPrefixPattern = regexp.MustCompile(`(?i)^\s*fwd\s*:`)

// FwdPrefix adds "Fwd: " to subject, unless it already has a Fwd:
// prefix (§3.14).
//
// arch: T3.4, §3.14
func FwdPrefix(subject string) string {
	if fwdPrefixPattern.MatchString(subject) {
		return subject
	}
	return "Fwd: " + subject
}

// ForwardBody builds the text body of a forwarded message: a header
// block naming the original From, Date, Subject and To, followed by
// its text (§3.14). The caller re-fetches the original attachments
// through Provider.Attachment and adds them to the outgoing message's
// own Attachments list; this function only builds the text.
//
// arch: T3.4, §3.14
func ForwardBody(from string, date time.Time, subject string, to []string, text string) string {
	toClean := make([]string, len(to))
	for i, addr := range to {
		toClean[i] = stripLineBreaks(addr)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\n", stripLineBreaks(from))
	fmt.Fprintf(&b, "Date: %s\n", date.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Subject: %s\n", stripLineBreaks(subject))
	fmt.Fprintf(&b, "To: %s\n\n", strings.Join(toClean, ", "))
	b.WriteString(text)
	return b.String()
}

// stripLineBreaks replaces CR and LF with a space. It keeps a header
// block field, such as From or Subject, to one line even when the
// source value holds a forged line break (gap 9, §3.14).
func stripLineBreaks(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
