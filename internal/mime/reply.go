// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	gomail "github.com/emersion/go-message/mail"
)

// keepReferences is the number of References ids to keep from the end
// of a long thread (§3.14: "Keep the first id and the last 20").
const keepReferences = 20

// rePrefixPattern matches a subject that already carries a Re: prefix.
// It is anchored at the start and allows only whitespace between "re"
// and the colon, so "Are: ..." and "Report: ..." do not match (M15).
var rePrefixPattern = regexp.MustCompile(`(?i)^\s*re\s*:`)

// RePrefix adds "Re: " to subject, unless it already has a Re: prefix
// (§3.14, M15).
//
// arch: T3.4, §3.14, M15
func RePrefix(subject string) string {
	if rePrefixPattern.MatchString(subject) {
		return subject
	}
	return "Re: " + subject
}

// ReplyHeaders computes the In-Reply-To and References header values
// of a reply (M5). msgID is the Message-ID header value of the
// message being replied to, or "" when it has none; refs is that
// message's own References, already split into ids. The result keeps
// the first id (the thread root) and the last 20, so References never
// grows without bound on a long thread (§3.14).
//
// arch: T3.4, §3.14, M5
func ReplyHeaders(msgID string, refs []string) (inReplyTo string, references []string) {
	merged := append([]string{}, refs...)
	if msgID != "" {
		merged = append(merged, msgID)
	}
	if len(merged) <= keepReferences+1 {
		return msgID, merged
	}
	references = append([]string{merged[0]}, merged[len(merged)-keepReferences:]...)
	return msgID, references
}

// ReplyRecipients computes the To and Cc addresses of a reply (M6).
// The base recipient is replyTo, or from when replyTo is blank. When
// all is true, the original message's To and Cc addresses join the Cc
// list too. When the base is an own address, the account sent the
// original, and To is the original's To instead. self lists the account's own address and its identities
// (plain addresses, no display name): any address that matches one of
// them, and any duplicate address after its first occurrence, is
// dropped. Matching is on the address only and ignores case.
//
// arch: T3.4, §3.14, M6
func ReplyRecipients(replyTo, from string, origTo, origCc []string, all bool, self []string) (to, cc []string, err error) {
	base := replyTo
	if strings.TrimSpace(base) == "" {
		base = from
	}

	drop := make(map[string]bool, len(self))
	for _, s := range self {
		drop[strings.ToLower(strings.TrimSpace(s))] = true
	}
	seen := map[string]bool{}

	filter := func(addrs []string) ([]string, error) {
		out := make([]string, 0, len(addrs))
		for _, a := range addrs {
			parsed, err := gomail.ParseAddress(a)
			if err != nil {
				return nil, fmt.Errorf("mime: reply recipient: %w", err)
			}
			key := strings.ToLower(parsed.Address)
			if drop[key] || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, a)
		}
		return out, nil
	}

	to, err = filter([]string{base})
	if err != nil {
		return nil, nil, err
	}
	if len(to) == 0 {
		// The base is an own address, so the account sent the original.
		// Reply to its recipients instead (T98).
		to, err = filter(origTo)
		if err != nil {
			return nil, nil, err
		}
	}
	if len(to) == 0 {
		return nil, nil, fmt.Errorf("mime: reply has no recipient: %s is the account's own address", base)
	}
	if all {
		cc, err = filter(append(append([]string{}, origTo...), origCc...))
		if err != nil {
			return nil, nil, err
		}
	}
	return to, cc, nil
}

// QuoteText builds the quoted body of a reply: "On <date>, <from>
// wrote:" followed by text with each line marked "> " (§3.14).
//
// arch: T3.4, §3.14
func QuoteText(date time.Time, from, text string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "On %s, %s wrote:\n", date.Format(time.RFC1123Z), from)
	normalised := strings.ReplaceAll(text, "\r\n", "\n")
	normalised = strings.ReplaceAll(normalised, "\r", "\n")
	for _, line := range strings.Split(normalised, "\n") {
		b.WriteString("> ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
