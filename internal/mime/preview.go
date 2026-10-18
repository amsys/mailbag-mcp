// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	stdmime "mime"
	"regexp"
	"strings"
	"unicode/utf8"
)

// previewChars is the cut length of §3.10's preview rule.
const previewChars = 200

// linkMarkerRE matches a parenthesized link a newsletter appends next
// to its own link text, e.g. "Shop now (https://track.example.com/x)"
// (§3.10).
var linkMarkerRE = regexp.MustCompile(`\(\s*https?://[^()\s]*\s*\)`)

// whitespaceRunRE collapses a run of white space, across lines, to one
// space (§3.10: "put all white space on one line").
var whitespaceRunRE = regexp.MustCompile(`\s+`)

// separatorChars is the character set of a newsletter separator line
// (§3.10: "3 or more of * = _ ~ # -").
const separatorChars = "*=_~#-"

// Preview builds the short summary text of one search result row from
// body, the first bytes of the first text part as §3.10 fetches them
// (BODY.PEEK[<part>]<0.2048>, text/plain first, then text/html). It
// never fails: bad or empty input gives an empty string, because a
// broken preview must never fail the whole search (§3.10).
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func Preview(body []byte, contentType, transferEncoding string) string {
	switch strings.ToLower(strings.TrimSpace(transferEncoding)) {
	case "base64":
		body = trimPartialBase64(body)
	case "quoted-printable":
		body = trimPartialQP(body)
	}

	text, err := decodePart(body, contentType, transferEncoding)
	if err != nil {
		return ""
	}
	if isHTML(contentType) {
		text = HTMLToText(text)
	}

	text = linkMarkerRE.ReplaceAllString(text, "")
	text = dropSeparatorLines(text)
	text = whitespaceRunRE.ReplaceAllString(text, " ")
	text = strings.TrimSpace(text)
	text = DefangLinks(text)

	return cutRunes(text, previewChars)
}

// linkRE matches each link form that a chat client makes into a live
// link: a scheme URL (http, https, ftp), a bare "www." host, and a
// mailto address. The match stops at white space, quotes and angle
// brackets.
var linkRE = regexp.MustCompile("(?i)\\b(?:(?:https?|ftp)://|mailto:|www\\.)[^\\s<>\"'`]*")

// DefangLinks changes each link in s so that a chat client does not
// show it as a live link. The scheme separator gets brackets
// ("hxxps[://]", "fxp[://]", "mailto[:]"), and each dot in the rest
// becomes "[.]". Use it on preview text only. The full read must keep
// the real URL (D4.1).
//
// arch: D4.1
func DefangLinks(s string) string {
	return linkRE.ReplaceAllStringFunc(s, func(m string) string {
		var head, rest string
		lower := strings.ToLower(m)
		switch {
		case strings.HasPrefix(lower, "https://"):
			head, rest = "hxxps[://]", m[len("https://"):]
		case strings.HasPrefix(lower, "http://"):
			head, rest = "hxxp[://]", m[len("http://"):]
		case strings.HasPrefix(lower, "ftp://"):
			head, rest = "fxp[://]", m[len("ftp://"):]
		case strings.HasPrefix(lower, "mailto:"):
			head, rest = "mailto[:]", m[len("mailto:"):]
		default:
			head, rest = "www[.]", m[len("www."):]
		}
		return head + strings.ReplaceAll(rest, ".", "[.]")
	})
}

// isHTML reports whether contentType names text/html. A content type
// that fails to parse is treated as not HTML, the safer default (the
// caller then skips HTMLToText and shows the raw decoded bytes).
func isHTML(contentType string) bool {
	mt, _, err := stdmime.ParseMediaType(contentType)
	return err == nil && mt == "text/html"
}

// dropSeparatorLines removes each line made only of separatorChars and
// spaces, with at least 3 separatorChars (§3.10).
func dropSeparatorLines(s string) string {
	lines := strings.Split(s, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !isSeparatorLine(line) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func isSeparatorLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	count := 0
	for _, r := range trimmed {
		switch {
		case r == ' ':
		case strings.ContainsRune(separatorChars, r):
			count++
		default:
			return false
		}
	}
	return count >= 3
}

// trimPartialBase64 cuts body to the end of its last complete 4-character
// base64 group, so a truncated fetch never leaves the base64 decoder a
// partial group (§3.10). Ordinary MIME base64 is wrapped at 76 characters
// per line with a CRLF between lines, so the valid-alphabet count, not the
// raw byte count, is what must land on a multiple of 4: counting line
// breaks as body length let a fetch cut mid-line pass a byte count that
// looked 4-aligned while the real base64 group was not.
func trimPartialBase64(body []byte) []byte {
	count, cut := 0, 0
	for i, b := range body {
		if !isBase64Char(b) {
			continue
		}
		count++
		if count%4 == 0 {
			cut = i + 1
		}
	}
	return body[:cut]
}

// isBase64Char reports whether b is a character of the standard base64
// alphabet (RFC 4648), including the "=" padding character.
func isBase64Char(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '+' || b == '/' || b == '=':
		return true
	default:
		return false
	}
}

// trimPartialQP drops one broken trailing quoted-printable escape
// ("=" alone, "=" plus CR with the LF cut off, or "=X" with a single
// hex digit) that a truncated fetch can leave. A complete soft line
// break ("=" CR LF) is left alone: it decodes cleanly on its own
// (§3.10).
func trimPartialQP(body []byte) []byte {
	n := len(body)
	if n >= 2 && body[n-2] == '=' && body[n-1] == '\r' {
		return body[:n-2]
	}
	if n >= 1 && body[n-1] == '=' {
		return body[:n-1]
	}
	if n >= 2 && body[n-2] == '=' && isHexDigit(body[n-1]) {
		return body[:n-2]
	}
	return body
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// cutRunes cuts s to at most n runes, never splitting a multi-byte
// character.
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
