// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Strict grammars for the outside zone of a tool result. Every string
// that is not under `untrusted` must match one closed grammar, or the
// checked free text of the kind owner.

package guard

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/amsys/mailbag-mcp/internal/config"
)

var strictRes = map[string][]*regexp.Regexp{
	"nonce": {regexp.MustCompile(`^[0-9a-f]{16}$`)},
	// A hex run is captured; strictHexOK checks its length, because
	// RE2 refuses a repeat count above 1000.
	"id": {
		regexp.MustCompile(`^[0-9]{1,10}-[0-9]{1,10}-([0-9a-f]+)$`),
		regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`),
	},
	"folder": {regexp.MustCompile(`^=([0-9a-f]+)$`)},
	"ref": {
		regexp.MustCompile(`^[0-9.]{1,64}$`),
		regexp.MustCompile(`^=([0-9a-f]+)$`),
	},
	"date":   {regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)},
	"day":    {regexp.MustCompile(`^\d{4}-\d\d-\d\d$`)},
	"word":   {regexp.MustCompile(`^[a-z0-9_]{1,32}$`)},
	"hex":    {regexp.MustCompile(`^[0-9a-f]{8,128}$`)},
	"cursor": {regexp.MustCompile(`^[A-Za-z0-9_-]+$`)},
	"msgid": {regexp.MustCompile(
		`^<[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]{1,200}@[A-Za-z0-9.-]{1,255}>$`)},
}

// strictFlags is the closed set of row flag words.
var strictFlags = map[string]bool{
	"unread": true, "starred": true, "answered": true, "draft": true,
	"flagged": true, "forwarded": true, "junk": true, "important": true,
}

// Strict reports whether s matches the closed grammar of kind. An
// unknown kind, and the kind "note", give false: the tool layer checks
// notes against its own registry. An empty string is false for every
// kind; a field with omitempty never reaches Strict when it is empty.
//
// arch: DU3.1
func Strict(kind, s string) bool {
	switch kind {
	case "alias":
		return len(s) <= 64 && config.ValidAlias(s)
	case "flags":
		return strictFlagList(s)
	case "cursor":
		return len(s) <= 4096 && strictMatch(kind, strictRes[kind][0], s)
	case "owner":
		return strictOwner(s)
	}
	for _, re := range strictRes[kind] {
		if strictMatch(kind, re, s) {
			return true
		}
	}
	return false
}

// ownerMaxBytes is the longest value of the kind owner.
const ownerMaxBytes = 1024

// strictOwner checks the kind owner. It is not a closed grammar: it is
// free text that only the owner config and the save roots feed. The
// value must be valid UTF-8 of 1 to ownerMaxBytes bytes. It must have
// no control character (Cc, so no line feed and no tab), no rune of
// Cf, Co or Cs, no Hangul filler, no fence marker and no chat template
// token. It does not need NFC or NFKC, so "ACME\u2122 Support" and a
// combining mark pass. The template check also reads the NFKC form,
// because the DeepSeek token has a full-width bar that only NFKC
// folds. The value itself stays as it is.
//
// arch: DU12.3, DU3.1
func strictOwner(s string) bool {
	if s == "" || len(s) > ownerMaxBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs) {
			return false
		}
		switch r {
		case 0x115F, 0x1160, 0x3164, 0xFFA0:
			return false // Hangul fillers
		}
	}
	if StripFenceMarkers(s) != s {
		return false
	}
	return !templateTokenRe.MatchString(s) && !templateTokenRe.MatchString(norm.NFKC.String(s))
}

// strictFlagList accepts words of strictFlags, separated by single
// spaces.
func strictFlagList(s string) bool {
	if s == "" {
		return false
	}
	for _, w := range strings.Split(s, " ") {
		if !strictFlags[w] {
			return false
		}
	}
	return true
}

// strictHexMax is the longest hex run, in digits, of each kind that
// carries a folder name as hex. Two digits make one byte.
var strictHexMax = map[string]int{"id": 1024, "folder": 1024, "ref": 512}

// strictMatch reports whether s matches re. A match with a hex run
// needs an even number of digits, at most strictHexMax.
func strictMatch(kind string, re *regexp.Regexp, s string) bool {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	if len(m) < 2 {
		return true
	}
	n := len(m[1])
	return n >= 2 && n%2 == 0 && n <= strictHexMax[kind]
}
