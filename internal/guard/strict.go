// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Strict grammars for the outside zone of a tool result. Every string
// that is not under `untrusted` must match one closed grammar.

package guard

import (
	"regexp"
	"strings"

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
		return s != "" && s == Sanitize(s) && StripFenceMarkers(s) == s
	}
	for _, re := range strictRes[kind] {
		if strictMatch(kind, re, s) {
			return true
		}
	}
	return false
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
