// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package guard fences sender-controlled text and redacts secrets, so
// a hostile message or a stray token cannot reach the model or the
// log unmarked (§3.15).
package guard

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// patterns are the token and header shapes of §3.15: a Google OAuth
// access token, a JWT, and an Authorization header value. This is the
// first pass, shape only (T1.4). Exact-value redaction of each secret
// the process loads is T2.2's job.
//
// arch: T1.4, §3.15
var patterns = []*regexp.Regexp{
	regexp.MustCompile(`ya29\.[^\s"']+`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),
	regexp.MustCompile(`Bearer\s+\S+`),
	regexp.MustCompile(`Basic\s+[A-Za-z0-9+/=]+`),
}

const redactedText = "<redacted>"

// minSecretLen is the shortest value RegisterSecret keeps. A shorter
// value redacts too much ordinary text (§3.15, T2.2).
//
// arch: T2.2, §3.15, G5, B6, §10.3
const minSecretLen = 6

var (
	secretsMu sync.RWMutex
	secrets   = map[string]struct{}{}
)

// RegisterSecret adds an exact value for Redact to replace, such as a
// loaded password or API key. Values shorter than minSecretLen are
// dropped: they are too common in plain text to redact safely.
//
// arch: T2.2, §3.15, G5, B6, §10.3
func RegisterSecret(value string) {
	if len(value) < minSecretLen {
		return
	}
	secretsMu.Lock()
	secrets[value] = struct{}{}
	secretsMu.Unlock()
}

// Redact replaces each registered secret value, then each pattern match,
// then the caller's home directory, so a log line or tool error never
// carries a loaded secret or a real path (§3.15, T2.2). Secrets go
// first: a secret that happens to contain a pattern shape (for example
// a Basic header value) would otherwise lose only the matched part and
// leak the rest.
//
// arch: T2.2, §3.15, G5, B6, §10.3
func Redact(s string) string {
	s = redactSecrets(s)
	for _, p := range patterns {
		s = p.ReplaceAllString(s, redactedText)
	}
	s = redactHome(s)
	return s
}

// redactSecrets replaces every registered value, longest first, so a
// secret that is a prefix of another does not leave a partial match
// behind (§3.15, T2.2).
//
// arch: T2.2, §3.15, G5, B6, §10.3
func redactSecrets(s string) string {
	secretsMu.RLock()
	values := make([]string, 0, len(secrets))
	for v := range secrets {
		values = append(values, v)
	}
	secretsMu.RUnlock()
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	for _, v := range values {
		s = strings.ReplaceAll(s, v, redactedText)
	}
	return s
}

// redactHome replaces the caller's home directory with "~", so a path
// in a log line or error does not disclose the account name (§3.15,
// T2.2, 03-design.md:470, :759). A match only counts at a word
// boundary: home followed by the end of the string, or by a byte that
// is not a letter, digit or "_". Without that check, home
// "/home/alice" would turn "/home/alicez" into "~ez", leaking part
// of a different name. Checking only for "/" is not enough either: Go
// wraps path errors as "<path>: <message>" (for example os.Stat's
// "stat %s: %s"), so a colon is a real boundary too, and rejecting it
// would leave the home directory unredacted in every stat or open
// error, which 03-design.md:759 forbids. Home "/" or "" never matches:
// replacing it would turn every path separator into "~".
//
// arch: T2.2, §3.15, G5, B6, §10.3
func redactHome(s string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return s
	}
	home = strings.TrimRight(home, "/")
	if home == "" {
		return s
	}
	var b strings.Builder
	rest := s
	for {
		i := strings.Index(rest, home)
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		end := i + len(home)
		if end == len(rest) || !continuesWord(rest[end:]) {
			b.WriteString(rest[:i])
			b.WriteString("~")
			rest = rest[end:]
			continue
		}
		// Not a boundary: this occurrence is part of a longer name.
		// Keep it and resume the search past its first byte.
		b.WriteString(rest[:i+1])
		rest = rest[i+1:]
	}
}

// continuesWord reports whether s starts with a letter, digit or "_",
// meaning the preceding match is only a prefix of a longer name and
// must not be redacted.
func continuesWord(s string) bool {
	r, _ := utf8.DecodeRuneInString(s)
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
