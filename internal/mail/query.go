// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mail

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// QueryTerm is one piece of a parsed query: a field name (or "text"
// for a bare word or phrase), its value, and whether it is negated
// with a leading "-" (§3.9).
type QueryTerm struct {
	Field string
	Value string
	Not   bool
}

// ParsedQuery is the structured form of the common query grammar of
// §3.9. imap, jmap and gmail each call ParseQuery and translate the
// terms to their own search syntax. gmail does not send Query.Raw to
// the server unchanged (DS7.6).
type ParsedQuery struct {
	Terms []QueryTerm

	// Empty is true for "" and for exactly "*" (trimmed): both list
	// the newest messages and must never become a real search for the
	// text "*" (§3.9, C6).
	Empty bool
}

// queryFields is every recognized "field:" prefix of §3.9. A token
// with a colon whose prefix is not in this set is a bare word or
// phrase instead (so "Re:" and an address like "j@x:8025" never turn
// into a field).
var queryFields = map[string]bool{
	"from": true, "to": true, "cc": true, "subject": true, "body": true,
	"has": true, "is": true, "in": true,
	"before": true, "after": true,
	"newer_than": true, "older_than": true,
	"larger": true, "smaller": true,
}

// ParseQuery splits raw into terms by the common grammar of §3.9: a
// quoted phrase or a bare word stays together across internal spaces,
// a recognized "field:value" prefix becomes a QueryTerm, and a leading
// "-" negates the term that follows it. It never returns an error: any
// input, including malformed quoting, produces some ParsedQuery rather
// than failing, because raw is free text a model wrote, not a format
// to validate (§3.9).
func ParseQuery(raw string) ParsedQuery {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "*" {
		return ParsedQuery{Empty: true}
	}
	var terms []QueryTerm
	for _, tok := range tokenizeQuery(trimmed) {
		terms = append(terms, parseQueryToken(tok))
	}
	return ParsedQuery{Terms: terms}
}

// tokenizeQuery splits s on white space, except inside a double-quoted
// phrase, where a space stays part of the token. An unterminated quote
// runs to the end of s instead of erroring.
func tokenizeQuery(s string) []string {
	var toks []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case unicode.IsSpace(r) && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return toks
}

// parseQueryToken turns one token from tokenizeQuery into a QueryTerm.
func parseQueryToken(tok string) QueryTerm {
	not := false
	if strings.HasPrefix(tok, "-") && len(tok) > 1 {
		not = true
		tok = tok[1:]
	}
	if field, value, ok := splitQueryField(tok); ok {
		return QueryTerm{Field: field, Value: unquoteQuery(value), Not: not}
	}
	return QueryTerm{Field: "text", Value: unquoteQuery(tok), Not: not}
}

// splitQueryField reports whether tok starts with a recognized
// "field:" prefix and, if so, returns the lower-cased field name and
// the text after the colon.
func splitQueryField(tok string) (field, value string, ok bool) {
	i := strings.IndexByte(tok, ':')
	if i < 0 {
		return "", "", false
	}
	name := strings.ToLower(tok[:i])
	if !queryFields[name] {
		return "", "", false
	}
	return name, tok[i+1:], true
}

// unquoteQuery strips one matching pair of surrounding double quotes.
// A value with only an opening or only a closing quote is left as is:
// it is malformed input, not a value to guess at.
func unquoteQuery(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ParseSpan reads 7d, 2m or 1y for newer_than and older_than. A month
// is 30 days and a year is 365. A span that a time.Duration cannot
// hold (about 292 years) is refused, so it never wraps (R16-L12).
func ParseSpan(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("too short")
	}
	n, err := strconv.ParseInt(s[:len(s)-1], 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("not a number")
	}
	day := 24 * time.Hour
	var unit time.Duration
	switch s[len(s)-1] {
	case 'd', 'D':
		unit = day
	case 'm', 'M':
		unit = 30 * day
	case 'y', 'Y':
		unit = 365 * day
	default:
		return 0, fmt.Errorf("unknown unit")
	}
	if n > math.MaxInt64/int64(unit) {
		return 0, fmt.Errorf("too large")
	}
	return time.Duration(n) * unit, nil
}

// ParseSize reads 5M, 200K, 1G or a plain number of bytes. It refuses
// a size past 1<<62 bytes, as Gmail sizeBytes does, so it never wraps.
func ParseSize(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	mul := int64(1)
	switch s[len(s)-1] {
	case 'k', 'K':
		mul, s = 1<<10, s[:len(s)-1]
	case 'm', 'M':
		mul, s = 1<<20, s[:len(s)-1]
	case 'g', 'G':
		mul, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > (1<<62)/mul {
		return 0, fmt.Errorf("not a number")
	}
	return n * mul, nil
}
