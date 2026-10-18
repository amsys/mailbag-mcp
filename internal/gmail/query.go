// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The translation of the shared query grammar (§3.9) to the q and
// labelIds arguments of messages.list (DS7.6). The terms that pass are
// those of G9; every other term fails with a fixed text.

package gmail

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// searchQuery is one search in the form of messages.list: the q text
// and the folder names of the in: terms. The caller changes each name
// to a label id for labelIds; it never goes into q (DS7.6).
type searchQuery struct {
	q       string
	folders []string
}

// translateQuery gives the Gmail form of pq (DS7.6, G9). from, to, cc
// and subject map one to one; free text and body: go in as quoted
// text; has:attachment, is:unread, is:starred, before, after,
// newer_than, older_than, larger and smaller map to the Gmail operator
// of the same name; a leading "-" stays a "-". in: gives a folder for
// labelIds. A zero since adds no lower bound; else it adds after: with
// the Unix seconds, which Gmail reads with no loss of precision. Any
// other term fails with "gmail search does not support <term>".
//
// arch: DS7.6, G9
func translateQuery(pq mail.ParsedQuery, since time.Time) (searchQuery, error) {
	var sq searchQuery
	var parts []string
	if !pq.Empty {
		for _, t := range pq.Terms {
			if t.Field == "in" {
				if t.Not || t.Value == "" {
					// labelIds has no negation (DS7.6).
					return searchQuery{}, unsupported(t)
				}
				sq.folders = append(sq.folders, t.Value)
				continue
			}
			s, err := termText(t)
			if err != nil {
				return searchQuery{}, err
			}
			if t.Not {
				s = "-" + s
			}
			parts = append(parts, s)
		}
	}
	if !since.IsZero() {
		parts = append(parts, "after:"+strconv.FormatInt(since.Unix(), 10))
	}
	sq.q = strings.Join(parts, " ")
	return sq, nil
}

// termText gives the q text of one term that is not in:, not yet
// negated.
func termText(t mail.QueryTerm) (string, error) {
	v := strings.ReplaceAll(t.Value, `"`, "")
	if v == "" {
		return "", unsupported(t)
	}
	switch t.Field {
	case "text", "body":
		// Gmail has no body-only operator; body: is free text (G9).
		// Quoted, so a word such as OR or a brace stays text.
		return `"` + v + `"`, nil
	case "from", "to", "cc", "subject":
		return t.Field + ":" + operand(v), nil
	case "has":
		if strings.EqualFold(v, "attachment") {
			return "has:attachment", nil
		}
	case "is":
		switch strings.ToLower(v) {
		case "unread", "starred":
			return "is:" + strings.ToLower(v), nil
		}
	case "before", "after":
		d, err := time.Parse("2006-01-02", v)
		if err != nil {
			d, err = time.Parse("2006/01/02", v)
		}
		if err != nil {
			return "", fmt.Errorf("gmail search: %s:%q is not a date; use YYYY-MM-DD", t.Field, t.Value)
		}
		return t.Field + ":" + d.Format("2006/01/02"), nil
	case "newer_than", "older_than":
		if !validSpan(v) {
			return "", fmt.Errorf("gmail search: %s:%q is not a time span; use 7d, 2m or 1y", t.Field, t.Value)
		}
		return t.Field + ":" + strings.ToLower(v), nil
	case "larger", "smaller":
		n, ok := sizeBytes(v)
		if !ok {
			return "", fmt.Errorf("gmail search: %s:%q is not a size; use 5M, 200K or a number of bytes", t.Field, t.Value)
		}
		return t.Field + ":" + strconv.FormatInt(n, 10), nil
	}
	return "", unsupported(t)
}

// unsupported gives the fixed error of a term with no Gmail form (G9).
func unsupported(t mail.QueryTerm) error {
	term := t.Value
	if t.Field != "text" {
		term = t.Field + ":" + t.Value
	}
	if t.Not {
		term = "-" + term
	}
	return fmt.Errorf("gmail search does not support %s", term)
}

// operand gives v as the operand of a Gmail operator: unchanged when
// it holds only letters, digits and the characters of an address,
// else in double quotes, so that a space, a brace or a parenthesis
// stays part of the value. v holds no double quote.
func operand(v string) string {
	if strings.HasPrefix(v, "-") || strings.ContainsFunc(v, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("@._+-'", r)
	}) {
		return `"` + v + `"`
	}
	return v
}

// validSpan reports whether s is a Gmail time span: a number and one
// of d, m or y, in any case.
func validSpan(s string) bool {
	if len(s) < 2 || !strings.ContainsRune("dmyDMY", rune(s[len(s)-1])) {
		return false
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	return err == nil && n >= 0
}

// sizeBytes reads 5M, 200K, 1G or a plain number of bytes, as the imap
// and jmap searches do. Gmail gets the number of bytes.
func sizeBytes(s string) (int64, bool) {
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
		return 0, false
	}
	return n * mul, true
}
