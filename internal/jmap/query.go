// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The translation of the shared query grammar (§3.9) to the arguments
// of Email/query (RFC 8621 §4.4). The terms that pass are those of G9;
// every other term fails with a fixed text (DS8.4).

package jmap

import (
	"fmt"
	"strings"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// utcDate is the RFC 3339 UTCDate form that JMAP asks for in after and
// before (RFC 8620 §1.4).
const utcDate = "2006-01-02T15:04:05Z"

// queryArgs gives the Email/query arguments for one search, without
// accountId: the filter, sort receivedAt descending, position, limit
// and calculateTotal true. mailboxID is the id of the folder to search,
// or "" for all mail. A zero since adds no lower bound. now is the
// clock for newer_than and older_than. Several conditions always use
// the AND operator form (F7), and a negated term is wrapped in NOT.
//
// arch: DS8.4, DS8.7
func queryArgs(pq mail.ParsedQuery, mailboxID string, since, now time.Time, position, limit int) (map[string]any, error) {
	var conds []any
	if mailboxID != "" {
		conds = append(conds, map[string]any{"inMailbox": mailboxID})
	}
	if !since.IsZero() {
		conds = append(conds, map[string]any{"after": since.UTC().Format(utcDate)})
	}
	if !pq.Empty {
		for _, t := range pq.Terms {
			c, err := termCondition(t, now)
			if err != nil {
				return nil, err
			}
			if t.Not {
				c = map[string]any{"operator": "NOT", "conditions": []any{c}}
			}
			conds = append(conds, c)
		}
	}
	args := map[string]any{
		"sort":           []any{map[string]any{"property": "receivedAt", "isAscending": false}},
		"position":       position,
		"limit":          limit,
		"calculateTotal": true,
	}
	switch len(conds) {
	case 0:
	case 1:
		args["filter"] = conds[0]
	default:
		args["filter"] = map[string]any{"operator": "AND", "conditions": conds}
	}
	return args, nil
}

// termCondition gives the FilterCondition of one term, not yet negated.
func termCondition(t mail.QueryTerm, now time.Time) (map[string]any, error) {
	switch t.Field {
	case "text":
		if strings.EqualFold(t.Value, "OR") || strings.EqualFold(t.Value, "AND") {
			// ParseQuery has no operator: a bare OR would search for the
			// word "OR" and find almost nothing without a sign (§3.9).
			return nil, unsupported(t)
		}
		return map[string]any{"text": t.Value}, nil
	case "from", "to", "cc", "subject", "body":
		return map[string]any{t.Field: t.Value}, nil
	case "has":
		if strings.EqualFold(t.Value, "attachment") {
			return map[string]any{"hasAttachment": true}, nil
		}
	case "is":
		switch strings.ToLower(t.Value) {
		case "unread":
			return map[string]any{"notKeyword": "$seen"}, nil
		case "starred":
			return map[string]any{"hasKeyword": "$flagged"}, nil
		}
	case "before", "after":
		d, err := time.ParseInLocation("2006-01-02", t.Value, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("jmap search: %s:%q is not a date; use YYYY-MM-DD", t.Field, t.Value)
		}
		return map[string]any{t.Field: d.Format(utcDate)}, nil
	case "newer_than", "older_than":
		d, err := mail.ParseSpan(t.Value)
		if err != nil {
			return nil, fmt.Errorf("jmap search: %s:%q is not a time span; use 7d, 2m or 1y", t.Field, t.Value)
		}
		at := now.Add(-d).UTC().Format(utcDate)
		if t.Field == "newer_than" {
			return map[string]any{"after": at}, nil
		}
		return map[string]any{"before": at}, nil
	case "larger", "smaller":
		n, err := mail.ParseSize(t.Value)
		if err != nil {
			return nil, fmt.Errorf("jmap search: %s:%q is not a size; use 5M, 200K or a number of bytes", t.Field, t.Value)
		}
		if t.Field == "larger" {
			return map[string]any{"minSize": n}, nil
		}
		return map[string]any{"maxSize": n}, nil
	}
	return nil, unsupported(t)
}

// unsupported gives the fixed error of a term with no JMAP form (G9).
func unsupported(t mail.QueryTerm) error {
	term := t.Value
	if t.Field != "text" {
		term = t.Field + ":" + t.Value
	}
	if t.Not {
		term = "-" + term
	}
	return fmt.Errorf("jmap search does not support %s", term)
}
