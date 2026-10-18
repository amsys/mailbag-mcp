// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests for the Email/query translation of DS8.4.

package jmap

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

var queryNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// filterJSON gives the filter of queryArgs as compact JSON.
func filterJSON(t *testing.T, raw, mailbox string, since time.Time) string {
	t.Helper()
	args, err := queryArgs(mail.ParseQuery(raw), mailbox, since, queryNow, 0, 50)
	if err != nil {
		t.Fatalf("queryArgs(%q): %v", raw, err)
	}
	b, err := json.Marshal(args["filter"])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestJMAP_AndFilter checks that a folder with text gives the explicit
// AND operator form, and that one condition stays bare.
//
// arch: DS8.4, DS8.7
func TestJMAP_AndFilter(t *testing.T) {
	got := filterJSON(t, "invoice", "mb1", time.Time{})
	want := `{"conditions":[{"inMailbox":"mb1"},{"text":"invoice"}],"operator":"AND"}`
	if got != want {
		t.Errorf("filter = %s, want %s", got, want)
	}
	if got := filterJSON(t, "invoice", "", time.Time{}); got != `{"text":"invoice"}` {
		t.Errorf("one condition = %s", got)
	}
	since := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	got = filterJSON(t, "", "mb1", since)
	want = `{"conditions":[{"inMailbox":"mb1"},{"after":"2026-01-02T03:04:05Z"}],"operator":"AND"}`
	if got != want {
		t.Errorf("since filter = %s, want %s", got, want)
	}
	args, err := queryArgs(mail.ParseQuery("*"), "", time.Time{}, queryNow, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := args["filter"]; ok {
		t.Errorf("empty query has a filter: %v", args["filter"])
	}
}

// TestJMAP_NotFilter checks that a negated term is wrapped in NOT.
//
// arch: DS8.4, DS8.7
func TestJMAP_NotFilter(t *testing.T) {
	got := filterJSON(t, "-from:bob is:unread", "", time.Time{})
	want := `{"conditions":[{"conditions":[{"from":"bob"}],"operator":"NOT"},{"notKeyword":"$seen"}],"operator":"AND"}`
	if got != want {
		t.Errorf("filter = %s, want %s", got, want)
	}
	got = filterJSON(t, "-has:attachment", "", time.Time{})
	want = `{"conditions":[{"hasAttachment":true}],"operator":"NOT"}`
	if got != want {
		t.Errorf("filter = %s, want %s", got, want)
	}
}

// TestJMAP_QueryTranslation checks each G9 term, the sort and paging
// arguments, and the fixed error of a term with no JMAP form.
//
// arch: DS8.4, DS8.7
func TestJMAP_QueryTranslation(t *testing.T) {
	cases := map[string]string{
		`"big deal"`:        `{"text":"big deal"}`,
		"from:a@x.org":      `{"from":"a@x.org"}`,
		"to:b":              `{"to":"b"}`,
		"cc:c":              `{"cc":"c"}`,
		"subject:hi":        `{"subject":"hi"}`,
		"body:word":         `{"body":"word"}`,
		"has:attachment":    `{"hasAttachment":true}`,
		"is:unread":         `{"notKeyword":"$seen"}`,
		"is:starred":        `{"hasKeyword":"$flagged"}`,
		"after:2026-03-01":  `{"after":"2026-03-01T00:00:00Z"}`,
		"before:2026-03-01": `{"before":"2026-03-01T00:00:00Z"}`,
		"newer_than:2d":     `{"after":"2026-10-07T12:00:00Z"}`,
		"older_than:1m":     `{"before":"2026-09-09T12:00:00Z"}`,
		"larger:2K":         `{"minSize":2048}`,
		"smaller:100":       `{"maxSize":100}`,
	}
	for raw, want := range cases {
		if got := filterJSON(t, raw, "", time.Time{}); got != want {
			t.Errorf("%s: filter = %s, want %s", raw, got, want)
		}
	}

	args, err := queryArgs(mail.ParseQuery("x"), "", time.Time{}, queryNow, 20, 10)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"sort": args["sort"], "position": args["position"], "limit": args["limit"], "calculateTotal": args["calculateTotal"]})
	want := `{"calculateTotal":true,"limit":10,"position":20,"sort":[{"isAscending":false,"property":"receivedAt"}]}`
	if string(b) != want {
		t.Errorf("args = %s, want %s", b, want)
	}

	fails := map[string]string{
		"is:read":      "jmap search does not support is:read",
		"has:drive":    "jmap search does not support has:drive",
		"in:Archive":   "jmap search does not support in:Archive",
		"-in:Archive":  "jmap search does not support -in:Archive",
		"a OR b":       "jmap search does not support OR",
		"before:soon":  "is not a date",
		"newer_than:x": "is not a time span",
		"larger:big":   "is not a size",
	}
	for raw, want := range fails {
		_, err := queryArgs(mail.ParseQuery(raw), "", time.Time{}, queryNow, 0, 10)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", raw, err, want)
		}
	}
}

// TestJMAP_QuerySpanAndSizeBounds checks that a time span or a size
// past the int64 bound is refused, as Gmail sizeBytes refuses a size,
// and never wraps to a date in the future or a negative size.
//
// arch: DS8.4, R16-L12
func TestJMAP_QuerySpanAndSizeBounds(t *testing.T) {
	fails := map[string]string{
		"newer_than:300y":           "is not a time span",
		"older_than:4000m":          "is not a time span",
		"newer_than:200000d":        "is not a time span",
		"larger:10000000000G":       "is not a size",
		"smaller:9999999999999999K": "is not a size",
	}
	for raw, want := range fails {
		_, err := queryArgs(mail.ParseQuery(raw), "", time.Time{}, queryNow, 0, 10)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", raw, err, want)
		}
	}
	if got, want := filterJSON(t, "newer_than:200y", "", time.Time{}), `{"after":"1826-11-27T12:00:00Z"}`; got != want {
		t.Errorf("newer_than:200y: filter = %s, want %s", got, want)
	}
}
