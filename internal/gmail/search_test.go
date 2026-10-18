// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of Gmail Search and Thread against fakeGmail (DS7.4, DS7.6):
// the limit of 10 messages.get calls at a time, the snippet that comes
// HTML-escaped, the cursor that holds the nextPageToken, and the
// thread rows that are the rows of Search.

package gmail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// wantMetadata fails the test when the query of a messages.get or
// threads.get call is not format=metadata with the six row headers
// (DS7.4).
func wantMetadata(t *testing.T, what string, q url.Values) {
	t.Helper()
	if got := q.Get("format"); got != "metadata" {
		t.Errorf("%s: format = %q, want metadata", what, got)
	}
	want := []string{"From", "To", "Cc", "Subject", "Date", "Message-ID"}
	if got := q["metadataHeaders"]; !reflect.DeepEqual(got, want) {
		t.Errorf("%s: metadataHeaders = %q, want %q", what, got, want)
	}
}

// listBody gives a messages.list answer with the ids and, when next is
// not empty, the nextPageToken.
func listBody(next string, ids ...string) string {
	type ref struct {
		ID       string `json:"id"`
		ThreadID string `json:"threadId"`
	}
	ans := struct {
		Messages      []ref  `json:"messages"`
		NextPageToken string `json:"nextPageToken,omitempty"`
		Estimate      int    `json:"resultSizeEstimate"`
	}{NextPageToken: next, Estimate: len(ids)}
	for _, id := range ids {
		ans.Messages = append(ans.Messages, ref{ID: id, ThreadID: id})
	}
	b, err := json.Marshal(ans)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestGmail_SearchFanOut10 holds the Search row of DS7.4: one
// messages.list call with q from DS7.6, labelIds from Folder and the
// in: term, maxResults and no pageToken on the first page; then one
// messages.get call with format=metadata and the six row headers for
// each id, never more than 10 at a time. The rows keep the order of
// messages.list. Since goes into q as after: (DS7.6).
//
// arch: DS7.4, DS7.6, DS7.9, IS78.5
func TestGmail_SearchFanOut10(t *testing.T) {
	const n = 25
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("18f0c00000000%03d", i)
	}
	labels := labelRoutes(t)["GET labels"]

	var (
		mu        sync.Mutex
		inFlight  int
		peak      int
		listQuery []url.Values
		getQuery  = map[string]url.Values{}
	)
	// full closes 100 ms after 10 calls are in flight: the time lets a
	// call above the limit arrive. stop closes after 3 s, so a limit
	// below 10 fails and does not hang.
	full := make(chan struct{})
	stop := make(chan struct{})
	timer := time.AfterFunc(3*time.Second, func() { close(stop) })
	t.Cleanup(func() { timer.Stop() })
	var fullOnce sync.Once

	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		rest := strings.TrimPrefix(r.URL.Path, apiPrefix)
		switch rest {
		case "labels":
			return labels
		case "messages":
			mu.Lock()
			listQuery = append(listQuery, r.URL.Query())
			mu.Unlock()
			return step{status: 200, body: listBody("", ids...)}
		}
		id, ok := strings.CutPrefix(rest, "messages/")
		if !ok {
			return step{status: 404, body: googleError(404, "NOT_FOUND", "notFound", "", "not found")}
		}
		mu.Lock()
		getQuery[id] = r.URL.Query()
		inFlight++
		peak = max(peak, inFlight)
		if inFlight == 10 {
			fullOnce.Do(func() { time.AfterFunc(100*time.Millisecond, func() { close(full) }) })
		}
		mu.Unlock()
		select {
		case <-full:
		case <-stop:
		}
		mu.Lock()
		inFlight--
		mu.Unlock()
		return step{status: 200, body: fmt.Sprintf(`{"id":%q,"threadId":%q,"labelIds":["INBOX","Label_1"],"snippet":"row %s","internalDate":"1791892800000","payload":{"headers":[]}}`, id, id, id)}
	})
	p, _ := f.provider(nil)

	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	q := mail.Query{Raw: "from:alice@example.com is:unread in:receipts", Folder: "INBOX", Since: since, Limit: n}
	page, err := p.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}

	mu.Lock()
	gotPeak, lists, gets := peak, listQuery, getQuery
	mu.Unlock()
	if gotPeak != 10 {
		t.Fatalf("messages.get calls in flight at most = %d, want 10", gotPeak)
	}
	if len(gets) != n {
		t.Fatalf("messages.get calls for %d ids, want %d", len(gets), n)
	}
	for id, gq := range gets {
		wantMetadata(t, "messages.get "+id, gq)
	}

	if len(lists) != 1 {
		t.Fatalf("messages.list calls = %d, want 1", len(lists))
	}
	lq := lists[0]
	wantQ := "from:alice@example.com is:unread after:" + strconv.FormatInt(since.Unix(), 10)
	if got := lq.Get("q"); got != wantQ {
		t.Errorf("q = %q, want %q", got, wantQ)
	}
	// Folder first, then the in: term as a label id; in: never goes into q.
	if got, want := lq["labelIds"], []string{"INBOX", "Label_1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("labelIds = %q, want %q", got, want)
	}
	if got := lq.Get("maxResults"); got != strconv.Itoa(n) {
		t.Errorf("maxResults = %q, want %d", got, n)
	}
	if lq.Has("pageToken") {
		t.Errorf("the first page sent pageToken %q", lq.Get("pageToken"))
	}

	if len(page.Messages) != n {
		t.Fatalf("Search gave %d rows, want %d", len(page.Messages), n)
	}
	for i, m := range page.Messages {
		if m.ID != ids[i] {
			t.Fatalf("row %d has id %q, want %q (the order of messages.list)", i, m.ID, ids[i])
		}
		if m.Folder != "INBOX" {
			t.Fatalf("row %d has folder %q, want INBOX (the search folder)", i, m.Folder)
		}
	}
	if page.NextCursor != "" {
		t.Fatalf("NextCursor = %q with no nextPageToken, want empty", page.NextCursor)
	}
}

// TestGmail_SnippetUnescaped holds E7: messages.get gives the snippet
// HTML-escaped, and the row preview is the plain text. The row date is
// internalDate and not the Date header (DS7.4). An empty query with no
// Since sends no q.
//
// arch: DS7.4, DS7.6, DS7.9, IS78.5
func TestGmail_SnippetUnescaped(t *testing.T) {
	m := labelRoutes(t)
	m["GET messages"] = step{status: 200, body: listBody("", "18f0a1b2c3d4e5f6")}
	m["GET messages/18f0a1b2c3d4e5f6"] = step{status: 200, body: fixture(t, "messages.get.json")}
	f := newFakeGmailRoutes(t, routes(m))
	p, _ := f.provider(nil)

	page, err := p.Search(context.Background(), mail.Query{Raw: "*"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 1 {
		t.Fatalf("Search gave %d rows, want 1", len(page.Messages))
	}
	got := page.Messages[0]
	want := `Tom & Jerry said "see you at 5" <not a tag> 'ok' ` + "\u2014" + ` bye`
	if got.Preview != want {
		t.Fatalf("Preview = %q, want %q", got.Preview, want)
	}
	if wantDate := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC); !got.Date.Equal(wantDate) {
		t.Fatalf("Date = %v, want %v (internalDate, not the Date header)", got.Date, wantDate)
	}
	if got.Subject != "Café plans" {
		t.Fatalf("Subject = %q, want the decoded text", got.Subject)
	}

	for _, r := range f.requests() {
		if strings.TrimPrefix(r.Path, apiPrefix) != "messages" {
			continue
		}
		lq, _ := url.ParseQuery(r.RawQuery)
		if lq.Has("q") || lq.Has("labelIds") {
			t.Fatalf("an empty search sent q or labelIds: %q", r.RawQuery)
		}
		if got := lq.Get("maxResults"); got != strconv.Itoa(defaultLimit) {
			t.Fatalf("maxResults = %q, want the default %d", got, defaultLimit)
		}
	}
}

// TestGmail_CursorIsPageToken holds the cursor rule of DS7.4: the
// Position of NextCursor is the nextPageToken of messages.list, bound
// to the query by its hash; the next call sends it back as pageToken;
// the last page gives no cursor; a cursor of another query fails with
// mail.ErrCursorMismatch before a call to the API.
//
// arch: DS7.4, DS7.6, DS7.9, IS78.5
func TestGmail_CursorIsPageToken(t *testing.T) {
	const token = "08123456789abcdefPAGE2"
	m := labelRoutes(t)
	meta := `{"id":%q,"threadId":%q,"labelIds":["INBOX"],"snippet":"s","internalDate":"1791892800000","payload":{"headers":[]}}`
	m["GET messages/18f0d0000000000a"] = step{status: 200, body: fmt.Sprintf(meta, "18f0d0000000000a", "18f0d0000000000a")}
	m["GET messages/18f0d0000000000b"] = step{status: 200, body: fmt.Sprintf(meta, "18f0d0000000000b", "18f0d0000000000b")}
	base := routes(m)
	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		if strings.TrimPrefix(r.URL.Path, apiPrefix) == "messages" {
			switch r.URL.Query().Get("pageToken") {
			case "":
				return step{status: 200, body: listBody(token, "18f0d0000000000a")}
			case token:
				return step{status: 200, body: listBody("", "18f0d0000000000b")}
			}
			return step{status: 400, body: googleError(400, "INVALID_ARGUMENT", "invalid", "", "Invalid pageToken")}
		}
		return base(r)
	})
	p, _ := f.provider(nil)
	ctx := context.Background()

	q := mail.Query{Raw: "subject:report", Folder: "INBOX", Limit: 1}
	p1, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search page 1: %v", err)
	}
	if len(p1.Messages) != 1 || p1.Messages[0].ID != "18f0d0000000000a" {
		t.Fatalf("page 1 rows = %+v, want 18f0d0000000000a", p1.Messages)
	}
	cur, err := mail.DecodeCursor(p1.NextCursor)
	if err != nil {
		t.Fatalf("NextCursor %q: %v", p1.NextCursor, err)
	}
	if cur.Position != token {
		t.Fatalf("cursor Position = %q, want the nextPageToken %q", cur.Position, token)
	}
	if cur.QueryHash != mail.HashQuery(q) {
		t.Fatalf("cursor QueryHash = %q, want the hash of the query", cur.QueryHash)
	}

	q.Cursor = p1.NextCursor
	p2, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search page 2: %v", err)
	}
	if len(p2.Messages) != 1 || p2.Messages[0].ID != "18f0d0000000000b" {
		t.Fatalf("page 2 rows = %+v, want 18f0d0000000000b", p2.Messages)
	}
	if p2.NextCursor != "" {
		t.Fatalf("the last page gave NextCursor %q, want empty", p2.NextCursor)
	}
	var tokens []string
	for _, r := range f.requests() {
		if strings.TrimPrefix(r.Path, apiPrefix) == "messages" {
			lq, _ := url.ParseQuery(r.RawQuery)
			tokens = append(tokens, lq.Get("pageToken"))
		}
	}
	if want := []string{"", token}; !reflect.DeepEqual(tokens, want) {
		t.Fatalf("pageToken of the messages.list calls = %q, want %q", tokens, want)
	}

	before := len(f.requests())
	other := mail.Query{Raw: "subject:other", Folder: "INBOX", Limit: 1, Cursor: p1.NextCursor}
	if _, err := p.Search(ctx, other); !errors.Is(err, mail.ErrCursorMismatch) {
		t.Fatalf("a cursor of another query: err = %v, want mail.ErrCursorMismatch", err)
	}
	if after := len(f.requests()); after != before {
		t.Fatalf("a cursor of another query made %d API calls, want 0", after-before)
	}
}

// TestGmail_ThreadRows holds the Thread row of DS7.4: one messages.get
// with format=minimal gives the threadId, then threads.get with
// format=metadata and the six row headers gives the messages, oldest
// first. Each row is the row that Search gives for the same message.
// An id that is not a Gmail id fails before a call to the API.
//
// arch: DS7.4, DS7.6, DS7.9, IS78.5
func TestGmail_ThreadRows(t *testing.T) {
	const threadID = "18f0b0000000000a"
	var th struct {
		Messages []json.RawMessage `json:"messages"`
	}
	thread := fixture(t, "threads.get.json")
	if err := json.Unmarshal([]byte(thread), &th); err != nil {
		t.Fatalf("threads.get.json: %v", err)
	}
	m := labelRoutes(t)
	m["GET threads/"+threadID] = step{status: 200, body: thread}
	var ids []string
	for _, raw := range th.Messages {
		var one struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &one); err != nil || one.ID == "" {
			t.Fatalf("threads.get.json: a message with no id: %v", err)
		}
		ids = append(ids, one.ID)
		m["GET messages/"+one.ID] = step{status: 200, body: string(raw)}
	}
	m["GET messages"] = step{status: 200, body: listBody("", ids...)}
	base := routes(m)
	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		if r.URL.Query().Get("format") == "minimal" {
			id := strings.TrimPrefix(r.URL.Path, apiPrefix+"messages/")
			return step{status: 200, body: fmt.Sprintf(`{"id":%q,"threadId":%q,"labelIds":["INBOX"]}`, id, threadID)}
		}
		return base(r)
	})
	p, _ := f.provider(nil)
	ctx := context.Background()

	res, err := p.Thread(ctx, "18f0b0000000000b")
	if err != nil {
		t.Fatalf("Thread: %v", err)
	}
	var sawMinimal, sawThread bool
	for _, r := range f.requests() {
		rq, _ := url.ParseQuery(r.RawQuery)
		switch strings.TrimPrefix(r.Path, apiPrefix) {
		case "messages/18f0b0000000000b":
			sawMinimal = rq.Get("format") == "minimal"
		case "threads/" + threadID:
			sawThread = true
			wantMetadata(t, "threads.get", rq)
		}
	}
	if !sawMinimal || !sawThread {
		t.Fatalf("Thread calls: messages.get minimal %v, threads.get %v; want both", sawMinimal, sawThread)
	}

	want := []mail.Message{
		{
			ID: "18f0b0000000000a", Folder: "SENT",
			From:      mail.Address{Name: "Me", Address: "me@example.com"},
			To:        []mail.Address{{Name: "Bob Example", Address: "bob@example.com"}},
			Cc:        []mail.Address{{Address: "carol@example.com"}},
			Date:      time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC),
			Subject:   "Friday",
			Preview:   "Shall we meet on Friday?",
			Flags:     mail.Flags{Seen: true, Labels: []string{"SENT"}},
			Size:      1200,
			MessageID: "<t1-a@example.com>",
		},
		{
			ID: "18f0b0000000000b", Folder: "INBOX",
			From:      mail.Address{Name: "Bob Example", Address: "bob@example.com"},
			To:        []mail.Address{{Name: "Me", Address: "me@example.com"}},
			Cc:        []mail.Address{},
			Date:      time.Date(2026, 10, 12, 13, 0, 0, 0, time.UTC),
			Subject:   "Re: Friday",
			Preview:   "Yes & I will bring the notes",
			Flags:     mail.Flags{Seen: true, Flagged: true, Labels: []string{"INBOX"}},
			Size:      2400,
			MessageID: "<t1-b@example.com>",
		},
		{
			ID: "18f0b0000000000c", Folder: "Projects/Alpha",
			From:      mail.Address{Address: "carol@example.com"},
			To:        []mail.Address{{Address: "me@example.com"}, {Address: "bob@example.com"}},
			Cc:        []mail.Address{},
			Date:      time.Date(2026, 10, 12, 14, 0, 0, 0, time.UTC),
			Subject:   "Re: Friday",
			Preview:   "Moved to the Alpha label",
			Flags:     mail.Flags{Labels: []string{"Label_2"}},
			Size:      3600,
			MessageID: "<t1-c@example.com>",
		},
	}
	if len(res.Messages) != len(want) {
		t.Fatalf("Thread gave %d rows, want %d", len(res.Messages), len(want))
	}
	for i, got := range res.Messages {
		if !reflect.DeepEqual(*got, want[i]) {
			t.Errorf("row %d:\n got %+v\nwant %+v", i, *got, want[i])
		}
	}

	// The rows of Search over the same messages are the same rows.
	page, err := p.Search(ctx, mail.Query{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != len(res.Messages) {
		t.Fatalf("Search gave %d rows, Thread %d", len(page.Messages), len(res.Messages))
	}
	for i := range page.Messages {
		if !reflect.DeepEqual(page.Messages[i], *res.Messages[i]) {
			t.Errorf("row %d: Search %+v, Thread %+v", i, page.Messages[i], *res.Messages[i])
		}
	}

	before := len(f.requests())
	if _, err := p.Thread(ctx, "../labels"); !errors.Is(err, mail.ErrInvalidID) {
		t.Fatalf("Thread(\"../labels\"): err = %v, want mail.ErrInvalidID", err)
	}
	if after := len(f.requests()); after != before {
		t.Fatalf("an id that is not a Gmail id made %d API calls, want 0", after-before)
	}
}

// TestGmail_QueryTranslation holds DS7.6 and G9: the shared terms map
// one to one to Gmail operators, body: and free text go in as quoted
// text, in: goes into labelIds and never into q, Since adds after:,
// and a term with no Gmail form fails with "gmail search does not
// support <term>".
//
// arch: DS7.4, DS7.6, DS7.9, IS78.5
func TestGmail_QueryTranslation(t *testing.T) {
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		raw     string
		since   time.Time
		q       string
		folders []string
		err     string
	}{
		{raw: "", q: ""},
		{raw: "*", since: since, q: "after:" + strconv.FormatInt(since.Unix(), 10)},
		{raw: `from:alice@example.com to:bob@example.com cc:carol@example.com subject:"weekly report"`,
			q: `from:alice@example.com to:bob@example.com cc:carol@example.com subject:"weekly report"`},
		{raw: `invoice body:"due date" -spam`, q: `"invoice" "due date" -"spam"`},
		{raw: "has:attachment is:unread -is:starred", q: "has:attachment is:unread -is:starred"},
		{raw: "before:2026-10-01 after:2026/09/01", q: "before:2026/10/01 after:2026/09/01"},
		{raw: "newer_than:7d older_than:1Y larger:5M smaller:200K",
			q: "newer_than:7d older_than:1y larger:5242880 smaller:204800"},
		{raw: "in:Receipts from:alice@example.com", q: "from:alice@example.com", folders: []string{"Receipts"}},
		{raw: "is:answered", err: "gmail search does not support is:answered"},
		{raw: "has:drive", err: "gmail search does not support has:drive"},
		{raw: "-in:INBOX", err: "gmail search does not support -in:INBOX"},
		{raw: "before:yesterday", err: `gmail search: before:"yesterday" is not a date; use YYYY-MM-DD`},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			sq, err := translateQuery(mail.ParseQuery(c.raw), c.since)
			if c.err != "" {
				if err == nil || err.Error() != c.err {
					t.Fatalf("translateQuery(%q): err = %v, want %q", c.raw, err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("translateQuery(%q): %v", c.raw, err)
			}
			if sq.q != c.q || !reflect.DeepEqual(sq.folders, c.folders) {
				t.Fatalf("translateQuery(%q) = q %q folders %q, want q %q folders %q", c.raw, sq.q, sq.folders, c.q, c.folders)
			}
		})
	}
}
