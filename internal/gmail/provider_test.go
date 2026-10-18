// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Gmail provider core against fakeGmail (DS7.4, DS7.4b):
// the map from labelIds to flags, the folders with their roles and
// counts, the limit of 10 labels.get calls at a time, and the label
// cache of 10 minutes that two providers of one account share.

package gmail

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// TestGmail_VolatileLabelsExcluded holds DS7.4b: Seen is no UNREAD,
// Flagged is STARRED, Draft is DRAFT, Answered is always false, and
// Flags.Labels holds every label id but UNREAD, STARRED, DRAFT,
// IMPORTANT, CHAT and CATEGORY_*. INBOX, SENT, TRASH, SPAM and the user
// labels stay in Labels, so a move is a label difference. A change that
// Gmail makes on its own (IMPORTANT, a category) gives the same flags,
// so the undo check does not refuse (DS78.5, R§7.3).
//
// arch: DS7.4, DS7.4b, DS7.9, IS7.1
func TestGmail_VolatileLabelsExcluded(t *testing.T) {
	cases := []struct {
		name string
		ids  []string
		want mail.Flags
	}{
		{
			name: "marks only",
			ids:  []string{"UNREAD", "STARRED", "DRAFT", "IMPORTANT", "CATEGORY_PERSONAL", "CHAT"},
			want: mail.Flags{Seen: false, Flagged: true, Draft: true},
		},
		{
			name: "read, in the inbox, with a category",
			ids:  []string{"INBOX", "CATEGORY_UPDATES", "IMPORTANT"},
			want: mail.Flags{Seen: true, Labels: []string{"INBOX"}},
		},
		{
			name: "folders and user labels stay",
			ids: []string{"INBOX", "UNREAD", "Label_1", "SENT", "CATEGORY_SOCIAL",
				"TRASH", "SPAM", "STARRED", "Label_22", "CATEGORY_FORUMS", "CATEGORY_PROMOTIONS"},
			want: mail.Flags{Flagged: true, Labels: []string{"INBOX", "Label_1", "SENT", "TRASH", "SPAM", "Label_22"}},
		},
		{
			name: "no labels",
			ids:  nil,
			want: mail.Flags{Seen: true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := flagsOf(c.ids); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("flagsOf(%q) = %+v, want %+v", c.ids, got, c.want)
			}
		})
	}

	// Gmail adds IMPORTANT and categories on its own: the flags stay equal.
	before := flagsOf([]string{"INBOX", "Label_1"})
	after := flagsOf([]string{"CATEGORY_UPDATES", "INBOX", "IMPORTANT", "Label_1", "CATEGORY_FORUMS", "CHAT"})
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("a change Gmail makes on its own changed the flags: %+v, then %+v", before, after)
	}

	// A move from INBOX to Label_1 shows as a label difference.
	moved := flagsOf([]string{"Label_1", "IMPORTANT"})
	if reflect.DeepEqual(flagsOf([]string{"INBOX", "IMPORTANT"}).Labels, moved.Labels) {
		t.Fatalf("a move left the labels equal: %q", moved.Labels)
	}
	if !reflect.DeepEqual(moved.Labels, []string{"Label_1"}) {
		t.Fatalf("labels after the move = %q, want [Label_1]", moved.Labels)
	}
}

// TestGmail_FoldersRoles holds the Folders row of DS7.4 (gap G9):
// INBOX, SENT, DRAFT, TRASH and SPAM have the roles inbox, sent,
// drafts, trash and junk; a user label is a folder with no role, also
// when its name is "Trash" (E5); STARRED, UNREAD, IMPORTANT, CHAT and
// CATEGORY_* are not folders. The counts come from labels.get, one
// call for each folder and none for a mark.
//
// arch: DS7.4, DS7.4b, DS7.9, IS7.1, E5
func TestGmail_FoldersRoles(t *testing.T) {
	f := newFakeGmailRoutes(t, routes(labelRoutes(t)))
	p, _ := f.provider(nil)

	got, err := p.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	want := []mail.Folder{
		{Name: "SENT", Role: "sent", Total: 45, Unread: 0},
		{Name: "INBOX", Role: "inbox", Total: 120, Unread: 7},
		{Name: "TRASH", Role: "trash", Total: 13, Unread: 1},
		{Name: "DRAFT", Role: "drafts", Total: 2, Unread: 0},
		{Name: "SPAM", Role: "junk", Total: 4, Unread: 4},
		{Name: "Receipts", Role: "", Total: 31, Unread: 3},
		{Name: "Projects/Alpha", Role: "", Total: 8, Unread: 2},
		{Name: "Trash", Role: "", Total: 6, Unread: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Folders =\n%+v\nwant\n%+v", got, want)
	}

	reqs := f.requests()
	if len(reqs) == 0 || reqs[0].Method != http.MethodGet || reqs[0].Path != apiPrefix+"labels" {
		t.Fatalf("first request = %+v, want GET %slabels", reqs, apiPrefix)
	}
	var gets []string
	for _, r := range reqs[1:] {
		if r.Method != http.MethodGet {
			t.Fatalf("request %s %s, want GET only", r.Method, r.Path)
		}
		gets = append(gets, strings.TrimPrefix(r.Path, apiPrefix))
	}
	sort.Strings(gets)
	wantGets := []string{"labels/DRAFT", "labels/INBOX", "labels/Label_1", "labels/Label_2",
		"labels/Label_3", "labels/SENT", "labels/SPAM", "labels/TRASH"}
	if !reflect.DeepEqual(gets, wantGets) {
		t.Fatalf("labels.get calls = %q, want %q", gets, wantGets)
	}
	for _, r := range reqs {
		if r.Auth != "Bearer tok-1" {
			t.Fatalf("request %s has Authorization %q, want the token", r.Path, r.Auth)
		}
	}
}

// TestGmail_FoldersFanOut10 holds E2 for Folders: labels.list gives no
// counts, and the labels.get calls run 10 at a time, never more and
// not one after the other. Each folder gets its own counts.
//
// arch: DS7.4, DS7.9, IS7.1, E2
func TestGmail_FoldersFanOut10(t *testing.T) {
	const n = 25
	var list strings.Builder
	list.WriteString(`{"labels":[{"id":"UNREAD","name":"UNREAD","type":"system"},{"id":"STARRED","name":"STARRED","type":"system"}`)
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&list, `,{"id":"Label_%d","name":"L%d","type":"user"}`, i, i)
	}
	list.WriteString(`]}`)

	var (
		mu       sync.Mutex
		inFlight int
		peak     int
		calls    int
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
		if rest == "labels" {
			return step{status: 200, body: list.String()}
		}
		id, ok := strings.CutPrefix(rest, "labels/")
		if !ok {
			return step{status: 404, body: googleError(404, "NOT_FOUND", "notFound", "", "not found")}
		}
		mu.Lock()
		inFlight++
		calls++
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
		num := strings.TrimPrefix(id, "Label_")
		return step{status: 200, body: fmt.Sprintf(`{"id":%q,"name":"L%s","type":"user","messagesTotal":%s,"messagesUnread":1}`, id, num, num)}
	})
	p, _ := f.provider(nil)

	got, err := p.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	mu.Lock()
	gotPeak, gotCalls := peak, calls
	mu.Unlock()
	if gotPeak != 10 {
		t.Fatalf("labels.get calls in flight at most = %d, want 10", gotPeak)
	}
	if gotCalls != n {
		t.Fatalf("labels.get calls = %d, want %d", gotCalls, n)
	}
	if len(got) != n {
		t.Fatalf("Folders gave %d folders, want %d", len(got), n)
	}
	for i, fo := range got {
		want := mail.Folder{Name: fmt.Sprintf("L%d", i+1), Total: i + 1, Unread: 1}
		if fo != want {
			t.Fatalf("folder %d = %+v, want %+v", i, fo, want)
		}
	}
}

// TestGmail_LabelCache10Min holds the label cache of DS7.4 and G6: the
// labels.list answer of Folders serves name to id and id to name for
// 10 minutes on the wall clock, also to a second provider with the same
// State; after 10 minutes, or when the clock steps back, the next
// lookup calls labels.list again. A name matches with no regard to
// case, and a user label named "Trash" keeps the name before the
// system TRASH (E5).
//
// arch: DS7.4, DS7.4a, DS7.9, IS7.1, E5
func TestGmail_LabelCache10Min(t *testing.T) {
	f := newFakeGmailRoutes(t, routes(labelRoutes(t)))
	st := &State{}
	clock := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	p1, _ := f.provider(st)
	p2, _ := f.provider(st)
	p1.now, p2.now = now, now
	ctx := context.Background()

	listCalls := func() int {
		n := 0
		for _, r := range f.requests() {
			if r.Path == apiPrefix+"labels" {
				n++
			}
		}
		return n
	}

	if _, err := p1.Folders(ctx); err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if got := listCalls(); got != 1 {
		t.Fatalf("labels.list calls after Folders = %d, want 1", got)
	}

	tab, err := p2.cachedLabels(ctx)
	if err != nil {
		t.Fatalf("cachedLabels: %v", err)
	}
	if got := listCalls(); got != 1 {
		t.Fatalf("labels.list calls after a lookup through the shared State = %d, want 1", got)
	}
	for name, id := range map[string]string{
		"inbox":          "INBOX",
		"receipts":       "Label_1",
		"projects/alpha": "Label_2",
		"trash":          "Label_3",
		"spam":           "SPAM",
	} {
		if got := tab.byName[name]; got != id {
			t.Fatalf("byName[%q] = %q, want %q", name, got, id)
		}
	}
	if got := tab.byID["Label_2"]; got != "Projects/Alpha" {
		t.Fatalf("byID[Label_2] = %q, want Projects/Alpha", got)
	}

	clock = clock.Add(labelTTL - time.Second)
	if _, err := p2.cachedLabels(ctx); err != nil {
		t.Fatalf("cachedLabels: %v", err)
	}
	if got := listCalls(); got != 1 {
		t.Fatalf("labels.list calls before 10 min = %d, want 1", got)
	}

	clock = clock.Add(time.Second)
	if _, err := p2.cachedLabels(ctx); err != nil {
		t.Fatalf("cachedLabels: %v", err)
	}
	if got := listCalls(); got != 2 {
		t.Fatalf("labels.list calls at 10 min = %d, want 2", got)
	}

	clock = clock.Add(-time.Minute)
	if _, err := p1.cachedLabels(ctx); err != nil {
		t.Fatalf("cachedLabels: %v", err)
	}
	if got := listCalls(); got != 3 {
		t.Fatalf("labels.list calls after the clock stepped back = %d, want 3", got)
	}
}

// TestGmail_SearchIDsOnly holds the ids-only search of DS9.4: with
// Query.IDsOnly, Search calls messages.list once and sends no
// messages.get, so the number of metadata gets is zero. The rows carry
// the ids of messages.list in its order and nothing else. The cursor
// holds the nextPageToken, and the next ids-only page sends it as
// pageToken. A full search on the same fake does send the metadata
// gets, so the count of zero is not a blind counter.
//
// arch: DS9.1, DS9.2, DS9.4
func TestGmail_SearchIDsOnly(t *testing.T) {
	ids := []string{"18f0c00000000001", "18f0c00000000002", "18f0c00000000003"}
	labels := labelRoutes(t)["GET labels"]
	var (
		mu       sync.Mutex
		lists    []string // pageToken of each messages.list call
		metaGets int
	)
	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		rest := strings.TrimPrefix(r.URL.Path, apiPrefix)
		switch {
		case rest == "labels":
			return labels
		case rest == "messages":
			mu.Lock()
			lists = append(lists, r.URL.Query().Get("pageToken"))
			mu.Unlock()
			if r.URL.Query().Get("pageToken") == "" {
				return step{status: 200, body: listBody("tok-2", ids...)}
			}
			return step{status: 200, body: listBody("", "18f0c00000000004")}
		case strings.HasPrefix(rest, "messages/"):
			mu.Lock()
			metaGets++
			mu.Unlock()
			return step{status: 200, body: fixture(t, "messages.get.json")}
		}
		return step{status: 404, body: googleError(404, "NOT_FOUND", "notFound", "", "not found")}
	})
	p, _ := f.provider(nil)
	ctx := context.Background()

	q := mail.Query{Raw: "from:alice@example.com", Folder: "INBOX", Limit: 3, IDsOnly: true}
	page, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search ids-only: %v", err)
	}
	var got []string
	for _, m := range page.Messages {
		if !reflect.DeepEqual(m, mail.Message{ID: m.ID}) {
			t.Errorf("ids-only row %q carries more than the id: %+v", m.ID, m)
		}
		got = append(got, m.ID)
	}
	if !reflect.DeepEqual(got, ids) {
		t.Fatalf("ids-only rows = %q, want %q", got, ids)
	}
	if page.NextCursor == "" {
		t.Fatal("ids-only page has no cursor, want one for nextPageToken tok-2")
	}
	if page.Partial {
		t.Error("ids-only page is Partial; every Gmail term runs on the server")
	}

	q.Cursor = page.NextCursor
	page2, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search ids-only page 2: %v", err)
	}
	if len(page2.Messages) != 1 || page2.Messages[0].ID != "18f0c00000000004" || page2.NextCursor != "" {
		t.Fatalf("ids-only page 2 = %+v, want one row 18f0c00000000004 and no cursor", page2)
	}

	mu.Lock()
	if metaGets != 0 {
		t.Errorf("ids-only search sent %d metadata gets, want 0", metaGets)
	}
	if want := []string{"", "tok-2"}; !reflect.DeepEqual(lists, want) {
		t.Errorf("messages.list pageTokens = %q, want %q", lists, want)
	}
	mu.Unlock()

	// The same query without IDsOnly reads each row.
	full, err := p.Search(ctx, mail.Query{Raw: q.Raw, Folder: q.Folder, Limit: 3})
	if err != nil {
		t.Fatalf("Search full: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if metaGets != len(ids) || len(full.Messages) != len(ids) {
		t.Fatalf("full search: %d metadata gets and %d rows, want %d of each", metaGets, len(full.Messages), len(ids))
	}
}

// TestGmail_ReadHeadersOnDemand holds the headers on demand of DS9.2:
// Read copies the headers that ReadOpts.Headers names from the
// payload.headers of the one format=full answer into Message.Headers.
// A header matches a name in any case; each instance gives one entry,
// in message order; a name that the list repeats counts once, under
// its first spelling. A value is unfolded and trimmed, but not decoded.
// A name with no instance has no key. With no names, or with no match,
// Message.Headers is nil. Each read sends one messages.get with
// format=full and no other messages call, so the headers cost nothing.
//
// arch: DS9.1, DS9.2, DS9.4
func TestGmail_ReadHeadersOnDemand(t *testing.T) {
	const id = "18f0c0000000000a"
	payload := leaf("", "text/plain", "text/plain; charset=utf-8", "Hello\r\n")
	payload.Headers = append(payload.Headers,
		metaHeader{Name: "List-Unsubscribe", Value: "<https://example.com/u/1>,\r\n <mailto:u@example.com?subject=stop>"},
		metaHeader{Name: "Subject", Value: "=?UTF-8?Q?Caf=C3=A9?="},
		metaHeader{Name: "list-unsubscribe", Value: "  <https://example.com/u/2>  "},
		metaHeader{Name: "List-Unsubscribe-Post", Value: "List-Unsubscribe=One-Click"},
	)
	f := readFake(t, id, fullBody(t, id, payload), nil)
	p, _ := f.provider(nil)
	ctx := context.Background()

	cases := []struct {
		name  string
		names []string
		want  map[string][]string
	}{
		{name: "no names", names: nil, want: nil},
		{name: "no match", names: []string{"X-Absent"}, want: nil},
		{
			name:  "asked names",
			names: []string{"LIST-UNSUBSCRIBE", "list-unsubscribe-post", "List-Unsubscribe", "X-Absent", "subject"},
			want: map[string][]string{
				"LIST-UNSUBSCRIBE":      {"<https://example.com/u/1>, <mailto:u@example.com?subject=stop>", "<https://example.com/u/2>"},
				"list-unsubscribe-post": {"List-Unsubscribe=One-Click"},
				"subject":               {"Test", "=?UTF-8?Q?Caf=C3=A9?="},
			},
		},
	}
	for _, c := range cases {
		before := len(f.requests())
		msg, err := p.Read(ctx, id, mail.ReadOpts{Headers: c.names})
		if err != nil {
			t.Fatalf("%s: Read: %v", c.name, err)
		}
		if !reflect.DeepEqual(msg.Headers, c.want) {
			t.Errorf("%s: Headers = %q, want %q", c.name, msg.Headers, c.want)
		}
		if msg.Body != "Hello\r\n" || msg.Subject != "Test" {
			t.Errorf("%s: Body = %q, Subject = %q; the header copy changed the read", c.name, msg.Body, msg.Subject)
		}
		var gets []string
		for _, r := range f.requests()[before:] {
			if strings.HasPrefix(strings.TrimPrefix(r.Path, apiPrefix), "messages") {
				gets = append(gets, r.Method+" "+strings.TrimPrefix(r.Path, apiPrefix)+"?"+r.RawQuery)
			}
		}
		if want := []string{"GET messages/" + id + "?format=full"}; !reflect.DeepEqual(gets, want) {
			t.Errorf("%s: messages calls = %q, want %q", c.name, gets, want)
		}
	}
}
