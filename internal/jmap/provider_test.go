// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the read side of the JMAP provider (DS8.2, DS8.2b) against
// fakeJMAP with a fakeStore. No test reaches the network (IS78.1).

package jmap

import (
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// The mailbox ids of testStore.
const (
	boxInbox    = "mb-inbox"
	boxArchive  = "mb-archive"
	boxProjects = "mb-projects"
	boxWork     = "mb-work"
	boxFlagged  = "mb-flagged"
)

// testMailboxes gives the mailboxes of testStore: a tree
// Projects/Work, two roles that are folder roles, and the role
// "flagged" that is not.
func testMailboxes() []map[string]any {
	return []map[string]any{
		{"id": boxInbox, "name": "Inbox", "parentId": nil, "role": "inbox", "totalEmails": 3, "unreadEmails": 1},
		{"id": boxWork, "name": "Work", "parentId": boxProjects, "role": nil, "totalEmails": 2, "unreadEmails": 2},
		{"id": boxArchive, "name": "Archive", "parentId": nil, "role": "archive", "totalEmails": 7, "unreadEmails": 0},
		{"id": boxProjects, "name": "Projects", "parentId": nil, "role": nil, "totalEmails": 0, "unreadEmails": 0},
		{"id": boxFlagged, "name": "Flagged", "parentId": nil, "role": "flagged", "totalEmails": 1, "unreadEmails": 0},
	}
}

// email gives a row object with id, mailboxes and keywords.
func email(id string, boxes []string, keywords map[string]any, at string) map[string]any {
	mb := map[string]any{}
	for _, b := range boxes {
		mb[b] = true
	}
	return map[string]any{
		"id":            id,
		"threadId":      "t-" + id,
		"mailboxIds":    mb,
		"keywords":      keywords,
		"from":          []any{map[string]any{"name": "Ann", "email": "ann@example.test"}},
		"to":            []any{map[string]any{"name": nil, "email": "me@example.test"}},
		"subject":       "Subject " + id,
		"receivedAt":    at,
		"size":          1234,
		"preview":       "Preview of " + id,
		"hasAttachment": false,
	}
}

// testStore gives three emails, newest first: e1 and e3 in the inbox,
// e2 in Projects/Work.
func testStore() *fakeStore {
	return &fakeStore{
		mailboxes: testMailboxes(),
		emails: []map[string]any{
			email("e1", []string{boxInbox}, map[string]any{"$seen": true}, "2026-10-09T10:00:00Z"),
			email("e2", []string{boxWork}, map[string]any{}, "2026-10-08T10:00:00Z"),
			email("e3", []string{boxInbox}, map[string]any{}, "2026-10-07T10:00:00Z"),
		},
	}
}

// inboxStore gives the three emails of testStore, all in the inbox, for
// the tests of paging that search with no folder.
func inboxStore() *fakeStore {
	s := testStore()
	s.emails[1] = email("e2", []string{boxInbox}, map[string]any{}, "2026-10-08T10:00:00Z")
	return s
}

// newTestProvider gives a provider of the fake with store, and the
// fake.
func newTestProvider(t *testing.T, store *fakeStore, onAuth func(error)) (*Provider, *fakeJMAP) {
	t.Helper()
	f := newFakeJMAP(t, fakeOpts{store: store})
	acct := config.Account{Alias: "home", Provider: "jmap", Email: "me@example.test"}
	return NewProvider(acct, f.client(nil, false), onAuth), f
}

// methodCalls gives every method call that the fake got, in order.
func methodCalls(f *fakeJMAP) []Invocation {
	var out []Invocation
	for _, r := range f.apiRequests() {
		out = append(out, r.MethodCalls...)
	}
	return out
}

// lastCall gives the last method call with the name.
func lastCall(t *testing.T, f *fakeJMAP, name string) Invocation {
	t.Helper()
	calls := methodCalls(f)
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Name == name {
			return calls[i]
		}
	}
	t.Fatalf("no %s call in %v", name, calls)
	return Invocation{}
}

// strs gives the strings of a JSON list.
func strs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// TestJMAP_KeywordsToLabelsNotMailboxes checks DS8.2b: the four flag
// keywords set the flags, every other keyword goes to Labels, and no
// mailbox (id or name) ever reaches Labels, also when a keyword and a
// mailbox have one name. The folder of the row is the mailbox path.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_KeywordsToLabelsNotMailboxes(t *testing.T) {
	store := &fakeStore{
		mailboxes: testMailboxes(),
		emails: []map[string]any{
			email("k1", []string{boxWork, boxFlagged}, map[string]any{
				"$seen": true, "$Flagged": true, "$answered": true, "$draft": true,
				"$forwarded": true, "Work": true, "off": false,
			}, "2026-10-09T10:00:00Z"),
			email("k2", []string{boxWork}, map[string]any{}, "2026-10-08T10:00:00Z"),
		},
	}
	p, _ := newTestProvider(t, store, nil)
	ctx := context.Background()

	page, err := p.Search(ctx, mail.Query{Folder: "Projects/Work"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 2 {
		t.Fatalf("Search gave %d rows, want 2", len(page.Messages))
	}
	read, err := p.Read(ctx, "k1", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	want := mail.Flags{Seen: true, Flagged: true, Answered: true, Draft: true, Labels: []string{"$forwarded", "Work"}}
	for name, got := range map[string]mail.Flags{"search": page.Messages[0].Flags, "read": read.Flags} {
		if got.Seen != want.Seen || got.Flagged != want.Flagged || got.Answered != want.Answered || got.Draft != want.Draft {
			t.Errorf("%s: flags %+v, want %+v", name, got, want)
		}
		if !slices.Equal(got.Labels, want.Labels) {
			t.Errorf("%s: labels %q, want %q", name, got.Labels, want.Labels)
		}
		for _, l := range got.Labels {
			if l == boxWork || l == boxFlagged || l == "Projects/Work" || l == "Flagged" {
				t.Errorf("%s: label %q is a mailbox", name, l)
			}
		}
	}
	if got := page.Messages[1].Flags; got.Seen || got.Flagged || len(got.Labels) != 0 {
		t.Errorf("k2: flags %+v, want none and no labels although it is in mailbox Work", got)
	}
	if got := page.Messages[1].Folder; got != "Projects/Work" {
		t.Errorf("k2: folder %q, want Projects/Work", got)
	}
	if got := page.Messages[0].Folder; got != "Projects/Work" {
		t.Errorf("k1: folder %q, want the searched folder Projects/Work", got)
	}
	if got := read.Folder; got != "Flagged" {
		t.Errorf("read k1: folder %q, want the first path in sort order, Flagged", got)
	}
}

// TestJMAP_FlagsOfKeywords checks the keyword map of DS8.2b in
// isolation: case does not matter for a flag keyword, a false keyword
// is not set, and Labels is sorted.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_FlagsOfKeywords(t *testing.T) {
	got := flagsOf(map[string]bool{"$SEEN": true, "zeta": true, "$junk": true, "$flagged": false, "alpha": true})
	if !got.Seen || got.Flagged || got.Answered || got.Draft {
		t.Errorf("flags %+v, want Seen only", got)
	}
	if want := []string{"$junk", "alpha", "zeta"}; !slices.Equal(got.Labels, want) {
		t.Errorf("labels %q, want %q", got.Labels, want)
	}
	if empty := flagsOf(nil); empty.Seen || empty.Labels != nil {
		t.Errorf("nil keywords gave %+v", empty)
	}
}

// htmlOnly gives an email whose only body part is text/html. A server
// puts that part in textBody too (RFC 8621 §4.1.4), which is the trap
// of F3.
func htmlOnly(id, html string) map[string]any {
	e := email(id, []string{boxInbox}, map[string]any{}, "2026-10-09T10:00:00Z")
	part := map[string]any{"partId": "1", "blobId": "b1", "size": len(html), "type": "text/html", "disposition": nil, "name": nil}
	e["bodyStructure"] = part
	e["textBody"] = []any{part}
	e["htmlBody"] = []any{part}
	e["attachments"] = []any{}
	e["bodyValues"] = map[string]any{"1": map[string]any{"value": html, "isTruncated": false, "isEncodingProblem": false}}
	return e
}

// TestJMAP_HTMLOnlyBody checks F3: the HTML part that a server lists
// in textBody is not shown as text. Read gives the text of the HTML
// part with the hidden run removed, and the source for format html.
// The request asks for both value kinds with the 1 MiB cap.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_HTMLOnlyBody(t *testing.T) {
	html := `<html><body><p>Hello <b>there</b></p><div style="display:none">HIDDEN-RUN</div></body></html>`
	store := &fakeStore{mailboxes: testMailboxes(), emails: []map[string]any{htmlOnly("h1", html)}}
	p, f := newTestProvider(t, store, nil)

	m, err := p.Read(context.Background(), "h1", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if strings.Contains(m.Body, "<") || !strings.Contains(m.Body, "Hello") || !strings.Contains(m.Body, "there") {
		t.Errorf("body %q, want the text of the HTML part", m.Body)
	}
	if strings.Contains(m.Body, "HIDDEN-RUN") || m.HiddenRemoved != 1 {
		t.Errorf("body %q, removed %d: want the hidden run removed and counted", m.Body, m.HiddenRemoved)
	}
	if m.PartsDiffer {
		t.Error("PartsDiffer set with one part")
	}
	if m.SignedHint != mail.SignedNo {
		t.Errorf("SignedHint %v, want not signed: the one text part arrived whole", m.SignedHint)
	}

	src, err := p.Read(context.Background(), "h1", mail.ReadOpts{Format: "html"})
	if err != nil {
		t.Fatalf("Read html: %v", err)
	}
	if src.Body != html {
		t.Errorf("html body %q, want the source", src.Body)
	}

	args := lastCall(t, f, "Email/get").Args
	if args["fetchTextBodyValues"] != true || args["fetchHTMLBodyValues"] != true {
		t.Errorf("fetch flags %v %v, want both true", args["fetchTextBodyValues"], args["fetchHTMLBodyValues"])
	}
	if got, _ := args["maxBodyValueBytes"].(float64); got != 1<<20 {
		t.Errorf("maxBodyValueBytes %v, want 1 MiB", args["maxBodyValueBytes"])
	}
	props := strs(args["properties"])
	for _, want := range []string{"textBody", "htmlBody", "bodyStructure", "bodyValues", "header:References", "header:Message-ID", "header:Authentication-Results:asRaw:all"} {
		if !slices.Contains(props, want) {
			t.Errorf("properties %q lack %q", props, want)
		}
	}
	if !slices.Contains(strs(args["bodyProperties"]), "subParts") {
		t.Errorf("bodyProperties %q lack subParts", strs(args["bodyProperties"]))
	}
}

// plainEmail gives an email with one text/plain part and the value v.
func plainEmail(id, v string, truncated bool) map[string]any {
	e := email(id, []string{boxInbox}, map[string]any{}, "2026-10-09T10:00:00Z")
	part := map[string]any{"partId": "1", "blobId": "b-" + id, "size": 5 << 20, "type": "text/plain"}
	e["bodyStructure"] = part
	e["textBody"] = []any{part}
	e["htmlBody"] = []any{part}
	e["attachments"] = []any{}
	e["bodyValues"] = map[string]any{"1": map[string]any{"value": v, "isTruncated": truncated}}
	return e
}

// TestJMAP_TruncatedBodyIsCut checks the cut of DS8.2: a value that the
// server marks isTruncated is a cut, so Read never says SignedNo for
// it, because the text after the cut can hold a signature marker. The
// same message whole gives SignedNo; a value that the answer lacks is
// a cut too; offset and max_chars still apply to the text that came.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_TruncatedBodyIsCut(t *testing.T) {
	text := "Dear reader, the first megabyte of a long message."
	missing := plainEmail("m1", "", false)
	missing["bodyValues"] = map[string]any{}
	store := &fakeStore{mailboxes: testMailboxes(), emails: []map[string]any{
		plainEmail("cut", text, true),
		plainEmail("whole", text, false),
		missing,
	}}
	p, _ := newTestProvider(t, store, nil)
	ctx := context.Background()

	cut, err := p.Read(ctx, "cut", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read cut: %v", err)
	}
	if cut.Body != text {
		t.Errorf("cut body %q, want the value that came", cut.Body)
	}
	if cut.SignedHint != mail.SignedUnknown {
		t.Errorf("cut SignedHint %v, want unknown", cut.SignedHint)
	}

	whole, err := p.Read(ctx, "whole", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read whole: %v", err)
	}
	if whole.SignedHint != mail.SignedNo {
		t.Errorf("whole SignedHint %v, want not signed", whole.SignedHint)
	}

	gone, err := p.Read(ctx, "m1", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read m1: %v", err)
	}
	if gone.SignedHint != mail.SignedUnknown || gone.Body != "" {
		t.Errorf("missing value: SignedHint %v body %q, want unknown and empty", gone.SignedHint, gone.Body)
	}

	part, err := p.Read(ctx, "cut", mail.ReadOpts{Offset: 5, MaxChars: 6})
	if err != nil {
		t.Fatalf("Read with offset: %v", err)
	}
	if part.Body != "reader" {
		t.Errorf("offset 5 max 6 gave %q, want reader", part.Body)
	}
}

// TestJMAP_ReadSignedAndHeaders checks the rest of the Read row of
// DS8.2: a multipart/signed structure gives SignedYes, a marker in a
// text value gives SignedYes, a top-level enveloped part gives no
// SignedYes, and the headers, Reply-To and the attachment list (Ref is
// the partId) arrive.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_ReadSignedAndHeaders(t *testing.T) {
	signed := plainEmail("s1", "Signed text", false)
	text := map[string]any{"partId": "1", "type": "text/plain"}
	sig := map[string]any{"partId": "2", "blobId": "b-sig", "type": "application/pkcs7-signature", "name": "smime.p7s", "disposition": "attachment", "size": 300}
	signed["bodyStructure"] = map[string]any{"type": "multipart/signed", "subParts": []any{text, sig}}
	signed["attachments"] = []any{sig}
	signed["replyTo"] = []any{map[string]any{"name": "Desk", "email": "desk@example.test"}}
	signed["header:Message-ID"] = " <s1@example.test>"
	signed["header:References"] = " <a@example.test>\r\n <b@example.test>"
	signed["header:Authentication-Results:asRaw:all"] = []any{" mx.example.test; dkim=pass", " relay.example.test; dkim=none"}

	pgp := plainEmail("p1", "intro\n"+mail.InlinePGPMarker+"\nHash: SHA256", false)

	enveloped := plainEmail("v1", "", false)
	enveloped["bodyStructure"] = map[string]any{"partId": "1", "type": "application/pkcs7-mime"}
	enveloped["textBody"] = []any{}
	enveloped["htmlBody"] = []any{}
	enveloped["header:Content-Type"] = " application/pkcs7-mime;\r\n smime-type=enveloped-data; name=\"smime.p7m\""

	store := &fakeStore{mailboxes: testMailboxes(), emails: []map[string]any{signed, pgp, enveloped}}
	p, _ := newTestProvider(t, store, nil)
	ctx := context.Background()

	m, err := p.Read(ctx, "s1", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read s1: %v", err)
	}
	if m.SignedHint != mail.SignedYes || m.MediaType != "multipart/signed" {
		t.Errorf("s1: SignedHint %v media %q, want signed multipart/signed", m.SignedHint, m.MediaType)
	}
	if m.MessageID != "<s1@example.test>" {
		t.Errorf("MessageID %q", m.MessageID)
	}
	if want := []string{"<a@example.test>", "<b@example.test>"}; !slices.Equal(m.References, want) {
		t.Errorf("References %q, want %q", m.References, want)
	}
	if want := "Authentication-Results: mx.example.test; dkim=pass\r\nAuthentication-Results: relay.example.test; dkim=none\r\n"; m.AuthResults != want {
		t.Errorf("AuthResults %q, want %q", m.AuthResults, want)
	}
	if len(m.ReplyTo) != 1 || m.ReplyTo[0].Address != "desk@example.test" {
		t.Errorf("ReplyTo %+v", m.ReplyTo)
	}
	if len(m.Attachments) != 1 || m.Attachments[0].Ref != "2" || m.Attachments[0].Filename != "smime.p7s" || m.Attachments[0].Size != 300 {
		t.Errorf("Attachments %+v, want one with Ref 2", m.Attachments)
	}
	if m.From.Address != "ann@example.test" || len(m.To) != 1 || m.Date.IsZero() {
		t.Errorf("row fields: from %+v to %+v date %v", m.From, m.To, m.Date)
	}

	pm, err := p.Read(ctx, "p1", mail.ReadOpts{MaxChars: 3})
	if err != nil {
		t.Fatalf("Read p1: %v", err)
	}
	if pm.SignedHint != mail.SignedYes {
		t.Errorf("p1: SignedHint %v, want signed although the marker is past max_chars", pm.SignedHint)
	}

	vm, err := p.Read(ctx, "v1", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read v1: %v", err)
	}
	if vm.SignedHint == mail.SignedYes || vm.SMIMEType != "enveloped-data" || vm.MediaType != "application/pkcs7-mime" {
		t.Errorf("v1: SignedHint %v smime %q media %q, want no signature, enveloped-data", vm.SignedHint, vm.SMIMEType, vm.MediaType)
	}
}

// TestJMAP_FoldersPathRoleCounts checks the Folders row of DS8.2: the
// name is the parent path joined by "/", the role maps, a role that is
// not a folder role gives none, and the counts arrive.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_FoldersPathRoleCounts(t *testing.T) {
	p, f := newTestProvider(t, testStore(), nil)
	got, err := p.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	want := []mail.Folder{
		{Name: "Archive", Role: "archive", Total: 7},
		{Name: "Flagged", Role: "", Total: 1},
		{Name: "Inbox", Role: "inbox", Total: 3, Unread: 1},
		{Name: "Projects"},
		{Name: "Projects/Work", Total: 2, Unread: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("Folders %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Role != want[i].Role || got[i].Total != want[i].Total || got[i].Unread != want[i].Unread {
			t.Errorf("folder %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	call := lastCall(t, f, "Mailbox/get")
	if props := strs(call.Args["properties"]); !slices.Contains(props, "parentId") || !slices.Contains(props, "totalEmails") {
		t.Errorf("Mailbox/get properties %q", props)
	}
}

// TestJMAP_MailboxPathLoop checks that a parent loop or a missing
// parent ends the walk, and that two mailboxes with one path make the
// name not unique instead of picking one.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_MailboxPathLoop(t *testing.T) {
	tab := newMailboxTable([]mailbox{
		{ID: "a", Name: "A", ParentID: "b"},
		{ID: "b", Name: "B", ParentID: "a"},
		{ID: "c", Name: "C", ParentID: "gone"},
		{ID: "d", Name: "Same"},
		{ID: "e", Name: "Same"},
	})
	if tab.path["a"] != "B/A" || tab.path["b"] != "A/B" || tab.path["c"] != "C" {
		t.Errorf("paths %v", tab.path)
	}
	if _, ok, err := tab.resolve("Same"); !ok || err == nil {
		t.Errorf("resolve Same: ok %v err %v, want not unique", ok, err)
	}
	if _, ok, err := tab.resolve("Nope"); ok || err != nil {
		t.Errorf("resolve Nope: ok %v err %v, want not found", ok, err)
	}
}

// TestJMAP_SearchBackReferenceAndPaging checks the Search row of
// DS8.2: one batch of Email/query and Email/get, the get takes the ids
// through #ids, the rows keep the query order, the cursor gives the
// next position, and total ends the paging. Without total a full page
// gives a cursor.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_SearchBackReferenceAndPaging(t *testing.T) {
	p, f := newTestProvider(t, inboxStore(), nil)
	ctx := context.Background()
	q := mail.Query{Raw: "is:unread", Limit: 2}

	page, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if ids := []string{page.Messages[0].ID, page.Messages[1].ID}; !slices.Equal(ids, []string{"e1", "e2"}) {
		t.Errorf("rows %q, want the query order e1 e2", ids)
	}
	if page.NextCursor == "" {
		t.Fatal("no cursor with 3 of total 3 left after 2")
	}
	reqs := f.apiRequests()
	last := reqs[len(reqs)-1].MethodCalls
	if len(last) != 2 || last[0].Name != "Email/query" || last[1].Name != "Email/get" {
		t.Fatalf("last batch %v, want Email/query then Email/get", last)
	}
	ref, _ := last[1].Args["#ids"].(map[string]any)
	if ref["resultOf"] != last[0].ID || ref["name"] != "Email/query" || ref["path"] != "/ids" {
		t.Errorf("#ids %v, want a reference to the query ids", ref)
	}
	if props := strs(last[1].Args["properties"]); !slices.Equal(props, listProperties) {
		t.Errorf("properties %q", props)
	}
	if last[0].Args["calculateTotal"] != true || last[0].Args["filter"] == nil {
		t.Errorf("query args %v", last[0].Args)
	}
	r := page.Messages[0]
	if r.Subject != "Subject e1" || r.Preview != "Preview of e1" || r.From.Address != "ann@example.test" || r.Folder != "Inbox" || r.Size != 1234 {
		t.Errorf("row %+v", r)
	}
	if want := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC); !r.Date.Equal(want) {
		t.Errorf("date %v, want receivedAt %v", r.Date, want)
	}

	q.Cursor = page.NextCursor
	page2, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search page 2: %v", err)
	}
	if len(page2.Messages) != 1 || page2.Messages[0].ID != "e3" || page2.NextCursor != "" {
		t.Errorf("page 2: %d rows, cursor %q; want e3 and no cursor", len(page2.Messages), page2.NextCursor)
	}
	if got, _ := lastCall(t, f, "Email/query").Args["position"].(float64); got != 2 {
		t.Errorf("page 2 position %v, want 2", got)
	}

	if _, err := p.Search(ctx, mail.Query{Raw: "other", Cursor: page.NextCursor}); !errors.Is(err, mail.ErrCursorMismatch) {
		t.Errorf("cursor of another query: %v, want ErrCursorMismatch", err)
	}

	store := inboxStore()
	store.noTotal = true
	np, _ := newTestProvider(t, store, nil)
	full, err := np.Search(ctx, mail.Query{Limit: 3})
	if err != nil {
		t.Fatalf("Search no total: %v", err)
	}
	if full.NextCursor == "" {
		t.Error("no total and a full page: want a cursor")
	}
	short, err := np.Search(ctx, mail.Query{Limit: 5})
	if err != nil {
		t.Fatalf("Search no total short: %v", err)
	}
	if short.NextCursor != "" {
		t.Error("no total and a short page: want no cursor")
	}
}

// TestJMAP_SearchDefaultsToInbox checks that a search with no folder
// runs in INBOX only, as the tool description says, and does not run
// over every mailbox. The id-only search does the same.
//
// arch: DS8.2, DS8.4
func TestJMAP_SearchDefaultsToInbox(t *testing.T) {
	for _, idsOnly := range []bool{false, true} {
		p, f := newTestProvider(t, testStore(), nil)
		page, err := p.Search(context.Background(), mail.Query{IDsOnly: idsOnly})
		if err != nil {
			t.Fatalf("Search (ids only %v): %v", idsOnly, err)
		}
		filter, _ := lastCall(t, f, "Email/query").Args["filter"].(map[string]any)
		if filter["inMailbox"] != boxInbox {
			t.Errorf("ids only %v: filter %v, want inMailbox %s", idsOnly, filter, boxInbox)
		}
		var ids []string
		for _, m := range page.Messages {
			ids = append(ids, m.ID)
		}
		if !slices.Equal(ids, []string{"e1", "e3"}) {
			t.Errorf("ids only %v: rows %q, want e1 e3 and not e2 of Projects/Work", idsOnly, ids)
		}
	}
}

// TestJMAP_SearchFolderAndCache checks the folder of a search and the
// mailbox cache of 10 minutes: the folder path gives inMailbox, a
// second search inside 10 minutes sends no Mailbox/get, a later one
// does, and an unknown name fails after one more Mailbox/get.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_SearchFolderAndCache(t *testing.T) {
	p, f := newTestProvider(t, testStore(), nil)
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return now }
	ctx := context.Background()
	boxGets := func() int {
		n := 0
		for _, c := range methodCalls(f) {
			if c.Name == "Mailbox/get" {
				n++
			}
		}
		return n
	}

	page, err := p.Search(ctx, mail.Query{Folder: "Projects/Work"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 1 || page.Messages[0].ID != "e2" {
		t.Errorf("rows %+v, want e2", page.Messages)
	}
	filter, _ := lastCall(t, f, "Email/query").Args["filter"].(map[string]any)
	if filter["inMailbox"] != boxWork {
		t.Errorf("filter %v, want inMailbox %s", filter, boxWork)
	}
	if _, err := p.Search(ctx, mail.Query{Folder: "inbox"}); err != nil {
		t.Fatalf("Search inbox: %v", err)
	}
	if got := boxGets(); got != 1 {
		t.Errorf("Mailbox/get %d times in 10 minutes, want 1", got)
	}
	now = now.Add(11 * time.Minute)
	if _, err := p.Search(ctx, mail.Query{Folder: "Archive"}); err != nil {
		t.Fatalf("Search Archive: %v", err)
	}
	if got := boxGets(); got != 2 {
		t.Errorf("Mailbox/get %d times after 11 minutes, want 2", got)
	}
	_, err = p.Search(ctx, mail.Query{Folder: "Nope"})
	if err == nil || !strings.Contains(err.Error(), `no folder "Nope"`) {
		t.Errorf("unknown folder: %v", err)
	}
	if got := boxGets(); got != 3 {
		t.Errorf("Mailbox/get %d times after a miss, want 3", got)
	}
}

// TestJMAP_ThreadRowsOldestFirst checks the Thread row of DS8.2: one
// batch gets the threadId and the Thread through a back-reference, and
// the rows come oldest first, as Search rows.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_ThreadRowsOldestFirst(t *testing.T) {
	store := testStore()
	store.emails[0]["threadId"] = "T1"
	store.emails[2]["threadId"] = "T1"
	store.threads = map[string][]string{"T1": {"e3", "e1"}}
	p, f := newTestProvider(t, store, nil)

	tr, err := p.Thread(context.Background(), "e1")
	if err != nil {
		t.Fatalf("Thread: %v", err)
	}
	if len(tr.Messages) != 2 || tr.Messages[0].ID != "e3" || tr.Messages[1].ID != "e1" {
		t.Fatalf("thread rows %+v, want e3 then e1", tr.Messages)
	}
	if tr.Messages[1].Subject != "Subject e1" || !tr.Messages[1].Flags.Seen {
		t.Errorf("row %+v", tr.Messages[1])
	}
	tg := lastCall(t, f, "Thread/get")
	if ref, _ := tg.Args["#ids"].(map[string]any); ref["path"] != "/list/*/threadId" {
		t.Errorf("Thread/get #ids %v", ref)
	}
	if _, err := p.Thread(context.Background(), "nope"); !errors.Is(err, errNoMessage) {
		t.Errorf("unknown id: %v", err)
	}
}

// TestJMAP_RawAndAttachmentDownload checks the Raw and Attachment rows
// of DS8.2: both get a blob through Download, an attachment by its
// partId or its file name (C19), and an unknown ref fails.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_RawAndAttachmentDownload(t *testing.T) {
	store := testStore()
	store.emails[0]["blobId"] = "blob-e1"
	store.emails[0]["attachments"] = []any{
		map[string]any{"partId": "3", "blobId": "blob-pdf", "name": "report.pdf", "type": "application/pdf", "size": 4},
	}
	f := newFakeJMAP(t, fakeOpts{store: store, blobs: map[string][]byte{
		"blob-e1":  []byte("From: ann@example.test\r\n\r\nhi\r\n"),
		"blob-pdf": []byte("%PDF"),
	}})
	p := NewProvider(config.Account{Alias: "home", Provider: "jmap"}, f.client(nil, false), nil)
	ctx := context.Background()

	raw, err := p.Raw(ctx, "e1")
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if string(raw) != "From: ann@example.test\r\n\r\nhi\r\n" {
		t.Errorf("raw %q", raw)
	}
	for _, ref := range []string{"3", "report.pdf"} {
		rc, info, err := p.Attachment(ctx, "e1", ref)
		if err != nil {
			t.Fatalf("Attachment %q: %v", ref, err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		if string(b) != "%PDF" || info.Filename != "report.pdf" || info.ContentType != "application/pdf" || info.Size != 4 {
			t.Errorf("attachment %q: %q %+v", ref, b, info)
		}
	}
	if _, _, err := p.Attachment(ctx, "e1", "9"); err == nil {
		t.Error("unknown ref: no error")
	}

	big := testStore()
	big.emails[0]["blobId"] = "blob-e1"
	big.emails[0]["size"] = MaxBlobBody + 1
	bp, _ := newTestProvider(t, big, nil)
	if _, err := bp.Raw(ctx, "e1"); err == nil || !strings.Contains(err.Error(), "larger than the limit") {
		t.Errorf("Raw above the cap: %v", err)
	}
}

// TestJMAP_ProviderReportsAuthError checks that a refused login of
// the server reaches onAuth (DS78.3, DRV.10), and that an id that is
// not a JMAP Id is refused before a request.
//
// arch: DS8.2, DS8.2b, DS8.7, IS78.5
func TestJMAP_ProviderReportsAuthError(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{store: testStore(), wantAuth: "Bearer right"})
	var got []error
	p := NewProvider(config.Account{Alias: "home"}, f.client(BearerAuth("wrong"), false), func(err error) { got = append(got, err) })

	_, err := p.Folders(context.Background())
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("Folders: %v, want *AuthError", err)
	}
	if len(got) != 1 || !errors.As(got[0], &ae) {
		t.Errorf("onAuth got %v, want the one *AuthError", got)
	}

	before := len(f.requests())
	if _, err := p.Read(context.Background(), "../x", mail.ReadOpts{}); !errors.Is(err, mail.ErrInvalidID) {
		t.Errorf("bad id: %v, want ErrInvalidID", err)
	}
	if len(f.requests()) != before {
		t.Error("a bad id sent a request")
	}
}

// emailGets gives the number of Email/get calls that the fake got.
func emailGets(f *fakeJMAP) int {
	n := 0
	for _, c := range methodCalls(f) {
		if c.Name == "Email/get" {
			n++
		}
	}
	return n
}

// TestJMAP_ReadHeadersOnDemand checks the headers on demand of Read:
// each name of ReadOpts.Headers adds one header:<Name>:asRaw:all
// property to the one Email/get of the read, a name repeated in
// another case is asked for and returned once under its first
// spelling, each instance gives one unfolded and trimmed entry, a name
// with no instance has no key, and a key that the server gives in
// another case still counts. A read with no names asks for the DS8.2
// properties only and gives nil. A name that is not a field name is
// refused before any call.
//
// arch: DS9.1, DS9.2, DS9.4
func TestJMAP_ReadHeadersOnDemand(t *testing.T) {
	h := plainEmail("h1", "Body", false)
	h["header:List-Unsubscribe:asRaw:all"] = []any{" <https://list.example.test/u?x=1>,\r\n <mailto:u@list.example.test>"}
	h["header:List-Unsubscribe-Post:asRaw:all"] = []any{" List-Unsubscribe=One-Click"}
	h["header:X-Two:asRaw:all"] = []any{" first", " second "}
	h["header:X-None:asRaw:all"] = []any{}
	h["HEADER:X-CASE:ASRAW:ALL"] = []any{" upper"}
	store := &fakeStore{mailboxes: testMailboxes(), emails: []map[string]any{h}}
	p, f := newTestProvider(t, store, nil)
	ctx := context.Background()

	asked := []string{"List-Unsubscribe", "list-unsubscribe", "List-Unsubscribe-Post", "X-Two", "X-None", "X-Missing", "X-Case"}
	m, err := p.Read(ctx, "h1", mail.ReadOpts{Headers: asked})
	if err != nil {
		t.Fatalf("Read with headers: %v", err)
	}
	if n := emailGets(f); n != 1 {
		t.Errorf("Email/get calls %d, want 1: the headers ride on the read", n)
	}
	want := map[string][]string{
		"List-Unsubscribe":      {"<https://list.example.test/u?x=1>, <mailto:u@list.example.test>"},
		"List-Unsubscribe-Post": {"List-Unsubscribe=One-Click"},
		"X-Two":                 {"first", "second"},
		"X-Case":                {"upper"},
	}
	if len(m.Headers) != len(want) {
		t.Errorf("Headers %q, want %q", m.Headers, want)
	}
	for k, v := range want {
		if !slices.Equal(m.Headers[k], v) {
			t.Errorf("Headers[%q] = %q, want %q", k, m.Headers[k], v)
		}
	}
	props := strs(lastCall(t, f, "Email/get").Args["properties"])
	for _, n := range []string{"List-Unsubscribe", "List-Unsubscribe-Post", "X-Two", "X-None", "X-Missing", "X-Case"} {
		if c := slices.Index(props, "header:"+n+":asRaw:all"); c < 0 {
			t.Errorf("properties %q lack the property of %s", props, n)
		}
	}
	if slices.Contains(props, "header:list-unsubscribe:asRaw:all") {
		t.Errorf("properties %q ask for the repeated name twice", props)
	}
	if !slices.Equal(props[:len(readProperties)], readProperties) {
		t.Errorf("properties %q do not start with readProperties", props)
	}
	if m.Body != "Body" {
		t.Errorf("Body %q: the headers changed the read", m.Body)
	}

	plain, err := p.Read(ctx, "h1", mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Read with no headers: %v", err)
	}
	if plain.Headers != nil {
		t.Errorf("Headers %q, want nil with no names", plain.Headers)
	}
	if props := strs(lastCall(t, f, "Email/get").Args["properties"]); !slices.Equal(props, readProperties) {
		t.Errorf("properties %q, want readProperties only", props)
	}
	if n := emailGets(f); n != 2 {
		t.Errorf("Email/get calls %d, want 2 after two reads", n)
	}

	for _, bad := range []string{"", "Bad:Name", "Bad Name", "X-Line\r\nInjected"} {
		if _, err := p.Read(ctx, "h1", mail.ReadOpts{Headers: []string{"List-Unsubscribe", bad}}); err == nil {
			t.Errorf("header name %q: no error", bad)
		}
	}
	if n := emailGets(f); n != 2 {
		t.Errorf("Email/get calls %d, want 2: a bad name sends nothing", n)
	}
}

// TestJMAP_ReadHeadersShortForm checks a server that gives the header
// properties without the asRaw form, as Stalwart does: asRaw is the
// default form of RFC 8621 §4.1.3, so the server answers
// header:<Name>:all to a request for header:<Name>:asRaw:all. The
// headers on demand and the Authentication-Results block still arrive.
//
// arch: DS9.2, DS8.2
func TestJMAP_ReadHeadersShortForm(t *testing.T) {
	h := plainEmail("h1", "Body", false)
	h["header:List-Unsubscribe:all"] = []any{" <https://list.example.test/u>"}
	h["header:list-unsubscribe-post:all"] = []any{" List-Unsubscribe=One-Click"}
	h["header:Authentication-Results:all"] = []any{" mx.example.test; dkim=pass"}
	store := &fakeStore{mailboxes: testMailboxes(), emails: []map[string]any{h}}
	p, _ := newTestProvider(t, store, nil)

	m, err := p.Read(context.Background(), "h1", mail.ReadOpts{Headers: []string{"List-Unsubscribe", "List-Unsubscribe-Post"}})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	want := map[string][]string{
		"List-Unsubscribe":      {"<https://list.example.test/u>"},
		"List-Unsubscribe-Post": {"List-Unsubscribe=One-Click"},
	}
	if len(m.Headers) != len(want) {
		t.Errorf("Headers %q, want %q", m.Headers, want)
	}
	for k, v := range want {
		if !slices.Equal(m.Headers[k], v) {
			t.Errorf("Headers[%q] = %q, want %q", k, m.Headers[k], v)
		}
	}
	if want := "Authentication-Results: mx.example.test; dkim=pass\r\n"; m.AuthResults != want {
		t.Errorf("AuthResults %q, want %q", m.AuthResults, want)
	}
}

// TestJMAP_SearchIDsOnly checks the ids-only search: the batch holds
// Email/query only and no Email/get, each row carries its ID only, the
// page is never Partial (every JMAP term runs on the server), the
// cursor pages as for a full page, and a cursor of a full page stays
// valid for an ids-only page. The search has no folder, so it runs in
// INBOX.
//
// arch: DS9.1, DS9.2, DS9.4
func TestJMAP_SearchIDsOnly(t *testing.T) {
	p, f := newTestProvider(t, inboxStore(), nil)
	ctx := context.Background()

	q := mail.Query{Raw: "is:unread", Limit: 2, IDsOnly: true}
	page, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search ids only: %v", err)
	}
	if n := emailGets(f); n != 0 {
		t.Errorf("Email/get calls %d, want 0", n)
	}
	reqs := f.apiRequests()
	if last := reqs[len(reqs)-1].MethodCalls; len(last) != 1 || last[0].Name != "Email/query" {
		t.Fatalf("last batch %v, want Email/query alone", last)
	}
	var ids []string
	for _, m := range page.Messages {
		ids = append(ids, m.ID)
		if !reflect.DeepEqual(m, mail.Message{ID: m.ID}) {
			t.Errorf("row %+v, want the ID only", m)
		}
	}
	if !slices.Equal(ids, []string{"e1", "e2"}) {
		t.Errorf("ids %q, want the query order e1 e2", ids)
	}
	if page.Partial || page.NextCursor == "" {
		t.Fatalf("page Partial %v cursor %q, want exact and a cursor", page.Partial, page.NextCursor)
	}

	q.Cursor = page.NextCursor
	page2, err := p.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search ids only page 2: %v", err)
	}
	if len(page2.Messages) != 1 || page2.Messages[0].ID != "e3" || page2.NextCursor != "" || page2.Partial {
		t.Errorf("page 2 %+v, want e3, no cursor, not Partial", page2)
	}
	if got, _ := lastCall(t, f, "Email/query").Args["position"].(float64); got != 2 {
		t.Errorf("page 2 position %v, want 2", got)
	}
	if n := emailGets(f); n != 0 {
		t.Errorf("Email/get calls %d after page 2, want 0", n)
	}

	full, err := p.Search(ctx, mail.Query{Folder: "Inbox", Limit: 1})
	if err != nil {
		t.Fatalf("Search full: %v", err)
	}
	if n := emailGets(f); n != 1 {
		t.Errorf("Email/get calls %d after a full search, want 1", n)
	}
	rest, err := p.Search(ctx, mail.Query{Folder: "Inbox", Limit: 1, IDsOnly: true, Cursor: full.NextCursor})
	if err != nil {
		t.Fatalf("Search ids only with the cursor of a full page: %v", err)
	}
	if len(rest.Messages) != 1 || rest.Messages[0].ID != "e2" {
		t.Errorf("rows %+v, want e2 after e1 in the inbox", rest.Messages)
	}
	if n := emailGets(f); n != 1 {
		t.Errorf("Email/get calls %d, want still 1", n)
	}
}
