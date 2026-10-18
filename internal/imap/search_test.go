// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// subjects gives the subject of every row of a page, newest first.
func subjects(p mail.Page) []string {
	out := make([]string, 0, len(p.Messages))
	for _, m := range p.Messages {
		out = append(out, m.Subject)
	}
	return out
}

// TestIMAP_UsesUIDCommands checks trap C1: a sequence number points
// at the wrong message as soon as a mailbox loses one. The provider
// sends UID commands only.
//
// The fixture removes two messages, so the sequence numbers and the
// UIDs no longer match. A provider that used sequence numbers would
// give the ids 3, 2, 1; the right answer is 5, 4, 2.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestIMAP_UsesUIDCommands(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "one", flags: []imap.Flag{imap.FlagDeleted}}, // uid 1
		msgSpec{subject: "two"}, // uid 2
		msgSpec{subject: "three", flags: []imap.Flag{imap.FlagDeleted}}, // uid 3
		msgSpec{subject: "four"}, // uid 4
		msgSpec{subject: "five"}, // uid 5
	)
	f.expunge("INBOX")
	f.warm()

	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	want := []string{"five", "four", "two"}
	if got := subjects(page); !equalStrings(got, want) {
		t.Fatalf("Search gave %v, want %v (newest UID first)", got, want)
	}
	wantIDs := []string{"5", "4", "2"}
	for i, m := range page.Messages {
		_, uid, folder, err := mail.ParseIMAPID(m.ID)
		if err != nil {
			t.Fatalf("ParseIMAPID(%q): %v", m.ID, err)
		}
		if fmt.Sprint(uid) != wantIDs[i] {
			t.Fatalf("row %d has uid %d, want %s: a sequence number was used as a UID (C1)", i, uid, wantIDs[i])
		}
		if folder != "INBOX" {
			t.Fatalf("row %d has folder %q, want INBOX", i, folder)
		}
	}

	for _, c := range f.commands() {
		for _, verb := range []string{"FETCH ", "SEARCH ", "STORE ", "COPY ", "MOVE "} {
			if strings.HasPrefix(c, verb) {
				t.Fatalf("the wire holds the command %q: C1 allows UID commands only", c)
			}
		}
	}
	if f.countCommands("UID SEARCH") == 0 || f.countCommands("UID FETCH") == 0 {
		t.Fatalf("want a UID SEARCH and a UID FETCH, commands were %v", f.commands())
	}
}

// TestIMAP_ReadsUseExamine checks trap C3: SELECT can change server
// state, so every read opens the folder with EXAMINE.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestIMAP_ReadsUseExamine(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "hello"})
	f.warm()

	if _, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX"}); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if f.countCommands("EXAMINE") != 1 {
		t.Fatalf("want one EXAMINE, commands were %v", f.commands())
	}
	if f.countCommands("SELECT") != 0 {
		t.Fatalf("a read sent SELECT; C3 allows EXAMINE only. commands: %v", f.commands())
	}
}

// TestIMAP_NonASCIIFallback checks trap C7: most servers match a
// header against its raw RFC 2047 text, so a query with a non-ASCII
// word finds nothing. The provider then scans the envelopes of the
// newest messages itself and matches there, where go-imap has already
// decoded the subject.
//
// The fixture server answers a non-ASCII search with an empty result,
// which is the real behaviour; the memory server on its own decodes
// the header first and would hide the trap.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestIMAP_NonASCIIFallback(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{rawSearch: true})
	f.add(
		msgSpec{subject: "=?utf-8?B?R3LDvMOfZSBhdXMgUHJhZw==?=", body: "ahoj"}, // "Grüße aus Prag"
		msgSpec{subject: "plain ascii subject", body: "hello"},
	)
	f.warm()

	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "subject:Grüße"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := subjects(page); !equalStrings(got, []string{"Grüße aus Prag"}) {
		t.Fatalf("Search gave %v, want the one message with the non-ASCII subject (C7)", got)
	}
}

// TestIMAP_ASCIIEmptyNoFallback is the other half of C7: the client
// scan is expensive, so it runs for a non-ASCII query only. An ASCII
// query that the server answers with nothing gives an empty page and
// no scan.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestIMAP_ASCIIEmptyNoFallback(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "quarterly report", body: "hello"})
	f.warm()

	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "subject:zzzznotthere"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 0 {
		t.Fatalf("Search gave %v, want no rows", subjects(page))
	}
	if n := f.countCommands("UID FETCH"); n != 0 {
		t.Fatalf("an ASCII query with no result ran %d UID FETCH commands; the envelope scan must stay off (C7)", n)
	}
	if n := f.countCommands("UID SEARCH"); n != 1 {
		t.Fatalf("want exactly one UID SEARCH, got %d: %v", n, f.commands())
	}
}

// TestIMAP_SincePrecise checks trap C8: SINCE has a precision of one
// day, so the server also sends messages from earlier in that same
// day. The exact time runs in the client, on INTERNALDATE.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestIMAP_SincePrecise(t *testing.T) {
	t.Parallel()
	day := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "morning", date: day.Add(9 * time.Hour)},
		msgSpec{subject: "evening", date: day.Add(20 * time.Hour)},
	)
	f.warm()

	q := mail.Query{Folder: "INBOX", Since: day.Add(12 * time.Hour)}
	page, err := f.prov.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := subjects(page); !equalStrings(got, []string{"evening"}) {
		t.Fatalf("Search gave %v, want only the message after the given time (C8)", got)
	}
	// The server saw the day only; the morning message came back and
	// the client dropped it.
	if f.countCommands("UID SEARCH") == 0 {
		t.Fatalf("want a UID SEARCH, commands were %v", f.commands())
	}
}

// TestSearch_LargeResultBounded checks trap C28: a search can give
// 100 000 UIDs. The provider keeps the highest few and fetches data
// for those only.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestSearch_LargeResultBounded(t *testing.T) {
	t.Parallel()
	const total = 300
	const limit = 20
	f := newFixture(t, fixtureOpts{})
	specs := make([]msgSpec, 0, total)
	for i := 0; i < total; i++ {
		specs = append(specs, msgSpec{subject: fmt.Sprintf("msg %03d", i), body: "hello"})
	}
	f.add(specs...)
	f.warm()

	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Limit: limit})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != limit {
		t.Fatalf("Search gave %d rows, want %d", len(page.Messages), limit)
	}
	if page.Messages[0].Subject != "msg 299" {
		t.Fatalf("the first row is %q, want the newest message", page.Messages[0].Subject)
	}
	sizes := f.fetchSetSizes()
	if len(sizes) == 0 {
		t.Fatalf("no UID FETCH on the wire: %v", f.commands())
	}
	for i, n := range sizes {
		if n > limit {
			t.Fatalf("UID FETCH %d asked for %d messages, want at most %d: the whole result was fetched (C28)", i, n, limit)
		}
	}
	if page.NextCursor == "" {
		t.Fatalf("want a next cursor after a full page")
	}
}

// TestSearch_CursorWalksDown checks the paging rule of §3.9: the
// cursor holds the lowest UID of the page and the next page takes
// UIDs below it. A cursor built for a different query is refused.
//
// arch: T4.3, §3.9, §3.10
func TestSearch_CursorWalksDown(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	for i := 0; i < 6; i++ {
		f.add(msgSpec{subject: fmt.Sprintf("m%d", i), body: "hello"})
	}
	q := mail.Query{Folder: "INBOX", Limit: 2}
	first, err := f.prov.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search page 1: %v", err)
	}
	if got := subjects(first); !equalStrings(got, []string{"m5", "m4"}) {
		t.Fatalf("page 1 = %v, want m5 m4", got)
	}
	q.Cursor = first.NextCursor
	second, err := f.prov.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search page 2: %v", err)
	}
	if got := subjects(second); !equalStrings(got, []string{"m3", "m2"}) {
		t.Fatalf("page 2 = %v, want m3 m2", got)
	}

	other := mail.Query{Folder: "INBOX", Limit: 2, Raw: "subject:m1"}
	other.Cursor = first.NextCursor
	if _, err := f.prov.Search(context.Background(), other); err == nil {
		t.Fatalf("a cursor from a different query was accepted")
	}
}

// TestSearch_PlainSearchTruncatedHasNoNote checks DRV.12: with no
// client-side filter the search window is the caller's own Limit
// (:43), not the candidateLimit window a filter uses. A page cut off
// at that plain Limit is the normal end of a page, not a hidden cut,
// so it must carry no Note.
//
// arch: DRV.12
func TestSearch_PlainSearchTruncatedHasNoNote(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	for i := 0; i < 6; i++ {
		f.add(msgSpec{subject: fmt.Sprintf("m%d", i), body: "hello"})
	}
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Limit: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 2 {
		t.Fatalf("Search gave %d rows, want 2", len(page.Messages))
	}
	if page.Note != "" {
		t.Fatalf("page.Note = %q, want no note: a plain search truncated at Limit is not a hidden cut (DRV.12)", page.Note)
	}
}

// TestSearch_ClientFilterShortPageHasCursor checks DRV.12: a
// client-side filter (has:attachment) only examines the newest
// candidateLimit UIDs. Before this fix, NextCursor was set only when
// the page came back full; a page with few matches inside that
// window, and unexamined messages below it, got no cursor at all, so
// the caller had no way to reach the rest.
//
// arch: DRV.12
func TestSearch_ClientFilterShortPageHasCursor(t *testing.T) {
	t.Parallel()
	withFile := func(subject string) string {
		return "From: Ann <ann@example.test>\r\n" +
			"To: Bob <bob@example.test>\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n" +
			"--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsee the file\r\n" +
			"--b1\r\nContent-Type: application/pdf\r\n" +
			"Content-Disposition: attachment; filename=\"report.pdf\"\r\n\r\n%PDF-1.4\r\n" +
			"--b1--\r\n"
	}

	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "old plain", body: "x"})                  // uid 1
	f.add(msgSpec{raw: withFile("old-match"), subject: "old-match"}) // uid 2, below the window
	for i := 0; i < 3; i++ {
		f.add(msgSpec{subject: fmt.Sprintf("old filler %d", i), body: "x"}) // uid 3-5
	}
	fillers := make([]msgSpec, 0, candidateLimit-1)
	for i := 0; i < candidateLimit-1; i++ {
		fillers = append(fillers, msgSpec{subject: fmt.Sprintf("filler %d", i), body: "x"})
	}
	f.add(fillers...)                                                // uid 6..504, inside the window
	f.add(msgSpec{raw: withFile("new-match"), subject: "new-match"}) // uid 505, inside the window

	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "has:attachment"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := subjects(page); !equalStrings(got, []string{"new-match"}) {
		t.Fatalf("page 1 = %v, want only new-match", got)
	}
	if page.NextCursor == "" {
		t.Fatalf("want a NextCursor: the window was full and older UIDs were never examined (DRV.12)")
	}
	if page.Note == "" {
		t.Fatalf("want a Note: the candidate window was cut off below the client-side filter (DRV.12)")
	}
	if !page.Partial {
		t.Fatalf("want Partial: the candidate window was cut, so the match set can be incomplete (S9-GAP1)")
	}

	q := mail.Query{Folder: "INBOX", Raw: "has:attachment", Cursor: page.NextCursor}
	page2, err := f.prov.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search page 2: %v", err)
	}
	if got := subjects(page2); !equalStrings(got, []string{"old-match"}) {
		t.Fatalf("page 2 = %v, want old-match: the cursor did not reach the UIDs below the window", got)
	}
}

// dialWrapped builds a DialFunc that dials addr and runs every
// connection through wrap before login, so a test can intercept one
// specific command (a tagged NO, or a dead socket) without touching
// the real server.
func dialWrapped(addr string, wrap func(net.Conn) net.Conn) DialFunc {
	return func(context.Context, string) (*imapclient.Client, error) {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		c := imapclient.New(wrap(raw), nil)
		if err := c.Login(fixtureUser, fixturePass).Wait(); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}
}

// previewTrip wraps a connection so the one BODY.PEEK[] partial fetch
// addPreviews sends gets answered the way trip answers it (a real NO,
// via noAnswerConn, or a dead socket, via tripConn).
func previewTrip(wrap func(net.Conn, func([]byte) bool) net.Conn) func(net.Conn) net.Conn {
	return func(c net.Conn) net.Conn {
		return wrap(c, func(b []byte) bool { return bytes.Contains(b, []byte("BODY.PEEK[")) })
	}
}

// TestSearch_PreviewSkipNote holds DR1G.5 and DR1G.18.3: a local
// error on the one preview fetch leaves the row itself in the page,
// with no preview, and the count goes on Page.Note. The error is a
// real NO from the server (noAnswerConn), never a dead socket, so the
// search itself must not fail (DRV.10 stays the other case).
//
// arch: DR1G.5, DR1G.18
func TestSearch_PreviewSkipNote(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "m1", body: "hello there, this is the body"})

	pool := NewPool(dialWrapped(f.addr, previewTrip(func(c net.Conn, trip func([]byte) bool) net.Conn {
		return &noAnswerConn{Conn: c, trip: trip}
	})), nil)
	t.Cleanup(pool.CloseAll)
	prov := New("acct", pool)

	page, err := prov.Search(context.Background(), mail.Query{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("Search: %v (a local preview-fetch error must not fail the search)", err)
	}
	if len(page.Messages) != 1 {
		t.Fatalf("Messages = %d, want 1", len(page.Messages))
	}
	const want = "previews are missing for 1 message(s)"
	if page.Note != want {
		t.Fatalf("Note = %q, want %q", page.Note, want)
	}
	if page.Messages[0].Preview != "" {
		t.Errorf("Preview = %q, want empty: the fetch for it was refused", page.Messages[0].Preview)
	}
}

// TestSearch_PreviewSkipJoinsNote holds DR1G.5: when the page already
// carries a Note (DRV.12's truncation note, from a client-side filter
// whose candidate window is cut off), a preview-skip note is appended
// to it with "; ", not written over it.
//
// arch: DR1G.5, DR1G.18
func TestSearch_PreviewSkipJoinsNote(t *testing.T) {
	t.Parallel()
	withFile := func(subject string) string {
		return "From: Ann <ann@example.test>\r\n" +
			"To: Bob <bob@example.test>\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n" +
			"--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsee the file\r\n" +
			"--b1\r\nContent-Type: application/pdf\r\n" +
			"Content-Disposition: attachment; filename=\"report.pdf\"\r\n\r\n%PDF-1.4\r\n" +
			"--b1--\r\n"
	}

	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "old plain", body: "x"})
	f.add(msgSpec{raw: withFile("old-match"), subject: "old-match"})
	for i := 0; i < 3; i++ {
		f.add(msgSpec{subject: fmt.Sprintf("old filler %d", i), body: "x"})
	}
	fillers := make([]msgSpec, 0, candidateLimit-1)
	for i := 0; i < candidateLimit-1; i++ {
		fillers = append(fillers, msgSpec{subject: fmt.Sprintf("filler %d", i), body: "x"})
	}
	f.add(fillers...)
	f.add(msgSpec{raw: withFile("new-match"), subject: "new-match"})

	pool := NewPool(dialWrapped(f.addr, previewTrip(func(c net.Conn, trip func([]byte) bool) net.Conn {
		return &noAnswerConn{Conn: c, trip: trip}
	})), nil)
	t.Cleanup(pool.CloseAll)
	prov := New("acct", pool)

	page, err := prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "has:attachment"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := subjects(page); !equalStrings(got, []string{"new-match"}) {
		t.Fatalf("page = %v, want only new-match", got)
	}
	const (
		truncNote   = "the newest 500 matching messages were checked"
		missingNote = "previews are missing for 1 message(s)"
	)
	if !strings.Contains(page.Note, truncNote) {
		t.Errorf("Note = %q, want it to hold the truncation note too", page.Note)
	}
	if !strings.Contains(page.Note, missingNote) {
		t.Errorf("Note = %q, want it to hold %q", page.Note, missingNote)
	}
	if !strings.Contains(page.Note, "; ") {
		t.Errorf("Note = %q, want the two notes joined with \"; \" (DR1G.5)", page.Note)
	}
}

// TestSearch_PreviewBrokenConnIsError holds the connBroken half of
// DR1G.5: a dead socket during the preview fetch fails the search
// outright. It must never turn into a note, the way a real NO does.
//
// arch: DR1G.5, DR1G.18
func TestSearch_PreviewBrokenConnIsError(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "m1", body: "hello"})

	pool := NewPool(dialWrapped(f.addr, previewTrip(func(c net.Conn, trip func([]byte) bool) net.Conn {
		return &tripConn{Conn: c, trip: trip}
	})), nil)
	t.Cleanup(pool.CloseAll)
	prov := New("acct", pool)

	if _, err := prov.Search(context.Background(), mail.Query{Folder: "INBOX"}); err == nil {
		t.Fatal("Search gave no error for a dead socket during the preview fetch, want one")
	}
}

// TestSearch_CursorUIDValidityChanged checks DRV.12: a cursor carries
// the folder's UIDVALIDITY. If the folder was recreated since the
// first page, an old UID can now name a different message, so paging
// on with a stale UIDVALIDITY must fail instead of silently showing
// the wrong rows.
//
// arch: DRV.12
func TestSearch_CursorUIDValidityChanged(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	for i := 0; i < 6; i++ {
		f.add(msgSpec{subject: fmt.Sprintf("m%d", i), body: "hello"})
	}
	q := mail.Query{Folder: "INBOX", Limit: 2}
	first, err := f.prov.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search page 1: %v", err)
	}
	if first.NextCursor == "" {
		t.Fatalf("want a NextCursor after a full page")
	}
	cur, err := mail.DecodeCursor(first.NextCursor)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	cur.UIDValidity++
	q.Cursor = mail.EncodeCursor(cur)

	if _, err := f.prov.Search(context.Background(), q); err == nil {
		t.Fatalf("a cursor with the wrong UIDVALIDITY was accepted")
	} else if !strings.Contains(err.Error(), "the folder changed since the first page; search again") {
		t.Fatalf("error = %v, want it to name the folder change", err)
	}
}

// TestSearch_NonASCIIToNotScanned checks the other half of DRV.12:
// canScan stands in for the subject and the sender only, so a to: or
// cc: word must not trigger it. envelopeHolds never reads the To
// address, so letting it through would give a wrong answer either
// way; the search must reach the server instead.
//
// arch: DRV.12
func TestSearch_NonASCIIToNotScanned(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{rawSearch: true})
	f.add(msgSpec{subject: "hello", to: "Grüße <gruesse@example.test>", body: "hi"})

	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "to:Grüße"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 0 {
		t.Fatalf("Search gave %v, want no rows: canScan must refuse to: (DRV.12)", subjects(page))
	}
	if n := f.countCommands("UID FETCH"); n != 0 {
		t.Fatalf("an envelope scan ran for a to: term: %d UID FETCH commands, commands were %v", n, f.commands())
	}
}

// TestSearch_UnknownFolderRefused checks §3.8: the folder inside a
// message id, and the folder argument of a search, are text the
// caller sent. The provider checks the name against the folder list
// the server gives now, before any EXAMINE.
//
// arch: T4.3, §3.8, §3.10
func TestSearch_UnknownFolderRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "hello"})
	f.warm()

	_, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX\" (\\Deleted)"})
	if err == nil {
		t.Fatalf("a folder that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "no folder") {
		t.Fatalf("error = %v, want it to name the missing folder", err)
	}
	if f.countCommands("EXAMINE") != 0 {
		t.Fatalf("EXAMINE ran on an unchecked folder name: %v", f.commands())
	}
}

// TestSearch_BadTermFails checks the decision of this stage: the
// query grammar has no error channel, so a term the grammar cannot
// read fails the call with a clear message. Without it a bad date or
// a bare OR reaches the server unchecked and the caller gets an empty
// page with no reason.
//
// A span or a size past the int64 bound is refused, not wrapped
// (R16-L12).
//
// arch: T4.3, §3.9, R16-L12
func TestSearch_BadTermFails(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "hello"})

	cases := []struct {
		query string
		want  string
	}{
		{"from:a@x.test OR from:b@x.test", "not an operator"},
		{"before:notadate", "not a date"},
		{"after:2026-13-45", "not a date"},
		{"larger:xyz", "not a size"},
		{"smaller:5X", "not a size"},
		{"newer_than:7x", "not a time span"},
		{"newer_than:300y", "not a time span"},
		{"larger:10000000000G", "not a size"},
		{"is:sparkling", "is not known"},
		{"has:unicorn", "is not known"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			_, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: c.query})
			if err == nil {
				t.Fatalf("query %q was accepted, want an error", c.query)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not hold %q", err, c.want)
			}
		})
	}
}

// TestSearch_GoodTermsRun is the other half of the check above: every
// term the grammar names still works.
//
// arch: T4.3, §3.9
func TestSearch_GoodTermsRun(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "invoice 42", from: "Ann <ann@example.test>", body: "please pay"},
		msgSpec{subject: "lunch", from: "Bo <bo@example.test>", body: "at one", flags: []imap.Flag{imap.FlagSeen}},
	)
	cases := []struct {
		query string
		want  []string
	}{
		{"", []string{"lunch", "invoice 42"}},
		{"*", []string{"lunch", "invoice 42"}},
		{"from:ann", []string{"invoice 42"}},
		{"subject:invoice", []string{"invoice 42"}},
		{"body:lunch", nil},
		{"is:unread", []string{"invoice 42"}},
		{"is:read", []string{"lunch"}},
		{"-from:ann", []string{"lunch"}},
		{"before:2030-01-01", []string{"lunch", "invoice 42"}},
		{"after:2000-01-01", []string{"lunch", "invoice 42"}},
		{"larger:10", []string{"lunch", "invoice 42"}},
		{"smaller:10", nil},
		{"newer_than:1y", []string{"lunch", "invoice 42"}},
		{"older_than:1d", []string{"lunch", "invoice 42"}},
		{"newer_than:1d", nil},
		{"in:INBOX", []string{"lunch", "invoice 42"}},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: c.query})
			if err != nil {
				t.Fatalf("query %q: %v", c.query, err)
			}
			if got := subjects(page); !equalStrings(got, c.want) {
				t.Fatalf("query %q gave %v, want %v", c.query, got, c.want)
			}
		})
	}
}

// TestSearch_HasAttachment checks the client-side filter of §3.10:
// the attachment list comes off BODYSTRUCTURE, with no download.
//
// arch: T4.3, §3.9, §3.10
func TestSearch_HasAttachment(t *testing.T) {
	t.Parallel()
	withFile := "From: Ann <ann@example.test>\r\n" +
		"To: Bob <bob@example.test>\r\n" +
		"Subject: with file\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n" +
		"--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsee the file\r\n" +
		"--b1\r\nContent-Type: application/pdf\r\n" +
		"Content-Disposition: attachment; filename=\"report.pdf\"\r\n\r\n%PDF-1.4\r\n" +
		"--b1--\r\n"

	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "plain only", body: "no file here"},
		msgSpec{raw: withFile, subject: "with file"},
	)
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "has:attachment"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := subjects(page); !equalStrings(got, []string{"with file"}) {
		t.Fatalf("Search gave %v, want only the message with an attachment", got)
	}
}

// TestSearch_NegatedHasAttachment checks DRV.5: termCriteria returned
// nil for "has" before t.Not was read, so "-has:attachment" searched
// with no filter at all and every message came back. The negated form
// must keep only messages with no attachment.
//
// arch: DRV.5
func TestSearch_NegatedHasAttachment(t *testing.T) {
	t.Parallel()
	withFile := "From: Ann <ann@example.test>\r\n" +
		"To: Bob <bob@example.test>\r\n" +
		"Subject: with file\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n" +
		"--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsee the file\r\n" +
		"--b1\r\nContent-Type: application/pdf\r\n" +
		"Content-Disposition: attachment; filename=\"report.pdf\"\r\n\r\n%PDF-1.4\r\n" +
		"--b1--\r\n"

	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "plain only", body: "no file here"},
		msgSpec{raw: withFile, subject: "with file"},
	)
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "-has:attachment"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := subjects(page); !equalStrings(got, []string{"plain only"}) {
		t.Fatalf("Search gave %v, want only the message with no attachment", got)
	}
}

// TestSearch_NegatedInRefused checks DRV.5: the loop skipped t.Not for
// "in" too, so "-in:Spam" searched Spam with no error, the opposite of
// what a person typing "-in:Spam" means. It must be refused, not
// turned into the positive.
//
// arch: DRV.5
func TestSearch_NegatedInRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "hello"})

	_, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "-in:Spam"})
	if err == nil {
		t.Fatalf("-in:Spam was accepted, want an error")
	}
	want := "imap: search: -in: is not supported; name the folder to search with in: or the folder field"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

// TestSearch_InAndFolderConflict checks DRV.5: today in: silently
// wins over the folder field with no word to the caller. An in: term
// that names a different folder than the one the call asked for must
// be refused instead of picking one of the two in silence.
//
// arch: DRV.5
func TestSearch_InAndFolderConflict(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{subject: "hello"})

	_, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX", Raw: "in:Archive"})
	if err == nil {
		t.Fatalf("in:Archive with folder INBOX was accepted, want an error")
	}
	if !strings.Contains(err.Error(), "in:") || !strings.Contains(err.Error(), "Archive") || !strings.Contains(err.Error(), "INBOX") {
		t.Fatalf("error %q does not name both the in: value and the folder", err)
	}
	if f.countCommands("EXAMINE") != 0 {
		t.Fatalf("EXAMINE ran despite the in:/folder conflict: %v", f.commands())
	}
}

// TestSearch_PreviewWindows checks the preview rule of §3.10 and the
// window decision of this stage. A text/plain part keeps the 2048
// byte window. An HTML-only message gets a larger one, because an
// HTML newsletter starts with a <style> head that is often longer
// than 2048 bytes on its own; a 2048-byte window decodes to nothing.
//
// arch: T4.3, §3.10, C2, C20
func TestSearch_PreviewWindows(t *testing.T) {
	t.Parallel()
	head := strings.Repeat("/* padding to push the body past 2048 bytes */\n", 60)
	htmlBody := "<html><head><style>" + head + "</style></head><body><h1>Big Sale This Weekend!</h1></body></html>"
	if len(htmlBody) < int(previewPlainBytes) {
		t.Fatalf("the test data is %d bytes, it must be longer than the plain window", len(htmlBody))
	}

	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "plain", body: "The quick brown fox."},
		msgSpec{subject: "html only", ctype: "text/html; charset=utf-8", body: htmlBody},
	)
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	byName := map[string]string{}
	for _, m := range page.Messages {
		byName[m.Subject] = m.Preview
	}
	if got := byName["plain"]; got != "The quick brown fox." {
		t.Fatalf("plain preview = %q, want the body text", got)
	}
	if got := byName["html only"]; !strings.Contains(got, "Big Sale This Weekend!") {
		t.Fatalf("html preview = %q, want the words after the <style> head", got)
	}

	// C2: a preview never sets \Seen, so it always peeks.
	for _, c := range f.commands() {
		if strings.Contains(c, "BODY[") && !strings.Contains(c, "BODY.PEEK[") {
			t.Fatalf("the command %q fetches a body without PEEK (C2)", c)
		}
	}
}

// TestSearch_PreviewWindowCapped checks that no part fetch asks for
// more than maxPartBytes. Mail has no size limit of its own, and the
// decoders in internal/mime hold a whole part in memory, so the cap
// belongs at the fetch.
//
// arch: T4.3, §3.10
func TestSearch_PreviewWindowCapped(t *testing.T) {
	t.Parallel()
	item := partialFetch([]int{1}, maxPartBytes*4)
	if item.Partial == nil || item.Partial.Size != maxPartBytes {
		t.Fatalf("partialFetch did not cap the window: %+v", item.Partial)
	}
	if !item.Peek {
		t.Fatalf("partialFetch must peek (C2)")
	}
	if previewHTMLBytes > maxPartBytes || previewPlainBytes > maxPartBytes {
		t.Fatalf("a preview window is larger than the part cap")
	}
}

// TestSearch_RowFields checks what one row carries: the date is
// INTERNALDATE and not the Date header (C22), and the Message-ID
// keeps its angle brackets so a reply can use it (§3.14).
//
// arch: T4.3, §3.10, C22
func TestSearch_RowFields(t *testing.T) {
	t.Parallel()
	internal := time.Date(2026, 9, 12, 8, 30, 0, 0, time.UTC)
	raw := "From: Ann <ann@example.test>\r\n" +
		"To: Bob <bob@example.test>\r\n" +
		"Cc: Cy <cy@example.test>\r\n" +
		"Reply-To: Desk <desk@example.test>\r\n" +
		"Subject: real subject\r\n" +
		"Date: Tue, 1 Jan 1980 00:00:00 +0000\r\n" +
		"Message-ID: <abc@example.test>\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\nbody text\r\n"

	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{raw: raw, date: internal, flags: []imap.Flag{imap.FlagFlagged}})

	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 1 {
		t.Fatalf("want one row, got %d", len(page.Messages))
	}
	m := page.Messages[0]
	if !m.Date.Equal(internal) {
		t.Fatalf("Date = %v, want INTERNALDATE %v (C22)", m.Date, internal)
	}
	if m.MessageID != "<abc@example.test>" {
		t.Fatalf("MessageID = %q, want it with angle brackets", m.MessageID)
	}
	if m.From.Address != "ann@example.test" || m.From.Name != "Ann" {
		t.Fatalf("From = %+v", m.From)
	}
	if len(m.Cc) != 1 || m.Cc[0].Address != "cy@example.test" {
		t.Fatalf("Cc = %+v", m.Cc)
	}
	if !m.Flags.Flagged || m.Flags.Seen {
		t.Fatalf("Flags = %+v, want flagged and not seen", m.Flags)
	}
	if m.Size == 0 {
		t.Fatalf("Size = 0, want the RFC822 size")
	}
	// The envelope already carries Reply-To, so a row that left it
	// empty would cost S5 an extra fetch for a header it has (§3.14).
	if len(m.ReplyTo) != 1 || m.ReplyTo[0].Address != "desk@example.test" {
		t.Fatalf("ReplyTo = %+v, want the Reply-To header from the envelope", m.ReplyTo)
	}
}

// TestSearch_FallbackKeepsOtherTerms checks the other half of the C7
// fallback: the envelope scan stands in for the text match only. The
// flags, the dates, the size and the cursor bound must still reach
// the server, or a query like "subject:Grüße is:unread" would give
// back read messages that the query excludes.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestSearch_FallbackKeepsOtherTerms(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{rawSearch: true})
	// Both subjects decode to "Grüße aus Prag"; one is already read.
	f.add(
		msgSpec{subject: "=?utf-8?B?R3LDvMOfZSBhdXMgUHJhZw==?=", body: "old", flags: []imap.Flag{imap.FlagSeen}},
		msgSpec{subject: "=?utf-8?B?R3LDvMOfZSBhdXMgUHJhZw==?=", body: "new"},
	)
	f.warm()

	q := mail.Query{Folder: "INBOX", Raw: "subject:Grüße is:unread"}
	page, err := f.prov.Search(context.Background(), q)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(page.Messages) != 1 {
		t.Fatalf("Search gave %d rows, want only the unread one; the fallback dropped is:unread (C7)", len(page.Messages))
	}
	if page.Messages[0].Flags.Seen {
		t.Fatalf("Search gave a read message for is:unread (C7)")
	}
}

// TestSearch_PreviewPerMessageEncoding checks that a preview decodes
// with the charset and the transfer encoding of its own part. Two
// rows can share a part path and a window and still need different
// decoding, so a shared fetch must not share the part description.
//
// arch: T4.3, §3.10, C20, C21
func TestSearch_PreviewPerMessageEncoding(t *testing.T) {
	t.Parallel()
	const b64Text = "Base64 body here."
	b64 := "From: Ann <ann@example.test>\r\n" +
		"To: Bob <bob@example.test>\r\n" +
		"Subject: encoded\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte(b64Text)) + "\r\n"

	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "plain", body: "Plain body here."},
		msgSpec{raw: b64},
	)
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	byName := map[string]string{}
	for _, m := range page.Messages {
		byName[m.Subject] = m.Preview
	}
	if got := byName["plain"]; got != "Plain body here." {
		t.Fatalf("plain preview = %q, want the 7bit body text", got)
	}
	if got := byName["encoded"]; got != b64Text {
		t.Fatalf("base64 preview = %q, want %q", got, b64Text)
	}
}

// equalStrings compares two string slices, treating nil and empty as
// the same.
func equalStrings(a, b []string) bool {
	return slices.Equal(a, b)
}

// TestPreview_NamedPartNotPreview checks that the preview skips a
// text part that has a file name but no Content-Disposition. Read
// already counts that part as an attachment, so the preview must not
// show it as the body (one part rule).
//
// arch: DRV.3
func TestPreview_NamedPartNotPreview(t *testing.T) {
	t.Parallel()
	named := &imap.BodyStructureSinglePart{
		Type: "text", Subtype: "plain",
		Params: map[string]string{"name": "notes.txt"},
	}
	body := &imap.BodyStructureSinglePart{
		Type: "text", Subtype: "plain",
		Params: map[string]string{"charset": "utf-8"},
	}
	bs := &imap.BodyStructureMultiPart{
		Subtype:  "mixed",
		Children: []imap.BodyStructure{named, body},
	}
	p, ok := pickPreviewPart(bs)
	if !ok {
		t.Fatal("pickPreviewPart found no part")
	}
	if len(p.path) != 1 || p.path[0] != 2 {
		t.Fatalf("preview part path = %v, want [2]: the named part is an attachment", p.path)
	}
	if hasAttachment(bs) != true {
		t.Fatal("hasAttachment = false, want true for the named part")
	}
}

// TestIMAP_SearchIDsOnlyNoFetch checks DS9.4 and S9-GAP1: a search
// with Query.IDsOnly sends UID SEARCH and no FETCH, and its rows carry
// the id alone. A cursor of a full first page stays valid for the
// ids-only pages, because IDsOnly is not part of the query hash. A
// query with a client-side term gives full rows and sets Partial, so
// bulk never acts on a match set the client cut.
//
// arch: DS9.1, DS9.2, DS9.4
func TestIMAP_SearchIDsOnlyNoFetch(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	for i := 0; i < 6; i++ {
		f.add(msgSpec{subject: fmt.Sprintf("m%d", i), body: "hello"}) // uid 1..6
	}
	f.warm()
	ctx := context.Background()

	q := mail.Query{Folder: "INBOX", Limit: 2}
	first, err := f.prov.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search page 1: %v", err)
	}
	if got := subjects(first); !equalStrings(got, []string{"m5", "m4"}) || first.NextCursor == "" {
		t.Fatalf("page 1 = %v cursor %q, want m5 m4 and a cursor", got, first.NextCursor)
	}
	v, _, _, err := mail.ParseIMAPID(first.Messages[0].ID)
	if err != nil {
		t.Fatalf("ParseIMAPID: %v", err)
	}

	f.wire.Reset()
	q.IDsOnly = true
	q.Cursor = first.NextCursor
	second, err := f.prov.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search ids-only page 2 with the cursor of a full page: %v", err)
	}
	wantIDs := []string{mail.FormatIMAPID(v, 4, "INBOX"), mail.FormatIMAPID(v, 3, "INBOX")}
	var gotIDs []string
	for _, m := range second.Messages {
		gotIDs = append(gotIDs, m.ID)
		if m.Subject != "" || m.From.Address != "" || !m.Date.IsZero() {
			t.Fatalf("an ids-only row carries envelope data: %+v", m)
		}
	}
	if !equalStrings(gotIDs, wantIDs) {
		t.Fatalf("ids-only page 2 = %v, want %v", gotIDs, wantIDs)
	}
	if second.NextCursor == "" || second.Partial || second.Note != "" {
		t.Fatalf("page 2: cursor %q partial %v note %q, want a cursor, no Partial, no note", second.NextCursor, second.Partial, second.Note)
	}

	q.Cursor = second.NextCursor
	third, err := f.prov.Search(ctx, q)
	if err != nil {
		t.Fatalf("Search ids-only page 3: %v", err)
	}
	wantIDs = []string{mail.FormatIMAPID(v, 2, "INBOX"), mail.FormatIMAPID(v, 1, "INBOX")}
	gotIDs = nil
	for _, m := range third.Messages {
		gotIDs = append(gotIDs, m.ID)
	}
	if !equalStrings(gotIDs, wantIDs) || third.NextCursor != "" {
		t.Fatalf("ids-only page 3 = %v cursor %q, want %v and no cursor", gotIDs, third.NextCursor, wantIDs)
	}
	if n := f.countCommands("UID FETCH"); n != 0 {
		t.Fatalf("the ids-only pages sent %d UID FETCH commands, want none: %v", n, f.commands())
	}
	if f.countCommands("UID SEARCH") < 2 {
		t.Fatalf("want one UID SEARCH per ids-only page, commands were %v", f.commands())
	}

	t.Run("client-side term", func(t *testing.T) {
		g := newFixture(t, fixtureOpts{})
		g.add(msgSpec{subject: "plain", body: "x"}, msgSpec{raw: attachRaw()})
		g.warm()
		full, err := g.prov.Search(ctx, mail.Query{Folder: "INBOX", Raw: "has:attachment"})
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if full.Partial {
			t.Fatalf("a normal page that examined every candidate has Partial set (note %q)", full.Note)
		}
		g.wire.Reset()
		page, err := g.prov.Search(ctx, mail.Query{Folder: "INBOX", Raw: "has:attachment", IDsOnly: true})
		if err != nil {
			t.Fatalf("Search ids-only: %v", err)
		}
		if got := subjects(page); !equalStrings(got, []string{"the quarter report"}) {
			t.Fatalf("page = %v, want the full row of the message with a file", got)
		}
		if !page.Partial || !strings.Contains(page.Note, clientMatchNote) {
			t.Fatalf("partial %v note %q, want Partial and the client-match note (S9-GAP1)", page.Partial, page.Note)
		}
		if g.countCommands("UID FETCH") == 0 {
			t.Fatalf("has:attachment needs BODYSTRUCTURE, but no UID FETCH went out: %v", g.commands())
		}
	})
}

// TestBuildCriteria_SmallerThenFrom checks that a smaller: term keeps
// its limit when another term follows it. The go-imap And merge sets
// Smaller back to 0 when a later term has no Smaller, so the search
// matched messages of any size.
//
// arch: REVIEW-2026-10-12 H1
func TestBuildCriteria_SmallerThenFrom(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, q := range []string{
		"smaller:1M from:bob",
		"smaller:1M is:unread",
		"from:bob smaller:1M",
	} {
		crit, _, err := buildCriteria(mail.ParseQuery(q), time.Time{}, now)
		if err != nil {
			t.Fatalf("%q: buildCriteria: %v", q, err)
		}
		if crit.Smaller != 1048576 {
			t.Errorf("%q: Smaller = %d, want 1048576", q, crit.Smaller)
		}
	}
}
