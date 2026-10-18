// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Gmail drafts and the send against fakeGmail (DS7.4,
// DS7.5): the send-as check before a draft is stored and before it is
// sent, the send-as cache of 10 minutes, the message id as the id of a
// draft, the draft search of SendDraft and the replace of a draft.

package gmail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
	mbmime "github.com/amsys/mailbag-mcp/internal/mime"
)

// uploadPrefix is the path of uploadURL on the fake.
const uploadPrefix = "/upload/gmail/v1/users/me/"

// draftFake is a Gmail mailbox with drafts on fakeGmail. It answers
// settings/sendAs from the fixture, drafts.list in pages of pageSize,
// drafts.create, drafts.update, drafts.send, and messages.get with
// format=minimal, metadata (From only) and raw. A stored draft keeps
// its source, so Raw on the draft's message id gives it back.
type draftFake struct {
	mu       sync.Mutex
	pageSize int
	drafts   []draftEntry // in the order of drafts.list
	next     int          // the number of the next new message id
	threads  map[string]string
	sendCode int // the status of drafts.send; 0 gives 200
}

// draftEntry is one stored draft.
type draftEntry struct {
	draftID, msgID, threadID string
	raw                      []byte
}

func newDraftFake() *draftFake {
	return &draftFake{pageSize: 2, threads: map[string]string{"orig1": "thr1"}}
}

// add stores a draft with the source raw and gives its message id.
func (d *draftFake) add(draftID, msgID, raw string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drafts = append(d.drafts, draftEntry{draftID: draftID, msgID: msgID, raw: []byte(raw)})
}

// newMsgID gives a new message id. The caller holds d.mu.
func (d *draftFake) newMsgID() string {
	d.next++
	return "msgnew" + string(rune('0'+d.next)) //nolint:gosec // G115: d.next is a small test counter
}

// jsonStep gives a 200 answer with the JSON of v.
func jsonStep(v any) step {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return step{status: 200, body: string(b)}
}

// notFound is the 404 answer of a Google API.
func notFound() step {
	return step{status: 404, body: googleError(404, "NOT_FOUND", "notFound", "", "Requested entity was not found.")}
}

// route answers one request. A stored upload keeps its meta threadId
// and its source in d.drafts.
func (d *draftFake) route(t *testing.T) func(r *http.Request) step {
	return func(r *http.Request) step {
		d.mu.Lock()
		defer d.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == apiPrefix+"settings/sendAs":
			return step{status: 200, body: fixture(t, "sendAs.list.json")}
		case r.Method == http.MethodGet && r.URL.Path == apiPrefix+"drafts":
			start := 0
			if tok := r.URL.Query().Get("pageToken"); tok != "" {
				start = int(tok[len(tok)-1] - '0')
			}
			type ref struct {
				ID      string            `json:"id"`
				Message map[string]string `json:"message"`
			}
			page := map[string]any{}
			var list []ref
			for i := start; i < len(d.drafts) && i < start+d.pageSize; i++ {
				list = append(list, ref{ID: d.drafts[i].draftID, Message: map[string]string{"id": d.drafts[i].msgID}})
			}
			page["drafts"] = list
			if start+d.pageSize < len(d.drafts) {
				page["nextPageToken"] = "page" + string(rune('0'+start+d.pageSize)) //nolint:gosec // G115: the test has only a few drafts
			}
			return jsonStep(page)
		case r.Method == http.MethodPost && r.URL.Path == uploadPrefix+"drafts",
			r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, uploadPrefix+"drafts/"):
			meta, raw := readUpload(t, r)
			e := draftEntry{msgID: d.newMsgID(), threadID: meta.Message.ThreadID, raw: raw}
			if r.Method == http.MethodPost {
				e.draftID = "r-" + e.msgID
				d.drafts = append(d.drafts, e)
			} else {
				id := strings.TrimPrefix(r.URL.Path, uploadPrefix+"drafts/")
				found := false
				for i := range d.drafts {
					if d.drafts[i].draftID == id {
						e.draftID = id
						d.drafts[i] = e
						found = true
					}
				}
				if !found || meta.ID != id {
					return notFound()
				}
			}
			return jsonStep(map[string]any{"id": e.draftID, "message": map[string]string{"id": e.msgID, "threadId": e.threadID}})
		case r.Method == http.MethodPost && r.URL.Path == apiPrefix+"drafts/send":
			if d.sendCode != 0 {
				return step{status: d.sendCode, body: googleError(d.sendCode, "UNAVAILABLE", "backendError", "", "Backend Error")}
			}
			return jsonStep(map[string]any{"id": "sent9", "threadId": "thr9", "labelIds": []string{"SENT"}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, apiPrefix+"messages/"):
			id := strings.TrimPrefix(r.URL.Path, apiPrefix+"messages/")
			if tid, ok := d.threads[id]; ok && r.URL.Query().Get("format") == "minimal" {
				return jsonStep(map[string]string{"id": id, "threadId": tid})
			}
			for _, e := range d.drafts {
				if e.msgID != id {
					continue
				}
				switch r.URL.Query().Get("format") {
				case "raw":
					return jsonStep(map[string]string{"id": id, "raw": base64.URLEncoding.EncodeToString(e.raw)})
				case "metadata":
					return jsonStep(map[string]any{"id": id, "payload": map[string]any{
						"headers": []map[string]string{{"name": "From", "value": headerOf(e.raw, "From")}},
					}})
				}
			}
		}
		return notFound()
	}
}

// readUpload reads the multipart/related body of drafts.create or
// drafts.update: the JSON meta and the message/rfc822 part.
func readUpload(t *testing.T, r *http.Request) (draftMeta, []byte) {
	t.Helper()
	var meta draftMeta
	if got := r.URL.Query().Get("uploadType"); got != "multipart" {
		t.Errorf("upload uploadType = %q, want multipart", got)
		return meta, nil
	}
	mt, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/related" {
		t.Errorf("upload Content-Type = %q, want multipart/related", r.Header.Get("Content-Type"))
		return meta, nil
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	var raw []byte
	for i := 0; ; i++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("upload part %d: %v", i, err)
			return meta, nil
		}
		b, _ := io.ReadAll(part)
		switch i {
		case 0:
			if err := json.Unmarshal(b, &meta); err != nil {
				t.Errorf("upload meta %q: %v", b, err)
			}
		case 1:
			if ct := part.Header.Get("Content-Type"); ct != "message/rfc822" {
				t.Errorf("upload part 2 Content-Type = %q, want message/rfc822", ct)
			}
			raw = b
		}
	}
	return meta, raw
}

// headerOf gives the first header name of an RFC 822 source, unfolded.
func headerOf(raw []byte, name string) string {
	head, _, _ := strings.Cut(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n\n")
	head = strings.ReplaceAll(head, "\n ", " ")
	for _, line := range strings.Split(head, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(k, name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// count gives the number of requests with the method and the path.
func count(f *fakeGmail, method, path string) int {
	n := 0
	for _, r := range f.requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

// outgoing is a plain message of the draft tests (IS7.1).
func outgoing(from string) *mail.Outgoing {
	return &mail.Outgoing{From: from, To: []string{"bob@example.com"}, Subject: "Plans", Text: "See you at 5."}
}

// TestGmail_FromNotVerified holds IS7.4 and E6: a From that is not a
// verified send-as address (a pending alias, a stranger) is refused
// before the draft is built and stored, and before drafts.send runs.
// The error lists the allowed addresses: the primary and the accepted
// alias, never the pending one. A verified address passes in any case.
//
// arch: DS7.4, DS7.5, DS78.8, IS7.3, IS7.4, G14
func TestGmail_FromNotVerified(t *testing.T) {
	ctx := context.Background()
	for _, from := range []string{"pending@example.com", "Eve <eve@example.net>"} {
		t.Run("save "+from, func(t *testing.T) {
			d := newDraftFake()
			f := newFakeGmailRoutes(t, d.route(t))
			p, _ := f.provider(nil)
			_, err := p.SaveDraft(ctx, outgoing(from), "")
			if err == nil {
				t.Fatal("SaveDraft with an unverified From gave no error")
			}
			if !strings.Contains(err.Error(), "allowed addresses are: me@example.com, ok@example.com") ||
				strings.Contains(err.Error(), "allowed addresses are: me@example.com, ok@example.com, pending") {
				t.Fatalf("error = %q, want the list of the primary and the accepted alias only", err)
			}
			for _, r := range f.requests() {
				if r.Path != apiPrefix+"settings/sendAs" {
					t.Fatalf("SaveDraft called %s %s after a refused From", r.Method, r.Path)
				}
			}
		})
	}

	t.Run("send", func(t *testing.T) {
		d := newDraftFake()
		d.add("r-1", "msgpend", "From: pending@example.com\r\nTo: bob@example.com\r\nSubject: x\r\n\r\nhi\r\n")
		f := newFakeGmailRoutes(t, d.route(t))
		p, _ := f.provider(nil)
		_, err := p.SendDraft(ctx, "msgpend")
		if err == nil || !strings.Contains(err.Error(), `"pending@example.com" is not a verified send-as address`) {
			t.Fatalf("SendDraft of a draft from a pending alias: err = %v", err)
		}
		if n := count(f, http.MethodPost, apiPrefix+"drafts/send"); n != 0 {
			t.Fatalf("drafts.send ran %d times after a refused From", n)
		}
	})

	t.Run("verified in any case", func(t *testing.T) {
		d := newDraftFake()
		f := newFakeGmailRoutes(t, d.route(t))
		p, _ := f.provider(nil)
		for _, from := range []string{"", "OK@Example.com", "Me <me@example.com>"} {
			if _, err := p.SaveDraft(ctx, outgoing(from), ""); err != nil {
				t.Fatalf("SaveDraft from %q: %v", from, err)
			}
		}
	})
}

// TestGmail_SendAsCached10Min holds DS7.5: the send-as list lives 10
// minutes on the wall clock, also for a second provider with the same
// State. After 10 minutes, or when the clock steps back, the next
// check calls settings/sendAs again. A miss in the cached list asks
// the server once more, so an alias verified a minute ago passes.
//
// arch: DS7.4, DS7.5, DS78.8, IS7.3, IS7.4, G14
func TestGmail_SendAsCached10Min(t *testing.T) {
	var mu sync.Mutex
	extra := ""
	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		if r.URL.Path != apiPrefix+"settings/sendAs" {
			return notFound()
		}
		mu.Lock()
		defer mu.Unlock()
		list := []map[string]any{{"sendAsEmail": "me@example.com", "isPrimary": true}}
		if extra != "" {
			list = append(list, map[string]any{"sendAsEmail": extra, "verificationStatus": "accepted"})
		}
		return jsonStep(map[string]any{"sendAs": list})
	})
	st := &State{}
	clock := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	p1, _ := f.provider(st)
	p2, _ := f.provider(st)
	p1.now, p2.now = now, now
	ctx := context.Background()
	calls := func() int { return count(f, http.MethodGet, apiPrefix+"settings/sendAs") }

	check := func(p *Provider, from string, wantCalls int) {
		t.Helper()
		if err := p.fromAllowed(ctx, from); err != nil {
			t.Fatalf("fromAllowed(%q): %v", from, err)
		}
		if got := calls(); got != wantCalls {
			t.Fatalf("settings/sendAs calls = %d, want %d", got, wantCalls)
		}
	}

	check(p1, "me@example.com", 1)
	clock = clock.Add(9*time.Minute + 59*time.Second)
	check(p2, "ME@example.com", 1) // the second provider shares the cache
	clock = clock.Add(time.Second)
	check(p1, "me@example.com", 2) // 10 minutes: the cache is old
	clock = clock.Add(-time.Minute)
	check(p2, "me@example.com", 3) // the clock stepped back: the age is not known

	// An alias verified after the cache was filled: one more call.
	mu.Lock()
	extra = "new@example.com"
	mu.Unlock()
	check(p1, "new@example.com", 4)
	check(p2, "new@example.com", 4)

	// A refused address asks again once, then fails.
	if err := p1.fromAllowed(ctx, "eve@example.net"); err == nil {
		t.Fatal("fromAllowed(eve@example.net) gave no error")
	}
	if got := calls(); got != 5 {
		t.Fatalf("settings/sendAs calls after a refused address = %d, want 5", got)
	}
}

// TestGmail_DraftIDIsMessageID holds DS7.4: SaveDraft stores the RFC
// 822 source with drafts.create (a multipart upload with the threadId
// meta) and gives the draft's message id, not the draft id, so Raw on
// that id gives the stored source back. A reply goes into the thread of
// the message it answers and carries no mailbag reply-id header, which
// drafts.send would put on the wire.
//
// arch: DS7.4, DS7.5, DS78.8, IS7.3, IS7.4, G14
func TestGmail_DraftIDIsMessageID(t *testing.T) {
	ctx := context.Background()
	d := newDraftFake()
	f := newFakeGmailRoutes(t, d.route(t))
	p, _ := f.provider(nil)

	id, err := p.SaveDraft(ctx, outgoing(""), "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	if id != "msgnew1" {
		t.Fatalf("SaveDraft id = %q, want the message id msgnew1 (draft id r-msgnew1)", id)
	}
	if n := count(f, http.MethodPost, uploadPrefix+"drafts"); n != 1 {
		t.Fatalf("drafts.create calls = %d, want 1", n)
	}
	raw, err := p.Raw(ctx, id)
	if err != nil {
		t.Fatalf("Raw(%s): %v", id, err)
	}
	if got := headerOf(raw, "From"); got != "<me@example.com>" && got != "me@example.com" {
		t.Fatalf("From of the draft = %q, want the account address", got)
	}
	if got := headerOf(raw, "Subject"); got != "Plans" {
		t.Fatalf("Subject of the draft = %q, want Plans", got)
	}
	d.mu.Lock()
	first := d.drafts[0]
	d.mu.Unlock()
	if first.threadID != "" {
		t.Fatalf("a new message got threadId %q, want none", first.threadID)
	}

	reply := outgoing("ok@example.com")
	reply.ReplyToID = "orig1"
	reply.InReplyTo = "<orig1@example.com>"
	reply.References = []string{"<orig1@example.com>"}
	id2, err := p.SaveDraft(ctx, reply, "")
	if err != nil {
		t.Fatalf("SaveDraft of a reply: %v", err)
	}
	d.mu.Lock()
	e := d.drafts[1]
	d.mu.Unlock()
	if id2 != e.msgID || e.threadID != "thr1" {
		t.Fatalf("reply draft: id %q threadId %q, want %q in thr1", id2, e.threadID, e.msgID)
	}
	if got := headerOf(e.raw, mbmime.ReplyIDHeader); got != "" {
		t.Fatalf("the reply draft carries %s: %q", mbmime.ReplyIDHeader, got)
	}
	if got := headerOf(e.raw, "In-Reply-To"); got != "<orig1@example.com>" {
		t.Fatalf("In-Reply-To = %q", got)
	}
}

// TestGmail_SendDraftFindsDraft holds DS7.4 and IS7.3: SendDraft reads
// drafts.list page by page to find the draft whose message id it got,
// checks its From, and sends it with drafts.send {"id": draftId}.
// SendResult.ID is the sent message id and Gmail files it in SENT. A
// message that is in no draft is refused with no send, and a 503 of
// drafts.send is not tried again.
//
// arch: DS7.4, DS7.5, DS78.8, IS7.3, IS7.4, G14
func TestGmail_SendDraftFindsDraft(t *testing.T) {
	ctx := context.Background()
	const src = "From: Me <ok@example.com>\r\nTo: bob@example.com\r\nSubject: x\r\n\r\nhi\r\n"
	d := newDraftFake()
	d.add("r-1", "msga", src)
	d.add("r-2", "msgb", src)
	d.add("r-3", "msgc", src)
	f := newFakeGmailRoutes(t, d.route(t))
	p, _ := f.provider(nil)

	res, err := p.SendDraft(ctx, "msgc")
	if err != nil {
		t.Fatalf("SendDraft: %v", err)
	}
	if want := (mail.SendResult{ID: "sent9", Sent: true, SavedToSent: true}); res != want {
		t.Fatalf("SendDraft = %+v, want %+v", res, want)
	}
	var lists []string
	var sendBody []byte
	for _, r := range f.requests() {
		switch r.Path {
		case apiPrefix + "drafts":
			lists = append(lists, r.RawQuery)
		case apiPrefix + "drafts/send":
			sendBody = r.Body
		}
	}
	if len(lists) != 2 {
		t.Fatalf("drafts.list calls = %q, want 2 pages", lists)
	}
	q, _ := url.ParseQuery(lists[1])
	if q.Get("pageToken") != "page2" || q.Get("maxResults") != "500" {
		t.Fatalf("second drafts.list query = %q, want pageToken=page2 and maxResults=500", lists[1])
	}
	var body map[string]string
	if err := json.Unmarshal(sendBody, &body); err != nil || len(body) != 1 || body["id"] != "r-3" {
		t.Fatalf("drafts.send body = %s, want {\"id\":\"r-3\"}", sendBody)
	}

	if _, err := p.SendDraft(ctx, "msgnone"); err == nil || !strings.Contains(err.Error(), "message msgnone is not a draft") {
		t.Fatalf("SendDraft of a message that is no draft: err = %v", err)
	}
	if n := count(f, http.MethodPost, apiPrefix+"drafts/send"); n != 1 {
		t.Fatalf("drafts.send calls = %d, want 1", n)
	}

	d.mu.Lock()
	d.sendCode = http.StatusServiceUnavailable
	d.mu.Unlock()
	if _, err := p.SendDraft(ctx, "msga"); err == nil {
		t.Fatal("SendDraft with a 503 of drafts.send gave no error")
	}
	if n := count(f, http.MethodPost, apiPrefix+"drafts/send"); n != 2 {
		t.Fatalf("drafts.send calls after one 503 = %d, want 2 (no second try, IS7.3)", n)
	}
}

// TestGmail_DraftReplace holds DS7.4: a replace finds the draft id of
// the old draft by its message id and calls drafts.update on it with
// the draft id in the meta. The answer gives the draft a new message
// id, and SaveDraft gives that one. A replace of a message that is no
// draft stores nothing.
//
// arch: DS7.4, DS7.5, DS78.8, IS7.3, IS7.4, G14
func TestGmail_DraftReplace(t *testing.T) {
	ctx := context.Background()
	d := newDraftFake()
	d.add("r-1", "msga", "From: me@example.com\r\n\r\nold\r\n")
	d.add("r-2", "msgb", "From: me@example.com\r\n\r\nold\r\n")
	d.add("r-3", "msgc", "From: me@example.com\r\n\r\nold\r\n")
	f := newFakeGmailRoutes(t, d.route(t))
	p, _ := f.provider(nil)

	m := outgoing("")
	m.Subject = "New plans"
	id, err := p.SaveDraft(ctx, m, "msgc")
	if err != nil {
		t.Fatalf("SaveDraft replace: %v", err)
	}
	d.mu.Lock()
	got := d.drafts
	d.mu.Unlock()
	if len(got) != 3 || got[2].draftID != "r-3" || got[2].msgID != id || id == "msgc" {
		t.Fatalf("after the replace: id %q, drafts %+v; want r-3 with a new message id", id, got)
	}
	if s := headerOf(got[2].raw, "Subject"); s != "New plans" {
		t.Fatalf("Subject of the replaced draft = %q", s)
	}
	if n := count(f, http.MethodPut, uploadPrefix+"drafts/r-3"); n != 1 {
		t.Fatalf("drafts.update calls on r-3 = %d, want 1", n)
	}
	if n := count(f, http.MethodPost, uploadPrefix+"drafts"); n != 0 {
		t.Fatalf("drafts.create calls in a replace = %d, want 0", n)
	}
	raw, err := p.Raw(ctx, id)
	if err != nil || headerOf(raw, "Subject") != "New plans" {
		t.Fatalf("Raw(%s) after the replace: %q, %v", id, raw, err)
	}

	if _, err := p.SaveDraft(ctx, m, "msgnone"); err == nil || !strings.Contains(err.Error(), "message msgnone is not a draft") {
		t.Fatalf("replace of a message that is no draft: err = %v", err)
	}
	for _, r := range f.requests() {
		if strings.HasPrefix(r.Path, uploadPrefix) && r.Path != uploadPrefix+"drafts/r-3" {
			t.Fatalf("a refused replace called %s %s", r.Method, r.Path)
		}
	}
}
