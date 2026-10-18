// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the write side of drafts in the JMAP provider (DS8.2,
// DS8.2a, IS8.3): SaveDraft with Email/set create and blobs, the from
// check against the identities, and SendDraft with EmailSubmission/set
// and its onSuccessUpdateEmail patch. Each test runs against fakeJMAP
// with a fakeStore; no test reaches the network (IS78.1).

package jmap

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// The mailbox ids of the roles drafts and sent in draftStore.
const (
	boxDrafts = "mb-drafts"
	boxSent   = "mb-sent"
)

// draftEmail gives a stored draft with the id and the from address,
// in the mailbox with the role drafts.
func draftEmail(id, from string) map[string]any {
	e := email(id, []string{boxDrafts}, map[string]any{"$draft": true, "$seen": true}, "2026-10-10T10:00:00Z")
	e["from"] = []any{map[string]any{"name": "Me", "email": from}}
	return e
}

// draftStore gives the mailboxes of testStore with Drafts and Sent,
// two identities (one exact, one for a whole domain), the drafts d-me,
// d-alias and d-foreign, and the inbox message e1 that is not a draft.
func draftStore() *fakeStore {
	boxes := append(testMailboxes(),
		map[string]any{"id": boxDrafts, "name": "Drafts", "parentId": nil, "role": "drafts", "totalEmails": 3, "unreadEmails": 0},
		map[string]any{"id": boxSent, "name": "Sent", "parentId": nil, "role": "sent", "totalEmails": 0, "unreadEmails": 0},
	)
	return &fakeStore{
		mailboxes: boxes,
		identities: []map[string]any{
			{"id": "I1", "name": "Me", "email": "me@example.test"},
			{"id": "I2", "name": "Alias", "email": "*@alias.test"},
		},
		emails: []map[string]any{
			draftEmail("d-me", "me@example.test"),
			draftEmail("d-alias", "sales@alias.test"),
			draftEmail("d-foreign", "boss@other.test"),
			email("e1", []string{boxInbox}, map[string]any{"$seen": true}, "2026-10-09T10:00:00Z"),
		},
	}
}

// callsNamed gives the method calls with the name, in order.
func callsNamed(f *fakeJMAP, name string) []Invocation {
	var out []Invocation
	for _, c := range methodCalls(f) {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// uploads gives the upload requests that the fake got, in order.
func uploads(f *fakeJMAP) []fakeReq {
	var out []fakeReq
	for _, r := range f.requests() {
		if r.Method == http.MethodPost && strings.HasPrefix(r.Path, "/jmap/upload/") {
			out = append(out, r)
		}
	}
	return out
}

// createdDraft gives the "draft" object of the last Email/set create.
func createdDraft(t *testing.T, f *fakeJMAP) map[string]any {
	t.Helper()
	set := lastCall(t, f, "Email/set")
	create, _ := set.Args["create"].(map[string]any)
	obj, ok := create["draft"].(map[string]any)
	if !ok {
		t.Fatalf("Email/set has no create of \"draft\": %v", set.Args)
	}
	return obj
}

// TestJMAP_SubmissionIdentity checks IS8.3 and DS8.2a: SendDraft sends
// the identityId of the identity whose email is the from address of
// the draft (exact, else a "*@domain" identity), in a batch whose
// using has submission (F1). A from address that no identity has is
// refused before any EmailSubmission/set or Email/set, and the error
// lists the identities. A message without $draft is not sent. The
// identity list comes from the 10-minute cache; a miss asks the server
// once more, and an old cache asks again.
//
// arch: DS8.2, DS8.2a, IS8.3
func TestJMAP_SubmissionIdentity(t *testing.T) {
	store := draftStore()
	p, f := newTestProvider(t, store, nil)
	ctx := context.Background()
	clock := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	p.now = func() time.Time { return clock }

	if _, err := p.SendDraft(ctx, "d-me"); err != nil {
		t.Fatalf("SendDraft d-me: %v", err)
	}
	if _, err := p.SendDraft(ctx, "d-alias"); err != nil {
		t.Fatalf("SendDraft d-alias: %v", err)
	}
	subs := callsNamed(f, "EmailSubmission/set")
	if len(subs) != 2 {
		t.Fatalf("%d EmailSubmission/set calls, want 2", len(subs))
	}
	for i, want := range []struct{ identity, email string }{{"I1", "d-me"}, {"I2", "d-alias"}} {
		create, _ := subs[i].Args["create"].(map[string]any)
		send, _ := create["send"].(map[string]any)
		if send["identityId"] != want.identity || send["emailId"] != want.email {
			t.Errorf("submission %d = %v, want identityId %s and emailId %s", i, send, want.identity, want.email)
		}
	}
	for _, req := range f.apiRequests() {
		for _, c := range req.MethodCalls {
			if c.Name == "EmailSubmission/set" && !slices.Contains(req.Using, usingSubmission) {
				t.Errorf("the batch of EmailSubmission/set has using %v, want submission in it", req.Using)
			}
		}
	}
	if n := len(callsNamed(f, "Identity/get")); n != 1 {
		t.Errorf("%d Identity/get calls for two sends in the cache time, want 1", n)
	}

	before := len(callsNamed(f, "EmailSubmission/set"))
	_, err := p.SendDraft(ctx, "d-foreign")
	if err == nil {
		t.Fatal("SendDraft from boss@other.test: no error, want the from check to refuse it")
	}
	for _, want := range []string{"boss@other.test", "me@example.test", "*@alias.test"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s", err, want)
		}
	}
	if n := len(callsNamed(f, "EmailSubmission/set")); n != before {
		t.Errorf("a refused from still sent %d EmailSubmission/set calls", n-before)
	}
	if n := len(callsNamed(f, "Identity/get")); n != 2 {
		t.Errorf("%d Identity/get calls after a miss in the cache, want 2 (one more ask)", n)
	}

	if _, err := p.SendDraft(ctx, "e1"); err == nil || !strings.Contains(err.Error(), "not a draft") {
		t.Errorf("SendDraft of a message without $draft: err = %v, want \"not a draft\"", err)
	}
	if n := len(callsNamed(f, "EmailSubmission/set")); n != before {
		t.Errorf("a message without $draft was submitted")
	}

	sets := len(callsNamed(f, "Email/set"))
	_, err = p.SaveDraft(ctx, &mail.Outgoing{From: "Boss <boss@other.test>", To: []string{"ann@example.test"}, Subject: "x", Text: "y"}, "")
	if err == nil || !strings.Contains(err.Error(), "me@example.test") {
		t.Errorf("SaveDraft from boss@other.test: err = %v, want the from check with the identity list", err)
	}
	if n := len(callsNamed(f, "Email/set")); n != sets {
		t.Errorf("a refused from still sent Email/set")
	}

	clock = clock.Add(identityTTL)
	ids := len(callsNamed(f, "Identity/get"))
	if _, err := p.SaveDraft(ctx, &mail.Outgoing{To: []string{"ann@example.test"}, Subject: "s", Text: "t"}, ""); err != nil {
		t.Fatalf("SaveDraft from the account address: %v", err)
	}
	if n := len(callsNamed(f, "Identity/get")); n != ids+1 {
		t.Errorf("an identity cache of age identityTTL was used; Identity/get calls %d, want %d", n, ids+1)
	}
}

// TestJMAP_SentFiling checks F2: SendDraft gives EmailSubmission/set
// the onSuccessUpdateEmail patch that takes the email out of Drafts,
// puts it into Sent and drops $draft, and SendResult.ID is the email
// id with Sent and SavedToSent set. The fake applies the patch, so the
// stored email ends in Sent only. With no mailbox with the role sent,
// the patch only drops $draft, the email keeps its mailbox (IS8.2) and
// the result has a warning.
//
// arch: DS8.2, DS8.2a, IS8.3
func TestJMAP_SentFiling(t *testing.T) {
	store := draftStore()
	p, f := newTestProvider(t, store, nil)
	ctx := context.Background()

	res, err := p.SendDraft(ctx, "d-me")
	if err != nil {
		t.Fatalf("SendDraft: %v", err)
	}
	want := mail.SendResult{ID: "d-me", Sent: true, SavedToSent: true}
	if res != want {
		t.Errorf("SendResult = %+v, want %+v", res, want)
	}
	sub := lastCall(t, f, "EmailSubmission/set")
	wantPatch := map[string]any{"#send": map[string]any{
		"mailboxIds/" + boxDrafts: nil,
		"mailboxIds/" + boxSent:   true,
		"keywords/$draft":         nil,
	}}
	if got := sub.Args["onSuccessUpdateEmail"]; !reflect.DeepEqual(got, wantPatch) {
		t.Errorf("onSuccessUpdateEmail = %v, want %v", got, wantPatch)
	}
	e := store.email("d-me")
	if got := e["mailboxIds"]; !reflect.DeepEqual(got, map[string]any{boxSent: true}) {
		t.Errorf("mailboxIds after the send = %v, want Sent only", got)
	}
	if kw, _ := e["keywords"].(map[string]any); kw["$draft"] != nil || kw["$seen"] != true {
		t.Errorf("keywords after the send = %v, want $seen without $draft", kw)
	}

	// An account with no Sent mailbox.
	noSent := draftStore()
	noSent.mailboxes = slices.DeleteFunc(noSent.mailboxes, func(m map[string]any) bool { return m["role"] == "sent" })
	p2, f2 := newTestProvider(t, noSent, nil)
	res, err = p2.SendDraft(ctx, "d-me")
	if err != nil {
		t.Fatalf("SendDraft with no Sent mailbox: %v", err)
	}
	if res.ID != "d-me" || !res.Sent || res.SavedToSent || res.Warning == "" {
		t.Errorf("SendResult with no Sent mailbox = %+v, want sent, not saved to Sent, a warning", res)
	}
	sub = lastCall(t, f2, "EmailSubmission/set")
	wantPatch = map[string]any{"#send": map[string]any{"keywords/$draft": nil}}
	if got := sub.Args["onSuccessUpdateEmail"]; !reflect.DeepEqual(got, wantPatch) {
		t.Errorf("onSuccessUpdateEmail with no Sent mailbox = %v, want %v", got, wantPatch)
	}
	if got := noSent.email("d-me")["mailboxIds"]; !reflect.DeepEqual(got, map[string]any{boxDrafts: true}) {
		t.Errorf("mailboxIds with no Sent mailbox = %v, want Drafts kept", got)
	}
}

// TestJMAP_SaveDraftCreate checks the Email/set create of SaveDraft
// (DS8.2): the mailbox with the role drafts, $draft and $seen, the
// addresses parsed from their strings, the subject, the bare reply ids
// and the body values. A replace destroys the old draft in the same
// Email/set, and a replace of a message without $draft destroys
// nothing.
//
// arch: DS8.2, DS8.2a, IS8.3
func TestJMAP_SaveDraftCreate(t *testing.T) {
	store := draftStore()
	p, f := newTestProvider(t, store, nil)
	ctx := context.Background()

	m := &mail.Outgoing{
		From:       "me@example.test",
		To:         []string{"Ann <ann@example.test>"},
		Cc:         []string{"bob@example.test"},
		Bcc:        []string{"carl@example.test"},
		Subject:    "Plan",
		Text:       "plain text",
		HTML:       "<p>html</p>",
		InReplyTo:  "<a1@example.test>",
		References: []string{"<a0@example.test> <a1@example.test>"},
	}
	id, err := p.SaveDraft(ctx, m, "d-alias")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	if id != "D1" {
		t.Errorf("id = %q, want D1, the id of the create", id)
	}
	set := lastCall(t, f, "Email/set")
	if got := strs(set.Args["destroy"]); !reflect.DeepEqual(got, []string{"d-alias"}) {
		t.Errorf("destroy = %v, want [d-alias] in the same Email/set", got)
	}
	if store.email("d-alias") != nil {
		t.Error("the replaced draft is still in the store")
	}
	obj := createdDraft(t, f)
	checks := map[string]any{
		"mailboxIds": map[string]any{boxDrafts: true},
		"keywords":   map[string]any{"$draft": true, "$seen": true},
		"from":       []any{map[string]any{"name": "Me", "email": "me@example.test"}},
		"to":         []any{map[string]any{"name": "Ann", "email": "ann@example.test"}},
		"cc":         []any{map[string]any{"name": "", "email": "bob@example.test"}},
		"bcc":        []any{map[string]any{"name": "", "email": "carl@example.test"}},
		"subject":    "Plan",
		"inReplyTo":  []any{"a1@example.test"},
		"references": []any{"a0@example.test", "a1@example.test"},
		"textBody":   []any{map[string]any{"partId": "text", "type": "text/plain"}},
		"htmlBody":   []any{map[string]any{"partId": "html", "type": "text/html"}},
		"bodyValues": map[string]any{"text": map[string]any{"value": "plain text"}, "html": map[string]any{"value": "<p>html</p>"}},
	}
	for k, want := range checks {
		if got := obj[k]; !reflect.DeepEqual(got, want) {
			t.Errorf("create %s = %v, want %v", k, got, want)
		}
	}
	if _, ok := obj["attachments"]; ok {
		t.Error("a draft with no attachment has an attachments list")
	}

	sets := len(callsNamed(f, "Email/set"))
	if _, err := p.SaveDraft(ctx, &mail.Outgoing{Subject: "s", Text: "t"}, "e1"); err == nil || !strings.Contains(err.Error(), "not a draft") {
		t.Errorf("replace of a message without $draft: err = %v, want \"not a draft\"", err)
	}
	if n := len(callsNamed(f, "Email/set")); n != sets || store.email("e1") == nil {
		t.Error("a replace of a message without $draft sent Email/set or removed the message")
	}
}

// TestJMAP_AttachmentBlob checks F6: each attachment goes up as a blob
// with its media type as Content-Type before the Email/set, and the
// draft names it by blobId with the type, the base name of the path
// and the disposition attachment. A file that cannot be read stops
// SaveDraft before Email/set.
//
// arch: DS8.2, DS8.2a, IS8.3
func TestJMAP_AttachmentBlob(t *testing.T) {
	store := draftStore()
	p, f := newTestProvider(t, store, nil)
	ctx := context.Background()
	dir := t.TempDir()
	pdf := []byte("%PDF-1.7\nbody")
	path := filepath.Join(dir, "report.pdf")
	if err := os.WriteFile(path, pdf, 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := p.SaveDraft(ctx, &mail.Outgoing{To: []string{"ann@example.test"}, Subject: "s", Text: "t", Attachments: []string{path}}, "")
	if err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	ups := uploads(f)
	if len(ups) != 1 {
		t.Fatalf("%d uploads, want 1", len(ups))
	}
	if ups[0].ContentType != "application/pdf" || !bytes.Equal(ups[0].Body, pdf) {
		t.Errorf("upload: Content-Type %q, body %q; want application/pdf and the file", ups[0].ContentType, ups[0].Body)
	}
	upAt, setAt := -1, -1
	for i, r := range f.requests() {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.Path, "/jmap/upload/"):
			upAt = i
		case r.Method == http.MethodPost && strings.HasPrefix(r.Path, "/jmap/api") && strings.Contains(string(r.Body), `"Email/set"`):
			setAt = i
		}
	}
	if upAt < 0 || setAt < upAt {
		t.Errorf("upload at request %d, Email/set at %d; want the upload first", upAt, setAt)
	}
	wantAtt := []any{map[string]any{"blobId": "G1", "type": "application/pdf", "name": "report.pdf", "disposition": "attachment"}}
	if got := createdDraft(t, f)["attachments"]; !reflect.DeepEqual(got, wantAtt) {
		t.Errorf("attachments = %v, want %v", got, wantAtt)
	}
	if got := store.email(id)["attachments"]; got == nil {
		t.Error("the stored draft has no attachments")
	}

	sets := len(callsNamed(f, "Email/set"))
	_, err = p.SaveDraft(ctx, &mail.Outgoing{Subject: "s", Text: "t", Attachments: []string{filepath.Join(dir, "gone.pdf")}}, "")
	if err == nil {
		t.Fatal("SaveDraft with a missing file: no error")
	}
	if n := len(callsNamed(f, "Email/set")); n != sets {
		t.Error("a missing attachment still sent Email/set")
	}
}
