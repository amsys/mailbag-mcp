// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// fakeJMAP stands in for a JMAP server on httptest.NewTLSServer
// (DS8.7). It listens on a loopback port only, so no test reaches the
// network (IS78.1). The guard refuses a loopback address, also for a
// private host, so the client under test reaches the fake through
// guard.HTTPOptions.Base, the test seam of DS78.11 G4. The fake serves
// the session object of testdata/jmap/session.json, the API URL, blob
// upload and download, and a redirect. It records each request. With
// a fakeStore, the API URL also answers Mailbox/get, Mailbox/set,
// Email/query, Email/get, Thread/get, Identity/get, Email/set and
// EmailSubmission/set from the store, and resolves each back-reference
// of RFC 8620 §3.7 first.

package jmap

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// sessionFixture is the session object of the fake. BASE_URL stands
// for the https URL of the fake.
const sessionFixture = "../../testdata/jmap/session.json"

// fakeAccount is the primary mail account of sessionFixture.
const fakeAccount = "u1a2b3"

// fakeOpts set the answers of fakeJMAP. A test gives them to
// newFakeJMAP, and the fake does not change them.
type fakeOpts struct {
	// editSession changes the session object of GET number n (from
	// 1) before the fake sends it. base is the https URL of the fake.
	editSession func(n int, base string, s map[string]any)
	// apiStatus gives the status of API POST number n (from 1). 0, or
	// a list that has ended, gives 200 with the answer. 307 gives a
	// redirect to the same URL.
	apiStatus []int
	// limitPosts is the number of API POSTs, from the first, that get
	// the request error urn:ietf:params:jmap:error:limit with HTTP 400
	// (RFC 8620 §3.6.1).
	limitPosts int
	// apiDelay is the time that each API POST waits before its answer.
	apiDelay time.Duration
	// blobStatus, when not 0, is the status of each download and
	// upload.
	blobStatus int
	// pad adds a "pad" string of pad bytes to the arguments of each
	// method response.
	pad int
	// wantAuth, when set, is the one Authorization value that the fake
	// accepts. Another value gets 401.
	wantAuth string
	// blobs are the blobs that a download can get, by blobId.
	blobs map[string][]byte
	// store, when set, answers the mail methods of fakeStore. A test
	// does not change it after newFakeJMAP.
	store *fakeStore
}

// fakeReq is one request that fakeJMAP got.
type fakeReq struct {
	Method      string
	Path        string // r.URL.Path, decoded
	RequestURI  string // as sent on the wire
	Auth        string
	ContentType string
	Body        []byte
}

// fakeJMAP is the fake server. mu guards every field below it.
type fakeJMAP struct {
	t       *testing.T
	srv     *httptest.Server
	opts    fakeOpts
	fixture string

	mu          sync.Mutex
	reqs        []fakeReq
	sessionGets int
	apiPosts    int
	inFlight    int
	maxInFlight int
	uploads     int
	blobs       map[string][]byte
}

// newFakeJMAP starts a fake with opts and stops it when the test ends.
func newFakeJMAP(t *testing.T, opts fakeOpts) *fakeJMAP {
	t.Helper()
	fixture, err := os.ReadFile(sessionFixture)
	if err != nil {
		t.Fatalf("read the session fixture: %v", err)
	}
	f := &fakeJMAP{t: t, opts: opts, fixture: string(fixture), blobs: map[string][]byte{}}
	for id, b := range opts.blobs {
		f.blobs[id] = b
	}
	f.srv = httptest.NewTLSServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

// sessionURL is the session URL of the fake.
func (f *fakeJMAP) sessionURL() string { return f.srv.URL + "/.well-known/jmap" }

// host is the host name of the fake.
func (f *fakeJMAP) host() string {
	u, err := url.Parse(f.srv.URL)
	if err != nil {
		f.t.Fatalf("parse the fake URL: %v", err)
	}
	return u.Hostname()
}

// client gives a client of the session URL of the fake. It has the
// production options of GuardOptions, with Base set to the transport
// of the TLS fake (DS78.11 G4).
func (f *fakeJMAP) client(auth AuthFunc, privateHost bool) *Client {
	return f.clientAt(f.sessionURL(), auth, privateHost)
}

// clientAt is client with the session URL sessionURL.
func (f *fakeJMAP) clientAt(sessionURL string, auth AuthFunc, privateHost bool) *Client {
	ph := ""
	if privateHost {
		ph = f.host()
	}
	api, blob := GuardOptions(ph)
	api.Base = f.srv.Client().Transport
	blob.Base = f.srv.Client().Transport
	return New(sessionURL, auth, guard.NewHTTPClientFor(api), guard.NewHTTPClientFor(blob), privateHost)
}

// defaultGuarded gives a guarded client with the zero HTTPOptions of
// T2.5 (a 64 KiB body cap) and Base set to the fake.
func (f *fakeJMAP) defaultGuarded() *http.Client {
	return guard.NewHTTPClientFor(guard.HTTPOptions{Base: f.srv.Client().Transport})
}

// requests gives a copy of the requests so far.
func (f *fakeJMAP) requests() []fakeReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeReq(nil), f.reqs...)
}

// counts gives the number of session GETs and API POSTs so far.
func (f *fakeJMAP) counts() (gets, posts int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessionGets, f.apiPosts
}

// apiRequests decodes the body of each API POST so far.
func (f *fakeJMAP) apiRequests() []request {
	f.t.Helper()
	var out []request
	for _, r := range f.requests() {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Path, "/jmap/api") {
			continue
		}
		var req request
		if err := json.Unmarshal(r.Body, &req); err != nil {
			f.t.Fatalf("decode an API request: %v\n%s", err, r.Body)
		}
		out = append(out, req)
	}
	return out
}

func (f *fakeJMAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, fakeReq{
		Method:      r.Method,
		Path:        r.URL.Path,
		RequestURI:  r.RequestURI,
		Auth:        r.Header.Get("Authorization"),
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
	})
	f.mu.Unlock()
	if f.opts.wantAuth != "" && r.Header.Get("Authorization") != f.opts.wantAuth {
		problem(w, http.StatusUnauthorized)
		return
	}
	// The handler reads its own URL from the request, so it never
	// reads f.srv, which the test goroutine writes.
	base := "https://" + r.Host
	switch p := r.URL.Path; {
	case r.Method == http.MethodGet && p == "/.well-known/jmap":
		f.serveSession(w, base)
	case p == "/redirect/session":
		http.Redirect(w, r, "/.well-known/jmap", http.StatusFound)
	case r.Method == http.MethodPost && (p == "/jmap/api/" || p == "/jmap/api2/"):
		f.serveAPI(w, r, body)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/jmap/download/"):
		f.serveDownload(w, r)
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/jmap/upload/"):
		f.serveUpload(w, r, body)
	default:
		problem(w, http.StatusNotFound)
	}
}

// problem writes a problem details answer (RFC 8620 §3.6.1) of the
// type notRequest. Its detail is a server text that no error of the
// client may show.
func problem(w http.ResponseWriter, status int) {
	problemOf(w, status, "urn:ietf:params:jmap:error:notRequest")
}

// problemOf writes a problem details answer of the type typ.
func problemOf(w http.ResponseWriter, status int, typ string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"type":"`+typ+`","status":`+
		strconv.Itoa(status)+`,"detail":"SERVER-DETAIL-TEXT"}`)
}

// maxAPIInFlight gives the largest number of API POSTs that the fake
// served at the same time.
func (f *fakeJMAP) maxAPIInFlight() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maxInFlight
}

func (f *fakeJMAP) serveSession(w http.ResponseWriter, base string) {
	f.mu.Lock()
	f.sessionGets++
	n := f.sessionGets
	f.mu.Unlock()
	var s map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(f.fixture, "BASE_URL", base)), &s); err != nil {
		f.t.Errorf("decode the session fixture: %v", err)
		problem(w, http.StatusInternalServerError)
		return
	}
	if f.opts.editSession != nil {
		f.opts.editSession(n, base, s)
	}
	writeJSON(w, http.StatusOK, s)
}

func (f *fakeJMAP) serveAPI(w http.ResponseWriter, r *http.Request, body []byte) {
	f.mu.Lock()
	f.apiPosts++
	n := f.apiPosts
	f.inFlight++
	f.maxInFlight = max(f.maxInFlight, f.inFlight)
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if f.opts.apiDelay > 0 {
		time.Sleep(f.opts.apiDelay)
	}
	if n <= f.opts.limitPosts {
		problemOf(w, http.StatusBadRequest, "urn:ietf:params:jmap:error:limit")
		return
	}
	status := 0
	if n <= len(f.opts.apiStatus) {
		status = f.opts.apiStatus[n-1]
	}
	switch status {
	case 0, http.StatusOK:
	case http.StatusTemporaryRedirect:
		http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // G710: a test server that redirects to its own path
		return
	default:
		problem(w, status)
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		problem(w, http.StatusBadRequest)
		return
	}
	resp := Response{MethodResponses: []Invocation{}}
	for _, call := range req.MethodCalls {
		if call.Name == "Fail/now" {
			resp.MethodResponses = append(resp.MethodResponses, Invocation{
				Name: "error",
				Args: map[string]any{"type": "unknownMethod", "description": "SERVER-DETAIL-TEXT"},
				ID:   call.ID,
			})
			continue
		}
		if f.opts.store != nil {
			if invs, ok := f.opts.store.answer(call, resp.MethodResponses); ok {
				resp.MethodResponses = append(resp.MethodResponses, invs...)
				continue
			}
		}
		args := map[string]any{"accountId": fakeAccount}
		if f.opts.pad > 0 {
			args["pad"] = strings.Repeat("x", f.opts.pad)
		}
		resp.MethodResponses = append(resp.MethodResponses, Invocation{Name: call.Name, Args: args, ID: call.ID})
	}
	// A real server also sends sessionState; the client does not read it.
	writeJSON(w, http.StatusOK, struct {
		Response
		SessionState string `json:"sessionState"`
	}{resp, "75128aab4b1b"})
}

// serveDownload serves /jmap/download/{accountId}/{blobId}/{name}.
func (f *fakeJMAP) serveDownload(w http.ResponseWriter, r *http.Request) {
	if f.opts.blobStatus != 0 {
		problem(w, f.opts.blobStatus)
		return
	}
	parts := strings.Split(r.URL.EscapedPath(), "/")
	if len(parts) != 6 {
		problem(w, http.StatusBadRequest)
		return
	}
	id, err := url.PathUnescape(parts[4])
	if err != nil {
		problem(w, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	b, ok := f.blobs[id]
	f.mu.Unlock()
	if !ok {
		problem(w, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// serveUpload keeps the body as blob G<n> and answers 201 (RFC 8620
// §6.1).
func (f *fakeJMAP) serveUpload(w http.ResponseWriter, r *http.Request, body []byte) {
	if f.opts.blobStatus != 0 {
		problem(w, f.opts.blobStatus)
		return
	}
	f.mu.Lock()
	f.uploads++
	id := "G" + strconv.Itoa(f.uploads)
	f.blobs[id] = body
	f.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{
		"accountId": fakeAccount,
		"blobId":    id,
		"type":      r.Header.Get("Content-Type"),
		"size":      len(body),
	})
}

// writeJSON writes v as a JSON answer with status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// fakeStore is the mail of the fake account. Each object is the JSON
// object as a server sends it. Email/get gives the whole object and
// does not apply "properties"; a test reads the request to check the
// properties that the client asked for. Email/set and
// EmailSubmission/set change the store, so mu guards every field
// while the fake answers; a test reads the store through email.
type fakeStore struct {
	mu sync.Mutex

	// mailboxes is the list of Mailbox/get.
	mailboxes []map[string]any
	// emails are the emails, newest first: the order of Email/query.
	emails []map[string]any
	// threads gives the emailIds of each thread id, oldest first.
	threads map[string][]string
	// noTotal leaves total out of the Email/query answer.
	noTotal bool
	// identities is the list of Identity/get.
	identities []map[string]any
	// submissions are the EmailSubmission objects that
	// EmailSubmission/set created, in order.
	submissions []map[string]any
	// created counts the emails of Email/set create; the new ids are
	// D1, D2 and so on.
	created int
	// boxesCreated counts the mailboxes of Mailbox/set create; the new
	// ids are M1, M2 and so on.
	boxesCreated int
}

// answer gives the responses to call when the store has the method. It
// resolves each "#" argument against the responses before it (RFC 8620
// §3.7); a reference that does not resolve gives the error
// invalidResultReference. EmailSubmission/set can give two responses:
// its own and the Email/set of onSuccessUpdateEmail (RFC 8621 §7.5).
func (s *fakeStore) answer(call Invocation, before []Invocation) ([]Invocation, bool) {
	switch call.Name {
	case "Mailbox/get", "Mailbox/set", "Email/query", "Email/get", "Thread/get",
		"Identity/get", "Email/set", "EmailSubmission/set":
	default:
		return nil, false
	}
	args, ok := resolveRefs(call.Args, before)
	if !ok {
		return []Invocation{{Name: "error", ID: call.ID, Args: map[string]any{"type": "invalidResultReference"}}}, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if call.Name == "EmailSubmission/set" {
		return s.submit(args, call.ID), true
	}
	var out map[string]any
	switch call.Name {
	case "Mailbox/get":
		out = map[string]any{"list": s.mailboxes, "notFound": []any{}}
	case "Mailbox/set":
		out = s.setMailboxes(args)
	case "Email/query":
		out = s.query(args)
	case "Email/get":
		out = s.getEmails(args)
	case "Thread/get":
		out = s.getThreads(args)
	case "Identity/get":
		out = map[string]any{"list": s.identities, "notFound": []any{}}
	case "Email/set":
		out = s.setEmails(args)
	}
	out["accountId"] = fakeAccount
	out["state"] = "s1"
	return []Invocation{{Name: call.Name, Args: out, ID: call.ID}}, true
}

// email gives a copy of the stored email with the id, or nil. A copy
// of the top level is enough for a test: the fake replaces a map of
// mailboxIds or keywords when a patch changes it.
func (s *fakeStore) email(id string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i := s.indexOf(id); i >= 0 {
		out := map[string]any{}
		for k, v := range s.emails[i] {
			out[k] = v
		}
		return out
	}
	return nil
}

// indexOf gives the index of the email with the id in s.emails, or -1.
// The caller holds mu.
func (s *fakeStore) indexOf(id any) int {
	for i, e := range s.emails {
		if e["id"] == id {
			return i
		}
	}
	return -1
}

// setEmails applies the create, update and destroy of Email/set (RFC
// 8620 §5.3). A created email gets the id D<n> and goes first, as the
// newest. An update is a patch of RFC 8620 §5.3 (applyPatch). An id
// that the store does not hold gets the SetError notFound.
func (s *fakeStore) setEmails(args map[string]any) map[string]any {
	created := map[string]any{}
	updated := map[string]any{}
	notUpdated := map[string]any{}
	destroyed := []any{}
	notDestroyed := map[string]any{}
	creates, _ := args["create"].(map[string]any)
	for cid, v := range creates {
		obj, _ := v.(map[string]any)
		s.created++
		id := "D" + strconv.Itoa(s.created)
		e := map[string]any{}
		for k, x := range obj {
			e[k] = x
		}
		e["id"] = id
		e["threadId"] = "t-" + id
		s.emails = append([]map[string]any{e}, s.emails...)
		created[cid] = map[string]any{"id": id, "threadId": "t-" + id, "blobId": "B" + id}
	}
	updates, _ := args["update"].(map[string]any)
	for id, v := range updates {
		patch, _ := v.(map[string]any)
		if i := s.indexOf(id); i >= 0 {
			applyPatch(s.emails[i], patch)
			updated[id] = nil
		} else {
			notUpdated[id] = map[string]any{"type": "notFound"}
		}
	}
	destroys, _ := args["destroy"].([]any)
	for _, id := range destroys {
		if i := s.indexOf(id); i >= 0 {
			s.emails = append(s.emails[:i], s.emails[i+1:]...)
			destroyed = append(destroyed, id)
		} else {
			key, _ := id.(string)
			notDestroyed[key] = map[string]any{"type": "notFound"}
		}
	}
	return map[string]any{
		"oldState": "s0", "newState": "s1",
		"created": created, "notCreated": map[string]any{},
		"updated": updated, "notUpdated": notUpdated,
		"destroyed": destroyed, "notDestroyed": notDestroyed,
	}
}

// setMailboxes applies the create, update and destroy of Mailbox/set
// (RFC 8621 §2.5). A created mailbox gets the id M<n>, no role and no
// messages. An update sets name and parentId. A destroy of a mailbox
// that an email is in gets mailboxHasEmail when onDestroyRemoveEmails
// is not true. An id that the store does not hold gets notFound.
func (s *fakeStore) setMailboxes(args map[string]any) map[string]any {
	created := map[string]any{}
	updated := map[string]any{}
	notUpdated := map[string]any{}
	destroyed := []any{}
	notDestroyed := map[string]any{}
	box := func(id any) int {
		for i, m := range s.mailboxes {
			if m["id"] == id {
				return i
			}
		}
		return -1
	}
	creates, _ := args["create"].(map[string]any)
	for cid, v := range creates {
		obj, _ := v.(map[string]any)
		s.boxesCreated++
		id := "M" + strconv.Itoa(s.boxesCreated)
		s.mailboxes = append(s.mailboxes, map[string]any{
			"id": id, "name": obj["name"], "parentId": obj["parentId"], "role": nil,
			"totalEmails": 0, "unreadEmails": 0,
		})
		created[cid] = map[string]any{"id": id}
	}
	updates, _ := args["update"].(map[string]any)
	for id, v := range updates {
		patch, _ := v.(map[string]any)
		if i := box(id); i >= 0 {
			m := map[string]any{}
			for k, x := range s.mailboxes[i] {
				m[k] = x
			}
			applyPatch(m, patch)
			s.mailboxes[i] = m
			updated[id] = nil
		} else {
			notUpdated[id] = map[string]any{"type": "notFound"}
		}
	}
	destroys, _ := args["destroy"].([]any)
	for _, id := range destroys {
		key, _ := id.(string)
		i := box(id)
		if i < 0 {
			notDestroyed[key] = map[string]any{"type": "notFound"}
			continue
		}
		used := false
		for _, e := range s.emails {
			if boxes, _ := e["mailboxIds"].(map[string]any); boxes[key] == true {
				used = true
			}
		}
		if used && args["onDestroyRemoveEmails"] != true {
			notDestroyed[key] = map[string]any{"type": "mailboxHasEmail"}
			continue
		}
		s.mailboxes = append(s.mailboxes[:i], s.mailboxes[i+1:]...)
		destroyed = append(destroyed, id)
	}
	return map[string]any{
		"oldState": "s0", "newState": "s1",
		"created": created, "notCreated": map[string]any{},
		"updated": updated, "notUpdated": notUpdated,
		"destroyed": destroyed, "notDestroyed": notDestroyed,
	}
}

// applyPatch applies a PatchObject (RFC 8620 §5.3) to the email e. A
// path "a/b" sets the key b of the map a, and null removes it; a path
// with no "/" sets the property. b is a JSON Pointer token, so "~1"
// gives "/" and "~0" gives "~". The map a is replaced, not changed in
// place, so a copy that email gave stays as it was.
func applyPatch(e map[string]any, patch map[string]any) {
	for path, v := range patch {
		top, key, nested := strings.Cut(path, "/")
		if !nested {
			e[path] = v
			continue
		}
		key = strings.NewReplacer("~1", "/", "~0", "~").Replace(key)
		old, _ := e[top].(map[string]any)
		sub := map[string]any{}
		for k, x := range old {
			sub[k] = x
		}
		if v == nil {
			delete(sub, key)
		} else {
			sub[key] = v
		}
		e[top] = sub
	}
}

// submit answers EmailSubmission/set create (RFC 8621 §7.5). A
// submission needs an identityId of s.identities (else forbiddenFrom)
// and an emailId of the store (else invalidProperties). For each
// created submission, the patch of onSuccessUpdateEmail under
// "#<creation id>" goes to its email, and a second response, Email/set
// with the call id of the submission, reports it.
func (s *fakeStore) submit(args map[string]any, callID string) []Invocation {
	created := map[string]any{}
	notCreated := map[string]any{}
	emailOf := map[string]any{}
	creates, _ := args["create"].(map[string]any)
	for cid, v := range creates {
		sub, _ := v.(map[string]any)
		known := false
		for _, id := range s.identities {
			if id["id"] == sub["identityId"] {
				known = true
			}
		}
		switch {
		case !known:
			notCreated[cid] = map[string]any{"type": "forbiddenFrom"}
		case s.indexOf(sub["emailId"]) < 0:
			notCreated[cid] = map[string]any{"type": "invalidProperties"}
		default:
			s.submissions = append(s.submissions, sub)
			created[cid] = map[string]any{"id": "S" + strconv.Itoa(len(s.submissions)), "undoStatus": "final"}
			emailOf["#"+cid] = sub["emailId"]
		}
	}
	out := []Invocation{{Name: "EmailSubmission/set", ID: callID, Args: map[string]any{
		"accountId": fakeAccount, "oldState": "u0", "newState": "u1",
		"created": created, "notCreated": notCreated,
	}}}
	onSuccess, _ := args["onSuccessUpdateEmail"].(map[string]any)
	update := map[string]any{}
	for ref, patch := range onSuccess {
		if id, ok := emailOf[ref]; ok {
			key, _ := id.(string)
			update[key] = patch
		}
	}
	if len(update) > 0 {
		res := s.setEmails(map[string]any{"update": update})
		res["accountId"] = fakeAccount
		out = append(out, Invocation{Name: "Email/set", ID: callID, Args: res})
	}
	return out
}

// query gives the ids of the emails in the mailbox of an inMailbox
// condition, at the top level or in an AND, from position, at most
// limit of them.
func (s *fakeStore) query(args map[string]any) map[string]any {
	box := inMailbox(args["filter"])
	var ids []any
	for _, e := range s.emails {
		if box != "" {
			boxes, _ := e["mailboxIds"].(map[string]any)
			if boxes[box] != true {
				continue
			}
		}
		ids = append(ids, e["id"])
	}
	total := len(ids)
	pos, _ := args["position"].(float64)
	limit, _ := args["limit"].(float64)
	start := min(int(pos), len(ids))
	end := len(ids)
	if limit > 0 {
		end = min(start+int(limit), len(ids))
	}
	out := map[string]any{"ids": append([]any{}, ids[start:end]...), "position": start, "queryState": "q1"}
	if !s.noTotal {
		out["total"] = total
	}
	return out
}

// inMailbox gives the inMailbox value of a filter, or "".
func inMailbox(filter any) string {
	m, _ := filter.(map[string]any)
	if v, ok := m["inMailbox"].(string); ok {
		return v
	}
	if m["operator"] == "AND" {
		conds, _ := m["conditions"].([]any)
		for _, c := range conds {
			if v := inMailbox(c); v != "" {
				return v
			}
		}
	}
	return ""
}

// getEmails gives the emails of args["ids"], in the reverse order of
// the ids, because a server does not promise the order of the list.
// Each email is a copy of the top level, so a later call of the same
// batch that changes the store does not change this answer.
func (s *fakeStore) getEmails(args map[string]any) map[string]any {
	ids, _ := args["ids"].([]any)
	list := []any{}
	notFound := []any{}
	for i := len(ids) - 1; i >= 0; i-- {
		found := false
		for _, e := range s.emails {
			if e["id"] == ids[i] {
				c := make(map[string]any, len(e))
				for k, v := range e {
					c[k] = v
				}
				list = append(list, c)
				found = true
			}
		}
		if !found {
			notFound = append(notFound, ids[i])
		}
	}
	return map[string]any{"list": list, "notFound": notFound}
}

// getThreads gives the threads of args["ids"].
func (s *fakeStore) getThreads(args map[string]any) map[string]any {
	ids, _ := args["ids"].([]any)
	list := []any{}
	notFound := []any{}
	for _, id := range ids {
		key, _ := id.(string)
		if emails, ok := s.threads[key]; ok {
			list = append(list, map[string]any{"id": key, "emailIds": emails})
		} else {
			notFound = append(notFound, id)
		}
	}
	return map[string]any{"list": list, "notFound": notFound}
}

// resolveRefs gives args with each "#name" argument replaced by
// "name" and the value that its ResultReference points at. ok is false
// when a reference names no earlier response.
func resolveRefs(args map[string]any, before []Invocation) (map[string]any, bool) {
	out := map[string]any{}
	for k, v := range args {
		if !strings.HasPrefix(k, "#") {
			out[k] = v
			continue
		}
		rr, _ := v.(map[string]any)
		var src *Invocation
		for i := range before {
			if before[i].ID == rr["resultOf"] && before[i].Name == rr["name"] {
				src = &before[i]
			}
		}
		if src == nil {
			return nil, false
		}
		var generic any
		b, _ := json.Marshal(src.Args)
		_ = json.Unmarshal(b, &generic)
		path, _ := rr["path"].(string)
		val := pointer(generic, strings.Split(strings.TrimPrefix(path, "/"), "/"))
		if _, isList := val.([]any); !isList {
			val = []any{val}
		}
		out[strings.TrimPrefix(k, "#")] = val
	}
	return out, true
}

// pointer applies a JSON pointer with the "*" of RFC 8620 §3.7: "*" on
// an array applies the rest of the path to each item, and an item
// whose result is an array adds its items.
func pointer(v any, path []string) any {
	if len(path) == 0 {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		return pointer(t[path[0]], path[1:])
	case []any:
		if path[0] != "*" {
			return nil
		}
		out := []any{}
		for _, item := range t {
			r := pointer(item, path[1:])
			if list, ok := r.([]any); ok {
				out = append(out, list...)
			} else {
				out = append(out, r)
			}
		}
		return out
	}
	return nil
}
