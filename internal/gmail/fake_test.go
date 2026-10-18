// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// fakeGmail stands in for the Gmail REST API on httptest.NewServer
// (DS7.9). It listens on a loopback port only, so no test reaches the
// network (IS78.1). A test gives the answers as a list of steps or as
// a route function, and the fake records each request. The JSON
// fixtures are in testdata/gmail/ (IS7.1: made-up ids, example.com).

package gmail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// step is one answer of fakeGmail.
type step struct {
	status int
	header map[string]string
	body   string
}

// fakeReq is one request that fakeGmail got.
type fakeReq struct {
	Method      string
	Path        string
	RawQuery    string
	Auth        string
	ContentType string
	Body        []byte
}

// fakeGmail gives the steps in order and repeats the last step when
// the list ends. When route is set, route gives each answer instead.
type fakeGmail struct {
	t     *testing.T
	srv   *httptest.Server
	mu    sync.Mutex
	steps []step
	route func(r *http.Request) step
	reqs  []fakeReq
}

// newFakeGmail starts a fake with the steps and stops it when the test
// ends.
func newFakeGmail(t *testing.T, steps ...step) *fakeGmail {
	t.Helper()
	if len(steps) == 0 {
		t.Fatal("newFakeGmail: no steps")
	}
	f := &fakeGmail{t: t, steps: steps}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

// newFakeGmailRoutes starts a fake that answers each request with
// route and stops it when the test ends. route runs on the goroutine of
// the request, without the lock of the fake, so it can block; it must
// be safe for calls at the same time.
func newFakeGmailRoutes(t *testing.T, route func(r *http.Request) step) *fakeGmail {
	t.Helper()
	f := &fakeGmail{t: t, route: route}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGmail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	// A route reads the body again, for example the parts of an upload.
	r.Body = io.NopCloser(bytes.NewReader(body))
	f.mu.Lock()
	f.reqs = append(f.reqs, fakeReq{
		Method:      r.Method,
		Path:        r.URL.Path,
		RawQuery:    r.URL.RawQuery,
		Auth:        r.Header.Get("Authorization"),
		ContentType: r.Header.Get("Content-Type"),
		Body:        body,
	})
	var s step
	if f.route == nil {
		s = f.steps[min(len(f.reqs), len(f.steps))-1]
	}
	f.mu.Unlock()
	if f.route != nil {
		s = f.route(r)
	}
	for k, v := range s.header {
		w.Header().Set(k, v)
	}
	if s.body != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(s.status)
	_, _ = io.WriteString(w, s.body)
}

// requests gives a copy of the requests so far.
func (f *fakeGmail) requests() []fakeReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeReq(nil), f.reqs...)
}

// probe records what an API under test did besides the HTTP calls: the
// waits it asked for, the auth events and the log.
type probe struct {
	mu    sync.Mutex
	waits []time.Duration
	auth  []error
	log   bytes.Buffer
}

func (p *probe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.Write(b)
}

func (p *probe) gotWaits() []time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]time.Duration(nil), p.waits...)
}

func (p *probe) gotAuth() []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]error(nil), p.auth...)
}

func (p *probe) logText() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.String()
}

// api gives an API that calls the fake. Its sleep records the wait and
// does not wait, its jitter is 0, onAuth and the log go to the probe.
func (f *fakeGmail) api(token TokenFunc) (*API, *probe) {
	p := &probe{}
	a := New(token, func(err error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.auth = append(p.auth, err)
	})
	a.base = f.srv.URL + "/gmail/v1/users/me/"
	a.upload = f.srv.URL + "/upload/gmail/v1/users/me/"
	a.sleep = func(_ context.Context, d time.Duration) error {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.waits = append(p.waits, d)
		return nil
	}
	a.jitter = func() time.Duration { return 0 }
	a.log = slog.New(slog.NewTextHandler(p, nil))
	return a, p
}

// staticToken gives the same token each time.
func staticToken(tok string) TokenFunc {
	return func(context.Context) (string, error) { return tok, nil }
}

// googleError gives the JSON error object of a Google API. An empty
// reason leaves errors[] empty; an empty detail leaves details[] empty.
func googleError(code int, status, reason, detail, message string) string {
	type item struct {
		Message string `json:"message"`
		Domain  string `json:"domain"`
		Reason  string `json:"reason"`
	}
	type info struct {
		Type   string `json:"@type"`
		Reason string `json:"reason"`
		Domain string `json:"domain"`
	}
	e := map[string]any{"code": code, "message": message, "status": status}
	if reason != "" {
		e["errors"] = []item{{Message: message, Domain: "global", Reason: reason}}
	}
	if detail != "" {
		e["details"] = []info{{Type: "type.googleapis.com/google.rpc.ErrorInfo", Reason: detail, Domain: "googleapis.com"}}
	}
	b, err := json.Marshal(map[string]any{"error": e})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// apiPrefix is the path of baseURL on the fake.
const apiPrefix = "/gmail/v1/users/me/"

// routes gives a route that answers "<METHOD> <path below baseURL>"
// from the map, for example "GET labels/INBOX". Any other request
// gets 404 notFound.
func routes(m map[string]step) func(r *http.Request) step {
	return func(r *http.Request) step {
		if s, ok := m[r.Method+" "+strings.TrimPrefix(r.URL.Path, apiPrefix)]; ok {
			return s
		}
		return step{status: 404, body: googleError(404, "NOT_FOUND", "notFound", "", "Requested entity was not found.")}
	}
}

// fixture gives the text of testdata/gmail/<name>.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gmail", name)) //nolint:gosec // G304: the path comes from the test, not from a user
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return string(b)
}

// labelRoutes gives the routes of labels.list and labels.get from the
// fixtures labels.list.json and labels.get.json (a list of labels.get
// answers).
func labelRoutes(t *testing.T) map[string]step {
	t.Helper()
	m := map[string]step{"GET labels": {status: 200, body: fixture(t, "labels.list.json")}}
	var each []json.RawMessage
	if err := json.Unmarshal([]byte(fixture(t, "labels.get.json")), &each); err != nil {
		t.Fatalf("labels.get.json: %v", err)
	}
	for _, raw := range each {
		var l struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &l); err != nil || l.ID == "" {
			t.Fatalf("labels.get.json: an entry with no id: %v", err)
		}
		m["GET labels/"+l.ID] = step{status: 200, body: string(raw)}
	}
	return m
}

// testAccount is the account of the provider tests (IS7.1).
var testAccount = config.Account{Alias: "work", Provider: "gmail", Email: "me@example.com", Access: "draft"}

// provider gives a Provider on the fake with the State st (nil: a new
// one) and the probe of its API.
func (f *fakeGmail) provider(st *State) (*Provider, *probe) {
	a, p := f.api(staticToken("tok-1"))
	return NewProvider(testAccount.Alias, testAccount, a, st), p
}
