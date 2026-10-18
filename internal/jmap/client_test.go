// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the JMAP client (DS8.1) against fakeJMAP: the kept session
// and its refetch, "using", the URL rules, the redirect refusal, the
// two auth forms, blob upload and download, and the body caps of
// DS8.3.

package jmap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// mailboxGet is a plain method call with no submission part.
func mailboxGet(id string) Invocation {
	return Invocation{Name: "Mailbox/get", Args: map[string]any{"accountId": fakeAccount}, ID: id}
}

// apiPaths gives the path of each API POST so far.
func apiPaths(f *fakeJMAP) []string {
	var out []string
	for _, r := range f.requests() {
		if r.Method == http.MethodPost && strings.HasPrefix(r.Path, "/jmap/api") {
			out = append(out, r.Path)
		}
	}
	return out
}

// TestJMAP_SessionKeptAndRefetchedOn401 checks that the client gets the
// session once and keeps it, also for calls that start at the same
// time; that a 401 on the API URL gets the session one more time and
// repeats the call once on the new apiUrl; and that the new session is
// kept after that.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_SessionKeptAndRefetchedOn401(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{
		apiStatus: []int{0, 0, http.StatusUnauthorized},
		editSession: func(n int, base string, s map[string]any) {
			if n >= 2 {
				s["apiUrl"] = base + "/jmap/api2/"
			}
		},
	})
	c := f.client(BearerAuth("tok"), false)
	ctx := context.Background()

	var wg sync.WaitGroup
	got := make([]*Session, 8)
	errs := make([]error, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = c.Session(ctx)
		}()
	}
	wg.Wait()
	for i := range got {
		if errs[i] != nil {
			t.Fatalf("Session %d: %v", i, errs[i])
		}
		if got[i] != got[0] {
			t.Fatalf("Session %d gave another session than Session 0", i)
		}
	}
	if gets, _ := f.counts(); gets != 1 {
		t.Fatalf("8 Session calls made %d session GETs, want 1", gets)
	}
	first := got[0]
	if first.AccountID != fakeAccount || first.MaxSizeUpload != 50000000 || !strings.HasSuffix(first.APIURL, "/jmap/api/") {
		t.Fatalf("session = %+v, want account %s, maxSizeUpload 50000000, apiUrl /jmap/api/", first, fakeAccount)
	}

	for i := range 3 {
		if _, err := c.Call(ctx, mailboxGet("c0")); err != nil {
			t.Fatalf("Call %d: %v", i+1, err)
		}
	}
	gets, posts := f.counts()
	if gets != 2 || posts != 4 {
		t.Fatalf("after three calls and one 401: %d session GETs and %d API POSTs, want 2 and 4", gets, posts)
	}
	want := []string{"/jmap/api/", "/jmap/api/", "/jmap/api/", "/jmap/api2/"}
	if paths := apiPaths(f); !reflect.DeepEqual(paths, want) {
		t.Fatalf("API POST paths = %v, want %v", paths, want)
	}

	s, err := c.Session(ctx)
	if err != nil {
		t.Fatalf("Session after the refetch: %v", err)
	}
	if s == first || !strings.HasSuffix(s.APIURL, "/jmap/api2/") {
		t.Fatalf("Session after the refetch has apiUrl %q, want the new /jmap/api2/", s.APIURL)
	}
	if _, err := c.Call(ctx, mailboxGet("c0")); err != nil {
		t.Fatalf("Call after the refetch: %v", err)
	}
	if gets, _ := f.counts(); gets != 2 {
		t.Fatalf("the call after the refetch made session GET %d, want the kept session", gets)
	}
}

// TestJMAP_RefetchedOn404Once checks that a 404 on the API URL gets the
// session one more time and repeats the call once: the call passes
// when the new apiUrl answers, and fails after one repeat when it
// does not. A 500 gets no refetch. The error text gives the status and
// the problem type, and never the "detail" text of the server.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_RefetchedOn404Once(t *testing.T) {
	ctx := context.Background()

	t.Run("recovers", func(t *testing.T) {
		f := newFakeJMAP(t, fakeOpts{
			apiStatus: []int{http.StatusNotFound},
			editSession: func(n int, base string, s map[string]any) {
				if n >= 2 {
					s["apiUrl"] = base + "/jmap/api2/"
				}
			},
		})
		resp, err := f.client(nil, false).Call(ctx, mailboxGet("c0"))
		if err != nil {
			t.Fatalf("Call: %v", err)
		}
		if len(resp.MethodResponses) != 1 || resp.MethodResponses[0].Name != "Mailbox/get" {
			t.Fatalf("answer = %+v, want one Mailbox/get", resp.MethodResponses)
		}
		if gets, posts := f.counts(); gets != 2 || posts != 2 {
			t.Fatalf("%d session GETs and %d API POSTs, want 2 and 2", gets, posts)
		}
		if paths := apiPaths(f); !reflect.DeepEqual(paths, []string{"/jmap/api/", "/jmap/api2/"}) {
			t.Fatalf("API POST paths = %v, want the old then the new apiUrl", paths)
		}
	})

	t.Run("fails after one repeat", func(t *testing.T) {
		f := newFakeJMAP(t, fakeOpts{apiStatus: []int{404, 404, 404, 404}})
		_, err := f.client(nil, false).Call(ctx, mailboxGet("c0"))
		if err == nil {
			t.Fatal("Call passed, want the 404 error")
		}
		const want = "jmap: api: HTTP 404 urn:ietf:params:jmap:error:notRequest"
		if err.Error() != want {
			t.Fatalf("error = %q, want %q", err, want)
		}
		var ae *AuthError
		if errors.As(err, &ae) {
			t.Fatalf("a 404 gave an AuthError: %v", err)
		}
		if gets, posts := f.counts(); gets != 2 || posts != 2 {
			t.Fatalf("%d session GETs and %d API POSTs, want 2 and 2 (one refetch, one repeat)", gets, posts)
		}
	})

	t.Run("no refetch on 500", func(t *testing.T) {
		f := newFakeJMAP(t, fakeOpts{apiStatus: []int{500, 500}})
		_, err := f.client(nil, false).Call(ctx, mailboxGet("c0"))
		if err == nil || strings.Contains(err.Error(), "SERVER-DETAIL-TEXT") {
			t.Fatalf("Call = %v, want an error without the server detail", err)
		}
		if gets, posts := f.counts(); gets != 1 || posts != 1 {
			t.Fatalf("%d session GETs and %d API POSTs, want 1 and 1", gets, posts)
		}
	})
}

// TestJMAP_UsingHasSubmission checks that "using" holds core and mail,
// and submission when the batch has an EmailSubmission or an Identity
// call (F1, IS8.3), and that each call goes on the wire as
// [name, arguments, call id] and comes back the same way.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_UsingHasSubmission(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{})
	c := f.client(nil, false)
	ctx := context.Background()

	plain := []string{usingCore, usingMail}
	withSub := []string{usingCore, usingMail, usingSubmission}
	cases := []struct {
		name  string
		calls []Invocation
		want  []string
	}{
		{"mailbox only", []Invocation{mailboxGet("c0")}, plain},
		{"email set and submission", []Invocation{
			{Name: "Email/set", Args: map[string]any{"accountId": fakeAccount}, ID: "c0"},
			{Name: "EmailSubmission/set", Args: map[string]any{"accountId": fakeAccount}, ID: "c1"},
		}, withSub},
		{"identity only", []Invocation{{Name: "Identity/get", Args: map[string]any{"accountId": fakeAccount}, ID: "c0"}}, withSub},
		{"nil arguments", []Invocation{{Name: "Mailbox/get", ID: "c0"}}, plain},
	}
	for i, tc := range cases {
		resp, err := c.Call(ctx, tc.calls...)
		if err != nil {
			t.Fatalf("%s: Call: %v", tc.name, err)
		}
		reqs := f.apiRequests()
		if len(reqs) != i+1 {
			t.Fatalf("%s: %d API requests, want %d", tc.name, len(reqs), i+1)
		}
		if got := reqs[i].Using; !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: using = %v, want %v", tc.name, got, tc.want)
		}
		if len(resp.MethodResponses) != len(tc.calls) {
			t.Fatalf("%s: %d responses, want %d", tc.name, len(resp.MethodResponses), len(tc.calls))
		}
		for j, call := range tc.calls {
			if r := resp.MethodResponses[j]; r.Name != call.Name || r.ID != call.ID || r.Args["accountId"] != fakeAccount {
				t.Errorf("%s: response %d = %+v, want %s %s", tc.name, j, r, call.Name, call.ID)
			}
		}
	}

	// The wire form of one call (RFC 8620 §3.2).
	var raw struct {
		MethodCalls [][]any `json:"methodCalls"`
	}
	body := f.requests()[len(f.requests())-1].Body
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode the last request: %v", err)
	}
	want := [][]any{{"Mailbox/get", map[string]any{}, "c0"}}
	if !reflect.DeepEqual(raw.MethodCalls, want) {
		t.Fatalf("methodCalls on the wire = %v, want %v", raw.MethodCalls, want)
	}
}

// TestJMAP_MethodErrorInAnswer checks that an "error" response does not
// fail Call, that Invocation.Err gives it as *MethodError, and that its
// text gives the type and not the description of the server.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_MethodErrorInAnswer(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{})
	resp, err := f.client(nil, false).Call(context.Background(), mailboxGet("c0"), Invocation{Name: "Fail/now", ID: "c1"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if len(resp.MethodResponses) != 2 {
		t.Fatalf("%d responses, want 2", len(resp.MethodResponses))
	}
	if err := resp.MethodResponses[0].Err(); err != nil {
		t.Fatalf("Mailbox/get response Err = %v, want nil", err)
	}
	err = resp.MethodResponses[1].Err()
	var me *MethodError
	if !errors.As(err, &me) || me.Type != "unknownMethod" || resp.MethodResponses[1].ID != "c1" {
		t.Fatalf("error response Err = %v, want *MethodError unknownMethod for c1", err)
	}
	if got, want := err.Error(), "jmap: method error unknownMethod"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

// TestJMAP_ServerURLGuard checks the URL rules of DS8.1 (F4, IS8.1):
// the session URL, apiUrl, downloadUrl and uploadUrl must be https;
// with private_host each must be on the session host; without it any
// host passes the client, and the guard checks the address at dial
// time. A refused URL fails with "jmap: server URL <which> refused"
// and gets no request.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_ServerURLGuard(t *testing.T) {
	ctx := context.Background()
	set := func(key, value string) func(int, string, map[string]any) {
		return func(_ int, base string, s map[string]any) {
			s[key] = strings.ReplaceAll(value, "BASE", strings.TrimPrefix(base, "https://"))
		}
	}
	cases := []struct {
		name        string
		edit        func(int, string, map[string]any)
		privateHost bool
		want        string // "" = the session passes
	}{
		{"apiUrl http", set("apiUrl", "http://BASE/jmap/api/"), false, `jmap: server URL apiUrl refused: the scheme "http" is not https`},
		{"downloadUrl http", set("downloadUrl", "http://BASE/jmap/download/{accountId}/{blobId}/{name}?accept={type}"), false, `jmap: server URL downloadUrl refused: the scheme "http" is not https`},
		{"uploadUrl http", set("uploadUrl", "http://BASE/jmap/upload/{accountId}/"), false, `jmap: server URL uploadUrl refused: the scheme "http" is not https`},
		{"apiUrl empty", set("apiUrl", ""), false, `jmap: server URL apiUrl refused: it is empty`},
		{"apiUrl relative", set("apiUrl", "/jmap/api/"), false, `jmap: server URL apiUrl refused: the scheme "" is not https`},
		{"field in the host", set("downloadUrl", "https://{accountId}.example.test/d/{blobId}"), false, `jmap: server URL downloadUrl refused: it is not a valid URL`},
		{"private host, apiUrl elsewhere", set("apiUrl", "https://other.example.test/jmap/api/"), true, `jmap: server URL apiUrl refused: the host "other.example.test" is not the session host "127.0.0.1", and private_host allows that host only`},
		{"private host, downloadUrl elsewhere", set("downloadUrl", "https://other.example.test/d/{blobId}"), true, `jmap: server URL downloadUrl refused: the host "other.example.test"`},
		{"private host, uploadUrl elsewhere", set("uploadUrl", "https://other.example.test/u/{accountId}/"), true, `jmap: server URL uploadUrl refused: the host "other.example.test"`},
		{"no private host, apiUrl elsewhere", set("apiUrl", "https://other.example.test/jmap/api/"), false, ""},
		{"private host, all on the session host", nil, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeJMAP(t, fakeOpts{editSession: tc.edit})
			c := f.client(nil, tc.privateHost)
			// Session only: a call to other.example.test would need DNS
			// (IS78.1).
			_, err := c.Session(ctx)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Session: %v, want it to pass", err)
				}
				return
			}
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Session = %v, want %q", err, tc.want)
			}
			if _, err := c.Call(ctx, mailboxGet("c0")); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Call = %v, want %q", err, tc.want)
			}
			if _, posts := f.counts(); posts != 0 {
				t.Fatalf("a refused session sent %d API POSTs, want 0", posts)
			}
			if _, _, err := c.Download(ctx, "B1", "n", "text/plain"); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Download = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("session_url http", func(t *testing.T) {
		f := newFakeJMAP(t, fakeOpts{})
		c := f.clientAt("http://"+strings.TrimPrefix(f.srv.URL, "https://")+"/.well-known/jmap", nil, false)
		_, err := c.Session(ctx)
		const want = `jmap: server URL session_url refused: the scheme "http" is not https`
		if err == nil || err.Error() != want {
			t.Fatalf("Session = %v, want %q", err, want)
		}
		if n := len(f.requests()); n != 0 {
			t.Fatalf("the fake got %d requests, want 0", n)
		}
	})
}

// TestJMAP_NoRedirects checks that the client follows no redirect (F4):
// a redirect on the session URL fails the session and its target gets
// no request, and a redirect on the API URL fails the call with no
// refetch and no second POST.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_NoRedirects(t *testing.T) {
	ctx := context.Background()

	f := newFakeJMAP(t, fakeOpts{})
	c := f.clientAt(f.srv.URL+"/redirect/session", nil, false)
	if _, err := c.Session(ctx); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("Session through a redirect = %v, want the redirect refused", err)
	}
	if gets, _ := f.counts(); gets != 0 {
		t.Fatalf("the redirect target got %d session GETs, want 0", gets)
	}

	f = newFakeJMAP(t, fakeOpts{apiStatus: []int{http.StatusTemporaryRedirect}})
	_, err := f.client(nil, false).Call(ctx, mailboxGet("c0"))
	if err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("Call through a redirect = %v, want the redirect refused", err)
	}
	if gets, posts := f.counts(); gets != 1 || posts != 1 {
		t.Fatalf("%d session GETs and %d API POSTs, want 1 and 1", gets, posts)
	}
}

// exerciseAll runs each kind of request of the client once: the
// session, a call, an upload and a download of the uploaded blob.
func exerciseAll(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	if _, err := c.Call(ctx, mailboxGet("c0")); err != nil {
		t.Fatalf("Call: %v", err)
	}
	id, err := c.Upload(ctx, "text/plain", strings.NewReader("hello"), 5)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	body, _, err := c.Download(ctx, id, "hello.txt", "text/plain")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer func() { _ = body.Close() }()
	if b, err := io.ReadAll(body); err != nil || string(b) != "hello" {
		t.Fatalf("Download body = %q, %v, want hello", b, err)
	}
}

// checkAuth checks that the fake got the four kinds of request, each
// with the Authorization value want.
func checkAuth(t *testing.T, f *fakeJMAP, want string) {
	t.Helper()
	reqs := f.requests()
	if len(reqs) != 4 {
		t.Fatalf("the fake got %d requests, want 4 (session, api, upload, download)", len(reqs))
	}
	for _, r := range reqs {
		if r.Auth != want {
			t.Errorf("%s %s: Authorization = %q, want %q", r.Method, r.Path, r.Auth, want)
		}
	}
}

// TestJMAP_BearerAuth checks that BearerAuth puts the token on each
// request: the session, the API, the upload and the download (F5).
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_BearerAuth(t *testing.T) {
	const want = "Bearer tok-123"
	f := newFakeJMAP(t, fakeOpts{wantAuth: want})
	exerciseAll(t, f.client(BearerAuth("tok-123"), false))
	checkAuth(t, f, want)
}

// TestJMAP_BasicAuth checks that BasicAuth puts the user and the
// password on each request with HTTP Basic (F5, DS8.6).
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_BasicAuth(t *testing.T) {
	const user, pass = "me@example.test", "pa:ss wörd" //nolint:gosec // G101: a test value, not a real credential
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	f := newFakeJMAP(t, fakeOpts{wantAuth: want})
	exerciseAll(t, f.client(BasicAuth(user, pass), false))
	checkAuth(t, f, want)
}

// TestJMAP_UploadTypeIsMediaType checks that Upload sends the media
// type of the blob as Content-Type (RFC 8620 §6.1), not
// application/json, to the upload URL of the account, with the bytes
// as the body; an empty type sends application/octet-stream.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_UploadTypeIsMediaType(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{})
	c := f.client(nil, false)
	ctx := context.Background()
	pdf := []byte("%PDF-1.7\n...")

	id, err := c.Upload(ctx, "application/pdf", bytes.NewReader(pdf), int64(len(pdf)))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if id != "G1" {
		t.Fatalf("blobId = %q, want G1", id)
	}
	if _, err := c.Upload(ctx, "", strings.NewReader("raw"), -1); err != nil {
		t.Fatalf("Upload with no type: %v", err)
	}

	var ups []fakeReq
	for _, r := range f.requests() {
		if r.Method == http.MethodPost && strings.HasPrefix(r.Path, "/jmap/upload/") {
			ups = append(ups, r)
		}
	}
	if len(ups) != 2 {
		t.Fatalf("%d uploads, want 2", len(ups))
	}
	if ups[0].Path != "/jmap/upload/"+fakeAccount+"/" {
		t.Errorf("upload path = %q, want the template filled with the account", ups[0].Path)
	}
	if ups[0].ContentType != "application/pdf" || !bytes.Equal(ups[0].Body, pdf) {
		t.Errorf("upload 1: Content-Type %q, body %q; want application/pdf and the bytes", ups[0].ContentType, ups[0].Body)
	}
	if ups[1].ContentType != "application/octet-stream" || string(ups[1].Body) != "raw" {
		t.Errorf("upload 2: Content-Type %q, body %q; want application/octet-stream and raw", ups[1].ContentType, ups[1].Body)
	}
}

// TestJMAP_TemplateEscaped checks that Download escapes each template
// value: a value cannot add a path segment, a query field or a
// fragment, and a "+" in the type stays a "+" for the server.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_TemplateEscaped(t *testing.T) {
	const blobID = "B/1 ?#"
	const name = "a b/../c#d.pdf"
	const typ = "image/svg+xml&evil=1"
	f := newFakeJMAP(t, fakeOpts{blobs: map[string][]byte{blobID: []byte("blob")}})
	body, _, err := f.client(nil, false).Download(context.Background(), blobID, name, typ)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	defer func() { _ = body.Close() }()
	if b, err := io.ReadAll(body); err != nil || string(b) != "blob" {
		t.Fatalf("Download body = %q, %v, want blob", b, err)
	}

	reqs := f.requests()
	got := reqs[len(reqs)-1].RequestURI
	want := "/jmap/download/" + fakeAccount + "/B%2F1%20%3F%23/a%20b%2F..%2Fc%23d.pdf?accept=image%2Fsvg%2Bxml%26evil%3D1"
	if got != want {
		t.Fatalf("request URI = %q, want %q", got, want)
	}
	u, err := url.ParseRequestURI(got)
	if err != nil {
		t.Fatalf("parse the request URI: %v", err)
	}
	q := u.Query()
	if len(q) != 1 || q.Get("accept") != typ {
		t.Fatalf("query = %v, want only accept=%q", q, typ)
	}

	if got := fillTemplate("https://h/{accountId}/{other}?a={type}&b={missing", map[string]string{"accountId": "x y", "type": "p q"}); got != "https://h/x%20y/{other}?a=p%20q&b={missing" {
		t.Fatalf("fillTemplate = %q", got)
	}
}

// TestJMAP_LargeAnswerPassesCap checks that an API answer of 200 KB
// passes the API client of GuardOptions (MaxAPIBody, DS8.3, T176), and
// that the 64 KiB client of T2.5 would cut it with guard.ErrTruncated.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_LargeAnswerPassesCap(t *testing.T) {
	const pad = 200 << 10
	f := newFakeJMAP(t, fakeOpts{pad: pad})
	ctx := context.Background()

	resp, err := f.client(nil, false).Call(ctx, mailboxGet("c0"))
	if err != nil {
		t.Fatalf("Call with a 200 KB answer: %v", err)
	}
	if got, _ := resp.MethodResponses[0].Args["pad"].(string); len(got) != pad {
		t.Fatalf("pad has %d bytes, want %d", len(got), pad)
	}

	old := New(f.sessionURL(), nil, f.defaultGuarded(), f.defaultGuarded(), false)
	if _, err := old.Call(ctx, mailboxGet("c0")); !errors.Is(err, guard.ErrTruncated) {
		t.Fatalf("Call through the 64 KiB client = %v, want guard.ErrTruncated", err)
	}
}

// TestJMAP_BlobAboveOldCap checks that Download gets a blob of 1 MiB
// whole through the blob client of GuardOptions (MaxBlobBody, DS8.3,
// T176), and that the 64 KiB client of T2.5 would cut it with
// guard.ErrTruncated.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_BlobAboveOldCap(t *testing.T) {
	blob := make([]byte, 1<<20)
	if _, err := rand.Read(blob); err != nil {
		t.Fatal(err)
	}
	f := newFakeJMAP(t, fakeOpts{blobs: map[string][]byte{"B1": blob}})
	ctx := context.Background()

	body, size, err := f.client(nil, false).Download(ctx, "B1", "m.eml", "message/rfc822")
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	got, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil {
		t.Fatalf("read the 1 MiB blob: %v", err)
	}
	if size != int64(len(blob)) || !bytes.Equal(got, blob) {
		t.Fatalf("blob: size %d, %d bytes read; want %d and the same bytes", size, len(got), len(blob))
	}

	api, _ := GuardOptions("")
	api.Base = f.srv.Client().Transport
	old := New(f.sessionURL(), nil, guard.NewHTTPClientFor(api), f.defaultGuarded(), false)
	body, _, err = old.Download(ctx, "B1", "m.eml", "message/rfc822")
	if err != nil {
		t.Fatalf("Download through the 64 KiB client: %v", err)
	}
	_, err = io.ReadAll(body)
	_ = body.Close()
	if !errors.Is(err, guard.ErrTruncated) {
		t.Fatalf("read through the 64 KiB client = %v, want guard.ErrTruncated", err)
	}
}

// TestJMAP_401IsAuthError checks that a 401 gives *AuthError (DRV.10):
// on the session GET, on a call that gets a 401 again after the one
// refetch, on a download and on an upload.
//
// arch: DS8.1, DS8.3, DS8.7, IS8.1, IS8.3, IS78.1, G10
func TestJMAP_401IsAuthError(t *testing.T) {
	ctx := context.Background()
	isAuth := func(t *testing.T, what string, err error) {
		t.Helper()
		var ae *AuthError
		if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
			t.Fatalf("%s = %v, want *AuthError with status 401", what, err)
		}
		if got, want := err.Error(), "jmap: login refused by the server (HTTP 401)"; got != want {
			t.Fatalf("%s text = %q, want %q", what, got, want)
		}
	}

	f := newFakeJMAP(t, fakeOpts{wantAuth: "Bearer good"})
	_, err := f.client(BearerAuth("bad"), false).Session(ctx)
	isAuth(t, "Session with a bad token", err)

	f = newFakeJMAP(t, fakeOpts{apiStatus: []int{401, 401, 401}})
	_, err = f.client(nil, false).Call(ctx, mailboxGet("c0"))
	isAuth(t, "Call with two 401s", err)
	if gets, posts := f.counts(); gets != 2 || posts != 2 {
		t.Fatalf("%d session GETs and %d API POSTs, want 2 and 2", gets, posts)
	}

	f = newFakeJMAP(t, fakeOpts{blobStatus: http.StatusUnauthorized})
	c := f.client(nil, false)
	_, _, err = c.Download(ctx, "B1", "n", "text/plain")
	isAuth(t, "Download", err)
	_, err = c.Upload(ctx, "text/plain", strings.NewReader("x"), 1)
	isAuth(t, "Upload", err)
}

// TestJMAP_LimitErrorRetried checks that Call sends the request again
// after the request error urn:ietf:params:jmap:error:limit (RFC 8620
// §3.6.1), and that it gives the answer of the next try. The server
// did not process the refused request, so a new try is safe.
//
// arch: DS8.1, DS8.7, G10
func TestJMAP_LimitErrorRetried(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{limitPosts: 2})
	resp, err := f.client(nil, false).Call(context.Background(), mailboxGet("c0"))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if len(resp.MethodResponses) != 1 || resp.MethodResponses[0].ID != "c0" {
		t.Fatalf("responses = %v, want one for c0", resp.MethodResponses)
	}
	if _, posts := f.counts(); posts != 3 {
		t.Fatalf("%d API POSTs, want 3 (two limit errors, then the answer)", posts)
	}
}

// TestJMAP_LimitErrorRetryBounded checks that Call stops after a fixed
// number of tries when the server gives the limit error each time, and
// that the error then names the limit type.
//
// arch: DS8.1, DS8.7, G10
func TestJMAP_LimitErrorRetryBounded(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{limitPosts: 100})
	_, err := f.client(nil, false).Call(context.Background(), mailboxGet("c0"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 400 urn:ietf:params:jmap:error:limit") {
		t.Fatalf("Call error = %v, want the limit error", err)
	}
	if _, posts := f.counts(); posts != limitTries {
		t.Fatalf("%d API POSTs, want %d", posts, limitTries)
	}
}

// TestJMAP_LimitRetryStopsOnCancel checks that the wait before a new
// try ends when the ctx ends.
//
// arch: DS8.1, DS8.7, G10
func TestJMAP_LimitRetryStopsOnCancel(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{limitPosts: 100})
	c := f.client(nil, false)
	if _, err := c.Session(context.Background()); err != nil {
		t.Fatalf("Session: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			if _, posts := f.counts(); posts >= 1 {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	_, err := c.Call(ctx, mailboxGet("c0"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Call error = %v, want context.Canceled", err)
	}
	if _, posts := f.counts(); posts >= limitTries {
		t.Fatalf("%d API POSTs after the cancel, want fewer than %d", posts, limitTries)
	}
}

// TestJMAP_OtherRequestErrorNotRetried checks that Call does not send
// the request again after a request error that is not the limit error.
//
// arch: DS8.1, DS8.7, G10
func TestJMAP_OtherRequestErrorNotRetried(t *testing.T) {
	f := newFakeJMAP(t, fakeOpts{apiStatus: []int{http.StatusBadRequest}})
	if _, err := f.client(nil, false).Call(context.Background(), mailboxGet("c0")); err == nil {
		t.Fatal("Call error = nil, want the notRequest error")
	}
	if _, posts := f.counts(); posts != 1 {
		t.Fatalf("%d API POSTs, want 1", posts)
	}
}

// TestJMAP_ConcurrentCallsCapped checks that one client never has more
// API requests in flight than maxConcurrentRequests of the session
// (RFC 8620 §2), and the default when the session gives none.
//
// arch: DS8.1, DS8.7, G10
func TestJMAP_ConcurrentCallsCapped(t *testing.T) {
	cases := []struct {
		name string
		edit func(int, string, map[string]any)
		want int
	}{
		{"from the session", func(_ int, _ string, s map[string]any) {
			s["capabilities"].(map[string]any)[usingCore].(map[string]any)["maxConcurrentRequests"] = 2
		}, 2},
		{"absent", func(_ int, _ string, s map[string]any) {
			delete(s["capabilities"].(map[string]any)[usingCore].(map[string]any), "maxConcurrentRequests")
		}, defaultConcurrentRequests},
		{"zero", func(_ int, _ string, s map[string]any) {
			s["capabilities"].(map[string]any)[usingCore].(map[string]any)["maxConcurrentRequests"] = 0
		}, defaultConcurrentRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeJMAP(t, fakeOpts{editSession: tc.edit, apiDelay: 20 * time.Millisecond})
			c := f.client(nil, false)
			var wg sync.WaitGroup
			errs := make(chan error, 12)
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := c.Call(context.Background(), mailboxGet("c0")); err != nil {
						errs <- err
					}
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Fatalf("Call: %v", err)
			}
			if got := f.maxAPIInFlight(); got != tc.want {
				t.Fatalf("%d API POSTs in flight at most, want %d", got, tc.want)
			}
		})
	}
}
