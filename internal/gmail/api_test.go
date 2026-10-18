// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Gmail REST client (DS7.3) against fakeGmail: the retry
// rules, the 401 refresh, the fixed errors, the error text and the
// body cap. No test waits for a backoff: sleep and jitter are fields.

package gmail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
)

// idAnswer is the decoded answer of most tests below.
type idAnswer struct {
	ID string `json:"id"`
}

// wantWaits fails the test when the waits differ from want.
func wantWaits(t *testing.T, p *probe, want ...time.Duration) {
	t.Helper()
	got := p.gotWaits()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("waits = %v, want %v", got, want)
	}
}

// wantAPIError gives err as *APIError and fails the test when it is
// not one or has another status.
func wantAPIError(t *testing.T, err error, status int) *APIError {
	t.Helper()
	var e *APIError
	if !errors.As(err, &e) {
		t.Fatalf("error = %v (%T), want *APIError", err, err)
	}
	if e.Status != status {
		t.Fatalf("status = %d, want %d", e.Status, status)
	}
	return e
}

// TestAPI_BackoffOn429 holds the DS7.3 backoff: two 429 answers wait
// 1 s and 2 s plus the jitter, and the third try gets the answer. Each
// try carries the token and the query.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_BackoffOn429(t *testing.T) {
	limit := googleError(429, "RESOURCE_EXHAUSTED", "rateLimitExceeded", "", "Too many requests")
	f := newFakeGmail(t,
		step{status: 429, body: limit},
		step{status: 429, body: limit},
		step{status: 200, body: `{"id":"m-1"}`},
	)
	a, p := f.api(staticToken("tok-1"))
	a.jitter = func() time.Duration { return 300 * time.Millisecond }

	var out idAnswer
	if err := a.Get(context.Background(), "messages/m-1", url.Values{"format": {"minimal"}}, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.ID != "m-1" {
		t.Fatalf("id = %q, want m-1", out.ID)
	}
	reqs := f.requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d, want 3", len(reqs))
	}
	for i, r := range reqs {
		if r.Method != http.MethodGet || r.Path != "/gmail/v1/users/me/messages/m-1" ||
			r.RawQuery != "format=minimal" || r.Auth != "Bearer tok-1" {
			t.Fatalf("request %d = %+v", i, r)
		}
	}
	wantWaits(t, p, 1300*time.Millisecond, 2300*time.Millisecond)
	if len(p.gotAuth()) != 0 {
		t.Fatalf("auth events = %v, want none", p.gotAuth())
	}
}

// TestAPI_403RateIsRetried holds DS7.3: a 403 with the reason
// rateLimitExceeded or userRateLimitExceeded is tried again; a 403
// with another reason is not.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_403RateIsRetried(t *testing.T) {
	t.Run("rate limits", func(t *testing.T) {
		f := newFakeGmail(t,
			step{status: 403, body: googleError(403, "PERMISSION_DENIED", "rateLimitExceeded", "", "Rate Limit Exceeded")},
			step{status: 403, body: googleError(403, "PERMISSION_DENIED", "userRateLimitExceeded", "", "User Rate Limit Exceeded")},
			step{status: 200, body: `{"id":"m-2"}`},
		)
		a, p := f.api(staticToken("tok-1"))
		var out idAnswer
		if err := a.Get(context.Background(), "messages/m-2", nil, &out); err != nil {
			t.Fatalf("Get: %v", err)
		}
		if out.ID != "m-2" || len(f.requests()) != 3 {
			t.Fatalf("id = %q, requests = %d; want m-2 and 3", out.ID, len(f.requests()))
		}
		wantWaits(t, p, 1*time.Second, 2*time.Second)
	})
	t.Run("other 403", func(t *testing.T) {
		f := newFakeGmail(t,
			step{status: 403, body: googleError(403, "PERMISSION_DENIED", "forbidden", "", "Forbidden")},
		)
		a, p := f.api(staticToken("tok-1"))
		err := a.Get(context.Background(), "messages/m-2", nil, nil)
		if e := wantAPIError(t, err, 403); e.Reason != "forbidden" {
			t.Fatalf("reason = %q, want forbidden", e.Reason)
		}
		if n := len(f.requests()); n != 1 {
			t.Fatalf("requests = %d, want 1", n)
		}
		wantWaits(t, p)
	})
}

// TestAPI_5xxRetried4Times holds DS7.3: a 5xx answer gets 4 tries in
// total with waits of 1 s, 2 s and 4 s, then the call gives the
// *APIError of the last answer.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_5xxRetried4Times(t *testing.T) {
	for _, code := range []int{500, 502, 503, 504} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			f := newFakeGmail(t, step{status: code, body: googleError(code, "UNAVAILABLE", "backendError", "", "Backend Error")})
			a, p := f.api(staticToken("tok-1"))
			err := a.Post(context.Background(), "messages/batchModify", nil, map[string]any{"ids": []string{"m-1"}}, nil)
			if e := wantAPIError(t, err, code); e.Reason != "backendError" {
				t.Fatalf("reason = %q, want backendError", e.Reason)
			}
			if n := len(f.requests()); n != maxTries || maxTries != 4 {
				t.Fatalf("requests = %d, maxTries = %d; want 4 and 4", n, maxTries)
			}
			wantWaits(t, p, 1*time.Second, 2*time.Second, 4*time.Second)
		})
	}
}

// TestAPI_RetryAfterWins holds DS7.3: a Retry-After value in seconds
// or as an HTTP date replaces the backoff and its jitter.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_RetryAfterWins(t *testing.T) {
	date := time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)
	f := newFakeGmail(t,
		step{status: 429, header: map[string]string{"Retry-After": "7"}, body: googleError(429, "RESOURCE_EXHAUSTED", "rateLimitExceeded", "", "slow down")},
		step{status: 503, header: map[string]string{"Retry-After": date}, body: googleError(503, "UNAVAILABLE", "backendError", "", "later")},
		step{status: 200, body: `{"id":"m-3"}`},
	)
	a, p := f.api(staticToken("tok-1"))
	a.jitter = func() time.Duration { return 500 * time.Millisecond }

	var out idAnswer
	if err := a.Get(context.Background(), "messages/m-3", nil, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	waits := p.gotWaits()
	if len(waits) != 2 {
		t.Fatalf("waits = %v, want 2", waits)
	}
	if waits[0] != 7*time.Second {
		t.Fatalf("wait 1 = %v, want 7s (Retry-After in seconds, no jitter)", waits[0])
	}
	if waits[1] < 8*time.Second || waits[1] > 10*time.Second {
		t.Fatalf("wait 2 = %v, want 8s to 10s (Retry-After as an HTTP date)", waits[1])
	}
}

// TestAPI_StopsAtDeadline holds DS7.3: a wait that ends after the ctx
// deadline stops the call at once with the last *APIError, and a ctx
// that ends during a wait stops the wait.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_StopsAtDeadline(t *testing.T) {
	limit := googleError(429, "RESOURCE_EXHAUSTED", "rateLimitExceeded", "", "Too many requests")
	t.Run("wait past the deadline", func(t *testing.T) {
		f := newFakeGmail(t, step{status: 429, body: limit})
		a, p := f.api(staticToken("tok-1"))
		ctx, cancel := context.WithTimeout(context.Background(), 3500*time.Millisecond)
		defer cancel()
		err := a.Get(ctx, "labels", nil, nil)
		_ = wantAPIError(t, err, 429)
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			t.Fatalf("error = %v, ctx = %v; want the API error before the deadline", err, ctx.Err())
		}
		if n := len(f.requests()); n != 3 {
			t.Fatalf("requests = %d, want 3 (the 4 s wait ends after the deadline)", n)
		}
		wantWaits(t, p, 1*time.Second, 2*time.Second)
	})
	t.Run("ctx ends during the wait", func(t *testing.T) {
		f := newFakeGmail(t, step{status: 429, body: limit})
		a, _ := f.api(staticToken("tok-1"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		a.sleep = func(ctx context.Context, d time.Duration) error {
			time.AfterFunc(20*time.Millisecond, cancel)
			return sleepCtx(ctx, d)
		}
		start := time.Now()
		err := a.Get(ctx, "labels", nil, nil)
		_ = wantAPIError(t, err, 429)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want it to wrap context.Canceled", err)
		}
		if d := time.Since(start); d > 900*time.Millisecond {
			t.Fatalf("call took %v, want it to stop when ctx ends", d)
		}
		if n := len(f.requests()); n != 1 {
			t.Fatalf("requests = %d, want 1", n)
		}
	})
}

// TestAPI_SendRetriesOnlyOn429 holds IS7.3: a sendOnce call (drafts.send)
// is tried again on 429 only, never on a 5xx or a 403 rate limit.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_SendRetriesOnlyOn429(t *testing.T) {
	for _, c := range []struct {
		name string
		s    step
	}{
		{"500", step{status: 500, body: googleError(500, "INTERNAL", "backendError", "", "Backend Error")}},
		{"503", step{status: 503, body: googleError(503, "UNAVAILABLE", "backendError", "", "Backend Error")}},
		{"403 rateLimitExceeded", step{status: 403, body: googleError(403, "PERMISSION_DENIED", "rateLimitExceeded", "", "Rate Limit Exceeded")}},
		{"403 userRateLimitExceeded", step{status: 403, body: googleError(403, "PERMISSION_DENIED", "userRateLimitExceeded", "", "User Rate Limit Exceeded")}},
	} {
		s := c.s
		t.Run(c.name, func(t *testing.T) {
			f := newFakeGmail(t, s, step{status: 200, body: `{"id":"sent-1"}`})
			a, p := f.api(staticToken("tok-1"))
			err := a.sendOnce(context.Background(), "drafts/send", map[string]string{"id": "r-1"}, nil)
			_ = wantAPIError(t, err, s.status)
			if n := len(f.requests()); n != 1 {
				t.Fatalf("requests = %d, want 1", n)
			}
			wantWaits(t, p)
		})
	}
	t.Run("429", func(t *testing.T) {
		f := newFakeGmail(t,
			step{status: 429, body: googleError(429, "RESOURCE_EXHAUSTED", "rateLimitExceeded", "", "Too many requests")},
			step{status: 200, body: `{"id":"sent-1"}`},
		)
		a, p := f.api(staticToken("tok-1"))
		var out idAnswer
		if err := a.sendOnce(context.Background(), "drafts/send", map[string]string{"id": "r-1"}, &out); err != nil {
			t.Fatalf("sendOnce: %v", err)
		}
		if out.ID != "sent-1" {
			t.Fatalf("id = %q, want sent-1", out.ID)
		}
		reqs := f.requests()
		if len(reqs) != 2 {
			t.Fatalf("requests = %d, want 2", len(reqs))
		}
		for i, r := range reqs {
			if r.Method != http.MethodPost || r.Path != "/gmail/v1/users/me/drafts/send" ||
				r.ContentType != "application/json" || string(r.Body) != `{"id":"r-1"}` {
				t.Fatalf("request %d = %+v", i, r)
			}
		}
		wantWaits(t, p, 1*time.Second)
	})
}

// TestAPI_401ForgetsAndRetriesOnce holds IS7.2: the first 401 goes to
// onAuth, which drops the token, and the one new try carries a new
// token.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_401ForgetsAndRetriesOnce(t *testing.T) {
	f := newFakeGmail(t,
		step{status: 401, body: googleError(401, "UNAUTHENTICATED", "authError", "", "Invalid Credentials")},
		step{status: 200, body: `{"id":"m-4"}`},
	)
	var n atomic.Int32
	a, p := f.api(func(context.Context) (string, error) {
		return "tok-" + strconv.Itoa(int(n.Add(1))), nil
	})
	var out idAnswer
	if err := a.Get(context.Background(), "messages/m-4", nil, &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.ID != "m-4" {
		t.Fatalf("id = %q, want m-4", out.ID)
	}
	reqs := f.requests()
	if len(reqs) != 2 || reqs[0].Auth != "Bearer tok-1" || reqs[1].Auth != "Bearer tok-2" {
		t.Fatalf("requests = %+v, want tok-1 then tok-2", reqs)
	}
	auth := p.gotAuth()
	if len(auth) != 1 {
		t.Fatalf("auth events = %v, want 1", auth)
	}
	_ = wantAPIError(t, auth[0], 401)
	wantWaits(t, p)
}

// TestAPI_Second401IsNeedsAuth holds IS7.2: a second 401 in one call
// gives oauthpkg.ErrNeedsAuth, and onAuth gets it too, so the Factory
// notes needs_sign_in.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_Second401IsNeedsAuth(t *testing.T) {
	f := newFakeGmail(t,
		step{status: 401, body: googleError(401, "UNAUTHENTICATED", "authError", "", "Invalid Credentials")},
	)
	a, p := f.api(staticToken("tok-1"))
	err := a.Get(context.Background(), "labels", nil, nil)
	if !errors.Is(err, oauthpkg.ErrNeedsAuth) {
		t.Fatalf("error = %v, want ErrNeedsAuth", err)
	}
	if n := len(f.requests()); n != 2 {
		t.Fatalf("requests = %d, want 2", n)
	}
	auth := p.gotAuth()
	if len(auth) != 2 {
		t.Fatalf("auth events = %v, want 2", auth)
	}
	_ = wantAPIError(t, auth[0], 401)
	if !errors.Is(auth[1], oauthpkg.ErrNeedsAuth) {
		t.Fatalf("auth event 2 = %v, want ErrNeedsAuth", auth[1])
	}
}

// fixedCase is one answer that must give a fixed error.
type fixedCase struct {
	name string
	body string
}

// checkFixed calls the fake with the case and wants the fixed error
// want: one request, no wait, the fixed text with no server text, and
// want sent to onAuth (DS7.3, IS7.5).
func checkFixed(t *testing.T, c fixedCase, want error) {
	t.Helper()
	f := newFakeGmail(t, step{status: 403, body: c.body})
	a, p := f.api(staticToken("tok-1"))
	err := a.Get(context.Background(), "labels", nil, nil)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if err.Error() != want.Error() || strings.Contains(err.Error(), "123456789012") {
		t.Fatalf("error text = %q, want the fixed text only", err.Error())
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("requests = %d, want 1", n)
	}
	wantWaits(t, p)
	auth := p.gotAuth()
	if len(auth) != 1 || !errors.Is(auth[0], want) {
		t.Fatalf("auth events = %v, want [%v]", auth, want)
	}
}

// TestAPI_AccessNotConfiguredIsFixedError holds DS7.3 and DS7.7: a 403
// with the reason accessNotConfigured or the detail SERVICE_DISABLED
// gives ErrAPIDisabled with its fixed text, and onAuth gets it.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_AccessNotConfiguredIsFixedError(t *testing.T) {
	msg := "Gmail API has not been used in project 123456789012 before or it is disabled."
	for _, c := range []fixedCase{
		{"accessNotConfigured", googleError(403, "PERMISSION_DENIED", "accessNotConfigured", "SERVICE_DISABLED", msg)},
		{"SERVICE_DISABLED only", googleError(403, "PERMISSION_DENIED", "", "SERVICE_DISABLED", msg)},
	} {
		t.Run(c.name, func(t *testing.T) { checkFixed(t, c, ErrAPIDisabled) })
	}
}

// TestAPI_ScopeIsFixedError holds DS7.3: a 403 with the reason
// insufficientPermissions or ACCESS_TOKEN_SCOPE_INSUFFICIENT gives
// ErrScope with its fixed text, and onAuth gets it.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_ScopeIsFixedError(t *testing.T) {
	msg := "Request had insufficient authentication scopes for project 123456789012."
	for _, c := range []fixedCase{
		{"insufficientPermissions", googleError(403, "PERMISSION_DENIED", "insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", msg)},
		{"ACCESS_TOKEN_SCOPE_INSUFFICIENT only", googleError(403, "PERMISSION_DENIED", "", "ACCESS_TOKEN_SCOPE_INSUFFICIENT", msg)},
	} {
		t.Run(c.name, func(t *testing.T) { checkFixed(t, c, ErrScope) })
	}
}

// TestAPI_ErrorTextHasNoServerMessage holds IS7.5: the error text is
// "gmail: HTTP <status> <reason>" with no server message; the message
// goes to the log once, at WARN, after guard.Redact; a reason that is
// not an identifier never reaches the text.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_ErrorTextHasNoServerMessage(t *testing.T) {
	guard.RegisterSecret("123456789012")
	msg := "Invalid label name for project 123456789012: Label_private"

	t.Run("message in the log only", func(t *testing.T) {
		f := newFakeGmail(t, step{status: 400, body: googleError(400, "INVALID_ARGUMENT", "invalidArgument", "", msg)})
		a, p := f.api(staticToken("tok-1"))
		err := a.Post(context.Background(), "labels", nil, map[string]string{"name": "x"}, nil)
		_ = wantAPIError(t, err, 400)
		if got := err.Error(); got != "gmail: HTTP 400 invalidArgument" {
			t.Fatalf("error text = %q, want %q", got, "gmail: HTTP 400 invalidArgument")
		}
		log := p.logText()
		if n := strings.Count(log, "level=WARN"); n != 1 || strings.Count(log, "\n") != 1 {
			t.Fatalf("log = %q, want one WARN line", log)
		}
		if !strings.Contains(log, "Invalid label name for project <redacted>") || strings.Contains(log, "123456789012") {
			t.Fatalf("log = %q, want the message with the project number redacted", log)
		}
	})
	t.Run("retried call logs once", func(t *testing.T) {
		f := newFakeGmail(t, step{status: 503, body: googleError(503, "UNAVAILABLE", "backendError", "", msg)})
		a, p := f.api(staticToken("tok-1"))
		err := a.Get(context.Background(), "labels", nil, nil)
		if strings.Contains(err.Error(), "Invalid label") || strings.Contains(err.Error(), "123456789012") {
			t.Fatalf("error text = %q holds the server message", err.Error())
		}
		if n := strings.Count(p.logText(), "level=WARN"); n != 1 {
			t.Fatalf("WARN lines = %d, want 1", n)
		}
	})
	t.Run("reason that is not an identifier", func(t *testing.T) {
		f := newFakeGmail(t, step{status: 404, body: googleError(404, "NOT_FOUND", "see project 123456789012", "", msg)})
		a, _ := f.api(staticToken("tok-1"))
		err := a.Get(context.Background(), "messages/m-9", nil, nil)
		if got := err.Error(); got != "gmail: HTTP 404 NOT_FOUND" {
			t.Fatalf("error text = %q, want %q", got, "gmail: HTTP 404 NOT_FOUND")
		}
	})
	t.Run("answer that is not a Google error", func(t *testing.T) {
		f := newFakeGmail(t, step{status: 404, body: "<html>" + msg + "</html>"})
		a, p := f.api(staticToken("tok-1"))
		err := a.Get(context.Background(), "messages/m-9", nil, nil)
		if got := err.Error(); got != "gmail: HTTP 404" {
			t.Fatalf("error text = %q, want %q", got, "gmail: HTTP 404")
		}
		if strings.Contains(p.logText(), "123456789012") {
			t.Fatalf("log = %q holds the project number", p.logText())
		}
	})
}

// TestAPI_BodyCap holds DS7.3: New caps an answer at 64 MiB, an answer
// of the cap size passes, and one byte more fails with the fixed text
// and no new try.
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_BodyCap(t *testing.T) {
	if a := New(staticToken("tok-1"), nil); a.maxBody != 64*1024*1024 {
		t.Fatalf("maxBody = %d, want 64 MiB", a.maxBody)
	}
	const limit = 1024
	answer := func(size int) string {
		s := `{"id":"m-5"}`
		return s + strings.Repeat(" ", size-len(s))
	}

	f := newFakeGmail(t, step{status: 200, body: answer(limit)})
	a, _ := f.api(staticToken("tok-1"))
	a.maxBody = limit
	var out idAnswer
	if err := a.Get(context.Background(), "messages/m-5", nil, &out); err != nil || out.ID != "m-5" {
		t.Fatalf("Get at the cap: id = %q, err = %v; want m-5 and nil", out.ID, err)
	}

	for _, status := range []int{200, 503} {
		f := newFakeGmail(t, step{status: status, body: answer(limit + 1)})
		a, p := f.api(staticToken("tok-1"))
		a.maxBody = limit
		err := a.Get(context.Background(), "messages/m-5", nil, &idAnswer{})
		if !errors.Is(err, errBodyTooLarge) || err.Error() != "gmail: the answer is larger than 64 MiB" {
			t.Fatalf("status %d: error = %v, want the fixed body cap text", status, err)
		}
		if n := len(f.requests()); n != 1 {
			t.Fatalf("status %d: requests = %d, want 1", status, n)
		}
		wantWaits(t, p)
	}
}

// TestAPI_RequestShapes checks the wire form of Patch, Delete and
// Upload: Upload sends multipart/related to uploadURL with
// uploadType=multipart, part 1 the JSON metadata and part 2 the raw
// message as message/rfc822 (§3.12 Send row).
//
// arch: DS7.3, DS7.7, DS7.9, IS7.2, IS7.3, IS7.5, IS78.1
func TestAPI_RequestShapes(t *testing.T) {
	f := newFakeGmail(t, step{status: 200, body: `{"id":"d-1"}`})
	a, _ := f.api(staticToken("tok-1"))
	ctx := context.Background()
	raw := []byte("From: a@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
	meta := map[string]any{"message": map[string]string{"threadId": "t-1"}}

	var out idAnswer
	if err := a.Upload(ctx, http.MethodPost, "drafts", meta, raw, &out); err != nil || out.ID != "d-1" {
		t.Fatalf("Upload: id = %q, err = %v", out.ID, err)
	}
	if err := a.Patch(ctx, "labels/Label_1", map[string]string{"name": "n"}, nil); err != nil {
		t.Fatalf("Patch: %v", err)
	}
	if err := a.Delete(ctx, "labels/Label_1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	reqs := f.requests()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d, want 3", len(reqs))
	}
	up := reqs[0]
	if up.Method != http.MethodPost || up.Path != "/upload/gmail/v1/users/me/drafts" || up.RawQuery != "uploadType=multipart" {
		t.Fatalf("upload request = %+v", up)
	}
	mt, params, err := mime.ParseMediaType(up.ContentType)
	if err != nil || mt != "multipart/related" || params["boundary"] == "" {
		t.Fatalf("upload Content-Type = %q (%v)", up.ContentType, err)
	}
	mr := multipart.NewReader(strings.NewReader(string(up.Body)), params["boundary"])
	wantParts := []struct{ ctype, body string }{
		{"application/json; charset=UTF-8", `{"message":{"threadId":"t-1"}}`},
		{"message/rfc822", string(raw)},
	}
	for i, w := range wantParts {
		p, err := mr.NextPart()
		if err != nil {
			t.Fatalf("part %d: %v", i+1, err)
		}
		b, _ := io.ReadAll(p)
		if p.Header.Get("Content-Type") != w.ctype || string(b) != w.body {
			t.Fatalf("part %d = %q %q, want %q %q", i+1, p.Header.Get("Content-Type"), b, w.ctype, w.body)
		}
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Fatalf("after part 2: %v, want io.EOF", err)
	}

	if r := reqs[1]; r.Method != http.MethodPatch || r.Path != "/gmail/v1/users/me/labels/Label_1" ||
		r.ContentType != "application/json" || !json.Valid(r.Body) || string(r.Body) != `{"name":"n"}` {
		t.Fatalf("patch request = %+v", r)
	}
	if r := reqs[2]; r.Method != http.MethodDelete || r.Path != "/gmail/v1/users/me/labels/Label_1" || len(r.Body) != 0 {
		t.Fatalf("delete request = %+v", r)
	}
}
