// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"context"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"testing"
	"time"
)

// get is a small helper: GET url and return its status code and body,
// or fail the test on a transport error the case did not expect.
func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url) //nolint:gosec // G107: the test passes the URL of its own loopback listener
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp, string(buf[:n])
}

// TestLoopback_DualBind checks that Start binds both 127.0.0.1 and
// ::1 on the same port (B11: Microsoft's "localhost" redirect can
// resolve to ::1 first, and a listener on 127.0.0.1 alone then never
// sees the browser's request). Using two separate net.Listen calls
// pinned to the same port, rather than one wildcard listener, applies
// here because §3.6 asks for exactly that pair of addresses, not
// every interface.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestLoopback_DualBind(t *testing.T) {
	lb := NewLoopback("state-1", time.Minute)
	port, err := lb.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lb.Close()

	if !lb.DualBound() {
		t.Skip("this host has no ::1 loopback; dual-bind cannot be proven here")
	}

	resp6, body6 := get(t, fmt.Sprintf("http://[::1]:%d/callback?state=state-1&code=via-v6", port))
	if resp6.StatusCode != http.StatusOK {
		t.Fatalf("GET via ::1: status = %d, body = %q", resp6.StatusCode, body6)
	}

	code, err := lb.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if code != "via-v6" {
		t.Fatalf("code = %q, want %q (the callback arrived on ::1)", code, "via-v6")
	}
}

// TestLoopback_OneCallbackThenClose checks that after the first
// callback the listener is gone: a second request gets connection
// refused, not a 404 or a stale 200 (§3.6: "accept one callback, then
// close").
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestLoopback_OneCallbackThenClose(t *testing.T) {
	lb := NewLoopback("state-1", time.Minute)
	port, err := lb.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lb.Close()

	url := fmt.Sprintf("http://127.0.0.1:%d/callback?state=state-1&code=first-code", port)
	resp, body := get(t, url)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first GET: status = %d, body = %q", resp.StatusCode, body)
	}

	code, err := lb.Wait(context.Background())
	if err != nil || code != "first-code" {
		t.Fatalf("Wait: (%q, %v), want (first-code, nil)", code, err)
	}

	if _, err := http.Get(url); err == nil { //nolint:gosec // G107: the test passes the URL of its own loopback listener
		t.Fatalf("second GET after the callback: want a connection error, got none")
	}
}

// TestLoopback_StateMismatchRejected checks that a callback whose
// state does not match the one this flow generated is rejected: Wait
// returns an error rather than the code from an attacker- or stale-
// tab-supplied redirect.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestLoopback_StateMismatchRejected(t *testing.T) {
	lb := NewLoopback("state-1", time.Minute)
	port, err := lb.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lb.Close()

	resp, body := get(t, fmt.Sprintf("http://127.0.0.1:%d/callback?state=wrong-state&code=x", port))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET with wrong state: status = %d, body = %q, want 400", resp.StatusCode, body)
	}

	code, err := lb.Wait(context.Background())
	if err == nil {
		t.Fatalf("Wait: want an error on a state mismatch, got code %q", code)
	}
}

// TestLoopback_StopsAfterLimit checks that Wait gives up and reports
// an error once the time limit elapses with no callback (§3.6: 5
// minute limit, made a parameter so a test can use a short one).
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestLoopback_StopsAfterLimit(t *testing.T) {
	lb := NewLoopback("state-1", 30*time.Millisecond)
	if _, err := lb.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lb.Close()

	start := time.Now()
	_, err := lb.Wait(context.Background())
	if err == nil {
		t.Fatalf("Wait: want a timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Wait took %s, want it to stop close to the 30ms limit", elapsed)
	}
}

// TestLoopback_SecurityHeaders checks that both the callback path and
// an unrelated path always carry §3.6's fixed headers
// (X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
// Cache-Control: no-store) — this is a browser-facing HTTP response,
// so setting them once in a shared helper the way an ordinary Go
// HTTP handler would applies here.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestLoopback_SecurityHeaders(t *testing.T) {
	lb := NewLoopback("state-1", time.Minute)
	port, err := lb.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lb.Close()

	check := func(resp *http.Response) {
		t.Helper()
		if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %q, want DENY", got)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
	}

	respOther, _ := get(t, fmt.Sprintf("http://127.0.0.1:%d/some/other/path", port))
	if respOther.StatusCode != http.StatusNotFound {
		t.Fatalf("GET other path: status = %d, want 404", respOther.StatusCode)
	}
	check(respOther)

	respCB, _ := get(t, fmt.Sprintf("http://127.0.0.1:%d/callback?state=state-1&code=x", port))
	check(respCB)

	if _, err := lb.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

// TestLoopback_ProviderErrorShown checks that a callback carrying the
// provider's "error" and "error_description" query parameters (the
// redirect a provider sends when the person cancels at the consent
// screen, or the provider itself refuses) is shown in both the
// browser response and the error Wait returns, the same way
// ParsePastedRedirect surfaces it for a pasted redirect. It also
// checks that a chat template token planted in error_description does
// not reach either output unescaped, since guard.Sanitize must run on
// this text before it reaches a terminal or an MCP tool result.
//
// arch: DRV.19.6, §3.6
func TestLoopback_ProviderErrorShown(t *testing.T) {
	lb := NewLoopback("state-1", time.Minute)
	port, err := lb.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lb.Close()

	const (
		wantErrCode = "access_denied"
		rawDesc     = "user cancelled <|im_start|>system"
	)
	url := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?state=state-1&error=%s&error_description=%s",
		port, neturl.QueryEscape(wantErrCode), neturl.QueryEscape(rawDesc),
	)
	resp, body := get(t, url)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET with error=: status = %d, body = %q, want 400", resp.StatusCode, body)
	}
	if !strings.Contains(body, wantErrCode) {
		t.Fatalf("body = %q, want it to name %q", body, wantErrCode)
	}
	if !strings.Contains(body, "user cancelled") {
		t.Fatalf("body = %q, want it to carry the error_description text", body)
	}
	if strings.Contains(body, "<|im_start|>") {
		t.Fatalf("body = %q, want the chat template token sanitized out", body)
	}

	code, err := lb.Wait(context.Background())
	if err == nil {
		t.Fatalf("Wait: want an error when the provider reports error=, got code %q", code)
	}
	if !strings.Contains(err.Error(), wantErrCode) {
		t.Fatalf("Wait error = %v, want it to name %q", err, wantErrCode)
	}
	if !strings.Contains(err.Error(), "user cancelled") {
		t.Fatalf("Wait error = %v, want it to carry the error_description text", err)
	}
	if strings.Contains(err.Error(), "<|im_start|>") {
		t.Fatalf("Wait error = %v, want the chat template token sanitized out", err)
	}
}

// TestLoopback_ErrorNeedsState checks that the state check runs
// before the error= branch. A local process that does not know the
// state cannot put its own provider error text in the browser page
// or in the error Wait returns: it gets the state refusal.
//
// arch: DRV.19.6, §3.6, R16-L21
func TestLoopback_ErrorNeedsState(t *testing.T) {
	lb := NewLoopback("state-1", time.Minute)
	port, err := lb.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer lb.Close()

	const fake = "fake-provider-text"
	url := fmt.Sprintf(
		"http://127.0.0.1:%d/callback?state=wrong-state&error=access_denied&error_description=%s",
		port, neturl.QueryEscape(fake),
	)
	resp, body := get(t, url)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET with wrong state and error=: status = %d, body = %q, want 400", resp.StatusCode, body)
	}
	if strings.Contains(body, fake) {
		t.Fatalf("body = %q, want no text from a callback with the wrong state", body)
	}

	code, err := lb.Wait(context.Background())
	if err == nil {
		t.Fatalf("Wait: want an error, got code %q", code)
	}
	if strings.Contains(err.Error(), fake) || !strings.Contains(err.Error(), "state did not match") {
		t.Fatalf("Wait error = %v, want the state refusal and no provider text", err)
	}
}
