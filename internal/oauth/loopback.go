// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// LoopbackTimeout is the default time limit for one loopback callback
// flow (§3.6, B11): the browser is expected to redirect back well
// inside 5 minutes, and a listener held open longer than that is a
// port sitting around for no reason.
const LoopbackTimeout = 5 * time.Minute

// NewState returns 32 random bytes, base64url-encoded, for the OAuth
// "state" parameter (§3.6).
func NewState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("oauth: generating state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Loopback is a one-shot HTTP server for the OAuth redirect back to
// this machine (§3.6). It binds 127.0.0.1 and, when the host has it,
// ::1 on the same port, because localhost can resolve to ::1 first
// and a listener on 127.0.0.1 alone then never sees the browser's
// request (B11). It accepts exactly one callback and then stops
// listening; every response, including the ones this server never
// meant to serve, carries the fixed security headers of §3.6.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
type Loopback struct {
	state   string
	timeout time.Duration

	ln4 net.Listener
	ln6 net.Listener // nil when ::1 could not be bound

	result     chan loopbackResult
	acceptOnce sync.Once
	closeOnce  sync.Once
}

type loopbackResult struct {
	code string
	err  error
}

// NewLoopback creates a loopback callback server that accepts only a
// request whose "state" query parameter matches state (compared in
// constant time, §3.6). timeout <= 0 uses LoopbackTimeout; tests pass
// a short value so they do not have to wait 5 minutes to see the
// timeout path.
func NewLoopback(state string, timeout time.Duration) *Loopback {
	if timeout <= 0 {
		timeout = LoopbackTimeout
	}
	return &Loopback{
		state:   state,
		timeout: timeout,
		result:  make(chan loopbackResult, 1),
	}
}

// Start binds the callback listener and returns its port. The caller
// builds the redirect URL (http://127.0.0.1:<port>/callback or
// http://localhost:<port>/callback, §3.6) from that port and opens it
// in the browser; Start does not do that itself, because a test wants
// to drive the callback directly.
func (l *Loopback) Start() (int, error) {
	ln4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("oauth: binding the loopback callback on 127.0.0.1: %w", err)
	}
	l.ln4 = ln4
	port := ln4.Addr().(*net.TCPAddr).Port

	// Best effort: a host with IPv6 disabled still works on
	// 127.0.0.1 alone, only Google's flow (127.0.0.1-only redirect)
	// needs it there. Microsoft's "localhost" redirect needs both
	// (B11), so callers that need dual-bind guaranteed check ln6 != nil
	// themselves (DualBound reports it).
	if ln6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port)); err == nil {
		l.ln6 = ln6
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", l.handleCallback)
	mux.HandleFunc("/", l.handleOther)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go srv.Serve(l.ln4) //nolint:errcheck // Serve's only error on our own Close is expected
	if l.ln6 != nil {
		go srv.Serve(l.ln6) //nolint:errcheck // Serve's only error on our own Close is expected
	}
	return port, nil
}

// DualBound reports whether Start managed to bind ::1 as well as
// 127.0.0.1 (B11). It is false only when the host itself has no IPv6
// loopback.
func (l *Loopback) DualBound() bool {
	return l.ln6 != nil
}

func (l *Loopback) handleCallback(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	first := false
	l.acceptOnce.Do(func() { first = true })
	if !first {
		// A second, concurrent hit on the one callback path (for
		// example the same redirect arriving on both 127.0.0.1 and
		// ::1). Only the first counts; §3.6 says one callback.
		w.WriteHeader(http.StatusNotFound)
		return
	}

	q := r.URL.Query()
	state := q.Get("state")
	code := q.Get("code")

	var res loopbackResult
	switch {
	case !constantTimeEqual(state, l.state):
		// The state check comes first (R16-L21). Else a local
		// process that does not know the state can put its own
		// provider error text in the result.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, "state does not match this sign-in")
		res = loopbackResult{err: errors.New("oauth: loopback callback state did not match")}
	case q.Get("error") != "":
		// The provider refused, or the person cancelled at the
		// consent screen. Surface its reason the way
		// ParsePastedRedirect does for a pasted redirect (§3.6,
		// DRV.19.6) instead of falling through to the generic "no
		// authorization code" message below. guard.Sanitize runs
		// first because this text reaches a terminal and, through
		// the MCP tool result, a model — the same untrusted-text
		// path guard.Sanitize already covers for sender content.
		errCode := guard.Sanitize(q.Get("error"))
		var msg string
		if desc := guard.Sanitize(q.Get("error_description")); desc != "" {
			msg = fmt.Sprintf("sign-in was refused: %s (%s)", errCode, desc)
		} else {
			msg = fmt.Sprintf("sign-in was refused: %s", errCode)
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, msg) //nolint:gosec // G705: the body starts with fixed plain text and the handler sets text/plain, so no browser parses it as HTML
		res = loopbackResult{err: fmt.Errorf("oauth: %s", msg)}
	case code == "":
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprint(w, "no authorization code")
		res = loopbackResult{err: errors.New("oauth: loopback callback carried no authorization code")}
	default:
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "Sign-in complete. You can close this window.")
		res = loopbackResult{code: code}
	}

	// The response above is already written to w by the time we stop
	// listening, so this one request always finishes; only the next
	// one finds the door closed (§3.6: "accept one callback, then
	// close").
	l.closeListeners()
	l.result <- res
}

func (l *Loopback) handleOther(w http.ResponseWriter, _ *http.Request) {
	setSecurityHeaders(w)
	w.WriteHeader(http.StatusNotFound)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	// This is a one-shot server: closing the connection after every
	// response, rather than leaving it keep-alive, means closing the
	// listener in closeListeners() actually stops a second request
	// from reaching the handler over a connection the browser already
	// had open (§3.6: "accept one callback, then close").
	w.Header().Set("Connection", "close")
}

func (l *Loopback) closeListeners() {
	l.closeOnce.Do(func() {
		if l.ln4 != nil {
			_ = l.ln4.Close()
		}
		if l.ln6 != nil {
			_ = l.ln6.Close()
		}
	})
}

// Wait blocks until the one callback arrives, the time limit elapses,
// or ctx is done, then makes sure the listeners are closed either
// way.
func (l *Loopback) Wait(ctx context.Context) (string, error) {
	select {
	case res := <-l.result:
		return res.code, res.err
	case <-time.After(l.timeout):
		l.closeListeners()
		return "", fmt.Errorf("oauth: no sign-in callback within %s", l.timeout)
	case <-ctx.Done():
		l.closeListeners()
		return "", ctx.Err()
	}
}

// Close stops the listeners without waiting for a callback. Callers
// that give up on a Wait already in flight (context cancellation from
// outside, a CLI interrupt) use this to free the port immediately.
func (l *Loopback) Close() {
	l.closeListeners()
}
