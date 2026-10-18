// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"golang.org/x/oauth2"
)

// fakeStore is a Store that keeps the refresh token in memory, the
// way T41's adapter over secrets.Store will for a real account.
type fakeStore struct {
	mu      sync.Mutex
	current string
	loads   int
	saves   []string
	saveErr error
}

func (s *fakeStore) LoadRefreshToken() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	return s.current, nil
}

func (s *fakeStore) SaveRefreshToken(tok string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves = append(s.saves, tok)
	if s.saveErr != nil {
		return s.saveErr
	}
	s.current = tok
	return nil
}

// fakeTokenEndpoint runs an httptest server standing in for
// login.microsoftonline.com's token endpoint. respond decides the
// response purely from the refresh_token the request carries, which
// is what lets a single fake serve every scenario below (a real
// server that layers "does this refresh token still work" over HTTP,
// which is exactly what B7/B8 are about) rather than a hand-rolled
// oauth2.TokenSource stand-in: exercising the real oauth2.Config
// machinery is the point of these tests.
func fakeTokenEndpoint(t *testing.T, respond func(refreshToken string) (status int, body map[string]any)) *oauth2.Config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		status, body := respond(r.Form.Get("refresh_token"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return &oauth2.Config{
		ClientID: "client-1",
		Endpoint: oauth2.Endpoint{
			TokenURL:  srv.URL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

func tokenBody(accessToken, refreshToken string) map[string]any {
	body := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
	if refreshToken != "" {
		body["refresh_token"] = refreshToken
	}
	return body
}

func invalidGrantBody() map[string]any {
	return map[string]any{
		"error":             "invalid_grant",
		"error_description": "the refresh token is no longer valid",
	}
}

// TestTokenSource_RotationPersists checks that a refresh token which
// changes on the wire is saved to the store, and that the next
// Token() call presents the new one (B7). The fake issues a 1-second
// access token, inside the freshWindow of §3.6, so the second call is
// forced to refresh instead of returning the first call's token from
// cache.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestTokenSource_RotationPersists(t *testing.T) {
	var lastSeenRefresh string
	cfg := fakeTokenEndpoint(t, func(rt string) (int, map[string]any) {
		lastSeenRefresh = rt
		// Rotate: every refresh gets a new refresh token derived from
		// the one it was given. expires_in is short so this test's
		// second Token() call is not served from the freshness cache.
		body := tokenBody("at-"+rt, "rt-2-from-"+rt)
		body["expires_in"] = 1
		return http.StatusOK, body
	})
	store := &fakeStore{current: "rt-1"}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "at-rt-1" {
		t.Fatalf("AccessToken = %q, want at-rt-1", tok.AccessToken)
	}
	if len(store.saves) != 1 || store.saves[0] != "rt-2-from-rt-1" {
		t.Fatalf("store.saves = %v, want exactly [rt-2-from-rt-1]", store.saves)
	}

	// The next Token() call must present the rotated refresh token,
	// not the original one.
	if _, err := ts.Token(); err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if lastSeenRefresh != "rt-2-from-rt-1" {
		t.Fatalf("second refresh request carried refresh_token = %q, want rt-2-from-rt-1", lastSeenRefresh)
	}
}

// TestTokenSource_KeepsOldWhenAbsent checks that when the token
// endpoint's response has no refresh_token, the one already on file
// stays: it is neither lost from the running TokenSource nor
// overwritten in the store with an empty value (B7).
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestTokenSource_KeepsOldWhenAbsent(t *testing.T) {
	cfg := fakeTokenEndpoint(t, func(_ string) (int, map[string]any) {
		return http.StatusOK, tokenBody("at-1", "") // no refresh_token in the response
	})
	store := &fakeStore{current: "rt-1"}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.RefreshToken != "rt-1" {
		t.Fatalf("RefreshToken = %q, want the original rt-1 kept", tok.RefreshToken)
	}
	if len(store.saves) != 0 {
		t.Fatalf("store.saves = %v, want no save when the refresh token did not change", store.saves)
	}
	if store.current != "rt-1" {
		t.Fatalf("store.current = %q, want rt-1 untouched", store.current)
	}
}

// TestTokenSource_KeepsOldWhenAbsent_FailedSaveWarns checks the other
// half of B7: a save that errors is reported through warn, and does
// not fail the Token() call that triggered it — the access token the
// caller actually needs is already in hand.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestTokenSource_KeepsOldWhenAbsent_FailedSaveWarns(t *testing.T) {
	cfg := fakeTokenEndpoint(t, func(_ string) (int, map[string]any) {
		return http.StatusOK, tokenBody("at-1", "rt-2")
	})
	store := &fakeStore{current: "rt-1", saveErr: errors.New("keyring is locked")}

	var warned error
	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", func(err error) { warned = err })

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v, want the call to succeed despite the save failure", err)
	}
	if tok.AccessToken != "at-1" {
		t.Fatalf("AccessToken = %q, want at-1", tok.AccessToken)
	}
	if warned == nil {
		t.Fatalf("warn was never called for the failed save")
	}
}

// TestTokenSource_InvalidGrantRereads checks B8: when the token
// endpoint answers invalid_grant, the TokenSource re-reads the store
// (in case a different process just saved a newer refresh token) and
// retries once, succeeding when that newer token works.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestTokenSource_InvalidGrantRereads(t *testing.T) {
	cfg := fakeTokenEndpoint(t, func(rt string) (int, map[string]any) {
		if rt == "rt-stale" {
			return http.StatusBadRequest, invalidGrantBody()
		}
		return http.StatusOK, tokenBody("at-fresh", "rt-fresh-2")
	})
	// The store already holds the newer token a sibling process saved;
	// the TokenSource started out with the stale one in memory.
	store := &fakeStore{current: "rt-fresh"}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-stale", nil)

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok.AccessToken != "at-fresh" {
		t.Fatalf("AccessToken = %q, want at-fresh", tok.AccessToken)
	}
	if store.loads == 0 {
		t.Fatalf("store.loads = 0, want the store re-read after invalid_grant")
	}
}

// TestTokenSource_InvalidGrantTwiceNeedsAuth checks B8/DS6.9: when
// the retry after a re-read also fails with invalid_grant, Token()
// returns the exact reauth text of §3.6, not a raw oauth2 error, and
// the account's alias is in it.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestTokenSource_InvalidGrantTwiceNeedsAuth(t *testing.T) {
	cfg := fakeTokenEndpoint(t, func(_ string) (int, map[string]any) {
		return http.StatusBadRequest, invalidGrantBody()
	})
	store := &fakeStore{current: "rt-1"}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	_, err := ts.Token()
	if err == nil {
		t.Fatalf("Token: want an error when both attempts get invalid_grant")
	}
	if err.Error() != NeedsAuthText("acct1") {
		t.Fatalf("error = %q, want the exact needs_auth text %q", err.Error(), NeedsAuthText("acct1"))
	}
	if !strings.Contains(err.Error(), "acct1") || !strings.Contains(err.Error(), "--reauth") {
		t.Fatalf("error = %q, want it to name the alias and --reauth", err.Error())
	}

	var rerr *oauth2.RetrieveError
	if errors.As(err, &rerr) {
		t.Fatalf("error = %v, want the raw oauth2.RetrieveError replaced by the needs_auth text", err)
	}
}

// blockingStore is a Store whose LoadRefreshToken never returns until
// the test closes unblock, standing in for a keyring stuck behind a
// locked-session prompt (L2).
type blockingStore struct {
	unblock chan struct{}
}

func (s *blockingStore) LoadRefreshToken() (string, error) {
	<-s.unblock
	return "", errors.New("blockingStore: should never get here in TestTokenSource_RereadHonoursTimeout")
}

func (s *blockingStore) SaveRefreshToken(string) error { return nil }

// TestTokenSource_RereadHonoursTimeout checks L2: the B8 re-read of
// the store, which runs while Token() holds its own mutex, is bounded
// by storeReadTimeout rather than able to block Token() forever behind
// a locked keyring. The test injects a short limit so it does not
// have to wait out the real 30s one.
//
// arch: S6-close-judge L2/L3, §3.4, §3.6, B8
func TestTokenSource_RereadHonoursTimeout(t *testing.T) {
	saved := storeReadTimeout
	storeReadTimeout = 50 * time.Millisecond
	t.Cleanup(func() { storeReadTimeout = saved })

	// The token endpoint always answers invalid_grant, so Token()
	// reaches the B8 re-read on every call.
	cfg := fakeTokenEndpoint(t, func(_ string) (int, map[string]any) {
		return http.StatusBadRequest, invalidGrantBody()
	})
	store := &blockingStore{unblock: make(chan struct{})}
	t.Cleanup(func() { close(store.unblock) })

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	done := make(chan struct{})
	var err error
	start := time.Now()
	go func() {
		defer close(done)
		_, err = ts.Token()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Token() did not stop at storeReadTimeout: the B8 re-read blocked forever")
	}
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Token() returned no error for a store that never answers")
	}
	if elapsed > time.Second {
		t.Fatalf("Token() took %s, want it to return in about storeReadTimeout (%s)", elapsed, storeReadTimeout)
	}
}

// TestTokenSource_CachesFreshToken checks the other half of §3.6's
// refresh rule ("refresh when less than 60 seconds of life remain"):
// a cached access token with plenty of life left is handed back
// without a second round trip to the token endpoint.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestTokenSource_CachesFreshToken(t *testing.T) {
	var calls int32
	cfg := fakeTokenEndpoint(t, func(_ string) (int, map[string]any) {
		atomic.AddInt32(&calls, 1)
		// Default tokenBody expires_in is 3600s, well outside freshWindow.
		return http.StatusOK, tokenBody("at-1", "rt-2")
	})
	store := &fakeStore{current: "rt-1"}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	first, err := ts.Token()
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	second, err := ts.Token()
	if err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("token endpoint called %d times, want exactly 1: a fresh cached token must not be re-fetched", got)
	}
	if second.AccessToken != first.AccessToken {
		t.Fatalf("second.AccessToken = %q, want the cached %q", second.AccessToken, first.AccessToken)
	}
}

// TestTokenSource_ConcurrentTokenCalls checks the golang.org/x/oauth2
// TokenSource contract: "Token must be safe for concurrent use by
// multiple goroutines." Before the mutex fix this raced on the
// TokenSource's cur field and failed under go test -race.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func TestTokenSource_ConcurrentTokenCalls(t *testing.T) {
	cfg := fakeTokenEndpoint(t, func(rt string) (int, map[string]any) {
		return http.StatusOK, tokenBody("at-1", "rt-2-from-"+rt)
	})
	store := &fakeStore{current: "rt-1"}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ts.Token(); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Token: %v", err)
	}
}

// blockingSaveStore is a Store whose SaveRefreshToken blocks until the
// test closes unblock, standing in for a slow or locked keyring write
// during a rotation (DRV.6). It closes entered as soon as the save is
// called, so a test can tell that the save was reached -- and so, per
// DRV.6, that t.mu was already released -- without racing on a sleep.
type blockingSaveStore struct {
	current string
	entered chan struct{}
	unblock chan struct{}
}

func (s *blockingSaveStore) LoadRefreshToken() (string, error) { return s.current, nil }

func (s *blockingSaveStore) SaveRefreshToken(string) error {
	close(s.entered)
	<-s.unblock
	return nil
}

// TestTokenSource_RotationSaveOutsideLock checks DRV.6/IRV.4:
// applyRotation updates the in-memory token under t.mu, releases the
// lock, and only then saves. A second, concurrent Token() call must
// not wait for a slow save to finish -- it only needs the lock long
// enough to see the freshly rotated, already-cached token.
//
// arch: DRV.6
func TestTokenSource_RotationSaveOutsideLock(t *testing.T) {
	cfg := fakeTokenEndpoint(t, func(_ string) (int, map[string]any) {
		return http.StatusOK, tokenBody("at-1", "rt-2")
	})
	store := &blockingSaveStore{current: "rt-1", entered: make(chan struct{}), unblock: make(chan struct{})}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	firstErr := make(chan error, 1)
	go func() {
		_, err := ts.Token()
		firstErr <- err
	}()

	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first Token() never reached the save")
	}

	// The save is now blocked. If applyRotation still held t.mu across
	// it, this second call would block too.
	secondErr := make(chan error, 1)
	go func() {
		_, err := ts.Token()
		secondErr <- err
	}()

	select {
	case err := <-secondErr:
		if err != nil {
			t.Fatalf("second Token: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Token() did not return while the first call's save was still blocked: t.mu was held across the save")
	}

	close(store.unblock)
	if err := <-firstErr; err != nil {
		t.Fatalf("first Token: %v", err)
	}
}

// TestTokenSource_RotatedTokenRedacted checks DRV.6's LOW item: the
// new refresh token reaches guard.RegisterSecret before any log line
// can hold it, so a later log or error that happens to repeat it
// comes back redacted.
//
// arch: DRV.6
func TestTokenSource_RotatedTokenRedacted(t *testing.T) {
	const rotated = "rt-2-drv6-redact-check"
	cfg := fakeTokenEndpoint(t, func(_ string) (int, map[string]any) {
		return http.StatusOK, tokenBody("at-1", rotated)
	})
	store := &fakeStore{current: "rt-1"}

	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	if _, err := ts.Token(); err != nil {
		t.Fatalf("Token: %v", err)
	}

	line := "debug: refresh token is " + rotated
	if got := guard.Redact(line); strings.Contains(got, rotated) {
		t.Fatalf("Redact(%q) = %q, want the rotated refresh token replaced", line, got)
	}
}

// TestTokenSource_NeedsAuthIsSentinel checks that the needs-auth
// error of Token() wraps ErrNeedsAuth, so a caller can test it with
// errors.Is, and that its text is still the exact NeedsAuthText. It
// covers both paths: a store that gives no token, and a retry that
// also gets invalid_grant.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func TestTokenSource_NeedsAuthIsSentinel(t *testing.T) {
	cfg := fakeTokenEndpoint(t, func(string) (int, map[string]any) {
		return http.StatusBadRequest, invalidGrantBody()
	})
	for name, stored := range map[string]string{"retry fails": "rt-1", "store empty": ""} {
		t.Run(name, func(t *testing.T) {
			ts := NewTokenSource(context.Background(), cfg, &fakeStore{current: stored}, "acct1", "rt-1", nil)

			_, err := ts.Token()

			if !errors.Is(err, ErrNeedsAuth) {
				t.Fatalf("error = %v, want it to wrap ErrNeedsAuth", err)
			}
			if err.Error() != NeedsAuthText("acct1") {
				t.Fatalf("error text = %q, want the unchanged %q", err.Error(), NeedsAuthText("acct1"))
			}
		})
	}
}

// TestTokenSource_RefreshTransportErrorHasAlias checks T199 item 6: a
// refresh that fails in transport (the connection closes with no
// answer) gives an error that names the account and keeps the cause.
// It is not the needs-auth error, and the store is not read again,
// because only invalid_grant means the refresh token is bad.
//
// arch: DS11.14, IS11.7, G6
func TestTokenSource_RefreshTransportErrorHasAlias(t *testing.T) {
	// Arrange: a token endpoint that drops each connection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the test server cannot hijack the connection")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)
	cfg := &oauth2.Config{
		ClientID: "client-1",
		Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
	}
	store := &fakeStore{current: "rt-1"}
	ts := NewTokenSource(context.Background(), cfg, store, "acct1", "rt-1", nil)

	// Act
	_, err := ts.Token()

	// Assert
	if err == nil {
		t.Fatal("Token: want the transport error, got nil")
	}
	const prefix = "oauth: refresh access token for acct1: "
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Errorf("error = %q, want it to start with %q", err.Error(), prefix)
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Errorf("error = %v, want the transport cause (*url.Error) kept", err)
	}
	if errors.Is(err, ErrNeedsAuth) {
		t.Errorf("error = %v, want no needs-auth: a transport error says nothing about the sign-in", err)
	}
	store.mu.Lock()
	loads := store.loads
	store.mu.Unlock()
	if loads != 0 {
		t.Errorf("store loads = %d, want 0: only invalid_grant reads the store again", loads)
	}
}
