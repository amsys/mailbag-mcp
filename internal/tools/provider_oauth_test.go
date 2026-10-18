// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/emersion/go-imap/v2/imapclient"
	"golang.org/x/oauth2"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/imap"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// mapStore is a secrets.Store with real per-key storage, unlike
// search_test.go's fakeStore (one fixed value for every key). It is
// what lets these tests give `oauth.microsoft` and an account alias
// different JSON at the same time.
type mapStore struct {
	mu   sync.Mutex
	data map[string]string
	sets map[string]int
}

func newMapStore() *mapStore {
	return &mapStore{data: make(map[string]string), sets: make(map[string]int)}
}

func (s *mapStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return "", secrets.ErrNotFound
	}
	return v, nil
}

func (s *mapStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	s.sets[key]++
	return nil
}

func (s *mapStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *mapStore) Kind() string { return "file" }

// fakeMSTokenEndpoint stands in for login.microsoftonline.com's token
// endpoint (DS6.2: the endpoint is a fixed constant this package never
// builds from mail or model input, so a plain httptest fake is the
// right double). respond decides the response purely from the
// refresh_token the request carries.
func fakeMSTokenEndpoint(t *testing.T, respond func(refreshToken string) (status int, body map[string]any)) *oauth2.Config {
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

// TestFactory_OAuthCredentialRefreshesOnRedial holds B14 at the
// Factory level: an outlook account's credential comes from a cached
// TokenSource, and every call to credential() — one per dial, per
// credentialFunc's doc comment — asks that source for a live access
// token rather than replaying the one minted at the account's first
// use. The fake token endpoint issues a 1-second access token (inside
// the 60s freshWindow), so a second credential() call is forced to go
// back to the wire and mint a different one.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func TestFactory_OAuthCredentialRefreshesOnRedial(t *testing.T) {
	var seen []string
	cfg := fakeMSTokenEndpoint(t, func(rt string) (int, map[string]any) {
		seen = append(seen, rt)
		return http.StatusOK, map[string]any{
			"access_token":  fmt.Sprintf("at-%d", len(seen)),
			"token_type":    "Bearer",
			"expires_in":    1,
			"refresh_token": "rt-1",
		}
	})

	store := newMapStore()
	store.data["work"] = `{"kind":"oauth","refresh_token":"rt-1"}`
	rtStore := &aliasRefreshTokenStore{store: store, alias: "work"}
	ts := oauthpkg.NewTokenSource(context.Background(), cfg, rtStore, "work", "rt-1", nil)

	f := NewFactory(nil)
	f.tokSrcs["work"] = ts

	acct := config.Account{Alias: "work", Provider: "outlook", Email: "ann@contoso.com"}

	cred1, cached1, err := f.credential(context.Background(), acct, store)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}
	if cached1 {
		t.Error("an oauth credential must never report cached=true (B14): the caller must not keep it past one dial")
	}
	if cred1.Token != "at-1" {
		t.Fatalf("cred1.Token = %q, want at-1", cred1.Token)
	}
	if cred1.Username != "ann@contoso.com" {
		t.Fatalf("cred1.Username = %q, want the account email (no username override set)", cred1.Username)
	}

	// A redial: the pool's dial func calls credential() again.
	cred2, cached2, err := f.credential(context.Background(), acct, store)
	if err != nil {
		t.Fatalf("credential (redial): %v", err)
	}
	if cached2 {
		t.Error("redial reported cached=true")
	}
	if cred2.Token == cred1.Token {
		t.Fatalf("redial got the same access token %q; want a fresh one (B14)", cred2.Token)
	}
	if len(seen) != 2 {
		t.Fatalf("token endpoint called %d times, want 2 (one per credential() call)", len(seen))
	}
}

// TestFactory_OAuthCredentialSurvivesDialContextCancel guards the real
// defect a first T41 run shipped (REFUTED, 2026-09-27): microsoftCredential
// built its TokenSource from the dial's own context, but imap.Pool.live
// cancels that context (its dialCtx) the moment the dial that carried
// it returns. The TokenSource is cached on the Factory and reused by
// every later dial (B14), so a token source built that way failed
// every dial after the first with "context canceled" — even though the
// token endpoint was healthy and the second dial's own context was
// perfectly live. TestFactory_OAuthCredentialRefreshesOnRedial does not
// catch this: it hands the Factory an already-built TokenSource, so it
// never runs parseCredential/microsoftCredential at all. This test
// goes through the real construction path once, via oauthConfigFunc's
// test seam, so no network call ever leaves this process.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func TestFactory_OAuthCredentialSurvivesDialContextCancel(t *testing.T) {
	var seen []string
	cfg := fakeMSTokenEndpoint(t, func(rt string) (int, map[string]any) {
		seen = append(seen, rt)
		return http.StatusOK, map[string]any{
			"access_token":  fmt.Sprintf("at-%d", len(seen)),
			"token_type":    "Bearer",
			"expires_in":    1,
			"refresh_token": "rt-1",
		}
	})
	saved := oauthConfigFunc
	oauthConfigFunc = func(_, _, _ string) (*oauth2.Config, error) {
		return cfg, nil
	}
	t.Cleanup(func() { oauthConfigFunc = saved })

	store := newMapStore()
	store.data[microsoftClientKey] = `{"client_id":"public-client-1"}`
	store.data["work"] = `{"kind":"oauth","refresh_token":"rt-1"}`

	f := NewFactory(nil)
	acct := config.Account{Alias: "work", Provider: "outlook", Tenant: "contoso.com", Email: "ann@contoso.com"}

	// First dial: this context dies the moment the dial that carried
	// it returns, exactly as imap.Pool.live's dialCtx does (it is
	// created with context.WithTimeout from the pool's ambient
	// context and cancelled by a deferred call right after dial()
	// returns).
	firstDialCtx, cancelFirstDial := context.WithCancel(context.Background())
	cred1, cached1, err := f.credential(firstDialCtx, acct, store)
	cancelFirstDial()
	if err != nil {
		t.Fatalf("first credential(): %v", err)
	}
	if cached1 {
		t.Error("an oauth credential must never report cached=true (B14)")
	}

	// Redial: a fresh context, after the first dial's own context has
	// already been cancelled. A token source that kept the first
	// dial's context would fail this call with "context canceled".
	cred2, cached2, err := f.credential(context.Background(), acct, store)
	if err != nil {
		t.Fatalf("credential (redial), after the first dial's context died: %v", err)
	}
	if cached2 {
		t.Error("redial reported cached=true")
	}
	if cred2.Token == cred1.Token {
		t.Fatalf("redial got the same access token %q; want a fresh one (B14)", cred2.Token)
	}
	if len(seen) != 2 {
		t.Fatalf("token endpoint called %d times, want 2 (one per credential() call)", len(seen))
	}
}

// TestProvider_ParseCredentialOAuthMicrosoft checks DS6.4's wiring
// without any network call: Config() only builds an *oauth2.Config
// struct, so parseCredential's oauth branch can be exercised down to
// "does it return a token source" without ever calling Token() (which
// would be the only step that reaches the network).
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func TestProvider_ParseCredentialOAuthMicrosoft(t *testing.T) {
	acct := config.Account{Alias: "work", Provider: "outlook", Tenant: "contoso.com", Email: "ann@contoso.com"}

	t.Run("builds a token source", func(t *testing.T) {
		store := newMapStore()
		store.data[microsoftClientKey] = `{"client_id":"public-client-1"}`
		res, err := parseCredential(context.Background(), acct, `{"kind":"oauth","refresh_token":"rt-1"}`, store, nil)
		if err != nil {
			t.Fatalf("parseCredential: %v", err)
		}
		if res.tokSrc == nil {
			t.Fatal("credentialResult.tokSrc is nil, want a token source (DS6.4)")
		}
	})

	t.Run("no client id configured", func(t *testing.T) {
		store := newMapStore() // no oauth.microsoft key
		if _, err := parseCredential(context.Background(), acct, `{"kind":"oauth","refresh_token":"rt-1"}`, store, nil); err == nil {
			t.Fatal("parseCredential accepted an oauth secret with no Microsoft client id configured")
		} else if !strings.Contains(err.Error(), "oauth set microsoft") {
			t.Errorf("error = %q, want it to name the fix", err.Error())
		}
	})

	t.Run("empty refresh token", func(t *testing.T) {
		store := newMapStore()
		store.data[microsoftClientKey] = `{"client_id":"public-client-1"}`
		if _, err := parseCredential(context.Background(), acct, `{"kind":"oauth","refresh_token":""}`, store, nil); err == nil {
			t.Fatal("parseCredential accepted an oauth secret with no refresh token")
		}
	})

	t.Run("invalid tenant rejected before the endpoint is built (I-S6.2)", func(t *testing.T) {
		bad := acct
		bad.Tenant = "contoso.com/../evil"
		store := newMapStore()
		store.data[microsoftClientKey] = `{"client_id":"public-client-1"}`
		if _, err := parseCredential(context.Background(), bad, `{"kind":"oauth","refresh_token":"rt-1"}`, store, nil); err == nil {
			t.Fatal("parseCredential accepted an invalid tenant")
		}
	})

	t.Run("non-outlook provider still errors", func(t *testing.T) {
		plain := config.Account{Alias: "work"}
		store := newMapStore()
		if _, err := parseCredential(context.Background(), plain, `{"kind":"oauth","refresh_token":"rt-1"}`, store, nil); err == nil {
			t.Fatal("parseCredential accepted an oauth secret for a non-outlook account")
		}
	})
}

// TestCredential_AccountUsernameWins holds DRV.14b: accounts.toml's
// own username wins over the username stored in the secret, so the
// login name lives in one place once an account names it there. The
// secret's username is read only as a fall-back for an old account
// that accounts.toml does not name.
//
// arch: DRV.14b
func TestCredential_AccountUsernameWins(t *testing.T) {
	t.Run("accounts.toml wins over a different stored username", func(t *testing.T) {
		acct := config.Account{Alias: "work", Username: "ann@example.test"}
		res, err := parseCredential(context.Background(), acct,
			`{"v":1,"kind":"password","username":"ann","password":"s3cret-value"}`, nil, nil)
		if err != nil {
			t.Fatalf("parseCredential: %v", err)
		}
		if res.cred.Username != "ann@example.test" {
			t.Fatalf("credential.Username = %q, want the accounts.toml username %q", res.cred.Username, "ann@example.test")
		}
	})

	t.Run("the stored username is the fall-back for an old account", func(t *testing.T) {
		acct := config.Account{Alias: "work"} // no Username in accounts.toml
		res, err := parseCredential(context.Background(), acct,
			`{"v":1,"kind":"password","username":"ann","password":"s3cret-value"}`, nil, nil)
		if err != nil {
			t.Fatalf("parseCredential: %v", err)
		}
		if res.cred.Username != "ann" {
			t.Fatalf("credential.Username = %q, want the stored fall-back %q", res.cred.Username, "ann")
		}
	})
}

// TestAliasRefreshTokenStore_SaveKeepsSecretShape checks that a rotated
// refresh token is written in the exact §3.4 shape of an oauth secret,
// {"v":1,"kind":"oauth","refresh_token":".."}, with no lost "v" and no
// empty password-only fields. It also checks that LoadRefreshToken
// reads the value back.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func TestAliasRefreshTokenStore_SaveKeepsSecretShape(t *testing.T) {
	store := newMapStore()
	store.data["work"] = `{"v":1,"kind":"oauth","refresh_token":"rt-1"}`
	rtStore := &aliasRefreshTokenStore{store: store, alias: "work"}

	if err := rtStore.SaveRefreshToken("rt-2"); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	const want = `{"v":1,"kind":"oauth","refresh_token":"rt-2"}`
	if got := store.data["work"]; got != want {
		t.Fatalf("stored secret = %s, want %s", got, want)
	}
	got, err := rtStore.LoadRefreshToken()
	if err != nil || got != "rt-2" {
		t.Fatalf("LoadRefreshToken = %q, %v; want rt-2, nil", got, err)
	}
}

// TestFactory_ClientIDReadHonoursTimeout checks L2: microsoftClientID's
// read of the shared `oauth.microsoft` client id is bounded the same
// way readSecret already is (TestFactory_SecretReadStopsOnDeadline in
// search_test.go proves that one), so a locked keyring cannot hold a
// dial past the caller's own deadline. It uses a store that never
// answers and a short caller deadline, so the test does not have to
// wait out the real 30s secretTimeout.
//
// arch: S6-close-judge L2/L3, §3.4, §3.6, B8, B14
func TestFactory_ClientIDReadHonoursTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := microsoftClientID(ctx, &fakeStore{block: block}); err == nil {
			t.Error("microsoftClientID waited for a store that never answers and returned no error")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("microsoftClientID did not stop at the caller deadline")
	}
}

// TestFactory_OAuthAuthErrorDropsCachedToken checks L3: an IMAP
// AuthError on the oauth token path drops the cached token source
// (f.forget) and dials once more with a freshly minted access token,
// the same shape the password path already had. Before this fix,
// tokenCredential's cached=false (B14: an oauth credential is never
// reported cached) skipped dial()'s retry branch entirely, so a
// revoked-but-unexpired token failed every call until it expired.
//
// arch: S6-close-judge L2/L3, §3.4, §3.6, B8, B14
func TestFactory_OAuthAuthErrorDropsCachedToken(t *testing.T) {
	writeAccounts(t, `
secrets = "file"

[accounts.work]
provider = "outlook"
email = "ann@contoso.com"
tenant = "contoso.com"
imap = "outlook.office365.com:993"
`)
	dir, err := config.ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, microsoftClientKey), []byte(`{"client_id":"public-client-1"}`), 0o600); err != nil {
		t.Fatalf("write client id secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "work"), []byte(`{"kind":"oauth","refresh_token":"rt-1"}`), 0o600); err != nil {
		t.Fatalf("write account secret: %v", err)
	}

	var minted []string
	cfg := fakeMSTokenEndpoint(t, func(_ string) (int, map[string]any) {
		at := fmt.Sprintf("at-%d", len(minted)+1)
		minted = append(minted, at)
		return http.StatusOK, map[string]any{
			"access_token":  at,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "rt-1",
		}
	})
	savedCfg := oauthConfigFunc
	oauthConfigFunc = func(_, _, _ string) (*oauth2.Config, error) { return cfg, nil }
	t.Cleanup(func() { oauthConfigFunc = savedCfg })

	var dialedTokens []string
	savedDial := dialAccountFunc
	dialAccountFunc = func(_ context.Context, _ config.Account, cred imap.Credential, _ io.Writer) (*imapclient.Client, error) {
		dialedTokens = append(dialedTokens, cred.Token)
		if len(dialedTokens) == 1 {
			return nil, &imap.AuthError{Err: errors.New("token rejected")}
		}
		return &imapclient.Client{}, nil
	}
	t.Cleanup(func() { dialAccountFunc = savedDial })

	f := NewFactory(nil)
	t.Cleanup(f.Close)

	if _, err := f.dial(context.Background(), "work"); err != nil {
		t.Fatalf("dial: %v, want the retry after AuthError to succeed", err)
	}
	if len(dialedTokens) != 2 {
		t.Fatalf("dialAccountFunc called %d times, want 2: the original attempt and one retry (L3)", len(dialedTokens))
	}
	if dialedTokens[0] == dialedTokens[1] {
		t.Fatalf("both dial attempts carried the same token %q; want the retry to carry a freshly minted one after f.forget dropped the cached token source", dialedTokens[0])
	}
	if len(minted) != 2 {
		t.Fatalf("token endpoint minted %d tokens, want 2: one for the failed dial, one after the cached token source was dropped", len(minted))
	}
}

// rotatingOutlook writes accounts.toml with one outlook account
// "work" on the file store, its secret with refresh token rt-0 and the
// client id. It points oauthConfigFunc at a token endpoint that
// rotates the refresh token on every refresh and gives an access
// token inside the 60 s fresh window, so each Token() call rotates.
// It gives the directory of the file store.
func rotatingOutlook(t *testing.T) string {
	t.Helper()
	writeAccounts(t, `
secrets = "file"

[accounts.work]
provider = "outlook"
email = "ann@contoso.com"
tenant = "contoso.com"
imap = "outlook.office365.com:993"
`)
	dir, err := config.ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, microsoftClientKey), []byte(`{"client_id":"public-client-1"}`), 0o600); err != nil {
		t.Fatalf("write client id secret: %v", err)
	}
	writeOAuthSecret(t, dir, "rt-0")

	var mu sync.Mutex
	n := 0
	cfg := fakeMSTokenEndpoint(t, func(string) (int, map[string]any) {
		mu.Lock()
		n++
		i := n
		mu.Unlock()
		return http.StatusOK, map[string]any{
			"access_token":  fmt.Sprintf("at-%d", i),
			"token_type":    "Bearer",
			"expires_in":    1,
			"refresh_token": fmt.Sprintf("rt-%d", i),
		}
	})
	savedCfg := oauthConfigFunc
	oauthConfigFunc = func(string, string, string) (*oauth2.Config, error) { return cfg, nil }
	t.Cleanup(func() { oauthConfigFunc = savedCfg })
	return dir
}

// writeOAuthSecret writes the secret of account "work" as another
// process does (account add --reauth): straight to the file store.
func writeOAuthSecret(t *testing.T, dir, refreshToken string) {
	t.Helper()
	body := `{"v":1,"kind":"oauth","refresh_token":"` + refreshToken + `"}`
	if err := os.WriteFile(filepath.Join(dir, "work"), []byte(body), 0o600); err != nil {
		t.Fatalf("write account secret: %v", err)
	}
}

// readOAuthSecret gives the stored secret of account "work".
func readOAuthSecret(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "work")) //nolint:gosec // G304: test code; the path is built by the test
	if err != nil {
		t.Fatalf("read account secret: %v", err)
	}
	return string(b)
}

// countingDial puts a fake dial in place that counts its calls and
// gives what fail returns.
func countingDial(t *testing.T, fail func() error) func() int {
	t.Helper()
	var mu sync.Mutex
	n := 0
	saved := dialAccountFunc
	dialAccountFunc = func(context.Context, config.Account, imap.Credential, io.Writer) (*imapclient.Client, error) {
		mu.Lock()
		n++
		mu.Unlock()
		return nil, fail()
	}
	t.Cleanup(func() { dialAccountFunc = saved })
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func refusedLogin() error {
	return &imap.AuthError{Err: errors.New("NO [AUTHENTICATIONFAILED] invalid credentials")}
}

// TestFactory_OwnRotationKeepsRefusal checks G-RV.1: the server
// refuses the login, and the token source rotated the refresh token
// during that login. The rotation that this process saved must not
// end the refusal, so the next call gets the refusal text and does
// not log in again.
//
// arch: DR1G.6, DR1G.18, IR1G.7
func TestFactory_OwnRotationKeepsRefusal(t *testing.T) {
	dir := rotatingOutlook(t)
	dials := countingDial(t, refusedLogin)
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	var authErr *imap.AuthError
	if _, err := f.dial(context.Background(), "work"); !errors.As(err, &authErr) {
		t.Fatalf("first dial error = %v, want an AuthError", err)
	}
	if got := readOAuthSecret(t, dir); strings.Contains(got, `"rt-0"`) {
		t.Fatalf("stored secret = %s, want a rotated refresh token: the test needs a rotation", got)
	}
	first := dials()

	for i := 0; i < 3; i++ {
		_, err := f.dial(context.Background(), "work")
		const want = `login refused by the server; run "mailbag-mcp account add work --reauth"`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("dial %d after the refusal: error = %v, want the refusal text", i+2, err)
		}
	}
	if got := dials(); got != first {
		t.Errorf("logins = %d after the refusal, want %d: an own rotation must not end the refusal", got, first)
	}
}

// TestFactory_OtherWriterEndsRefusal checks the other half of IR1G.7:
// a secret that another process writes (account add --reauth) ends
// the refusal at once, and the next call logs in again.
//
// arch: DR1G.6, DR1G.18, IR1G.7
func TestFactory_OtherWriterEndsRefusal(t *testing.T) {
	dir := rotatingOutlook(t)
	var mu sync.Mutex
	refuse := true
	dials := countingDial(t, func() error {
		mu.Lock()
		defer mu.Unlock()
		if refuse {
			return refusedLogin()
		}
		return errDialed
	})
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	if _, err := f.dial(context.Background(), "work"); err == nil {
		t.Fatal("first dial gave no error, want the AuthError")
	}
	first := dials()

	writeOAuthSecret(t, dir, "rt-reauth")
	mu.Lock()
	refuse = false
	mu.Unlock()
	_, err := f.dial(context.Background(), "work")

	if !errors.Is(err, errDialed) {
		t.Fatalf("dial after the new secret: error = %v, want a login", err)
	}
	if got := dials(); got != first+1 {
		t.Errorf("logins after the new secret = %d, want 1", got-first)
	}
}

// TestFactory_RotationDuringDial runs dials that rotate the refresh
// token at the same time as refusal checks and direct writes through
// the wrapper. Under -race it shows that the lock rule of DR1G.6.1
// holds: no data race and no deadlock. After the goroutines stop, one
// more rotation leaves the hash equal to the stored secret.
//
// arch: DR1G.6, DR1G.18, IR1G.7
func TestFactory_RotationDuringDial(t *testing.T) {
	dir := rotatingOutlook(t)
	countingDial(t, func() error { return errDialed })
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	store, err := f.store()
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				for i := 0; i < 10; i++ {
					if _, err := f.dial(context.Background(), "work"); !errors.Is(err, errDialed) {
						t.Errorf("dial: %v, want the fake dial to run", err)
						return
					}
				}
			}()
			go func(g int) {
				defer wg.Done()
				rs := &recordingStore{Store: store, f: f}
				for i := 0; i < 10; i++ {
					if err := f.checkRefusal(context.Background(), "work", store); err != nil {
						t.Errorf("checkRefusal: %v", err)
					}
					if err := rs.Set(fmt.Sprintf("other-%d", g), "x"); err != nil {
						t.Errorf("Set: %v", err)
					}
				}
			}(g)
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("dials and rotations did not finish: a lock is held across the rotation write")
	}

	if _, err := f.dial(context.Background(), "work"); !errors.Is(err, errDialed) {
		t.Fatalf("last dial: %v", err)
	}
	f.mu.Lock()
	sum := f.sums["work"]
	f.mu.Unlock()
	if sum != sha256.Sum256([]byte(readOAuthSecret(t, dir))) {
		t.Error("after the last rotation, sums[work] is not the hash of the stored secret")
	}
}

// TestFactory_NoteLoginKeepsStateOnTransportError checks T199 item 6
// at the Factory: a token refresh that fails in transport fails the
// dial with an error that names the account, writes one WARN line
// with the alias, and keeps the sign-in state as it was. No IMAP
// login runs, because the credential read failed first.
//
// arch: DS11.14, IS11.7, G6
func TestFactory_NoteLoginKeepsStateOnTransportError(t *testing.T) {
	// Arrange
	writeAccounts(t, `
secrets = "file"

[accounts.work]
provider = "outlook"
email = "ann@contoso.com"
tenant = "contoso.com"
imap = "outlook.office365.com:993"
`)
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
		_ = conn.Close() // a transport error: no HTTP answer at all
	}))
	t.Cleanup(srv.Close)
	cfg := &oauth2.Config{
		ClientID: "client-1",
		Endpoint: oauth2.Endpoint{TokenURL: srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams},
	}
	store := newMapStore()
	rtStore := &aliasRefreshTokenStore{store: store, alias: "work"}
	ts := oauthpkg.NewTokenSource(context.Background(), cfg, rtStore, "work", "rt-1", nil)
	dials := countingDial(t, func() error { return errDialed })

	var logBuf bytes.Buffer
	f := NewFactory(slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(f.Close)
	f.tokSrcs["work"] = ts
	f.states["work"] = AuthOK // an earlier login worked

	// Act
	_, err := f.dial(context.Background(), "work")

	// Assert
	const want = "oauth: refresh access token for work: "
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("dial error = %v, want it to hold %q", err, want)
	}
	if got := f.AuthState("work"); got != AuthOK {
		t.Errorf("AuthState = %q, want %q kept: a transport error is not a sign-in state", got, AuthOK)
	}
	if n := dials(); n != 0 {
		t.Errorf("IMAP logins = %d, want 0 after the credential read failed", n)
	}
	logText := logBuf.String()
	for _, part := range []string{"level=WARN", "alias=work", want} {
		if !strings.Contains(logText, part) {
			t.Errorf("log = %q, want it to hold %q", logText, part)
		}
	}
	if n := strings.Count(logText, "level=WARN"); n != 1 {
		t.Errorf("log has %d WARN lines, want 1", n)
	}
}
