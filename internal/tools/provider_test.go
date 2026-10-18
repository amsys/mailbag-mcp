// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"golang.org/x/oauth2"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/imap"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// errDialed is what the fake dial gives when it ran with a live
// context. The tests below need no real server: they check what
// reaches the dial, not the login itself.
var errDialed = errors.New("fake dial ran")

// passwordAccount writes accounts.toml with one password account
// "work" on the file store, and the secret of that account.
func passwordAccount(t *testing.T, password string) {
	t.Helper()
	writeAccounts(t, `
secrets = "file"

[accounts.work]
provider = "imap"
email = "ann@example.test"
imap = "mail.example.test:993"
`)
	writePassword(t, password)
}

// writePassword replaces the stored secret of account "work".
func writePassword(t *testing.T, password string) {
	t.Helper()
	dir, err := config.ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	body := `{"kind":"password","username":"ann","password":"` + password + `"}`
	if err := os.WriteFile(filepath.Join(dir, "work"), []byte(body), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
}

// fakeDial puts fn in place of imap.DialAccount for one test.
func fakeDial(t *testing.T, fn func(ctx context.Context, cred imap.Credential) error) {
	t.Helper()
	saved := dialAccountFunc
	dialAccountFunc = func(ctx context.Context, _ config.Account, cred imap.Credential, _ io.Writer) (*imapclient.Client, error) {
		return nil, fn(ctx, cred)
	}
	t.Cleanup(func() { dialAccountFunc = saved })
}

// slowStore answers every Get after delay.
type slowStore struct {
	delay time.Duration
	value string
}

func (s *slowStore) Get(string) (string, error) {
	time.Sleep(s.delay)
	return s.value, nil
}
func (s *slowStore) Set(string, string) error { return nil }
func (s *slowStore) Delete(string) error      { return nil }
func (s *slowStore) Kind() string             { return "keyring" }

func noRun(*imap.Conn) error { return errors.New("fn ran with no connection") }

// TestFactory_SlowSecretNotCutByDialLimit checks that the dial limit
// covers the network part only. A keyring that takes longer than the
// dial limit to open (but less than its own 30 s limit) must still
// give its secret, and the dial after it must start with a live
// context.
// arch: DRV.10
func TestFactory_SlowSecretNotCutByDialLimit(t *testing.T) {
	passwordAccount(t, "pw-1")
	savedLimit := imap.DialTimeout
	imap.DialTimeout = 100 * time.Millisecond
	t.Cleanup(func() { imap.DialTimeout = savedLimit })
	savedSelect := selectStore
	selectStore = func(string, string, string) (secrets.Store, error) {
		return &slowStore{delay: 400 * time.Millisecond, value: `{"kind":"password","username":"ann","password":"pw-1"}`}, nil
	}
	t.Cleanup(func() { selectStore = savedSelect })
	fakeDial(t, func(ctx context.Context, _ imap.Credential) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return errDialed
	})
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	err := f.Pool().WithRead(context.Background(), "work", noRun)

	if !errors.Is(err, errDialed) {
		t.Fatalf("WithRead error = %v, want the dial to run: the secret read is not part of the dial limit", err)
	}
}

// TestFactory_OpenGivesCapsReporter checks that the value Factory.Open
// gives for an IMAP account is still a tools.CapsReporter. Open does
// not dial (it only builds imap.New(alias, f.pool)), so this test
// needs no server and no fake dial. The compile-time assertion in
// caps.go checks the type; this test checks the value Open actually
// hands back, closing R1G-judge M1.
//
// arch: DR1G.11, DR1G.18.8, IR1G.15
func TestFactory_OpenGivesCapsReporter(t *testing.T) {
	passwordAccount(t, "pw-1")
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	reader, _, err := f.Open(context.Background(), "work")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := reader.(CapsReporter); !ok {
		t.Fatalf("Open gave a %T, which is not a CapsReporter", reader)
	}
}

// TestFactory_AuthErrorNoRelogin checks IRV.8: after the server
// refused a login, the next call does not log in again with the same
// credential. It gets the refusal text, which names the command that
// fixes it.
// arch: DRV.10
func TestFactory_AuthErrorNoRelogin(t *testing.T) {
	passwordAccount(t, "pw-1")
	dials := 0
	fakeDial(t, func(context.Context, imap.Credential) error {
		dials++
		return &imap.AuthError{Err: errors.New("NO [AUTHENTICATIONFAILED] invalid credentials")}
	})
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	var authErr *imap.AuthError
	if err := f.Pool().WithRead(context.Background(), "work", noRun); !errors.As(err, &authErr) {
		t.Fatalf("first call error = %v, want an AuthError", err)
	}
	first := dials

	for i := 0; i < 3; i++ {
		err := f.Pool().WithRead(context.Background(), "work", noRun)
		if err == nil || !strings.Contains(err.Error(), `login refused by the server; run "mailbag-mcp account add work" to store the new password`) {
			t.Fatalf("call %d error = %v, want the refusal text", i+2, err)
		}
	}
	if dials != first {
		t.Errorf("logins = %d after the refusal, want %d: a refused credential is not tried again", dials, first)
	}
}

// TestFactory_CheckRefusalOAuthText checks ORV.13: for an account
// whose stored secret has kind "oauth", the refusal text names
// "account add <alias> --reauth", not the missing "account reauth"
// subcommand.
// arch: DRV.10, ORV.13
func TestFactory_CheckRefusalOAuthText(t *testing.T) {
	store := newMapStore()
	raw := `{"kind":"oauth","refresh_token":"rt-1"}`
	store.data["work"] = raw

	f := NewFactory(nil)
	t.Cleanup(f.Close)
	f.refused["work"] = refusal{
		sum:   sha256.Sum256([]byte(raw)),
		until: time.Now().Add(time.Hour),
		err:   errors.New("NO [AUTHENTICATIONFAILED] invalid credentials"),
	}

	err := f.checkRefusal(context.Background(), "work", store)
	const want = `login refused by the server; run "mailbag-mcp account add work --reauth"`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkRefusal error = %v, want it to contain %q", err, want)
	}
}

// TestFactory_ChangedSecretEndsRefusal checks that a new secret in
// the store ends the refusal at once: the next call logs in with the
// new password, and never with the refused one.
// arch: DRV.10
func TestFactory_ChangedSecretEndsRefusal(t *testing.T) {
	passwordAccount(t, "pw-1")
	var used []string
	fakeDial(t, func(_ context.Context, cred imap.Credential) error {
		used = append(used, cred.Password)
		if cred.Password == "pw-1" {
			return &imap.AuthError{Err: errors.New("NO [AUTHENTICATIONFAILED] invalid credentials")}
		}
		return errDialed
	})
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	if err := f.Pool().WithRead(context.Background(), "work", noRun); err == nil {
		t.Fatal("first call gave no error, want the AuthError")
	}
	before := len(used)

	writePassword(t, "pw-2")
	err := f.Pool().WithRead(context.Background(), "work", noRun)

	if !errors.Is(err, errDialed) {
		t.Fatalf("call after the new secret: error = %v, want a login with the new secret", err)
	}
	after := used[before:]
	if len(after) != 1 || after[0] != "pw-2" {
		t.Errorf("logins after the new secret = %q, want exactly [pw-2]", after)
	}
}

// TestFactory_RefusalWindowUsesWallClock checks T199 item 8: the login
// refusal window runs on the wall clock. The fake clock jumps past
// authRefusal while almost no real time passes, as a suspend does to
// the wall clock and not to the monotonic one. The next call must then
// log in again, because the refusal ended during the sleep. The default
// clock must carry no monotonic reading, so the same holds in
// production.
//
// arch: DS11.14, DS11.18
func TestFactory_RefusalWindowUsesWallClock(t *testing.T) {
	passwordAccount(t, "pw-1")
	dials := 0
	fakeDial(t, func(context.Context, imap.Credential) error {
		dials++
		return &imap.AuthError{Err: errors.New("NO [AUTHENTICATIONFAILED] invalid credentials")}
	})
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	if got := f.now().String(); strings.Contains(got, "m=") {
		t.Errorf("default now = %s, want a wall-only time with no monotonic reading", got)
	}
	clock := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	f.now = func() time.Time { return clock }

	var authErr *imap.AuthError
	if err := f.Pool().WithRead(context.Background(), "work", noRun); !errors.As(err, &authErr) {
		t.Fatalf("first call error = %v, want an AuthError", err)
	}
	if until := f.refused["work"].until; !until.Equal(clock.Add(authRefusal)) {
		t.Errorf("refusal ends at %v, want %v: the window must start on the injected clock", until, clock.Add(authRefusal))
	}
	first := dials

	// Inside the window: refused with no login.
	clock = clock.Add(authRefusal - time.Second)
	if err := f.Pool().WithRead(context.Background(), "work", noRun); err == nil || !strings.Contains(err.Error(), "login refused by the server") {
		t.Fatalf("call inside the window: error = %v, want the refusal text", err)
	}
	if dials != first {
		t.Fatalf("logins inside the window = %d, want %d", dials, first)
	}

	// The suspend: the wall clock passes the end of the window.
	clock = clock.Add(2 * time.Second)
	if err := f.Pool().WithRead(context.Background(), "work", noRun); !errors.As(err, &authErr) {
		t.Fatalf("call after the window: error = %v, want a new login and its AuthError", err)
	}
	// A cached password gets one fresh read and a second dial (L3), so
	// the count is "more than before", not an exact number.
	if dials == first {
		t.Errorf("logins after the window = %d, want more than %d: the refusal must end on the wall clock", dials, first)
	}
}

// TestRecordingStore_HashesExactValue checks that the wrapper records
// the hash of the exact string that it writes, also for a rotation
// that aliasRefreshTokenStore writes through it.
//
// arch: DR1G.6, DR1G.18, IR1G.7
func TestRecordingStore_HashesExactValue(t *testing.T) {
	store := newMapStore()
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	rs := &recordingStore{Store: store, f: f}

	const value = `{"kind":"password","username":"ann","password":"pw-1"}`
	if err := rs.Set("work", value); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := f.sums["work"]; got != sha256.Sum256([]byte(value)) {
		t.Fatal("sums[work] is not the hash of the value written")
	}

	rt := &aliasRefreshTokenStore{store: rs, alias: "work"}
	if err := rt.SaveRefreshToken("rt-2"); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	stored := store.data["work"]
	if f.sums["work"] != sha256.Sum256([]byte(stored)) {
		t.Fatalf("sums[work] is not the hash of the stored rotation %s", stored)
	}
	if got, err := rs.Get("work"); err != nil || got != stored {
		t.Fatalf("Get through the wrapper = %q, %v; want the stored value", got, err)
	}
}

// failSetStore is a mapStore whose Set always fails.
type failSetStore struct{ *mapStore }

func (failSetStore) Set(string, string) error { return errors.New("keyring locked") }

// TestFactory_FailedSaveKeepsOldHash checks that a write that failed
// does not change the hash: the store still holds the old secret, so
// the old hash stays correct.
//
// arch: DR1G.6, DR1G.18, IR1G.7
func TestFactory_FailedSaveKeepsOldHash(t *testing.T) {
	const old = `{"v":1,"kind":"oauth","refresh_token":"rt-1"}`
	store := failSetStore{newMapStore()}
	store.data["work"] = old
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	f.sums["work"] = sha256.Sum256([]byte(old))

	rt := &aliasRefreshTokenStore{store: &recordingStore{Store: store, f: f}, alias: "work"}
	if err := rt.SaveRefreshToken("rt-2"); err == nil {
		t.Fatal("SaveRefreshToken gave no error, want the store error")
	}
	if store.data["work"] != old {
		t.Fatalf("store changed to %s after a failed write", store.data["work"])
	}
	if f.sums["work"] != sha256.Sum256([]byte(old)) {
		t.Fatal("sums[work] changed after a failed write")
	}
}

// errRefused is the server refusal that the fake dials below give.
var errRefused = &imap.AuthError{Err: errors.New("NO [AUTHENTICATIONFAILED] invalid credentials")}

// switchDial puts a fake dial in place that gives what *result holds
// at each call. A nil result is a login that succeeded.
func switchDial(t *testing.T, result *error) {
	t.Helper()
	saved := dialAccountFunc
	dialAccountFunc = func(context.Context, config.Account, imap.Credential, io.Writer) (*imapclient.Client, error) {
		return nil, *result
	}
	t.Cleanup(func() { dialAccountFunc = saved })
}

// dirNames gives the sorted names in dir.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestFactory_AuthStateZeroIsUnknown checks IR1G.8: a new Factory
// knows no state, an error that is not a login result does not set
// one, and no state reaches the disk.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func TestFactory_AuthStateZeroIsUnknown(t *testing.T) {
	passwordAccount(t, "pw-1")
	dir, err := config.ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	before := dirNames(t, dir)
	result := error(errDialed)
	switchDial(t, &result)
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	if got := f.AuthState("work"); got != AuthUnknown {
		t.Fatalf("state of a new Factory = %q, want unknown", got)
	}
	if _, err := f.dial(context.Background(), "work"); !errors.Is(err, errDialed) {
		t.Fatalf("dial error = %v, want the network error", err)
	}
	if got := f.AuthState("work"); got != AuthUnknown {
		t.Fatalf("state after a network error = %q, want unknown: only a login result sets a state", got)
	}
	result = nil
	if _, err := f.dial(context.Background(), "work"); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if after := dirNames(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("config dir = %v after logins, want %v: the state lives in memory only", after, before)
	}
}

// TestFactory_AuthStateOKOnlyAfterLogin checks IR1G.8: only a login
// that succeeded sets ok, and a later success replaces a refusal.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func TestFactory_AuthStateOKOnlyAfterLogin(t *testing.T) {
	passwordAccount(t, "pw-1")
	result := error(errDialed)
	switchDial(t, &result)
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	_, _ = f.dial(context.Background(), "work")
	if got := f.AuthState("work"); got == AuthOK {
		t.Fatal("state = ok after a dial that failed")
	}

	result = nil
	if _, err := f.dial(context.Background(), "work"); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := f.AuthState("work"); got != AuthOK {
		t.Fatalf("state after a login that succeeded = %q, want ok", got)
	}
	if got := f.AuthState("home"); got != AuthUnknown {
		t.Fatalf("state of an alias with no login = %q, want unknown", got)
	}
}

// TestFactory_AuthStateNeedsAuth checks that a needs-auth error from
// Token() sets needs_auth, on the dial path and on the credential
// path of send, and that the error keeps the reauth text.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func TestFactory_AuthStateNeedsAuth(t *testing.T) {
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
	cfg := fakeMSTokenEndpoint(t, func(string) (int, map[string]any) {
		return http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "AADSTS70008: expired"}
	})
	savedCfg := oauthConfigFunc
	oauthConfigFunc = func(string, string, string) (*oauth2.Config, error) { return cfg, nil }
	t.Cleanup(func() { oauthConfigFunc = savedCfg })
	result := error(nil)
	switchDial(t, &result)

	f := NewFactory(nil)
	t.Cleanup(f.Close)
	_, err = f.dial(context.Background(), "work")
	if !errors.Is(err, oauthpkg.ErrNeedsAuth) {
		t.Fatalf("dial error = %v, want ErrNeedsAuth", err)
	}
	if !strings.Contains(err.Error(), oauthpkg.NeedsAuthText("work")) {
		t.Fatalf("dial error = %q, want the reauth text", err)
	}
	if got := f.AuthState("work"); got != AuthNeedsSignIn {
		t.Fatalf("state after dial = %q, want needs_auth", got)
	}

	g := NewFactory(nil)
	t.Cleanup(g.Close)
	if _, err := g.credentialFunc("work")(context.Background()); !errors.Is(err, oauthpkg.ErrNeedsAuth) {
		t.Fatalf("credential error = %v, want ErrNeedsAuth", err)
	}
	if got := g.AuthState("work"); got != AuthNeedsSignIn {
		t.Fatalf("state after the send credential read = %q, want needs_auth", got)
	}
}

// TestFactory_AuthStateLoginRefused checks that a refusal by the
// server sets login_refused, that the refusal window keeps it, and
// that reads of the state while logins run are free of races.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func TestFactory_AuthStateLoginRefused(t *testing.T) {
	passwordAccount(t, "pw-1")
	result := error(errRefused)
	switchDial(t, &result)
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_ = f.AuthState("work")
			}
		}
	}()
	for i := 0; i < 3; i++ {
		if _, err := f.dial(context.Background(), "work"); err == nil {
			t.Errorf("dial %d gave no error, want the refusal", i+1)
		}
	}
	close(stop)
	<-done

	if got := f.AuthState("work"); got != AuthLoginRefused {
		t.Fatalf("state = %q, want login_refused", got)
	}
}

// TestFactory_AuthStateResetOnSecretChange checks that a refusal that
// ends because the secret changed sets the state back to unknown, and
// that the next login result then decides.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func TestFactory_AuthStateResetOnSecretChange(t *testing.T) {
	passwordAccount(t, "pw-1")
	result := error(errRefused)
	switchDial(t, &result)
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	if _, err := f.dial(context.Background(), "work"); err == nil {
		t.Fatal("first dial gave no error, want the refusal")
	}
	if got := f.AuthState("work"); got != AuthLoginRefused {
		t.Fatalf("state = %q, want login_refused", got)
	}

	writePassword(t, "pw-2")
	result = errDialed
	if _, err := f.dial(context.Background(), "work"); !errors.Is(err, errDialed) {
		t.Fatalf("dial after the new secret: error = %v, want a new login attempt", err)
	}
	if got := f.AuthState("work"); got != AuthUnknown {
		t.Fatalf("state after the secret changed = %q, want unknown until a login decides", got)
	}

	result = nil
	if _, err := f.dial(context.Background(), "work"); err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got := f.AuthState("work"); got != AuthOK {
		t.Fatalf("state after a login with the new secret = %q, want ok", got)
	}
}
