// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the gmail branch of the Factory (DS78.3): Open and
// OpenWriter give the Gmail provider, the token comes from the
// TokenSource that the oauth.google client builds, the auth events set
// the sign-in state and the refusal window, and no Google client value
// reaches an error or a log line (IS7.5). A fake token endpoint and a
// fake Gmail API on httptest serve every call, so no test reaches the
// network (IS78.1). The client id and the project number are made up
// (IS7.1).

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	netmail "net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
)

// The Google client of these tests. The values are made up (IS7.1).
const (
	gmailTestProject  = "314159265358"
	gmailTestClientID = gmailTestProject + "-test-client.apps.googleusercontent.com"
	gmailTestSecret   = "test-google-client-secret-1"
)

// gmailAccount writes an accounts.toml with the gmail account "work",
// the oauth.google client and the oauth secret of "work" into the file
// store of a new config directory, and gives that directory.
func gmailAccount(t *testing.T) string {
	t.Helper()
	writeAccounts(t, `
secrets = "file"

[accounts.work]
provider = "gmail"
email = "ann@example.com"
`)
	dir, err := config.ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	client := `{"client_id":"` + gmailTestClientID + `","client_secret":"` + gmailTestSecret + `"}`
	if err := os.WriteFile(filepath.Join(dir, googleClientKey), []byte(client), 0o600); err != nil {
		t.Fatalf("write the Google client: %v", err)
	}
	writeOAuthSecret(t, dir, "rt-g1")
	return dir
}

// googleTokenFake is a fake Google token endpoint. It counts its calls
// and keeps the form of the last one.
type googleTokenFake struct {
	mu    sync.Mutex
	calls int
	form  url.Values
}

// count gives the number of token calls so far.
func (g *googleTokenFake) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

// lastForm gives the form of the last token call.
func (g *googleTokenFake) lastForm() url.Values {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.form
}

// fakeGoogleToken starts a token endpoint that answers with respond
// and points googleConfigFunc at it for this test. respond gets the
// number of the call, from 1.
func fakeGoogleToken(t *testing.T, respond func(n int) (int, map[string]any)) *googleTokenFake {
	t.Helper()
	g := &googleTokenFake{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		g.mu.Lock()
		g.calls++
		n := g.calls
		g.form = r.PostForm
		g.mu.Unlock()
		status, body := respond(n)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	saved := googleConfigFunc
	googleConfigFunc = func(c oauthpkg.GoogleClient, redirectURL string) *oauth2.Config {
		cfg := oauthpkg.GoogleConfig(c, redirectURL)
		cfg.Endpoint.TokenURL = srv.URL + "/token"
		return cfg
	}
	t.Cleanup(func() { googleConfigFunc = saved })
	return g
}

// tokenSeq answers each token call n with the access token "at-<n>",
// valid for one hour.
func tokenSeq(n int) (int, map[string]any) {
	return http.StatusOK, map[string]any{
		"access_token": "at-" + strconv.Itoa(n),
		"token_type":   "Bearer",
		"expires_in":   3600,
	}
}

// gmailAPIFake is a fake Gmail REST API. It records the Authorization
// header of each request.
type gmailAPIFake struct {
	mu    sync.Mutex
	auths []string
	route func(r *http.Request) (int, string)
}

// requests gives the number of requests so far.
func (g *gmailAPIFake) requests() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.auths)
}

// setRoute changes the answers of the fake.
func (g *gmailAPIFake) setRoute(route func(r *http.Request) (int, string)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.route = route
}

// rewriteGmail sends each request for gmail.googleapis.com to the fake
// and every other request to base unchanged. It is the seam to the
// fixed baseURL of internal/gmail, which this package cannot set.
type rewriteGmail struct {
	base   http.RoundTripper
	target *url.URL
}

func (r rewriteGmail) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "gmail.googleapis.com" {
		req = req.Clone(req.Context())
		req.URL.Scheme = r.target.Scheme
		req.URL.Host = r.target.Host
		req.Host = ""
	}
	return r.base.RoundTrip(req)
}

// fakeGmailAPI starts a fake Gmail API and sends every request for
// gmail.googleapis.com to it for this test. No test in this package
// runs in parallel, so the change of http.DefaultTransport reaches
// this test only.
func fakeGmailAPI(t *testing.T, route func(r *http.Request) (int, string)) *gmailAPIFake {
	t.Helper()
	g := &gmailAPIFake{route: route}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.auths = append(g.auths, r.Header.Get("Authorization"))
		route := g.route
		g.mu.Unlock()
		status, body := route(r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse fake URL: %v", err)
	}
	saved := http.DefaultTransport
	http.DefaultTransport = rewriteGmail{base: saved, target: target}
	t.Cleanup(func() { http.DefaultTransport = saved })
	return g
}

// labelsOK answers labels.list with INBOX and labels.get with its
// counts.
func labelsOK(r *http.Request) (int, string) {
	switch r.URL.Path {
	case "/gmail/v1/users/me/labels":
		return http.StatusOK, `{"labels":[{"id":"INBOX","name":"INBOX","type":"system"}]}`
	case "/gmail/v1/users/me/labels/INBOX":
		return http.StatusOK, `{"id":"INBOX","name":"INBOX","type":"system","messagesTotal":3,"messagesUnread":1}`
	}
	return http.StatusNotFound, `{"error":{"code":404,"message":"not found","errors":[{"reason":"notFound"}]}}`
}

// apiOff is the 403 of a Cloud project with the Gmail API off. The
// server message names the project, as Google does.
func apiOff(*http.Request) (int, string) {
	return http.StatusForbidden, `{"error":{"code":403,"message":"Gmail API has not been used in project ` + gmailTestProject +
		` before or it is disabled. Client ` + gmailTestClientID + ` secret ` + gmailTestSecret +
		`","errors":[{"reason":"accessNotConfigured","message":"project ` + gmailTestProject + `"}]}}`
}

// openFolders opens alias through f and lists its folders.
func openFolders(f *Factory, alias string) ([]string, error) {
	r, _, err := f.Open(context.Background(), alias)
	if err != nil {
		return nil, err
	}
	folders, err := r.Folders(context.Background())
	var names []string
	for _, fo := range folders {
		names = append(names, fo.Name)
	}
	return names, err
}

// TestFactory_OpenGmail checks that Open and OpenWriter give the Gmail
// provider for a gmail account with no network call, that the first
// API call carries an access token from the TokenSource that the
// oauth.google client and the account's refresh token build, that the
// TokenSource is kept for later calls, and that the Gmail caches are
// shared per alias and dropped by forget (G6).
//
// arch: DS78.3, DS7.2, DS7.7, DS78.1, IS7.2, IS7.5, IS78.2, IS78.3, IS78.4, DRV.10
func TestFactory_OpenGmail(t *testing.T) {
	gmailAccount(t)
	tok := fakeGoogleToken(t, tokenSeq)
	api := fakeGmailAPI(t, labelsOK)
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	r, acct, err := f.Open(context.Background(), "work")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := r.(*gmail.Provider); !ok {
		t.Fatalf("Open gave %T, want *gmail.Provider", r)
	}
	if _, ok := r.(CapsReporter); !ok {
		t.Fatal("the Gmail provider is not a CapsReporter")
	}
	if acct.Provider != "gmail" || acct.Email != "ann@example.com" {
		t.Fatalf("account = %+v", acct)
	}
	w, _, err := f.OpenWriter(context.Background(), "work")
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	if _, ok := w.(*gmail.Provider); !ok {
		t.Fatalf("OpenWriter gave %T, want *gmail.Provider", w)
	}
	if tok.count() != 0 || api.requests() != 0 {
		t.Fatalf("Open made calls: token %d, api %d; want none before the first API call", tok.count(), api.requests())
	}

	folders, err := r.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if len(folders) != 1 || folders[0].Name != "INBOX" || folders[0].Total != 3 || folders[0].Unread != 1 {
		t.Fatalf("folders = %+v", folders)
	}
	form := tok.lastForm()
	if form.Get("client_id") != gmailTestClientID || form.Get("client_secret") != gmailTestSecret ||
		form.Get("refresh_token") != "rt-g1" || form.Get("grant_type") != "refresh_token" {
		t.Fatalf("token request = %v; want the oauth.google client and the refresh token of work", form)
	}
	api.mu.Lock()
	for i, a := range api.auths {
		if a != "Bearer at-1" {
			t.Errorf("request %d: Authorization = %q, want Bearer at-1", i, a)
		}
	}
	api.mu.Unlock()
	if got := f.AuthState("work"); got != AuthOK {
		t.Fatalf("state = %q, want ok", got)
	}

	// A second call on a new provider uses the kept TokenSource.
	if _, err := openFolders(f, "work"); err != nil {
		t.Fatalf("second Folders: %v", err)
	}
	if tok.count() != 1 {
		t.Fatalf("token calls = %d, want 1: the TokenSource must be kept (B14)", tok.count())
	}

	// The caches are shared per alias, and forget drops them (G6).
	f.mu.Lock()
	st := f.gmailState["work"]
	f.mu.Unlock()
	if st == nil {
		t.Fatal("no Gmail State for work after Open")
	}
	if _, _, err := f.Open(context.Background(), "work"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	f.mu.Lock()
	same := f.gmailState["work"] == st
	f.mu.Unlock()
	if !same {
		t.Fatal("a second Open made a new Gmail State; two sessions must share it (G6)")
	}
	f.forget("work")
	f.mu.Lock()
	_, kept := f.gmailState["work"]
	f.mu.Unlock()
	if kept {
		t.Fatal("forget kept the Gmail State (G6)")
	}

	// The gmail branch of parseCredential gives a token source, and
	// an oauth secret of an account with no OAuth provider still fails.
	if _, err := parseCredential(context.Background(), config.Account{Alias: "work", Provider: "imap"}, `{"v":1,"kind":"oauth","refresh_token":"x"}`, nil, nil); err == nil {
		t.Fatal("an oauth secret was accepted for an imap account")
	}
}

// testClock is a fake wall clock that is safe for calls from more
// than one goroutine.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestFactory_GmailAuthStates checks the auth events of DS78.3: the
// Gmail API off gives api_off and a later good call gives ok; a scope
// error gives needs_auth; the first 401 drops the token and the retry
// gets a new one; a second 401 and a refused refresh token give
// needs_auth and start the 10 min refusal window, which keeps every
// call off the network until it ends or the secret changes (IS78.4).
//
// arch: DS78.3, DS7.2, DS7.7, DS78.1, IS7.2, IS7.5, IS78.2, IS78.3, IS78.4, DRV.10
func TestFactory_GmailAuthStates(t *testing.T) {
	if AuthAPIOff != "api_off" {
		t.Fatalf("AuthAPIOff = %q, want api_off", AuthAPIOff)
	}

	t.Run("api_off", func(t *testing.T) {
		gmailAccount(t)
		fakeGoogleToken(t, tokenSeq)
		api := fakeGmailAPI(t, apiOff)
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		_, err := openFolders(f, "work")
		if !errors.Is(err, gmail.ErrAPIDisabled) {
			t.Fatalf("Folders error = %v, want ErrAPIDisabled", err)
		}
		if got := f.AuthState("work"); got != AuthAPIOff {
			t.Fatalf("state = %q, want api_off", got)
		}
		// The person turns the API on: the next call works, with no
		// refusal window in the way.
		api.setRoute(labelsOK)
		if _, err := openFolders(f, "work"); err != nil {
			t.Fatalf("Folders after the API is on: %v", err)
		}
		if got := f.AuthState("work"); got != AuthOK {
			t.Fatalf("state = %q, want ok", got)
		}
	})

	t.Run("scope", func(t *testing.T) {
		gmailAccount(t)
		fakeGoogleToken(t, tokenSeq)
		fakeGmailAPI(t, func(*http.Request) (int, string) {
			return http.StatusForbidden, `{"error":{"code":403,"message":"Request had insufficient authentication scopes.","errors":[{"reason":"insufficientPermissions"}]}}`
		})
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		if _, err := openFolders(f, "work"); !errors.Is(err, gmail.ErrScope) {
			t.Fatalf("Folders error = %v, want ErrScope", err)
		}
		if got := f.AuthState("work"); got != AuthNeedsSignIn {
			t.Fatalf("state = %q, want needs_auth", got)
		}
	})

	t.Run("first 401 gets a new token", func(t *testing.T) {
		gmailAccount(t)
		tok := fakeGoogleToken(t, tokenSeq)
		fakeGmailAPI(t, func(r *http.Request) (int, string) {
			if r.Header.Get("Authorization") == "Bearer at-1" {
				return http.StatusUnauthorized, `{"error":{"code":401,"message":"Invalid Credentials","errors":[{"reason":"authError"}]}}`
			}
			return labelsOK(r)
		})
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		if _, err := openFolders(f, "work"); err != nil {
			t.Fatalf("Folders: %v; the retry must get a new token (IS7.2)", err)
		}
		if tok.count() != 2 {
			t.Fatalf("token calls = %d, want 2: the 401 must drop the kept token source", tok.count())
		}
		if got := f.AuthState("work"); got != AuthOK {
			t.Fatalf("state = %q, want ok", got)
		}
	})

	t.Run("second 401 starts the refusal window", func(t *testing.T) {
		gmailAccount(t)
		tok := fakeGoogleToken(t, tokenSeq)
		api := fakeGmailAPI(t, func(*http.Request) (int, string) {
			return http.StatusUnauthorized, `{"error":{"code":401,"message":"Invalid Credentials","errors":[{"reason":"authError"}]}}`
		})
		f := NewFactory(nil)
		t.Cleanup(f.Close)
		clock := &testClock{t: time.Now().Round(0)}
		f.now = clock.now

		if _, err := openFolders(f, "work"); !errors.Is(err, oauthpkg.ErrNeedsAuth) {
			t.Fatalf("Folders error = %v, want ErrNeedsAuth", err)
		}
		if got := f.AuthState("work"); got != AuthNeedsSignIn {
			t.Fatalf("state = %q, want needs_auth", got)
		}
		calls, reqs := tok.count(), api.requests()

		_, _, err := f.Open(context.Background(), "work")
		if err == nil || !strings.Contains(err.Error(), "--reauth") || !errors.Is(err, oauthpkg.ErrNeedsAuth) {
			t.Fatalf("Open in the refusal window: error = %v, want the refusal with the reauth text", err)
		}
		if _, _, err := f.OpenWriter(context.Background(), "work"); err == nil {
			t.Fatal("OpenWriter in the refusal window gave no error")
		}
		if tok.count() != calls || api.requests() != reqs {
			t.Fatal("a call in the refusal window reached the network (IS78.4)")
		}

		clock.add(authRefusal + time.Second)
		api.setRoute(labelsOK)
		if _, err := openFolders(f, "work"); err != nil {
			t.Fatalf("Folders after the window: %v", err)
		}
	})

	t.Run("refused refresh token starts the refusal window", func(t *testing.T) {
		dir := gmailAccount(t)
		tok := fakeGoogleToken(t, func(int) (int, map[string]any) {
			return http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "Token has been expired or revoked."}
		})
		api := fakeGmailAPI(t, labelsOK)
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		if _, err := openFolders(f, "work"); !errors.Is(err, oauthpkg.ErrNeedsAuth) {
			t.Fatalf("Folders error = %v, want ErrNeedsAuth", err)
		}
		if got := f.AuthState("work"); got != AuthNeedsSignIn {
			t.Fatalf("state = %q, want needs_auth", got)
		}
		if api.requests() != 0 {
			t.Fatalf("api requests = %d, want 0 with no token", api.requests())
		}
		calls := tok.count()
		if _, err := openFolders(f, "work"); err == nil || !strings.Contains(err.Error(), "login refused") {
			t.Fatalf("second call: error = %v, want the refusal", err)
		}
		if tok.count() != calls {
			t.Fatalf("token calls = %d, want %d: the refusal window must keep the call off the network (IS78.4)", tok.count(), calls)
		}

		// "account add work --reauth" writes a new secret: the window
		// ends at once and the state goes back to unknown.
		writeOAuthSecret(t, dir, "rt-g2")
		if _, _, err := f.Open(context.Background(), "work"); err != nil {
			t.Fatalf("Open after a new secret: %v", err)
		}
		if got := f.AuthState("work"); got != AuthUnknown {
			t.Fatalf("state = %q, want unknown after the secret changed", got)
		}
	})
}

// TestFactory_GmailNeedsAuthNamesTesting checks B9 on the server
// side: when Google refuses the refresh token of a Gmail account, the
// error of the call names the 7-day cause of a consent screen in
// "Testing", and errors.Is still finds ErrNeedsAuth.
//
// arch: DS7.2, DS78.3, B9, R16-L20
func TestFactory_GmailNeedsAuthNamesTesting(t *testing.T) {
	gmailAccount(t)
	fakeGoogleToken(t, func(int) (int, map[string]any) {
		return http.StatusBadRequest, map[string]any{"error": "invalid_grant", "error_description": "Token has been expired or revoked."}
	})
	fakeGmailAPI(t, labelsOK)
	f := NewFactory(nil)
	t.Cleanup(f.Close)

	_, err := openFolders(f, "work")
	if !errors.Is(err, oauthpkg.ErrNeedsAuth) {
		t.Fatalf("Folders error = %v, want ErrNeedsAuth", err)
	}
	for _, part := range []string{`"Testing"`, "7 days", "account add work --reauth"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("Folders error = %q, want it to name %q", err, part)
		}
	}
}

// TestFactory_GmailSecretsRedacted checks IS7.5 on the server side:
// the client id, the client secret and the project number are given
// to the redactor when the client is loaded, so the Gmail-off error
// and its WARN log line show none of them; an oauth.google value that
// is not readable never shows in the error; and a missing client names
// the command that stores it.
//
// arch: DS78.3, DS7.2, DS7.7, DS78.1, IS7.2, IS7.5, IS78.2, IS78.3, IS78.4, DRV.10
func TestFactory_GmailSecretsRedacted(t *testing.T) {
	dir := gmailAccount(t)
	fakeGoogleToken(t, tokenSeq)
	fakeGmailAPI(t, apiOff)

	var logs bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(saved) })

	f := NewFactory(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(f.Close)
	_, err := openFolders(f, "work")
	if !errors.Is(err, gmail.ErrAPIDisabled) {
		t.Fatalf("Folders error = %v, want ErrAPIDisabled", err)
	}
	if logs.Len() == 0 {
		t.Fatal("no log line for the failed call; the test would prove nothing about the log")
	}
	for name, v := range map[string]string{"project number": gmailTestProject, "client id": gmailTestClientID, "client secret": gmailTestSecret} {
		if strings.Contains(err.Error(), v) {
			t.Errorf("the tool error holds the %s: %q", name, err)
		}
		if strings.Contains(logs.String(), v) {
			t.Errorf("the log holds the %s: %q", name, logs.String())
		}
		if strings.Contains(guard.Redact("x "+v+" y"), v) {
			t.Errorf("the %s is not registered with the redactor", name)
		}
	}

	// A broken client value never shows in the error.
	const marker = "MARKER-not-a-client-7f3a"
	if err := os.WriteFile(filepath.Join(dir, googleClientKey), []byte(`{"client_id":"`+marker), 0o600); err != nil {
		t.Fatalf("write the Google client: %v", err)
	}
	g := NewFactory(nil)
	t.Cleanup(g.Close)
	_, err = openFolders(g, "work")
	if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "oauth set google") {
		t.Fatalf("error = %v; want the fixed text that names oauth set google, without the stored value", err)
	}

	// No client at all names the command that stores one.
	if err := os.Remove(filepath.Join(dir, googleClientKey)); err != nil {
		t.Fatalf("remove the Google client: %v", err)
	}
	h := NewFactory(nil)
	t.Cleanup(h.Close)
	if _, err := openFolders(h, "work"); err == nil || !strings.Contains(err.Error(), "no Google OAuth client is configured") {
		t.Fatalf("error = %v; want the text for a missing Google client", err)
	}
}

// TestProviderGmail_SaveDraftKeepsSignature checks I1 for Gmail: the
// text part of the saved draft holds "-- \n" + the signature byte for
// byte. It also checks DI6.1: the Gmail provider is unchanged, so a From
// that is not a verified send-as address fails at SaveDraft and nothing
// is uploaded.
//
// arch: DI6.1, I1
func TestProviderGmail_SaveDraftKeepsSignature(t *testing.T) {
	gmailAccount(t)
	fakeGoogleToken(t, tokenSeq)
	var mu sync.Mutex
	var uploads [][]byte
	fakeGmailAPI(t, func(r *http.Request) (int, string) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/gmail/v1/users/me/settings/sendAs":
			return http.StatusOK, `{"sendAs":[{"sendAsEmail":"ann@example.com","isPrimary":true}]}`
		case r.Method == http.MethodPost && r.URL.Path == "/upload/gmail/v1/users/me/drafts":
			_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				return http.StatusBadRequest, `{}`
			}
			mr := multipart.NewReader(r.Body, params["boundary"])
			for i := 0; ; i++ {
				part, err := mr.NextPart()
				if err != nil {
					break
				}
				b, _ := io.ReadAll(part)
				if i == 1 {
					mu.Lock()
					uploads = append(uploads, b)
					mu.Unlock()
				}
			}
			return http.StatusOK, `{"id":"r1","message":{"id":"m1"}}`
		}
		return http.StatusNotFound, `{"error":{"code":404,"message":"not found"}}`
	})
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	w, _, err := f.OpenWriter(context.Background(), "work")
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}

	const sig = "Ann Example\nExample Ltd"
	m := &mail.Outgoing{From: "Ann <ann@example.com>", To: []string{"bob@example.org"}, Subject: "hi", Text: "Hello.\n\n-- \n" + sig}
	if _, err := w.SaveDraft(context.Background(), m, ""); err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	mu.Lock()
	n := len(uploads)
	var raw []byte
	if n > 0 {
		raw = uploads[0]
	}
	mu.Unlock()
	if n != 1 {
		t.Fatalf("uploads = %d, want 1", n)
	}
	if got := decodedTextPart(t, raw); !strings.Contains(got, "-- \n"+sig) {
		t.Errorf("text part = %q, want it to hold %q byte for byte", got, "-- \n"+sig)
	}

	// A catch-all address that is not a send-as address is refused.
	bad := &mail.Outgoing{From: "info@example.com", To: []string{"bob@example.org"}, Text: "x"}
	if _, err := w.SaveDraft(context.Background(), bad, ""); err == nil {
		t.Fatal("SaveDraft accepted an address that is not a verified send-as address")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(uploads) != 1 {
		t.Errorf("uploads = %d after the refused draft, want 1", len(uploads))
	}
}

// decodedTextPart gives the text of a single-part RFC 822 source, with
// the transfer encoding removed and CRLF changed to LF.
func decodedTextPart(t *testing.T, raw []byte) string {
	t.Helper()
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("read draft source: %v", err)
	}
	var rd io.Reader = msg.Body //nolint:staticcheck // ST1023: rd is assigned a quotedprintable reader below, so it needs the io.Reader type
	if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "quoted-printable") {
		rd = quotedprintable.NewReader(msg.Body)
	}
	b, err := io.ReadAll(rd)
	if err != nil {
		t.Fatalf("read draft body: %v", err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}
