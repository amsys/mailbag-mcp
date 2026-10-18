// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the jmap branch of the Factory (DS78.3): Open and OpenWriter
// give the JMAP provider over two guarded clients (DS8.3, IS8.1), the
// private_host key decides if the session host may be private (G11),
// and a 401 starts the refusal window (DRV.10, IS78.4). A fake JMAP
// server answers in process through HTTPOptions.Base, or a fake
// resolver gives an address that the guard refuses before any dial, so
// no test reaches the network (IS78.1).

package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// jmapTestHost is the session host of the JMAP account of these tests.
const jmapTestHost = "mail.example.test"

// jmapAccount writes an accounts.toml with the jmap account "home" plus
// extra lines of its block, and the secret of "home" into the file
// store. It gives the config directory.
func jmapAccount(t *testing.T, extra, secret string) string {
	t.Helper()
	writeAccounts(t, `
secrets = "file"

[accounts.home]
provider = "jmap"
email = "ann@example.test"
session_url = "https://`+jmapTestHost+`/.well-known/jmap"
`+extra+"\n")
	dir, err := config.ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	writeJMAPSecret(t, dir, secret)
	return dir
}

// writeJMAPSecret writes the secret of account "home" as another
// process does (account add): straight to the file store.
func writeJMAPSecret(t *testing.T, dir, secret string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "home"), []byte(secret), 0o600); err != nil {
		t.Fatalf("write account secret: %v", err)
	}
}

// jmapFake is a fake JMAP server: the session object and Mailbox/get.
// It records the Authorization header of each request. While status is
// not 0, every request gets that status.
type jmapFake struct {
	mu     sync.Mutex
	auths  []string
	status int
}

func (j *jmapFake) setStatus(s int) {
	j.mu.Lock()
	j.status = s
	j.mu.Unlock()
}

// requests gives the number of requests so far.
func (j *jmapFake) requests() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.auths)
}

// lastAuth gives the Authorization header of the last request.
func (j *jmapFake) lastAuth() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.auths) == 0 {
		return ""
	}
	return j.auths[len(j.auths)-1]
}

func (j *jmapFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	j.mu.Lock()
	j.auths = append(j.auths, r.Header.Get("Authorization"))
	status := j.status
	j.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/.well-known/jmap":
		_, _ = w.Write([]byte(`{"capabilities":{"urn:ietf:params:jmap:core":{"maxSizeUpload":1000000},"urn:ietf:params:jmap:mail":{}},` +
			`"primaryAccounts":{"urn:ietf:params:jmap:mail":"A1"},` +
			`"apiUrl":"https://` + jmapTestHost + `/api",` +
			`"downloadUrl":"https://` + jmapTestHost + `/dl/{accountId}/{blobId}/{name}?type={type}",` +
			`"uploadUrl":"https://` + jmapTestHost + `/up/{accountId}"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api":
		_, _ = w.Write([]byte(`{"methodResponses":[["Mailbox/get",{"accountId":"A1","state":"1","list":[` +
			`{"id":"mb1","name":"Inbox","role":"inbox","totalEmails":3,"unreadEmails":1}],"notFound":[]},"m"]],"sessionState":"s1"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// handlerTransport serves each request with an http.Handler in
// process: no socket, no DNS.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// setGuardHook puts hook in guardOptionsHook for this test.
func setGuardHook(t *testing.T, hook func(*guard.HTTPOptions)) {
	t.Helper()
	saved := guardOptionsHook
	guardOptionsHook = hook
	t.Cleanup(func() { guardOptionsHook = saved })
}

// fakeJMAPServer starts a jmapFake and sends every request of the
// JMAP clients that the Factory builds in this test to it (G4 Base).
func fakeJMAPServer(t *testing.T) *jmapFake {
	t.Helper()
	j := &jmapFake{}
	setGuardHook(t, func(o *guard.HTTPOptions) { o.Base = handlerTransport{h: j} })
	return j
}

// jmapFolders opens alias and lists its folders under a short limit.
func jmapFolders(f *Factory, alias string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, _, err := f.Open(ctx, alias)
	if err != nil {
		return nil, err
	}
	folders, err := r.Folders(ctx)
	var names []string
	for _, fo := range folders {
		names = append(names, fo.Name)
	}
	return names, err
}

// TestFactory_OpenJMAP checks the jmap branch of Open and OpenWriter
// (DS78.3): both give the *jmap.Provider of the account, Open sends no
// request, a token secret becomes a Bearer header and a password secret
// HTTP Basic with the username of the account (F5, DS8.6), the client
// of the alias is kept for the next call (DS78.11 G6), and an unreadable
// tls_ca fails the open.
//
// arch: DS78.3, DS8.3, DS8.6, DS78.8, IS8.1, IS78.2, IS78.3, IS78.4, DRV.10, G11
func TestFactory_OpenJMAP(t *testing.T) {
	t.Run("token secret gives Bearer, the client is kept", func(t *testing.T) {
		jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
		srv := fakeJMAPServer(t)
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		r, acct, err := f.Open(context.Background(), "home")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if _, ok := r.(*jmap.Provider); !ok {
			t.Fatalf("Open gave %T, want *jmap.Provider", r)
		}
		if acct.Provider != "jmap" || acct.Alias != "home" {
			t.Fatalf("Open gave the account %+v", acct)
		}
		if _, ok := r.(CapsReporter); !ok {
			t.Fatal("the JMAP provider gives no CapsReporter")
		}
		if srv.requests() != 0 {
			t.Fatalf("Open sent %d requests, want 0", srv.requests())
		}
		w, _, err := f.OpenWriter(context.Background(), "home")
		if err != nil {
			t.Fatalf("OpenWriter: %v", err)
		}
		if _, ok := w.(*jmap.Provider); !ok {
			t.Fatalf("OpenWriter gave %T, want *jmap.Provider", w)
		}

		names, err := jmapFolders(f, "home")
		if err != nil {
			t.Fatalf("Folders: %v", err)
		}
		if len(names) != 1 || names[0] != "Inbox" {
			t.Fatalf("folders = %v, want [Inbox]", names)
		}
		if got := srv.lastAuth(); got != "Bearer tok-1" {
			t.Fatalf("Authorization = %q, want the bearer token", got)
		}
		// Session GET plus Mailbox/get. The second call reuses the kept
		// session of the kept client: one more request only.
		if srv.requests() != 2 {
			t.Fatalf("requests = %d after one Folders, want 2", srv.requests())
		}
		if _, err := jmapFolders(f, "home"); err != nil {
			t.Fatalf("second Folders: %v", err)
		}
		if srv.requests() != 3 {
			t.Fatalf("requests = %d after two Folders, want 3: the client of the alias must be kept", srv.requests())
		}
	})

	t.Run("password secret gives Basic", func(t *testing.T) {
		jmapAccount(t, `username = "ann"`, `{"v":1,"kind":"password","password":"pw-1"}`)
		srv := fakeJMAPServer(t)
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		if _, err := jmapFolders(f, "home"); err != nil {
			t.Fatalf("Folders: %v", err)
		}
		req, _ := http.NewRequest(http.MethodGet, "https://x/", nil)
		req.SetBasicAuth("ann", "pw-1")
		if got, want := srv.lastAuth(), req.Header.Get("Authorization"); got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
	})

	t.Run("an oauth secret is refused", func(t *testing.T) {
		jmapAccount(t, "", `{"v":1,"kind":"oauth","refresh_token":"rt-1"}`)
		fakeJMAPServer(t)
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		_, _, err := f.Open(context.Background(), "home")
		if err == nil || !strings.Contains(err.Error(), "does not sign in with OAuth") {
			t.Fatalf("Open error = %v, want the OAuth refusal", err)
		}
	})

	t.Run("unreadable tls_ca fails the open", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-ca.pem")
		jmapAccount(t, `tls_ca = "`+missing+`"`, `{"v":1,"kind":"token","token":"tok-1"}`)
		fakeJMAPServer(t)
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		_, _, err := f.Open(context.Background(), "home")
		if err == nil || !strings.Contains(err.Error(), "tls_ca") {
			t.Fatalf("Open error = %v, want an error that names tls_ca", err)
		}
	})
}

// TestFactory_JMAPClientIsGuarded checks IS8.1 and G11 on the clients
// that the Factory builds: both are guarded (guard.IsGuarded, so Base
// is not set in production), have no time limit of their own and carry
// the DS8.3 caps; PrivateHost is the session host only with
// private_host = true; without the key a private session host fails
// with a text that names the key, and with it the loopback stays
// refused.
//
// arch: DS78.3, DS8.3, DS8.6, DS78.8, IS8.1, IS78.2, IS78.3, IS78.4, DRV.10, G11
func TestFactory_JMAPClientIsGuarded(t *testing.T) {
	t.Run("production clients are guarded", func(t *testing.T) {
		jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		if _, _, err := f.Open(context.Background(), "home"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		f.mu.Lock()
		conn := f.jmapClients["home"]
		f.mu.Unlock()
		if conn == nil {
			t.Fatal("the Factory keeps no JMAP client for the alias")
		}
		for name, c := range map[string]*http.Client{"api": conn.api, "blob": conn.blob} {
			if !guard.IsGuarded(c) {
				t.Errorf("the %s client is not guarded (IS8.1)", name)
			}
			if c.Timeout != 0 {
				t.Errorf("the %s client has Timeout %v, want none (NoTimeout)", name, c.Timeout)
			}
		}
	})

	t.Run("options per private_host", func(t *testing.T) {
		for _, tc := range []struct {
			extra, want string
		}{
			{"", ""},
			{"private_host = true", jmapTestHost},
		} {
			jmapAccount(t, tc.extra, `{"v":1,"kind":"token","token":"tok-1"}`)
			var mu sync.Mutex
			var seen []guard.HTTPOptions
			setGuardHook(t, func(o *guard.HTTPOptions) {
				mu.Lock()
				seen = append(seen, *o)
				mu.Unlock()
			})
			f := NewFactory(nil)
			t.Cleanup(f.Close)
			if _, _, err := f.Open(context.Background(), "home"); err != nil {
				t.Fatalf("Open (%q): %v", tc.extra, err)
			}
			mu.Lock()
			got := append([]guard.HTTPOptions(nil), seen...)
			mu.Unlock()
			if len(got) != 2 {
				t.Fatalf("%q: %d clients built, want 2 (api, blob)", tc.extra, len(got))
			}
			for i, maxBody := range []int64{8 << 20, 32 << 20} {
				o := got[i]
				if o.MaxBody != maxBody || o.Timeout != guard.NoTimeout || o.PrivateHost != tc.want || o.Base != nil {
					t.Errorf("%q: client %d options = {MaxBody %d, Timeout %v, PrivateHost %q, Base %v}, want {%d, NoTimeout, %q, nil}",
						tc.extra, i, o.MaxBody, o.Timeout, o.PrivateHost, o.Base, maxBody, tc.want)
				}
			}
		}
	})

	t.Run("private address without the key names the key", func(t *testing.T) {
		jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
		setGuardHook(t, func(o *guard.HTTPOptions) {
			o.LookupNetIP = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
			}
		})
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		_, err := jmapFolders(f, "home")
		want := "set private_host = true for account home"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Folders error = %v, want the text %q", err, want)
		}
	})

	t.Run("private_host still refuses the loopback", func(t *testing.T) {
		jmapAccount(t, "private_host = true", `{"v":1,"kind":"token","token":"tok-1"}`)
		setGuardHook(t, func(o *guard.HTTPOptions) {
			o.LookupNetIP = func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
		})
		f := NewFactory(nil)
		t.Cleanup(f.Close)

		_, err := jmapFolders(f, "home")
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("Folders error = %v, want the guard's loopback refusal", err)
		}
	})
}

// TestFactory_JMAPRefusalWindow checks DRV.10 and IS78.4 for JMAP: a
// 401 gives *jmap.AuthError and the state login_refused; for 10 min the
// same secret gets the refusal text and no request reaches the server;
// after the window the next call goes out again; a changed secret ends
// the refusal at once and its new token is sent.
//
// arch: DS78.3, DS8.3, DS8.6, DS78.8, IS8.1, IS78.2, IS78.3, IS78.4, DRV.10, G11
func TestFactory_JMAPRefusalWindow(t *testing.T) {
	t.Run("same secret waits for the window", func(t *testing.T) {
		jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
		srv := fakeJMAPServer(t)
		srv.setStatus(http.StatusUnauthorized)
		f := NewFactory(nil)
		t.Cleanup(f.Close)
		clock := &testClock{t: time.Now().Round(0)}
		f.now = clock.now

		_, err := jmapFolders(f, "home")
		var ae *jmap.AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("Folders error = %v, want *jmap.AuthError", err)
		}
		if got := f.AuthState("home"); got != AuthLoginRefused {
			t.Fatalf("state = %q, want login_refused", got)
		}
		reqs := srv.requests()

		_, _, err = f.Open(context.Background(), "home")
		if err == nil || !strings.Contains(err.Error(), "login refused by the server") || !errors.As(err, &ae) {
			t.Fatalf("Open in the refusal window: error = %v, want the refusal text", err)
		}
		if _, _, err := f.OpenWriter(context.Background(), "home"); err == nil {
			t.Fatal("OpenWriter in the refusal window gave no error")
		}
		clock.add(authRefusal - time.Second)
		if _, _, err := f.Open(context.Background(), "home"); err == nil {
			t.Fatal("Open 1 s before the end of the window gave no error")
		}
		if srv.requests() != reqs {
			t.Fatal("a call in the refusal window reached the server (IS78.4)")
		}

		clock.add(2 * time.Second)
		srv.setStatus(0)
		if _, err := jmapFolders(f, "home"); err != nil {
			t.Fatalf("Folders after the window: %v", err)
		}
		if srv.requests() == reqs {
			t.Fatal("the call after the window sent no request")
		}
	})

	t.Run("a changed secret ends the refusal", func(t *testing.T) {
		dir := jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
		srv := fakeJMAPServer(t)
		srv.setStatus(http.StatusUnauthorized)
		f := NewFactory(nil)
		t.Cleanup(f.Close)
		clock := &testClock{t: time.Now().Round(0)}
		f.now = clock.now

		if _, err := jmapFolders(f, "home"); err == nil {
			t.Fatal("Folders with a refused token gave no error")
		}
		if got := f.AuthState("home"); got != AuthLoginRefused {
			t.Fatalf("state = %q, want login_refused", got)
		}

		writeJMAPSecret(t, dir, `{"v":1,"kind":"token","token":"tok-2"}`)
		srv.setStatus(0)
		if _, err := jmapFolders(f, "home"); err != nil {
			t.Fatalf("Folders with the new secret: %v", err)
		}
		if got := srv.lastAuth(); got != "Bearer tok-2" {
			t.Fatalf("Authorization = %q, want the new token", got)
		}
		if got := f.AuthState("home"); got == AuthLoginRefused {
			t.Fatal("the state stays login_refused after the secret changed")
		}
	})
}

// idleCounter is an http.RoundTripper that counts the calls of
// CloseIdleConnections. It sends no request.
type idleCounter struct {
	mu     sync.Mutex
	closes int
}

func (c *idleCounter) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("idleCounter sends no request")
}

func (c *idleCounter) CloseIdleConnections() {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
}

func (c *idleCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// TestFactory_JMAPOldClientsClosed holds R16-L25: when forget drops
// the JMAP client of an alias, or openJMAP replaces it because a value
// of jmapKey changed, the Factory closes the idle connections of the
// old API client and the old blob client. Else each replace leaves the
// sockets of the old clients open until the server ends them.
//
// arch: DS78.11 G6, DS8.3, R16-L25
func TestFactory_JMAPOldClientsClosed(t *testing.T) {
	// swap puts counting transports under the kept clients of "home".
	swap := func(t *testing.T, f *Factory) (api, blob *idleCounter) {
		t.Helper()
		f.mu.Lock()
		defer f.mu.Unlock()
		conn := f.jmapClients["home"]
		if conn == nil {
			t.Fatal("the Factory keeps no JMAP client for the alias")
		}
		api, blob = &idleCounter{}, &idleCounter{}
		conn.api.Transport, conn.blob.Transport = api, blob
		return api, blob
	}

	t.Run("forget", func(t *testing.T) {
		jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
		fakeJMAPServer(t)
		f := NewFactory(nil)
		t.Cleanup(f.Close)
		if _, _, err := f.Open(context.Background(), "home"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		api, blob := swap(t, f)
		f.forget("home")
		if api.count() != 1 || blob.count() != 1 {
			t.Errorf("CloseIdleConnections calls: api %d, blob %d, want 1 and 1", api.count(), blob.count())
		}
	})

	t.Run("changed key", func(t *testing.T) {
		jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
		fakeJMAPServer(t)
		f := NewFactory(nil)
		t.Cleanup(f.Close)
		if _, _, err := f.Open(context.Background(), "home"); err != nil {
			t.Fatalf("Open: %v", err)
		}
		api, blob := swap(t, f)
		f.mu.Lock()
		f.jmapClients["home"].key.tlsCA = "changed"
		f.mu.Unlock()
		if _, _, err := f.Open(context.Background(), "home"); err != nil {
			t.Fatalf("second Open: %v", err)
		}
		if api.count() != 1 || blob.count() != 1 {
			t.Errorf("CloseIdleConnections calls: api %d, blob %d, want 1 and 1", api.count(), blob.count())
		}
	})
}

// TestProviderJMAP_SaveDraftKeepsSignature checks I1 for JMAP: the text
// body value of the Email/set draft holds "-- \n" + the signature byte
// for byte. DI6.1: the JMAP provider is unchanged, so the From check is
// the server identity list, and no Identity/get is added to the draft
// path beyond the one that DS8.2a already makes.
//
// arch: DI6.1, I1
func TestProviderJMAP_SaveDraftKeepsSignature(t *testing.T) {
	jmapAccount(t, "", `{"v":1,"kind":"token","token":"tok-1"}`)
	var mu sync.Mutex
	var text string
	var identityGets int
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"capabilities":{"urn:ietf:params:jmap:core":{"maxSizeUpload":1000000},"urn:ietf:params:jmap:mail":{},"urn:ietf:params:jmap:submission":{}},` +
				`"primaryAccounts":{"urn:ietf:params:jmap:mail":"A1"},` +
				`"apiUrl":"https://` + jmapTestHost + `/api",` +
				`"downloadUrl":"https://` + jmapTestHost + `/dl/{accountId}/{blobId}/{name}?type={type}",` +
				`"uploadUrl":"https://` + jmapTestHost + `/up/{accountId}"}`))
			return
		}
		var req struct {
			Raw []json.RawMessage `json:"methodCalls"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Raw) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var call [3]json.RawMessage
		_ = json.Unmarshal(req.Raw[0], &call)
		var name, id string
		var args map[string]any
		_ = json.Unmarshal(call[0], &name)
		_ = json.Unmarshal(call[1], &args)
		_ = json.Unmarshal(call[2], &id)
		var out string
		switch name {
		case "Mailbox/get":
			out = `{"accountId":"A1","state":"1","list":[{"id":"mb1","name":"Drafts","role":"drafts"}],"notFound":[]}`
		case "Identity/get":
			mu.Lock()
			identityGets++
			mu.Unlock()
			out = `{"accountId":"A1","state":"1","list":[{"id":"i1","name":"Ann","email":"ann@example.test"}],"notFound":[]}`
		case "Email/set":
			if c, ok := args["create"].(map[string]any); ok {
				if d, ok := c["draft"].(map[string]any); ok {
					if bv, ok := d["bodyValues"].(map[string]any); ok {
						if tv, ok := bv["text"].(map[string]any); ok {
							mu.Lock()
							text, _ = tv["value"].(string)
							mu.Unlock()
						}
					}
				}
			}
			out = `{"accountId":"A1","oldState":"1","newState":"2","created":{"draft":{"id":"e1"}}}`
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"methodResponses":[["` + name + `",` + out + `,"` + id + `"]],"sessionState":"s1"}`))
	})
	setGuardHook(t, func(o *guard.HTTPOptions) { o.Base = handlerTransport{h: h} })
	f := NewFactory(nil)
	t.Cleanup(f.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, _, err := f.OpenWriter(ctx, "home")
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}

	const sig = "Ann Example\nExample Ltd"
	m := &mail.Outgoing{From: "Ann <ann@example.test>", To: []string{"bob@example.org"}, Subject: "hi", Text: "Hello.\n\n-- \n" + sig}
	if _, err := w.SaveDraft(ctx, m, ""); err != nil {
		t.Fatalf("SaveDraft: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(text, "-- \n"+sig) {
		t.Errorf("text body value = %q, want it to hold %q byte for byte", text, "-- \n"+sig)
	}
	if identityGets != 1 {
		t.Errorf("Identity/get calls = %d, want 1 (the DS8.2a check only)", identityGets)
	}
}
