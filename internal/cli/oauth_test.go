// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of "oauth set" and of the Microsoft sign-in flow. They use a
// temp config directory and the file store (sandbox), an httptest
// token endpoint and fake loopback and browser seams, so no test sends
// a request off the machine or opens a browser.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/amsys/mailbag-mcp/internal/guard"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// fakeMicrosoftConfig stands in for oauthpkg.Config: it builds an
// oauth2.Config against an httptest token endpoint instead of the
// real login.microsoftonline.com (DS6.2 says the endpoint is a fixed
// constant, never a URL this package builds from mail or model
// input, so a plain httptest fake is the right double). tokenResponse
// is served for every call, unconditionally: the CLI's own PKCE
// mechanics are already proven in internal/oauth's tests, so this
// helper checks the CLI's wiring only.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func fakeMicrosoftConfig(t *testing.T, tokenResponse map[string]any) func(clientID, tenant, redirectURL string) (*oauth2.Config, error) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse)
	}))
	t.Cleanup(srv.Close)
	return func(clientID, _, redirectURL string) (*oauth2.Config, error) {
		return &oauth2.Config{
			ClientID:    clientID,
			RedirectURL: redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:   srv.URL + "/authorize",
				TokenURL:  srv.URL + "/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
		}, nil
	}
}

// extractState pulls the "state=" value out of the authorize URL that
// signInMicrosoft already printed to stderr by the time a test's
// ReadLine fake runs, so the fake can build a redirect URL whose
// state matches this one sign-in attempt (§3.6: state is generated
// fresh and compared in constant time; a test that hard-codes a
// state guesses wrong every time NewState() changes its output).
func extractState(t *testing.T, stderr string) string {
	t.Helper()
	const marker = "state="
	i := strings.Index(stderr, marker)
	if i < 0 {
		t.Fatalf("stderr carries no %q; the authorize URL was never printed:\n%s", marker, stderr)
	}
	rest := stderr[i+len(marker):]
	end := strings.IndexAny(rest, "&\n \t")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end]
}

// pasteRedirect builds the redirect URL a person would paste back,
// carrying this sign-in attempt's own state (read from stderr) and a
// fixed authorization code.
func pasteRedirect(t *testing.T, stderr *bytes.Buffer) string {
	t.Helper()
	state := extractState(t, stderr.String())
	return "https://localhost/?state=" + state + "&code=the-code"
}

// seedMicrosoftClientID writes the `oauth.microsoft` store key
// directly, standing in for a prior "oauth set microsoft --client-id"
// run, so a test that only exercises accountAdd's outlook branch does
// not have to run two commands to get there.
func seedMicrosoftClientID(t *testing.T, dir, clientID string) {
	t.Helper()
	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	value, err := json.Marshal(map[string]any{"client_id": clientID})
	if err != nil {
		t.Fatalf("encode the client id: %v", err)
	}
	if err := store.Set(microsoftClientKey, string(value)); err != nil {
		t.Fatalf("seed the Microsoft client id: %v", err)
	}
}

// fakeLoopback is a loopback double for TestCLI_LoopbackWarnsWhenNotDualBound.
// It opens no real socket: Start reports a fixed port, DualBound
// reports whatever the test needs, and Wait fails at once so the test
// never waits for a browser that will never call back.
type fakeLoopback struct {
	dualBound bool
}

func (f *fakeLoopback) Start() (int, error) { return 54321, nil }
func (f *fakeLoopback) DualBound() bool     { return f.dualBound }
func (f *fakeLoopback) Wait(context.Context) (string, error) {
	return "", errors.New("fakeLoopback: no browser will ever call back")
}
func (f *fakeLoopback) Close() {}

// TestCLI_LoopbackWarnsWhenNotDualBound proves L4 of S6-close-judge:
// when Start() could not bind [::1], the CLI prints one warning line
// naming the ::1 bind failure and suggesting --paste, then still lets
// the sign-in continue on 127.0.0.1 (it does not fail the command by
// itself). It drives this through newLoopback and openBrowser, the
// seams oauth.go carries for exactly this test, so no real socket or
// browser process is involved.
//
// arch: S6-close-judge L1/L4, §3.5, §3.6, B3, B11
func TestCLI_LoopbackWarnsWhenNotDualBound(t *testing.T) {
	dir := sandbox(t)
	seedMicrosoftClientID(t, dir, "public-client-1")

	origLoopback, origBrowser := newLoopback, openBrowser
	t.Cleanup(func() { newLoopback = origLoopback; openBrowser = origBrowser })

	newLoopback = func(_ string, _ time.Duration) loopback {
		return &fakeLoopback{dualBound: false}
	}
	browserURL := ""
	openBrowser = func(rawURL string) error { browserURL = rawURL; return nil }

	var out, errOut bytes.Buffer
	code := Run([]string{
		"account", "add", "work",
		"--provider", "outlook",
		"--email", "ann@contoso.com",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		Login: func(context.Context, string) (string, error) {
			t.Error("login ran although the fake loopback never received a callback")
			return "", nil
		},
	})

	// The fake loopback's Wait always fails, so the sign-in itself
	// fails; that is not what this test is proving.
	if code != exitFail {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
	}
	if browserURL == "" {
		t.Error("the sign-in never tried to open a browser; the loopback path was not exercised")
	}
	stderr := errOut.String()
	if !strings.Contains(stderr, "::1") {
		t.Errorf("stderr does not name the ::1 bind failure:\n%s", stderr)
	}
	if !strings.Contains(stderr, "--paste") {
		t.Errorf("stderr does not suggest --paste:\n%s", stderr)
	}
}

// TestCLI_OAuthSetMicrosoftClientID proves "oauth set microsoft
// --client-id ID" is reachable from Run (main.go's "oauth" case
// dispatches here) and writes the store key of §3.4's table. It also
// checks the two usage errors: no --client-id, and an unknown
// provider.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_OAuthSetMicrosoftClientID(t *testing.T) {
	dir := sandbox(t)
	var out, errOut bytes.Buffer

	code := Run([]string{"oauth", "set", "microsoft", "--client-id", "abc-123"}, Env{Stdout: &out, Stderr: &errOut})
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}

	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	raw, err := store.Get(microsoftClientKey)
	if err != nil {
		t.Fatalf("read %q: %v", microsoftClientKey, err)
	}
	var v struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("decode the stored client id: %v", err)
	}
	if v.ClientID != "abc-123" {
		t.Errorf("stored client id = %q, want %q", v.ClientID, "abc-123")
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"oauth", "set", "microsoft"}, Env{Stdout: &out, Stderr: &errOut}); code != exitUsage {
		t.Errorf("no --client-id: exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"oauth", "set", "pigeon", "--client-id", "x"}, Env{Stdout: &out, Stderr: &errOut}); code != exitUsage {
		t.Errorf("unknown provider: exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
	}
}

// googleUsageLine is the "oauth set google" line of the DS78.6 usage
// block. Each usage error prints the block (§3.5).
const googleUsageLine = "mailbag-mcp oauth set google --file client_secret.json"

// writeGoogleClientFile writes a client_secret.json of the shape that
// the Google Cloud console gives for a Desktop client, and returns its
// path. The values are made up (IS7.1).
func writeGoogleClientFile(t *testing.T, clientID, clientSecret string) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"installed": map[string]any{ //nolint:gosec // G101: a fake test value, not a real credential
			"client_id":     clientID,
			"project_id":    "test-project",
			"auth_uri":      "https://accounts.google.com/o/oauth2/auth",
			"token_uri":     "https://oauth2.googleapis.com/token",
			"client_secret": clientSecret,
			"redirect_uris": []string{"http://localhost"},
		},
	})
	if err != nil {
		t.Fatalf("encode the client file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "client_secret.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write the client file: %v", err)
	}
	return path
}

// TestCLI_OAuthSetGoogleFile proves that "oauth set google --file"
// reads client_secret.json, stores the client id and the client secret
// at the `oauth.google` key of §3.4, and prints the one fixed line. It
// also proves the failures: no --file and an extra argument are usage
// errors (exit 2) that print the DS78.6 usage line of the command; a
// file that is not there or that has the wrong shape exits 1 and
// writes neither the store key nor accounts.toml.
//
// arch: DS7.8, DS78.6, DS7.2, IS7.5
func TestCLI_OAuthSetGoogleFile(t *testing.T) {
	dir := sandbox(t)
	const clientID = "test-client.apps.googleusercontent.com"
	const clientSecret = "cli-file-test-secret" //nolint:gosec // G101: a fake test value, not a real credential
	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	accountsPath := filepath.Join(dir, "accounts.toml")

	usage := map[string][]string{
		"no --file":      {"oauth", "set", "google"},
		"extra argument": {"oauth", "set", "google", "--file", "x.json", "more"},
	}
	for name, args := range usage {
		var out, errOut bytes.Buffer
		if code := Run(args, Env{Stdout: &out, Stderr: &errOut}); code != exitUsage {
			t.Errorf("%s: exit code = %d, want %d\nstderr: %s", name, code, exitUsage, errOut.String())
		}
		if !strings.HasPrefix(errOut.String(), "usage:") {
			t.Errorf("%s: stderr does not start with \"usage:\":\n%s", name, errOut.String())
		}
		if !strings.Contains(errOut.String(), googleUsageLine) {
			t.Errorf("%s: the usage block does not hold the DS78.6 line %q:\n%s", name, googleUsageLine, errOut.String())
		}
	}

	badShape := filepath.Join(t.TempDir(), "service_account.json")
	if err := os.WriteFile(badShape, []byte(`{"type":"service_account","client_id":"x"}`), 0o600); err != nil {
		t.Fatalf("write the wrong-shape file: %v", err)
	}
	failures := map[string]string{
		"no such file": filepath.Join(t.TempDir(), "absent.json"),
		"wrong shape":  badShape,
	}
	for name, file := range failures {
		var out, errOut bytes.Buffer
		if code := Run([]string{"oauth", "set", "google", "--file", file}, Env{Stdout: &out, Stderr: &errOut}); code != exitFail {
			t.Errorf("%s: exit code = %d, want %d\nstderr: %s", name, code, exitFail, errOut.String())
		}
		if out.Len() != 0 {
			t.Errorf("%s: stdout = %q, want nothing", name, out.String())
		}
		if _, err := store.Get(googleClientKey); !errors.Is(err, secrets.ErrNotFound) {
			t.Errorf("%s: the store holds %q after a failure (err = %v)", name, googleClientKey, err)
		}
		if _, err := os.Stat(accountsPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: accounts.toml was written although the client file was bad (stat err = %v)", name, err)
		}
	}

	var out, errOut bytes.Buffer
	file := writeGoogleClientFile(t, clientID, clientSecret)
	if code := Run([]string{"oauth", "set", "google", "--file", file}, Env{Stdout: &out, Stderr: &errOut}); code != exitOK {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if got, want := out.String(), "stored the google OAuth client\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if errOut.Len() != 0 {
		t.Errorf("stderr = %q, want nothing", errOut.String())
	}

	// The literal key name, not googleClientKey: the server side reads
	// the key by this name (DS7.2), so a changed constant must fail here.
	raw, err := store.Get("oauth.google")
	if err != nil {
		t.Fatalf("read %q: %v", "oauth.google", err)
	}
	var got oauthpkg.GoogleClient
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("decode the stored Google client: %v", err)
	}
	if want := (oauthpkg.GoogleClient{ClientID: clientID, ClientSecret: clientSecret}); got != want {
		t.Errorf("stored Google client = %+v, want %+v", got, want)
	}
}

// TestCLI_OAuthSetGoogleNeverPrintsID proves IS7.5 for "oauth set
// google": no terminal line holds the client id, the client secret or
// the project number (the part of the client id before the first "-"),
// on success, on a bad file, and on a usage error after a good --file;
// that usage error prints the DS78.6 usage line and none of the three
// values. It also proves that the command gives the three values to
// guard.RegisterSecret, so that guard.Redact removes them from each
// later error and log line of the process.
//
// arch: DS7.8, DS78.6, DS7.2, IS7.5
func TestCLI_OAuthSetGoogleNeverPrintsID(t *testing.T) {
	sandbox(t)
	// The project numbers are made up (IS7.1). Each is a value of its
	// own, because the test looks for it apart from the client id.
	const (
		project      = "271828182845"
		clientID     = project + "-test-client.apps.googleusercontent.com"
		clientSecret = "cli-never-print-secret" //nolint:gosec // G101: a fake test value, not a real credential

		badProject = "161803398874"
		badID      = badProject + "-test-client.apps.googleusercontent.com"
		badSecret  = "cli-bad-file-secret" //nolint:gosec // G101: a fake test value, not a real credential
	)

	// A file cut off after the secret: the parse fails, so nothing is
	// registered, and only the CLI itself keeps these values off the
	// terminal.
	badFile := filepath.Join(t.TempDir(), "client_secret.json")
	cut := `{"installed":{"client_id":"` + badID + `","client_secret":"` + badSecret
	if err := os.WriteFile(badFile, []byte(cut), 0o600); err != nil {
		t.Fatalf("write the cut-off file: %v", err)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"oauth", "set", "google", "--file", badFile}, Env{Stdout: &out, Stderr: &errOut}); code != exitFail {
		t.Errorf("cut-off file: exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
	}
	text := out.String() + errOut.String()
	for _, leak := range []string{badProject, badSecret, "googleusercontent"} {
		if strings.Contains(text, leak) {
			t.Errorf("cut-off file: the output holds %q:\n%s", leak, text)
		}
	}

	out.Reset()
	errOut.Reset()
	file := writeGoogleClientFile(t, clientID, clientSecret)
	if code := Run([]string{"oauth", "set", "google", "--file", file}, Env{Stdout: &out, Stderr: &errOut}); code != exitOK {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}
	text = out.String() + errOut.String()
	for _, leak := range []string{project, clientSecret, "googleusercontent"} {
		if strings.Contains(text, leak) {
			t.Errorf("the output holds %q:\n%s", leak, text)
		}
	}

	// A usage error after a good --file: the usage block shows the
	// DS78.6 line of the command, and the file content stays off the
	// terminal.
	out.Reset()
	errOut.Reset()
	if code := Run([]string{"oauth", "set", "google", "--file", file, "more"}, Env{Stdout: &out, Stderr: &errOut}); code != exitUsage {
		t.Errorf("extra argument: exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
	}
	if !strings.Contains(errOut.String(), googleUsageLine) {
		t.Errorf("extra argument: the usage block does not hold the DS78.6 line %q:\n%s", googleUsageLine, errOut.String())
	}
	text = out.String() + errOut.String()
	for _, leak := range []string{project, clientSecret, "googleusercontent"} {
		if strings.Contains(text, leak) {
			t.Errorf("extra argument: the output holds %q:\n%s", leak, text)
		}
	}

	for name, value := range map[string]string{
		"client id":      clientID,
		"client secret":  clientSecret,
		"project number": project,
	} {
		line := "server said: " + value + " is not allowed"
		if got := guard.Redact(line); strings.Contains(got, value) {
			t.Errorf("the %s is not registered with the redactor: Redact(%q) = %q", name, line, got)
		}
	}
}
