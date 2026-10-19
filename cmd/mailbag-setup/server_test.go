// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the setup server: the Host check, the token, the security
// headers, the CLI jobs, the version match and the idle stop. A fake
// CLI is the test binary itself: TestMain runs it as the fake when
// MAILBAG_SETUP_FAKE_CLI is 1, and the fake records each call.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Environment names of the fake CLI. None of them holds a secret.
const (
	envFake        = "MAILBAG_SETUP_FAKE_CLI"
	envFakeLog     = "MAILBAG_SETUP_FAKE_LOG"
	envFakeVersion = "MAILBAG_SETUP_FAKE_VERSION"
	envFakeBlock   = "MAILBAG_SETUP_FAKE_BLOCK"
	envFakeNoTerm  = "MAILBAG_SETUP_FAKE_IGNORE_TERM"
)

// fakeCall is one call of the fake CLI, as it records it.
type fakeCall struct {
	Args     []string `json:"args"`
	Env      []string `json:"env"`
	Stdin    string   `json:"stdin"`
	File     string   `json:"file,omitempty"`
	FileMode string   `json:"file_mode,omitempty"`
	DirMode  string   `json:"dir_mode,omitempty"`
}

func TestMain(m *testing.M) {
	if os.Getenv(envFake) == "1" {
		os.Exit(fakeCLI(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeCLI acts as mailbag-mcp. It records the call, prints a version
// line for "version", waits for a signal for "doctor" when
// MAILBAG_SETUP_FAKE_BLOCK is 1, and else prints two lines.
func fakeCLI(args []string) int {
	if os.Getenv(envFakeNoTerm) == "1" {
		// Before the call is recorded, so a test that sees the call
		// knows that SIGTERM has no effect.
		signal.Ignore(syscall.SIGTERM)
	}
	stdin, _ := io.ReadAll(os.Stdin)
	call := fakeCall{Args: args, Env: os.Environ(), Stdin: string(stdin)}
	for _, a := range args {
		if f, ok := strings.CutPrefix(a, "--file="); ok {
			data, _ := os.ReadFile(f) //nolint:gosec // G304: the fake CLI reads the file that the server under test made
			call.File = string(data)
			if fi, err := os.Stat(f); err == nil { //nolint:gosec // G703: the path comes from the server under test
				call.FileMode = fi.Mode().Perm().String()
			}
			if di, err := os.Stat(filepath.Dir(f)); err == nil { //nolint:gosec // G703: the path comes from the server under test
				call.DirMode = di.Mode().Perm().String()
			}
		}
	}
	line, _ := json.Marshal(call)
	if f, err := os.OpenFile(os.Getenv(envFakeLog), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil { //nolint:gosec // G703: the log path is a test temp file
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}
	switch {
	case len(args) == 1 && args[0] == "version":
		_, _ = io.WriteString(os.Stdout, "mailbag-mcp "+os.Getenv(envFakeVersion)+"\n")
	case len(args) == 1 && args[0] == "doctor" && os.Getenv(envFakeBlock) == "1":
		time.Sleep(time.Minute) // SIGTERM ends the process before this
	default:
		_, _ = io.WriteString(os.Stdout, "line one\n")
		_, _ = io.WriteString(os.Stderr, "line two")
	}
	return 0
}

// fakeRunner stands in for claude and pgrep. It records each call and
// answers with answer, or fails when answer is nil. No test runs the
// real claude.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []string
	answer func(call string) ([]byte, error)
}

// run is the cmdRunner of the fake.
func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, call)
	if f.answer == nil {
		return nil, errors.New("executable file not found")
	}
	return f.answer(call)
}

// set replaces the answer function.
func (f *fakeRunner) set(answer func(call string) ([]byte, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

// reset forgets the recorded calls.
func (f *fakeRunner) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// recorded gives the calls so far.
func (f *fakeRunner) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

// harness is one running setup server with the fake CLI.
type harness struct {
	t    *testing.T
	s    *server
	base string
	log  string
	cfg  string
	home string
	run  *fakeRunner
}

// newHarness starts a server on 127.0.0.1 with the test binary as the
// CLI. cliVersion is the version that the fake CLI gives.
func newHarness(t *testing.T, setupVersion, cliVersion string, idle time.Duration) *harness {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.jsonl")
	t.Setenv(envFake, "1")
	t.Setenv(envFakeLog, logPath)
	t.Setenv(envFakeVersion, cliVersion)
	t.Setenv(envFakeBlock, "")
	t.Setenv(envFakeNoTerm, "")
	t.Setenv("MAILBAG_CONFIG_DIR", filepath.Join(dir, "config"))
	// A -race binary sleeps 1 s at exit by default; the fake CLI is a
	// -race binary when the test is.
	t.Setenv("GORACE", "atexit_sleep_ms=0")

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("Executable: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	home := filepath.Join(dir, "home")
	runner := &fakeRunner{}
	s, err := newServer(serverConfig{
		CLIPath: exe, SetupVersion: "mailbag-setup " + setupVersion, Idle: idle,
		Home: home, GOOS: "darwin", Run: runner.run,
	}, ln.Addr().String())
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		s.serve(ctx, ln)
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	return &harness{t: t, s: s, base: "http://" + s.host, log: logPath, cfg: filepath.Join(dir, "config"), home: home, run: runner}
}

// request is one test request. An empty host means the right host,
// and token nil means the right token.
type request struct {
	method, path, body string
	contentType        string
	host               string
	token              *string
	headers            map[string]string
}

// do sends the request and gives the status, the headers and the body.
func (h *harness) do(r request) (int, http.Header, []byte) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), r.method, h.base+r.path, strings.NewReader(r.body))
	if err != nil {
		h.t.Fatalf("NewRequest: %v", err)
	}
	if r.host != "" {
		req.Host = r.host
	}
	switch {
	case r.token == nil:
		req.Header.Set(tokenHeader, h.s.token)
	case *r.token != "":
		req.Header.Set(tokenHeader, *r.token)
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	} else if r.method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", r.method, r.path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("read the body: %v", err)
	}
	return resp.StatusCode, resp.Header, body
}

// calls gives the recorded calls of the fake CLI other than "version".
func (h *harness) calls() []fakeCall {
	h.t.Helper()
	f, err := os.Open(h.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatalf("open the call log: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []fakeCall
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var c fakeCall
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			h.t.Fatalf("decode a call: %v", err)
		}
		if len(c.Args) == 1 && c.Args[0] == "version" {
			continue
		}
		out = append(out, c)
	}
	return out
}

// startJob posts to path and gives the job id from a 202 answer.
func (h *harness) startJob(path, body string) string {
	h.t.Helper()
	code, _, resp := h.do(request{method: http.MethodPost, path: path, body: body})
	if code != http.StatusAccepted {
		h.t.Fatalf("POST %s: status %d, body %s", path, code, resp)
	}
	var v struct {
		Job string `json:"job"`
	}
	if err := json.Unmarshal(resp, &v); err != nil || v.Job == "" {
		h.t.Fatalf("POST %s: no job id in %s", path, resp)
	}
	return v.Job
}

// waitJob polls the job until it ends, with a deadline, and gives its
// last view.
func (h *harness) waitJob(id string) jobView {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		code, _, body := h.do(request{method: http.MethodGet, path: "/api/jobs/" + id})
		if code != http.StatusOK {
			h.t.Fatalf("GET job %s: status %d, body %s", id, code, body)
		}
		var v jobView
		if err := json.Unmarshal(body, &v); err != nil {
			h.t.Fatalf("decode job: %v", err)
		}
		if v.Done {
			return v
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("job %s did not end before the deadline", id)
	return jobView{}
}

// ptr gives a pointer to v.
func ptr[T any](v T) *T { return &v }

// TestSetup_HostMismatch403 checks that a request with another Host
// gets 403 and runs no CLI command (DNS rebinding).
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_HostMismatch403(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	_, port, _ := net.SplitHostPort(h.s.host)
	for _, host := range []string{"localhost:" + port, "evil.example:" + port, "127.0.0.1", "127.0.0.2:" + port, "evil.example"} {
		for _, r := range []request{
			{method: http.MethodGet, path: "/"},
			{method: http.MethodGet, path: "/api/state"},
			{method: http.MethodPost, path: "/api/doctor", body: "{}"},
			{method: http.MethodDelete, path: "/api/accounts/work"},
		} {
			r.host = host
			if code, _, body := h.do(r); code != http.StatusForbidden {
				t.Errorf("Host %q %s %s: status %d, want 403; body %s", host, r.method, r.path, code, body)
			}
		}
	}
	if c := h.calls(); len(c) != 0 {
		t.Errorf("the CLI ran %d times after refused requests: %v", len(c), c)
	}
}

// TestSetup_NoToken403 checks that an API request with no token gets
// 403 and runs no CLI command.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_NoToken403(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	none := ptr("")
	for _, r := range []request{
		{method: http.MethodGet, path: "/api/state", token: none},
		{method: http.MethodPost, path: "/api/doctor", body: "{}", token: none},
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"work","provider":"imap","email":"me@example.test","secret":"x"}`, token: none},
		{method: http.MethodDelete, path: "/api/accounts/work", token: none},
		{method: http.MethodPost, path: "/api/finish", body: "{}", token: none},
	} {
		if code, _, body := h.do(r); code != http.StatusForbidden {
			t.Errorf("%s %s with no token: status %d, want 403; body %s", r.method, r.path, code, body)
		}
	}
	if c := h.calls(); len(c) != 0 {
		t.Errorf("the CLI ran %d times after refused requests: %v", len(c), c)
	}
	select {
	case <-h.s.done:
		t.Error("a finish request with no token stopped the server")
	default:
	}
}

// TestSetup_WrongToken403 checks that an API request with a wrong
// token gets 403, also when the wrong token has the right length.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_WrongToken403(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	sameLen := strings.Repeat("0", len(h.s.token))
	if sameLen == h.s.token {
		sameLen = strings.Repeat("1", len(h.s.token))
	}
	for _, tok := range []string{sameLen, "abc", h.s.token + "0", strings.ToUpper(h.s.token)} {
		if tok == h.s.token {
			continue
		}
		for _, r := range []request{
			{method: http.MethodGet, path: "/api/state", token: ptr(tok)},
			{method: http.MethodPost, path: "/api/service", body: "{}", token: ptr(tok)},
		} {
			if code, _, body := h.do(r); code != http.StatusForbidden {
				t.Errorf("%s %s with a wrong token: status %d, want 403; body %s", r.method, r.path, code, body)
			}
		}
	}
	if c := h.calls(); len(c) != 0 {
		t.Errorf("the CLI ran %d times after refused requests: %v", len(c), c)
	}
	if code, _, body := h.do(request{method: http.MethodGet, path: "/api/state"}); code != http.StatusOK {
		t.Errorf("GET /api/state with the right token: status %d; body %s", code, body)
	}
}

// TestSetup_NoCORSHeaders checks that a preflight from another origin
// fails: the server sends no CORS header on it, and none on a request
// with an Origin header.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_NoCORSHeaders(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	preflight := map[string]string{
		"Origin":                         "http://evil.example",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "x-mailbag-setup,content-type",
	}
	for _, r := range []request{
		{method: http.MethodOptions, path: "/api/accounts", token: ptr(""), headers: preflight},
		{method: http.MethodOptions, path: "/api/state", token: ptr(""), headers: preflight},
		{method: http.MethodGet, path: "/api/state", headers: map[string]string{"Origin": "http://evil.example"}},
	} {
		code, hdr, _ := h.do(r)
		for k := range hdr {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s %s: CORS header %s: %q", r.method, r.path, k, hdr.Get(k))
			}
		}
		if r.method == http.MethodOptions && code >= 200 && code < 300 {
			t.Errorf("preflight %s: status %d, want a failure", r.path, code)
		}
	}
}

// TestSetup_PostNeedsJSON checks that a POST without the JSON content
// type gets 415 and runs no CLI command.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_PostNeedsJSON(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx", "none"} {
		r := request{method: http.MethodPost, path: "/api/doctor", body: "{}", contentType: ct}
		if ct == "none" {
			r.contentType = ""
			r.headers = map[string]string{"Content-Type": ""}
		}
		if code, _, body := h.do(r); code != http.StatusUnsupportedMediaType {
			t.Errorf("POST with Content-Type %q: status %d, want 415; body %s", ct, code, body)
		}
	}
	if c := h.calls(); len(c) != 0 {
		t.Fatalf("the CLI ran %d times after refused requests: %v", len(c), c)
	}
	id := h.startJob("/api/doctor", "{}")
	if v := h.waitJob(id); v.Exit == nil || *v.Exit != 0 {
		t.Errorf("doctor job: %+v, want exit 0", v)
	}
	code, _, body := h.do(request{method: http.MethodPost, path: "/api/finish", body: "{}", contentType: "application/json; charset=utf-8"})
	if code != http.StatusOK {
		t.Errorf("POST with a charset parameter: status %d; body %s", code, body)
	}
}

// TestSetup_SecurityHeadersOnEveryResponse checks the headers of
// DS13.6 rule 6 on each kind of answer, refusals too.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_SecurityHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
			"connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for _, r := range []request{
		{method: http.MethodGet, path: "/"},
		{method: http.MethodGet, path: "/api/state"},
		{method: http.MethodGet, path: "/api/state", host: "evil.example"},
		{method: http.MethodGet, path: "/api/state", token: ptr("")},
		{method: http.MethodPost, path: "/api/doctor", contentType: "text/plain"},
		{method: http.MethodGet, path: "/nothing"},
		{method: http.MethodGet, path: "/api/jobs/99"},
		{method: http.MethodGet, path: "/api/../api/state"},
		{method: http.MethodPut, path: "/api/state"},
	} {
		_, hdr, _ := h.do(r)
		for k, v := range want {
			if got := hdr.Get(k); got != v {
				t.Errorf("%s %s (host %q): %s = %q, want %q", r.method, r.path, r.host, k, got, v)
			}
		}
	}
	_, hdr, body := h.do(request{method: http.MethodGet, path: "/"})
	if strings.Contains(string(body), "<script>") || strings.Contains(string(body), "<script type") ||
		strings.Count(string(body), "<script") != strings.Count(string(body), "<script src=\"/app.js\"></script>") {
		t.Errorf("the page holds an inline script: %s", body)
	}
	if !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
		t.Errorf("page Content-Type = %q", hdr.Get("Content-Type"))
	}
}

// TestSetup_SecretNotInArgvOrEnv checks that the secret of an account
// goes to the CLI on stdin in the --answers-stdin document, and not in
// argv, the environment or the job output.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_SecretNotInArgvOrEnv(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	const secret = "S3cret-Value-417"
	id := h.startJob("/api/accounts", `{"alias":"work","provider":"imap","email":"me@example.test",`+
		`"imap":"imap.example.test:993","smtp":"smtp.example.test:465","access":"read",`+
		`"secret":"`+secret+`","use_file_store":false}`)
	v := h.waitJob(id)
	if v.Exit == nil || *v.Exit != 0 {
		t.Fatalf("account add job: %+v, want exit 0", v)
	}
	if !slices.Equal(v.Lines, []string{"line one", "line two"}) && !slices.Equal(v.Lines, []string{"line two", "line one"}) {
		t.Errorf("job lines = %q", v.Lines)
	}
	calls := h.calls()
	if len(calls) != 1 {
		t.Fatalf("CLI calls = %d, want 1: %v", len(calls), calls)
	}
	c := calls[0]
	wantArgs := []string{"account", "add", "work", "--provider=imap", "--answers-stdin",
		"--email=me@example.test", "--access=read", "--imap=imap.example.test:993", "--smtp=smtp.example.test:465"}
	if !slices.Equal(c.Args, wantArgs) {
		t.Errorf("argv = %q, want %q", c.Args, wantArgs)
	}
	for _, a := range c.Args {
		if strings.Contains(a, secret) {
			t.Errorf("the secret is in argv: %q", a)
		}
	}
	for _, e := range c.Env {
		if strings.Contains(e, secret) {
			t.Errorf("the secret is in the environment: %q", e)
		}
	}
	for _, l := range v.Lines {
		if strings.Contains(l, secret) {
			t.Errorf("the secret is in the job output: %q", l)
		}
	}
	if want := `{"secret":"` + secret + `","use_file_store":false}`; c.Stdin != want {
		t.Errorf("stdin = %q, want %q", c.Stdin, want)
	}

	// A sign-in account sends a document with no secret.
	id = h.startJob("/api/accounts", `{"alias":"g","provider":"gmail","email":"me@example.test"}`)
	h.waitJob(id)
	calls = h.calls()
	if got := calls[len(calls)-1].Stdin; got != "{}" {
		t.Errorf("gmail stdin = %q, want {}", got)
	}
}

// TestSetup_GoogleClientFileRemoved checks that the uploaded Google
// client file goes to a 0600 file in a 0700 directory, never into
// argv, and that no file stays after the request.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_GoogleClientFileRemoved(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	const clientSecret = "test-client-secret-value"
	body := `{"installed":{"client_id":"1-abc.test-client.apps.googleusercontent.com","client_secret":"` + clientSecret + `"}}`
	code, _, resp := h.do(request{method: http.MethodPost, path: "/api/oauth/google", body: body})
	if code != http.StatusOK {
		t.Fatalf("POST /api/oauth/google: status %d, body %s", code, resp)
	}
	var v jobView
	if err := json.Unmarshal(resp, &v); err != nil || !v.Done || v.Exit == nil || *v.Exit != 0 {
		t.Fatalf("answer %s: %v", resp, err)
	}
	calls := h.calls()
	if len(calls) != 1 {
		t.Fatalf("CLI calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if len(c.Args) != 4 || !slices.Equal(c.Args[:3], []string{"oauth", "set", "google"}) || !strings.HasPrefix(c.Args[3], "--file="+tmp) {
		t.Errorf("argv = %q", c.Args)
	}
	if c.File != body {
		t.Errorf("the CLI read %q, want the uploaded file", c.File)
	}
	if c.FileMode != "-rw-------" || c.DirMode != "-rwx------" {
		t.Errorf("file mode %s, dir mode %s; want 0600 and 0700", c.FileMode, c.DirMode)
	}
	for _, a := range c.Args {
		if strings.Contains(a, clientSecret) {
			t.Errorf("the client secret is in argv: %q", a)
		}
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("files stay in TMPDIR after the request: %v", entries)
	}

	// A web client file is refused before the CLI runs.
	code, _, resp = h.do(request{method: http.MethodPost, path: "/api/oauth/google", body: `{"web":{}}`})
	if code != http.StatusBadRequest || !strings.Contains(string(resp), "Desktop app") {
		t.Errorf("web client: status %d, body %s", code, resp)
	}
	if n := len(h.calls()); n != 1 {
		t.Errorf("CLI calls = %d after a refused file, want 1", n)
	}
}

// TestSetup_BadInputRefused checks that the server refuses fields
// that it cannot check before it builds an argv, and runs no CLI
// command for them.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_BadInputRefused(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	for _, r := range []request{
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"-x","provider":"imap","email":"a@example.test"}`},
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"a b","provider":"imap","email":"a@example.test"}`},
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"a","provider":"smtp","email":"a@example.test"}`},
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"a","provider":"imap","email":""}`},
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"a","provider":"imap","email":"a@example.test\n--x"}`},
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"a","provider":"imap","email":"a@example.test","extra":1}`},
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"a","provider":"imap","email":"a@example.test"}{}`},
		{method: http.MethodPost, path: "/api/oauth/microsoft", body: `{"client_id":"not-a-guid"}`},
		{method: http.MethodPost, path: "/api/oauth/google", body: `not json`},
		{method: http.MethodPost, path: "/api/accounts/-x/test", body: `{}`},
		{method: http.MethodDelete, path: "/api/accounts/a.b"},
		{method: http.MethodGet, path: "/api/jobs/1?after=-1"},
	} {
		code, _, body := h.do(r)
		if code != http.StatusBadRequest && code != http.StatusNotFound {
			t.Errorf("%s %s %s: status %d, want 400; body %s", r.method, r.path, r.body, code, body)
		}
	}
	if c := h.calls(); len(c) != 0 {
		t.Errorf("the CLI ran %d times after refused requests: %v", len(c), c)
	}

	code, _, body := h.do(request{method: http.MethodPost, path: "/api/oauth/microsoft", body: `{"client_id":"00000000-1111-2222-3333-444444444444"}`})
	if code != http.StatusOK {
		t.Fatalf("microsoft: status %d, body %s", code, body)
	}
	c := h.calls()
	if len(c) != 1 || !slices.Equal(c[0].Args, []string{"oauth", "set", "microsoft", "--client-id=00000000-1111-2222-3333-444444444444"}) {
		t.Errorf("calls = %v", c)
	}
}

// TestSetup_OneJobAtATime checks that a second CLI job is refused
// with 409 while one runs, that cancel ends the running job, and that
// a new job can start after it.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_OneJobAtATime(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	t.Setenv(envFakeBlock, "1")
	id := h.startJob("/api/doctor", "{}")

	for _, r := range []request{
		{method: http.MethodPost, path: "/api/service", body: "{}"},
		{method: http.MethodPost, path: "/api/doctor", body: "{}"},
		{method: http.MethodPost, path: "/api/accounts/work/test", body: "{}"},
		{method: http.MethodPost, path: "/api/oauth/microsoft", body: `{"client_id":"00000000-1111-2222-3333-444444444444"}`},
		{method: http.MethodDelete, path: "/api/accounts/work"},
	} {
		if code, _, body := h.do(r); code != http.StatusConflict {
			t.Errorf("%s %s while a job runs: status %d, want 409; body %s", r.method, r.path, code, body)
		}
	}

	// Cancel only after the fake CLI runs, so the test sees its call.
	deadline := time.Now().Add(20 * time.Second)
	for len(h.calls()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the doctor job did not start before the deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
	code, _, body := h.do(request{method: http.MethodPost, path: "/api/jobs/" + id + "/cancel", body: "{}"})
	if code != http.StatusOK {
		t.Fatalf("cancel: status %d, body %s", code, body)
	}
	if v := h.waitJob(id); v.Exit == nil || *v.Exit == 0 {
		t.Errorf("cancelled job: %+v, want a non-zero exit", v)
	}

	t.Setenv(envFakeBlock, "")
	id2 := h.startJob("/api/service", "{}")
	if v := h.waitJob(id2); v.Exit == nil || *v.Exit != 0 {
		t.Errorf("job after cancel: %+v, want exit 0", v)
	}
	var argv [][]string
	for _, c := range h.calls() {
		argv = append(argv, c.Args)
	}
	want := [][]string{{"doctor"}, {"service", "install"}}
	if !slices.EqualFunc(argv, want, slices.Equal[[]string]) {
		t.Errorf("CLI calls = %q, want %q", argv, want)
	}
}

// TestSetup_JobOutputAfter checks the line paging of GET
// /api/jobs/<id>?after=n.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_JobOutputAfter(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	id := h.startJob("/api/accounts/work/test", "{}")
	all := h.waitJob(id)
	if all.Next != 2 || len(all.Lines) != 2 {
		t.Fatalf("job view %+v, want 2 lines", all)
	}
	for after, want := range map[string]int{"1": 1, "2": 0, "50": 0} {
		code, _, body := h.do(request{method: http.MethodGet, path: "/api/jobs/" + id + "?after=" + after})
		var v jobView
		if code != http.StatusOK || json.Unmarshal(body, &v) != nil {
			t.Fatalf("after=%s: status %d, body %s", after, code, body)
		}
		if len(v.Lines) != want || v.Next != 2 {
			t.Errorf("after=%s: %d lines, next %d; want %d lines, next 2", after, len(v.Lines), v.Next, want)
		}
	}
}

// TestSetup_IdleExit checks that the server stops after the idle time
// with no API request, and that an API request starts the time again.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_IdleExit(t *testing.T) {
	const idle = 400 * time.Millisecond
	h := newHarness(t, "v1.0.0", "v1.0.0", idle)
	start := time.Now()
	// Requests at a shorter interval than idle keep the server alive.
	var last time.Time
	for range 4 {
		time.Sleep(idle / 4)
		last = time.Now() // the server starts the idle time after this
		if code, _, _ := h.do(request{method: http.MethodGet, path: "/api/state"}); code != http.StatusOK {
			t.Fatalf("GET /api/state: status %d", code)
		}
	}
	select {
	case <-h.s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not stop after the idle time")
	}
	if since := time.Since(last); since < idle {
		t.Errorf("the server stopped %v after the last request, before the idle time %v", since, idle)
	}
	if time.Since(start) < idle+idle/2 {
		t.Errorf("the requests did not start the idle time again")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.base+"/", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			break
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("the listener still answers after the stop")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSetup_FinishStops checks that POST /api/finish answers and then
// stops the server.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_FinishStops(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	if code, _, body := h.do(request{method: http.MethodPost, path: "/api/finish", body: "{}"}); code != http.StatusOK {
		t.Fatalf("finish: status %d, body %s", code, body)
	}
	select {
	case <-h.s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not stop after finish")
	}
}

// TestSetup_VersionMismatchNoWrites checks that the state shows both
// versions when they differ, and that each write action is refused
// with no CLI call.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_VersionMismatchNoWrites(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v9.9.9", time.Minute)
	code, _, body := h.do(request{method: http.MethodGet, path: "/api/state"})
	if code != http.StatusOK {
		t.Fatalf("state: status %d", code)
	}
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if st["versions_match"] != false || st["setup_version"] != "mailbag-setup v1.0.0" || st["cli_version"] != "mailbag-mcp v9.9.9" {
		t.Errorf("state = %s", body)
	}
	for _, r := range []request{
		{method: http.MethodPost, path: "/api/accounts", body: `{"alias":"work","provider":"imap","email":"me@example.test","secret":"x"}`},
		{method: http.MethodPost, path: "/api/oauth/google", body: `{"installed":{}}`},
		{method: http.MethodPost, path: "/api/oauth/microsoft", body: `{"client_id":"00000000-1111-2222-3333-444444444444"}`},
		{method: http.MethodDelete, path: "/api/accounts/work"},
		{method: http.MethodPost, path: "/api/service", body: "{}"},
	} {
		code, _, resp := h.do(r)
		if code != http.StatusConflict || !strings.Contains(string(resp), "v9.9.9") || !strings.Contains(string(resp), "v1.0.0") {
			t.Errorf("%s %s: status %d, body %s; want 409 with both versions", r.method, r.path, code, resp)
		}
	}
	if c := h.calls(); len(c) != 0 {
		t.Errorf("the CLI ran %d times with a version mismatch: %v", len(c), c)
	}
}

// TestSetup_StateListsAccounts checks that GET /api/state reads the
// accounts from accounts.toml, and gives an empty list with no file.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_StateListsAccounts(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	var st struct {
		Accounts []stateAccount `json:"accounts"`
		Match    bool           `json:"versions_match"`
		CLIPath  string         `json:"cli_path"`
		Error    string         `json:"config_error"`
		Secrets  string         `json:"secrets"`
	}
	_, _, body := h.do(request{method: http.MethodGet, path: "/api/state"})
	if err := json.Unmarshal(body, &st); err != nil || len(st.Accounts) != 0 || !st.Match || st.CLIPath != h.s.cliPath || st.Error != "" {
		t.Fatalf("state with no file = %s (%v)", body, err)
	}

	dir := h.cfg
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	toml := "secrets = \"file\"\n\n[accounts.work]\nprovider = \"imap\"\nemail    = \"me@example.test\"\nimap     = \"imap.example.test:993\"\nsmtp     = \"smtp.example.test:465\"\naccess   = \"read\"\n"
	if err := os.WriteFile(filepath.Join(dir, "accounts.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, body = h.do(request{method: http.MethodGet, path: "/api/state"})
	st.Accounts = nil
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	want := []stateAccount{{Alias: "work", Provider: "imap", Email: "me@example.test", Access: "read"}}
	if !slices.Equal(st.Accounts, want) || st.Secrets != "file" {
		t.Errorf("state = %s, want account %+v and secrets file", body, want)
	}
}

// TestSetup_FindCLI checks the lookup of DS13.7: the binary next to
// mailbag-setup first, then PATH, and the path before symlinks are
// resolved.
//
// arch: DS13.1, DS13.2, DS13.6, DS13.7, DS13.9, DS13.10, IS13.1, IS13.2, IS13.3, IS13.5
func TestSetup_FindCLI(t *testing.T) {
	side := t.TempDir()
	onPath := t.TempDir()
	write := func(p string) {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // G306: the test file must be executable
			t.Fatal(err)
		}
	}
	write(filepath.Join(side, setupName))
	write(filepath.Join(onPath, cliName))

	got, err := findCLI(filepath.Join(side, setupName), onPath)
	if err != nil || got != filepath.Join(onPath, cliName) {
		t.Errorf("no side binary: got %q, %v; want the PATH binary", got, err)
	}

	write(filepath.Join(side, cliName))
	got, err = findCLI(filepath.Join(side, setupName), onPath)
	if err != nil || got != filepath.Join(side, cliName) {
		t.Errorf("side binary: got %q, %v; want %q", got, err, filepath.Join(side, cliName))
	}

	// Started by name from PATH: the side binary in that PATH directory.
	got, err = findCLI(setupName, side+string(os.PathListSeparator)+onPath)
	if err != nil || got != filepath.Join(side, cliName) {
		t.Errorf("by name: got %q, %v", got, err)
	}

	// A symlink to mailbag-setup: the directory of the link counts.
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(side, setupName), filepath.Join(link, setupName)); err != nil {
		t.Skipf("symlink: %v", err)
	}
	got, err = findCLI(filepath.Join(link, setupName), onPath)
	if err != nil || got != filepath.Join(onPath, cliName) {
		t.Errorf("symlink: got %q, %v; want the PATH binary, not the link target's directory", got, err)
	}

	if _, err := findCLI(filepath.Join(link, setupName), "relative/dir"); err == nil {
		t.Error("no binary anywhere: no error")
	}
}

// TestSetup_PageFilesServedWithHeaders checks that "/", /app.js,
// /style.css and /presets.json come from the embedded web files with
// the DS13.6 headers and no token.
//
// arch: DS13.4, DS13.6, DS13.8
func TestSetup_PageFilesServedWithHeaders(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	for path, typ := range map[string]string{
		"/": "text/html", "/app.js": "text/javascript",
		"/style.css": "text/css", "/presets.json": "application/json",
	} {
		code, hdr, body := h.do(request{method: http.MethodGet, path: path})
		if code != http.StatusOK || len(body) == 0 {
			t.Errorf("GET %s = %d, %d bytes", path, code, len(body))
		}
		if !strings.HasPrefix(hdr.Get("Content-Type"), typ) {
			t.Errorf("GET %s Content-Type = %q", path, hdr.Get("Content-Type"))
		}
		if hdr.Get("X-Content-Type-Options") != "nosniff" || hdr.Get("Content-Security-Policy") == "" ||
			hdr.Get("Cache-Control") != "no-store" || hdr.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("GET %s lacks the DS13.6 headers: %v", path, hdr)
		}
	}
}

// desktopConfig makes the Claude Desktop directory in the temp home of
// h and, when content is not "", the config file. It gives the path.
func (h *harness) desktopConfig(content string) string {
	h.t.Helper()
	p := desktopConfigPath(h.home, "darwin")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		h.t.Fatal(err)
	}
	// The tool writes the backup next to the resolved file, and on macOS
	// the temp dir is under the /var symlink, so compare resolved paths.
	if dir, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		p = filepath.Join(dir, filepath.Base(p))
	}
	if content != "" {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
	return p
}

// claudeAnswers gives a fake runner answer: claude is present, "claude
// mcp get mailbag" shows getOut (an error when getOut is ""), pgrep
// finds the app when appRuns is true, and each other call works.
func claudeAnswers(getOut string, appRuns bool) func(string) ([]byte, error) {
	return func(call string) ([]byte, error) {
		switch {
		case call == "claude mcp get mailbag" && getOut == "":
			return []byte("No MCP server found"), errors.New("exit status 1")
		case call == "claude mcp get mailbag":
			return []byte(getOut), nil
		case strings.HasPrefix(call, "pgrep ") && !appRuns:
			return nil, errors.New("exit status 1")
		}
		return []byte("ok"), nil
	}
}

// getClients gives the answer of GET /api/clients by name.
func (h *harness) getClients() map[string]clientView {
	h.t.Helper()
	code, _, body := h.do(request{method: http.MethodGet, path: "/api/clients"})
	if code != http.StatusOK {
		h.t.Fatalf("GET /api/clients: status %d, body %s", code, body)
	}
	var list []clientView
	if err := json.Unmarshal(body, &list); err != nil {
		h.t.Fatalf("decode clients: %v; body %s", err, body)
	}
	out := map[string]clientView{}
	for _, c := range list {
		out[c.Name] = c
	}
	if len(out) != 2 {
		h.t.Fatalf("clients = %s, want claude-desktop and claude-code", body)
	}
	return out
}

// TestSetup_ClientsState checks GET /api/clients: both clients with
// their current entry and the planned change, and no write and no add.
//
// arch: DS13.3, DS13.8, DS13.10, IS13.4, IS13.5
func TestSetup_ClientsState(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)

	// No Claude Desktop directory and no claude: neither is present.
	cs := h.getClients()
	if cs[clientDesktop].Present || cs[clientCode].Present {
		t.Fatalf("clients with nothing installed = %+v", cs)
	}

	orig := `{"mcpServers":{"mailbag":{"command":"/old/mailbag-mcp"},"other":{"command":"x"}}}`
	p := h.desktopConfig(orig)
	h.run.set(claudeAnswers("mailbag:\n  Command: /old/mailbag-mcp\n", true))
	cs = h.getClients()
	d, c := cs[clientDesktop], cs[clientCode]
	if !d.Present || d.Path != p || d.Before != orig || !strings.Contains(d.After, h.s.cliPath) ||
		!strings.Contains(d.Current, "/old/mailbag-mcp") || d.Same || !d.Running || d.Error != "" {
		t.Errorf("desktop = %+v", d)
	}
	if !c.Present || !strings.Contains(c.Current, "/old/mailbag-mcp") || c.Same ||
		c.After != "claude mcp add --scope user mailbag -- "+h.s.cliPath {
		t.Errorf("claude code = %+v", c)
	}
	if got, _ := os.ReadFile(p); string(got) != orig { //nolint:gosec // G304: a test temp file
		t.Errorf("GET changed the config: %s", got)
	}
	for _, call := range h.run.recorded() {
		if strings.Contains(call, " add ") || strings.Contains(call, " remove ") {
			t.Errorf("GET ran %q", call)
		}
	}

	// The same path: Same is true for both.
	h.desktopConfig(`{"mcpServers":{"mailbag":{"command":` + jsonQuote(h.s.cliPath) + `}}}`)
	h.run.set(claudeAnswers("mailbag:\n  Command: "+h.s.cliPath+"\n", false))
	cs = h.getClients()
	if !cs[clientDesktop].Same || !cs[clientCode].Same || cs[clientDesktop].Running {
		t.Errorf("clients with the same path = %+v", cs)
	}

	// Bad JSON: the view gives the reason and no change.
	h.desktopConfig("{")
	if d := h.getClients()[clientDesktop]; d.Error == "" || d.After != "" {
		t.Errorf("desktop with bad JSON = %+v", d)
	}
}

// jsonQuote gives s as a JSON string.
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestSetup_ClientsApplyDesktop checks POST /api/clients/claude-desktop:
// a backup and the merge, a refusal while the app runs, and a refusal
// of bad JSON with the file kept.
//
// arch: DS13.3, DS13.8, DS13.10, IS13.4, IS13.5
func TestSetup_ClientsApplyDesktop(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	post := request{method: http.MethodPost, path: "/api/clients/" + clientDesktop, body: "{}"}

	if code, _, body := h.do(post); code != http.StatusNotFound {
		t.Errorf("no Claude Desktop: status %d, body %s; want 404", code, body)
	}

	orig := `{"theme":"dark","mcpServers":{"other":{"command":"x"}}}`
	p := h.desktopConfig(orig)
	h.run.set(claudeAnswers("", true))
	if code, _, body := h.do(post); code != http.StatusConflict || !strings.Contains(string(body), "quit") {
		t.Errorf("app runs: status %d, body %s; want 409", code, body)
	}
	if got, _ := os.ReadFile(p); string(got) != orig { //nolint:gosec // G304: a test temp file
		t.Errorf("the config changed while the app runs: %s", got)
	}
	for _, call := range h.run.recorded() {
		if !strings.HasPrefix(call, "pgrep -x ") {
			t.Errorf("the apply ran %q; it may only read the process list (IS13.5)", call)
		}
	}

	h.run.set(claudeAnswers("", false))
	code, _, body := h.do(post)
	var ap clientApplied
	if code != http.StatusOK || json.Unmarshal(body, &ap) != nil || !ap.Changed || ap.Name != clientDesktop {
		t.Fatalf("apply: status %d, body %s", code, body)
	}
	if !strings.HasPrefix(ap.Backup, p+".bak-") {
		t.Errorf("backup %q, want %s.bak-<time>", ap.Backup, p)
	}
	if got, _ := os.ReadFile(ap.Backup); string(got) != orig {
		t.Errorf("backup = %s, want the original", got)
	}
	got, _ := os.ReadFile(p) //nolint:gosec // G304: a test temp file
	for _, w := range []string{`"theme": "dark"`, `"other"`, `"mailbag"`, jsonQuote(h.s.cliPath)} {
		if !strings.Contains(string(got), w) {
			t.Errorf("config lacks %s: %s", w, got)
		}
	}

	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, body := h.do(post); code == http.StatusOK {
		t.Errorf("bad JSON: status %d, body %s; want a refusal", code, body)
	}
	if got, _ := os.ReadFile(p); string(got) != "{" { //nolint:gosec // G304: a test temp file
		t.Errorf("bad JSON was replaced: %s", got)
	}
}

// TestSetup_ClientsApplyClaudeCode checks POST
// /api/clients/claude-code: the add for the user with the CLI path, a
// remove of an entry with another path first, and no call when the
// entry is the same.
//
// arch: DS13.3, DS13.8, DS13.10, IS13.5
func TestSetup_ClientsApplyClaudeCode(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	post := request{method: http.MethodPost, path: "/api/clients/" + clientCode, body: "{}"}
	add := "claude mcp add --scope user mailbag -- " + h.s.cliPath

	apply := func() clientApplied {
		t.Helper()
		code, _, body := h.do(post)
		var ap clientApplied
		if code != http.StatusOK || json.Unmarshal(body, &ap) != nil {
			t.Fatalf("apply: status %d, body %s", code, body)
		}
		return ap
	}

	h.run.set(claudeAnswers("", false))
	if ap := apply(); !ap.Changed {
		t.Errorf("new entry: %+v, want changed", ap)
	}
	if got, want := h.run.recorded(), []string{"claude mcp get mailbag", add}; !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}

	h.run.reset()
	h.run.set(claudeAnswers("mailbag:\n  Command: /old/mailbag-mcp\n", false))
	apply()
	want := []string{"claude mcp get mailbag", "claude mcp remove --scope user mailbag", add}
	if got := h.run.recorded(); !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}

	h.run.set(claudeAnswers("mailbag:\n  Command: "+h.s.cliPath+"\n", false))
	before := len(h.run.recorded())
	if ap := apply(); ap.Changed {
		t.Errorf("same entry: %+v, want no change", ap)
	}
	if got := h.run.recorded()[before:]; !slices.Equal(got, []string{"claude mcp get mailbag"}) {
		t.Errorf("same entry ran %q", got)
	}

	h.run.set(func(call string) ([]byte, error) {
		if strings.Contains(call, " add ") {
			return []byte("boom"), errors.New("exit status 1")
		}
		return nil, errors.New("exit status 1")
	})
	if code, _, body := h.do(post); code != http.StatusInternalServerError || !strings.Contains(string(body), "boom") {
		t.Errorf("failed add: status %d, body %s", code, body)
	}

	if code, _, body := h.do(request{method: http.MethodPost, path: "/api/clients/vscode", body: "{}"}); code != http.StatusNotFound {
		t.Errorf("unknown client: status %d, body %s; want 404", code, body)
	}
}

// TestSetup_ClientsRefused checks that the client routes need the
// token and the Host, take a JSON {} body only, and refuse a write
// when the versions differ, each with no call and no file change.
//
// arch: DS13.6, DS13.7, DS13.10, IS13.3, IS13.4
func TestSetup_ClientsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		r       request
		want    int
	}{
		{"no token GET", "v1.0.0", request{method: http.MethodGet, path: "/api/clients", token: ptr("")}, http.StatusForbidden},
		{"no token POST", "v1.0.0", request{method: http.MethodPost, path: "/api/clients/claude-desktop", body: "{}", token: ptr("")}, http.StatusForbidden},
		{"wrong token", "v1.0.0", request{method: http.MethodPost, path: "/api/clients/claude-code", body: "{}", token: ptr("abc")}, http.StatusForbidden},
		{"wrong Host GET", "v1.0.0", request{method: http.MethodGet, path: "/api/clients", host: "localhost"}, http.StatusForbidden},
		{"wrong Host POST", "v1.0.0", request{method: http.MethodPost, path: "/api/clients/claude-desktop", body: "{}", host: "evil.example"}, http.StatusForbidden},
		{"not JSON", "v1.0.0", request{method: http.MethodPost, path: "/api/clients/claude-desktop", body: "{}", contentType: "text/plain"}, http.StatusUnsupportedMediaType},
		{"unknown field", "v1.0.0", request{method: http.MethodPost, path: "/api/clients/claude-desktop", body: `{"path":"/etc/x"}`}, http.StatusBadRequest},
		{"version mismatch", "v9.9.9", request{method: http.MethodPost, path: "/api/clients/claude-desktop", body: "{}"}, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "v1.0.0", tc.version, time.Minute)
			orig := `{"a":1}`
			p := h.desktopConfig(orig)
			h.run.set(claudeAnswers("", false))
			if code, _, body := h.do(tc.r); code != tc.want {
				t.Errorf("status %d, body %s; want %d", code, body, tc.want)
			}
			if got := h.run.recorded(); len(got) != 0 {
				t.Errorf("a refused request ran %q", got)
			}
			if got, _ := os.ReadFile(p); string(got) != orig { //nolint:gosec // G304: a test temp file
				t.Errorf("a refused request changed the config: %s", got)
			}
			if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
				t.Errorf("a refused request left %d files", len(ents))
			}
		})
	}
}

// TestSetup_StopKillsStuckJob checks L3: at the stop, a CLI that
// ignores SIGTERM is killed after stopWait, so serve ends.
//
// arch: DS13.6, IS13.5
func TestSetup_StopKillsStuckJob(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	t.Setenv(envFakeBlock, "1")
	t.Setenv(envFakeNoTerm, "1")
	id := h.startJob("/api/doctor", "{}")
	deadline := time.Now().Add(20 * time.Second)
	for len(h.calls()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the doctor job did not start before the deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
	j := h.s.lookupJob(id)

	const wait = 300 * time.Millisecond
	h.s.stopWait = wait // read by serve only after stop
	start := time.Now()
	h.s.stop()
	select {
	case <-j.done:
	case <-time.After(15 * time.Second):
		t.Fatal("the stuck job did not end after the stop")
	}
	took := time.Since(start)
	if took < wait {
		t.Errorf("the job ended after %v, before stopWait %v: SIGTERM was not ignored", took, wait)
	}
	if v := j.view(0); v.Exit == nil || *v.Exit == 0 {
		t.Errorf("killed job: %+v, want a non-zero exit", v)
	}
}

// TestSetup_FileStoreChoicePassed checks review M3: the page sends the
// answer to the file-store question with each step that can ask it,
// and the server gives it to the CLI on stdin with --answers-stdin.
// Account add carries use_file_store in its document; "oauth set
// microsoft" takes it from the JSON body and "oauth set google" from
// the query. A bad query value is refused before the CLI runs. With no
// answer, "oauth set" gets no flag and no stdin, as before (B5).
//
// arch: DS13.5, DS13.8, DS13.10, IS13.1, IS13.2
func TestSetup_FileStoreChoicePassed(t *testing.T) {
	h := newHarness(t, "v1.0.0", "v1.0.0", time.Minute)
	t.Setenv("TMPDIR", t.TempDir())
	last := func() fakeCall {
		t.Helper()
		calls := h.calls()
		if len(calls) == 0 {
			t.Fatal("the CLI did not run")
		}
		return calls[len(calls)-1]
	}

	id := h.startJob("/api/accounts", `{"alias":"g","provider":"gmail","email":"me@example.test","use_file_store":true}`)
	h.waitJob(id)
	if got := last().Stdin; got != `{"use_file_store":true}` {
		t.Errorf("account add stdin = %q, want the use_file_store answer", got)
	}

	const guid = "00000000-1111-2222-3333-444444444444"
	code, _, body := h.do(request{method: http.MethodPost, path: "/api/oauth/microsoft", body: `{"client_id":"` + guid + `","use_file_store":true}`})
	if code != http.StatusOK {
		t.Fatalf("microsoft: status %d, body %s", code, body)
	}
	c := last()
	if want := []string{"oauth", "set", "microsoft", "--client-id=" + guid, "--answers-stdin"}; !slices.Equal(c.Args, want) {
		t.Errorf("microsoft argv = %q, want %q", c.Args, want)
	}
	if c.Stdin != `{"use_file_store":true}` {
		t.Errorf("microsoft stdin = %q", c.Stdin)
	}

	code, _, body = h.do(request{method: http.MethodPost, path: "/api/oauth/google?use_file_store=false", body: `{"installed":{}}`})
	if code != http.StatusOK {
		t.Fatalf("google: status %d, body %s", code, body)
	}
	c = last()
	if len(c.Args) != 5 || !slices.Equal(c.Args[:3], []string{"oauth", "set", "google"}) ||
		!strings.HasPrefix(c.Args[3], "--file=") || c.Args[4] != "--answers-stdin" {
		t.Errorf("google argv = %q", c.Args)
	}
	if c.Stdin != `{"use_file_store":false}` {
		t.Errorf("google stdin = %q", c.Stdin)
	}

	n := len(h.calls())
	for _, q := range []string{"yes", "", "true&use_file_store=false"} {
		code, _, body = h.do(request{method: http.MethodPost, path: "/api/oauth/google?use_file_store=" + q, body: `{"installed":{}}`})
		if code != http.StatusBadRequest {
			t.Errorf("use_file_store=%s: status %d, want 400; body %s", q, code, body)
		}
	}
	if got := len(h.calls()); got != n {
		t.Errorf("the CLI ran %d times after refused queries", got-n)
	}

	code, _, body = h.do(request{method: http.MethodPost, path: "/api/oauth/microsoft", body: `{"client_id":"` + guid + `"}`})
	if code != http.StatusOK {
		t.Fatalf("microsoft with no answer: status %d, body %s", code, body)
	}
	if c = last(); len(c.Args) != 4 || c.Stdin != "" {
		t.Errorf("microsoft with no answer: argv %q, stdin %q; want no flag and no stdin", c.Args, c.Stdin)
	}

	// The page: one checkbox, and its value goes with each of the three
	// requests under the field name that the server reads.
	if !jsonTags(addAccountRequest{})["use_file_store"] {
		t.Fatal("addAccountRequest has no use_file_store field")
	}
	html, err := fs.ReadFile(webFiles(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `type="checkbox" id="f-filestore"`) {
		t.Error("index.html has no file-store checkbox")
	}
	js, err := fs.ReadFile(webFiles(), "app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`$("f-filestore").checked`,
		`"/api/oauth/google?use_file_store=" + fileStore()`,
		`{ client_id: id, use_file_store: fileStore() }`,
		`use_file_store: fileStore(),`,
	} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js does not hold %q", want)
		}
	}
}
