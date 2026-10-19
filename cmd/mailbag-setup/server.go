// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The local HTTP server of mailbag-setup: the Host check, the token
// header, the security headers, the API of DS13.10 and the one CLI
// job at a time. The server writes no file except the temporary
// client file of "oauth set google", and it writes no log.

package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
)

// tokenHeader is the request header that carries the token (DS13.6
// rule 3). A custom header forces a CORS preflight from another
// origin, and the server never answers a preflight with a CORS header.
const tokenHeader = "X-Mailbag-Setup" //nolint:gosec // G101: a header name, not a credential

// contentSecurityPolicy is the CSP of DS13.6 rule 6, word for word.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"

// maxBodyBytes is the largest request body that the server reads. A
// Google client file is about 0.5 KB.
const maxBodyBytes = 1 << 20

// maxJobLines is the number of output lines that one job keeps. A
// longer output keeps its first lines only.
const maxJobLines = 10000

// versionTimeout limits the "mailbag-mcp version" call at start.
const versionTimeout = 10 * time.Second

// jobWaitDelay is the time that the server waits for the output pipes
// of a CLI process after the process ended. A child of the CLI that
// keeps the pipe open cannot block the job.
const jobWaitDelay = 5 * time.Second

// jobStopWait is the time that serve waits for a CLI job after SIGTERM
// at the stop. Then it kills that process (L3, IS13.5).
const jobStopWait = 10 * time.Second

// clientTimeout limits the calls of claude and pgrep for one client
// request.
const clientTimeout = 30 * time.Second

// guidPattern is the form of a Microsoft client id (DS13.8 step 5).
var guidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// errBusy is the refusal of a second CLI job while one runs (DS13.6
// rule 8).
var errBusy = errors.New("another job runs; wait for it to end, or cancel it")

// serverConfig is the input of newServer.
type serverConfig struct {
	// CLIPath is the absolute path of the mailbag-mcp binary (DS13.7).
	CLIPath string
	// SetupVersion is the version line of mailbag-setup, such as
	// "mailbag-setup v1.2.0".
	SetupVersion string
	// Idle is the time with no API request after which the server
	// stops (DS13.6 rule 10).
	Idle time.Duration
	// Home is the home directory of the person. The Claude Desktop
	// config is under it. "" means no Claude Desktop config.
	Home string
	// GOOS selects the Claude Desktop config path.
	GOOS string
	// Run starts claude and pgrep. main gives execRunner; tests give
	// a fake, so no test runs the real claude.
	Run cmdRunner
}

// server is the setup server. It implements http.Handler.
//
// arch: DS13.6, DS13.10, IS13.1, IS13.3
type server struct {
	cliPath      string
	setupVersion string
	cliVersion   string
	match        bool
	token        string
	host         string
	idle         time.Duration
	home         string
	goos         string
	run          cmdRunner
	stopWait     time.Duration
	mux          *http.ServeMux

	// clientMu lets one client change run at a time.
	clientMu sync.Mutex

	idleTimer *time.Timer
	done      chan struct{}
	stopOnce  sync.Once

	mu      sync.Mutex
	running *job
	jobs    map[string]*job
	lastID  int
}

// newServer makes a server for the listener address addr, which must
// be "127.0.0.1:<port>". It runs "mailbag-mcp version" once and
// compares the version with cfg.SetupVersion (DS13.7). The idle timer
// starts here.
//
// arch: DS13.6, DS13.7
func newServer(cfg serverConfig, addr string) (*server, error) {
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		return nil, fmt.Errorf("the server listens on 127.0.0.1 only, not on %s", addr)
	}
	token, err := newToken()
	if err != nil {
		return nil, fmt.Errorf("make the token: %w", err)
	}
	s := &server{
		cliPath:      cfg.CLIPath,
		setupVersion: cfg.SetupVersion,
		token:        token,
		host:         addr,
		idle:         cfg.Idle,
		home:         cfg.Home,
		goos:         cfg.GOOS,
		run:          cfg.Run,
		stopWait:     jobStopWait,
		done:         make(chan struct{}),
		jobs:         map[string]*job{},
	}
	s.cliVersion = s.readCLIVersion()
	s.match = versionsMatch(s.setupVersion, s.cliVersion)
	s.routes()
	s.idleTimer = time.AfterFunc(s.idle, s.stop)
	return s, nil
}

// readCLIVersion runs "mailbag-mcp version" and gives its first
// line, or "" when the command fails. It runs before the server
// serves, so it does not take the job lock.
func (s *server) readCLIVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, s.cliPath, "version").Output() //nolint:gosec // G204: the fixed CLI path of DS13.7 and a fixed argument, no shell
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(line)
}

// versionsMatch reports whether the two version lines give the same
// version after the program name (DS13.7). An empty version never
// matches.
func versionsMatch(setupLine, cliLine string) bool {
	_, a, okA := strings.Cut(strings.TrimSpace(setupLine), " ")
	_, b, okB := strings.Cut(strings.TrimSpace(cliLine), " ")
	return okA && okB && a != "" && a == b
}

// routes registers the API of DS13.10 and the page.
func (s *server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", s.handlePage)
	m.HandleFunc("GET /app.js", s.handlePage)
	m.HandleFunc("GET /style.css", s.handlePage)
	m.HandleFunc("GET /presets.json", s.handlePage)
	m.HandleFunc("GET /api/state", s.handleState)
	m.HandleFunc("POST /api/oauth/google", s.writeAction(s.handleOAuthGoogle))
	m.HandleFunc("POST /api/oauth/microsoft", s.writeAction(s.handleOAuthMicrosoft))
	m.HandleFunc("POST /api/accounts", s.writeAction(s.handleAccountAdd))
	m.HandleFunc("POST /api/accounts/{alias}/test", s.handleAccountTest)
	m.HandleFunc("DELETE /api/accounts/{alias}", s.writeAction(s.handleAccountRemove))
	m.HandleFunc("GET /api/jobs/{id}", s.handleJob)
	m.HandleFunc("POST /api/jobs/{id}/cancel", s.handleJobCancel)
	m.HandleFunc("POST /api/doctor", s.handleDoctor)
	m.HandleFunc("POST /api/service", s.writeAction(s.handleService))
	m.HandleFunc("GET /api/clients", s.handleClients)
	m.HandleFunc("POST /api/clients/{name}", s.writeAction(s.handleClientApply))
	m.HandleFunc("POST /api/finish", s.handleFinish)
	s.mux = m
}

// ServeHTTP applies the rules of DS13.6 to each request before the
// router sees it: the security headers on each response (rule 6), the
// exact Host (rule 4), the token on each API request (rule 3) and the
// JSON content type on each POST (rule 5). A refused request reaches
// no handler, so it changes nothing (IS13.3).
//
// arch: DS13.6, IS13.3
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")

	if r.Host != s.host {
		writeError(w, http.StatusForbidden, "wrong Host header")
		return
	}
	// A path that is not clean could reach the router in another form
	// than the prefix check below sees.
	if path.Clean(r.URL.Path) != r.URL.Path {
		writeError(w, http.StatusBadRequest, "the path is not clean")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		got := r.Header.Get(tokenHeader)
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeError(w, http.StatusForbidden, "missing or wrong token")
			return
		}
		s.touch()
	}
	if r.Method == http.MethodPost && !isJSON(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "a POST must have Content-Type: application/json")
		return
	}
	s.mux.ServeHTTP(w, r)
}

// isJSON reports whether the media type of a Content-Type header is
// application/json.
func isJSON(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/json"
}

// touch starts the idle time again after an API request.
func (s *server) touch() {
	s.idleTimer.Reset(s.idle)
}

// stop ends the server. It is safe to call more than once.
func (s *server) stop() {
	s.stopOnce.Do(func() { close(s.done) })
}

// serve serves on ln until ctx ends or stop is called (Finish, idle
// time, signal). Then it shuts the HTTP server down and sends SIGTERM
// to a CLI job that still runs. When that process does not end in
// stopWait, serve kills it. It stops no other process (IS13.5).
//
// arch: DS13.6, IS13.5
func (s *server) serve(ctx context.Context, ln net.Listener) {
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	select {
	case <-ctx.Done():
	case <-s.done:
	}
	s.idleTimer.Stop()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)

	s.mu.Lock()
	j := s.running
	s.mu.Unlock()
	if j != nil {
		j.cancel()
		select {
		case <-j.done:
		case <-time.After(s.stopWait):
			// The process that startJob started, and no other one
			// (IS13.5). It ignored SIGTERM.
			_ = j.proc.Kill()
			<-j.done
		}
	}
}

// writeAction refuses a write action when the versions of the two
// binaries differ (DS13.7). The page then shows both versions.
//
// arch: DS13.7
func (s *server) writeAction(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.match {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":         "the versions of mailbag-setup and mailbag-mcp differ; install the same version of both",
				"setup_version": s.setupVersion,
				"cli_version":   s.cliVersion,
			})
			return
		}
		next(w, r)
	}
}

// pageTypes maps each served web file to its Content-Type.
var pageTypes = map[string]string{
	"/":             "text/html; charset=utf-8",
	"/app.js":       "text/javascript; charset=utf-8",
	"/style.css":    "text/css; charset=utf-8",
	"/presets.json": "application/json",
}

// handlePage serves the embedded page, script, style sheet and presets
// from webFiles(). The security headers come from ServeHTTP.
//
// arch: DS13.4, DS13.6, DS13.8
func (s *server) handlePage(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	b, err := fs.ReadFile(webFiles(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Content-Type", pageTypes[r.URL.Path])
	_, _ = w.Write(b) //nolint:gosec // G705: the router passes only four fixed paths, b is an embedded file and the Content-Type comes from pageTypes
}

// stateAccount is one account in the state of GET /api/state.
type stateAccount struct {
	Alias    string `json:"alias"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Access   string `json:"access"`
}

// handleState gives the versions, the paths, the accounts and the
// secret store kind. It reads accounts.toml through internal/config,
// read only (IS13.1). A missing file gives no accounts.
//
// arch: DS13.2, DS13.7, DS13.10, IS13.1
func (s *server) handleState(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{
		"setup_version":  s.setupVersion,
		"cli_version":    s.cliVersion,
		"cli_path":       s.cliPath,
		"versions_match": s.match,
		"accounts":       []stateAccount{},
	}
	p, err := config.AccountsPath()
	if err != nil {
		out["config_error"] = err.Error()
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["config_path"] = p
	cfg, err := config.Load(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		out["config_error"] = err.Error()
	default:
		accts := []stateAccount{}
		for _, a := range cfg.Aliases() {
			acct, _ := cfg.Account(a)
			accts = append(accts, stateAccount{Alias: a, Provider: acct.Provider, Email: acct.Email, Access: acct.Access})
		}
		out["accounts"] = accts
		out["secrets"] = cfg.Secrets()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleOAuthGoogle takes the client file of the Google Cloud console
// as the body and runs "oauth set google --file". The file goes to a
// 0600 file in a new 0700 temporary directory, and the server removes
// the directory when the command ends (DS13.6 rule 11, IS13.2). The
// body is the file as it is, so the answer to the file-store question
// comes in the query: ?use_file_store=true or false (review M3).
//
// arch: DS13.5, DS13.6, DS13.10, IS13.2
func (s *server) handleOAuthGoogle(w http.ResponseWriter, r *http.Request) {
	var useFileStore *bool
	if q := r.URL.Query(); q.Has("use_file_store") {
		v, err := strconv.ParseBool(q.Get("use_file_store"))
		if err != nil || len(q["use_file_store"]) != 1 {
			writeError(w, http.StatusBadRequest, "use_file_store must be true or false")
			return
		}
		useFileStore = &v
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read the body")
		return
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		writeError(w, http.StatusBadRequest, "the body is not one JSON object")
		return
	}
	if _, ok := top["installed"]; !ok {
		msg := `the file has no "installed" key; make a "Desktop app" client`
		if _, web := top["web"]; web {
			msg = `the file is for a "Web application" client; make a "Desktop app" client`
		}
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	dir, err := os.MkdirTemp("", "mailbag-setup-")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "make a temporary directory")
		return
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	file := filepath.Join(dir, "client_secret.json")
	if err := writePrivateFile(file, body); err != nil {
		cleanup()
		writeError(w, http.StatusInternalServerError, "write the temporary client file")
		return
	}
	clear(body)
	args, stdin := oauthAnswers([]string{"oauth", "set", "google", "--file=" + file}, useFileStore)
	s.runSync(w, args, stdin, cleanup)
}

// oauthAnswers adds --answers-stdin to an "oauth set" argv when the
// page answered the file-store question, and gives the document for
// stdin: {"use_file_store": B} (DS13.5, review M3). With no answer, the
// argv stays as it is and stdin is empty. The CLI then refuses the
// question as before, because its stdin is not a terminal (B5).
//
// arch: DS13.5, IS13.2, B5
func oauthAnswers(args []string, useFileStore *bool) ([]string, []byte) {
	if useFileStore == nil {
		return args, nil
	}
	doc, _ := json.Marshal(answersDoc{UseFileStore: useFileStore}) //nolint:gosec // G117: the document goes to the CLI on stdin by design (IS13.2); a struct of a bool pointer always encodes
	return append(args, "--answers-stdin"), doc
}

// writePrivateFile writes data to a new file at p with mode 0600.
func writePrivateFile(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: p is in a directory that this process just made
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// handleOAuthMicrosoft runs "oauth set microsoft --client-id". The
// client id of a public client is not a secret. The optional
// use_file_store goes to the CLI on stdin (review M3).
//
// arch: DS13.5, DS13.10
func (s *server) handleOAuthMicrosoft(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"client_id"`
		UseFileStore *bool  `json:"use_file_store"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if !guidPattern.MatchString(req.ClientID) {
		writeError(w, http.StatusBadRequest, "the client id must be a GUID")
		return
	}
	args, stdin := oauthAnswers([]string{"oauth", "set", "microsoft", "--client-id=" + req.ClientID}, req.UseFileStore)
	s.runSync(w, args, stdin, nil)
}

// addAccountRequest is the body of POST /api/accounts. Secret and
// UseFileStore go to the CLI in the --answers-stdin document only,
// never in argv or the environment (IS13.2).
type addAccountRequest struct {
	Alias        string  `json:"alias"`
	Provider     string  `json:"provider"`
	Email        string  `json:"email"`
	Access       string  `json:"access"`
	IMAP         string  `json:"imap"`
	SMTP         string  `json:"smtp"`
	Username     string  `json:"username"`
	Tenant       string  `json:"tenant"`
	SessionURL   string  `json:"session_url"`
	Bearer       bool    `json:"bearer"`
	PrivateHost  bool    `json:"private_host"`
	Secret       *string `json:"secret"`
	UseFileStore *bool   `json:"use_file_store"`
}

// answersDoc is the --answers-stdin document of DS13.5.
type answersDoc struct {
	Secret       *string `json:"secret,omitempty"`
	UseFileStore *bool   `json:"use_file_store,omitempty"`
}

// handleAccountAdd starts "account add <alias> --answers-stdin" with
// an argv built from checked fields (DS13.6 rule 9). Each value goes
// as "--flag=value", so no value can be read as a flag. The secret
// goes to the CLI on stdin only (IS13.2). It gives a job id.
//
// arch: DS13.5, DS13.6, DS13.10, IS13.1, IS13.2
func (s *server) handleAccountAdd(w http.ResponseWriter, r *http.Request) {
	var req addAccountRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if msg := checkAlias(req.Alias); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	switch req.Provider {
	case "imap", "outlook", "gmail", "jmap":
	default:
		writeError(w, http.StatusBadRequest, "provider must be imap, outlook, gmail or jmap")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is empty")
		return
	}
	args := []string{"account", "add", req.Alias, "--provider=" + req.Provider, "--answers-stdin"}
	for _, f := range []struct{ flag, value string }{
		{"email", req.Email}, {"access", req.Access}, {"imap", req.IMAP}, {"smtp", req.SMTP},
		{"username", req.Username}, {"tenant", req.Tenant}, {"session-url", req.SessionURL},
	} {
		if f.value == "" {
			continue
		}
		if hasControl(f.value) {
			writeError(w, http.StatusBadRequest, f.flag+" holds a control character")
			return
		}
		args = append(args, "--"+f.flag+"="+f.value)
	}
	if req.Bearer {
		args = append(args, "--bearer")
	}
	if req.PrivateHost {
		args = append(args, "--private-host")
	}

	doc, err := json.Marshal(answersDoc{Secret: req.Secret, UseFileStore: req.UseFileStore}) //nolint:gosec // G117: the secret goes to the CLI on stdin only (IS13.2), never to a log or a file
	req.Secret = nil
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode the answers")
		return
	}
	s.runAsync(w, args, doc, nil)
}

// handleAccountTest starts "account test <alias>". It gives a job id.
//
// arch: DS13.10
func (s *server) handleAccountTest(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("alias")
	if msg := checkAlias(alias); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	s.runAsync(w, []string{"account", "test", alias}, nil, nil)
}

// handleAccountRemove runs "account remove <alias>".
//
// arch: DS13.10, IS13.1
func (s *server) handleAccountRemove(w http.ResponseWriter, r *http.Request) {
	alias := r.PathValue("alias")
	if msg := checkAlias(alias); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	s.runSync(w, []string{"account", "remove", alias}, nil, nil)
}

// handleDoctor starts "doctor". It gives a job id.
func (s *server) handleDoctor(w http.ResponseWriter, _ *http.Request) {
	s.runAsync(w, []string{"doctor"}, nil, nil)
}

// handleService starts "service install". The server never runs
// systemctl; the page shows the command to copy (IS13.5).
//
// arch: DS13.8, IS13.5
func (s *server) handleService(w http.ResponseWriter, _ *http.Request) {
	s.runAsync(w, []string{"service", "install"}, nil, nil)
}

// desktopPath gives the Claude Desktop config path, or "" when no
// home directory or no path for this system is known.
func (s *server) desktopPath() string {
	if s.home == "" {
		return ""
	}
	return desktopConfigPath(s.home, s.goos)
}

// handleClients gives the state of Claude Desktop and Claude Code:
// present, the current mailbag entry, the change that "Apply" makes,
// and whether the Claude app runs. It writes nothing.
//
// arch: DS13.3, DS13.8, DS13.10
func (s *server) handleClients(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), clientTimeout)
	defer cancel()
	desktop := desktopState(s.desktopPath(), s.cliPath, desktopAppRunning(ctx, s.run))
	writeJSON(w, http.StatusOK, []clientView{desktop, claudeCodeState(ctx, s.run, s.cliPath)})
}

// handleClientApply connects mailbag to one client. Claude Desktop:
// a backup, a merge and a rename, refused while the app runs.
// Claude Code: "claude mcp add --scope user". The body is {}.
//
// arch: DS13.3, DS13.8, DS13.10, IS13.4, IS13.5
func (s *server) handleClientApply(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if !decodeBody(w, r, &req) {
		return
	}
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), clientTimeout)
	defer cancel()
	name := r.PathValue("name")
	switch name {
	case clientDesktop:
		if !desktopPresent(s.desktopPath()) {
			writeError(w, http.StatusNotFound, "Claude Desktop is not on this computer")
			return
		}
		running := func() bool { return desktopAppRunning(ctx, s.run) }
		backup, err := applyDesktop(s.desktopPath(), s.cliPath, running, time.Now)
		switch {
		case errors.Is(err, errAppRunning):
			writeError(w, http.StatusConflict, err.Error())
		case err != nil:
			writeError(w, http.StatusInternalServerError, err.Error())
		default:
			writeJSON(w, http.StatusOK, clientApplied{Name: name, Changed: true, Backup: backup})
		}
	case clientCode:
		changed, err := connectClaudeCode(ctx, s.run, s.cliPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, clientApplied{Name: name, Changed: changed})
	default:
		writeError(w, http.StatusNotFound, "no such client")
	}
}

// handleFinish answers, then stops the server.
func (s *server) handleFinish(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	s.stop()
}

// handleJob gives the output lines of a job after line n
// (?after=n), and the exit code when the job ended.
//
// arch: DS13.10
func (s *server) handleJob(w http.ResponseWriter, r *http.Request) {
	j := s.lookupJob(r.PathValue("id"))
	if j == nil {
		writeError(w, http.StatusNotFound, "no such job")
		return
	}
	after := 0
	if v := r.URL.Query().Get("after"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "after must be a number of lines")
			return
		}
		after = n
	}
	writeJSON(w, http.StatusOK, j.view(after))
}

// handleJobCancel sends SIGTERM to the CLI of a job that runs.
//
// arch: DS13.10, IS13.5
func (s *server) handleJobCancel(w http.ResponseWriter, r *http.Request) {
	j := s.lookupJob(r.PathValue("id"))
	if j == nil {
		writeError(w, http.StatusNotFound, "no such job")
		return
	}
	j.cancel()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// lookupJob gives the job with the id, or nil.
func (s *server) lookupJob(id string) *job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

// runAsync starts a job and answers 202 with its id.
func (s *server) runAsync(w http.ResponseWriter, args []string, stdin []byte, cleanup func()) {
	j, err := s.startJob(args, stdin, cleanup)
	if err != nil {
		writeJobError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": j.id})
}

// runSync starts a job, waits for its end and answers with its output
// and exit code.
func (s *server) runSync(w http.ResponseWriter, args []string, stdin []byte, cleanup func()) {
	j, err := s.startJob(args, stdin, cleanup)
	if err != nil {
		writeJobError(w, err)
		return
	}
	<-j.done
	writeJSON(w, http.StatusOK, j.view(0))
}

// writeJobError answers a failed job start.
func writeJobError(w http.ResponseWriter, err error) {
	if errors.Is(err, errBusy) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, "start mailbag-mcp: "+err.Error())
}

// startJob runs the CLI with args, with no shell and the fixed CLI
// path (DS13.6 rule 9). It refuses a second job while one runs (rule
// 8). stdin, when not nil, is the whole stdin of the CLI; the server
// clears it when the CLI ends. cleanup, when not nil, runs when the
// CLI ends, or at once when the start fails.
//
// arch: DS13.6, IS13.2, IS13.5
func (s *server) startJob(args []string, stdin []byte, cleanup func()) (*job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, errBusy
	}
	s.lastID++
	j := &job{id: strconv.Itoa(s.lastID), done: make(chan struct{})}
	cmd := exec.Command(s.cliPath, args...) //nolint:gosec // G204: the fixed CLI path of DS13.7 and an argv of checked fields, no shell
	cmd.Stdout = j
	cmd.Stderr = j
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.WaitDelay = jobWaitDelay
	if err := cmd.Start(); err != nil {
		clear(stdin)
		if cleanup != nil {
			cleanup()
		}
		return nil, err
	}
	j.proc = cmd.Process
	s.running = j
	s.jobs[j.id] = j

	go func() {
		_ = cmd.Wait()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		clear(stdin)
		if cleanup != nil {
			cleanup()
		}
		s.mu.Lock()
		if s.running == j {
			s.running = nil
		}
		s.mu.Unlock()
		j.finish(code)
	}()
	return j, nil
}

// job is one run of the CLI. Its stdout and stderr go into one list
// of lines, in the order of the writes.
type job struct {
	id   string
	proc *os.Process
	done chan struct{}

	mu      sync.Mutex
	lines   []string
	partial []byte
	exit    int
	ended   bool
}

// Write takes output of the CLI and splits it into lines.
func (j *job) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.partial = append(j.partial, p...)
	for {
		i := bytes.IndexByte(j.partial, '\n')
		if i < 0 {
			break
		}
		j.addLine(string(bytes.TrimRight(j.partial[:i], "\r")))
		j.partial = j.partial[i+1:]
	}
	return len(p), nil
}

// addLine keeps a line while the job has fewer than maxJobLines.
func (j *job) addLine(line string) {
	if len(j.lines) < maxJobLines {
		j.lines = append(j.lines, line)
	}
}

// finish records the exit code and the last line without a newline.
func (j *job) finish(code int) {
	j.mu.Lock()
	if len(j.partial) > 0 {
		j.addLine(string(j.partial))
		j.partial = nil
	}
	j.exit = code
	j.ended = true
	j.mu.Unlock()
	close(j.done)
}

// cancel sends SIGTERM to the CLI of the job while it runs. It sends
// no signal to any other process (IS13.5).
func (j *job) cancel() {
	select {
	case <-j.done:
		return
	default:
	}
	_ = j.proc.Signal(syscall.SIGTERM)
}

// jobView is the answer of GET /api/jobs/<id>.
type jobView struct {
	ID    string   `json:"id"`
	Lines []string `json:"lines"`
	Next  int      `json:"next"`
	Done  bool     `json:"done"`
	Exit  *int     `json:"exit"`
}

// view gives the lines after line after, and the exit code when the
// job ended.
func (j *job) view(after int) jobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	after = min(after, len(j.lines))
	v := jobView{ID: j.id, Lines: append([]string{}, j.lines[after:]...), Next: len(j.lines), Done: j.ended}
	if j.ended {
		code := j.exit
		v.Exit = &code
	}
	return v
}

// checkAlias gives "" for an alias that the CLI takes, else the
// refusal. It is the check of guard.ValidateAlias; the CLI checks it
// again (DS13.6 rule 9). An alias that starts with "-" is refused, so
// it cannot be read as a flag.
func checkAlias(alias string) string {
	if guard.ValidateAlias(alias) != nil || strings.HasPrefix(alias, "-") {
		return "alias: use letters, digits, - and _ only, and do not start with -"
	}
	return ""
}

// hasControl reports whether s holds a control character.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// decodeBody reads one strict JSON object from the body into v. It
// answers 400 and gives false on a bad body. The answer never repeats
// the body, so a secret in it goes nowhere.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "the body is not one JSON object with the known fields")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "the body holds more than one JSON document")
		return false
	}
	return true
}

// writeJSON writes v as the JSON answer with the status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes {"error": msg} with the status code.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
