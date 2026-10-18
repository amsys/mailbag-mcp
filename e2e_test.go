// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// binPath is the mailbag-mcp binary TestMain builds once, so every
// e2e test below spawns the same static binary instead of paying for
// a fresh build each time (§5.1 "Process").
var binPath string

// TestMain builds the binary before any test in this file runs, and
// removes it afterwards. It builds the way the release does
// (CGO_ENABLED=0, §7), so a build tag or an accidental cgo import
// would fail here rather than only at release time.
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "mailbag-mcp-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mailbag-mcp-e2e: %v\n", err)
		os.Exit(1)
	}

	binPath = filepath.Join(dir, "mailbag-mcp")
	build := exec.Command("go", "build", "-o", binPath, ".") //nolint:gosec // G204: the test builds this module with fixed arguments
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "go build: %v\n%s", err, out)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// rpcRequest is one JSON-RPC 2.0 request or notification (an ID of 0
// is omitted, which is how a notification is told apart from a
// request on the wire here, since the helper never issues request id
// 0).
type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// rpcResponse is one JSON-RPC 2.0 response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// testServer is a running mailbag-mcp process under test, talking
// newline-delimited JSON-RPC over its own stdin and stdout (the same
// framing the SDK's stdio transport uses). It never uses the SDK
// client: the e2e tests need raw access to every stdout line
// (TestE2E_StdoutIsOnlyJSONRPC) and to the process's signals and
// pipes, which a client would hide.
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
type testServer struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stderr io.ReadCloser

	runtimeDir string // XDG_RUNTIME_DIR of the process: the daemon socket is below it (IS11.9)

	lines chan string // one entry per stdout line, for the next unread reply (A13)

	mu       sync.Mutex
	allLines []string // every stdout line seen this session, for TestE2E_StdoutIsOnlyJSONRPC

	waitDone chan struct{}
	waitErr  error

	nextID int64
}

// startServer starts the built binary with no argument, pointed at a
// temporary config and state directory of its own (never the owner's
// real one). A background goroutine keeps reading stdout for the life
// of the test so the pipe never fills while nobody is looking (A13);
// every line it reads is also kept for TestE2E_StdoutIsOnlyJSONRPC.
// Cleanup closes stdin (stdin EOF is one of the two ways the design
// asks the server to exit, §10.1) and waits up to 2s before killing
// the process, so no e2e test can leave one running.
//
// From S11 the binary with no argument is the shim (DS11.13): it
// connects to the daemon on $XDG_RUNTIME_DIR/mailbag/mailbag.sock, or
// starts the daemon there. Thus each test gets a short XDG_RUNTIME_DIR
// of its own, and never dials the live socket of the owner (IS11.9).
// The cleanup also stops the daemon that the shim started (G6 in
// DS11.20). The tests below check the process that the client starts:
// the shim, with a daemon behind it.
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2, DS11.1, DS11.13, DS11.15, IS11.1, IS11.9, IS11.10
func startServer(t *testing.T) *testServer {
	t.Helper()
	return startServerWithStateDir(t, t.TempDir())
}

// startServerWithStateDir is startServer with the state directory
// under the caller's control, so a test can seed it before the
// process starts. TestE2E_ClosedStderrKeepsServing uses this to force
// the server's log file open to fail, which is the only way to make
// it log to stderr (internal/server/log.go's stderrLogger fallback):
// normal logging goes to state-dir/server.log, never to stderr
// (§3.19), so a test that only closes stderr's read side without
// this would never see a write on that fd at all and would pass
// whether or not SIGPIPE is ignored (A5).
//
// arch: T1.6, §5.3, §5.1, A5, §10.1, §10.2, DS11.1, DS11.13, DS11.15, IS11.1, IS11.9, IS11.10
func startServerWithStateDir(t *testing.T, stateDir string) *testServer {
	t.Helper()
	runtimeDir := shortRuntimeDir(t)
	return startServerWithDirs(t, t.TempDir(), stateDir, runtimeDir)
}

// startServerWithDirs starts the built binary with no argument, with
// the config dir, the state dir and the runtime dir that the caller
// gives. It is the one launch site of the e2e tests. Thus each launch
// sets XDG_RUNTIME_DIR to a test directory, and no launch dials the
// live socket of the owner (IS11.9). Two launches with the same three
// directories reach one daemon (DS11.18 step 2):
// TestE2E_ShimSecondSessionNoNewStart uses this.
//
// arch: DS11.15, DS11.18, IS11.1, IS11.9
func startServerWithDirs(t *testing.T, configDir, stateDir, runtimeDir string) *testServer {
	t.Helper()

	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(),
		"MAILBAG_CONFIG_DIR="+configDir,
		"MAILBAG_STATE_DIR="+stateDir,
		"XDG_RUNTIME_DIR="+runtimeDir,
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binPath, err)
	}

	ts := &testServer{
		t:          t,
		cmd:        cmd,
		stdin:      stdin,
		stderr:     stderr,
		runtimeDir: runtimeDir,
		lines:      make(chan string, 64),
		waitDone:   make(chan struct{}),
	}

	go func() {
		defer close(ts.lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			ts.mu.Lock()
			ts.allLines = append(ts.allLines, line)
			ts.mu.Unlock()
			ts.lines <- line
		}
	}()
	go io.Copy(io.Discard, stderr) //nolint:errcheck // default drain; TestE2E_ClosedStderrKeepsServing closes stderr itself instead

	go func() {
		ts.waitErr = cmd.Wait()
		close(ts.waitDone)
	}()

	t.Cleanup(ts.cleanup)
	return ts
}

// cleanup stops the shim, and then the daemon that the shim started.
// It runs before the cleanup of the temp dirs (t.Cleanup is last in,
// first out), so no daemon writes to a state dir that is removed.
func (ts *testServer) cleanup() {
	_ = ts.stdin.Close()
	select {
	case <-ts.waitDone:
	case <-time.After(2 * time.Second):
		_ = ts.cmd.Process.Kill()
		<-ts.waitDone
	}
	ts.stopDaemon()
}

// maxSocketPath is the longest socket path that the e2e tests use. A
// Unix socket path has a limit of 104 bytes on macOS and 108 bytes on
// Linux, with the terminating zero byte.
const maxSocketPath = 100

// shortRuntimeDir makes a short directory for XDG_RUNTIME_DIR and
// removes it at cleanup. It skips the test with the reason when the
// daemon socket path below it is longer than maxSocketPath: a long
// TMPDIR is a fact of the host, not a fault of the code (DS11.15).
//
// arch: DS11.15, IS11.9
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mbrt")
	if err != nil {
		t.Fatalf("make runtime dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if p := filepath.Join(dir, "mailbag", "mailbag.sock"); len(p) > maxSocketPath {
		t.Skipf("the socket path %s has %d bytes, more than %d; set a shorter TMPDIR", p, len(p), maxSocketPath)
	}
	return dir
}

// daemonStopWait is the time that a daemon gets to exit after
// SIGTERM (G6 in DS11.20).
const daemonStopWait = 5 * time.Second

// stopDaemon stops the daemon that the shim of this test started (G6
// in DS11.20). The daemon writes its pid into mailbag.lock in the
// socket directory after it takes the lock. stopDaemon reads that pid,
// sends SIGTERM only when ps shows the process as "<binPath> serve",
// so a stale pid record never sends a signal to another process, and
// waits up to daemonStopWait for the process to end. With no pid
// record, no daemon started: the shim ran the in-process server (on
// Windows always, G8), and stopDaemon does nothing.
//
// arch: DS11.15, DS11.20, IS11.9
func (ts *testServer) stopDaemon() {
	t := ts.t
	record, err := os.ReadFile(filepath.Join(ts.runtimeDir, "mailbag", "mailbag.lock"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(record)))
	if err != nil || !isTestDaemon(pid) {
		return
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		t.Errorf("find the daemon pid %d: %v", pid, err)
		return
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		t.Errorf("send SIGTERM to the daemon pid %d: %v", pid, err)
		return
	}
	deadline := time.Now().Add(daemonStopWait)
	for isTestDaemon(pid) {
		if time.Now().After(deadline) {
			t.Errorf("the daemon pid %d did not exit within %s of SIGTERM (G6)", pid, daemonStopWait)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// isTestDaemon reports whether pid is a live process "<binPath>
// serve". A process that ended but is not yet reaped (ps state Z) is
// not live.
func isTestDaemon(pid int) bool {
	out, err := exec.Command("ps", "-ww", "-o", "stat=,args=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: the test runs ps with a fixed command and an integer pid
	if err != nil {
		return false // no such process
	}
	stat, args, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	return !strings.HasPrefix(stat, "Z") && strings.TrimSpace(args) == binPath+" serve"
}

// exitWithin waits up to timeout for the process to exit and returns
// its exit code.
func (ts *testServer) exitWithin(t *testing.T, timeout time.Duration) int {
	t.Helper()
	select {
	case <-ts.waitDone:
	case <-time.After(timeout):
		t.Fatalf("process did not exit within %s", timeout)
	}
	if ts.waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(ts.waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("Wait: %v", ts.waitErr)
	return -1
}

// writeLine marshals v as one line of newline-delimited JSON to
// stdin (the framing [mcp.StdioTransport] and [mcp.CommandTransport]
// both use).
func (ts *testServer) writeLine(t *testing.T, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	data = append(data, '\n')
	if _, err := ts.stdin.Write(data); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
}

// nextLine returns the next stdout line, or fails the test if none
// arrives within timeout.
func (ts *testServer) nextLine(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case line, ok := <-ts.lines:
		if !ok {
			t.Fatalf("stdout closed before a reply arrived")
		}
		return line
	case <-time.After(timeout):
		t.Fatalf("no stdout line within %s", timeout)
	}
	return ""
}

// recordedLines returns every stdout line seen so far.
func (ts *testServer) recordedLines() []string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]string(nil), ts.allLines...)
}

// call sends a JSON-RPC request and returns its response, matched by
// id.
func (ts *testServer) call(t *testing.T, method string, params any) rpcResponse {
	t.Helper()
	id := atomic.AddInt64(&ts.nextID, 1)
	ts.writeLine(t, rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})

	line := ts.nextLine(t, 5*time.Second)
	var resp rpcResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", line, err)
	}
	if resp.ID != id {
		t.Fatalf("response id = %d, want %d (line %q)", resp.ID, id, line)
	}
	return resp
}

// notify sends a JSON-RPC notification (no id, no reply expected).
func (ts *testServer) notify(t *testing.T, method string, params any) {
	t.Helper()
	ts.writeLine(t, rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

// initResult is the part of [mcp.InitializeResult] the e2e tests
// check.
type initResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
	Instructions string `json:"instructions"`
}

// initialize sends "initialize" with the given protocol version,
// checks it did not error, sends "notifications/initialized" the way
// a real client does, and returns the parsed result.
func (ts *testServer) initialize(t *testing.T, protocolVersion string) initResult {
	t.Helper()
	resp := ts.call(t, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mailbag-mcp-e2e", "version": "test"},
	})
	if resp.Error != nil {
		t.Fatalf("initialize: %+v", resp.Error)
	}
	var res initResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal initialize result %s: %v", resp.Result, err)
	}
	ts.notify(t, "notifications/initialized", nil)
	return res
}

// TestE2E_LegacyInitialize sends "initialize" with protocol version
// 2025-06-18, the one an older client still sends (A11), and checks
// the reply's serverInfo and instructions.
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_LegacyInitialize(t *testing.T) {
	ts := startServer(t)
	res := ts.initialize(t, "2025-06-18")

	if res.ServerInfo.Name != "mailbag-mcp" {
		t.Errorf("serverInfo.name = %q, want %q", res.ServerInfo.Name, "mailbag-mcp")
	}
	if res.ServerInfo.Version == "" {
		t.Error("serverInfo.version is empty")
	}
	if !strings.Contains(res.Instructions, "UNTRUSTED INPUT") {
		t.Errorf("instructions text does not read like Appendix C: %q", res.Instructions)
	}
}

// TestE2E_InitializeUnder1s checks the reply to "initialize" arrives
// in under 1s from process start, because §3.1 step 3 forbids any
// network or keyring access before it (A9).
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_InitializeUnder1s(t *testing.T) {
	start := time.Now()
	ts := startServer(t)
	ts.initialize(t, "2025-06-18")

	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("initialize took %s from process start, want under 1s (A9)", elapsed)
	}
}

// TestE2E_ToolsListCore checks "tools/list" reports exactly the six
// core tools of D2.1, over the real transport of a real server
// process. The send and modify tools are toolsets that are off by
// default (D2.1, D2.2), so they are not on this list. A toolset that
// is off gives no tool name (I5): a write tool on this list by
// mistake is a safety failure, not only a size failure.
//
// The test names all six tools instead of counting them, so a
// missing tool and an extra one both show with the name that changed.
//
// arch: T1.6, §5.3, §5.1, §3.16, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2, D2.1, D2.2
func TestE2E_ToolsListCore(t *testing.T) {
	ts := startServer(t)
	ts.initialize(t, "2025-06-18")

	resp := ts.call(t, "tools/list", map[string]any{})
	if resp.Error != nil {
		t.Fatalf("tools/list: %+v", resp.Error)
	}

	var res struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal tools/list result %s: %v", resp.Result, err)
	}

	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	want := []string{"accounts", "folders", "search", "read", "attachment", "export"}
	for _, name := range want {
		if !got[name] {
			t.Errorf("tools/list has no %q tool: %v", name, res.Tools)
		}
		delete(got, name)
	}
	for name := range got {
		t.Errorf("tools/list has the extra tool %q; the default list holds the six core tools (D2.1, I5)", name)
	}
	if len(res.Tools) != len(want) {
		t.Errorf("tools/list has %d tools, want %d (D2.1)", len(res.Tools), len(want))
	}
}

// skipOnWindows skips a signal-based test on Windows, where the
// design does not ask for one (§5.1: "Signal tests skip on Windows").
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("signal tests skip on Windows (§5.1)")
	}
}

// testSurvivesSignal sends sig to a running server and checks it
// still answers "tools/list" afterwards (A2): SIGINT and SIGHUP must
// not stop serve mode.
func testSurvivesSignal(t *testing.T, sig syscall.Signal) {
	skipOnWindows(t)
	ts := startServer(t)
	ts.initialize(t, "2025-06-18")

	if err := ts.cmd.Process.Signal(sig); err != nil {
		t.Fatalf("send %s: %v", sig, err)
	}

	resp := ts.call(t, "tools/list", map[string]any{})
	if resp.Error != nil {
		t.Fatalf("tools/list after %s: %+v", sig, resp.Error)
	}
}

// TestE2E_SurvivesSIGINT: arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_SurvivesSIGINT(t *testing.T) { testSurvivesSignal(t, syscall.SIGINT) }

// TestE2E_SurvivesSIGHUP: arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_SurvivesSIGHUP(t *testing.T) { testSurvivesSignal(t, syscall.SIGHUP) }

// TestE2E_SIGTERMExits0 checks SIGTERM stops serve mode with exit
// code 0 inside 2s (A3).
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_SIGTERMExits0(t *testing.T) {
	skipOnWindows(t)
	ts := startServer(t)
	ts.initialize(t, "2025-06-18")

	if err := ts.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	if code := ts.exitWithin(t, 2*time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

// TestE2E_StdinEOFExits0 checks a closed stdin stops serve mode with
// exit code 0 inside 2s (A3), the other of the two normal ways to
// stop the server (§10.1).
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_StdinEOFExits0(t *testing.T) {
	ts := startServer(t)
	ts.initialize(t, "2025-06-18")

	if err := ts.stdin.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}
	if code := ts.exitWithin(t, 2*time.Second); code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
}

// TestE2E_ClosedStderrKeepsServing closes the read side of the
// server's stderr from the test's own end (simulating a client that
// stopped reading it), causes one log line by calling a tool, and
// checks the server still answers: a write error on stderr must be
// dropped, not fatal (A5).
//
// A normal run never writes to stderr after start (§3.19: the log
// goes to state-dir/server.log), so this test seeds the state dir
// with a directory named "server.log" before starting the server.
// That makes the real log file impossible to open, so every log line
// -- including "call-start"/"call-end" for the tool call below --
// falls back to stderr. Without that, closing stderr's read side
// would never be followed by a write on that fd, and the test would
// pass whether or not SIGPIPE is ignored, which is the failure this
// test exists to catch.
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_ClosedStderrKeepsServing(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(stateDir, "server.log"), 0o700); err != nil {
		t.Fatalf("seed state dir with a server.log directory: %v", err)
	}
	ts := startServerWithStateDir(t, stateDir)
	ts.initialize(t, "2025-06-18")

	if err := ts.stderr.Close(); err != nil {
		t.Fatalf("close stderr read side: %v", err)
	}

	resp := ts.call(t, "tools/call", map[string]any{"name": "accounts", "arguments": map[string]any{}})
	if resp.Error != nil {
		t.Fatalf("tools/call accounts after closing stderr: %+v", resp.Error)
	}

	resp = ts.call(t, "tools/list", map[string]any{})
	if resp.Error != nil {
		t.Fatalf("tools/list after closing stderr: %+v", resp.Error)
	}
}

// TestE2E_StdoutIsOnlyJSONRPC runs a short session (initialize,
// tools/list, one tool call) and checks every line the server wrote
// to stdout parses as JSON with "jsonrpc":"2.0" (A1). It is the
// runtime half of the guarantee TestNoStdoutWrites checks at the
// source level.
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_StdoutIsOnlyJSONRPC(t *testing.T) {
	ts := startServer(t)
	ts.initialize(t, "2025-06-18")
	ts.call(t, "tools/list", map[string]any{})
	ts.call(t, "tools/call", map[string]any{"name": "accounts", "arguments": map[string]any{}})

	for _, line := range ts.recordedLines() {
		var frame struct {
			JSONRPC string `json:"jsonrpc"`
		}
		if err := json.Unmarshal([]byte(line), &frame); err != nil {
			t.Errorf("stdout line is not valid JSON: %q (%v)", line, err)
			continue
		}
		if frame.JSONRPC != "2.0" {
			t.Errorf("stdout line has jsonrpc = %q, want \"2.0\": %q", frame.JSONRPC, line)
		}
	}
}

// TestE2E_ZeroAccounts checks that an empty config directory (no
// accounts.toml yet) still gives a working "accounts" tool, and that
// its result carries the add-account hint.
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2
func TestE2E_ZeroAccounts(t *testing.T) {
	ts := startServer(t)
	ts.initialize(t, "2025-06-18")

	resp := ts.call(t, "tools/call", map[string]any{"name": "accounts", "arguments": map[string]any{}})
	if resp.Error != nil {
		t.Fatalf("tools/call accounts: %+v", resp.Error)
	}
	if !strings.Contains(string(resp.Result), "mailbag-mcp account add") {
		t.Errorf("accounts result on an empty config has no add hint: %s", resp.Result)
	}
}

// TestE2E_ShimSecondSessionNoNewStart starts two shims with one config
// dir, one state dir and one short runtime dir, and runs initialize on
// both. The first shim starts the daemon (DS11.18 step 1). The second
// shim reaches the same daemon and starts nothing (DS11.18 step 2).
// Thus server.log has one "start" line, from the daemon pid in
// mailbag.lock, and the daemon logs one handshake OK for each shim. No
// shim logs a fallback line. A second "start" line shows an in-process
// server: for example after a CONFIG reply, when the two shims have
// different config dirs (IS11.5). The stdout of each shim carries
// JSON-RPC only (IS11.1). After the cleanup of both shims, the daemon
// of this test does not run (G6 in DS11.20).
//
// arch: DS11.15, DS11.18, IS11.1, IS11.9
func TestE2E_ShimSecondSessionNoNewStart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no daemon: the shim runs the in-process server (G8)")
	}
	runtimeDir := shortRuntimeDir(t)
	configDir, stateDir := t.TempDir(), t.TempDir()

	// t.Cleanup is last in, first out: this check runs after the
	// cleanup of both shims, which stops the daemon.
	var daemonPID int
	t.Cleanup(func() {
		if daemonPID != 0 && isTestDaemon(daemonPID) {
			t.Errorf("the daemon pid %d still runs after the cleanup of both shims (G6 in DS11.20)", daemonPID)
		}
	})

	first := startServerWithDirs(t, configDir, stateDir, runtimeDir)
	first.initialize(t, "2025-06-18")

	lockPath := filepath.Join(runtimeDir, "mailbag", "mailbag.lock")
	record, err := os.ReadFile(lockPath) //nolint:gosec // G304: the path is built from the test temp dir
	if err != nil {
		t.Fatalf("read the pid record of the daemon: %v", err)
	}
	daemonPID, err = strconv.Atoi(strings.TrimSpace(string(record)))
	if err != nil || !isTestDaemon(daemonPID) {
		t.Fatalf("%s holds %q, not the pid of a live %q", lockPath, record, binPath+" serve")
	}

	second := startServerWithDirs(t, configDir, stateDir, runtimeDir)
	second.initialize(t, "2025-06-18")

	logPath := filepath.Join(stateDir, "server.log")
	data, err := os.ReadFile(logPath) //nolint:gosec // G304: the path is built from the test temp dir
	if err != nil {
		t.Fatalf("read server.log: %v", err)
	}
	daemonField := "pid=" + strconv.Itoa(daemonPID)
	var starts, oks, fallbacks int
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		switch {
		case slices.Contains(f, "msg=start"):
			starts++
			if !slices.Contains(f, daemonField) {
				t.Errorf("a start line is not from the daemon pid %d: %s", daemonPID, line)
			}
		case slices.Contains(f, "msg=handshake") && slices.Contains(f, "result=OK"):
			oks++
			if !slices.Contains(f, daemonField) {
				t.Errorf("a handshake line is not from the daemon pid %d: %s", daemonPID, line)
			}
		case strings.Contains(line, `msg="shim fallback"`):
			fallbacks++
		}
	}
	if starts != 1 || oks != 2 || fallbacks != 0 {
		t.Errorf("server.log has %d start lines, %d handshake OK lines and %d shim fallback lines; want 1, 2 and 0 (DS11.18 step 2):\n%s",
			starts, oks, fallbacks, data)
	}

	for i, ts := range []*testServer{first, second} {
		for _, line := range ts.recordedLines() {
			var frame struct {
				JSONRPC string `json:"jsonrpc"`
			}
			if err := json.Unmarshal([]byte(line), &frame); err != nil || frame.JSONRPC != "2.0" {
				t.Errorf("shim %d wrote a stdout line that is not JSON-RPC 2.0: %q (IS11.1)", i+1, line)
			}
		}
	}
}
