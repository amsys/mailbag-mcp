// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build !windows

// Tests of the shim (DS11.8): the copy loop, the spawn lock, the
// fallback paths, the spawn path after RESTART and the start of
// "serve". Each test runs a fake daemon on a Unix socket in its own
// short temp dir, so no test dials the live socket (IS11.9).

package shim

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The ids that the tests send in the hello line.
const (
	testBuildID  = "build-T"
	testConfigID = "config-T"
	testSockName = "mailbag.sock"
	testHello    = "MAILBAG 1 " + testBuildID + " " + testConfigID
)

// shortDir gives a new short temp dir for the socket and spawn.lock.
// The test skips when the socket path has more than 100 bytes, near
// the sun_path limit (DS11.15).
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mbshim-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if p := filepath.Join(dir, testSockName); len(p) > 100 {
		t.Skipf("socket path has %d bytes, above the sun_path limit: %s", len(p), p)
	}
	return dir
}

// lockedBuf is a bytes.Buffer that the shim goroutines and the test
// can use at the same time.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// fakeDaemon answers each hello line with reply. After OK it echoes
// the bytes that it reads until EOF, then closes the connection.
// Before a RESTART reply it closes its listener, as the daemon does
// (DS11.7).
type fakeDaemon struct {
	reply string
	ln    net.Listener
	wg    sync.WaitGroup

	mu     sync.Mutex
	hellos []string
	got    bytes.Buffer // the bytes after the hello line, of all connections
	ends   []error      // why the echo of each OK connection ended
}

// startFake listens on path and serves each connection in its own
// goroutine. The cleanup closes the listener and waits for the
// connections.
func startFake(t *testing.T, path, reply string) *fakeDaemon {
	t.Helper()
	f, err := listenFake(path, reply)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	t.Cleanup(f.stop)
	return f
}

// listenFake is startFake without the test, for a Spawn function.
func listenFake(path, reply string) (*fakeDaemon, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	f := &fakeDaemon{reply: reply, ln: ln}
	f.wg.Add(1)
	go f.accept()
	return f, nil
}

func (f *fakeDaemon) stop() {
	_ = f.ln.Close()
	f.wg.Wait()
}

func (f *fakeDaemon) accept() {
	defer f.wg.Done()
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.serve(conn)
		}()
	}
}

func (f *fakeDaemon) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := readLine(conn, 512)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.hellos = append(f.hellos, line)
	f.mu.Unlock()
	if f.reply == replyRestart {
		_ = f.ln.Close()
	}
	if _, err := io.WriteString(conn, f.reply+"\n"); err != nil || f.reply != replyOK {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			f.mu.Lock()
			f.got.Write(buf[:n])
			f.mu.Unlock()
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			// io.EOF: the shim closed its write side. A timeout
			// means that the shim never did.
			f.mu.Lock()
			f.ends = append(f.ends, err)
			f.mu.Unlock()
			return
		}
	}
}

// echoEnds gives why the echo of each OK connection ended.
func (f *fakeDaemon) echoEnds() []error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]error(nil), f.ends...)
}

// helloLines gives the hello lines that the fake read.
func (f *fakeDaemon) helloLines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hellos...)
}

// received gives the bytes that the fake read after the hello lines.
func (f *fakeDaemon) received() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got.String()
}

// unixDial dials the Unix socket at path.
func unixDial(path string) func(context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
}

// fallbackProbe is a Fallback that records each call. At the call it
// records how many bytes Out held and reads all of In, so that a test
// can prove that the shim wrote nothing and read nothing before it.
type fallbackProbe struct {
	in    io.Reader
	out   *lockedBuf
	calls atomic.Int32

	mu       sync.Mutex
	outAtRun string
	inAtRun  string
}

func (p *fallbackProbe) run() int {
	p.calls.Add(1)
	got, _ := io.ReadAll(p.in)
	p.mu.Lock()
	p.outAtRun = p.out.String()
	p.inAtRun = string(got)
	p.mu.Unlock()
	return 0
}

// testOptions gives Options for one shim on the socket in dir. Spawn
// fails and Fallback fails the test unless the test replaces them.
func testOptions(t *testing.T, dir string, in io.Reader, out, logBuf *lockedBuf) Options {
	return Options{
		Version:  "mailbag-mcp test",
		BuildID:  testBuildID,
		ConfigID: testConfigID,
		In:       io.NopCloser(in),
		Out:      out,
		Logger:   slog.New(slog.NewTextHandler(logBuf, nil)),
		Dial:     unixDial(filepath.Join(dir, testSockName)),
		Spawn: func(context.Context) error {
			t.Error("Spawn called")
			return errors.New("no spawn in this test")
		},
		Fallback: func() int {
			t.Error("Fallback called")
			return 0
		},
		Ppid:    func() int { return 1 }, // a fixed parent: the watchdog never fires
		LockDir: dir,
	}
}

// runShim runs Run and gives its exit code. When Run does not return
// within 15 s, it marks the test failed and gives -1. It does not stop
// the test, so a test can call it from another goroutine.
func runShim(t *testing.T, o Options) int {
	t.Helper()
	done := make(chan int, 1)
	go func() { done <- Run(context.Background(), o) }()
	select {
	case code := <-done:
		return code
	case <-time.After(15 * time.Second):
		t.Error("Run did not return within 15 s")
		return -1
	}
}

// fallbackLines gives the "shim fallback" lines of the log.
func fallbackLines(log string) []string {
	var lines []string
	for _, l := range strings.Split(log, "\n") {
		if strings.Contains(l, `msg="shim fallback"`) {
			lines = append(lines, l)
		}
	}
	return lines
}

// payload gives n bytes of JSON-RPC-like lines that name tag.
func payload(tag string, n int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","id":%d,"method":"%s"}`+"\n", i, tag)
	}
	return b.String()
}

// TestShim_CopiesBytes runs the shim against a fake daemon that
// replies OK and echoes. The bytes of In reach the daemon unchanged,
// the bytes of the daemon reach Out unchanged, Out holds no other byte
// (no handshake line), and the EOF of In ends Run with exit code 0.
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, IS11.1, IS11.5, IS11.6
func TestShim_CopiesBytes(t *testing.T) {
	dir := shortDir(t)
	fake := startFake(t, filepath.Join(dir, testSockName), replyOK)
	data := payload("copy", 256<<10)

	var out, logBuf lockedBuf
	o := testOptions(t, dir, strings.NewReader(data), &out, &logBuf)

	if code := runShim(t, o); code != 0 {
		t.Fatalf("Run = %d, want 0", code)
	}
	if got := fake.helloLines(); len(got) != 1 || got[0] != testHello {
		t.Errorf("hello lines = %q, want [%q]", got, testHello)
	}
	if got := fake.received(); got != data {
		t.Errorf("daemon got %d bytes, want the %d bytes of In", len(got), len(data))
	}
	if ends := fake.echoEnds(); len(ends) != 1 || !errors.Is(ends[0], io.EOF) {
		t.Errorf("daemon read ends = %v, want [EOF]: the EOF of In must reach the daemon", ends)
	}
	if got := out.String(); got != data {
		t.Errorf("Out has %d bytes, want only the %d echoed bytes; start %q", len(got), len(data), head(got))
	}
	if lines := fallbackLines(logBuf.String()); len(lines) != 0 {
		t.Errorf("fallback lines = %q, want none", lines)
	}
}

// head gives the first 40 bytes of s.
func head(s string) string {
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

// TestShim_SpawnsOnce starts two shims at the same time with no
// daemon. The first dial of each shim fails, and then waits until the
// first dial of the other shim failed too, so both shims take the
// spawn path. The first Spawn call waits before it listens: until a
// second Spawn call comes, or for spawnHold. With the spawn lock, the
// second shim waits for the lock in that time, then dials under the
// lock and finds the daemon. With no lock, or with no dial under the
// lock, the second shim calls Spawn too. Spawn is called once, and
// both sessions copy their own bytes.
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, IS11.1, IS11.5, IS11.6
func TestShim_SpawnsOnce(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, testSockName)

	// The first dial of each shim dials, then waits until the first
	// dial of the other shim returned too. No shim can spawn while a
	// first dial waits, so both first dials fail.
	var dials atomic.Int32
	bothFailed := make(chan struct{})
	dial := func(ctx context.Context) (net.Conn, error) {
		n := dials.Add(1)
		conn, err := unixDial(sock)(ctx)
		switch n {
		case 1:
			select {
			case <-bothFailed:
			case <-time.After(5 * time.Second):
				t.Error("the second shim did not dial within 5 s")
			}
		case 2:
			close(bothFailed)
		}
		return conn, err
	}

	// spawnHold is the wait of the first Spawn call when no second
	// Spawn call comes. The second shim waits for the lock for
	// spawnWait, so it gets the lock after the hold.
	const spawnHold = spawnWait / 2
	var spawns atomic.Int32
	secondSpawn := make(chan struct{})
	var mu sync.Mutex
	var fakes []*fakeDaemon
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fakes {
			f.stop()
		}
	})
	spawnFake := func(context.Context) error {
		switch spawns.Add(1) {
		case 1:
			select {
			case <-secondSpawn:
			case <-time.After(spawnHold):
			}
		case 2:
			close(secondSpawn)
		}
		f, err := listenFake(sock, replyOK)
		if err != nil {
			return err
		}
		mu.Lock()
		fakes = append(fakes, f)
		mu.Unlock()
		return nil
	}

	type shim struct {
		data      string
		out, logs lockedBuf
		code      int
	}
	shims := []*shim{{data: payload("first", 32<<10)}, {data: payload("second", 32<<10)}}
	var wg sync.WaitGroup
	for _, s := range shims {
		o := testOptions(t, dir, strings.NewReader(s.data), &s.out, &s.logs)
		o.Dial = dial
		o.Spawn = spawnFake
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.code = runShim(t, o)
		}()
	}
	wg.Wait()

	if n := spawns.Load(); n != 1 {
		t.Errorf("Spawn called %d times, want 1", n)
	}
	for i, s := range shims {
		if s.code != 0 {
			t.Errorf("shim %d: Run = %d, want 0", i, s.code)
		}
		if got := s.out.String(); got != s.data {
			t.Errorf("shim %d: Out has %d bytes, want its own %d bytes", i, len(got), len(s.data))
		}
		if lines := fallbackLines(s.logs.String()); len(lines) != 0 {
			t.Errorf("shim %d: fallback lines = %q, want none", i, lines)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(fakes) == 1 {
		if got := fakes[0].helloLines(); len(got) != 2 {
			t.Errorf("the daemon got %d hello lines, want 2", len(got))
		}
	}
	if _, err := os.Stat(filepath.Join(dir, spawnLockName)); err != nil {
		t.Errorf("spawn.lock: %v", err)
	}
}

// TestShim_FallbackOnConfig runs the shim against a daemon of another
// config pair, which replies CONFIG. The shim runs Fallback once, with
// no spawn, after one INFO line with reason=config. At the call, Out
// is empty and In still holds all its bytes; after it, Out is still
// empty.
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, IS11.1, IS11.5, IS11.6
func TestShim_FallbackOnConfig(t *testing.T) {
	dir := shortDir(t)
	fake := startFake(t, filepath.Join(dir, testSockName), replyConfig)
	data := payload("config", 4<<10)

	var out, logBuf lockedBuf
	in := strings.NewReader(data)
	o := testOptions(t, dir, in, &out, &logBuf)
	probe := &fallbackProbe{in: in, out: &out}
	o.Fallback = probe.run

	if code := runShim(t, o); code != 0 {
		t.Fatalf("Run = %d, want 0", code)
	}
	checkFallback(t, probe, &out, data)
	checkFallbackLine(t, logBuf.String(), reasonConfig)
	if got := fake.helloLines(); len(got) != 1 || got[0] != testHello {
		t.Errorf("hello lines = %q, want [%q]", got, testHello)
	}
	if got := fake.received(); got != "" {
		t.Errorf("daemon got %q after the hello line, want nothing", head(got))
	}
}

// TestShim_FallbackOnBadReply runs the shim against a daemon that
// replies with a word that is not in DS11.6. The shim runs Fallback
// once, with no spawn, after one INFO line with reason=handshake.
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, IS11.1, IS11.5, IS11.6
func TestShim_FallbackOnBadReply(t *testing.T) {
	dir := shortDir(t)
	startFake(t, filepath.Join(dir, testSockName), "HELLO")
	data := payload("bad", 1<<10)

	var out, logBuf lockedBuf
	in := strings.NewReader(data)
	o := testOptions(t, dir, in, &out, &logBuf)
	probe := &fallbackProbe{in: in, out: &out}
	o.Fallback = probe.run

	if code := runShim(t, o); code != 0 {
		t.Fatalf("Run = %d, want 0", code)
	}
	checkFallback(t, probe, &out, data)
	checkFallbackLine(t, logBuf.String(), reasonHandshake)
}

// TestShim_FallbackNoSocket runs the shim with no daemon. When Spawn
// starts nothing, the shim dials for spawnWait and falls back with
// reason=no-socket; when Spawn fails, with reason=spawn-failed. With
// no Dial (the Windows entry), Run calls Fallback at once and writes
// no log line. In each case Fallback runs once, Out is empty and In
// holds all its bytes.
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, IS11.1, IS11.5, IS11.6
func TestShim_FallbackNoSocket(t *testing.T) {
	cases := []struct {
		name     string
		spawnErr error
		noDial   bool
		reason   string // "" means no fallback line
		spawns   int32
	}{
		{name: "no-socket", reason: reasonNoSocket, spawns: 1},
		{name: "spawn-failed", spawnErr: errors.New("exec format error"), reason: reasonSpawnFailed, spawns: 1},
		{name: "nil-dial", noDial: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := shortDir(t)
			data := payload(c.name, 1<<10)

			var out, logBuf lockedBuf
			in := strings.NewReader(data)
			o := testOptions(t, dir, in, &out, &logBuf)
			probe := &fallbackProbe{in: in, out: &out}
			o.Fallback = probe.run
			var spawns atomic.Int32
			o.Spawn = func(context.Context) error {
				spawns.Add(1)
				return c.spawnErr
			}
			if c.noDial {
				o.Dial = nil
			}

			start := time.Now()
			if code := runShim(t, o); code != 0 {
				t.Fatalf("Run = %d, want 0", code)
			}
			took := time.Since(start)

			checkFallback(t, probe, &out, data)
			if n := spawns.Load(); n != c.spawns {
				t.Errorf("Spawn called %d times, want %d", n, c.spawns)
			}
			if c.reason == "" {
				if log := logBuf.String(); log != "" {
					t.Errorf("log = %q, want no line", log)
				}
				return
			}
			checkFallbackLine(t, logBuf.String(), c.reason)
			if c.reason == reasonNoSocket && took < spawnWait {
				t.Errorf("Run fell back after %s, want the dial retries of spawnWait (%s) first", took, spawnWait)
			}
			if c.spawnErr != nil && !strings.Contains(logBuf.String(), c.spawnErr.Error()) {
				t.Errorf("log = %q, want the Spawn error %q", logBuf.String(), c.spawnErr)
			}
		})
	}
}

// TestShim_RestartTakesSpawnPath runs the shim against a daemon of
// another build. That daemon closes its listener and replies RESTART;
// the shim spawns a new daemon, gets OK from it and copies the bytes
// (DS11.18 sequence 4).
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, IS11.1, IS11.5, IS11.6
func TestShim_RestartTakesSpawnPath(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, testSockName)
	old := startFake(t, sock, replyRestart)
	data := payload("restart", 8<<10)

	var out, logBuf lockedBuf
	o := testOptions(t, dir, strings.NewReader(data), &out, &logBuf)
	var spawns atomic.Int32
	var fresh *fakeDaemon
	o.Spawn = func(context.Context) error {
		spawns.Add(1)
		f, err := listenFake(sock, replyOK)
		fresh = f
		return err
	}
	t.Cleanup(func() {
		if fresh != nil {
			fresh.stop()
		}
	})

	if code := runShim(t, o); code != 0 {
		t.Fatalf("Run = %d, want 0", code)
	}
	if n := spawns.Load(); n != 1 {
		t.Errorf("Spawn called %d times, want 1", n)
	}
	if got := old.helloLines(); len(got) != 1 {
		t.Errorf("old daemon got %d hello lines, want 1", len(got))
	}
	if fresh == nil {
		t.Fatal("no new daemon")
	}
	if got := fresh.helloLines(); len(got) != 1 || got[0] != testHello {
		t.Errorf("new daemon hello lines = %q, want [%q]", got, testHello)
	}
	if got := out.String(); got != data {
		t.Errorf("Out has %d bytes, want the %d echoed bytes", len(got), len(data))
	}
	if lines := fallbackLines(logBuf.String()); len(lines) != 0 {
		t.Errorf("fallback lines = %q, want none", lines)
	}
}

// TestShim_DebugRunsInProcess checks that MAILBAG_DEBUG=1 makes the
// shim run the in-process server, also when a daemon replies OK. The
// daemon has no stderr, so its wire debug never reaches the client;
// the in-process server writes it to the stderr of the client. The
// shim sends no hello line, and Fallback gets the stdio untouched.
//
// arch: DS11.8, §3.10, IS11.1, R16-L22
func TestShim_DebugRunsInProcess(t *testing.T) {
	t.Setenv("MAILBAG_DEBUG", "1")
	dir := shortDir(t)
	fake := startFake(t, filepath.Join(dir, testSockName), replyOK)
	data := payload("debug", 1<<10)

	var out, logBuf lockedBuf
	in := strings.NewReader(data)
	o := testOptions(t, dir, in, &out, &logBuf)
	probe := &fallbackProbe{in: in, out: &out}
	o.Fallback = probe.run

	if code := runShim(t, o); code != 0 {
		t.Fatalf("Run = %d, want 0", code)
	}
	checkFallback(t, probe, &out, data)
	if got := fake.helloLines(); len(got) != 0 {
		t.Errorf("daemon hello lines = %q, want none", got)
	}
}

// checkFallback checks that Fallback ran once, that Out was empty at
// the call and is empty after it, and that In held all of data at the
// call.
func checkFallback(t *testing.T, p *fallbackProbe, out *lockedBuf, data string) {
	t.Helper()
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("Fallback called %d times, want 1", n)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.outAtRun != "" {
		t.Errorf("Out held %q before Fallback, want nothing", head(p.outAtRun))
	}
	if p.inAtRun != data {
		t.Errorf("Fallback read %d bytes of In, want all %d", len(p.inAtRun), len(data))
	}
	if got := out.String(); got != "" {
		t.Errorf("Out = %q after Fallback, want nothing", head(got))
	}
}

// checkFallbackLine checks that the log has one INFO "shim fallback"
// line, with reason.
func checkFallbackLine(t *testing.T, log, reason string) {
	t.Helper()
	lines := fallbackLines(log)
	if len(lines) != 1 {
		t.Fatalf("fallback lines = %q, want 1", lines)
	}
	if !strings.Contains(lines[0], "level=INFO") || !strings.Contains(lines[0], "reason="+reason) {
		t.Errorf("fallback line = %q, want level=INFO and reason=%s", lines[0], reason)
	}
}

// TestShim_SpawnStartsServeDetached runs spawn with a shell script as
// the executable. The script gets the argument "serve" and the
// environment of the shim, and leads its own process group (Setsid).
// With an ended ctx, spawn starts nothing.
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, IS11.1, IS11.5, IS11.6
func TestShim_SpawnStartsServeDetached(t *testing.T) {
	if _, err := exec.LookPath("ps"); err != nil {
		t.Skip("ps is not in PATH")
	}
	dir := t.TempDir()
	report := filepath.Join(dir, "child.txt")
	script := filepath.Join(dir, "fake-mailbag")
	body := "#!/bin/sh\n" +
		`printf '%s|%s|%s|%s\n' "$*" "$SHIM_TEST_MARK" "$$" "$(ps -o pgid= -p $$ | tr -d ' ')" > "$SHIM_TEST_REPORT.tmp"` + "\n" +
		`mv "$SHIM_TEST_REPORT.tmp" "$SHIM_TEST_REPORT"` + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // G306: the fake child must be executable
		t.Fatalf("write script: %v", err)
	}
	t.Setenv("SHIM_TEST_MARK", "inherited")
	t.Setenv("SHIM_TEST_REPORT", report)

	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := spawn(ended, script); err == nil {
		t.Error("spawn with an ended ctx = nil, want an error")
	}

	if err := spawn(context.Background(), script); err != nil {
		t.Fatalf("spawn: %v", err)
	}
	var got []byte
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, err := os.ReadFile(report) //nolint:gosec // G304: path built by the test in its temp dir
		if err == nil {
			got = b
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the child wrote no report within 10 s: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	f := strings.Split(strings.TrimSpace(string(got)), "|")
	if len(f) != 4 {
		t.Fatalf("report = %q, want 4 fields", got)
	}
	if f[0] != "serve" {
		t.Errorf("arguments = %q, want \"serve\"", f[0])
	}
	if f[1] != "inherited" {
		t.Errorf("SHIM_TEST_MARK = %q, want the inherited value", f[1])
	}
	if f[2] != f[3] {
		t.Errorf("child pid %s, process group %s: want a group of its own (Setsid)", f[2], f[3])
	}
	if own := strconv.Itoa(syscall.Getpgrp()); f[3] == own {
		t.Errorf("child process group = %s, the group of the test; want another", f[3])
	}
}
