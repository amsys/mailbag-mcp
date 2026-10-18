// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build linux || darwin

// Tests of daemon mode (DS11.4, DS11.6, DS11.7): the own listener and
// its lock, the peer uid check, the handshake, the build handover, the
// config mismatch and the idle exit. Each test sets XDG_RUNTIME_DIR,
// MAILBAG_CONFIG_DIR and MAILBAG_STATE_DIR to its own temp dirs, so no
// test dials or locks the live socket (IS11.9).

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The ids of the test daemon. A shim with these ids gets OK.
const (
	testBuildID  = "build-A"
	testConfigID = "config-A"
)

// socketTestEnv sets XDG_RUNTIME_DIR to a short temp dir, and the
// config and state dirs to temp dirs. It gives the socket dir. The
// test skips when the socket path has more than 100 bytes, near the
// sun_path limit.
func socketTestEnv(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "mbs-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	t.Setenv("XDG_RUNTIME_DIR", base)
	t.Setenv("MAILBAG_CONFIG_DIR", t.TempDir())
	t.Setenv("MAILBAG_STATE_DIR", t.TempDir())
	dir, err := socketDir()
	if err != nil {
		t.Fatalf("socketDir: %v", err)
	}
	if p := filepath.Join(dir, socketName); len(p) > 100 {
		t.Skipf("socket path has %d bytes, above the sun_path limit: %s", len(p), p)
	}
	return dir
}

// testDaemon is a daemon that runs in the test process on an own
// listener, with a tick channel that only the test sends on.
type testDaemon struct {
	d      *daemon
	svc    *Service
	log    *lockedBuf
	path   string
	tick   chan time.Time
	stop   context.CancelFunc // stands for SIGTERM
	done   chan struct{}      // closed when run returned
	reason string
	code   int
}

// startTestDaemon starts a daemon in dir with the ids testBuildID and
// testConfigID. setup can change the daemon and add tools to the
// Service before run starts. The cleanup stops the daemon and waits
// for run.
func startTestDaemon(t *testing.T, dir string, setup func(*daemon, *Service)) *testDaemon {
	t.Helper()
	svc, logBuf := newTestService(t)
	ln, err := ownListener(dir)
	if err != nil {
		t.Fatalf("ownListener: %v", err)
	}
	tick := make(chan time.Time)
	d := newDaemon(svc, svc.logger, ln, testBuildID, testConfigID, tick)
	if setup != nil {
		setup(d, svc)
	}
	ctx, cancel := context.WithCancel(context.Background())
	td := &testDaemon{
		d:    d,
		svc:  svc,
		log:  logBuf,
		path: filepath.Join(dir, socketName),
		tick: tick,
		stop: cancel,
		done: make(chan struct{}),
	}
	go func() {
		td.reason, td.code = d.run(ctx)
		close(td.done)
	}()
	t.Cleanup(func() {
		cancel()
		td.wait(t)
	})
	return td
}

// wait waits for run to return and gives its reason and exit code.
func (td *testDaemon) wait(t *testing.T) (string, int) {
	t.Helper()
	select {
	case <-td.done:
		return td.reason, td.code
	case <-time.After(15 * time.Second):
		t.Fatalf("the daemon did not stop")
		return "", 0
	}
}

// stopState reports whether the daemon began to stop, and the reason.
func (td *testDaemon) stopState() (bool, string) {
	td.d.mu.Lock()
	defer td.d.mu.Unlock()
	return td.d.stopping, td.d.reason
}

// tickNoExit sends two ticks. The second send ends only after the
// loop handled the first, so the idle check of the first tick is done
// when tickNoExit returns. The test fails when the daemon stops.
func (td *testDaemon) tickNoExit(t *testing.T, when string) {
	t.Helper()
	for range 2 {
		select {
		case td.tick <- time.Now():
		case <-td.done:
			t.Fatalf("%s: the daemon stopped (%s, code %d), want it to keep running", when, td.reason, td.code)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the daemon did not take the tick", when)
		}
	}
	if stopping, reason := td.stopState(); stopping {
		t.Fatalf("%s: the daemon began to stop (%s), want it to keep running", when, reason)
	}
}

// dialSocket connects to the socket at path. The cleanup closes the
// connection.
func dialSocket(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// sendHello writes the hello line of DS11.6 on conn and gives the
// reply line.
func sendHello(t *testing.T, conn *net.UnixConn, build, config string) string {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if _, err := fmt.Fprintf(conn, "MAILBAG 1 %s %s\n", build, config); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	line, err := readLine(conn, maxHandshakeLine)
	if err != nil {
		t.Fatalf("read the reply to the hello: %v", err)
	}
	return line
}

// dialHello dials the socket at path and sends the hello line.
func dialHello(t *testing.T, path, build, config string) (*net.UnixConn, string) {
	t.Helper()
	conn := dialSocket(t, path)
	return conn, sendHello(t, conn, build, config)
}

// connectMCP runs the MCP initialize on conn and gives the client
// session. The cleanup closes it.
func connectMCP(ctx context.Context, t *testing.T, conn *net.UnixConn) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	// The Writer half must not close conn a second time (R§2.5).
	cs, err := client.Connect(ctx, &mcp.IOTransport{Reader: conn, Writer: nopCloseWriter{conn}}, nil)
	if err != nil {
		t.Fatalf("MCP initialize over the socket: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// expectClosed reads from conn and fails the test unless the daemon
// closed the connection with no byte.
func expectClosed(t *testing.T, conn *net.UnixConn, what string) error {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf [64]byte
	n, err := conn.Read(buf[:])
	if n != 0 || err == nil {
		t.Fatalf("%s: read %d bytes %q (err %v), want the connection closed with no byte", what, n, buf[:n], err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("%s: the daemon did not close the connection", what)
	}
	return err
}

// expectGone fails the test when the file at path exists.
func expectGone(t *testing.T, path, what string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s: Lstat(%s) = %v, want the file gone", what, path, err)
	}
}

// fakeClock is a wall clock that moves only when the test sets it.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// TestSocket_HandshakeAndSession checks the normal path of a daemon on
// its own socket: the dir has mode 0700 and the socket 0600; a client
// of the same uid that sends the hello with the daemon's ids gets OK;
// MCP initialize and tools/list work on the same connection. SIGTERM
// (the end of the run ctx) stops the daemon with exit code 0, unlinks
// the socket and releases the lock, and no line is at ERROR.
//
// arch: DS11.4, DS11.6, DS11.7, DS11.19, IS11.3, IS11.5, IS11.6, IS11.7, IS11.9
func TestSocket_HandshakeAndSession(t *testing.T) {
	dir := socketTestEnv(t)
	td := startTestDaemon(t, dir, nil)

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("socket dir: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("socket dir mode = %v, want 0700", fi.Mode().Perm())
	}
	fi, err = os.Stat(td.path)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if fi.Mode().Type() != os.ModeSocket || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode = %v, want a socket with mode 0600", fi.Mode())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, reply := dialHello(t, td.path, testBuildID, testConfigID)
	if reply != replyOK {
		t.Fatalf("reply to a matching hello = %q, want %q", reply, replyOK)
	}
	cs := connectMCP(ctx, t, conn)
	if got := cs.InitializeResult().ServerInfo.Name; got != "mailbag-mcp" {
		t.Errorf("server name after initialize = %q, want mailbag-mcp", got)
	}
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list over the socket: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Errorf("tools/list over the socket gave no tools")
	}
	waitLive(t, td.svc, 1)

	if err := cs.Close(); err != nil {
		t.Fatalf("close the client: %v", err)
	}
	waitLive(t, td.svc, 0)

	td.stop()
	reason, code := td.wait(t)
	if reason != stopSigterm || code != 0 {
		t.Errorf("run = (%q, %d), want (%q, 0)", reason, code, stopSigterm)
	}
	expectGone(t, td.path, "after SIGTERM")
	again, err := ownListener(dir)
	if err != nil {
		t.Fatalf("ownListener after the daemon stopped: %v, want the lock free", err)
	}
	_ = again.Close()

	log := td.log.String()
	if !strings.Contains(log, "msg=handshake result=OK") {
		t.Errorf("log = %q, want a handshake line with result=OK", log)
	}
	if strings.Contains(log, "level=ERROR") {
		t.Errorf("log = %q, want no line at ERROR", log)
	}
}

// TestSocket_BuildMismatchDrains checks the build handover (DS11.7,
// G2). A session has a call in flight. A second client with another
// build id gets RESTART. At once the socket file is gone and the lock
// is free, so a new daemon can bind while the old one drains. A
// connection accepted before the handover gets RESTART for its hello
// too, also with the daemon's own ids. The daemon waits for the call
// in flight: the call ends with no cancel of its ctx, and only then
// does run return build-change with exit code 0 (IS11.7). The client
// does not get the reply of that call: go-sdk v1.7.0 refuses each
// write after ServerSession.Close (internal/jsonrpc2 write), so the
// test logs what the client got and does not check it.
//
// arch: DS11.4, DS11.6, DS11.7, DS11.19, IS11.3, IS11.5, IS11.6, IS11.7, IS11.9
func TestSocket_BuildMismatchDrains(t *testing.T) {
	dir := socketTestEnv(t)
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	accepted := make(chan struct{}, 8)
	td := startTestDaemon(t, dir, func(d *daemon, svc *Service) {
		mcp.AddTool(svc.srv, &mcp.Tool{Name: "block", Description: "waits until the test releases it"},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, struct{}, error) {
				close(started)
				select {
				case <-release:
				case <-time.After(20 * time.Second):
				}
				finished <- ctx.Err()
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "done"}}}, struct{}{}, nil
			})
		d.peerUID = func(c *net.UnixConn) (uint32, error) {
			accepted <- struct{}{}
			return peerUID(c)
		}
	})
	waitAccepted := func(what string) {
		t.Helper()
		select {
		case <-accepted:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the daemon did not accept the connection", what)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, reply := dialHello(t, td.path, testBuildID, testConfigID)
	waitAccepted("first client")
	if reply != replyOK {
		t.Fatalf("reply to the first client = %q, want %q", reply, replyOK)
	}
	cs := connectMCP(ctx, t, conn)
	callDone := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "block", Arguments: map[string]any{}})
		callDone <- err
	}()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not start")
	}

	late := dialSocket(t, td.path)
	waitAccepted("late client")

	_, reply = dialHello(t, td.path, "build-B", testConfigID)
	waitAccepted("client of the new build")
	if reply != replyRestart {
		t.Fatalf("reply to a client of another build = %q, want %q", reply, replyRestart)
	}

	expectGone(t, td.path, "right after RESTART")
	next, err := ownListener(dir)
	if err != nil {
		t.Fatalf("ownListener while the old daemon drains: %v, want the lock free at once", err)
	}
	if err := next.Close(); err != nil {
		t.Fatalf("close the new listener: %v", err)
	}

	if got := sendHello(t, late, testBuildID, testConfigID); got != replyRestart {
		t.Errorf("reply to a hello during the drain = %q, want %q", got, replyRestart)
	}

	select {
	case <-td.done:
		t.Fatalf("the daemon stopped (%s) while a call was in flight", td.reason)
	case <-time.After(200 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("the ctx of the call in flight ended (%v) before the call did: the handover cut the call", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call in flight did not finish")
	}
	reason, code := td.wait(t)
	if reason != stopBuildChange || code != 0 {
		t.Errorf("run = (%q, %d), want (%q, 0)", reason, code, stopBuildChange)
	}
	select {
	case err := <-callDone:
		t.Logf("the client's call returned: %v", err)
	case <-time.After(10 * time.Second):
		t.Error("the client's call did not return after the daemon stopped")
	}

	log := td.log.String()
	if !strings.Contains(log, "msg=stopping reason="+stopBuildChange) {
		t.Errorf("log = %q, want the stop with reason=%s", log, stopBuildChange)
	}
	if strings.Contains(log, "level=ERROR") {
		t.Errorf("log = %q, want no line at ERROR", log)
	}
}

// TestSocket_ConfigMismatchStays checks that a shim with another
// config pair gets CONFIG and the connection closes, and that the
// daemon stays: its socket is still there and the next shim with the
// matching ids gets OK and a working session. A shim with another
// build and another config also gets CONFIG, not RESTART, so a test
// binary never stops the live daemon (IS11.5, IS11.9).
//
// arch: DS11.4, DS11.6, DS11.7, DS11.19, IS11.3, IS11.5, IS11.6, IS11.7, IS11.9
func TestSocket_ConfigMismatchStays(t *testing.T) {
	dir := socketTestEnv(t)
	td := startTestDaemon(t, dir, nil)

	for _, c := range []struct{ name, build string }{
		{"same build, other config", testBuildID},
		{"other build, other config", "build-B"},
	} {
		conn, reply := dialHello(t, td.path, c.build, "config-B")
		if reply != replyConfig {
			t.Fatalf("%s: reply = %q, want %q", c.name, reply, replyConfig)
		}
		if err := expectClosed(t, conn, c.name); !errors.Is(err, io.EOF) {
			t.Errorf("%s: read after CONFIG = %v, want EOF", c.name, err)
		}
	}
	if stopping, reason := td.stopState(); stopping {
		t.Fatalf("the daemon began to stop (%s) after a config mismatch", reason)
	}
	if _, err := os.Stat(td.path); err != nil {
		t.Fatalf("socket after a config mismatch: %v, want it in place", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, reply := dialHello(t, td.path, testBuildID, testConfigID)
	if reply != replyOK {
		t.Fatalf("reply to the matching shim = %q, want %q", reply, replyOK)
	}
	cs := connectMCP(ctx, t, conn)
	if _, err := cs.ListTools(ctx, nil); err != nil {
		t.Fatalf("tools/list after a config mismatch: %v", err)
	}
	_ = cs.Close()

	td.stop()
	if reason, code := td.wait(t); reason != stopSigterm || code != 0 {
		t.Errorf("run = (%q, %d), want (%q, 0)", reason, code, stopSigterm)
	}
	if n := strings.Count(td.log.String(), "msg=handshake result=CONFIG"); n != 2 {
		t.Errorf("log has %d handshake lines with result=CONFIG, want 2", n)
	}
}

// TestSocket_PeerUIDRefused checks IS11.3: the injected peerUID gives
// the uid of this process plus one. The client writes its hello line
// before the check ends. The daemon closes the connection with no byte
// written and logs one WARN line with the peer uid. On Linux the read
// gives ECONNRESET, which the kernel gives only when the hello line
// was still unread at the close: the daemon read no byte.
//
// arch: DS11.4, DS11.6, DS11.7, DS11.19, IS11.3, IS11.5, IS11.6, IS11.7, IS11.9
func TestSocket_PeerUIDRefused(t *testing.T) {
	dir := socketTestEnv(t)
	written := make(chan struct{})
	other := uint32(os.Getuid()) + 1 //nolint:gosec // G115: a process uid is never negative and fits in 32 bits
	td := startTestDaemon(t, dir, func(d *daemon, _ *Service) {
		d.peerUID = func(*net.UnixConn) (uint32, error) {
			select {
			case <-written:
			case <-time.After(5 * time.Second):
			}
			return other, nil
		}
	})

	conn := dialSocket(t, td.path)
	if _, err := fmt.Fprintf(conn, "MAILBAG 1 %s %s\n", testBuildID, testConfigID); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	close(written)
	err := expectClosed(t, conn, "peer of another uid")
	if runtime.GOOS == "linux" && !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("read on Linux = %v, want ECONNRESET: the daemon must close with the hello line unread", err)
	}

	log := td.log.String()
	want := "level=WARN msg=\"peer refused\" peer_uid=" + strconv.FormatUint(uint64(other), 10)
	if strings.Count(log, want) != 1 {
		t.Errorf("log = %q, want one line %q", log, want)
	}
	if strings.Contains(log, "msg=handshake") {
		t.Errorf("log = %q, want no handshake for a refused peer", log)
	}
	if n, _ := td.svc.Live(); n != 0 {
		t.Errorf("Live() = %d sessions, want 0", n)
	}
}

// TestSocket_IdleExit checks the idle exit on an injected wall clock
// and injected ticks. While one session lives, a tick 30 min after the
// start does not stop the daemon. When the last session ended, a tick
// at 15 min less 1 s does not stop it; a tick at 15 min does: run
// returns idle with exit code 0 and the socket is gone.
//
// arch: DS11.4, DS11.6, DS11.7, DS11.19, IS11.3, IS11.5, IS11.6, IS11.7, IS11.9
func TestSocket_IdleExit(t *testing.T) {
	dir := socketTestEnv(t)
	clock := &fakeClock{t: time.Now().Round(0)}
	td := startTestDaemon(t, dir, func(d *daemon, _ *Service) { d.now = clock.Now })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, reply := dialHello(t, td.path, testBuildID, testConfigID)
	if reply != replyOK {
		t.Fatalf("reply = %q, want %q", reply, replyOK)
	}
	cs := connectMCP(ctx, t, conn)
	waitLive(t, td.svc, 1)

	clock.Set(clock.Now().Add(30 * time.Minute))
	td.tickNoExit(t, "one session lives, 30 min after the start")

	if err := cs.Close(); err != nil {
		t.Fatalf("close the client: %v", err)
	}
	waitLive(t, td.svc, 0)
	_, idleAt := td.svc.Live()

	clock.Set(idleAt.Add(idleExit - time.Second))
	td.tickNoExit(t, "no session, 1 s before the idle limit")

	clock.Set(idleAt.Add(idleExit))
	select {
	case td.tick <- time.Now():
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon did not take the tick at the idle limit")
	}
	reason, code := td.wait(t)
	if reason != stopIdle || code != 0 {
		t.Errorf("run = (%q, %d), want (%q, 0)", reason, code, stopIdle)
	}
	expectGone(t, td.path, "after the idle exit")
}

// TestSocket_LockRefusesSecondDaemon checks the lock of the socket
// dir (IS11.6). A second ownListener on the same dir gets the error
// "another mailbag-mcp serve owns <path>" and leaves the socket of the
// first in place; ServeSocket gives exit code 2 with that text in the
// log. The lock file holds the pid of the owner (G6 in DS11.20) until
// the owner closes. A stale socket file with no lock does not block a
// new start.
//
// arch: DS11.4, DS11.6, DS11.7, DS11.19, IS11.3, IS11.5, IS11.6, IS11.7, IS11.9
func TestSocket_LockRefusesSecondDaemon(t *testing.T) {
	dir := socketTestEnv(t)
	sockPath := filepath.Join(dir, socketName)
	lockPath := filepath.Join(dir, lockName)

	first, err := ownListener(dir)
	if err != nil {
		t.Fatalf("first ownListener: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if b, err := os.ReadFile(lockPath); err != nil || string(b) != strconv.Itoa(os.Getpid())+"\n" { //nolint:gosec // G304: test code; the path is built by the test
		t.Errorf("lock file = %q (%v), want the pid %d", b, err, os.Getpid())
	}

	second, err := ownListener(dir)
	if err == nil {
		_ = second.Close()
		t.Fatal("second ownListener on the same dir: no error, want the lock error")
	}
	var owned *ownedError
	if !errors.As(err, &owned) || err.Error() != "another mailbag-mcp serve owns "+sockPath {
		t.Fatalf("second ownListener: %v, want %q", err, "another mailbag-mcp serve owns "+sockPath)
	}
	_ = dialSocket(t, sockPath) // the socket of the first is still there and listens

	if code := ServeSocket("test"); code != 2 {
		t.Errorf("ServeSocket while another daemon owns the socket = %d, want 2", code)
	}
	logBytes, err := os.ReadFile(filepath.Join(os.Getenv("MAILBAG_STATE_DIR"), "server.log")) //nolint:gosec // G703: test code; the path is built by the test
	if err != nil || !strings.Contains(string(logBytes), "another mailbag-mcp serve owns "+sockPath) {
		t.Errorf("server.log = %q (%v), want the lock error", logBytes, err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close the first listener: %v", err)
	}
	expectGone(t, sockPath, "after the owner closed")
	if b, err := os.ReadFile(lockPath); err != nil || len(b) != 0 { //nolint:gosec // G304: test code; the path is built by the test
		t.Errorf("lock file after close = %q (%v), want it empty", b, err)
	}

	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatalf("make a stale socket: %v", err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close()
	if _, err := os.Lstat(sockPath); err != nil {
		t.Fatalf("stale socket: %v, want the file in place", err)
	}
	third, err := ownListener(dir)
	if err != nil {
		t.Fatalf("ownListener over a stale socket: %v, want it unlinked", err)
	}
	t.Cleanup(func() { _ = third.Close() })
	_ = dialSocket(t, sockPath)
}

// TestSocket_DirNeedsRuntimeDir checks that socketDir fails when
// XDG_RUNTIME_DIR is unset or relative, so the socket never goes to
// /tmp (owner rule 9), and that ServeSocket then gives exit code 2.
//
// arch: DS11.4, IS11.9
func TestSocket_DirNeedsRuntimeDir(t *testing.T) {
	t.Setenv("MAILBAG_CONFIG_DIR", t.TempDir())
	t.Setenv("MAILBAG_STATE_DIR", t.TempDir())
	for _, v := range []string{"", "run/user/1"} {
		t.Setenv("XDG_RUNTIME_DIR", v)
		if dir, err := socketDir(); err == nil || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR") {
			t.Errorf("socketDir with XDG_RUNTIME_DIR=%q = (%q, %v), want an error that names the variable", v, dir, err)
		}
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	if code := ServeSocket("test"); code != 2 {
		t.Errorf("ServeSocket with no XDG_RUNTIME_DIR = %d, want 2", code)
	}
}
