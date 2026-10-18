// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build !windows

// Daemon mode (DS11.4): one Service, and one MCP session for each
// connection on a Unix socket. This file holds the own listener under
// a flock, the peer uid check, the handshake (DS11.6), the build
// handover (DS11.7), the idle exit and SIGTERM. The socket directory
// and the socket name are in server.go, because main.go names them on
// every OS.
// Windows has no flock and no daemon; socket_windows.go gives the
// text of G8 there.

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The names and the time limits of DS11.4.
const (
	socketName     = SocketName
	lockName       = "mailbag.lock"
	idleExit       = 15 * time.Minute
	idleTick       = time.Minute
	handshakeLimit = 2 * time.Second

	// maxHandshakeLine is the longest first line that the daemon
	// reads. A real line has about 120 bytes: the build id of DS11.5
	// and a config id of 16 hex digits.
	maxHandshakeLine = 512
)

// drainLimit is the time that the calls in flight get to finish
// after a build change or SIGTERM. It is the longest call that waits
// for a human: confirmWaitLimit in internal/tools (10 min). The
// systemd unit sets TimeoutStopSec to this value plus 20 s (DS11.11).
var drainLimit = 10 * time.Minute

// The lines of the handshake (DS11.6). The shim sends
// "MAILBAG 1 <buildid> <configid>"; the daemon replies with one of
// the three words. Each line ends with "\n".
const (
	helloWord     = "MAILBAG"
	helloProtocol = "1"
	replyOK       = "OK"
	replyRestart  = "RESTART"
	replyConfig   = "CONFIG"
)

// The reasons of a daemon end in the "shutdown" log line.
const (
	stopSigterm     = "sigterm"
	stopIdle        = "idle"
	stopBuildChange = "build-change"
	stopAcceptError = "accept-error"
)

// ServeSocket runs the daemon: one Service, one session for each
// connection on the Unix socket of DS11.4. It returns the exit code:
// 0 on SIGTERM, idle exit and build handover; 1 when the Service does
// not start or the listener fails; 2 when the socket cannot be set up,
// for example when another daemon owns it. It never calls os.Exit.
//
// The listener is the one that systemd passed (DS11.10), else an own
// listener in socketDir. ServeSocket opens the log and closes it after
// Service.Close (G8 in DS11.20). SIGINT and SIGHUP are ignored, as in
// every server mode.
//
// arch: DS11.4, DS11.6, DS11.7, DS11.10, DS11.20
func ServeSocket(version string) int {
	IgnoreForServe()

	ctx, cancel, _ := TermContext(context.Background())
	defer cancel()

	logger, closeLog, logErr := setupLog()
	if closeLog != nil {
		defer func() { _ = closeLog.Close() }()
	}
	if logErr != nil {
		// §3.19: a log failure never stops the server.
		logger.Error("log open failed, writing to stderr instead", "error", logErr.Error())
	}

	ln, err := daemonListener(logger)
	if err != nil {
		logger.Error("socket setup failed", "error", err.Error())
		fmt.Fprintf(os.Stderr, "mailbag-mcp: %s\n", err)
		logger.Info("exit", "code", 2)
		return 2
	}
	configID, err := ConfigID()
	if err != nil {
		_ = ln.Close()
		return startFailed(logger, err)
	}
	svc, err := NewService(ctx, version, logger)
	if err != nil {
		_ = ln.Close()
		return startFailed(logger, err)
	}

	ticker := time.NewTicker(idleTick)
	defer ticker.Stop()
	d := newDaemon(svc, logger, ln, BuildID(), configID, ticker.C)
	reason, code := d.run(ctx)

	logger.Info("shutdown", "reason", reason)
	svc.Close()
	logger.Info("exit", "code", code)
	return code
}

// acceptor is the listener of the daemon: a *net.UnixListener from
// socket activation, or an *ownedListener.
type acceptor interface {
	AcceptUnix() (*net.UnixConn, error)
	Close() error
}

// daemonListener gives the listener that systemd passed as fd 3, else
// an own listener in socketDir (DS11.4 steps 1 and 2).
func daemonListener(logger *slog.Logger) (acceptor, error) {
	activated, err := activationListener(os.Getenv, os.Unsetenv, os.NewFile)
	if err != nil {
		return nil, err
	}
	if activated != nil {
		logger.Info("listen", "activated", true)
		return activated, nil
	}
	dir, err := socketDir()
	if err != nil {
		return nil, err
	}
	own, err := ownListener(dir)
	if err != nil {
		return nil, err
	}
	logger.Info("listen", "socket", filepath.Join(dir, socketName))
	return own, nil
}

// ownedError is the error of ownListener when another process holds
// the lock of the socket directory.
type ownedError struct{ path string }

// Error gives the text of DS11.4.
func (e *ownedError) Error() string { return "another mailbag-mcp serve owns " + e.path }

// ownedListener is the listener of a daemon that made its own socket.
// It holds the flock on lockName as long as the listener is open.
type ownedListener struct {
	*net.UnixListener
	lock *os.File
	once sync.Once
	err  error
}

// Close closes the listener, which unlinks the socket file. Then it
// clears the pid record and closes the lock file, which releases the
// flock. The unlink comes first, so this daemon never removes the
// socket of a new daemon that takes the lock after it. A second call
// gives the result of the first.
//
// arch: DS11.4, DS11.7, DS11.20
func (l *ownedListener) Close() error {
	l.once.Do(func() {
		l.err = errors.Join(l.UnixListener.Close(), l.lock.Truncate(0), l.lock.Close())
	})
	return l.err
}

// ownListener makes the socket of the daemon in dir. In order: make
// dir with mode 0700 and refuse it when it is not a directory of this
// uid; take flock(LOCK_EX|LOCK_NB) on lockName, else give an
// *ownedError; write the pid of this process into the lock file (G6
// in DS11.20); unlink a stale socket; listen; set mode 0600 on the
// socket; unlink the socket on close.
//
// arch: DS11.4, DS11.7, DS11.19, DS11.20, IS11.6
func ownListener(dir string) (*ownedListener, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("server: socket dir: %w", err)
	}
	if err := checkOwnDir(dir); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: this is a directory, and 0700 is the owner-only mode it needs (it needs the x bit)
		return nil, fmt.Errorf("server: socket dir: %w", err)
	}

	sockPath := filepath.Join(dir, socketName)
	lock, err := os.OpenFile(filepath.Join(dir, lockName), os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the path is the checked own socket dir plus a fixed lock file name
	if err != nil {
		return nil, fmt.Errorf("server: lock file: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, &ownedError{path: sockPath}
		}
		return nil, fmt.Errorf("server: lock %s: %w", lock.Name(), err)
	}

	ln, err := listenLocked(lock, sockPath)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return &ownedListener{UnixListener: ln, lock: lock}, nil
}

// checkOwnDir refuses dir when it is a symlink, not a directory, or a
// directory of another uid.
func checkOwnDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("server: socket dir: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("server: socket dir %s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("server: socket dir %s: owner unknown", dir)
	}
	if uid := os.Getuid(); st.Uid != uint32(uid) { //nolint:gosec // G115: a process uid is never negative and fits in 32 bits
		return fmt.Errorf("server: socket dir %s is owned by uid %d, not by uid %d", dir, st.Uid, uid)
	}
	return nil
}

// listenLocked does the steps of ownListener that need the lock: the
// pid record, the stale socket, the listener and its mode.
func listenLocked(lock *os.File, sockPath string) (*net.UnixListener, error) {
	if err := lock.Truncate(0); err != nil {
		return nil, fmt.Errorf("server: lock file: %w", err)
	}
	if _, err := lock.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		return nil, fmt.Errorf("server: lock file: %w", err)
	}
	if err := os.Remove(sockPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("server: stale socket: %w", err)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("server: listen: %w", err)
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("server: socket mode: %w", err)
	}
	return ln, nil
}

// daemon is the accept loop and the stop rules of one ServeSocket.
// The fields above mu are fixed before run starts. peerUID, now and
// tick are the test seams (DS11.12, DS11.15).
type daemon struct {
	svc      *Service
	logger   *slog.Logger
	ln       acceptor
	buildID  string
	configID string
	uid      uint32
	peerUID  func(*net.UnixConn) (uint32, error)
	now      func() time.Time // wall time only
	tick     <-chan time.Time // the idle check runs on each tick
	stopped  chan struct{}    // closed when the daemon starts to stop
	conns    sync.WaitGroup   // one for each accepted connection

	mu       sync.Mutex
	stopping bool
	reason   string
	active   int // connections that got OK and whose Session has not returned
}

// newDaemon gives a daemon that serves svc on ln. The handshake
// compares the ids of the shim with buildID and configID.
func newDaemon(svc *Service, logger *slog.Logger, ln acceptor, buildID, configID string, tick <-chan time.Time) *daemon {
	return &daemon{
		svc:      svc,
		logger:   logger,
		ln:       ln,
		buildID:  buildID,
		configID: configID,
		uid:      uint32(os.Getuid()), //nolint:gosec // G115: a process uid is never negative and fits in 32 bits
		peerUID:  peerUID,
		now:      func() time.Time { return time.Now().Round(0) },
		tick:     tick,
		stopped:  make(chan struct{}),
	}
}

// run serves connections until ctx ends (SIGTERM), the idle exit, the
// first RESTART reply or an accept error. Then it stops: the listener
// is closed at once; each session closes after its calls in flight,
// within drainLimit. run gives the reason and the exit code. It does
// not close the Service.
//
// arch: DS11.4, DS11.7, IS11.7
func (d *daemon) run(ctx context.Context) (reason string, code int) {
	sessCtx, closeSessions := context.WithCancel(ctx)
	defer closeSessions()

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		d.acceptLoop(sessCtx)
	}()

loop:
	for {
		select {
		case <-ctx.Done():
			d.beginStop(stopSigterm)
			break loop
		case <-d.stopped:
			break loop
		case <-d.tick:
			d.checkIdle()
		}
	}

	// The listener is closed, so the accept loop ends. After that, no
	// connection is added to d.conns.
	<-acceptDone

	// A session that got OK but is not yet known to the Service sees
	// its ctx end and closes itself. CloseSessions closes the others.
	// Each close waits for the calls in flight (DS11.7 step 3).
	closeSessions()
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), drainLimit)
	defer cancelDrain()
	d.svc.CloseSessions(drainCtx)
	if !waitGroupCtx(drainCtx, &d.conns) {
		d.logger.Warn("drain limit reached", "limit", drainLimit.String())
	}

	d.mu.Lock()
	reason = d.reason
	d.mu.Unlock()
	if reason == stopAcceptError {
		return reason, 1
	}
	return reason, 0
}

// waitGroupCtx waits for wg or for the end of ctx. It reports whether
// wg finished first.
func waitGroupCtx(ctx context.Context, wg *sync.WaitGroup) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// acceptLoop accepts connections until the listener closes. Each
// connection gets its own goroutine. An accept error that the daemon
// did not cause stops the daemon.
func (d *daemon) acceptLoop(ctx context.Context) {
	for {
		conn, err := d.ln.AcceptUnix()
		if err != nil {
			if !d.isStopping() {
				d.logger.Error("accept failed", "error", err.Error())
				d.beginStop(stopAcceptError)
			}
			return
		}
		d.conns.Add(1)
		go func() {
			defer d.conns.Done()
			d.serveConn(ctx, conn)
		}()
	}
}

// serveConn runs one connection: the peer uid check before any byte
// is read (IS11.3), the handshake within handshakeLimit, and on OK the
// MCP session until it ends.
//
// arch: DS11.4, DS11.6, IS11.3, IS11.5
func (d *daemon) serveConn(ctx context.Context, conn *net.UnixConn) {
	uid, err := d.peerUID(conn)
	if err != nil || uid != d.uid {
		if err != nil {
			d.logger.Warn("peer refused", "error", err.Error())
		} else {
			d.logger.Warn("peer refused", "peer_uid", uid)
		}
		_ = conn.Close()
		return
	}

	_ = conn.SetDeadline(time.Now().Add(handshakeLimit))
	line, err := readLine(conn, maxHandshakeLine)
	if err != nil {
		_ = conn.Close()
		d.logger.Info("handshake", "result", "bad", "error", err.Error())
		return
	}
	build, config, ok := parseHello(line)
	if !ok {
		_ = conn.Close()
		d.logger.Info("handshake", "result", "bad")
		return
	}

	reply := d.answer(build, config)
	d.logger.Info("handshake", "result", reply)
	_, err = io.WriteString(conn, reply+"\n")
	if reply != replyOK || err != nil {
		_ = conn.Close()
		if reply == replyOK {
			d.sessionEnded()
		}
		return
	}

	_ = conn.SetDeadline(time.Time{})
	defer d.sessionEnded()
	_ = d.svc.Session(ctx, conn) // Session logs its end and closes conn
}

// answer gives the reply to a valid hello line (DS11.6). The config
// check comes first: a shim with another config pair never stops this
// daemon, also when its build is another one (IS11.5, IS11.9). While
// the daemon stops, each shim of this config pair gets RESTART. The
// first build mismatch starts the handover: the listener closes before
// the reply goes out, so the next dial of that shim does not reach
// this daemon (DS11.7). An OK counts the session as active.
//
// arch: DS11.6, DS11.7, IS11.5
func (d *daemon) answer(build, config string) string {
	d.mu.Lock()
	var reply string
	began := false
	switch {
	case config != d.configID:
		reply = replyConfig
	case d.stopping:
		reply = replyRestart
	case build != d.buildID:
		reply = replyRestart
		began = d.markStopLocked(stopBuildChange)
	default:
		reply = replyOK
		d.active++
	}
	d.mu.Unlock()
	if began {
		d.closeListener(stopBuildChange)
	}
	return reply
}

// sessionEnded counts down one active session.
func (d *daemon) sessionEnded() {
	d.mu.Lock()
	d.active--
	d.mu.Unlock()
}

// checkIdle stops the daemon when no session lives and the last one
// ended idleExit ago, on the wall clock d.now. A suspend counts as idle
// time. The check and the stop are under one lock with answer, so a
// shim that gets OK never sees its session closed by the idle exit.
//
// arch: DS11.4, DS11.19
func (d *daemon) checkIdle() {
	n, idleAt := d.svc.Live()
	now := d.now()
	d.mu.Lock()
	if d.stopping || n > 0 || d.active > 0 || now.Sub(idleAt) < idleExit {
		d.mu.Unlock()
		return
	}
	d.markStopLocked(stopIdle)
	d.mu.Unlock()
	d.closeListener(stopIdle)
}

// beginStop starts the stop with reason, unless the daemon already
// stops, and closes the listener.
func (d *daemon) beginStop(reason string) {
	d.mu.Lock()
	began := d.markStopLocked(reason)
	d.mu.Unlock()
	if began {
		d.closeListener(reason)
	}
}

// markStopLocked records the first stop and its reason, and reports
// whether this call was the first. The caller holds d.mu.
func (d *daemon) markStopLocked(reason string) bool {
	if d.stopping {
		return false
	}
	d.stopping = true
	d.reason = reason
	close(d.stopped)
	return true
}

// closeListener closes the listener. An own listener unlinks the
// socket and releases the lock at once, so a new daemon can start
// while this one drains; an activated listener closes its fd copy and
// systemd keeps the socket (DS11.7 step 2).
func (d *daemon) closeListener(reason string) {
	d.logger.Info("stopping", "reason", reason)
	if err := d.ln.Close(); err != nil {
		d.logger.Warn("listener close failed", "error", err.Error())
	}
}

// isStopping reports whether the stop began.
func (d *daemon) isStopping() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stopping
}

// readLine reads one line of at most limit bytes, one byte at a time,
// so that it never reads a byte past the "\n". The line has no "\n".
func readLine(r io.Reader, limit int) (string, error) {
	var b [1]byte
	line := make([]byte, 0, 128)
	for len(line) < limit {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
	}
	return "", fmt.Errorf("server: handshake line longer than %d bytes", limit)
}

// parseHello splits "MAILBAG 1 <buildid> <configid>" into the two ids.
// It reports false for another word, another protocol or another
// number of fields.
func parseHello(line string) (build, config string, ok bool) {
	f := strings.Fields(line)
	if len(f) != 4 || f[0] != helloWord || f[1] != helloProtocol {
		return "", "", false
	}
	return f[2], f[3], true
}
