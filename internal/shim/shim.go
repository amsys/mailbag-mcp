// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package shim is the MCP entry of mailbag-mcp (DS11.8): the process
// that the client starts. It connects the stdio of the client to the
// daemon on the Unix socket, starts the daemon when no daemon runs,
// and runs the in-process server when it cannot use a daemon. The
// shim writes no byte to its stdout except the bytes of the daemon
// (IS11.1).
package shim

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/server"
)

// The time limits of DS11.8 and DS11.6.
const (
	// dialWait is the limit of one dial of the socket.
	dialWait = 500 * time.Millisecond
	// spawnWait is the limit of the wait for spawn.lock, and of the
	// dial retries after a spawn.
	spawnWait = 2 * time.Second
	// dialRetry is the period of the dial retries after a spawn. The
	// first dial after a spawn fails, so the first start waits for one
	// period: 50 ms gave a first start of 57 ms, 5 ms gave 15 ms
	// (median, 2026-10-09). A failed dial of a Unix socket costs
	// microseconds.
	dialRetry = 5 * time.Millisecond
	// handshakeLimit is the limit of the hello line and the reply. It
	// is the same limit that the daemon uses (DS11.6).
	handshakeLimit = 2 * time.Second
	// watchdogInterval is the parent check period of §3.1 step 4, as
	// in server.Serve.
	watchdogInterval = 30 * time.Second
	// maxReplyLine is the longest reply line that the shim reads. The
	// longest real reply is "RESTART".
	maxReplyLine = 64
)

// The lines of the handshake (DS11.6), as internal/server/socket.go
// reads and writes them. The shim sends
// "MAILBAG 1 <buildid> <configid>"; the daemon replies with one word.
// Each line ends with "\n".
const (
	helloPrefix  = "MAILBAG 1 "
	replyOK      = "OK"
	replyRestart = "RESTART"
	replyConfig  = "CONFIG"
)

// The reasons of the fallback line (DS11.8 step 4).
const (
	reasonNoSocket    = "no-socket"
	reasonConfig      = "config"
	reasonHandshake   = "handshake"
	reasonSpawnFailed = "spawn-failed"
)

// Options are the seams of Run. Production fills them in main.go;
// tests replace Dial, Spawn and Fallback.
//
// arch: DS11.8, DS11.20
type Options struct {
	Version  string
	BuildID  string // DS11.5; sent in the hello line
	ConfigID string // DS11.5; sent in the hello line
	In       io.ReadCloser
	Out      io.Writer
	// Logger is server.log. The shim writes at most one INFO line to
	// it: the fallback line. A nil Logger discards the line.
	Logger *slog.Logger
	// Dial dials the Unix socket of the daemon. It is nil on Windows.
	Dial func(ctx context.Context) (net.Conn, error)
	// Spawn starts "serve" detached.
	Spawn func(ctx context.Context) error
	// Fallback runs the in-process server: server.Serve(version, in,
	// out). Run gives its exit code.
	Fallback func() int
	// Ppid gives the parent pid for the watchdog. Nil means
	// os.Getppid.
	Ppid func() int
	// LockDir is the directory of spawn.lock: the socket directory in
	// production, a temp dir in tests (G4 in DS11.20). It must be an
	// absolute path.
	LockDir string
}

// Run is the MCP entry. It returns the process exit code.
//
// On Windows, or when Dial is nil, Run calls Fallback at once (G5,
// G8). When MAILBAG_DEBUG is "1", Run also calls Fallback at once: the
// daemon has no stderr, so only the in-process server can write the
// wire debug of §3.10 to the stderr of the client (R16-L22). Else it
// dials the daemon and sends the hello line. OK starts
// the copy loop. CONFIG runs Fallback. RESTART, or no daemon, takes
// the spawn path: Run takes spawn.lock, dials once more, else calls
// Spawn and dials again for spawnWait, then releases the lock and
// sends the hello line again. A path that does not end in OK runs
// Fallback, after one INFO line "shim fallback" with the reason.
//
// Run reads no byte of In and writes no byte to Out before the copy
// loop starts, so Fallback gets the stdio of the client untouched.
// The exit code is 0 for each end of the copy loop: stdin EOF, the
// end of the daemon connection, SIGTERM and a parent that is gone
// (§3.1 step 7).
//
// arch: DS11.8, DS11.6, DS11.18, DS11.19, DS11.20, IS11.1, IS11.5, IS11.6
func Run(ctx context.Context, o Options) int {
	if runtime.GOOS == "windows" || o.Dial == nil || os.Getenv(imap.DebugEnv) == "1" {
		return o.Fallback()
	}

	server.IgnoreForServe()
	ctx, cancel, _ := server.TermContext(ctx)
	defer cancel()

	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	ppid := o.Ppid
	if ppid == nil {
		ppid = os.Getppid
	}
	// The shim is the process that the client started, so the parent
	// rule of §3.1 step 4 stays here (R§11.4).
	go server.Watchdog(ctx, cancel, ppid, watchdogInterval, logger)

	conn, reason, err := connect(ctx, o)
	if conn == nil {
		if ctx.Err() != nil {
			// SIGTERM or a parent that is gone: stop, do not start
			// the in-process server.
			return 0
		}
		if err != nil {
			logger.Info("shim fallback", "reason", reason, "error", err.Error())
		} else {
			logger.Info("shim fallback", "reason", reason)
		}
		return o.Fallback()
	}
	copyLoop(ctx, conn, o.In, o.Out)
	return 0
}

// connect gives a connection whose handshake got OK. Else it gives a
// nil connection with the fallback reason, and the error when there
// is one.
func connect(ctx context.Context, o Options) (net.Conn, string, error) {
	// DS11.8 step 3.
	if conn, err := dialOnce(ctx, o.Dial); err == nil {
		reply, err := hello(conn, o.BuildID, o.ConfigID)
		if err != nil || reply != replyRestart {
			return answer(conn, reply, err)
		}
		// The daemon closed its listener before this reply (DS11.7),
		// so the spawn path starts a new daemon.
		_ = conn.Close()
	}

	// DS11.8 step 4.
	conn, reason, err := spawnPath(ctx, o)
	if conn == nil {
		return nil, reason, err
	}
	reply, err := hello(conn, o.BuildID, o.ConfigID)
	return answer(conn, reply, err)
}

// answer maps the result of a handshake on conn. OK keeps conn. Each
// other result closes conn and gives the fallback reason: CONFIG gives
// "config" (IS11.5); another reply, a timeout or EOF gives "handshake"
// (DS11.6).
func answer(conn net.Conn, reply string, err error) (net.Conn, string, error) {
	if err == nil && reply == replyOK {
		return conn, "", nil
	}
	_ = conn.Close()
	switch {
	case err != nil:
		return nil, reasonHandshake, err
	case reply == replyConfig:
		return nil, reasonConfig, nil
	default:
		return nil, reasonHandshake, fmt.Errorf("shim: unknown handshake reply %q", reply)
	}
}

// spawnPath holds spawn.lock while it dials once more and, when that
// fails, calls Spawn and dials for spawnWait. Two shims that start at
// the same time so start one daemon: the second shim dials after the
// first one released the lock, and finds the daemon (IS11.6).
//
// arch: DS11.8, DS11.19, IS11.6
func spawnPath(ctx context.Context, o Options) (net.Conn, string, error) {
	release, err := lockSpawn(ctx, o.LockDir, spawnWait)
	if err != nil {
		return nil, reasonSpawnFailed, err
	}
	defer release()

	// Another shim may have started the daemon while this one waited
	// for the lock.
	if conn, err := dialOnce(ctx, o.Dial); err == nil {
		return conn, "", nil
	}
	if err := o.Spawn(ctx); err != nil {
		return nil, reasonSpawnFailed, err
	}
	conn, err := dialUntil(ctx, o.Dial, spawnWait)
	if err != nil {
		return nil, reasonNoSocket, err
	}
	return conn, "", nil
}

// dialOnce dials one time, bounded by dialWait.
func dialOnce(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialWait)
	defer cancel()
	return dial(ctx)
}

// dialUntil dials every dialRetry until a dial succeeds, wait ends or
// ctx ends. It gives the error of the last dial.
func dialUntil(ctx context.Context, dial func(context.Context) (net.Conn, error), wait time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	tick := time.NewTicker(dialRetry)
	defer tick.Stop()
	for {
		conn, err := dial(ctx)
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-tick.C:
		}
	}
}

// hello sends the hello line of DS11.6 and reads the reply line,
// both within handshakeLimit. It gives the reply without "\n".
//
// arch: DS11.6
func hello(conn net.Conn, buildID, configID string) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(handshakeLimit))
	if _, err := io.WriteString(conn, helloPrefix+buildID+" "+configID+"\n"); err != nil {
		return "", err
	}
	reply, err := readLine(conn, maxReplyLine)
	if err != nil {
		return "", err
	}
	_ = conn.SetDeadline(time.Time{})
	return reply, nil
}

// readLine reads one line of at most limit bytes, one byte at a time,
// so that it never reads a byte past the "\n": the bytes after the
// reply are JSON-RPC and belong to the copy loop. The line has no
// "\n". The same rule is in readLine of internal/server/socket.go.
func readLine(r io.Reader, limit int) (string, error) {
	var b [1]byte
	line := make([]byte, 0, 16)
	for len(line) < limit {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
	}
	return "", fmt.Errorf("shim: handshake reply line longer than %d bytes", limit)
}

// copyLoop copies in to conn and conn to out until the daemon closes
// conn or ctx ends (DS11.8 step 5). On EOF of in, it closes the write
// side of conn, so the daemon reads EOF and ends the session, and
// then it waits for the daemon to close. When ctx ends (SIGTERM, the
// parent is gone), it closes conn at once.
//
// arch: DS11.8, IS11.1
func copyLoop(ctx context.Context, conn net.Conn, in io.Reader, out io.Writer) {
	defer func() { _ = conn.Close() }()

	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		_, _ = io.Copy(out, conn)
	}()
	go func() {
		_, _ = io.Copy(conn, in)
		// stdin EOF: no more requests come. A connection with no
		// write side to close is closed in full.
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			return
		}
		_ = conn.Close()
	}()

	select {
	case <-outDone:
	case <-ctx.Done():
	}
}
