// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// In-process mode: one MCP session on the stdio of this process, with
// a Service of its own (DS11.3). It is the path of a host with no
// daemon and the fallback of the shim.

package server

import (
	"context"
	"io"
	"os"
)

// stdioConn is the byte stream of the in-process session: it reads
// from in and writes to out. Its Close closes in only. out stays
// open, as the SDK's StdioTransport keeps os.Stdout open (DS11.3).
type stdioConn struct {
	in  io.ReadCloser
	out io.Writer
}

// Read reads the next bytes from in.
func (c stdioConn) Read(p []byte) (int, error) { return c.in.Read(p) }

// Write writes p to out.
func (c stdioConn) Write(p []byte) (int, error) { return c.out.Write(p) }

// Close closes in. It does not close out.
func (c stdioConn) Close() error { return c.in.Close() }

// Serve runs one MCP session on in and out (the stdio of this
// process) with a [Service] of its own, and returns the process exit
// code. It never calls os.Exit itself, so main can do that after
// Serve returns, and a test can call Serve without ending the test
// process.
//
// The steps follow DS11.3 in this order: IgnoreForServe, TermContext,
// setupLog, NewService, the parent watchdog, [Service.Session] on
// stdioConn{in, out}, the "shutdown" line, Service.Close, the "exit"
// line. Serve opens the log and closes it after Service.Close (G8 in
// DS11.20). The exit code is 0 for SIGTERM, stdin EOF and a parent
// that is gone (§3.1 step 7), and 1 for a start failure.
//
// out gets the JSON-RPC stream only (A1, IS11.1). The session runs
// through Service.Session, not Server.Run, so a normal end writes no
// ERROR line (IS11.2).
//
// arch: DS11.3, DS11.13, IS11.1, IS11.2, T1.4, T1.5, §3.1, §3.16, §3.15, App C, A2, A3, A4, A5, A6, A7, A9
func Serve(version string, in io.ReadCloser, out io.Writer) int {
	IgnoreForServe() // step 1, serve mode only: A2, A5

	ctx, cancel, sigtermReceived := TermContext(context.Background()) // step 2: A3
	defer cancel()

	logger, closeLog, logErr := setupLog()
	if closeLog != nil {
		defer func() { _ = closeLog.Close() }()
	}
	if logErr != nil {
		// §3.19: a log failure never stops the server. It already has
		// a stderr fallback logger; just record the cause once.
		logger.Error("log open failed, writing to stderr instead", "error", logErr.Error())
	}

	svc, err := NewService(ctx, version, logger) // steps 3, 3a, 3b and 5
	if err != nil {
		return startFailed(logger, err)
	}

	go Watchdog(ctx, cancel, os.Getppid, watchdogInterval, logger) // step 4, A4; recovers on its own (A7)

	// step 6: A1, A6, A11. Session closes in when the session ends.
	sessErr := svc.Session(ctx, stdioConn{in: in, out: out})

	logger.Info("shutdown", "reason", shutdownReason(ctx, sessErr, sigtermReceived()))

	// step 7: stop the background work and close the mail
	// connections. Each LOGOUT has its own 2 s limit inside the pool
	// (T4.2, §3.10). It runs after the session ended, so a connection
	// never closes under a call that still serves.
	svc.Close()

	logger.Info("exit", "code", 0)
	return 0
}
