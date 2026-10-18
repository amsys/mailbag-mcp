// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

// IgnoreForServe ignores SIGINT, SIGHUP and SIGPIPE. Call it in serve
// mode only; the CLI commands must still stop on Ctrl-C (§3.1 step 1).
//
//   - SIGINT, SIGHUP: the client's terminal sends these on Ctrl-C, a
//     closed window or a detach. The server must outlive them (A2).
//   - SIGPIPE: Go kills the process on a failed write to fd 1 or fd 2.
//     A client that stops reading stderr must not take the server down
//     at the next log line (A5).
//
// arch: T1.4, §3.1, A2, A5
func IgnoreForServe() {
	signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGPIPE)
}

// TermContext returns a context that SIGTERM cancels (§3.1 step 2,
// A3), and a function reporting whether that SIGTERM is what
// cancelled it. A caller that also cancels ctx for another reason
// (the watchdog, A4) can use the function afterwards to tell the two
// apart for the shutdown log line (§3.19).
//
// arch: T1.4, §3.1, A3, A7
func TermContext(parent context.Context) (ctx context.Context, cancel context.CancelFunc, sigtermReceived func() bool) {
	ctx, cancel = context.WithCancel(parent)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)

	// TermContext runs before Serve opens the real log (it is step 2;
	// the log opens after it), so a panic in the goroutine below has no
	// logger to report through yet. stderrLogger is the same fallback
	// setupLog itself uses whenever the real log is not available
	// (§3.19); reusing it keeps this to one fallback logger, not two
	// (DRV.19.7). Make it here, not in the goroutine: stderrLogger reads
	// os.Stderr, and a read in the goroutine can come after the caller
	// has returned (T182).
	fallback := stderrLogger()
	var got atomic.Bool
	go func() {
		defer recoverBackground(fallback, "sigterm-watch") // A7, DRV.19.7: every background goroutine recovers on its own
		defer signal.Stop(ch)
		select {
		case <-ch:
			got.Store(true)
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel, got.Load
}
