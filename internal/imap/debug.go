// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"io"
	"os"
	"sync"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// DebugEnv is the variable that turns wire debug on (§3.10).
const DebugEnv = "MAILBAG_DEBUG"

// WireDebug gives the writer for the go-imap DebugWriter option, or
// nil when debug is off. Debug output goes to stderr, never to
// stdout, because stdout carries JSON-RPC only (§3.1).
//
// arch: T4.2, §3.10, §3.1, B15
func WireDebug() io.Writer {
	if os.Getenv(DebugEnv) == "1" {
		return os.Stderr
	}
	return nil
}

// debugWriter is the writer the pool gives to go-imap. The go-imap
// DebugWriter shows the whole exchange, the login included (B15).
// This writer drops every byte until Open says the login finished, so
// a password or an access token never reaches the debug stream. After
// Open it still passes each block through guard.Redact, because a
// later command can carry a secret too.
//
// It is safe for concurrent use: go-imap writes from the read
// goroutine and from the caller goroutine at the same time.
//
// arch: T4.2, §3.10, B15
type debugWriter struct {
	mu   sync.Mutex
	w    io.Writer
	open bool
}

// newDebugWriter wraps w. The caller gives a writer only when debug
// is on, so w is never nil.
func newDebugWriter(w io.Writer) *debugWriter {
	return &debugWriter{w: w}
}

// Write drops the block before the login finished. It always reports
// the full length, because a short count is a write error to go-imap
// and would break the connection.
func (d *debugWriter) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.open {
		return len(p), nil
	}
	if _, err := io.WriteString(d.w, guard.Redact(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Open lets the traffic through. Call it after the login finished.
func (d *debugWriter) Open() {
	d.mu.Lock()
	d.open = true
	d.mu.Unlock()
}
