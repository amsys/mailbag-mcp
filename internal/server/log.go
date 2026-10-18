// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package server

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// logRotateSize is the point past which the log rotates to
// "<path>.old" (§3.19).
const logRotateSize = 1 << 20 // 1 MB

// rotatingFile is an io.WriteCloser over the log file that renames it
// to "<path>.old" once it passes logRotateSize, so the log never
// grows without bound.
//
// ponytail: the size check reads the file's own Stat, so a process
// never drifts from the file on disk, but §3.1 also runs several
// server processes at once, each with its own rotatingFile over the
// same path. Two processes can race the rename (each sees the file as
// too big and both rotate). The log is diagnostic, not authoritative
// state, so a lost line there is not the record corruption A10 guards
// against; add a lock file if cross-process log integrity ever
// matters.
//
// arch: T1.4, §3.19
type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func openRotatingFile(path string) (*rotatingFile, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: the log path comes from the human's own config, not from mail data
	if err != nil {
		return nil, err
	}
	return &rotatingFile{path: path, f: f}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info, err := r.f.Stat(); err == nil && info.Size() > logRotateSize {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}
	return r.f.Write(p)
}

func (r *rotatingFile) rotateLocked() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	old := r.path + ".old"
	if err := os.Rename(r.path, old); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	r.f = f
	return nil
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// redactingWriter passes every write through guard.Redact before it
// reaches w, so a token that ends up in a log line never survives to
// disk (§3.15). It reports the length of the original write, not
// the redacted one, so callers see an ordinary short-write-free
// io.Writer.
type redactingWriter struct{ w io.Writer }

func (r redactingWriter) Write(p []byte) (int, error) {
	if _, err := r.w.Write([]byte(guard.Redact(string(p)))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// stderrLogger is the fallback used whenever the log file cannot be
// opened or its directory cannot be created (§3.19: a log failure
// never stops the server).
func stderrLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(redactingWriter{os.Stderr}, nil)).With("pid", os.Getpid())
}

// openLog opens the server log at path as a slog.Logger that writes
// text lines with the process id on each one (§3.19), rotating and
// redacting as above. A failure to open the file must never stop the
// server (§3.19): on error it returns stderrLogger instead, together
// with the error for the caller to report once.
//
// arch: T1.4, §3.19
func openLog(path string) (*slog.Logger, io.Closer, error) {
	rf, err := openRotatingFile(path)
	if err != nil {
		return stderrLogger(), nil, err
	}

	h := slog.NewTextHandler(redactingWriter{rf}, nil)
	logger := slog.New(h).With("pid", os.Getpid())
	return logger, rf, nil
}
