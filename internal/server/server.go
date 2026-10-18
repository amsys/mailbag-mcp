// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package server owns the serve-mode process lifecycle: signal rules,
// the parent watchdog, the log, and shutdown (§3.1, §3.19).
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/tools"
	"github.com/amsys/mailbag-mcp/internal/undo"
)

// watchdogInterval is the parent-check period of §3.1 step 4.
const watchdogInterval = 30 * time.Second

// toolsetWatchInterval is the accounts.toml poll period of D2.3.
const toolsetWatchInterval = 2 * time.Second

// recoverBackground recovers a panic in a background goroutine so it
// cannot take the whole process down (A7), and writes one error log
// line naming where it happened, the panic value and the stack, so
// the panic leaves evidence instead of vanishing (DRV.19.7). Call it
// as the deferred call in a background goroutine, one per goroutine:
// [Watchdog], the SIGTERM watcher (signals.go) and toolsetWatcher
// below each recover this way instead of discarding the panic.
//
// recover only stops a panic when called directly by the deferred
// function; recoverBackground is itself that deferred function, so
// calling recover() at its own top level still qualifies.
//
// arch: DRV.19.7
func recoverBackground(logger *slog.Logger, source string) {
	if r := recover(); r != nil {
		logger.Error("background goroutine panicked",
			"source", source,
			"panic", fmt.Sprintf("%v", r),
			"stack", string(debug.Stack()),
		)
	}
}

// newMCPServer builds the MCP server with the core tools registered
// (tools.RegisterCore, T1.5) and the guard-layer instructions of
// Appendix C set. It gives back the [tools.Factory] those tools
// share, because that Factory owns the one IMAP pool that holds the
// connections: NewService reaps it at step 5 and Service.Close closes
// it at step 7. A test that builds a server through newMCPServer must
// close this Factory itself (DRV.16b: the exported NewMCPServer that used to
// drop it for a test with no connection to close is gone).
// logger is passed straight through: it need not be
// non-nil for safety (mcp.NewServer replaces a nil
// ServerOptions.Logger with a discard logger before Server.Run ever
// reads it — go-sdk v1.7.0 mcp/server.go:207-209, mcp/logging.go:
// 105-110), but this package always passes a live logger anyway, so
// the §3.19 start/shutdown/exit events actually reach server.log
// instead of being discarded.
//
// arch: T1.4, T1.5, §3.1, §3.16, §3.15, App C
func newMCPServer(version string, logger *slog.Logger) (*mcp.Server, *tools.Factory) {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "mailbag-mcp",
		Version: version,
	}, &mcp.ServerOptions{Logger: logger, Instructions: tools.Instructions})
	return srv, tools.RegisterCore(srv, logger)
}

// startReaper and closeMail are §3.1 step 5 and step 7 as variables,
// so a test can read which pool NewService reaps and which Factory
// Service.Close closes. Both must act on the Factory the mail tools
// share: a second, empty pool reaps nothing and closes nothing.
var (
	startReaper = func(ctx context.Context, p *imap.Pool) { go p.Reaper(ctx) }
	closeMail   = func(f *tools.Factory) { f.Close() }
)

// toolsetWatcher re-reads accounts.toml every interval and applies
// its extras list to registry, so a human edit takes effect with no
// restart (D2.3): 1) the human changes extras, 2) this watcher sees
// the new mtime and calls cfg.Refresh then registry.Sync, 3) Sync
// calls the changed group's Add or removes its tools, and the SDK
// sends notifications/tools/list_changed for each one, 4) a connected
// client's next tools/list carries the change (D8.2).
//
// A stat or parse error from Refresh keeps the running set. D2.3 asks
// for one log line, not one every tick, so this remembers the last
// error text and only logs again when the text changes; a good reload
// clears that memory, so the same text logs again if the file goes
// bad a second time (R1B-judge.md finding 2).
//
// Sync gets cfg.Extras() as it is. Every name config accepts has a
// group in [tools.Toolsets] (DS9.8), so Sync's "unknown toolset" error
// of D2.2 fires only for a name config does not know.
//
// Run it as its own goroutine, tied to ctx like Watchdog. It recovers
// on its own, so a bug here cannot take the whole process down (A7).
//
// DRV.14c: cfg is nil on a first run, before "account add" has
// written accounts.toml yet. This watcher must still start (NewService no
// longer gates the "go toolsetWatcher(...)" call on cfg != nil) and
// wait: each tick it tries [config.Load](accountsPath) itself, using
// the same lastReloadErr dedup as a bad reload has, until the file
// exists and parses; the first successful Load then syncs registry
// from a running set of nothing, exactly as a later accounts.toml
// edit would (D2.3), and the loop falls through to the normal
// cfg.Refresh path from then on.
//
// T135: a runtime accounts.toml change can also flip the D7.1 decrypt
// state (not only the extras it was already watching for), and that
// deserves the same warning or off line serve prints at start, not
// silence until the next restart. After each successful Sync this
// calls [tools.StatusLines] and writes its decrypt line through
// writeStatusLines, but only when it differs from the last one
// reported (lastDecrypt): a Sync that a "send" or "modify" extras
// edit triggered, with decrypt untouched, repeats nothing. w is the
// writer NewService captured before starting this goroutine; see the call
// site's comment for why. initialDecrypt seeds lastDecrypt with the
// line NewService already wrote at start (cfg != nil case), so the first
// Sync this goroutine runs does not re-announce a state the operator
// already saw; on a first run (cfg == nil, DRV.14c) initialDecrypt is
// nil, and this goroutine's own first successful Load is correctly
// the first report.
//
// arch: D2.1, D2.2, D2.3, D8.2, DRV.14c, DR1G.10, IR1G.10, IR1G.11, DS9.8
func toolsetWatcher(ctx context.Context, cfg *config.Config, accountsPath string, registry *tools.Registry, srv *mcp.Server, logger *slog.Logger, interval time.Duration, w io.Writer, initialDecrypt []string) {
	defer recoverBackground(logger, "toolset-watcher") // A7, DRV.19.7

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastReloadErr string      // finding 2: dedup by error text, reset on a good reload
	lastDecrypt := initialDecrypt // T135: the decrypt lines last reported to the operator

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if cfg == nil {
				loaded, err := config.Load(accountsPath)
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						msg := err.Error()
						if msg != lastReloadErr {
							logger.Error("toolset watcher: accounts.toml reload failed, keeping the running set", "error", msg)
							lastReloadErr = msg
						}
					}
					continue
				}
				cfg = loaded
				lastReloadErr = ""
				if err := registry.Sync(srv, cfg.Extras()); err != nil {
					logger.Error("toolset watcher: sync failed, keeping the running set", "error", err.Error())
				} else {
					lastDecrypt = writeDecryptIfChanged(logger, w, cfg, lastDecrypt)
				}
				continue
			}
			changed, err := cfg.Refresh()
			if err != nil {
				msg := err.Error()
				if msg != lastReloadErr {
					logger.Error("toolset watcher: accounts.toml reload failed, keeping the running set", "error", msg)
					lastReloadErr = msg
				}
				continue
			}
			lastReloadErr = "" // a good reload; the same text logs again if it recurs
			if !changed {
				continue
			}
			if err := registry.Sync(srv, cfg.Extras()); err != nil {
				logger.Error("toolset watcher: sync failed, keeping the running set", "error", err.Error())
			} else {
				lastDecrypt = writeDecryptIfChanged(logger, w, cfg, lastDecrypt)
			}
		}
	}
}

// writeDecryptIfChanged writes cfg's current decrypt line (T135) when
// it differs from last, and gives back the lines it wrote (or last,
// unchanged, when it wrote nothing), so the caller's next comparison
// stays correct.
//
// arch: DR1G.10, IR1G.10
func writeDecryptIfChanged(logger *slog.Logger, w io.Writer, cfg *config.Config, last []string) []string {
	_, decrypt := tools.StatusLines(cfg)
	if slices.Equal(decrypt, last) {
		return last
	}
	writeStatusLines(logger, w, nil, decrypt)
	return decrypt
}

// cleanUndoJournal removes the undo records older than 30 days
// (§3.18). It runs at start, which is the one moment the design
// names, because a record is only useful while the person can still
// ask for the change back.
//
// A failure never stops the server: the journal is a help, not a part
// of the transport. Like the log (§3.19), it writes the cause and
// goes on. Nothing is deleted when the directory does not exist yet.
//
// arch: T5.3, §3.18, §3.1, A10
func cleanUndoJournal(logger *slog.Logger) {
	j, err := undo.Open()
	if err != nil {
		logger.Error("undo cleanup skipped", "error", err.Error())
		return
	}
	removed, err := j.Cleanup(undo.MaxAge)
	if err != nil {
		logger.Error("undo cleanup failed", "error", err.Error())
	}
	if removed > 0 {
		logger.Info("undo-cleanup", "removed", removed)
	}
}

// startFailed logs and reports an error from the pre-transport start
// steps (accounts path, config load). §3.19: "Errors at start also go
// to stderr", on top of the log line, so a person running the server
// by hand without a log open in another window still sees why it
// exited 1.
//
// arch: T1.4, §3.19
func startFailed(logger *slog.Logger, err error) int {
	logger.Error("start failed", "error", err.Error())
	fmt.Fprintf(os.Stderr, "mailbag-mcp: start failed: %s\n", err)
	return 1
}

// writeStatusLines logs each of toolsets and decrypt ([tools.StatusLines]
// gives both) and, for the lines a person running serve by hand should
// also see on stderr, writes w too (03-design-R1G.md DR1G.10). It
// replaces the old logOffToolsets and logDecryptState. DR1G.10's bar
// is grep-safe text, not an identical log line: the old functions
// logged structured attrs (for example `msg=toolsets-off
// off="modify, send"`), while this logs the fixed [tools.StatusLines]
// string as the whole message. The substrings an existing test greps
// server.log or stderr for ("modify", "send", [tools.DecryptWarning])
// still appear; the slog message text and attribute shape do not
// match the old calls verbatim.
//
// Every toolsets line goes to logger.Info and to w; w gets the same
// "toolsets off: ..." text logOffToolsets wrote to stderr (D2.1's
// migration check). A decrypt line starting "decrypt-on: " is the
// D7.1 warning: it goes to logger.Warn, and only [tools.DecryptWarning]
// itself (the prefix stripped) goes to w — the same stderr text
// logDecryptState wrote, though the log message is not the same
// string. Any other decrypt line (the "decrypt-off: " line naming
// missing keys) goes to logger.Info only, same as before: a missing
// key is not yet an error a person running serve by hand needs on
// stderr. No line holds mail text (I14): [tools.StatusLines] builds
// every line from fixed words and config key names only.
//
// arch: DR1G.10, IR1G.10, D2.1, D7.1, I13, I14
func writeStatusLines(logger *slog.Logger, w io.Writer, toolsets, decrypt []string) {
	for _, l := range toolsets {
		logger.Info(l)
		_, _ = fmt.Fprintf(w, "mailbag-mcp: %s\n", l) // a failed status line to the console is not worth stopping for
	}
	for _, l := range decrypt {
		if rest, ok := strings.CutPrefix(l, "decrypt-on: "); ok {
			logger.Warn(l)
			_, _ = fmt.Fprintf(w, "mailbag-mcp: %s\n", rest) // as above
			continue
		}
		logger.Info(l)
	}
}

// setupLog opens the server log under the state directory (§3.3,
// §3.19), creating that directory on a first run. Any failure here
// falls back to a stderr-only logger rather than stopping the server.
func setupLog() (logger *slog.Logger, closer io.Closer, err error) {
	stateDir, dirErr := config.StateDir()
	if dirErr != nil {
		return stderrLogger(), nil, dirErr
	}
	if mkErr := os.MkdirAll(stateDir, 0o700); mkErr != nil {
		return stderrLogger(), nil, mkErr
	}
	return openLog(filepath.Join(stateDir, "server.log"))
}

// OpenLog is setupLog for main.go, which gives the logger to the shim
// (G4 in DS11.20). It opens server.log under the state directory. On
// a failure it gives the stderr logger and the error, and the caller
// continues (§3.19). The caller closes the io.Closer when it is not
// nil. Serve and ServeSocket call setupLog.
//
// arch: DS11.13, DS11.20
func OpenLog() (*slog.Logger, io.Closer, error) {
	return setupLog()
}

// SocketName is the name of the daemon socket in SocketDir (DS11.4).
// The shim dials it. The systemd socket unit of DS11.11 names the
// same path, and every build uses it (G9).
const SocketName = "mailbag.sock"

// socketDir is $XDG_RUNTIME_DIR/mailbag. It fails when the variable
// is unset or is not an absolute path: a runtime socket never goes to
// /tmp (owner rule 9). It is in this file and not in socket.go, so
// that main.go can call SocketDir on Windows too: there it builds,
// and the shim runs the in-process server (G8).
//
// arch: DS11.4
func socketDir() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		return "", errors.New("server: XDG_RUNTIME_DIR is not set; the daemon socket never goes to /tmp")
	}
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("server: XDG_RUNTIME_DIR %q is not an absolute path", base)
	}
	return filepath.Join(base, "mailbag"), nil
}

// SocketDir is socketDir for main.go: the directory of the daemon
// socket and of spawn.lock (G4 in DS11.20).
//
// arch: DS11.4, DS11.13, DS11.20
func SocketDir() (string, error) {
	return socketDir()
}

// shutdownReason maps the process-model outcome to the §3.19 event
// vocabulary. The session of [Serve] ends in one of four ways: a
// cancelled context (either SIGTERM or the watchdog cancelled it;
// sigterm tells the two apart), stdin EOF (Service.Session returns
// nil), and any other error, which is a transport error.
//
// arch: T1.4, §3.19, A3, A4, DS11.3
func shutdownReason(ctx context.Context, runErr error, sigterm bool) string {
	switch {
	case ctx.Err() != nil && sigterm:
		return "sigterm"
	case ctx.Err() != nil:
		return "parent-gone"
	case runErr == nil:
		return "stdin-eof"
	default:
		return "transport-error"
	}
}
