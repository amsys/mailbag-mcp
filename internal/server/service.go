// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The Service: the state that all MCP sessions of one process share
// (DS11.2). Each session gets its own transport (session.go).

package server

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/secrets"
	"github.com/amsys/mailbag-mcp/internal/tools"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// Service holds the state that every MCP session of one process
// shares: the SDK server with its tools, the Factory (pool,
// credentials, token sources, auth states), the toolset watcher and
// the pool reaper. One process has one Service. A second session
// uses the IMAP connection that the first session opened, so it
// makes no new login (G4).
//
// arch: DS11.1, DS11.2, D11.1, T11.2
type Service struct {
	logger *slog.Logger
	srv    *mcp.Server
	mail   *tools.Factory
	cancel context.CancelFunc // ends the watcher, the reaper and the openssl probe
	bg     sync.WaitGroup     // the watcher and the openssl probe

	mu       sync.Mutex
	live     int       // sessions that have not ended
	idleAt   time.Time // wall time when live last became 0
	sessions map[*mcp.ServerSession]struct{}
	now      func() time.Time // wall time only, as imap.wallNow
}

// NewService runs the start steps of §3.1 that are not about one
// session: it reads accounts.toml, writes the status lines, starts
// the openssl probe, cleans the undo journal, builds the SDK server
// with the core tools and the toolsets, and starts the toolset
// watcher and the pool reaper. Then it logs the "start" line.
//
// The caller owns logger and closes it after [Service.Close] (G8 in
// DS11.20). An error comes from the accounts path, from a bad
// accounts.toml or from the toolset list; the caller reports it as a
// start failure.
//
// arch: DS11.2, §3.1, T1.4, T1.5, A9
func NewService(ctx context.Context, version string, logger *slog.Logger) (*Service, error) {
	// step 3: read accounts.toml, no network and no keyring access, so
	// the reply to "initialize" stays under 1 s (A9). A first run with
	// no accounts.toml yet (before "account add") is not an error; cfg
	// then stays nil, so every extras-only toolset opens off. The
	// D2.3 watcher below still starts (DRV.14c): it polls for the
	// file itself and syncs once "account add" creates it.
	secretsKind := secrets.KindKeyring
	numAccounts := 0
	var cfg *config.Config
	accountsPath, err := config.AccountsPath()
	if err != nil {
		return nil, err
	}
	if loaded, loadErr := config.Load(accountsPath); loadErr == nil {
		cfg = loaded
		secretsKind = cfg.Secrets()
		numAccounts = len(cfg.Aliases())
		toolsetsLines, _ := tools.StatusLines(cfg) // D2.1 migration line (DR1G.10)
		writeStatusLines(logger, os.Stderr, toolsetsLines, nil)
	} else if !errors.Is(loadErr, fs.ErrNotExist) {
		return nil, loadErr
	}

	ctx, cancel := context.WithCancel(ctx)
	s := &Service{
		logger:   logger,
		cancel:   cancel,
		sessions: make(map[*mcp.ServerSession]struct{}),
		now:      func() time.Time { return time.Now().Round(0) },
	}
	s.idleAt = s.now()

	// step 3a: log the openssl state once (F-D3, R1E-judge.md finding
	// 4). Only the fixed reason word goes to the log, never openssl
	// output (I18); an empty accounts.toml still checks PATH so the
	// human learns of a broken host before the first S/MIME read.
	//
	// R1E-fix-judge.md finding 6: OpensslStatus runs an external
	// binary with a 5 s timeout and a 1 s WaitDelay, so a slow or
	// hanging openssl_path must never sit in line before a session
	// reads its first request, or the "initialize" reply could miss
	// the A9 budget. The probe runs in a goroutine instead.
	//
	// R1E-fix2-judge.md finding 4: Close cancels ctx and then waits
	// for the probe, so a hanging openssl_path cannot hold the process
	// open after the client closes, and the log line is always
	// written before Close returns. A canceled probe gives
	// "not_openssl_3", so the warn line is still written.
	var verifyCfg verify.Config
	if cfg != nil {
		verifyCfg = cfg.Verify()
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		if ok, reason := verify.OpensslStatus(ctx, verifyCfg); !ok {
			logger.Warn("openssl unusable for s/mime", "reason", reason)
		}
	}()

	// step 3b: drop the undo records older than 30 days (§3.18). This
	// reads one local directory and removes files, so it adds no
	// network and no keyring work to the start (A9).
	cleanUndoJournal(logger)

	s.srv, s.mail = newMCPServer(version, logger)

	// D2.2 wiring continues here, not inside newMCPServer: extras
	// depends on cfg, which newMCPServer never sees, so NewService
	// builds the Registry itself right after RegisterCore ran inside
	// newMCPServer. The order D2.2 names (RegisterCore, then
	// RegisterToolsets with cfg.Extras()) still holds; the two calls
	// live in different functions instead of one.
	var extras []string
	var initialDecrypt []string // T135: seeds toolsetWatcher's dedup, see the call site below
	if cfg != nil {
		extras = cfg.Extras()                      // every name has a group (DS9.8)
		_, initialDecrypt = tools.StatusLines(cfg) // D7.1 (DR1G.10)
		writeStatusLines(logger, os.Stderr, nil, initialDecrypt)
	}
	registry, err := tools.RegisterToolsets(s.srv, logger, s.mail, extras)
	if err != nil {
		cancel()
		s.bg.Wait() // the probe ends at once on a canceled ctx
		return nil, err
	}
	// DRV.14c: cfg is nil on a first run (no accounts.toml yet), but the
	// watcher must still start so that "account add" is picked up with
	// no restart; toolsetWatcher itself waits for the file to appear
	// when cfg is nil.
	//
	// stderrW is captured here, before the goroutine starts, and passed
	// in rather than letting toolsetWatcher read the package os.Stderr
	// itself: a test that swaps os.Stderr around Serve's own lifetime
	// (not the watcher's) would otherwise race the watcher's read of it,
	// the T182 race class (DR1G.10).
	//
	// initialDecrypt seeds the watcher's own dedup memory with the line
	// this step already wrote above (cfg != nil case): without this, the
	// watcher's first Sync-triggered decrypt check would always find its
	// own nil lastDecrypt different from the current state and re-write
	// a line an operator already saw at start, even though decrypt never
	// changed. On a first run (cfg == nil), nothing was written above, so
	// initialDecrypt is nil and the watcher's own first successful Load
	// is correctly the first report (DRV.14c).
	stderrW := os.Stderr
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		toolsetWatcher(ctx, cfg, accountsPath, registry, s.srv, logger, toolsetWatchInterval, stderrW, initialDecrypt) // D2.3, T135
	}()

	// step 5: the IMAP pool reaper (§3.10). It runs on the pool the
	// mail tools dial with, so an idle connection closes after 15 min
	// and no account collects one held connection per client session.
	startReaper(ctx, s.mail.Pool()) // recovers on its own (A7)

	logger.Info("start",
		"version", version,
		"pid", os.Getpid(),
		"ppid", os.Getppid(),
		"secrets", secretsKind,
		"accounts", numAccounts,
	)
	return s, nil
}

// Live returns the number of sessions that have not ended and the
// wall time when that number last became zero. Before the first
// session, that time is the start of the Service.
//
// arch: DS11.2
func (s *Service) Live() (n int, idleAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live, s.idleAt
}

// CloseSessions closes every open session. The SDK's Close is
// graceful: it refuses new requests and waits for the calls in
// flight. CloseSessions waits for all of them, or until ctx ends.
// Each session's own [Service.Session] call then returns.
//
// arch: DS11.2, G2
func (s *Service) CloseSessions(ctx context.Context) {
	s.mu.Lock()
	open := make([]*mcp.ServerSession, 0, len(s.sessions))
	for ss := range s.sessions {
		open = append(open, ss)
	}
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, ss := range open {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ss.Close()
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Close ends the toolset watcher, the pool reaper and the openssl
// probe, waits for the watcher and the probe, and then closes the
// mail Factory (§3.1 step 7: each LOGOUT has its own 2 s limit inside
// the pool). Call it once, after the last session ended or after
// [Service.CloseSessions]. Close does not close the log; the caller
// that opened it does (G8 in DS11.20).
//
// arch: DS11.2, §3.1, §3.10, T4.5
func (s *Service) Close() {
	s.cancel()
	s.bg.Wait()
	closeMail(s.mail)
}

// track adds ss to the open sessions, or removes it when add is
// false. The removal of the last one sets idleAt.
func (s *Service) track(ss *mcp.ServerSession, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.sessions[ss] = struct{}{}
		s.live++
		return
	}
	delete(s.sessions, ss)
	s.live--
	if s.live == 0 {
		s.idleAt = s.now()
	}
}
