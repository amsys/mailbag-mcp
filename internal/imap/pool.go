// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Pool timing, from the table in §3.10.
const (
	idleClose     = 15 * time.Minute // close a connection nobody used
	staleAfter    = 60 * time.Second // send NOOP before reuse after this
	noopTimeout   = 10 * time.Second // a NOOP with no answer means a dead socket
	dialTimeout   = 15 * time.Second
	logoutTimeout = 2 * time.Second
	reapInterval  = time.Minute
)

// ErrNoDialer is the error every call gets when the pool has no
// dialer. It means the caller built the pool without one.
var ErrNoDialer = errors.New("imap: the pool has no dialer")

// Client is the go-imap client of one login. A package that gives a
// [DialFunc] uses this name, so the go-imap import stays in this
// package (C26).
//
// arch: C26
type Client = imapclient.Client

// DialFunc opens one connection for an account alias. The pool calls
// it for the first use and again for every reconnect, so the function
// must read the password or the access token each time it runs. A
// token that the caller read once and kept ends after about an hour
// and every redial after that fails (B14).
//
// arch: T4.2, §3.10, B14
type DialFunc func(ctx context.Context, alias string) (*Client, error)

// Conn is one live connection and the folder state that belongs to
// it. Selected holds the open folder (§3.10). A reconnect clears it.
//
// arch: T4.2, §3.10
type Conn struct {
	*imapclient.Client

	Selected string
}

// Pool keeps one IMAP connection for each account alias in this
// process (§3.10). It is safe for concurrent use.
//
// Each entry has its own mutex. That mutex puts the commands of one
// account in sequence, because the selected folder is state of the
// connection, and it makes two callers that come together share one
// reconnect (C24).
//
// arch: T4.2, §3.10, §3.1, C24, C25, B14
type Pool struct {
	dial DialFunc
	log  *slog.Logger

	// now and after are the injected clock. A test replaces them, so
	// the 60 s, 10 s and 15 min rules run in no time (C24). now gives
	// wall time only (wallNow, T199). A replacement now must give
	// wall-only times (Round(0)), as the fake clock does.
	now   func() time.Time
	after func(time.Duration) <-chan time.Time

	mu      sync.Mutex
	entries map[string]*entry
}

// entry is the connection of one alias.
type entry struct {
	mu   sync.Mutex
	conn *Conn
	last time.Time
}

// NewPool makes a pool. dial may be nil; every call then fails with
// ErrNoDialer. log may be nil.
//
// arch: T4.2, §3.10
func NewPool(dial DialFunc, log *slog.Logger) *Pool {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Pool{
		dial:    dial,
		log:     log,
		now:     wallNow,
		after:   time.After,
		entries: make(map[string]*entry),
	}
}

// WithRead runs fn on a live connection for alias. When the
// connection broke, it reconnects and runs fn one more time. A read
// is safe to repeat.
//
// arch: T4.2, §3.10, C24, C25
func (p *Pool) WithRead(ctx context.Context, alias string, fn func(*Conn) error) error {
	return p.with(ctx, alias, fn, true)
}

// WithWrite runs fn on a live connection for alias. It never runs fn
// a second time: a repeated APPEND makes a duplicate message (§3.10).
//
// arch: T4.2, §3.10, C24, C25
func (p *Pool) WithWrite(ctx context.Context, alias string, fn func(*Conn) error) error {
	return p.with(ctx, alias, fn, false)
}

func (p *Pool) with(ctx context.Context, alias string, fn func(*Conn) error, retry bool) error {
	if p.dial == nil {
		return ErrNoDialer
	}
	e := p.entryFor(alias)
	e.mu.Lock()
	defer e.mu.Unlock()

	c, err := p.live(ctx, e, alias)
	if err != nil {
		return err
	}
	err = p.run(ctx, e, c, fn)
	if err == nil || !retry || ctx.Err() != nil || !connBroken(c, err) {
		return err
	}
	// The socket died. Reconnect once and run fn again (C24).
	p.closeLocked(e)
	c, dialErr := p.live(ctx, e, alias)
	if dialErr != nil {
		return errors.Join(err, dialErr)
	}
	return p.run(ctx, e, c, fn)
}

// wallNow is time.Now without the monotonic reading. Go subtracts
// two monotonic readings when both times have one, and on Linux the
// monotonic clock stops during suspend. Idle time on it leaves out
// the hours of sleep, so a socket that died in sleep would skip the
// probe after resume. The wall clock counts the sleep (T199).
//
// arch: T199, §3.10, C24
func wallNow() time.Time { return time.Now().Round(0) }

// fresh reports whether a connection idle for d can skip the probe.
// A negative d means the wall clock stepped back (NTP, a manual
// change), so the real idle time is not known and the probe runs
// (T199).
func fresh(d time.Duration) bool { return d >= 0 && d < staleAfter }

// live gives a connection that answers. It dials when there is none
// or when the client of the one it has is closed. After staleAfter it
// sends a NOOP first. A probe that fails or gives no answer inside
// noopTimeout means a dead connection, so it dials again (C24,
// DRV.10).
//
// A failed probe writes a WARN line with the alias, the idle time and
// the probe error. When the dial after it fails too, the error gives
// the probe error and wraps the dial error (DS11.14).
//
// When ctx ended, a failed probe returns the context error and the
// probe error, and live makes no dial. A dial reads the credential
// first, and a token refresh takes no context, so it can hold e.mu for
// many seconds after the caller left (DS11.14).
//
// The caller holds e.mu.
func (p *Pool) live(ctx context.Context, e *entry, alias string) (*Conn, error) {
	var probeErr error
	if e.conn != nil {
		idle := p.now().Sub(e.last)
		switch {
		case clientGone(e.conn):
			// The socket died while the connection sat in the pool.
			// A LOGOUT cannot go out on it, so close it at once.
			_ = e.conn.Close()
			e.conn = nil
		case fresh(idle):
			return e.conn, nil
		default:
			if probeErr = p.probe(ctx, e.conn); probeErr == nil {
				e.last = p.now()
				return e.conn, nil
			}
			p.log.Warn("imap probe failed", "alias", alias, "idle", idle, "err", probeErr)
			p.closeLocked(e)
			if ctx.Err() != nil {
				return nil, fmt.Errorf("imap: probe: %w", errors.Join(ctx.Err(), probeErr))
			}
		}
	}
	// The dial function applies no pool limit here. DialAccount limits
	// the network part itself (DialTimeout), and the secret read
	// before it keeps its own limit (DRV.10).
	c, err := p.dial(ctx, alias)
	if err != nil {
		if probeErr != nil {
			return nil, fmt.Errorf("imap: redial after failed probe (%v): %w", probeErr, err)
		}
		return nil, err
	}
	e.conn = &Conn{Client: c}
	e.last = p.now()
	return e.conn, nil
}

// probe sends NOOP and waits at most noopTimeout for the answer. A
// go-imap command cannot be cancelled, so the wait runs in its own
// goroutine; the goroutine ends when the answer or the close arrives.
// A panic in the NOOP becomes an error that gives the panic value
// (DS11.14).
func (p *Pool) probe(ctx context.Context, c *Conn) error {
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("imap: noop panicked: %v", r)
			}
		}()
		done <- c.Noop().Wait()
	}()
	select {
	case err := <-done:
		return err
	case <-p.after(noopTimeout):
		_ = c.Close() // unblocks the goroutine above
		return errors.New("imap: no answer to NOOP")
	case <-ctx.Done():
		_ = c.Close()
		return ctx.Err()
	}
}

// run calls fn with the socket tied to ctx. go-imap commands take no
// context, so a cancelled ctx closes the socket and the command fails
// at once (C25).
//
// The caller holds e.mu.
func (p *Pool) run(ctx context.Context, e *entry, c *Conn, fn func(*Conn) error) error {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()

	err := fn(c)
	if ctxErr := ctx.Err(); ctxErr != nil {
		// AfterFunc closed the socket. The entry is dead.
		p.closeLocked(e)
		if err == nil {
			// fn got its answer before the end of ctx. An error here
			// makes the caller repeat a write that is done (R16-L1).
			return nil
		}
		return errors.Join(err, ctxErr)
	}
	e.last = p.now()
	return err
}

// entryFor gives the entry of alias and makes it on a first use.
func (p *Pool) entryFor(alias string) *entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[alias]
	if !ok {
		e = &entry{}
		p.entries[alias] = e
	}
	return e
}

// list gives the entries as they are now, so the reaper walks them
// without holding the pool lock.
func (p *Pool) list() []*entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*entry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e)
	}
	return out
}

// Reaper closes connections that nobody used for idleClose. It runs
// each minute until ctx ends (§3.1 step 5, §3.10). Each tick recovers
// on its own, because a background goroutine must not stop the process
// (§3.1). A tick that panics writes an ERROR line with the stack, and
// the next tick runs (DS11.14).
//
// arch: T4.2, §3.10, §3.1, C24, DS11.14
func (p *Pool) Reaper(ctx context.Context) {
	t := time.NewTicker(reapInterval)
	defer t.Stop()
	p.reap(ctx, t.C)
}

// reap runs reapTick for each value from tick until ctx ends. A test
// gives its own tick channel.
func (p *Pool) reap(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			p.reapTick()
		}
	}
}

// reapTick runs ReapOnce one time. A panic in it writes one ERROR line
// with the panic value and the stack, and reapTick returns, so the
// reaper goes on. A panic is a defect, not a normal session end, so
// this ERROR is allowed (IS11.2, DS11.14).
func (p *Pool) reapTick() {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("pool reaper panicked", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	p.ReapOnce()
}

// ReapOnce closes every connection that went idle for idleClose. It
// skips an entry that a call holds, because that call is using the
// connection right now (§3.10). A negative idle time means the wall
// clock stepped back, so the real idle time is not known; the reaper
// closes that connection too (DS11.14).
//
// arch: T4.2, §3.10, C24, DS11.14
func (p *Pool) ReapOnce() {
	for _, e := range p.list() {
		p.reapEntry(e)
	}
}

// reapEntry closes the connection of e when it went idle. It releases
// e.mu in a defer, so a panic in closeLocked does not keep e locked: a
// locked entry stops every later call for its alias and CloseAll
// (DS11.14).
func (p *Pool) reapEntry(e *entry) {
	if !e.mu.TryLock() {
		return
	}
	defer e.mu.Unlock()
	if d := p.now().Sub(e.last); e.conn != nil && (d < 0 || d >= idleClose) {
		p.closeLocked(e)
	}
}

// CloseAll ends every connection. Serve calls it at shutdown (§3.1
// step 7).
//
// arch: T4.2, §3.10, §3.1
func (p *Pool) CloseAll() {
	for _, e := range p.list() {
		e.mu.Lock()
		p.closeLocked(e)
		e.mu.Unlock()
	}
}

// closeLocked sends LOGOUT with a logoutTimeout limit and then closes
// the socket. A LOGOUT on a dead socket fails, which is normal, so that
// error is dropped. A panic in the LOGOUT becomes an error that gives
// the panic value, and closeLocked writes it in a WARN line (DS11.14).
// The caller holds e.mu.
func (p *Pool) closeLocked(e *entry) {
	c := e.conn
	e.conn = nil
	if c == nil {
		return
	}
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("imap: logout panicked: %v", r)
			}
		}()
		_ = c.Logout().Wait()
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			p.log.Warn("imap logout failed", "err", err)
		}
	case <-p.after(logoutTimeout):
	}
	_ = c.Close()
}

// connBroken reports whether the error came from a dead socket. It is
// true when the client is closed, or when the error is io.EOF,
// io.ErrUnexpectedEOF, net.ErrClosed or a net.Error. Every other error
// (a NO or BAD answer, a stale id, a bad folder, a size limit) is
// local: the socket is fine and the pool does not dial again (DRV.10,
// IRV.8).
func connBroken(c *Conn, err error) bool {
	if err == nil {
		return false
	}
	if clientGone(c) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

// clientGone reports whether the client of c is closed. go-imap sets
// the logout state before it fails the pending commands, and it closes
// the Closed channel only after that. The state check therefore sees
// a dead socket also in the moment between those two steps.
func clientGone(c *Conn) bool {
	select {
	case <-c.Closed():
		return true
	default:
	}
	return c.State() == imap.ConnStateLogout
}
