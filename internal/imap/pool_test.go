// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// --- helpers -------------------------------------------------------

// syncBuf is a buffer that go-imap may write to from its read
// goroutine and from the caller goroutine at the same time.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuf) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// fakeClock is the injected clock of C24. A test moves it by hand, so
// the 60 s, 10 s and 15 min rules run in no time.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// memServer starts an in-memory IMAP server on the loopback address
// and gives its address. The user is "bob" with the password "pw".
func memServer(t *testing.T) string { return memServerWith(t, nil, false) }

// memServerWith is memServer with a TLS setting. With a tlsCfg the
// server offers STARTTLS and refuses a login before it; with none it
// takes a login in the clear, which keeps the pool tests short. With
// implicit set, TLS starts with the connection, which is what port
// 993 means.
func memServerWith(t *testing.T, tlsCfg *tls.Config, implicit bool) string {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser("bob", "pw")
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	mem.AddUser(user)
	// A second user with a password no other text holds, so a test can
	// look for that exact word in a debug stream (B15).
	secret := imapmemserver.NewUser("carol", debugTestPassword)
	if err := secret.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	mem.AddUser(secret)
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		TLSConfig:    tlsCfg,
		InsecureAuth: tlsCfg == nil,
		Logger:       discardLogger{},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if implicit {
		ln = tls.NewListener(ln, tlsCfg)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return addr
}

type discardLogger struct{}

func (discardLogger) Printf(string, ...any) {}

// dialLog records what the pool asked for, dial by dial.
type dialLog struct {
	mu      sync.Mutex
	aliases []string
	tokens  []string
	conns   []*imapclient.Client
}

func (l *dialLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.aliases)
}

func (l *dialLog) allAliases() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.aliases...)
}

func (l *dialLog) allTokens() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.tokens...)
}

func (l *dialLog) conn(i int) *imapclient.Client {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns[i]
}

// memDialer gives a DialFunc that logs in to the memory server. token
// runs before each dial, which is how a redial reads a new access
// token (B14). wire may be nil.
func memDialer(t *testing.T, addr string, wire io.Writer, token func(n int) string, delay time.Duration) (DialFunc, *dialLog) {
	t.Helper()
	log := &dialLog{}
	return func(_ context.Context, alias string) (*imapclient.Client, error) {
		if delay > 0 {
			time.Sleep(delay)
		}
		log.mu.Lock()
		n := len(log.aliases)
		log.aliases = append(log.aliases, alias)
		log.mu.Unlock()

		tok := ""
		if token != nil {
			tok = token(n)
		}
		var opts *imapclient.Options
		if wire != nil {
			opts = &imapclient.Options{DebugWriter: wire}
		}
		c, err := imapclient.DialInsecure(addr, opts)
		if err != nil {
			return nil, err
		}
		if err := c.Login("bob", "pw").Wait(); err != nil {
			_ = c.Close()
			return nil, err
		}
		log.mu.Lock()
		log.tokens = append(log.tokens, tok)
		log.conns = append(log.conns, c)
		log.mu.Unlock()
		return c, nil
	}, log
}

// testPool makes a pool on the memory server with the fake clock in
// place.
func testPool(t *testing.T, wire io.Writer, token func(n int) string) (*Pool, *fakeClock, *dialLog) {
	t.Helper()
	addr := memServer(t)
	dial, log := memDialer(t, addr, wire, token, 0)
	p := NewPool(dial, nil)
	clk := newClock()
	p.now = clk.Now
	t.Cleanup(p.CloseAll)
	return p, clk, log
}

func isClosed(c *imapclient.Client) bool {
	select {
	case <-c.Closed():
		return true
	default:
		return false
	}
}

func waitClosed(t *testing.T, c *imapclient.Client) {
	t.Helper()
	select {
	case <-c.Closed():
	case <-time.After(3 * time.Second):
		t.Fatal("the connection is still open, want it closed")
	}
}

// noop is the smallest command a test can run on a pooled connection.
func noop(c *Conn) error { return c.Noop().Wait() }

// silentServer starts a TCP server that sends an IMAP greeting and then
// never answers. A probe on it gets no answer, so the injected NOOP
// timeout decides the probe and no real answer can race it.
func silentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func() {
				_, _ = io.WriteString(c, "* OK silent server\r\n")
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

// silentPool makes a pool on a silent server with the fake clock in
// place. Every pool timer fires at once, so a probe fails with "no
// answer to NOOP" and a LOGOUT does not wait. Dial n (from 0) fails
// with fail(n) when fail is not nil and gives an error. The int counts
// the dials.
func silentPool(t *testing.T, log *slog.Logger, fail func(n int) error) (*Pool, *fakeClock, *int) {
	t.Helper()
	addr := silentServer(t)
	dials := new(int)
	p := NewPool(func(context.Context, string) (*imapclient.Client, error) {
		n := *dials
		*dials++
		if fail != nil {
			if err := fail(n); err != nil {
				return nil, err
			}
		}
		return imapclient.DialInsecure(addr, nil)
	}, log)
	p.after = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}
	clk := newClock()
	p.now = clk.Now
	t.Cleanup(p.CloseAll)
	return p, clk, dials
}

// --- tests ---------------------------------------------------------

// TestPool_NoDialer checks that a pool built with no dialer fails
// every call instead of panicking on a nil function.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_NoDialer(t *testing.T) {
	// Arrange
	p := NewPool(nil, nil)

	// Act
	err := p.WithRead(context.Background(), "a", noop)

	// Assert
	if !errors.Is(err, ErrNoDialer) {
		t.Fatalf("WithRead error = %v, want ErrNoDialer", err)
	}
	if err := p.WithWrite(context.Background(), "a", noop); !errors.Is(err, ErrNoDialer) {
		t.Fatalf("WithWrite error = %v, want ErrNoDialer", err)
	}
}

// TestPool_ReuseWithin60s checks that a second call inside staleAfter
// reuses the connection and sends no probe.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ReuseWithin60s(t *testing.T) {
	// Arrange
	wire := &syncBuf{}
	p, clk, log := testPool(t, wire, nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	wire.Reset()
	clk.Add(59 * time.Second)

	// Act
	err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil })

	// Assert
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1", got)
	}
	if strings.Contains(wire.String(), "NOOP") {
		t.Errorf("a probe was sent inside 60 s; wire = %q", wire.String())
	}
}

// TestPool_ProbeAfter60s checks that a call after staleAfter sends
// NOOP first and then reuses the same connection.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ProbeAfter60s(t *testing.T) {
	// Arrange
	wire := &syncBuf{}
	p, clk, log := testPool(t, wire, nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	wire.Reset()
	clk.Add(61 * time.Second)

	// Act
	err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil })

	// Assert
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1: the probe answered, so no redial", got)
	}
	if !strings.Contains(wire.String(), "NOOP") {
		t.Errorf("no probe was sent after 60 s; wire = %q", wire.String())
	}
}

// TestPool_ReconnectWhenProbeFails checks that a dead socket found by
// the probe gives a new connection.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ReconnectWhenProbeFails(t *testing.T) {
	// Arrange
	p, clk, log := testPool(t, nil, nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	_ = log.conn(0).Close() // the server went away
	clk.Add(61 * time.Second)

	// Act
	err := p.WithRead(context.Background(), "a", noop)

	// Assert
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
}

// TestPool_ProbeTimeoutReconnects checks that a probe with no answer
// inside noopTimeout counts as a dead connection.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ProbeTimeoutReconnects(t *testing.T) {
	// Arrange
	p, clk, log := testPool(t, nil, nil)
	// Only the NOOP wait times out at once; LOGOUT keeps its real timer.
	p.after = func(d time.Duration) <-chan time.Time {
		if d == noopTimeout {
			ch := make(chan time.Time, 1)
			ch <- time.Time{}
			return ch
		}
		return time.After(d)
	}
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	first := log.conn(0)
	clk.Add(61 * time.Second)

	// Act
	err := p.WithRead(context.Background(), "a", noop)

	// Assert
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
	waitClosed(t, first)
}

// TestPool_IdleCloseAfter15Min checks that the reaper closes a
// connection that nobody used for idleClose.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_IdleCloseAfter15Min(t *testing.T) {
	// Arrange
	p, clk, log := testPool(t, nil, nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	first := log.conn(0)
	clk.Add(15 * time.Minute)

	// Act
	p.ReapOnce()

	// Assert
	waitClosed(t, first)
	if err := p.WithRead(context.Background(), "a", noop); err != nil {
		t.Fatalf("call after the reaper: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
}

// TestPool_UseResetsIdleTimer checks that each use moves the idle
// deadline, so a connection in steady use never gets reaped.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_UseResetsIdleTimer(t *testing.T) {
	// Arrange
	p, clk, log := testPool(t, nil, nil)
	for i := 0; i < 3; i++ {
		if err := p.WithRead(context.Background(), "a", noop); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		clk.Add(10 * time.Minute)
	}
	first := log.conn(0)

	// Act
	p.ReapOnce()

	// Assert
	if isClosed(first) {
		t.Error("the connection was closed, but it was used 10 min ago")
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1", got)
	}
}

// TestPool_ReaperSkipsBusyEntry checks that the reaper leaves a
// connection alone while a call holds it.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ReaperSkipsBusyEntry(t *testing.T) {
	// Arrange
	p, clk, log := testPool(t, nil, nil)
	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- p.WithRead(context.Background(), "a", func(*Conn) error {
			close(inside)
			<-release
			return nil
		})
	}()
	<-inside
	clk.Add(30 * time.Minute)

	// Act
	p.ReapOnce()

	// Assert
	if isClosed(log.conn(0)) {
		t.Error("the reaper closed a connection that a call was using")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("held call: %v", err)
	}
}

// TestPool_PerAliasConnections checks that each alias gets its own
// connection.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_PerAliasConnections(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)

	// Act
	for _, alias := range []string{"work", "home", "work", "home"} {
		if err := p.WithRead(context.Background(), alias, noop); err != nil {
			t.Fatalf("%s: %v", alias, err)
		}
	}

	// Assert
	got := log.allAliases()
	if len(got) != 2 {
		t.Fatalf("dials = %v, want one for each alias", got)
	}
	if log.conn(0) == log.conn(1) {
		t.Error("both aliases share one connection")
	}
}

// TestPool_ConcurrentCallersShareOneReconnect checks C24: callers
// that come together get one dial, not one each.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ConcurrentCallersShareOneReconnect(t *testing.T) {
	// Arrange
	addr := memServer(t)
	dial, log := memDialer(t, addr, nil, nil, 50*time.Millisecond)
	p := NewPool(dial, nil)
	clk := newClock()
	p.now = clk.Now
	t.Cleanup(p.CloseAll)

	// Act
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- p.WithRead(context.Background(), "a", noop)
		}()
	}
	wg.Wait()
	close(errs)

	// Assert
	for err := range errs {
		if err != nil {
			t.Fatalf("call: %v", err)
		}
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1", got)
	}
}

// TestPool_ReadRetriesOnce checks that a read runs a second time on a
// fresh connection when the socket died under it.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ReadRetriesOnce(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	runs := 0

	// Act
	err := p.WithRead(context.Background(), "a", func(c *Conn) error {
		runs++
		if runs == 1 {
			_ = c.Close()
			return errors.New("write: broken pipe")
		}
		return nil
	})

	// Assert
	if err != nil {
		t.Fatalf("WithRead: %v", err)
	}
	if runs != 2 {
		t.Errorf("fn ran %d times, want 2", runs)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
}

// TestPool_WriteNeverRetries checks that a write runs once only. A
// repeated APPEND makes a duplicate message.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_WriteNeverRetries(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	runs := 0

	// Act
	err := p.WithWrite(context.Background(), "a", func(c *Conn) error {
		runs++
		_ = c.Close()
		return errors.New("write: broken pipe")
	})

	// Assert
	if err == nil {
		t.Fatal("WithWrite gave no error, want the one from fn")
	}
	if runs != 1 {
		t.Errorf("fn ran %d times, want 1", runs)
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1", got)
	}
}

// TestPool_ServerErrorDoesNotRetry checks that a NO or BAD answer
// from the server is not a connection failure. The command gives the
// same answer a second time, so the pool must not run it again.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ServerErrorDoesNotRetry(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	runs := 0

	// Act
	err := p.WithRead(context.Background(), "a", func(*Conn) error {
		runs++
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: "mailbox does not exist"}
	})

	// Assert
	if err == nil {
		t.Fatal("WithRead gave no error, want the server error")
	}
	if runs != 1 {
		t.Errorf("fn ran %d times, want 1", runs)
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1", got)
	}
}

// TestPool_ContextCancelClosesConn checks C25: a go-imap command
// cannot be cancelled, so a cancelled context closes the socket and
// the entry is dead after it.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ContextCancelClosesConn(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errStayedOpen := errors.New("the socket stayed open under the running command")

	// Act
	err := p.WithRead(ctx, "a", func(c *Conn) error {
		cancel()
		select {
		case <-c.Closed():
			return errors.New("command failed")
		case <-time.After(3 * time.Second):
			return errStayedOpen
		}
	})

	// Assert
	if errors.Is(err, errStayedOpen) {
		t.Fatal("the cancel did not close the socket while the command was running")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want it to carry context.Canceled", err)
	}
	if !isClosed(log.conn(0)) {
		t.Error("the connection is open, want it closed by the cancel")
	}
	if err := p.WithRead(context.Background(), "a", noop); err != nil {
		t.Fatalf("call after the cancel: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2: the cancelled entry must be dropped", got)
	}
}

// TestPool_SuccessAfterCancelReportsSuccess checks a write whose
// command got its OK, but whose context ended before run looked at
// it. The write is done, so the pool reports success: an error makes
// the caller send the APPEND again and store the message twice. The
// pool still drops the connection, because the cancel closed it.
//
// arch: T4.2, §3.10, C24, C25, R16-L1
func TestPool_SuccessAfterCancelReportsSuccess(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Act
	err := p.WithWrite(ctx, "a", func(c *Conn) error {
		if err := c.Noop().Wait(); err != nil {
			return err
		}
		cancel() // the OK is in; the context ends after it
		return nil
	})

	// Assert
	if err != nil {
		t.Fatalf("error = %v, want nil: the command got its OK", err)
	}
	waitClosed(t, log.conn(0))
	if err := p.WithRead(context.Background(), "a", noop); err != nil {
		t.Fatalf("call after the cancel: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2: the cancelled entry must be dropped", got)
	}
}

// TestPool_RedialGetsFreshToken checks B14: an access token ends after
// about an hour and the server then closes the connection. The pool
// must ask the dialer again, so the dialer reads a new token. A pool
// that kept the first credential would send the dead token forever.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_RedialGetsFreshToken(t *testing.T) {
	// Arrange
	tokens := []string{"token-hour-1", "token-hour-2"}
	p, clk, log := testPool(t, nil, func(n int) string { return tokens[n] })
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	_ = log.conn(0).Close() // the server dropped us when the token died
	clk.Add(61 * time.Minute)

	// Act
	err := p.WithRead(context.Background(), "a", noop)

	// Assert
	if err != nil {
		t.Fatalf("call after the token ended: %v", err)
	}
	got := log.allTokens()
	if len(got) != 2 || got[0] != tokens[0] || got[1] != tokens[1] {
		t.Fatalf("tokens = %v, want %v", got, tokens)
	}
}

// TestPool_CloseAllEndsEveryConnection checks the shutdown step of
// §3.1.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_CloseAllEndsEveryConnection(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	for _, alias := range []string{"work", "home"} {
		if err := p.WithRead(context.Background(), alias, noop); err != nil {
			t.Fatalf("%s: %v", alias, err)
		}
	}

	// Act
	p.CloseAll()

	// Assert
	waitClosed(t, log.conn(0))
	waitClosed(t, log.conn(1))
	if err := p.WithRead(context.Background(), "work", noop); err != nil {
		t.Fatalf("call after CloseAll: %v", err)
	}
	if got := log.count(); got != 3 {
		t.Errorf("dials = %d, want 3", got)
	}
}

// TestPool_ReaperStopsWithContext checks that the reaper goroutine
// ends when the server context ends (§3.1 step 5).
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_ReaperStopsWithContext(t *testing.T) {
	// Arrange
	p := NewPool(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Reaper(ctx); close(done) }()

	// Act
	cancel()

	// Assert
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the reaper is still running after the context ended")
	}
}

// TestPool_DialErrorReachesCaller checks that a dial failure is the
// error the caller gets, and that the pool keeps no broken entry.
// arch: T4.2, §3.10, §3.1, C24, C25, C26, C27, B14, B15
func TestPool_DialErrorReachesCaller(t *testing.T) {
	// Arrange
	want := errors.New("no route to host")
	calls := 0
	p := NewPool(func(context.Context, string) (*imapclient.Client, error) {
		calls++
		return nil, want
	}, nil)

	// Act
	err := p.WithRead(context.Background(), "a", noop)

	// Assert
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if err := p.WithRead(context.Background(), "a", noop); !errors.Is(err, want) {
		t.Fatalf("second error = %v, want %v", err, want)
	}
	if calls != 2 {
		t.Errorf("dials = %d, want 2: a failed dial leaves no entry behind", calls)
	}
}

// TestPool_NoRedialOnLocalError checks IRV.8: an error that fn made
// on a live socket (a stale id, a bad folder, a size limit) goes back
// to the caller once. The pool does not log out, dial again or run fn
// a second time, and the next call uses the same connection.
// arch: DRV.10
func TestPool_NoRedialOnLocalError(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	local := errors.New("imap: no message with uid 7 in this folder; search again")
	runs := 0

	// Act
	err := p.WithRead(context.Background(), "a", func(*Conn) error {
		runs++
		return local
	})

	// Assert
	if !errors.Is(err, local) {
		t.Fatalf("WithRead error = %v, want the local error", err)
	}
	if runs != 1 {
		t.Errorf("fn ran %d times, want 1: a local error is not a dead socket", runs)
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1: a local error costs no new connection", got)
	}
	if err := p.WithRead(context.Background(), "a", noop); err != nil {
		t.Fatalf("next call: %v", err)
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials after the next call = %d, want 1: the connection stays in use", got)
	}
}

// TestPool_ClosedConnNotReused checks that live() does not give out a
// connection whose socket closed while it sat in the pool, also inside
// staleAfter when no probe runs. A write gets no second run, so a
// closed connection given to it loses the write.
// arch: DRV.10
func TestPool_ClosedConnNotReused(t *testing.T) {
	// Arrange
	p, _, log := testPool(t, nil, nil)
	if err := p.WithRead(context.Background(), "a", noop); err != nil {
		t.Fatalf("first call: %v", err)
	}
	first := log.conn(0)
	_ = first.Close()
	runs := 0

	// Act
	err := p.WithWrite(context.Background(), "a", func(c *Conn) error {
		runs++
		if c.Client == first {
			return errors.New("the pool gave out the closed connection")
		}
		return c.Noop().Wait()
	})

	// Assert
	if err != nil {
		t.Fatalf("WithWrite: %v", err)
	}
	if runs != 1 {
		t.Errorf("fn ran %d times, want 1", runs)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2: a closed connection needs a new one", got)
	}
}

// TestNewPool_ClockIsWallOnly checks that the pool clock carries no
// monotonic reading. On Linux the monotonic clock stops during
// suspend, so idle time measured on it leaves out the hours of sleep,
// and a socket that died in sleep looks fresh after resume (T199).
// arch: T199, §3.10, C24
func TestNewPool_ClockIsWallOnly(t *testing.T) {
	// Arrange
	p := NewPool(nil, nil)

	// Act
	now := p.now()

	// Assert
	if now != now.Round(0) {
		t.Errorf("pool clock %v has a monotonic reading; idle time would skip a suspend", now)
	}
}

// TestPool_ProbeWhenClockStepsBack checks that a wall clock that steps
// back (NTP, a manual change) does not make an old connection look
// fresh: a negative idle time gets the probe (T199).
// arch: T199, §3.10, C24
func TestPool_ProbeWhenClockStepsBack(t *testing.T) {
	// Arrange
	wire := &syncBuf{}
	p, clk, log := testPool(t, wire, nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	wire.Reset()
	clk.Add(-time.Hour)

	// Act
	err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil })

	// Assert
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := log.count(); got != 1 {
		t.Errorf("dials = %d, want 1: the probe answered, so no redial", got)
	}
	if !strings.Contains(wire.String(), "NOOP") {
		t.Errorf("no probe was sent after the clock stepped back; wire = %q", wire.String())
	}
}

// TestPool_ProbeFailureIsLogged checks that a failed probe writes one
// WARN line with the alias, the idle time and the probe error. Without
// it, a socket that died in a suspend costs a call noopTimeout and
// leaves no record (T199 review item 1).
// arch: DS11.14, DS11.18
func TestPool_ProbeFailureIsLogged(t *testing.T) {
	// Arrange
	logs := &syncBuf{}
	p, clk, dials := silentPool(t, slog.New(slog.NewTextHandler(logs, nil)), nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	clk.Add(61 * time.Second)

	// Act
	err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil })

	// Assert
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if *dials != 2 {
		t.Errorf("dials = %d, want 2: the probe failed, so the pool dials again", *dials)
	}
	got := logs.String()
	for _, want := range []string{
		"level=WARN",
		`msg="imap probe failed"`,
		"alias=a",
		"idle=1m1s",
		`err="imap: no answer to NOOP"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log does not hold %s; log = %q", want, got)
		}
	}
}

// TestPool_RedialErrorNamesProbe checks that when the dial after a
// failed probe fails too, the error gives the probe error and wraps the
// dial error, so the caller sees both causes.
// arch: DS11.14, DS11.18
func TestPool_RedialErrorNamesProbe(t *testing.T) {
	// Arrange
	dialErr := errors.New("dial tcp: connect: network is unreachable")
	p, clk, dials := silentPool(t, nil, func(n int) error {
		if n == 1 {
			return dialErr
		}
		return nil
	})
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	clk.Add(61 * time.Second)

	// Act
	err := p.WithRead(context.Background(), "a", noop)

	// Assert
	if !errors.Is(err, dialErr) {
		t.Fatalf("error = %v, want it to wrap the dial error", err)
	}
	const want = "imap: redial after failed probe (imap: no answer to NOOP): "
	if !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error = %q, want the prefix %q", err.Error(), want)
	}
	if *dials != 2 {
		t.Errorf("dials = %d, want 2", *dials)
	}
}

// TestPool_ReaperClosesOnClockStepBack checks that the reaper closes a
// connection whose idle time is negative. A wall clock that stepped
// back hides the real idle time; without this rule an unused socket
// stays open for the size of the step plus idleClose.
// arch: DS11.14, DS11.18
func TestPool_ReaperClosesOnClockStepBack(t *testing.T) {
	// Arrange
	p, clk, log := testPool(t, nil, nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	first := log.conn(0)
	clk.Add(-time.Hour)

	// Act
	p.ReapOnce()

	// Assert
	waitClosed(t, first)
	if err := p.WithRead(context.Background(), "a", noop); err != nil {
		t.Fatalf("call after the reaper: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
}

// TestPool_LiveStopsAtContextEnd checks that a probe that fails after
// the context ended gives the context error and makes no new dial. A
// dial reads the credential first, and a token refresh takes no
// context, so a dial at this point can hold the entry lock for many
// seconds after the caller left (T199 review item 5). The failed
// connection is still dropped, so the next call dials. A context end
// is a normal session end, so the pool writes the probe failure at
// WARN and writes no ERROR line (IS11.2).
// arch: DS11.14, IS11.2
func TestPool_LiveStopsAtContextEnd(t *testing.T) {
	// Arrange
	logs := &syncBuf{}
	p, clk, dials := silentPool(t, slog.New(slog.NewTextHandler(logs, nil)), nil)
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	clk.Add(61 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Act
	err := p.WithRead(ctx, "a", func(*Conn) error { return nil })

	// Assert
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want it to carry context.Canceled", err)
	}
	if !strings.HasPrefix(err.Error(), "imap: probe: ") {
		t.Errorf("error = %q, want the prefix %q", err.Error(), "imap: probe: ")
	}
	if *dials != 1 {
		t.Errorf("dials = %d, want 1: the context ended, so the pool must not dial", *dials)
	}
	if err := p.WithRead(context.Background(), "a", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("call after the context end: %v", err)
	}
	if *dials != 2 {
		t.Errorf("dials = %d, want 2: the failed connection must be dropped", *dials)
	}
	got := logs.String()
	if !strings.Contains(got, `level=WARN msg="imap probe failed" alias=a`) {
		t.Errorf("log has no WARN line for the failed probe; log = %q", got)
	}
	if strings.Contains(got, "level=ERROR") {
		t.Errorf("log has an ERROR line for a normal session end (IS11.2); log = %q", got)
	}
}

// TestPool_ReaperSurvivesPanic checks that one panic in a reaper tick
// does not end the reaper. The entry "bad" holds a connection with no
// client, so its LOGOUT and its close panic. The tick writes one ERROR
// line with the panic and the stack, and the next tick still closes the
// idle connection of "good". The alias "bad" works again after it, so
// the panic left no entry locked (T199 review item 7). The panic line
// is the only ERROR line: the normal reap of "good", the stop of the
// reaper at the context end and CloseAll write no ERROR line (IS11.2).
// arch: DS11.14, IS11.2
func TestPool_ReaperSurvivesPanic(t *testing.T) {
	// Arrange
	logs := &syncBuf{}
	addr := memServer(t)
	dial, dlog := memDialer(t, addr, nil, nil, 0)
	p := NewPool(dial, slog.New(slog.NewTextHandler(logs, nil)))
	clk := newClock()
	p.now = clk.Now
	if err := p.WithRead(context.Background(), "good", func(*Conn) error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	good := dlog.conn(0)
	bad := p.entryFor("bad")
	bad.conn = &Conn{} // no client: LOGOUT and close panic
	bad.last = clk.Now().Add(-2 * idleClose)
	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { p.reap(ctx, tick); close(stopped) }()
	send := func() {
		t.Helper()
		select {
		case tick <- time.Time{}:
		case <-time.After(3 * time.Second):
			t.Fatal("the reaper takes no tick: it ended")
		}
	}

	// Act
	send() // first tick: "bad" panics; "good" is not idle yet
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "pool reaper panicked") {
		if time.Now().After(deadline) {
			t.Fatalf("no panic line after the first tick; log = %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	clk.Add(idleClose)
	send() // next tick: "good" is idle now

	// Assert
	waitClosed(t, good)
	got := logs.String()
	for _, want := range []string{
		"level=ERROR",
		`msg="pool reaper panicked"`,
		"panic=\"runtime error: invalid memory address or nil pointer dereference\"",
		`stack="goroutine `,
		"runtime/debug.Stack",
		`err="imap: logout panicked: runtime error: invalid memory address or nil pointer dereference"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log does not hold %s; log = %q", want, got)
		}
	}
	if n := strings.Count(got, "pool reaper panicked"); n != 1 {
		t.Errorf("panic lines = %d, want 1: the entry has no connection after the first tick", n)
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("the reaper is still running after the context ended")
	}
	called := make(chan error, 1)
	go func() { called <- p.WithRead(context.Background(), "bad", noop) }()
	select {
	case err := <-called:
		if err != nil {
			t.Fatalf("call on the alias whose reap panicked: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a call on the alias whose reap panicked still waits: the panic left the entry locked")
	}
	p.CloseAll()
	if got := logs.String(); strings.Count(got, "level=ERROR") != 1 {
		t.Errorf("ERROR lines = %d, want 1: only the panic is a defect (IS11.2); log = %q",
			strings.Count(got, "level=ERROR"), got)
	}
}

// TestPool_ProbePanicGivesValue checks that a panic in the NOOP of a
// probe becomes an error that gives the panic value. Before, the error
// said only "imap: noop panicked" (T199 review item 7).
// arch: DS11.14
func TestPool_ProbePanicGivesValue(t *testing.T) {
	// Arrange
	p := NewPool(nil, nil)

	// Act
	err := p.probe(context.Background(), &Conn{}) // no client: NOOP panics

	// Assert
	const want = "imap: noop panicked: runtime error: invalid memory address or nil pointer dereference"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
}
