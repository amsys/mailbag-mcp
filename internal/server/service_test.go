// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Service and its sessions: two sessions share one IMAP
// login, and no normal session end writes an ERROR line (DS11.2).

package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/tools"
)

// newTestService builds a Service on the config and state directories
// that the test set in its environment. The log goes to the returned
// buffer, in the text form of server.log. The cleanup closes the
// Service.
func newTestService(t *testing.T) (*Service, *lockedBuf) {
	t.Helper()
	logBuf := &lockedBuf{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))
	svc, err := NewService(context.Background(), "test", logger)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(svc.Close)
	return svc, logBuf
}

// startSession runs svc.Session on serverEnd in a goroutine and gives
// a channel that receives its result.
func startSession(ctx context.Context, svc *Service, serverEnd io.ReadWriteCloser) <-chan error {
	done := make(chan error, 1)
	go func() { done <- svc.Session(ctx, serverEnd) }()
	return done
}

// connectClient connects an MCP client to a new session of svc over
// net.Pipe. It gives the client session, the client end of the pipe
// and the channel of the Session result.
func connectClient(ctx, sessionCtx context.Context, t *testing.T, svc *Service) (*mcp.ClientSession, net.Conn, <-chan error) {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	done := startSession(sessionCtx, svc, serverEnd)
	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	cs, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientEnd, Writer: clientEnd}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, clientEnd, done
}

// waitSession waits for the result of one Session call.
func waitSession(t *testing.T, what string, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: Session did not return", what)
		return nil
	}
}

// waitLive waits until svc has want live sessions.
func waitLive(t *testing.T, svc *Service, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n, _ := svc.Live()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Live() = %d sessions, want %d", n, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// listFolders calls the folders tool on account "work" and checks
// that the result names INBOX.
func listFolders(ctx context.Context, t *testing.T, cs *mcp.ClientSession, who string) {
	t.Helper()
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "folders", Arguments: map[string]any{"account": "work"}})
	if err != nil {
		t.Fatalf("%s: folders: %v", who, err)
	}
	if res.IsError {
		t.Fatalf("%s: folders failed: %s", who, resultText(res))
	}
	var out tools.FoldersOut
	decodeStructured(t, res, &out)
	for _, f := range out.Folders {
		if f.Name == "INBOX" {
			return
		}
	}
	t.Fatalf("%s: folders = %+v, want INBOX in the list", who, out.Folders)
}

// TestService_TwoSessionsOneLogin checks the acceptance of S11: the
// first tool call of a second session makes no new IMAP login. One
// Service serves two sessions over net.Pipe at the same time. Each
// calls folders on the same account against the in-process IMAP
// server of newSendStack, and that server counts one login in all.
// When both clients are gone, no session is live.
//
// arch: DS11.1, DS11.2, DS11.16, IS11.2
func TestService_TwoSessionsOneLogin(t *testing.T) {
	stack := newSendStack(t)
	svc, logBuf := newTestService(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first, _, firstDone := connectClient(ctx, ctx, t, svc)
	listFolders(ctx, t, first, "first session")
	if got := stack.loginCount(); got != 1 {
		t.Fatalf("after the first session's call the IMAP server saw %d logins, want 1", got)
	}

	second, _, secondDone := connectClient(ctx, ctx, t, svc)
	waitLive(t, svc, 2)
	listFolders(ctx, t, second, "second session")
	if got := stack.loginCount(); got != 1 {
		t.Errorf("after the second session's call the IMAP server saw %d logins, want 1: the second session must use the pool connection of the first (G4)", got)
	}

	beforeEnd := time.Now().Round(0)
	if err := first.Close(); err != nil {
		t.Fatalf("close first client: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second client: %v", err)
	}
	if err := waitSession(t, "first session", firstDone); err != nil {
		t.Errorf("first Session = %v, want nil for a normal end", err)
	}
	if err := waitSession(t, "second session", secondDone); err != nil {
		t.Errorf("second Session = %v, want nil for a normal end", err)
	}
	n, idleAt := svc.Live()
	if n != 0 {
		t.Errorf("Live() = %d sessions after both clients closed, want 0", n)
	}
	if idleAt.Before(beforeEnd) {
		t.Errorf("Live() idle time %v is before the sessions ended (%v)", idleAt, beforeEnd)
	}
	if log := logBuf.String(); strings.Count(log, "reason="+endPeerClosed) != 2 {
		t.Errorf("log = %q, want two session ends with reason=%s", log, endPeerClosed)
	}
}

// pipePair is one end of two os.Pipe pairs: what a process sees as
// its stdin and its stdout.
type pipePair struct {
	in  *os.File
	out *os.File
}

func (p pipePair) Read(b []byte) (int, error)  { return p.in.Read(b) }
func (p pipePair) Write(b []byte) (int, error) { return p.out.Write(b) }
func (p pipePair) Close() error                { return errors.Join(p.in.Close(), p.out.Close()) }

// TestService_SessionEndNeverLogsError checks that a normal session
// end writes no ERROR line, and that each end gets its reason (IS11.2):
//
//   - the peer closes while a call is in flight (the folders call
//     waits on an IMAP server that never greets): peer-gone;
//   - the peer closes its side, as at stdin EOF: peer-closed;
//   - the session ctx ends: shutdown.
//
// Session returns nil in each case. Server.Run wrote "server run
// cancelled" at ERROR for a ctx end; Connect plus Wait does not
// (DS11.16).
//
// arch: DS11.1, DS11.2, DS11.16, IS11.2
func TestService_SessionEndNeverLogsError(t *testing.T) {
	// An IMAP server that takes the connection and never sends its
	// greeting, so a dial to it waits until its ctx ends.
	quiet, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var connsMu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = quiet.Close()
		connsMu.Lock()
		defer connsMu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	dialed := make(chan struct{}, 1)
	go func() {
		for {
			c, err := quiet.Accept()
			if err != nil {
				return
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			select {
			case dialed <- struct{}{}:
			default:
			}
		}
	}()

	configDir := t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", configDir)
	t.Setenv("MAILBAG_STATE_DIR", t.TempDir())
	toml := `secrets = "file"

[accounts.work]
provider = "imap"
email    = "me@example.test"
username = "bob"
imap     = "` + quiet.Addr().String() + `"
`
	if err := os.WriteFile(filepath.Join(configDir, "accounts.toml"), []byte(toml), 0o600); err != nil {
		t.Fatalf("write accounts.toml: %v", err)
	}
	secret := `{"kind":"password","username":"bob","password":"pw"}`
	if err := os.WriteFile(filepath.Join(configDir, "work"), []byte(secret), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	svc, logBuf := newTestService(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("peer closes mid-call", func(t *testing.T) {
		cs, clientEnd, done := connectClient(ctx, ctx, t, svc)
		callDone := make(chan error, 1)
		go func() {
			_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "folders", Arguments: map[string]any{"account": "work"}})
			callDone <- err
		}()
		select {
		case <-dialed: // the call is in flight: its dial waits for the greeting
		case <-time.After(10 * time.Second):
			t.Fatal("the folders call never dialed the IMAP server")
		}
		if err := clientEnd.Close(); err != nil {
			t.Fatalf("close the client end: %v", err)
		}
		if err := waitSession(t, "mid-call close", done); err != nil {
			t.Errorf("Session = %v, want nil for a peer that went away", err)
		}
		select {
		case <-callDone:
		case <-time.After(10 * time.Second):
			t.Fatal("the client call did not end after its connection closed")
		}
		if log := logBuf.String(); !strings.Contains(log, "reason="+endPeerGone) {
			t.Errorf("log = %q, want a session end with reason=%s", log, endPeerGone)
		}
	})

	t.Run("stdin EOF", func(t *testing.T) {
		serverIn, clientOut, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		clientIn, serverOut, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe: %v", err)
		}
		done := startSession(ctx, svc, pipePair{in: serverIn, out: serverOut})
		client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
		cs, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientIn, Writer: clientOut}, nil)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		if err := cs.Close(); err != nil { // closes clientOut: the server reads EOF
			t.Fatalf("client close: %v", err)
		}
		if err := waitSession(t, "stdin EOF", done); err != nil {
			t.Errorf("Session = %v, want nil at stdin EOF", err)
		}
		if log := logBuf.String(); !strings.Contains(log, "reason="+endPeerClosed) {
			t.Errorf("log = %q, want a session end with reason=%s", log, endPeerClosed)
		}
	})

	t.Run("ctx cancel", func(t *testing.T) {
		sessionCtx, endSession := context.WithCancel(ctx)
		defer endSession()
		_, _, done := connectClient(ctx, sessionCtx, t, svc)
		waitLive(t, svc, 1)
		endSession()
		if err := waitSession(t, "ctx cancel", done); err != nil {
			t.Errorf("Session = %v, want nil when its ctx ends", err)
		}
		if log := logBuf.String(); !strings.Contains(log, "reason="+endShutdown) {
			t.Errorf("log = %q, want a session end with reason=%s", log, endShutdown)
		}
	})

	if n, _ := svc.Live(); n != 0 {
		t.Errorf("Live() = %d sessions after every session ended, want 0", n)
	}
	log := logBuf.String()
	if strings.Contains(log, "level=ERROR") {
		t.Errorf("a normal session end wrote an ERROR line (IS11.2); log = %q", log)
	}
	if strings.Contains(log, "reason="+endTransportError) {
		t.Errorf("a normal session end was logged as %s; log = %q", endTransportError, log)
	}
}
