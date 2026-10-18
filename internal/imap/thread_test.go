// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// tripConn is a socket that dies when the client writes a command
// that trip matches. The write fails and the socket closes, which is
// what a connection reset looks like to the client.
type tripConn struct {
	net.Conn
	trip func([]byte) bool
}

func (c *tripConn) Write(b []byte) (int, error) {
	if c.trip(b) {
		_ = c.Close()
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

// TestThread_BrokenSocketRetried checks that a socket that dies in
// the middle of a thread search fails the run, so the pool dials
// again and runs the read once more. Before the fix the folder was
// skipped with no error: the caller got a thread with messages
// missing, and the dead connection stayed in the pool.
// arch: DRV.10
func TestThread_BrokenSocketRetried(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	head := func(subject, msgID, refs string) string {
		lines := []string{
			"From: Ann <ann@example.test>",
			"To: Bob <bob@example.test>",
			"Subject: " + subject,
			"Message-ID: " + msgID,
		}
		if refs != "" {
			lines = append(lines, "References: "+refs)
		}
		lines = append(lines, "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "", subject+" body", "")
		return strings.Join(lines, "\r\n")
	}
	f.add(
		msgSpec{raw: head("root", "<root@example.test>", "")},
		msgSpec{raw: head("reply", "<reply@example.test>", "<root@example.test>")},
	)
	v := uidValidityOf(t, f, "INBOX")

	// The first connection dies at the thread search; every later
	// connection is healthy.
	var dials atomic.Int32
	pool := NewPool(func(context.Context, string) (*imapclient.Client, error) {
		n := dials.Add(1)
		raw, err := net.Dial("tcp", f.addr)
		if err != nil {
			return nil, err
		}
		conn := raw
		if n == 1 {
			conn = &tripConn{Conn: raw, trip: func(b []byte) bool {
				return bytes.Contains(b, []byte("SEARCH")) && bytes.Contains(b, []byte("References"))
			}}
		}
		c := imapclient.New(conn, nil)
		if err := c.Login(fixtureUser, fixturePass).Wait(); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}, nil)
	t.Cleanup(pool.CloseAll)
	prov := New("acct", pool)

	// Act
	got, err := prov.Thread(context.Background(), mail.FormatIMAPID(v, 2, "INBOX"))

	// Assert
	if err != nil {
		t.Fatalf("Thread: %v", err)
	}
	var subjects []string
	for _, m := range got.Messages {
		subjects = append(subjects, m.Subject)
	}
	if !equalStrings(subjects, []string{"root", "reply"}) {
		t.Fatalf("Thread gave %v, want [root reply]: the broken socket must fail the run so the pool runs it again", subjects)
	}
	if n := dials.Load(); n != 2 {
		t.Errorf("dials = %d, want 2: one retry on a new connection", n)
	}
}

// TestThread_NoSpecialUseFindsSent checks that the thread search uses
// the role map of roles.go, which falls back to the name table when
// the server gives no SPECIAL-USE attribute (RFC 6154). Before the
// fix, threadFolderNames read the special-use attrs directly and
// never found a "Sent" folder that carries no such attr, so a reply
// this account sent never joined the thread.
// arch: DRV.19.5
func TestThread_NoSpecialUseFindsSent(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{folders: []string{"Sent"}})
	head := func(folder, subject, msgID, refs string) msgSpec {
		lines := []string{
			"From: Ann <ann@example.test>",
			"To: Bob <bob@example.test>",
			"Subject: " + subject,
			"Message-ID: " + msgID,
		}
		if refs != "" {
			lines = append(lines, "References: "+refs)
		}
		lines = append(lines, "MIME-Version: 1.0", "Content-Type: text/plain; charset=utf-8", "", subject+" body", "")
		return msgSpec{folder: folder, raw: strings.Join(lines, "\r\n")}
	}
	f.add(
		head("INBOX", "root", "<root@example.test>", ""),
		head("Sent", "reply", "<reply@example.test>", "<root@example.test>"),
	)
	v := uidValidityOf(t, f, "INBOX")

	// Act
	got, err := f.prov.Thread(context.Background(), mail.FormatIMAPID(v, 1, "INBOX"))

	// Assert
	if err != nil {
		t.Fatalf("Thread: %v", err)
	}
	var subjects []string
	for _, m := range got.Messages {
		subjects = append(subjects, m.Subject)
	}
	if !equalStrings(subjects, []string{"root", "reply"}) {
		t.Fatalf("Thread gave %v, want [root reply]: the \"Sent\" folder carries no SPECIAL-USE attr here, so it must be found by name", subjects)
	}
}

// rootCrit builds the search criteria a thread search runs once it
// has found the root id of a conversation, the same shape Thread
// builds for itself.
func rootCrit(root string) *imap.SearchCriteria {
	return &imap.SearchCriteria{Or: [][2]imap.SearchCriteria{{
		{Header: []imap.SearchCriteriaHeaderField{{Key: "Message-ID", Value: root}}},
		{Header: []imap.SearchCriteriaHeaderField{{Key: "References", Value: root}}},
	}}}
}

// noAnswerConn answers the first write that trip matches with a
// tagged NO, instead of forwarding it to the real server. The socket
// stays open and healthy throughout, so the error this produces is
// local, never connBroken (DRV.10): a test proves the skip-and-count
// path cannot mistake a real NO for a dead connection, the other way
// around from tripConn above.
//
// Read polls the real connection with a short deadline between checks
// of the synthetic answer, so the client's reader goroutine can never
// block forever on a command the real server never saw.
type noAnswerConn struct {
	net.Conn
	trip func([]byte) bool

	mu      sync.Mutex
	tripped bool
	pending []byte
}

func (c *noAnswerConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	already := c.tripped
	c.mu.Unlock()
	if !already && c.trip(b) {
		tag, _, _ := bytes.Cut(b, []byte(" "))
		c.mu.Lock()
		c.tripped = true
		c.pending = append(c.pending, tag...)
		c.pending = append(c.pending, []byte(" NO denied for this test\r\n")...)
		c.mu.Unlock()
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *noAnswerConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.pending) > 0 {
			n := copy(b, c.pending)
			c.pending = c.pending[n:]
			c.mu.Unlock()
			return n, nil
		}
		c.mu.Unlock()
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, err := c.Conn.Read(b)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return n, err
		}
		return n, err
	}
}

// TestThread_SkippedFolderCounted holds DR1G.4: a folder that gives a
// local error is skipped, not fatal, and read gets every message the
// other folders did find plus a count of what it could not check. The
// skip comes from a folder name that truly does not exist on the
// server, a real "no such mailbox" NO (confirmed against
// imapmemserver's own session.go), so the test needs no race against
// a client that must out-run a LIST report of a folder about to
// disappear.
//
// arch: DR1G.4, DR1G.5, DR1G.18, IR1G.12
func TestThread_SkippedFolderCounted(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{raw: strings.Join([]string{
		"From: Ann <ann@example.test>",
		"To: Bob <bob@example.test>",
		"Subject: root",
		"Message-ID: <root@example.test>",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"", "root body", "",
	}, "\r\n")})
	f.warm()

	var found []mail.Message
	var skipped, missing int
	err := f.pool.WithRead(context.Background(), "acct", func(c *Conn) error {
		var err error
		found, skipped, missing, err = threadSearchFolders(context.Background(), c, []string{"INBOX", "NoSuchFolder"}, rootCrit("<root@example.test>"), f.pool.log)
		return err
	})
	if err != nil {
		t.Fatalf("threadSearchFolders: %v", err)
	}
	if skipped != 1 {
		t.Errorf("Skipped = %d, want 1 for the one folder that does not exist", skipped)
	}
	if missing != 0 {
		t.Errorf("PreviewsMissing = %d, want 0", missing)
	}
	if len(found) != 1 || found[0].Subject != "root" {
		t.Fatalf("found = %v, want the one message from INBOX despite the other folder's error", found)
	}
}

// TestThread_BrokenConnIsError holds the other half of IR1G.12: a
// dead socket must stay an error, never a silent skip that a count
// could hide. tripConn kills the connection on the SEARCH of the one
// folder named, the same shape TestThread_BrokenSocketRetried uses,
// but here threadSearchFolders is called directly so the "no
// retry happened to mask it" case is checked on its own.
//
// arch: DR1G.4, DR1G.18, IR1G.12
func TestThread_BrokenConnIsError(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{raw: strings.Join([]string{
		"From: Ann <ann@example.test>",
		"To: Bob <bob@example.test>",
		"Subject: root",
		"Message-ID: <root@example.test>",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"", "root body", "",
	}, "\r\n")})
	f.warm()

	raw, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := &tripConn{Conn: raw, trip: func(b []byte) bool {
		return bytes.Contains(b, []byte("SEARCH"))
	}}
	cl := imapclient.New(conn, nil)
	if err := cl.Login(fixtureUser, fixturePass).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	c := &Conn{Client: cl}

	found, skipped, _, err := threadSearchFolders(context.Background(), c, []string{"INBOX"}, rootCrit("<root@example.test>"), f.pool.log)
	if err == nil {
		t.Fatal("threadSearchFolders gave no error for a dead socket, want one")
	}
	if !connBroken(c, err) {
		t.Errorf("err = %v, want connBroken true (DRV.10)", err)
	}
	if skipped != 0 {
		t.Errorf("Skipped = %d, want 0: a broken connection must not be counted as a folder skip (IR1G.12)", skipped)
	}
	if found != nil {
		t.Errorf("found = %v, want nil: a broken connection gives back no messages", found)
	}
}

// TestThread_PreviewsMissingCounted holds DR1G.5 and DR1G.18.3: a
// local error on the preview fetch leaves the message rows
// themselves intact and reports the count on
// mail.ThreadResult.PreviewsMissing, never as a failed search.
// noAnswerConn answers the one BODY.PEEK[] partial fetch addPreviews
// sends with a real NO, which is the only such fetch here because
// fetchRows asks for BODYSTRUCTURE and Envelope, not a body section.
//
// arch: DR1G.5, DR1G.18
func TestThread_PreviewsMissingCounted(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(msgSpec{raw: strings.Join([]string{
		"From: Ann <ann@example.test>",
		"To: Bob <bob@example.test>",
		"Subject: root",
		"Message-ID: <root@example.test>",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"", strings.Repeat("preview text ", 20), "",
	}, "\r\n")})
	f.warm()

	raw, err := net.Dial("tcp", f.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := &noAnswerConn{Conn: raw, trip: func(b []byte) bool {
		return bytes.Contains(b, []byte("BODY.PEEK["))
	}}
	cl := imapclient.New(conn, nil)
	if err := cl.Login(fixtureUser, fixturePass).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	c := &Conn{Client: cl}

	found, skipped, missing, err := threadSearchFolders(context.Background(), c, []string{"INBOX"}, rootCrit("<root@example.test>"), f.pool.log)
	if err != nil {
		t.Fatalf("threadSearchFolders: %v (a local preview-fetch error must not fail the search)", err)
	}
	if skipped != 0 {
		t.Errorf("Skipped = %d, want 0: the folder search itself succeeded", skipped)
	}
	if missing != 1 {
		t.Errorf("PreviewsMissing = %d, want 1", missing)
	}
	if len(found) != 1 || found[0].Preview != "" {
		t.Fatalf("found = %v, want the one message with no preview set", found)
	}
}
