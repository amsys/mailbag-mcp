// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// This file is the shared setup every IMAP provider test uses: a memory
// server with the folders and messages a case needs, a pool and a
// provider wired to it, and a record of the wire traffic so a test
// can check which commands went out (C1, C3, C9, C23).
//
// arch: T4.3, §3.10, C1, C3, C7, C8, C9, C23, C28

const (
	fixtureUser = "bob"
	fixturePass = "pw"
)

// fullCaps is what a modern server offers. A case that needs a poorer
// server passes its own set.
var fullCaps = imap.CapSet{
	imap.CapIMAP4rev1:    {},
	imap.CapListExtended: {},
	imap.CapListStatus:   {},
	imap.CapSpecialUse:   {},
	imap.CapESearch:      {},
	imap.CapUIDPlus:      {},
}

// noListStatusCaps is a server that answers STATUS one folder at a
// time, which is the case trap C23 is about.
var noListStatusCaps = imap.CapSet{
	imap.CapIMAP4rev1:    {},
	imap.CapListExtended: {},
	imap.CapSpecialUse:   {},
	imap.CapESearch:      {},
}

// fixtureOpts shapes one memory server.
type fixtureOpts struct {
	caps      imap.CapSet
	folders   []string // extra folders beside INBOX
	slowWrite time.Duration
	rawSearch bool
}

// fixture is a running memory server with a provider on it.
type fixture struct {
	t    *testing.T
	addr string
	user *imapmemserver.User
	wire *syncBuf
	pool *Pool
	prov *Provider
}

// newFixture starts a memory server and gives a provider that talks
// to it through a real pool, so every test runs the same code path as
// the server does.
func newFixture(t *testing.T, opts fixtureOpts) *fixture {
	t.Helper()
	if opts.caps == nil {
		opts.caps = fullCaps
	}
	mem := imapmemserver.New()
	user := imapmemserver.NewUser(fixtureUser, fixturePass)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	for _, name := range opts.folders {
		if err := user.Create(name, nil); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
	}
	mem.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			s := mem.NewSession()
			if opts.rawSearch {
				s = rawSearchSession{Session: s}
			}
			return s, nil, nil
		},
		InsecureAuth: true,
		Caps:         opts.caps,
		Logger:       discardLogger{},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if opts.slowWrite > 0 {
		ln = slowListener{Listener: ln, delay: opts.slowWrite}
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	f := &fixture{t: t, addr: addr, user: user, wire: &syncBuf{}}
	f.pool = NewPool(f.dial, nil)
	t.Cleanup(f.pool.CloseAll)
	f.prov = New("acct", f.pool)
	return f
}

// dial is the pool's DialFunc: one clear-text login to the memory
// server, with every byte copied into the wire record.
func (f *fixture) dial(context.Context, string) (*imapclient.Client, error) {
	c, err := imapclient.DialInsecure(f.addr, &imapclient.Options{DebugWriter: f.wire})
	if err != nil {
		return nil, err
	}
	if err := c.Login(fixtureUser, fixturePass).Wait(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// msgSpec is one message to put in a folder.
type msgSpec struct {
	folder  string // empty means INBOX
	from    string // empty means "Ann <ann@example.test>"
	to      string
	subject string
	date    time.Time // INTERNALDATE; zero means a fixed base time
	ctype   string    // empty means text/plain; charset=utf-8
	body    string
	raw     string // a whole message, instead of the fields above
	flags   []imap.Flag
}

// baseTime is the INTERNALDATE a spec gets when it names none.
var baseTime = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// add puts messages in the server, in the order given. UIDs follow
// that order, so the newest message has the highest UID.
func (f *fixture) add(specs ...msgSpec) {
	f.t.Helper()
	for i, s := range specs {
		folder := s.folder
		if folder == "" {
			folder = "INBOX"
		}
		when := s.date
		if when.IsZero() {
			when = baseTime.Add(time.Duration(i) * time.Minute)
		}
		raw := s.raw
		if raw == "" {
			raw = buildRaw(s, when)
		}
		_, err := f.user.Append(folder, literalOf(raw), &imap.AppendOptions{
			Time:  when,
			Flags: s.flags,
		})
		if err != nil {
			f.t.Fatalf("append to %q: %v", folder, err)
		}
	}
}

// buildRaw makes the RFC 822 text of one spec.
func buildRaw(s msgSpec, when time.Time) string {
	from := s.from
	if from == "" {
		from = "Ann <ann@example.test>"
	}
	to := s.to
	if to == "" {
		to = "Bob <bob@example.test>"
	}
	ctype := s.ctype
	if ctype == "" {
		ctype = "text/plain; charset=utf-8"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", s.subject)
	fmt.Fprintf(&b, "Date: %s\r\n", when.Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%d@example.test>\r\n", when.UnixNano())
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: %s\r\n\r\n", ctype)
	b.WriteString(s.body)
	if !strings.HasSuffix(s.body, "\r\n") {
		b.WriteString("\r\n")
	}
	return b.String()
}

// expunge removes every message that carries \Deleted from folder. It
// runs over a second connection, which is how a test makes gaps in
// the UID list (C1).
func (f *fixture) expunge(folder string) {
	f.t.Helper()
	c := f.client()
	defer func() { _ = c.Close() }()
	if _, err := c.Select(folder, nil).Wait(); err != nil {
		f.t.Fatalf("select %q: %v", folder, err)
	}
	if err := c.Expunge().Close(); err != nil {
		f.t.Fatalf("expunge %q: %v", folder, err)
	}
}

// store changes flags on one UID over a second connection, so the
// connection the provider holds knows nothing about the change (C9).
func (f *fixture) store(folder string, uid imap.UID, add []imap.Flag, remove []imap.Flag) {
	f.t.Helper()
	c := f.client()
	defer func() { _ = c.Close() }()
	if _, err := c.Select(folder, nil).Wait(); err != nil {
		f.t.Fatalf("select %q: %v", folder, err)
	}
	set := imap.UIDSetNum(uid)
	if len(add) > 0 {
		op := &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: add, Silent: true}
		if err := c.Store(set, op, nil).Close(); err != nil {
			f.t.Fatalf("store add: %v", err)
		}
	}
	if len(remove) > 0 {
		op := &imap.StoreFlags{Op: imap.StoreFlagsDel, Flags: remove, Silent: true}
		if err := c.Store(set, op, nil).Close(); err != nil {
			f.t.Fatalf("store remove: %v", err)
		}
	}
}

// client opens one extra connection outside the pool.
func (f *fixture) client() *imapclient.Client {
	f.t.Helper()
	c, err := imapclient.DialInsecure(f.addr, nil)
	if err != nil {
		f.t.Fatalf("dial: %v", err)
	}
	if err := c.Login(fixtureUser, fixturePass).Wait(); err != nil {
		f.t.Fatalf("login: %v", err)
	}
	return c
}

// warm opens a pooled connection, so the login traffic is out of the
// way before a test records the wire.
func (f *fixture) warm() {
	f.t.Helper()
	if err := f.pool.WithRead(context.Background(), "acct", noop); err != nil {
		f.t.Fatalf("warm the pool: %v", err)
	}
	f.wire.Reset()
}

// --- wire reading --------------------------------------------------

// cmdLineRE matches one client command line in the debug record. The
// record holds both directions; a server line starts with "*", "+" or
// a tag and a status word.
var cmdLineRE = regexp.MustCompile(`^[A-Za-z]+[0-9]+ ([A-Z0-9]+(?: [A-Z0-9]+)?)`)

// statusWordRE matches a tagged server answer.
var statusWordRE = regexp.MustCompile(`^[A-Za-z]+[0-9]+ (OK|NO|BAD)\b`)

// commands gives the client command lines of the wire record, without
// their tag.
func (f *fixture) commands() []string {
	var out []string
	for _, line := range strings.Split(f.wire.String(), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "+") {
			continue
		}
		if statusWordRE.MatchString(line) {
			continue
		}
		if m := cmdLineRE.FindStringSubmatch(line); m != nil {
			out = append(out, line[strings.Index(line, " ")+1:])
		}
	}
	return out
}

// countCommands counts the client commands that start with verb.
func (f *fixture) countCommands(verb string) int {
	n := 0
	for _, c := range f.commands() {
		if strings.HasPrefix(c, verb) {
			n++
		}
	}
	return n
}

// maxPipelined gives the longest run of client commands that start
// with verb and went out with no server answer in between. That run
// is the batch size the client used (C23).
func (f *fixture) maxPipelined(verb string) int {
	run, best := 0, 0
	for _, line := range strings.Split(f.wire.String(), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		isServer := strings.HasPrefix(line, "*") || strings.HasPrefix(line, "+") || statusWordRE.MatchString(line)
		switch {
		case isServer:
			best = max(best, run)
			run = 0
		case cmdLineRE.MatchString(line) && strings.Contains(line, " "+verb):
			run++
		}
	}
	return max(best, run)
}

// numSetSize counts the numbers an IMAP number set names. "3,5:8"
// gives 5. It reads the set out of a UID FETCH command line, so a
// test can prove that a fetch stayed inside one page (C28).
func numSetSize(set string) int {
	n := 0
	for _, part := range strings.Split(set, ",") {
		lo, hi, ok := strings.Cut(part, ":")
		a, errA := strconv.Atoi(strings.TrimSpace(lo))
		if !ok {
			if errA == nil {
				n++
			}
			continue
		}
		b, errB := strconv.Atoi(strings.TrimSpace(hi))
		if errA != nil || errB != nil {
			continue
		}
		if b < a {
			a, b = b, a
		}
		n += b - a + 1
	}
	return n
}

// fetchSetSizes gives the size of the number set of every UID FETCH
// command in the record.
func (f *fixture) fetchSetSizes() []int {
	var out []int
	for _, c := range f.commands() {
		rest, ok := strings.CutPrefix(c, "UID FETCH ")
		if !ok {
			continue
		}
		set, _, _ := strings.Cut(rest, " ")
		out = append(out, numSetSize(set))
	}
	return out
}

// --- server wrappers -----------------------------------------------

// rawSearchSession is a server that matches a header against its raw
// RFC 2047 text, which is what most real servers do (C7): a query
// with a non-ASCII word then finds nothing. The memory server decodes
// the header first and would find the message, so a test that needs
// the real behaviour wraps the session.
type rawSearchSession struct {
	imapserver.Session
}

func (s rawSearchSession) Search(kind imapserver.NumKind, crit *imap.SearchCriteria, opts *imap.SearchOptions) (*imap.SearchData, error) {
	if criteriaNonASCII(crit) {
		return &imap.SearchData{All: imap.UIDSet(nil)}, nil
	}
	return s.Session.Search(kind, crit, opts)
}

// criteriaNonASCII reports whether any text of the criteria holds a
// character above ASCII.
func criteriaNonASCII(crit *imap.SearchCriteria) bool {
	if crit == nil {
		return false
	}
	words := append([]string(nil), crit.Text...)
	words = append(words, crit.Body...)
	for _, h := range crit.Header {
		words = append(words, h.Value)
	}
	for _, w := range words {
		for _, r := range w {
			if r > 127 {
				return true
			}
		}
	}
	for i := range crit.Not {
		if criteriaNonASCII(&crit.Not[i]) {
			return true
		}
	}
	return false
}

// slowListener delays every byte the server sends. With the answers
// late, a pipelined batch of commands appears in the wire record as
// one run, which is what TestFolders_StatusBatches measures.
type slowListener struct {
	net.Listener
	delay time.Duration
}

func (l slowListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return slowConn{Conn: c, delay: l.delay}, nil
}

type slowConn struct {
	net.Conn
	delay time.Duration
}

func (c slowConn) Write(p []byte) (int, error) {
	time.Sleep(c.delay)
	return c.Conn.Write(p)
}

// literalOf makes an imap.LiteralReader out of a string.
func literalOf(s string) imap.LiteralReader {
	return &stringLiteral{Reader: strings.NewReader(s), size: int64(len(s))}
}

type stringLiteral struct {
	*strings.Reader
	size int64
}

func (l *stringLiteral) Size() int64 { return l.size }
