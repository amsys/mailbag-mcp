// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// folderByName finds one row of a folder list.
func folderByName(t *testing.T, list []mail.Folder, name string) mail.Folder {
	t.Helper()
	for _, f := range list {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no folder %q in %v", name, list)
	return mail.Folder{}
}

// TestFolders_StatusBatches checks trap C23: a server without
// LIST-STATUS gets one STATUS for each folder, and the commands go
// out in batches of statusBatch, never as one long run. A server with
// LIST-STATUS gets no STATUS command at all, because the counts come
// with the LIST answer.
//
// The memory server answers late (slowWrite), so a batch that the
// client pipelined shows up in the wire record as one run of commands
// with no answer in between. Without the batch rule the whole list
// would go out as one run.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestFolders_StatusBatches(t *testing.T) {
	t.Parallel()
	names := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("Folder%02d", i))
	}

	t.Run("no LIST-STATUS: one STATUS per folder, in batches", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{
			caps:      noListStatusCaps,
			folders:   names,
			slowWrite: 3 * time.Millisecond,
		})
		f.add(msgSpec{subject: "one"}, msgSpec{subject: "two", flags: []imap.Flag{imap.FlagSeen}})
		f.warm()

		list, err := f.prov.Folders(context.Background())
		if err != nil {
			t.Fatalf("Folders: %v", err)
		}
		if len(list) != len(names)+1 {
			t.Fatalf("Folders gave %d rows, want %d", len(list), len(names)+1)
		}
		if got := f.countCommands("STATUS "); got != len(names)+1 {
			t.Fatalf("the wire holds %d STATUS commands, want %d (one for each folder)", got, len(names)+1)
		}
		run := f.maxPipelined("STATUS ")
		if run != statusBatch {
			t.Fatalf("the longest run of STATUS commands with no answer is %d, want %d (C23)", run, statusBatch)
		}
		inbox := folderByName(t, list, "INBOX")
		if inbox.Total != 2 || inbox.Unread != 1 {
			t.Fatalf("INBOX total=%d unread=%d, want 2 and 1", inbox.Total, inbox.Unread)
		}
	})

	t.Run("LIST-STATUS: no STATUS command", func(t *testing.T) {
		f := newFixture(t, fixtureOpts{folders: names})
		f.add(msgSpec{subject: "one"}, msgSpec{subject: "two", flags: []imap.Flag{imap.FlagSeen}})
		f.warm()

		list, err := f.prov.Folders(context.Background())
		if err != nil {
			t.Fatalf("Folders: %v", err)
		}
		if got := f.countCommands("STATUS "); got != 0 {
			t.Fatalf("the wire holds %d STATUS commands, want none: LIST-STATUS carries the counts (C23)", got)
		}
		inbox := folderByName(t, list, "INBOX")
		if inbox.Total != 2 || inbox.Unread != 1 {
			t.Fatalf("INBOX total=%d unread=%d, want 2 and 1", inbox.Total, inbox.Unread)
		}
		if inbox.Role != "inbox" {
			t.Fatalf("INBOX role = %q, want %q", inbox.Role, "inbox")
		}
	})
}

// TestIMAP_UnreadCountIsLive checks trap C9: the counts that come
// with EXAMINE go stale, and a server may answer STATUS on the
// selected mailbox from that same stale state. So the folder that is
// open on the connection gets a live UID SEARCH.
//
// The test opens INBOX with a search, then marks a message read over
// a second connection. A count taken from the first EXAMINE, or
// cached from it, would still say two unread.
//
// arch: T4.3, §3.9, §3.10, §3.8, C1, C3, C7, C8, C9, C23, C28, §10.8
func TestIMAP_UnreadCountIsLive(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{})
	f.add(
		msgSpec{subject: "first"},
		msgSpec{subject: "second"},
		msgSpec{subject: "third", flags: []imap.Flag{imap.FlagSeen}},
	)

	// The search opens INBOX read only and leaves it selected.
	if _, err := f.prov.Search(context.Background(), mail.Query{Folder: "INBOX"}); err != nil {
		t.Fatalf("Search: %v", err)
	}

	before, err := f.prov.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if got := folderByName(t, before, "INBOX").Unread; got != 2 {
		t.Fatalf("INBOX unread = %d, want 2", got)
	}

	// Another client reads one message. The pooled connection has no
	// way to know.
	f.store("INBOX", imap.UID(1), []imap.Flag{imap.FlagSeen}, nil)

	f.wire.Reset()
	after, err := f.prov.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if got := folderByName(t, after, "INBOX").Unread; got != 1 {
		t.Fatalf("INBOX unread = %d after another client read a message, want 1 (C9)", got)
	}
	if f.countCommands("UID SEARCH") == 0 {
		t.Fatalf("the selected folder got no live UID SEARCH; commands were %v", f.commands())
	}
	if f.countCommands("STATUS \"INBOX\"") != 0 {
		t.Fatalf("the selected folder got a STATUS; C9 forbids it. commands: %v", f.commands())
	}
}

// TestFolders_SpecialUseRole checks that a role comes off the
// special-use attribute, not off a guess about the name. The memory
// server gives no special-use attributes, so this case covers the
// name of INBOX and the empty role of a plain folder; the name table
// and the config table arrive with T4.4.
//
// arch: T4.3, §3.10, C10
func TestFolders_SpecialUseRole(t *testing.T) {
	t.Parallel()
	f := newFixture(t, fixtureOpts{folders: []string{"Projects"}})
	list, err := f.prov.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if got := folderByName(t, list, "INBOX").Role; got != "inbox" {
		t.Fatalf("INBOX role = %q, want %q", got, "inbox")
	}
	if got := folderByName(t, list, "Projects").Role; got != "" {
		t.Fatalf("Projects role = %q, want none", got)
	}
}

// --- folder writes (T5.5) ------------------------------------------

// nsCaps is a server that answers NAMESPACE. fullCaps does not hold
// the capability, so a case that wants the prefix rule asks for this
// set.
var nsCaps = imap.CapSet{
	imap.CapIMAP4rev1:    {},
	imap.CapListExtended: {},
	imap.CapListStatus:   {},
	imap.CapSpecialUse:   {},
	imap.CapESearch:      {},
	imap.CapUIDPlus:      {},
	imap.CapNamespace:    {},
}

// nsSession is a server whose personal namespace has a prefix and a
// delimiter of its own. The memory server always answers "" and "/",
// and trap C11 is about the servers that do not.
type nsSession struct {
	imapserver.Session
	data imap.NamespaceData
}

func (s nsSession) Namespace() (*imap.NamespaceData, error) { return &s.data, nil }

// nsFixture is a memory server behind nsSession, with a write
// provider on it. It is not newFixture, because the session wrapper
// must go in before the server starts and fixtureOpts has no field
// for it.
type nsFixture struct {
	user *imapmemserver.User
	pool *Pool
	prov *Provider
	w    *WriteProvider
}

// newNSFixture starts a server whose personal namespace is prefix
// and delim.
func newNSFixture(t *testing.T, prefix string, delim rune, folders ...string) *nsFixture {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser(fixtureUser, fixturePass)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	for _, name := range folders {
		if err := user.Create(name, nil); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
	}
	mem.AddUser(user)

	data := imap.NamespaceData{Personal: []imap.NamespaceDescriptor{{Prefix: prefix, Delim: delim}}}
	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return nsSession{Session: mem.NewSession(), data: data}, nil, nil
		},
		InsecureAuth: true,
		Caps:         nsCaps,
		Logger:       discardLogger{},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	pool := NewPool(func(context.Context, string) (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return nil, err
		}
		if err := c.Login(fixtureUser, fixturePass).Wait(); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}, nil)
	t.Cleanup(pool.CloseAll)

	f := &nsFixture{user: user, pool: pool, prov: New("acct", pool)}
	f.w = NewWriter("acct", pool, config.Account{Alias: "acct", Email: "bob@example.test"}, nil, nil)
	f.w.Provider = f.prov
	return f
}

// specialUseTree is the folder tree of one specialUseFixture: each
// folder name with the special-use attributes it carries. The
// sessions of every connection share one tree, so a create or a
// delete on one connection shows on the next LIST of another.
type specialUseTree struct {
	mu    sync.Mutex
	attrs map[string][]imap.MailboxAttr
}

func (t *specialUseTree) names() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.attrs))
	for name := range t.attrs {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (t *specialUseTree) attrsOf(name string) []imap.MailboxAttr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.attrs[name]
}

func (t *specialUseTree) put(name string, attrs []imap.MailboxAttr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.attrs[name] = attrs
}

func (t *specialUseTree) drop(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attrs, name)
}

// specialUseSession is a server that follows RFC 6154: it gives the
// special-use attributes of a folder only when the LIST asks for them
// with RETURN (SPECIAL-USE). Many real servers do this, and trap C11
// is about them.
//
// It answers LIST from its own tree, because the memory server drops
// CreateOptions.SpecialUse and so can never carry a role that comes
// from an attribute alone.
type specialUseSession struct {
	imapserver.Session
	tree *specialUseTree
}

func (s specialUseSession) List(w *imapserver.ListWriter, _ string, _ []string, options *imap.ListOptions) error {
	for _, name := range s.tree.names() {
		data := &imap.ListData{Mailbox: name, Delim: '/'}
		if options != nil && options.ReturnSpecialUse {
			data.Attrs = append(data.Attrs, s.tree.attrsOf(name)...)
		}
		if err := w.WriteList(data); err != nil {
			return err
		}
	}
	return nil
}

// Create and Delete keep the tree and the memory server in step, so a
// LIST after a write tells the truth.
func (s specialUseSession) Create(name string, options *imap.CreateOptions) error {
	if err := s.Session.Create(name, options); err != nil {
		return err
	}
	s.tree.put(name, nil)
	return nil
}

func (s specialUseSession) Delete(name string) error {
	if err := s.Session.Delete(name); err != nil {
		return err
	}
	s.tree.drop(name)
	return nil
}

// newSpecialUseFixture starts a server behind specialUseSession with
// INBOX and the named folders, and gives a write provider on it. It
// is not newFixture, because the session wrapper must go in before
// the server starts and fixtureOpts has no field for it.
func newSpecialUseFixture(t *testing.T, folders map[string][]imap.MailboxAttr) *nsFixture {
	t.Helper()
	tree := &specialUseTree{attrs: map[string][]imap.MailboxAttr{"INBOX": nil}}
	mem := imapmemserver.New()
	user := imapmemserver.NewUser(fixtureUser, fixturePass)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	for name, attrs := range folders {
		if err := user.Create(name, nil); err != nil {
			t.Fatalf("create %q: %v", name, err)
		}
		tree.put(name, attrs)
	}
	mem.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return specialUseSession{Session: mem.NewSession(), tree: tree}, nil, nil
		},
		InsecureAuth: true,
		Caps:         fullCaps,
		Logger:       discardLogger{},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	pool := NewPool(func(context.Context, string) (*imapclient.Client, error) {
		c, err := imapclient.DialInsecure(addr, nil)
		if err != nil {
			return nil, err
		}
		if err := c.Login(fixtureUser, fixturePass).Wait(); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}, nil)
	t.Cleanup(pool.CloseAll)

	f := &nsFixture{user: user, pool: pool, prov: New("acct", pool)}
	f.w = NewWriter("acct", pool, config.Account{Alias: "acct", Email: "bob@example.test"}, nil, nil)
	f.w.Provider = f.prov
	return f
}

// folderNames gives the names of the folder list, so a case can say
// what the account holds now.
func folderNames(t *testing.T, p *Provider) []string {
	t.Helper()
	list, err := p.Folders(context.Background())
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	out := make([]string, 0, len(list))
	for _, f := range list {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

// hasFolder reports whether the account holds one folder now.
func hasFolder(t *testing.T, p *Provider, name string) bool {
	t.Helper()
	for _, got := range folderNames(t, p) {
		if got == name {
			return true
		}
	}
	return false
}

// TestFolders_DelimiterAndPrefix holds trap C11: the name a caller
// gives is not the name that goes on the wire. The hierarchy
// delimiter is the one the server reports, and a server whose
// NAMESPACE has a personal prefix takes a new folder below that
// prefix only.
//
// The case reads the folder list after the create, because the list
// is what a caller sees; a test of the name builder alone would pass
// even if no command ever left.
//
// arch: T5.5, §3.10, §3.16, §3.17, C10, C11
func TestFolders_DelimiterAndPrefix(t *testing.T) {
	t.Parallel()

	t.Run("no NAMESPACE: the delimiter comes from LIST", func(t *testing.T) {
		t.Parallel()
		// Arrange: fullCaps holds no NAMESPACE, and the memory server
		// spells its tree with "/".
		x := newWriteFix(t, fixtureOpts{}, config.Account{})
		x.warm()

		// Act
		if err := x.w.CreateFolder(context.Background(), "Projects/2026"); err != nil {
			t.Fatalf("CreateFolder: %v", err)
		}

		// Assert
		if !hasFolder(t, x.prov, "Projects/2026") {
			t.Errorf("the account holds %v, want Projects/2026", folderNames(t, x.prov))
		}
		if got := x.countCommands("NAMESPACE"); got != 0 {
			t.Errorf("%d NAMESPACE commands went out; the server does not offer the capability", got)
		}
	})

	t.Run("NAMESPACE: the prefix and its delimiter win", func(t *testing.T) {
		t.Parallel()
		// Arrange: a server like Courier, "INBOX." and ".".
		f := newNSFixture(t, "INBOX.", '.')

		// Act: the caller writes the tree with "/" and no prefix.
		if err := f.w.CreateFolder(context.Background(), "Projects/2026"); err != nil {
			t.Fatalf("CreateFolder: %v", err)
		}

		// Assert
		if !hasFolder(t, f.prov, "INBOX.Projects.2026") {
			t.Errorf("the account holds %v, want INBOX.Projects.2026 (C11)", folderNames(t, f.prov))
		}
	})

	t.Run("NAMESPACE: a name that already carries the prefix keeps it once", func(t *testing.T) {
		t.Parallel()
		f := newNSFixture(t, "INBOX.", '.')
		if err := f.w.CreateFolder(context.Background(), "INBOX.Notes"); err != nil {
			t.Fatalf("CreateFolder: %v", err)
		}
		if !hasFolder(t, f.prov, "INBOX.Notes") {
			t.Errorf("the account holds %v, want INBOX.Notes and no second prefix", folderNames(t, f.prov))
		}
	})

	t.Run("a name that is empty or only delimiters is refused", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{}, config.Account{})
		for _, name := range []string{"", "   ", "/", "//"} {
			if err := x.w.CreateFolder(context.Background(), name); err == nil {
				t.Errorf("CreateFolder(%q) made a folder; a name of delimiters names nothing", name)
			}
		}
	})
}

// TestFolders_CacheCleared holds trap C10: what this process knows
// about the folder tree must not survive a change of that tree. The
// role map of the TypeScript server was never cleared, so a renamed
// Sent folder kept its old role for the life of the process.
//
// Two facts make the rule hold here. The folder list and every role
// come from LIST at each call, so nothing is kept between calls. And
// the one piece of folder state a connection does keep, the selected
// folder, is cleared by each write, because a rename or a delete can
// take that folder away.
//
// arch: T5.5, §3.10, §3.16, §3.17, C10, C11
func TestFolders_CacheCleared(t *testing.T) {
	t.Parallel()
	// Arrange: a search opens INBOX and leaves it selected, so the
	// connection carries folder state before the first write.
	// Scratch carries no role, so the delete below is a delete the
	// rules of C11 allow. Archive is created further down to prove
	// the role table runs again, and C11 keeps a role folder, so
	// Archive is not the folder this test deletes.
	x := newWriteFix(t, fixtureOpts{folders: []string{"Projects", "Scratch"}}, config.Account{})
	ctx := context.Background()
	if _, err := x.prov.Search(ctx, mail.Query{Folder: "INBOX"}); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if got := selectedFolder(t, x.pool); got != "INBOX" {
		t.Fatalf("the connection has %q selected, want INBOX before the first write", got)
	}

	// Act and assert: a create shows in the next list, and the
	// connection forgot the selected folder.
	if err := x.w.CreateFolder(ctx, "Archive"); err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if got := selectedFolder(t, x.pool); got != "" {
		t.Errorf("the connection still has %q selected after a create (C10)", got)
	}
	list, err := x.prov.Folders(ctx)
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if got := folderByName(t, list, "Archive").Role; got != "archive" {
		t.Errorf("the new Archive folder has role %q, want archive: the role table runs again after a change (C10)", got)
	}

	// A rename: the old name is gone and the new one carries the role
	// of its new name.
	if err := x.w.RenameFolder(ctx, "Projects", "Sent"); err != nil {
		t.Fatalf("RenameFolder: %v", err)
	}
	if hasFolder(t, x.prov, "Projects") {
		t.Errorf("the account still holds Projects after the rename; the list is stale (C10)")
	}
	list, err = x.prov.Folders(ctx)
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	if got := folderByName(t, list, "Sent").Role; got != "sent" {
		t.Errorf("the renamed folder has role %q, want sent (C10)", got)
	}

	// A delete: the name is gone from the very next list. The folder
	// that goes is Scratch, which carries no role. Archive stays,
	// because C11 keeps every role folder; TestFolders_DeleteRefuses
	// holds that rule.
	if err := x.w.DeleteFolder(ctx, "Scratch"); err != nil {
		t.Fatalf("DeleteFolder: %v", err)
	}
	if got := selectedFolder(t, x.pool); got != "" {
		t.Errorf("the connection still has %q selected after a delete (C10)", got)
	}
	if hasFolder(t, x.prov, "Scratch") {
		t.Errorf("the account still holds Scratch after the delete; the list is stale (C10)")
	}
}

// selectedFolder reads the folder the pooled connection has open.
func selectedFolder(t *testing.T, pool *Pool) string {
	t.Helper()
	var name string
	err := pool.WithRead(context.Background(), "acct", func(c *Conn) error {
		name = c.Selected
		return nil
	})
	if err != nil {
		t.Fatalf("read the pooled connection: %v", err)
	}
	return name
}

// TestFolders_DeleteRefuses holds the three folders §3.10 keeps: a
// delete cannot be undone, so INBOX, a folder that carries a role and
// a folder that still holds messages all stay.
//
// arch: T5.5, §3.10, §3.16, §3.17, C10, C11
func TestFolders_DeleteRefuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("INBOX", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{}, config.Account{})
		if err := x.w.DeleteFolder(ctx, "INBOX"); err == nil {
			t.Fatal("DeleteFolder(INBOX) gave no error")
		}
		if !hasFolder(t, x.prov, "INBOX") {
			t.Error("INBOX is gone")
		}
	})

	t.Run("a folder with a role from its name", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{folders: []string{"Trash"}}, config.Account{})
		err := x.w.DeleteFolder(ctx, "Trash")
		if err == nil {
			t.Fatal("DeleteFolder(Trash) gave no error")
		}
		if !strings.Contains(err.Error(), "trash") {
			t.Errorf("the error %q does not name the role", err)
		}
		if !hasFolder(t, x.prov, "Trash") {
			t.Error("the Trash folder is gone")
		}
	})

	t.Run("a folder the account table gives a role", func(t *testing.T) {
		t.Parallel()
		// C10: the [accounts.<alias>.folders] table wins over the
		// server, so a plain name can be the Sent folder.
		x := newWriteFix(t, fixtureOpts{folders: []string{"Odeslané"}},
			config.Account{Folders: map[string]string{"sent": "Odeslané"}})
		if err := x.w.DeleteFolder(ctx, "Odeslané"); err == nil {
			t.Fatal("DeleteFolder gave no error; the account table names this folder Sent (C10)")
		}
		if !hasFolder(t, x.prov, "Odeslané") {
			t.Error("the folder is gone")
		}
	})

	t.Run("a folder whose role comes only from the special-use attribute", func(t *testing.T) {
		t.Parallel()
		// C11: RFC 6154 lets a server give the special-use attributes
		// only when the LIST asks for them with RETURN (SPECIAL-USE).
		// This name is not in the T4.4 name table and the account
		// table is empty, so the attribute is the one source of the
		// role. A LIST without the RETURN part reads the folder as
		// plain and a delete removes the Sent folder of the account.
		x := newSpecialUseFixture(t, map[string][]imap.MailboxAttr{
			"Gesendete Objekte": {imap.MailboxAttrSent},
		})
		err := x.w.DeleteFolder(ctx, "Gesendete Objekte")
		if err == nil {
			t.Fatal("DeleteFolder gave no error; the special-use attribute makes this folder Sent (C11)")
		}
		if !strings.Contains(err.Error(), "sent") {
			t.Errorf("the error %q does not name the role", err)
		}
		if !hasFolder(t, x.prov, "Gesendete Objekte") {
			t.Error("the Sent folder of the account is gone")
		}
	})

	t.Run("a folder that holds messages", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{folders: []string{"Keep"}}, config.Account{})
		x.add(msgSpec{folder: "Keep", subject: "one"})
		err := x.w.DeleteFolder(ctx, "Keep")
		if err == nil {
			t.Fatal("DeleteFolder(Keep) gave no error")
		}
		if !strings.Contains(err.Error(), "1 messages") {
			t.Errorf("the error %q does not say how many messages are in the way", err)
		}
		if !hasFolder(t, x.prov, "Keep") {
			t.Error("the folder is gone with its message")
		}
	})

	t.Run("a folder that is open on the connection and holds messages", func(t *testing.T) {
		t.Parallel()
		// C9: a STATUS on the selected folder can answer from the
		// state SELECT reported. The count that a delete reads must
		// be live.
		x := newWriteFix(t, fixtureOpts{folders: []string{"Keep"}}, config.Account{})
		x.add(msgSpec{folder: "Keep", subject: "one"})
		if _, err := x.prov.Search(ctx, mail.Query{Folder: "Keep"}); err != nil {
			t.Fatalf("Search: %v", err)
		}
		if err := x.w.DeleteFolder(ctx, "Keep"); err == nil {
			t.Fatal("DeleteFolder(Keep) gave no error while the folder was open and full")
		}
		if !hasFolder(t, x.prov, "Keep") {
			t.Error("the folder is gone with its message")
		}
	})

	t.Run("an empty folder with no role goes", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{folders: []string{"Old"}}, config.Account{})
		if err := x.w.DeleteFolder(ctx, "Old"); err != nil {
			t.Fatalf("DeleteFolder: %v", err)
		}
		if hasFolder(t, x.prov, "Old") {
			t.Error("the folder is still there")
		}
	})
}

// TestFolders_RenameRules holds what a rename may do: INBOX stays,
// a name that another folder already has is refused, and a plain
// rename moves the folder.
//
// arch: T5.5, §3.10, §3.16, §3.17, C10, C11
func TestFolders_RenameRules(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("INBOX is refused", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{}, config.Account{})
		if err := x.w.RenameFolder(ctx, "INBOX", "Old mail"); err == nil {
			t.Fatal("RenameFolder(INBOX) gave no error")
		}
		if !hasFolder(t, x.prov, "INBOX") {
			t.Error("INBOX is gone")
		}
	})

	t.Run("a name that is taken is refused", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{folders: []string{"One", "Two"}}, config.Account{})
		if err := x.w.RenameFolder(ctx, "One", "Two"); err == nil {
			t.Fatal("RenameFolder gave no error; Two is taken")
		}
		if !hasFolder(t, x.prov, "One") {
			t.Error("the source folder is gone")
		}
	})

	t.Run("an unknown folder is refused", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{}, config.Account{})
		if err := x.w.RenameFolder(ctx, "Nothing", "Something"); err == nil {
			t.Fatal("RenameFolder gave no error for a folder that does not exist")
		}
	})

	t.Run("the folder and its messages move", func(t *testing.T) {
		t.Parallel()
		x := newWriteFix(t, fixtureOpts{folders: []string{"Old"}}, config.Account{})
		x.add(msgSpec{folder: "Old", subject: "one"})
		if err := x.w.RenameFolder(ctx, "Old", "New"); err != nil {
			t.Fatalf("RenameFolder: %v", err)
		}
		if hasFolder(t, x.prov, "Old") || !hasFolder(t, x.prov, "New") {
			t.Fatalf("the account holds %v, want New and no Old", folderNames(t, x.prov))
		}
		if got := countIn(t, x.fixture, "New"); got != 1 {
			t.Errorf("the renamed folder holds %d messages, want 1", got)
		}
	})
}

// TestFolders_CreateRefusesAName holds the two names a create never
// sends: one that a folder already has, and one with a control
// character in it.
//
// arch: T5.5, §3.10, §3.16, §3.17, C10, C11
func TestFolders_CreateRefusesAName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	x := newWriteFix(t, fixtureOpts{folders: []string{"Taken"}}, config.Account{})

	if err := x.w.CreateFolder(ctx, "Taken"); err == nil {
		t.Error("CreateFolder gave no error for a name that is taken")
	}
	if err := x.w.CreateFolder(ctx, "bad\r\nname"); err == nil {
		t.Error("CreateFolder gave no error for a name with a control character")
	}
}
