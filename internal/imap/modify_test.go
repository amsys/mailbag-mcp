// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// These cases cover the IMAP write path for flags, keywords and
// moves: the new id of a move (C5), the move fallback that never
// sends a plain EXPUNGE (C12, invariant 6), and the keyword check
// against PERMANENTFLAGS (C17).
//
// arch: T5.3, §3.10, §3.8, C5, C12, C17, §10.6

// t35Caps gives the capabilities of a modern server plus extra.
func t35Caps(extra ...imap.Cap) imap.CapSet {
	out := imap.CapSet{}
	for c := range fullCaps {
		out[c] = struct{}{}
	}
	for _, c := range extra {
		out[c] = struct{}{}
	}
	return out
}

// t35PlainCaps is a server with neither MOVE nor UIDPLUS. It is the
// server of trap C12: the only command left to remove the old copy
// would be a plain EXPUNGE.
var t35PlainCaps = imap.CapSet{
	imap.CapIMAP4rev1:    {},
	imap.CapListExtended: {},
	imap.CapSpecialUse:   {},
	imap.CapESearch:      {},
}

// t35Account is the account block of the write provider in these
// cases. It names no folder roles, so the role comes from the folder
// names the server gives.
func t35Account() config.Account {
	return config.Account{}
}

// t35HasCommand reports whether the wire record holds a command that
// starts with verb. It compares the whole word, so "EXPUNGE" does not
// match "UID EXPUNGE 4".
func t35HasCommand(cmds []string, verb string) bool {
	for _, c := range cmds {
		if c == verb || strings.HasPrefix(c, verb+" ") {
			return true
		}
	}
	return false
}

// t35OneID gives the id of the one message in folder.
func t35OneID(t *testing.T, f *fixture, folder string) string {
	t.Helper()
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: folder, Limit: 10})
	if err != nil {
		t.Fatalf("search %q: %v", folder, err)
	}
	if len(page.Messages) != 1 {
		t.Fatalf("folder %q holds %d messages, want 1", folder, len(page.Messages))
	}
	return page.Messages[0].ID
}

// TestIMAP_MoveReturnsNewID holds C5: a move changes the id, and the
// new id comes from COPYUID. The undo journal of §3.18 needs it. Both
// server kinds must give it: one with the MOVE extension and one that
// gets the COPY fallback with UIDPLUS.
//
// arch: T5.3, §3.10, §3.8, C5, C12, §10.6
func TestIMAP_MoveReturnsNewID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		caps     imap.CapSet
		wantVerb string
	}{
		{"server with MOVE", t35Caps(imap.CapMove), "UID MOVE"},
		{"server without MOVE, with UIDPLUS", t35Caps(), "UID COPY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newWriteFix(t, fixtureOpts{caps: tc.caps, folders: []string{"Archive"}}, t35Account())
			f.add(msgSpec{subject: "to move", body: "text"})
			id := t35OneID(t, f.fixture, "INBOX")
			f.warm()

			res, err := f.w.ModifyDetail(context.Background(), []string{id}, mail.Change{MoveTo: "Archive"})
			if err != nil {
				t.Fatalf("modify: %v", err)
			}
			if len(res.Applied) != 1 {
				t.Fatalf("got %d rows, want 1", len(res.Applied))
			}
			row := res.Applied[0]
			if row.ID != id {
				t.Errorf("row id = %q, want %q", row.ID, id)
			}
			if row.NewID == "" {
				t.Fatalf("the move gave no new id; COPYUID was not read (C5)")
			}
			if res.ExpungePending {
				t.Errorf("expunge_pending is set, but the server removed the old copy")
			}
			cmds := f.commands()
			if !t35HasCommand(cmds, tc.wantVerb) {
				t.Errorf("no %s went out; commands: %v", tc.wantVerb, cmds)
			}
			if t35HasCommand(cmds, "EXPUNGE") {
				t.Errorf("a plain EXPUNGE went out (C12); commands: %v", cmds)
			}

			_, newUID, newFolder, err := mail.ParseIMAPID(row.NewID)
			if err != nil {
				t.Fatalf("new id %q does not parse: %v", row.NewID, err)
			}
			if newFolder != "Archive" {
				t.Errorf("new id names folder %q, want Archive", newFolder)
			}
			if newUID == 0 {
				t.Errorf("new id carries uid 0")
			}

			// The new id must reach the message, which is the only
			// proof that COPYUID was paired with the right source.
			m, err := f.prov.Read(context.Background(), row.NewID, mail.ReadOpts{})
			if err != nil {
				t.Fatalf("read the moved message by its new id: %v", err)
			}
			if m.Subject != "to move" {
				t.Errorf("new id reads subject %q, want %q", m.Subject, "to move")
			}
			if n := countIn(t, f.fixture, "INBOX"); n != 0 {
				t.Errorf("INBOX still holds %d messages after the move", n)
			}
		})
	}
}

// TestIMAP_MoveFallbackNoPlainExpunge holds C12 and invariant 6. A
// server with no MOVE gets COPY, STORE \Deleted and UID EXPUNGE. A
// server with no UIDPLUS either gets COPY and STORE only: the old
// copy stays and the answer says so. A plain EXPUNGE never goes out,
// because it removes every \Deleted message in the folder, also the
// ones another client marked.
//
// arch: T5.3, §3.10, C12, §10.6
func TestIMAP_MoveFallbackNoPlainExpunge(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		caps        imap.CapSet
		wantPending bool
		wantUIDExp  bool
		wantLeft    int // messages left in INBOX
	}{
		{"no MOVE, with UIDPLUS", t35Caps(), false, true, 0},
		{"no MOVE, no UIDPLUS", t35PlainCaps, true, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newWriteFix(t, fixtureOpts{caps: tc.caps, folders: []string{"Trash"}}, t35Account())
			f.add(msgSpec{subject: "to trash", body: "text"})
			id := t35OneID(t, f.fixture, "INBOX")
			f.warm()

			res, err := f.w.ModifyDetail(context.Background(), []string{id}, mail.Change{Trash: true})
			if err != nil {
				t.Fatalf("modify: %v", err)
			}
			cmds := f.commands()
			if t35HasCommand(cmds, "EXPUNGE") {
				t.Errorf("a plain EXPUNGE went out (C12); commands: %v", cmds)
			}
			if !t35HasCommand(cmds, "UID COPY") {
				t.Errorf("no UID COPY went out; commands: %v", cmds)
			}
			if !t35HasCommand(cmds, "UID STORE") {
				t.Errorf("no UID STORE went out; commands: %v", cmds)
			}
			if got := t35HasCommand(cmds, "UID EXPUNGE"); got != tc.wantUIDExp {
				t.Errorf("UID EXPUNGE sent = %v, want %v; commands: %v", got, tc.wantUIDExp, cmds)
			}
			if res.ExpungePending != tc.wantPending {
				t.Errorf("expunge_pending = %v, want %v", res.ExpungePending, tc.wantPending)
			}
			if n := countIn(t, f.fixture, "Trash"); n != 1 {
				t.Errorf("Trash holds %d messages, want 1", n)
			}
			if n := countIn(t, f.fixture, "INBOX"); n != tc.wantLeft {
				t.Errorf("INBOX holds %d messages, want %d", n, tc.wantLeft)
			}
		})
	}
}

// TestIMAP_KeywordNeedsPermission holds C17: a label becomes a
// keyword only when the open folder answers PERMANENTFLAGS with \*.
// A folder that does not take one gives an error that names move_to,
// and the folder stays unchanged.
//
// arch: T5.3, §3.10, C17
func TestIMAP_KeywordNeedsPermission(t *testing.T) {
	t.Parallel()

	t.Run("folder takes keywords", func(t *testing.T) {
		t.Parallel()
		f := newWriteFix(t, fixtureOpts{}, t35Account())
		f.add(msgSpec{subject: "label me", body: "text"})
		id := t35OneID(t, f.fixture, "INBOX")

		rows, err := f.w.Modify(context.Background(), []string{id}, mail.Change{AddLabels: []string{"work"}})
		if err != nil {
			t.Fatalf("modify: %v", err)
		}
		if len(rows) != 1 {
			t.Fatalf("got %d rows, want 1", len(rows))
		}
		if indexFold(rows[0].After.Labels, "work") < 0 {
			t.Errorf("after flags %v hold no label work", rows[0].After.Labels)
		}
		m, err := f.prov.Read(context.Background(), id, mail.ReadOpts{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if indexFold(m.Flags.Labels, "work") < 0 {
			t.Errorf("the server kept no keyword; flags %v", m.Flags.Labels)
		}
	})

	t.Run("folder refuses keywords", func(t *testing.T) {
		t.Parallel()
		f := t35NoKeywordFix(t)
		f.add(msgSpec{subject: "label me", body: "text"})
		id := t35OneID(t, f.fixture, "INBOX")

		_, err := f.w.Modify(context.Background(), []string{id}, mail.Change{AddLabels: []string{"work"}})
		if err == nil {
			t.Fatalf("the keyword went through on a folder with no \\* in PERMANENTFLAGS (C17)")
		}
		if !errors.Is(err, ErrKeywordNotPermitted) {
			t.Errorf("error %v is not ErrKeywordNotPermitted", err)
		}
		if !strings.Contains(err.Error(), "move_to") {
			t.Errorf("error %q does not name move_to", err)
		}
		m, err := f.prov.Read(context.Background(), id, mail.ReadOpts{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(m.Flags.Labels) != 0 {
			t.Errorf("the message carries labels %v after the refused change", m.Flags.Labels)
		}
	})
}

// TestModify_FlagsRoundTrip checks the two system flags of §3.10:
// read is \Seen and starred is \Flagged. The Before and After rows
// feed the undo journal, so both must tell the truth.
//
// arch: T5.3, §3.10, §3.18
func TestModify_FlagsRoundTrip(t *testing.T) {
	t.Parallel()
	f := newWriteFix(t, fixtureOpts{}, t35Account())
	f.add(msgSpec{subject: "flag me", body: "text"})
	id := t35OneID(t, f.fixture, "INBOX")
	ctx := context.Background()

	yes, no := true, false
	rows, err := f.w.Modify(ctx, []string{id}, mail.Change{Read: &yes, Starred: &yes})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if rows[0].Before.Seen || rows[0].Before.Flagged {
		t.Errorf("before = %+v, want both flags clear", rows[0].Before)
	}
	if !rows[0].After.Seen || !rows[0].After.Flagged {
		t.Errorf("after = %+v, want both flags set", rows[0].After)
	}
	if rows[0].NewID != "" {
		t.Errorf("a flag change gave a new id %q", rows[0].NewID)
	}
	m, err := f.prov.Read(ctx, id, mail.ReadOpts{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !m.Flags.Seen || !m.Flags.Flagged {
		t.Fatalf("the server kept %+v, want both flags set", m.Flags)
	}

	rows, err = f.w.Modify(ctx, []string{id}, mail.Change{Read: &no, Starred: &no})
	if err != nil {
		t.Fatalf("modify back: %v", err)
	}
	if !rows[0].Before.Seen || !rows[0].Before.Flagged {
		t.Errorf("before = %+v, want both flags set", rows[0].Before)
	}
	if rows[0].After.Seen || rows[0].After.Flagged {
		t.Errorf("after = %+v, want both flags clear", rows[0].After)
	}
	m, err = f.prov.Read(ctx, id, mail.ReadOpts{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if m.Flags.Seen || m.Flags.Flagged {
		t.Errorf("the server kept %+v, want both flags clear", m.Flags)
	}
}

// TestModify_TrashAndArchiveNeedAFolder holds the rule of §3.10: with
// no folder for the role, the call fails and the error names the
// setting of accounts.toml that fixes it. Nothing is removed.
//
// arch: T5.3, §3.10, §10.6
func TestModify_TrashAndArchiveNeedAFolder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		change   mail.Change
		wantText string
	}{
		{"trash", mail.Change{Trash: true}, "folders.trash"},
		{"archive", mail.Change{Archive: true}, "folders.archive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newWriteFix(t, fixtureOpts{}, t35Account())
			f.add(msgSpec{subject: "stay", body: "text"})
			id := t35OneID(t, f.fixture, "INBOX")

			_, err := f.w.Modify(context.Background(), []string{id}, tc.change)
			if err == nil {
				t.Fatalf("the call worked with no %s folder", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error %q does not name %s", err, tc.wantText)
			}
			if n := countIn(t, f.fixture, "INBOX"); n != 1 {
				t.Errorf("INBOX holds %d messages, want 1", n)
			}
		})
	}
}

// TestModify_RefusesBadInput checks the guards before any command
// goes out: one target at a time, and a label that a server takes as
// an atom. A label with a space would end the flag list on the wire.
//
// arch: T5.3, §3.10, §3.15
func TestModify_RefusesBadInput(t *testing.T) {
	t.Parallel()
	f := newWriteFix(t, fixtureOpts{folders: []string{"Trash"}}, t35Account())
	f.add(msgSpec{subject: "stay", body: "text"})
	id := t35OneID(t, f.fixture, "INBOX")
	ctx := context.Background()

	cases := []struct {
		name   string
		ids    []string
		change mail.Change
	}{
		{"no id", nil, mail.Change{Trash: true}},
		{"two targets", []string{id}, mail.Change{Trash: true, MoveTo: "Trash"}},
		{"label with a space", []string{id}, mail.Change{AddLabels: []string{"my label"}}},
		{"label with a bracket", []string{id}, mail.Change{RemoveLabels: []string{"a(b"}}},
		{"label of a system flag", []string{id}, mail.Change{AddLabels: []string{`\Deleted`}}},
		{"id of the wrong shape", []string{"not-an-id"}, mail.Change{Trash: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.w.Modify(ctx, tc.ids, tc.change); err == nil {
				t.Fatalf("the call worked")
			}
		})
	}
	if n := countIn(t, f.fixture, "INBOX"); n != 1 {
		t.Errorf("INBOX holds %d messages, want 1", n)
	}
	if n := countIn(t, f.fixture, "Trash"); n != 0 {
		t.Errorf("Trash holds %d messages, want 0", n)
	}
}

// TestModify_StaleUIDValidityRefused holds C4 on the write path: an
// id that carries the wrong UIDVALIDITY points at nothing, so the
// call fails before it changes a message.
//
// arch: T5.3, §3.8, C4
func TestModify_StaleUIDValidityRefused(t *testing.T) {
	t.Parallel()
	f := newWriteFix(t, fixtureOpts{folders: []string{"Trash"}}, t35Account())
	f.add(msgSpec{subject: "stay", body: "text"})
	id := t35OneID(t, f.fixture, "INBOX")
	_, uid, folder, err := mail.ParseIMAPID(id)
	if err != nil {
		t.Fatalf("parse %q: %v", id, err)
	}
	stale := mail.FormatIMAPID(999999, uid, folder)

	if _, err := f.w.Modify(context.Background(), []string{stale}, mail.Change{Trash: true}); !errors.Is(err, ErrStaleID) {
		t.Fatalf("error = %v, want ErrStaleID", err)
	}
	if n := countIn(t, f.fixture, "INBOX"); n != 1 {
		t.Errorf("INBOX holds %d messages, want 1", n)
	}
}

// --- a server that takes no keyword ---------------------------------

// t35NoKeywordSession is a server that answers SELECT with a
// PERMANENTFLAGS list that has no \*. Many real servers answer this
// way for a shared or a read-only folder, and the memory server
// always sends \*, so a case that needs trap C17 wraps the session.
//
// arch: T5.3, §3.10, C17
type t35NoKeywordSession struct {
	imapserver.Session
}

func (s t35NoKeywordSession) Select(mailbox string, opts *imap.SelectOptions) (*imap.SelectData, error) {
	d, err := s.Session.Select(mailbox, opts)
	if err != nil || d == nil {
		return d, err
	}
	kept := make([]imap.Flag, 0, len(d.PermanentFlags))
	for _, f := range d.PermanentFlags {
		if f != imap.FlagWildcard {
			kept = append(kept, f)
		}
	}
	d.PermanentFlags = kept
	return d, nil
}

// t35NoKeywordFix starts a memory server behind t35NoKeywordSession
// and gives a write provider on it. It repeats newFixture, because
// fixtureOpts has no switch for this wrapper and imaptest_test.go
// belongs to another task.
func t35NoKeywordFix(t *testing.T) *writeFix {
	t.Helper()
	mem := imapmemserver.New()
	user := imapmemserver.NewUser(fixtureUser, fixturePass)
	if err := user.Create("INBOX", nil); err != nil {
		t.Fatalf("create INBOX: %v", err)
	}
	mem.AddUser(user)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return t35NoKeywordSession{Session: mem.NewSession()}, nil, nil
		},
		InsecureAuth: true,
		Caps:         fullCaps,
		Logger:       discardLogger{},
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	f := &fixture{t: t, addr: ln.Addr().String(), user: user, wire: &syncBuf{}}
	f.pool = NewPool(f.dial, nil)
	t.Cleanup(f.pool.CloseAll)
	f.prov = New("acct", f.pool)

	acct := t35Account()
	acct.Alias = "acct"
	acct.Email = "bob@example.test"
	acct.SMTP = "mail.example.test:587"
	return &writeFix{fixture: f, w: NewWriter("acct", f.pool, acct, nil, nil)}
}

// --- a message that another client removed ---------------------------

// t76IDs gives the ids of the messages in folder, oldest first.
func t76IDs(t *testing.T, f *fixture, folder string) []string {
	t.Helper()
	page, err := f.prov.Search(context.Background(), mail.Query{Folder: folder, Limit: 10})
	if err != nil {
		t.Fatalf("search %q: %v", folder, err)
	}
	out := make([]string, 0, len(page.Messages))
	for _, m := range page.Messages {
		out = append(out, m.ID)
	}
	// Search gives the newest first; the UIDs follow the add order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// t76UID gives the uid part of one id.
func t76UID(t *testing.T, id string) imap.UID {
	t.Helper()
	_, uid, _, err := mail.ParseIMAPID(id)
	if err != nil {
		t.Fatalf("parse %q: %v", id, err)
	}
	return imap.UID(uid)
}

// t76MoveAway moves one message out of folder over a second
// connection, the way another client does: COPY, STORE \Deleted,
// EXPUNGE.
func t76MoveAway(t *testing.T, f *fixture, folder string, uid imap.UID, dest string) {
	t.Helper()
	c := f.client()
	defer func() { _ = c.Close() }()
	if _, err := c.Select(folder, nil).Wait(); err != nil {
		t.Fatalf("select %q: %v", folder, err)
	}
	if _, err := c.Copy(imap.UIDSetNum(uid), dest).Wait(); err != nil {
		t.Fatalf("copy to %q: %v", dest, err)
	}
	f.store(folder, uid, []imap.Flag{imap.FlagDeleted}, nil)
	f.expunge(folder)
}

// TestModify_GoneMessage holds I16 on the IMAP layer: a message that
// another client expunged or moved gets no applied row. Its id is in
// Gone, no command acts on it, and the messages that are still there
// get the change as before. A SILENT STORE and a MOVE both answer OK
// for a UID that does not exist, so only the FETCH before the change
// can see the gap.
//
// arch: D5.4
func TestModify_GoneMessage(t *testing.T) {
	t.Parallel()
	yes := true

	t.Run("flag change, one message expunged", func(t *testing.T) {
		t.Parallel()
		f := newWriteFix(t, fixtureOpts{}, t35Account())
		f.add(msgSpec{subject: "gone", body: "a"}, msgSpec{subject: "kept", body: "b"})
		ids := t76IDs(t, f.fixture, "INBOX")
		f.store("INBOX", t76UID(t, ids[0]), []imap.Flag{imap.FlagDeleted}, nil)
		f.expunge("INBOX")

		res, err := f.w.ModifyDetail(context.Background(), ids, mail.Change{Starred: &yes})
		if err != nil {
			t.Fatalf("modify: %v", err)
		}
		if len(res.Gone) != 1 || res.Gone[0] != ids[0] {
			t.Errorf("gone = %v, want [%s]", res.Gone, ids[0])
		}
		if len(res.Applied) != 1 || res.Applied[0].ID != ids[1] {
			t.Fatalf("applied = %+v, want one row for %s", res.Applied, ids[1])
		}
		if !res.Applied[0].After.Flagged {
			t.Errorf("after = %+v, want flagged", res.Applied[0].After)
		}
		m, err := f.prov.Read(context.Background(), ids[1], mail.ReadOpts{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !m.Flags.Flagged {
			t.Errorf("the kept message is not flagged: %+v", m.Flags)
		}

		// The Provider method gives the applied rows only, so a caller
		// that reads it never sees a row for the gone message.
		rows, err := f.w.Modify(context.Background(), ids[:1], mail.Change{Starred: &yes})
		if err != nil {
			t.Fatalf("modify of the gone id: %v", err)
		}
		if len(rows) != 0 {
			t.Errorf("rows = %+v, want none for a gone message", rows)
		}
	})

	moveCases := []struct {
		name string
		caps imap.CapSet
	}{
		{"move with MOVE", t35Caps(imap.CapMove)},
		{"move with COPY and UIDPLUS", t35Caps()},
		{"move with no MOVE and no UIDPLUS", t35PlainCaps},
	}
	for _, tc := range moveCases {
		t.Run(tc.name+", one message moved by another client", func(t *testing.T) {
			t.Parallel()
			f := newWriteFix(t, fixtureOpts{caps: tc.caps, folders: []string{"Archive", "Elsewhere"}}, t35Account())
			f.add(msgSpec{subject: "gone", body: "a"}, msgSpec{subject: "kept", body: "b"})
			ids := t76IDs(t, f.fixture, "INBOX")
			t76MoveAway(t, f.fixture, "INBOX", t76UID(t, ids[0]), "Elsewhere")

			res, err := f.w.ModifyDetail(context.Background(), ids, mail.Change{MoveTo: "Archive"})
			if err != nil {
				t.Fatalf("modify: %v", err)
			}
			if len(res.Gone) != 1 || res.Gone[0] != ids[0] {
				t.Errorf("gone = %v, want [%s]", res.Gone, ids[0])
			}
			if len(res.Applied) != 1 || res.Applied[0].ID != ids[1] {
				t.Fatalf("applied = %+v, want one row for %s", res.Applied, ids[1])
			}
			if res.Applied[0].NewID == "" {
				t.Errorf("the kept message has no new id")
			}
			if n := countIn(t, f.fixture, "Archive"); n != 1 {
				t.Errorf("Archive holds %d messages, want 1", n)
			}
			if n := countIn(t, f.fixture, "Elsewhere"); n != 1 {
				t.Errorf("Elsewhere holds %d messages, want 1", n)
			}
		})
	}

	t.Run("every message gone, no command acts", func(t *testing.T) {
		t.Parallel()
		f := newWriteFix(t, fixtureOpts{caps: t35Caps(imap.CapMove), folders: []string{"Archive"}}, t35Account())
		f.add(msgSpec{subject: "gone", body: "a"})
		ids := t76IDs(t, f.fixture, "INBOX")
		f.store("INBOX", t76UID(t, ids[0]), []imap.Flag{imap.FlagDeleted}, nil)
		f.expunge("INBOX")
		f.warm()

		res, err := f.w.ModifyDetail(context.Background(), ids, mail.Change{Read: &yes, MoveTo: "Archive"})
		if err != nil {
			t.Fatalf("modify: %v", err)
		}
		if len(res.Applied) != 0 {
			t.Errorf("applied = %+v, want none", res.Applied)
		}
		if len(res.Gone) != 1 || res.Gone[0] != ids[0] {
			t.Errorf("gone = %v, want [%s]", res.Gone, ids[0])
		}
		cmds := f.commands()
		for _, verb := range []string{"UID STORE", "UID MOVE", "UID COPY"} {
			if t35HasCommand(cmds, verb) {
				t.Errorf("%s went out for a gone message; commands: %v", verb, cmds)
			}
		}
	})

	t.Run("COPYUID leaves a uid out", func(t *testing.T) {
		t.Parallel()
		src := imap.UIDSetNum(4)
		dst := imap.UIDSetNum(9)
		pairs, lost, val := readCopyUID(src, dst, 77, []imap.UID{4, 5})
		if pairs[4] != 9 || val != 77 {
			t.Errorf("pairs = %v, uidvalidity = %d; want 4->9 and 77", pairs, val)
		}
		if !lost[5] || lost[4] {
			t.Errorf("lost = %v, want uid 5 only", lost)
		}

		// With no pairs the code cannot tell, so no uid is lost.
		pairs, lost, _ = readCopyUID(nil, nil, 0, []imap.UID{4})
		if pairs != nil || lost != nil {
			t.Errorf("no COPYUID gave pairs %v and lost %v, want none", pairs, lost)
		}
	})
}

// TestModify_SecondFolderFailsKeepsFirstRows holds IRV.9: when the
// change of the second folder fails, the first folder has changed
// already. Modify and ModifyDetail give the rows of the first folder
// together with the error, so the undo journal can record them.
//
// arch: DRV.11, R16-M6
func TestModify_SecondFolderFailsKeepsFirstRows(t *testing.T) {
	t.Parallel()
	f := newWriteFix(t, fixtureOpts{}, t35Account())
	f.add(msgSpec{subject: "first folder", body: "text"})
	id := t35OneID(t, f.fixture, "INBOX")
	_, uid, _, err := mail.ParseIMAPID(id)
	if err != nil {
		t.Fatalf("parse %q: %v", id, err)
	}
	// The second id names a folder the server does not have, so the
	// SELECT of the second group fails after the first group changed.
	missing := mail.FormatIMAPID(1, uid, "NoSuchFolder")
	ctx := context.Background()
	yes := true

	res, err := f.w.ModifyDetail(ctx, []string{id, missing}, mail.Change{Read: &yes})
	if err == nil {
		t.Fatal("ModifyDetail passed although the second folder does not exist")
	}
	// R16-M6: undo skips the ids of a deleted folder, so it must be
	// able to tell this error apart from a failed read.
	if !errors.Is(err, ErrFolderGone) {
		t.Errorf("error = %v, want ErrFolderGone", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].ID != id || !res.Applied[0].After.Seen || res.Applied[0].Before.Seen {
		t.Fatalf("ModifyDetail rows = %+v, want the one row of the first folder", res.Applied)
	}

	no := false
	rows, err := f.w.Modify(ctx, []string{id, missing}, mail.Change{Read: &no})
	if err == nil {
		t.Fatal("Modify passed although the second folder does not exist")
	}
	if len(rows) != 1 || rows[0].ID != id || rows[0].After.Seen || !rows[0].Before.Seen {
		t.Fatalf("Modify rows = %+v, want the one row of the first folder", rows)
	}
	m, err := f.prov.Read(ctx, id, mail.ReadOpts{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if m.Flags.Seen {
		t.Errorf("the server kept %+v, want the first folder changed back", m.Flags)
	}
}

// TestModify_InboxCaseNoSelfCopy holds DRV.19 item 3: the folder named
// in an id must be checked against the folder list the server gives,
// and the check that skips a move onto the same folder must compare
// the server's own spelling, not the raw text of the id. INBOX is
// case insensitive under RFC 3501 (§3.8), so an id that names the
// folder "inbox" and a move target spelled "INBOX" name the same
// folder: the move is a no-op, not a COPY or MOVE onto itself.
//
// arch: DRV.19.3, R16-M5
func TestModify_InboxCaseNoSelfCopy(t *testing.T) {
	t.Parallel()
	f := newWriteFix(t, fixtureOpts{}, t35Account())
	f.add(msgSpec{subject: "case test", body: "text"})
	id := t35OneID(t, f.fixture, "INBOX")
	uidValidity, uid, _, err := mail.ParseIMAPID(id)
	if err != nil {
		t.Fatalf("parse %q: %v", id, err)
	}
	// The id names the folder in lower case; the server spells the
	// same folder "INBOX".
	lower := mail.FormatIMAPID(uidValidity, uid, "inbox")
	f.warm()

	yes := true
	res, err := f.w.ModifyDetail(context.Background(), []string{lower}, mail.Change{MoveTo: "INBOX", Read: &yes})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if len(res.Applied) != 1 {
		t.Fatalf("applied = %+v, want one row", res.Applied)
	}
	// R16-M5: the row of a message that did not move carries its own
	// id as the new id, so the tool layer can tell it apart from a
	// move whose new id never came back.
	if res.Applied[0].NewID != lower {
		t.Errorf("new id = %q, want %q: a move onto the same folder is a no-op and keeps the id", res.Applied[0].NewID, lower)
	}
	if !res.Applied[0].After.Seen {
		t.Errorf("after = %+v, want Seen: the flag change must still apply", res.Applied[0].After)
	}
	cmds := f.commands()
	for _, verb := range []string{"UID MOVE", "UID COPY"} {
		if t35HasCommand(cmds, verb) {
			t.Errorf("%s went out for a move onto the same folder; commands: %v", verb, cmds)
		}
	}
	if n := countIn(t, f.fixture, "INBOX"); n != 1 {
		t.Errorf("INBOX holds %d messages, want 1 (no copy made)", n)
	}
}

// --- the junk rule of a move (DS8.2d) ---------------------------------

// t35Labels gives the labels of the message id as the server keeps them.
func t35Labels(t *testing.T, f *fixture, id string) []string {
	t.Helper()
	m, err := f.prov.Read(context.Background(), id, mail.ReadOpts{})
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return m.Flags.Labels
}

// TestIMAP_MoveOutOfJunkMarksNotJunk holds DS8.2d: a move out of the
// junk folder into a folder that is not junk or trash removes $Junk
// and adds $NotJunk with a STORE before the move, so the keywords
// travel with the message. The rows give the keywords before and
// after, and the undo change (move back, labels back,
// KeepJunkKeywords) puts the message back as it was. A move into Junk
// adds $Junk and removes $NotJunk. Trash from Junk keeps the keywords.
//
// arch: DS8.2d, T5.3, §3.10, §3.18
func TestIMAP_MoveOutOfJunkMarksNotJunk(t *testing.T) {
	t.Parallel()
	f := newWriteFix(t, fixtureOpts{caps: t35Caps(imap.CapMove), folders: []string{"Junk", "Work", "Trash"}}, t35Account())
	f.add(msgSpec{folder: "Junk", subject: "not spam", body: "text", flags: []imap.Flag{"$Junk"}})
	id := t35OneID(t, f.fixture, "Junk")
	ctx := context.Background()

	res, err := f.w.ModifyDetail(ctx, []string{id}, mail.Change{MoveTo: "Work"})
	if err != nil {
		t.Fatalf("move out of junk: %v", err)
	}
	if len(res.Applied) != 1 || res.Applied[0].NewID == "" {
		t.Fatalf("Applied = %+v, want one row with a new id", res.Applied)
	}
	row := res.Applied[0]
	if indexFold(row.Before.Labels, "$Junk") < 0 || indexFold(row.After.Labels, "$Junk") >= 0 ||
		indexFold(row.After.Labels, "$NotJunk") < 0 {
		t.Errorf("row = %+v, want $Junk before and $NotJunk, not $Junk, after", row)
	}
	got := t35Labels(t, f.fixture, row.NewID)
	if indexFold(got, "$Junk") >= 0 || indexFold(got, "$NotJunk") < 0 {
		t.Errorf("the moved message has labels %v, want $NotJunk and no $Junk", got)
	}

	// Undo: the reverse change that the tool layer builds.
	back := mail.Change{MoveTo: "Junk", AddLabels: []string{"$Junk"}, RemoveLabels: []string{"$NotJunk"}, KeepJunkKeywords: true}
	undone, err := f.w.ModifyDetail(ctx, []string{row.NewID}, back)
	if err != nil || len(undone.Applied) != 1 {
		t.Fatalf("undo: rows %+v, err %v", undone.Applied, err)
	}
	got = t35Labels(t, f.fixture, undone.Applied[0].NewID)
	if indexFold(got, "$Junk") < 0 || indexFold(got, "$NotJunk") >= 0 {
		t.Errorf("after the undo the message has labels %v, want $Junk and no $NotJunk", got)
	}
	junkID := undone.Applied[0].NewID

	// Trash from Junk keeps the keywords.
	res, err = f.w.ModifyDetail(ctx, []string{junkID}, mail.Change{Trash: true})
	if err != nil || len(res.Applied) != 1 {
		t.Fatalf("trash: rows %+v, err %v", res.Applied, err)
	}
	if got := t35Labels(t, f.fixture, res.Applied[0].NewID); indexFold(got, "$Junk") < 0 || indexFold(got, "$NotJunk") >= 0 {
		t.Errorf("after trash the message has labels %v, want $Junk kept", got)
	}

	// Into Junk: $Junk on, $NotJunk off.
	f.add(msgSpec{subject: "spam", body: "text", flags: []imap.Flag{"$NotJunk"}})
	inbox := t35OneID(t, f.fixture, "INBOX")
	res, err = f.w.ModifyDetail(ctx, []string{inbox}, mail.Change{MoveTo: "Junk"})
	if err != nil || len(res.Applied) != 1 {
		t.Fatalf("move into junk: rows %+v, err %v", res.Applied, err)
	}
	if got := t35Labels(t, f.fixture, res.Applied[0].NewID); indexFold(got, "$Junk") < 0 || indexFold(got, "$NotJunk") >= 0 {
		t.Errorf("after the move into Junk the message has labels %v, want $Junk and no $NotJunk", got)
	}
}

// TestIMAP_JunkRuleSkipsFolderWithoutKeywords holds DS8.2d and C17: a
// junk folder that takes no keyword still lets the move go through.
// The junk rule then adds no keyword and gives no error.
//
// arch: DS8.2d, C17
func TestIMAP_JunkRuleSkipsFolderWithoutKeywords(t *testing.T) {
	t.Parallel()
	f := t35NoKeywordFix(t)
	if err := f.user.Create("Junk", nil); err != nil {
		t.Fatalf("create Junk: %v", err)
	}
	f.add(msgSpec{folder: "Junk", subject: "not spam", body: "text"})
	id := t35OneID(t, f.fixture, "Junk")

	res, err := f.w.ModifyDetail(context.Background(), []string{id}, mail.Change{MoveTo: "INBOX"})
	if err != nil {
		t.Fatalf("move out of a junk folder with no keywords: %v", err)
	}
	if len(res.Applied) != 1 || len(res.Applied[0].After.Labels) != 0 {
		t.Errorf("Applied = %+v, want one row with no labels", res.Applied)
	}
}
