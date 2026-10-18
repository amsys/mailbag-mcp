// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the write side of messages and folders in the JMAP provider
// (DS8.2, DS8.2c, DS78.4, DS78.5): Modify with Email/set patches and
// the mailboxes before and after a move, the rule that a message keeps
// one mailbox at least, the folder writes with Mailbox/set, and the
// capability report. Each test runs against fakeJMAP with a fakeStore;
// no test reaches the network (IS78.1).

package jmap

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// boxTrash is the mailbox id of the role trash in modifyStore.
const boxTrash = "mb-trash"

// modifyStore gives the mailboxes of testStore with Trash, and four
// emails: e1 (read) and e3 in the inbox, e2 in Projects/Work, and e4
// in the inbox and in Projects/Work.
func modifyStore() *fakeStore {
	s := testStore()
	s.mailboxes = append(s.mailboxes,
		map[string]any{"id": boxTrash, "name": "Trash", "parentId": nil, "role": "trash", "totalEmails": 0, "unreadEmails": 0})
	s.emails = append(s.emails,
		email("e4", []string{boxInbox, boxWork}, map[string]any{"work": true}, "2026-10-06T10:00:00Z"))
	return s
}

// boxesOf gives the sorted mailbox ids of the stored email id.
func boxesOf(t *testing.T, s *fakeStore, id string) []string {
	t.Helper()
	e := s.email(id)
	if e == nil {
		t.Fatalf("the store has no email %s", id)
	}
	m, _ := e["mailboxIds"].(map[string]any)
	in := map[string]bool{}
	for k, v := range m {
		in[k] = v == true
	}
	return mailboxList(in)
}

// TestJMAP_ArchiveMissing checks F8: with no mailbox with the role
// archive, archive fails with a hint that names move_to, sends no
// Email/set and leaves the message where it was. The cached table is
// checked against the server once more before the error.
//
// arch: DS8.2, DS8.2c, DS78.4, DS78.5, IS8.2, IS8.4
func TestJMAP_ArchiveMissing(t *testing.T) {
	s := modifyStore()
	var boxes []map[string]any
	for _, m := range s.mailboxes {
		if m["role"] != "archive" {
			boxes = append(boxes, m)
		}
	}
	s.mailboxes = boxes
	p, f := newTestProvider(t, s, nil)

	_, err := p.Modify(context.Background(), []string{"e1"}, mail.Change{Archive: true})
	if err == nil {
		t.Fatal("archive with no archive mailbox: no error")
	}
	for _, want := range []string{"role archive", "move_to"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if n := len(callsNamed(f, "Email/set")); n != 0 {
		t.Errorf("%d Email/set calls, want none", n)
	}
	if n := len(callsNamed(f, "Mailbox/get")); n != 2 {
		t.Errorf("%d Mailbox/get calls, want 2: the cache, then once more before the error", n)
	}
	if got := boxesOf(t, s, "e1"); !reflect.DeepEqual(got, []string{boxInbox}) {
		t.Errorf("e1 is in %v, want only the inbox", got)
	}

	// Trash with no trash mailbox fails the same way.
	s2 := testStore()
	p2, _ := newTestProvider(t, s2, nil)
	if _, err := p2.Modify(context.Background(), []string{"e1"}, mail.Change{Trash: true}); err == nil || !strings.Contains(err.Error(), "role trash") {
		t.Errorf("trash with no trash mailbox: err = %v, want the role trash named", err)
	}
}

// TestJMAP_NeverRemovesLastMailbox checks IS8.2 and DS8.2c: each patch
// of a move sets mailboxIds to exactly one target and never clears a
// single mailbox; a message in two mailboxes ends in the target alone;
// and an undo whose mailboxes the account no longer has is refused
// with the fixed text, with no Email/set sent.
//
// arch: DS8.2, DS8.2c, DS78.4, DS78.5, IS8.2, IS8.4
func TestJMAP_NeverRemovesLastMailbox(t *testing.T) {
	s := modifyStore()
	p, f := newTestProvider(t, s, nil)
	ctx := context.Background()

	cases := []struct {
		id   string
		c    mail.Change
		want string
	}{
		{"e4", mail.Change{MoveTo: "Archive"}, boxArchive},
		{"e2", mail.Change{Trash: true}, boxTrash},
		{"e3", mail.Change{Archive: true}, boxArchive},
	}
	for _, tc := range cases {
		if _, err := p.Modify(ctx, []string{tc.id}, tc.c); err != nil {
			t.Fatalf("modify %s: %v", tc.id, err)
		}
		set := lastCall(t, f, "Email/set")
		upd, _ := set.Args["update"].(map[string]any)
		patch, _ := upd[tc.id].(map[string]any)
		for k := range patch {
			if strings.HasPrefix(k, "mailboxIds/") {
				t.Errorf("patch of %s has %q: a path patch can clear the last mailbox", tc.id, k)
			}
		}
		boxes, _ := patch["mailboxIds"].(map[string]any)
		if len(boxes) != 1 || boxes[tc.want] != true {
			t.Errorf("patch of %s sets mailboxIds %v, want exactly {%s}", tc.id, boxes, tc.want)
		}
		if got := boxesOf(t, s, tc.id); !reflect.DeepEqual(got, []string{tc.want}) {
			t.Errorf("%s is in %v, want only %s", tc.id, got, tc.want)
		}
	}

	before := len(callsNamed(f, "Email/set"))
	_, err := p.Modify(ctx, []string{"e1"}, mail.Change{RestoreFolders: []string{"mb-gone"}})
	if !errors.Is(err, errNoMailbox) {
		t.Fatalf("restore into a mailbox that is gone: err = %v, want errNoMailbox", err)
	}
	if n := len(callsNamed(f, "Email/set")); n != before {
		t.Errorf("a refused patch sent %d Email/set calls", n-before)
	}
	if got := boxesOf(t, s, "e1"); !reflect.DeepEqual(got, []string{boxInbox}) {
		t.Errorf("e1 is in %v after a refused patch, want the inbox", got)
	}

	// One target at most: two targets are refused before any call.
	if _, err := p.Modify(ctx, []string{"e1"}, mail.Change{MoveTo: "Archive", Trash: true}); err == nil {
		t.Error("move_to with trash: no error")
	}
}

// TestJMAP_MoveRecordsFolders checks DS78.5 and IS8.4: a move keeps the
// id and fills FoldersBefore and FoldersAfter with the mailbox ids; the
// reverse change (RestoreFolders = FoldersBefore) puts the message
// back; the state read (an empty change) sends no Email/set and gives
// the current mailboxes in FoldersAfter; a missing id is Gone; and read,
// starred and a label are keyword patches with no folder record.
//
// arch: DS8.2, DS8.2c, DS78.4, DS78.5, IS8.2, IS8.4
func TestJMAP_MoveRecordsFolders(t *testing.T) {
	s := modifyStore()
	p, f := newTestProvider(t, s, nil)
	ctx := context.Background()

	res, err := p.ModifyDetail(ctx, []string{"e4", "e1", "zz"}, mail.Change{MoveTo: "Projects/Work"})
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if !reflect.DeepEqual(res.Gone, []string{"zz"}) {
		t.Errorf("Gone = %v, want [zz]", res.Gone)
	}
	if len(res.Applied) != 2 {
		t.Fatalf("Applied = %+v, want rows for e4 and e1", res.Applied)
	}
	e4, e1 := res.Applied[0], res.Applied[1]
	if e4.ID != "e4" || e4.NewID != "" ||
		!reflect.DeepEqual(e4.FoldersBefore, []string{boxInbox, boxWork}) ||
		!reflect.DeepEqual(e4.FoldersAfter, []string{boxWork}) {
		t.Errorf("e4 row = %+v, want the id kept, before [inbox work], after [work]", e4)
	}
	if e1.ID != "e1" || !reflect.DeepEqual(e1.FoldersBefore, []string{boxInbox}) ||
		!reflect.DeepEqual(e1.FoldersAfter, []string{boxWork}) || !e1.Before.Seen || !e1.After.Seen {
		t.Errorf("e1 row = %+v, want before [inbox], after [work], still read", e1)
	}

	// Undo of the move: the reverse change restores FoldersBefore.
	back, err := p.ModifyDetail(ctx, []string{"e4"}, mail.Change{RestoreFolders: e4.FoldersBefore})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := boxesOf(t, s, "e4"); !reflect.DeepEqual(got, []string{boxInbox, boxWork}) {
		t.Errorf("e4 is in %v after the undo, want inbox and work", got)
	}
	if len(back.Applied) != 1 || !reflect.DeepEqual(back.Applied[0].FoldersAfter, []string{boxInbox, boxWork}) {
		t.Errorf("restore rows = %+v, want FoldersAfter [inbox work]", back.Applied)
	}

	// The state read of undo: no Email/set, the current mailboxes.
	sets := len(callsNamed(f, "Email/set"))
	cur, err := p.ModifyDetail(ctx, []string{"e1", "zz"}, mail.Change{})
	if err != nil {
		t.Fatalf("state read: %v", err)
	}
	if n := len(callsNamed(f, "Email/set")); n != sets {
		t.Errorf("the state read sent %d Email/set calls", n-sets)
	}
	if len(cur.Applied) != 1 || !reflect.DeepEqual(cur.Applied[0].FoldersAfter, []string{boxWork}) ||
		!cur.Applied[0].Before.Seen || len(cur.Applied[0].FoldersBefore) != 0 {
		t.Errorf("state read rows = %+v, want e1 read in [work]", cur.Applied)
	}
	if !reflect.DeepEqual(cur.Gone, []string{"zz"}) {
		t.Errorf("state read Gone = %v, want [zz]", cur.Gone)
	}

	// Flags and labels are keyword patches; no mailbox changes.
	yes, no := true, false
	rows, err := p.Modify(ctx, []string{"e3"}, mail.Change{Read: &yes, Starred: &yes, AddLabels: []string{"a/b~c"}})
	if err != nil {
		t.Fatalf("flags: %v", err)
	}
	set := lastCall(t, f, "Email/set")
	upd, _ := set.Args["update"].(map[string]any)
	want := map[string]any{"keywords/$seen": true, "keywords/$flagged": true, "keywords/a~1b~0c": true}
	if !reflect.DeepEqual(upd["e3"], want) {
		t.Errorf("patch = %v, want %v", upd["e3"], want)
	}
	if len(rows) != 1 || !rows[0].After.Seen || !rows[0].After.Flagged || rows[0].Before.Seen ||
		!reflect.DeepEqual(rows[0].After.Labels, []string{"a/b~c"}) || rows[0].FoldersBefore != nil || rows[0].FoldersAfter != nil {
		t.Errorf("flag row = %+v, want unread to read and starred, label a/b~c, no folders", rows)
	}
	if _, err := p.Modify(ctx, []string{"e3"}, mail.Change{Read: &no, RemoveLabels: []string{"a/b~c"}}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	upd, _ = lastCall(t, f, "Email/set").Args["update"].(map[string]any)
	if want := map[string]any{"keywords/$seen": nil, "keywords/a~1b~0c": nil}; !reflect.DeepEqual(upd["e3"], want) {
		t.Errorf("clear patch = %v, want %v", upd["e3"], want)
	}
	if _, err := p.Modify(ctx, []string{"e3"}, mail.Change{AddLabels: []string{"$Seen"}}); err == nil {
		t.Error("the flag keyword $Seen as a label: no error")
	}
}

// TestJMAP_AddAndRemoveSameLabelRefused checks DS8.2b: a label in
// add_labels and in remove_labels, in any case, is refused with the
// Gmail text, and no Email/set goes out. Before, remove won with no
// error.
//
// arch: DS8.2, DS8.2b, R16-L10
func TestJMAP_AddAndRemoveSameLabelRefused(t *testing.T) {
	p, f := newTestProvider(t, modifyStore(), nil)
	for _, remove := range []string{"work", "Work"} {
		_, err := p.Modify(context.Background(), []string{"e4"}, mail.Change{AddLabels: []string{"work"}, RemoveLabels: []string{remove}})
		if err == nil || !strings.Contains(err.Error(), "the change both adds and removes the label") {
			t.Errorf("add work, remove %s: error %v, want the refusal", remove, err)
		}
	}
	if n := len(callsNamed(f, "Email/set")); n != 0 {
		t.Errorf("Email/set calls = %d, want 0", n)
	}
}

// TestJMAP_CapsLines checks DS78.4: Kind is "jmap" and Lines give the
// session, the three capabilities, the mailbox and identity counts and
// maxSizeUpload of the session fixture. Without the submission
// capability no Identity/get is sent.
//
// arch: DS8.2, DS8.2c, DS78.4, DS78.5, IS8.2, IS8.4
func TestJMAP_CapsLines(t *testing.T) {
	s := draftStore()
	p, _ := newTestProvider(t, s, nil)
	caps, err := p.Caps(context.Background())
	if err != nil {
		t.Fatalf("Caps: %v", err)
	}
	want := mail.Caps{Kind: "jmap", Lines: []string{
		"session: ok",
		"capabilities: core, mail, submission",
		"mailboxes: 7",
		"identities: 2",
		"maxSizeUpload: 50000000",
	}}
	if !reflect.DeepEqual(caps, want) {
		t.Errorf("Caps =\n%#v\nwant\n%#v", caps, want)
	}

	f := newFakeJMAP(t, fakeOpts{store: draftStore(), editSession: func(_ int, _ string, sess map[string]any) {
		c, _ := sess["capabilities"].(map[string]any)
		delete(c, usingSubmission)
		core, _ := c[usingCore].(map[string]any)
		delete(core, "maxSizeUpload")
	}})
	p2 := NewProvider(p.acct, f.client(nil, false), nil)
	caps, err = p2.Caps(context.Background())
	if err != nil {
		t.Fatalf("Caps without submission: %v", err)
	}
	if got := caps.Lines; len(got) != 5 || got[1] != "capabilities: core, mail" ||
		!strings.HasPrefix(got[3], "identities: none") || got[4] != "maxSizeUpload: not given" {
		t.Errorf("Lines without submission = %q", got)
	}
	if n := len(callsNamed(f, "Identity/get")); n != 0 {
		t.Errorf("%d Identity/get calls without the submission capability, want none", n)
	}
}

// TestJMAP_FolderWritesMailboxSet checks the folder rows of DS8.2:
// create and rename send Mailbox/set with the name and the parent id;
// delete refuses a mailbox with a role and one that holds messages
// before any Mailbox/set, and destroys an empty one with
// onDestroyRemoveEmails false.
//
// arch: DS8.2, DS8.2c, DS78.4, DS78.5, IS8.2, IS8.4
func TestJMAP_FolderWritesMailboxSet(t *testing.T) {
	s := modifyStore()
	p, f := newTestProvider(t, s, nil)
	ctx := context.Background()

	if err := p.CreateFolder(ctx, "Projects/New"); err != nil {
		t.Fatalf("create: %v", err)
	}
	cr, _ := lastCall(t, f, "Mailbox/set").Args["create"].(map[string]any)
	if want := map[string]any{"new": map[string]any{"name": "New", "parentId": boxProjects}}; !reflect.DeepEqual(cr, want) {
		t.Errorf("create = %v, want %v", cr, want)
	}
	if err := p.CreateFolder(ctx, "Projects/New"); err == nil {
		t.Error("create of a folder that exists: no error")
	}
	if err := p.CreateFolder(ctx, "Nope/New"); err == nil {
		t.Error("create under a parent that does not exist: no error")
	}

	if err := p.RenameFolder(ctx, "Projects/New", "Old"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	up, _ := lastCall(t, f, "Mailbox/set").Args["update"].(map[string]any)
	if want := map[string]any{"M1": map[string]any{"name": "Old", "parentId": nil}}; !reflect.DeepEqual(up, want) {
		t.Errorf("rename = %v, want %v", up, want)
	}

	sets := len(callsNamed(f, "Mailbox/set"))
	for _, name := range []string{"Archive", "INBOX", "Flagged"} {
		if err := p.DeleteFolder(ctx, name); err == nil || !strings.Contains(err.Error(), "role") {
			t.Errorf("delete %s: err = %v, want a refusal for the role", name, err)
		}
	}
	if err := p.DeleteFolder(ctx, "Projects/Work"); err == nil || !strings.Contains(err.Error(), "holds") {
		t.Errorf("delete of a folder with messages: err = %v, want a refusal", err)
	}
	if n := len(callsNamed(f, "Mailbox/set")); n != sets {
		t.Errorf("a refused delete sent %d Mailbox/set calls", n-sets)
	}

	if err := p.DeleteFolder(ctx, "Old"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	del := lastCall(t, f, "Mailbox/set").Args
	if !reflect.DeepEqual(strs(del["destroy"]), []string{"M1"}) || del["onDestroyRemoveEmails"] != false {
		t.Errorf("destroy args = %v, want destroy [M1] with onDestroyRemoveEmails false", del)
	}
	folders, err := p.Folders(ctx)
	if err != nil {
		t.Fatalf("folders: %v", err)
	}
	for _, fo := range folders {
		if fo.Name == "Old" {
			t.Error("the folder Old is still listed after the delete")
		}
	}
}

// boxJunk is the mailbox id of the role junk in junkStore.
const boxJunk = "mb-junk"

// junkStore gives the mailboxes of modifyStore with Junk, and three
// more emails: j1 ($junk) and j2 (no junk keyword) in Junk, and j3
// ($notjunk) in the inbox.
func junkStore() *fakeStore {
	s := modifyStore()
	s.mailboxes = append(s.mailboxes,
		map[string]any{"id": boxJunk, "name": "Junk", "parentId": nil, "role": "junk", "totalEmails": 2, "unreadEmails": 0})
	s.emails = append(s.emails,
		email("j1", []string{boxJunk}, map[string]any{"$junk": true}, "2026-10-05T10:00:00Z"),
		email("j2", []string{boxJunk}, map[string]any{}, "2026-10-04T10:00:00Z"),
		email("j3", []string{boxInbox}, map[string]any{"$notjunk": true}, "2026-10-03T10:00:00Z"))
	return s
}

// keywordsOf gives the keywords of the stored email id that are true.
func keywordsOf(t *testing.T, s *fakeStore, id string) map[string]bool {
	t.Helper()
	e := s.email(id)
	if e == nil {
		t.Fatalf("the store has no email %s", id)
	}
	kw, _ := e["keywords"].(map[string]any)
	out := map[string]bool{}
	for k, v := range kw {
		if v == true {
			out[k] = true
		}
	}
	return out
}

// TestJMAP_MoveOutOfJunkMarksNotJunk holds DS8.2d: a move out of the
// junk mailbox into a mailbox that is not junk or trash removes $junk
// and sets $notjunk in the same Email/set patch, only on the messages
// that were in Junk. A move into Junk sets $junk and removes
// $notjunk. Trash from Junk keeps the keywords. The rows give the
// keywords before and after, and the undo change (labels back,
// RestoreFolders, KeepJunkKeywords) puts the message back as it was.
//
// arch: DS8.2d, DS8.2, DS78.5
func TestJMAP_MoveOutOfJunkMarksNotJunk(t *testing.T) {
	s := junkStore()
	p, f := newTestProvider(t, s, nil)
	ctx := context.Background()

	sets := len(callsNamed(f, "Email/set"))
	res, err := p.ModifyDetail(ctx, []string{"j1", "j2", "e3"}, mail.Change{MoveTo: "Projects/Work"})
	if err != nil {
		t.Fatalf("move out of junk: %v", err)
	}
	if n := len(callsNamed(f, "Email/set")) - sets; n != 1 {
		t.Errorf("the move sent %d Email/set calls, want 1: the keywords go in the same patch", n)
	}
	upd, _ := lastCall(t, f, "Email/set").Args["update"].(map[string]any)
	for _, id := range []string{"j1", "j2"} {
		patch, _ := upd[id].(map[string]any)
		if v, ok := patch["keywords/$junk"]; !ok || v != nil {
			t.Errorf("patch of %s = %v, want keywords/$junk: null", id, patch)
		}
		if patch["keywords/$notjunk"] != true {
			t.Errorf("patch of %s = %v, want keywords/$notjunk: true", id, patch)
		}
		if got := keywordsOf(t, s, id); !reflect.DeepEqual(got, map[string]bool{"$notjunk": true}) {
			t.Errorf("%s has keywords %v, want only $notjunk", id, got)
		}
	}
	if patch, _ := upd["e3"].(map[string]any); len(patch) != 1 || patch["mailboxIds"] == nil {
		t.Errorf("patch of e3 = %v, want the mailbox only: e3 was not in Junk", patch)
	}
	if len(res.Applied) != 3 {
		t.Fatalf("Applied = %+v, want 3 rows", res.Applied)
	}
	j1 := res.Applied[0]
	if !reflect.DeepEqual(j1.Before.Labels, []string{"$junk"}) || !reflect.DeepEqual(j1.After.Labels, []string{"$notjunk"}) ||
		!reflect.DeepEqual(j1.FoldersBefore, []string{boxJunk}) {
		t.Errorf("j1 row = %+v, want labels [$junk] to [$notjunk], from Junk", j1)
	}

	// Undo of j1: the reverse change that the tool layer builds.
	back := mail.Change{AddLabels: []string{"$junk"}, RemoveLabels: []string{"$notjunk"},
		RestoreFolders: j1.FoldersBefore, KeepJunkKeywords: true}
	if _, err := p.ModifyDetail(ctx, []string{"j1"}, back); err != nil {
		t.Fatalf("undo of j1: %v", err)
	}
	if got := keywordsOf(t, s, "j1"); !reflect.DeepEqual(got, map[string]bool{"$junk": true}) {
		t.Errorf("j1 has keywords %v after the undo, want only $junk", got)
	}
	if got := boxesOf(t, s, "j1"); !reflect.DeepEqual(got, []string{boxJunk}) {
		t.Errorf("j1 is in %v after the undo, want Junk", got)
	}
	// Undo of j2, which had no junk keyword: no label to restore, and
	// the move back into Junk must not add $junk.
	back = mail.Change{RemoveLabels: []string{"$notjunk"}, RestoreFolders: []string{boxJunk}, KeepJunkKeywords: true}
	if _, err := p.ModifyDetail(ctx, []string{"j2"}, back); err != nil {
		t.Fatalf("undo of j2: %v", err)
	}
	if got := keywordsOf(t, s, "j2"); len(got) != 0 {
		t.Errorf("j2 has keywords %v after the undo, want none", got)
	}

	// Into Junk: $junk on, $notjunk off.
	res, err = p.ModifyDetail(ctx, []string{"j3"}, mail.Change{MoveTo: "Junk"})
	if err != nil {
		t.Fatalf("move into junk: %v", err)
	}
	if got := keywordsOf(t, s, "j3"); !reflect.DeepEqual(got, map[string]bool{"$junk": true}) {
		t.Errorf("j3 has keywords %v after the move into Junk, want only $junk", got)
	}
	if len(res.Applied) != 1 || !reflect.DeepEqual(res.Applied[0].After.Labels, []string{"$junk"}) {
		t.Errorf("j3 rows = %+v, want After labels [$junk]", res.Applied)
	}

	// Trash from Junk keeps the keywords.
	if _, err := p.ModifyDetail(ctx, []string{"j1"}, mail.Change{Trash: true}); err != nil {
		t.Fatalf("trash from junk: %v", err)
	}
	if got := keywordsOf(t, s, "j1"); !reflect.DeepEqual(got, map[string]bool{"$junk": true}) {
		t.Errorf("j1 has keywords %v after trash, want only $junk", got)
	}

	// A call that names a junk keyword itself gets only what it names.
	if _, err := p.ModifyDetail(ctx, []string{"j2"}, mail.Change{MoveTo: "Inbox", AddLabels: []string{"$junk"}}); err != nil {
		t.Fatalf("move with $junk named: %v", err)
	}
	if got := keywordsOf(t, s, "j2"); !reflect.DeepEqual(got, map[string]bool{"$junk": true}) {
		t.Errorf("j2 has keywords %v, want only the $junk the call named", got)
	}
}
