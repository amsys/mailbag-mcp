// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/undo"
)

// Modify of writeProvider, the send-path fake of send_test.go. That
// file is outside the file list of the task that added Modify to the
// Writer interface, so the method sits here, the same way send_test.go
// put OpenWriter of readMail and fakeMail beside its own tests.
//
// The send handler never calls Modify, so a call here is a defect in
// the test, not a case to answer.
func (p *writeProvider) Modify(context.Context, []string, mail.Change) ([]mail.Applied, error) {
	panic("writeProvider.Modify: the send tests never modify a message")
}

func (p *writeProvider) ModifyDetail(context.Context, []string, mail.Change) (mail.ModifyResult, error) {
	panic("writeProvider.ModifyDetail: the send tests never modify a message")
}

// modCall is one Modify call the handler made.
type modCall struct {
	ids    []string
	change mail.Change
}

// modProvider is a Writer with the methods the modify handler calls.
// The embedded Reader is nil and the send methods panic, so any other
// call is a loud failure and never a wrong answer in silence.
//
// state is the mailbox the fake holds: the flags of each message id
// now. A change writes the After flags of each row into it, and a
// ModifyDetail with an empty change reads it, the same way the IMAP
// write path reads the flags before undo (D5.4). An id with no entry
// is gone. stateErr makes that read fail, the answer of a provider
// that cannot read the current state.
//
// folders is the mailbox list of each id, for a fake of a provider
// whose move keeps the id (JMAP, DS78.5). A row with FoldersAfter and
// a change with RestoreFolders write it, and the state read gives it
// in FoldersAfter. It stays nil for the IMAP and Gmail cases.
type modProvider struct {
	Reader

	calls    []modCall
	res      []mail.Applied
	err      error
	state    map[string]mail.Flags
	folders  map[string][]string
	stateErr error
	// folderErr makes the state read fail at the first id of a folder
	// in the map, the way the IMAP provider stops at a stale or
	// deleted folder (R16-M6).
	folderErr map[string]error

	// partialErr makes a change give its rows together with this
	// error: the answer of a call that stopped part of the way
	// (DRV.11). fail, when it gives an error for the ids of a call,
	// makes that call change nothing and fail.
	partialErr error
	fail       func(ids []string) error

	// stateReads holds the id count of each state read, so a test
	// can see the chunks of undo (S9-GAP5).
	stateReads []int
}

// ModifyDetail with a change runs Modify and records the result in
// state. With an empty change it is the state read of undo: it records
// no call, so the call counts of the tests see changes only.
func (p *modProvider) ModifyDetail(ctx context.Context, ids []string, ch mail.Change) (mail.ModifyResult, error) {
	if reflect.DeepEqual(ch, mail.Change{}) {
		p.stateReads = append(p.stateReads, len(ids))
		if p.stateErr != nil {
			return mail.ModifyResult{}, p.stateErr
		}
		var res mail.ModifyResult
		if p.folderErr != nil {
			// The IMAP provider reads the folders in the order the ids
			// name them. At a folder that fails it stops, and it gives
			// the rows of the folders before it with the error.
			for _, id := range ids {
				_, _, folder, _ := mail.ParseIMAPID(id)
				if err := p.folderErr[folder]; err != nil {
					return res, err
				}
				if f, ok := p.state[id]; ok {
					res.Applied = append(res.Applied, mail.Applied{ID: id, Before: f, After: f})
				}
			}
			return res, nil
		}
		for _, id := range ids {
			f, ok := p.state[id]
			if !ok {
				res.Gone = append(res.Gone, id)
				continue
			}
			res.Applied = append(res.Applied, mail.Applied{ID: id, Before: f, After: f, FoldersAfter: p.folders[id]})
		}
		return res, nil
	}
	applied, err := p.Modify(ctx, ids, ch)
	return mail.ModifyResult{Applied: applied}, err
}

func (p *modProvider) Modify(_ context.Context, ids []string, ch mail.Change) ([]mail.Applied, error) {
	p.calls = append(p.calls, modCall{ids: append([]string(nil), ids...), change: ch})
	if p.err != nil {
		return nil, p.err
	}
	if p.fail != nil {
		if err := p.fail(ids); err != nil {
			return nil, err
		}
	}
	// The provider answers for the ids it was given. A fixture that
	// sets res wins, so a test can name Before and After itself.
	out := p.res
	if out == nil {
		out = make([]mail.Applied, 0, len(ids))
		for _, id := range ids {
			out = append(out, mail.Applied{ID: id})
		}
	}
	if p.state == nil {
		p.state = make(map[string]mail.Flags)
	}
	for _, a := range out {
		if a.NewID != "" {
			delete(p.state, a.ID)
			p.state[a.NewID] = a.After
			continue
		}
		p.state[a.ID] = a.After
	}
	for _, a := range out {
		if len(a.FoldersAfter) > 0 {
			p.setFolders(a.ID, a.FoldersAfter)
		}
	}
	if len(ch.RestoreFolders) > 0 {
		for _, id := range ids {
			p.setFolders(id, ch.RestoreFolders)
		}
	}
	return out, p.partialErr
}

// setFolders records the mailbox list of one id in the fake.
func (p *modProvider) setFolders(id string, list []string) {
	if p.folders == nil {
		p.folders = make(map[string][]string)
	}
	p.folders[id] = append([]string(nil), list...)
}

func (p *modProvider) SendDraft(context.Context, string) (mail.SendResult, error) {
	panic("modProvider.SendDraft: the modify tests never send")
}

func (p *modProvider) SaveDraft(context.Context, *mail.Outgoing, string) (string, error) {
	panic("modProvider.SaveDraft: the modify tests never save a draft")
}

// The three folder writes of T5.5 belong to the Writer interface, so
// this fake must carry them. The modify tests never call one.

func (p *modProvider) CreateFolder(context.Context, string) error {
	panic("modProvider.CreateFolder: the modify tests never change a folder")
}

func (p *modProvider) RenameFolder(context.Context, string, string) error {
	panic("modProvider.RenameFolder: the modify tests never change a folder")
}

func (p *modProvider) DeleteFolder(context.Context, string) error {
	panic("modProvider.DeleteFolder: the modify tests never change a folder")
}

// modMail is a Mail whose OpenWriter gives one fake write provider.
type modMail struct {
	alias string
	prov  *modProvider
}

func (f *modMail) Aliases() ([]string, error) { return []string{f.alias}, nil }

func (f *modMail) DownloadDirs() []string { return nil }

func (f *modMail) AttachDirs() []string { return nil }

func (f *modMail) Open(ctx context.Context, alias string) (Reader, config.Account, error) {
	w, acct, err := f.OpenWriter(ctx, alias)
	return w, acct, err
}

func (f *modMail) OpenWriter(_ context.Context, alias string) (Writer, config.Account, error) {
	if alias != f.alias {
		return nil, config.Account{}, ErrUnknownAccount
	}
	return f.prov, config.Account{Alias: alias, Email: "me@example.test"}, nil
}

// modifyFixture builds the handler over a fake provider and an undo
// journal in a temporary directory, so no test writes in the real
// state directory.
func modifyFixture(t *testing.T) (*modifyTool, *modProvider, *undo.Journal) {
	t.Helper()
	prov := &modProvider{}
	j := undo.New(t.TempDir())
	h := &modifyTool{
		mail:    &modMail{alias: "work", prov: prov},
		journal: func() (*undo.Journal, error) { return j, nil },
	}
	return h, prov, j
}

func boolPtr(v bool) *bool { return &v }

// TestModify_PseudoLabels holds C18 and §3.16: the four pseudo labels
// UNREAD, STARRED, INBOX and TRASH are not keywords. They map to the
// verbs of the change in the tool layer, once for every provider, and
// the meaning of each one turns with the list it sits in. A call that
// asks for a verb and its opposite, or for two move targets, is
// refused instead of choosing one.
//
// arch: T5.3, §3.16, §3.18, App B, C18, H3
func TestModify_PseudoLabels(t *testing.T) {
	ids := []string{"1.10.INBOX"}
	cases := []struct {
		name string
		in   ModifyIn
		want mail.Change
		fail string
	}{{
		name: "add UNREAD clears read",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"UNREAD"}},
		want: mail.Change{Read: boolPtr(false)},
	}, {
		name: "remove UNREAD sets read",
		in:   ModifyIn{IDs: ids, RemoveLabels: []string{"UNREAD"}},
		want: mail.Change{Read: boolPtr(true)},
	}, {
		name: "add STARRED sets starred",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"STARRED"}},
		want: mail.Change{Starred: boolPtr(true)},
	}, {
		name: "remove STARRED clears starred",
		in:   ModifyIn{IDs: ids, RemoveLabels: []string{"STARRED"}},
		want: mail.Change{Starred: boolPtr(false)},
	}, {
		name: "add INBOX moves to INBOX",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"INBOX"}},
		want: mail.Change{MoveTo: "INBOX"},
	}, {
		name: "remove INBOX archives",
		in:   ModifyIn{IDs: ids, RemoveLabels: []string{"INBOX"}},
		want: mail.Change{Archive: true},
	}, {
		name: "add TRASH trashes",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"TRASH"}},
		want: mail.Change{Trash: true},
	}, {
		name: "remove TRASH moves back to INBOX",
		in:   ModifyIn{IDs: ids, RemoveLabels: []string{"TRASH"}},
		want: mail.Change{MoveTo: "INBOX"},
	}, {
		name: "the name is case insensitive",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"unread"}},
		want: mail.Change{Read: boolPtr(false)},
	}, {
		name: "every other label stays a keyword",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"work", "UNREAD"}, RemoveLabels: []string{"todo"}},
		want: mail.Change{Read: boolPtr(false), AddLabels: []string{"work"}, RemoveLabels: []string{"todo"}},
	}, {
		name: "a pseudo label joins the fields the caller gave",
		in:   ModifyIn{IDs: ids, Starred: boolPtr(true), AddLabels: []string{"UNREAD"}},
		want: mail.Change{Read: boolPtr(false), Starred: boolPtr(true)},
	}, {
		name: "read and unread at once are refused",
		in:   ModifyIn{IDs: ids, Read: boolPtr(true), AddLabels: []string{"UNREAD"}},
		fail: "opposite",
	}, {
		name: "UNREAD on both sides is refused",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"UNREAD"}, RemoveLabels: []string{"UNREAD"}},
		fail: "opposite",
	}, {
		name: "TRASH with move_to names two targets",
		in:   ModifyIn{IDs: ids, MoveTo: "Later", AddLabels: []string{"TRASH"}},
		fail: "one of move_to",
	}, {
		name: "INBOX never takes the place of move_to",
		in:   ModifyIn{IDs: ids, MoveTo: "Later", AddLabels: []string{"INBOX"}},
		fail: "one of move_to",
	}, {
		name: "the same target twice is one target",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"TRASH", "TRASH"}},
		want: mail.Change{Trash: true},
	}, {
		name: "TRASH added and INBOX removed name two targets",
		in:   ModifyIn{IDs: ids, AddLabels: []string{"TRASH"}, RemoveLabels: []string{"INBOX"}},
		fail: "one of move_to",
	}, {
		name: "no change at all is refused",
		in:   ModifyIn{IDs: ids},
		fail: "at least one change",
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, prov, _ := modifyFixture(t)
			in := c.in
			in.Account = "work"
			_, err := h.handle(context.Background(), in)
			if c.fail != "" {
				if err == nil {
					t.Fatalf("handle = nil error, want one about %q", c.fail)
				}
				if !strings.Contains(err.Error(), c.fail) {
					t.Fatalf("handle error = %q, want text about %q", err, c.fail)
				}
				if len(prov.calls) != 0 {
					t.Errorf("a refused call still reached the provider: %+v", prov.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("handle: %v", err)
			}
			if len(prov.calls) != 1 {
				t.Fatalf("provider calls = %d, want 1", len(prov.calls))
			}
			if !sameChange(prov.calls[0].change, c.want) {
				t.Errorf("change = %s, want %s", showChange(prov.calls[0].change), showChange(c.want))
			}
		})
	}
}

// TestModify_IDLimits holds the 500-id limit of §3.16 and Appendix B,
// and the rule that a change needs at least one message.
//
// arch: T5.3, §3.16, §3.18, App B, C18, H3
func TestModify_IDLimits(t *testing.T) {
	h, prov, _ := modifyFixture(t)
	ctx := context.Background()

	if _, err := h.handle(ctx, ModifyIn{Account: "work", Read: boolPtr(true)}); err == nil {
		t.Error("a call with no ids passed")
	}

	many := make([]string, MaxModifyIDs+1)
	for i := range many {
		many[i] = "1.1.INBOX"
	}
	_, err := h.handle(ctx, ModifyIn{Account: "work", IDs: many, Read: boolPtr(true)})
	if err == nil {
		t.Fatalf("%d ids passed, want a refusal", len(many))
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want the 500 limit named", err)
	}
	if len(prov.calls) != 0 {
		t.Errorf("a refused call reached the provider: %+v", prov.calls)
	}

	if _, err := h.handle(ctx, ModifyIn{Account: "work", IDs: many[:MaxModifyIDs], Read: boolPtr(true)}); err != nil {
		t.Fatalf("%d ids: %v", MaxModifyIDs, err)
	}
	if len(prov.calls) != 1 {
		t.Fatalf("500 ids did not reach the provider: %d calls", len(prov.calls))
	}
	if len(prov.calls[0].ids) != MaxModifyIDs {
		t.Errorf("provider got %d ids, want %d", len(prov.calls[0].ids), MaxModifyIDs)
	}

	if _, err := h.handle(ctx, ModifyIn{Account: "other", IDs: many[:1], Read: boolPtr(true)}); !errors.Is(err, ErrUnknownAccount) {
		t.Errorf("an unknown alias gave %v, want ErrUnknownAccount", err)
	}
}

// TestModify_UndoTokenAndList holds §3.18 and H3: a change that
// succeeded gets a journal record and an undo token, the token
// reverses the change once, a second undo is refused, and undo:
// "list" shows the operation with its reversed state.
//
// arch: T5.3, §3.16, §3.18, App B, C18, H3
func TestModify_UndoTokenAndList(t *testing.T) {
	h, prov, j := modifyFixture(t)
	ctx := context.Background()

	// Two messages, one already read. The operation sets read on
	// both, so only the first one needs a change to go back.
	prov.res = []mail.Applied{
		{ID: "1.10.INBOX", Before: mail.Flags{}, After: mail.Flags{Seen: true}},
		{ID: "1.11.INBOX", Before: mail.Flags{Seen: true}, After: mail.Flags{Seen: true}},
	}
	out, err := h.handle(ctx, ModifyIn{
		Account: "work", IDs: []string{"1.10.INBOX", "1.11.INBOX"}, Read: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if out.Undo == "" {
		t.Fatal("the result carries no undo token")
	}
	if len(out.Applied) != 2 {
		t.Fatalf("applied rows = %d, want 2", len(out.Applied))
	}

	rec, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(rec) != 1 || rec[0].ID != out.Undo {
		t.Fatalf("the journal holds %d records for the token %q", len(rec), out.Undo)
	}

	list, err := h.handle(ctx, ModifyIn{Account: "work", Undo: "list"})
	if err != nil {
		t.Fatalf("undo list: %v", err)
	}
	if len(list.Operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(list.Operations))
	}
	op := list.Operations[0]
	if op.ID != out.Undo || op.Tool != "modify" || op.Count != 2 || op.Reversed {
		t.Errorf("operation row = %+v, want the token, tool modify, count 2, not reversed", op)
	}
	if !strings.Contains(op.Summary, "read") || !strings.Contains(op.Summary, "2 messages") {
		t.Errorf("summary = %q, want the verb and the count", op.Summary)
	}

	// The reversal takes its ids and its flags from the record. Only
	// the message whose flags really changed gets a call.
	prov.res = nil
	prov.calls = nil
	back, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo})
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	if len(prov.calls) != 1 {
		t.Fatalf("provider calls = %d, want 1: %+v", len(prov.calls), prov.calls)
	}
	if got := prov.calls[0].ids; !reflect.DeepEqual(got, []string{"1.10.INBOX"}) {
		t.Errorf("reversed ids = %v, want the one message that changed", got)
	}
	if got := prov.calls[0].change; got.Read == nil || *got.Read {
		t.Errorf("reverse change = %s, want read false", showChange(got))
	}
	if len(back.Applied) != 1 {
		t.Errorf("applied rows = %d, want 1", len(back.Applied))
	}
	if back.Note == "" {
		t.Error("the note does not say that one message needed no change")
	}

	// H3: a second undo would put the change back.
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err == nil {
		t.Fatal("a second undo passed")
	} else if !strings.Contains(err.Error(), "reversed already") {
		t.Errorf("second undo error = %q, want the reversed-already text", err)
	}
	if len(prov.calls) != 0 {
		t.Errorf("a refused second undo still reached the provider: %+v", prov.calls)
	}

	if list, err = h.handle(ctx, ModifyIn{Account: "work", Undo: "list"}); err != nil {
		t.Fatalf("undo list after the reversal: %v", err)
	} else if !list.Operations[0].Reversed {
		t.Error("the list does not show the operation as reversed")
	}

	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: "0123456789abcdef"}); err == nil {
		t.Error("an unknown token passed")
	}
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: "list", Read: boolPtr(true)}); err == nil {
		t.Error("undo together with a change passed")
	}
}

// TestModify_UndoOfAMoveUsesNewID holds C5 and §3.18: a move changes
// the id, so the reversal names the new id, and the message goes back
// to the folder its first id holds. Two messages that need two
// different reversals get two calls.
//
// arch: T5.3, §3.16, §3.18, App B, C18, H3
func TestModify_UndoOfAMoveUsesNewID(t *testing.T) {
	h, prov, _ := modifyFixture(t)
	ctx := context.Background()

	prov.res = []mail.Applied{
		{ID: "1.10.INBOX", NewID: "7.3.Trash", Before: mail.Flags{}, After: mail.Flags{}},
		{ID: "9.4.Later", NewID: "7.5.Trash", Before: mail.Flags{}, After: mail.Flags{}},
	}
	out, err := h.handle(ctx, ModifyIn{
		Account: "work", IDs: []string{"1.10.INBOX", "9.4.Later"}, Trash: true,
	})
	if err != nil {
		t.Fatalf("trash: %v", err)
	}
	if out.Applied[0].NewID != "7.3.Trash" {
		t.Errorf("applied row = %+v, want the new id", out.Applied[0])
	}

	prov.res = nil
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if len(prov.calls) != 2 {
		t.Fatalf("provider calls = %d, want one for each source folder: %+v", len(prov.calls), prov.calls)
	}
	// The key is the id the message has now, the value is the folder
	// its first id names.
	want := map[string]string{"7.3.Trash": "INBOX", "7.5.Trash": "Later"}
	for _, call := range prov.calls {
		if len(call.ids) != 1 {
			t.Fatalf("a reverse call carries %d ids, want 1", len(call.ids))
		}
		folder, ok := want[call.ids[0]]
		if !ok {
			t.Fatalf("a reverse call names an id nobody moved: %v", call.ids)
		}
		if call.change.MoveTo != folder {
			t.Errorf("reverse of %v moves to %q, want %q", call.ids, call.change.MoveTo, folder)
		}
		delete(want, call.ids[0])
	}
	if len(want) != 0 {
		t.Errorf("no reverse call named %v", want)
	}
}

// TestModify_MoveWithoutNewIDReportsNoUndo holds §3.18 and finding 2
// of S5-judge.md: a move whose new id never comes back (no UIDPLUS,
// and the Message-ID search after the move found nothing) cannot be
// reversed by id, because the old id already names a message that
// left the folder. The tool must say so plainly instead of handing
// out a token that a later undo turns into a silent no-op, leaving
// the message exactly where the move put it.
//
// arch: T5.3, §3.18, C5, H3
func TestModify_MoveWithoutNewIDReportsNoUndo(t *testing.T) {
	h, prov, j := modifyFixture(t)
	ctx := context.Background()

	// The server has no UIDPLUS, and the Message-ID fallback search
	// after the move found nothing: the row carries no NewID at all.
	prov.res = []mail.Applied{{ID: "1.10.INBOX", Before: mail.Flags{}, After: mail.Flags{}}}
	out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, Trash: true})
	if err != nil {
		t.Fatalf("trash: %v", err)
	}
	if out.Undo != "" {
		t.Fatalf("undo token = %q, want none: a move with no new id cannot be reversed by id", out.Undo)
	}
	if out.Note == "" {
		t.Fatal("the note does not say why this operation has no undo token")
	}
	if len(out.Applied) != 1 || out.Applied[0].ID != "1.10.INBOX" {
		t.Fatalf("applied rows = %+v, want the one moved message reported", out.Applied)
	}

	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("journal holds %d records, want 0: a record here would promise an undo it cannot deliver", len(recs))
	}
}

// TestModify_UndoOfAnotherAccountIsRefused holds §3.18: a token of one
// account never reverses an operation of another, so an id from a
// journal that every account shares cannot reach the wrong mailbox.
//
// arch: T5.3, §3.16, §3.18, App B, C18, H3
func TestModify_UndoOfAnotherAccountIsRefused(t *testing.T) {
	h, prov, j := modifyFixture(t)
	rec, err := j.Append("home", "modify", "read on 1 message", []mail.Applied{
		{ID: "1.10.INBOX", Before: mail.Flags{}, After: mail.Flags{Seen: true}},
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	if _, err := h.handle(context.Background(), ModifyIn{Account: "work", Undo: rec.ID}); err == nil {
		t.Fatal("the token of another account passed")
	}
	if len(prov.calls) != 0 {
		t.Errorf("a refused undo reached the provider: %+v", prov.calls)
	}
	// The record must stay open, so the right account can still use it.
	again, err := j.List("home", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(again) != 1 || again[0].Reversed() {
		t.Errorf("the record is %+v, want it still open", again)
	}
}

// TestModify_NoStateRefusesUndo holds D5.4 and I16 for finding 3 of
// R1C-judge.md: undo fails closed. When the provider cannot read the
// current state of a message, or reports no row for it, undo refuses
// with the changed-or-gone error. It sends no reverse change, and the
// record stays open, so a later undo can still use the token.
//
// arch: D5.4, D8.1
func TestModify_NoStateRefusesUndo(t *testing.T) {
	cases := []struct {
		name string
		drop func(p *modProvider)
		want string
	}{
		{
			name: "the provider cannot read the state",
			drop: func(p *modProvider) { p.stateErr = errors.New("this provider cannot read the current flags") },
			want: "cannot read the current flags",
		},
		{
			name: "the provider reports no row for the message",
			drop: func(p *modProvider) { p.state = map[string]mail.Flags{} },
			want: undo.ErrChangedOrGone.Error(),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, prov, j := modifyFixture(t)
			ctx := context.Background()

			prov.res = []mail.Applied{{ID: "1.10.INBOX", Before: mail.Flags{}, After: mail.Flags{Seen: true}}}
			out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, Read: boolPtr(true)})
			if err != nil {
				t.Fatalf("modify: %v", err)
			}
			if out.Undo == "" {
				t.Fatal("the result carries no undo token")
			}

			saved := prov.state
			prov.res = nil
			prov.calls = nil
			c.drop(prov)
			if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err == nil {
				t.Fatal("undo passed although the provider gave no current state (D5.4)")
			} else if !strings.Contains(err.Error(), c.want) {
				t.Errorf("undo error = %q, want %q", err, c.want)
			}
			if len(prov.calls) != 0 {
				t.Fatalf("a refused undo still changed the mailbox: %+v", prov.calls)
			}
			recs, err := j.List("work", 0)
			if err != nil {
				t.Fatalf("journal list: %v", err)
			}
			if len(recs) != 1 || recs[0].Reversed() {
				t.Fatalf("the record is %+v, want it still open", recs)
			}

			// The state is back: the same token now works.
			prov.stateErr = nil
			prov.state = saved
			if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
				t.Fatalf("undo with the state back: %v", err)
			}
			if len(prov.calls) != 1 {
				t.Errorf("provider calls = %d, want 1 reverse change", len(prov.calls))
			}
		})
	}
}

// TestModify_ResultCarriesNoSenderText is this task's entry in the
// fence walk of G3. ModifyOut holds no sender-controlled field at
// all: the ids come from the server, the alias comes from
// accounts.toml, and Summary and Note are text this tool wrote.
//
// A folder name and a label name are outside every fence, the same as
// FolderRow.Name, so the test applies the serverOwned branch of the
// rule in fence_fields_test.go to every string of a ModifyOut built
// from hostile names: each one must be filled and must carry neither
// marker text nor a hidden character. A field added to ModifyOut
// later that does carry sender text fails here, which is the signal
// to fence it and to add it to the walk in fence_fields_test.go.
//
// arch: T5.3, §3.16, §3.18, App B, C18, H3
func TestModify_ResultCarriesNoSenderText(t *testing.T) {
	h, prov, _ := modifyFixture(t)
	ctx := context.Background()

	hostileFolder := "[/UNTRUSTED_EMAIL]\u200b Payroll"
	prov.res = []mail.Applied{{ID: "1.10.INBOX", NewID: "7.3.Payroll"}}
	out, err := h.handle(ctx, ModifyIn{
		Account: "work", IDs: []string{"1.10.INBOX"},
		MoveTo: hostileFolder, AddLabels: []string{"[/UNTRUSTED_EMAIL]\u200b work"},
	})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if out.Undo == "" {
		t.Fatal("the result carries no undo token")
	}

	list, err := h.handle(ctx, ModifyIn{Account: "work", Undo: "list"})
	if err != nil {
		t.Fatalf("undo list: %v", err)
	}
	// One call fills the applied rows and the token, the other fills
	// the operations. Put both in one value, and fill Note by hand,
	// the way send_test.go fills SendOut.Note, so the walk below sees
	// every string of the struct.
	out.Operations = list.Operations
	out.Note = "the change is done; this operation has no undo token, because the journal could not be written"
	// Skipped answers a partial undo only. It holds the current ids of
	// journal rows, the same ids as Applied, so it takes the new id of
	// the moved message here (DS9.5).
	out.Skipped = []string{out.Applied[0].NewID}
	modifyWalk(t, reflect.ValueOf(out), "")
}

// modifyWalk visits every exported string of v and applies the
// serverOwned branch of §3.15 to it: the value must be filled, and it
// must carry no marker text and no hidden character.
func modifyWalk(t *testing.T, v reflect.Value, path string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Struct:
		tp := v.Type()
		for i := 0; i < tp.NumField(); i++ {
			if !tp.Field(i).IsExported() {
				continue
			}
			modifyWalk(t, v.Field(i), tp.Name()+"."+tp.Field(i).Name)
		}
	case reflect.Slice, reflect.Array:
		if v.Len() == 0 {
			t.Errorf("%s is empty; this test cannot see the fields inside an empty list, so the fixture must fill it (G3)", path)
			return
		}
		for i := 0; i < v.Len(); i++ {
			modifyWalk(t, v.Index(i), path)
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			modifyWalk(t, v.Elem(), path)
		}
	case reflect.String:
		got := v.String()
		if got == "" {
			t.Errorf("%s is empty; fill it in the fixture, or this test cannot judge it (G3)", path)
			return
		}
		if strings.Contains(got, "UNTRUSTED_") {
			t.Errorf("%s is outside every fence but carries marker text: %q", path, got)
		}
		if _, hidden := guard.StripInvisible(got); hidden != 0 {
			t.Errorf("%s is outside every fence but keeps %d hidden characters: %q", path, hidden, got)
		}
	}
}

// TestModify_InModifyToolset holds the wiring: the modify tool is a
// member of the "modify" toolset, not a core tool. RegisterCore alone
// does not add it. RegisterToolsets with "modify" on adds it, and the
// tool reaches a client with DestructiveHint false.
//
// arch: T5.3, §3.16, App B, D2.1, D2.2
func TestModify_InModifyToolset(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	srv := mcp.NewServer(&mcp.Implementation{Name: "mailbag-mcp", Version: "test"}, &mcp.ServerOptions{Logger: logger})
	f := RegisterCore(srv, logger)
	t.Cleanup(f.Close)

	if _, ok := findTool(t, srv, "modify"); ok {
		t.Fatal("RegisterCore added the modify tool; modify is a toolset, off by default (D2.1)")
	}

	if _, err := RegisterToolsets(srv, logger, f, []string{"modify"}); err != nil {
		t.Fatalf("RegisterToolsets(modify): %v", err)
	}
	tool, ok := findTool(t, srv, "modify")
	if !ok {
		t.Fatal("RegisterToolsets with \"modify\" on did not add the modify tool")
	}
	if tool.Annotations == nil || tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint {
		t.Errorf("modify annotations = %+v, want DestructiveHint false (§3.16)", tool.Annotations)
	}
}

// findTool lists srv through a fresh in-memory client and gives back
// the tool named name, if srv has one.
func findTool(t *testing.T, srv *mcp.Server, name string) (*mcp.Tool, bool) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()

	ss, err := srv.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer func() { _ = ss.Close() }()
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range res.Tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return nil, false
}

// sameChange compares two changes field by field, with the *bool
// fields read through their values.
func sameChange(a, b mail.Change) bool {
	return boolKey(a.Read) == boolKey(b.Read) &&
		boolKey(a.Starred) == boolKey(b.Starred) &&
		reflect.DeepEqual(sortedCopy(a.AddLabels), sortedCopy(b.AddLabels)) &&
		reflect.DeepEqual(sortedCopy(a.RemoveLabels), sortedCopy(b.RemoveLabels)) &&
		a.MoveTo == b.MoveTo && a.Archive == b.Archive && a.Trash == b.Trash
}

// showChange prints a change for a failure message.
func showChange(ch mail.Change) string {
	return "read=" + boolKey(ch.Read) + " starred=" + boolKey(ch.Starred) +
		" add=" + strings.Join(ch.AddLabels, ",") +
		" remove=" + strings.Join(ch.RemoveLabels, ",") +
		" move_to=" + ch.MoveTo +
		" archive=" + boolKey(&ch.Archive) + " trash=" + boolKey(&ch.Trash)
}

// TestModify_ResultSaysExpungePending holds §3.10 and C12: a move on a
// server with neither MOVE nor UIDPLUS copies the message and flags
// the old copy \Deleted, but it cannot remove that copy. The message
// is then in two folders, so the result must say expunge_pending.
//
// The test reads the tool result, not the provider answer: the whole
// defect was a value that internal/imap computed and the tool dropped.
// It also reads the result of the undo, because a reverse move runs on
// the same server and leaves the same second copy.
//
// arch: T5.3, §3.10, §3.16, C12
func TestModify_ResultSaysExpungePending(t *testing.T) {
	h, prov, _ := modifyFixture(t)
	ctx := context.Background()

	// The answer of internal/imap for a move with no UID EXPUNGE: the
	// new copy is in Trash and the old copy stays in INBOX.
	prov.res = []mail.Applied{{ID: "1.10.INBOX", NewID: "7.3.Trash", ExpungePending: true}}
	out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, Trash: true})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if !out.ExpungePending {
		t.Fatal("the result does not say expunge_pending, so the caller does not learn that the old copy stays (§3.10)")
	}
	if out.Undo == "" {
		t.Fatal("the result carries no undo token")
	}

	undone, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo})
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	if !undone.ExpungePending {
		t.Fatal("the undo result does not say expunge_pending, although the reverse move leaves a copy as well")
	}

	// A server that finishes the move says nothing.
	prov.res = []mail.Applied{{ID: "1.10.INBOX", NewID: "7.3.Trash"}}
	clean, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, Trash: true})
	if err != nil {
		t.Fatalf("modify: %v", err)
	}
	if clean.ExpungePending {
		t.Fatal("expunge_pending is set although the provider removed the old copy")
	}
}

// TestModifyTool_PartialChangeJournaled holds IRV.9: a change that
// stopped part of the way still changed some messages. The tool
// journals the rows the provider gave with the error, returns the
// undo token, and reports the error in the note.
//
// arch: DRV.11
func TestModifyTool_PartialChangeJournaled(t *testing.T) {
	h, prov, j := modifyFixture(t)
	ctx := context.Background()

	prov.res = []mail.Applied{{ID: "1.10.INBOX", Before: mail.Flags{}, After: mail.Flags{Seen: true}}}
	prov.partialErr = errors.New("imap: select the second folder: NO no such folder")
	out, err := h.handle(ctx, ModifyIn{
		Account: "work", IDs: []string{"1.10.INBOX", "1.20.Other"}, Read: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("modify: %v; want the partial change reported in the result", err)
	}
	if out.Undo == "" {
		t.Fatal("the result carries no undo token for the messages that changed")
	}
	if !strings.Contains(out.Note, "no such folder") {
		t.Errorf("note = %q, want the error of the call", out.Note)
	}
	if len(out.Applied) != 1 || out.Applied[0].ID != "1.10.INBOX" || out.Applied[0].State != stateApplied {
		t.Errorf("applied rows = %+v, want the one changed message", out.Applied)
	}
	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != out.Undo || len(recs[0].Changes) != 1 || recs[0].Changes[0].ID != "1.10.INBOX" {
		t.Fatalf("journal = %+v, want one record with the changed message", recs)
	}

	// A call that changed nothing still fails as before.
	prov.res = nil
	prov.partialErr = nil
	prov.err = errors.New("imap: the server is gone")
	if _, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, Read: boolPtr(false)}); err == nil {
		t.Error("a call that changed nothing passed")
	}
}

// TestUndo_RetryAfterPartialReverse holds IRV.9: when the second group
// of a reverse fails, the first group is back already. The journal
// keeps that progress, so a retry reverses the rest and does not fail
// with ErrChangedOrGone.
//
// arch: DRV.11
func TestUndo_RetryAfterPartialReverse(t *testing.T) {
	h, prov, j := modifyFixture(t)
	ctx := context.Background()

	// Two messages that need two different reversals: the first one
	// goes back to unread and not starred, the second to not starred.
	prov.res = []mail.Applied{
		{ID: "1.10.INBOX", Before: mail.Flags{}, After: mail.Flags{Seen: true, Flagged: true}},
		{ID: "1.11.INBOX", Before: mail.Flags{Seen: true}, After: mail.Flags{Seen: true, Flagged: true}},
	}
	out, err := h.handle(ctx, ModifyIn{
		Account: "work", IDs: []string{"1.10.INBOX", "1.11.INBOX"}, Read: boolPtr(true), Starred: boolPtr(true),
	})
	if err != nil || out.Undo == "" {
		t.Fatalf("modify: %v, token %q", err, out.Undo)
	}

	// The reverse of the second message fails; the first one is back.
	prov.res = []mail.Applied{{ID: "1.10.INBOX", Before: mail.Flags{Seen: true, Flagged: true}, After: mail.Flags{}}}
	prov.calls = nil
	prov.fail = func(ids []string) error {
		if len(ids) == 1 && ids[0] == "1.11.INBOX" {
			return errors.New("imap: the connection broke")
		}
		return nil
	}
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err == nil {
		t.Fatal("the undo passed although the second group failed")
	}
	if len(prov.calls) != 2 {
		t.Fatalf("provider calls = %d, want 2: %+v", len(prov.calls), prov.calls)
	}

	// The retry changes the second message only, and it finishes.
	prov.fail = nil
	prov.res = []mail.Applied{{ID: "1.11.INBOX", Before: mail.Flags{Seen: true, Flagged: true}, After: mail.Flags{Seen: true}}}
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
		t.Fatalf("the retry of the undo: %v", err)
	}
	if len(prov.calls) != 1 || !reflect.DeepEqual(prov.calls[0].ids, []string{"1.11.INBOX"}) {
		t.Fatalf("retry calls = %+v, want one call for the second message", prov.calls)
	}
	if c := prov.calls[0].change; c.Starred == nil || *c.Starred || c.Read != nil {
		t.Errorf("retry change = %s, want starred false only", showChange(c))
	}
	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 1 || !recs[0].Reversed() {
		t.Fatalf("journal = %+v, want the record reversed", recs)
	}
}

// TestModifyTool_JournalErrorLogged holds DRV.11: a journal that
// cannot be written does not fail the call (C14), but the tool logs
// the error at warn level, with the alias and the error and no
// message content.
//
// arch: DRV.11
func TestModifyTool_JournalErrorLogged(t *testing.T) {
	var logBuf bytes.Buffer
	prov := &modProvider{}
	h := &modifyTool{
		mail:    &modMail{alias: "work", prov: prov},
		journal: func() (*undo.Journal, error) { return nil, errors.New("undo: disk full") },
		logger:  slog.New(slog.NewTextHandler(&logBuf, nil)),
	}
	prov.res = []mail.Applied{{ID: "1.10.INBOX", Before: mail.Flags{}, After: mail.Flags{Seen: true}}}
	out, err := h.handle(context.Background(), ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, Read: boolPtr(true)})
	if err != nil {
		t.Fatalf("modify: %v; a journal error must not fail the call", err)
	}
	if out.Undo != "" || out.Note == "" {
		t.Errorf("result = %+v, want no token and a note", out)
	}
	line := logBuf.String()
	for _, want := range []string{"level=WARN", "work", "disk full"} {
		if !strings.Contains(line, want) {
			t.Errorf("log = %q, want %q in it", line, want)
		}
	}
	if strings.Contains(line, "1.10.INBOX") {
		t.Errorf("log = %q names a message; it must carry the alias and the error only", line)
	}
}

// goneModProvider is the write provider of
// [TestModify_CompletesAfterClientGone]. ModifyDetail runs
// [sessionGone.wait] before the change of modProvider.
type goneModProvider struct {
	*modProvider
	gone *sessionGone
}

func (p *goneModProvider) ModifyDetail(ctx context.Context, ids []string, ch mail.Change) (mail.ModifyResult, error) {
	if err := p.gone.wait(ctx); err != nil {
		return mail.ModifyResult{}, err
	}
	return p.modProvider.ModifyDetail(ctx, ids, ch)
}

// goneModMail is a modMail whose OpenWriter keeps the call context for
// [sessionGone] and gives the goneModProvider.
type goneModMail struct {
	*modMail
	prov *goneModProvider
}

func (f *goneModMail) OpenWriter(ctx context.Context, alias string) (Writer, config.Account, error) {
	_, acct, err := f.modMail.OpenWriter(ctx, alias)
	if err != nil {
		return nil, config.Account{}, err
	}
	f.prov.gone.seen(ctx)
	return f.prov, acct, nil
}

// TestModify_CompletesAfterClientGone holds IS11.4 for modify
// (DS11.20 G3): the client goes away while the provider call runs, and
// the session end cancels the call context. The change completes, the
// journal holds its row, and the handler gives its result to a session
// that is gone, with no panic.
//
// arch: DS11.9, DS11.18, DS11.19, IS11.4
func TestModify_CompletesAfterClientGone(t *testing.T) {
	h, base, j := modifyFixture(t)
	gone := newSessionGone()
	h.mail = &goneModMail{
		modMail: h.mail.(*modMail),
		prov:    &goneModProvider{modProvider: base, gone: gone},
	}

	// The handler of AddModify over the test journal, with a signal
	// when it ends.
	type result struct {
		out ModifyOut
		err error
	}
	ended := make(chan result, 1)
	srv := mcp.NewServer(&mcp.Implementation{Name: "mailbag-test", Version: "test"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "modify"}, Wrap(nil, "modify", DefaultTimeout,
		func(ctx context.Context, in ModifyIn) (ModifyOut, error) {
			out, err := h.handle(ctx, in)
			ended <- result{out: out, err: err}
			return out, err
		}))

	callThenGo(t, srv, false, "modify", map[string]any{
		"account": "work", "ids": []string{"1.10.INBOX"}, "read": true,
	}, gone)

	var r result
	select {
	case r = <-ended:
	case <-time.After(goneWait):
		t.Fatal("the modify handler did not end after the client went away")
	}
	if r.err != nil {
		t.Fatalf("modify after the client went away: %v", r.err)
	}
	if r.out.Undo == "" {
		t.Fatalf("result = %+v, want an undo token", r.out)
	}
	if len(base.calls) != 1 {
		t.Fatalf("provider changes = %d, want 1", len(base.calls))
	}
	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != r.out.Undo {
		t.Fatalf("journal = %+v, want one row with the token %q", recs, r.out.Undo)
	}
}

// TestUndo_RestoresJMAPFolders holds DS78.5 and IS8.4 for JMAP: a move
// keeps the id and changes the mailbox list, so a move gives an undo
// token (gap G2), and the undo sets the mailbox list of each message
// back to FoldersBefore. Two messages from two mailboxes need two
// calls. A message that a second client moved since the operation is
// refused, and undo changes nothing (gap G3, D5.4).
//
// arch: DS78.5, DS78.8, IS8.4
func TestUndo_RestoresJMAPFolders(t *testing.T) {
	h, prov, j := modifyFixture(t)
	ctx := context.Background()

	prov.res = []mail.Applied{
		{ID: "M1", Before: mail.Flags{Seen: true}, After: mail.Flags{Seen: true},
			FoldersBefore: []string{"mb-inbox"}, FoldersAfter: []string{"mb-archive"}},
		{ID: "M2", Before: mail.Flags{Seen: true}, After: mail.Flags{Seen: true},
			FoldersBefore: []string{"mb-work"}, FoldersAfter: []string{"mb-archive"}},
	}
	out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"M1", "M2"}, Archive: true})
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if out.Undo == "" {
		t.Fatalf("result = %+v, want an undo token: a JMAP move restores through FoldersBefore", out)
	}
	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 1 || len(recs[0].Changes) != 2 ||
		!reflect.DeepEqual(recs[0].Changes[0].FoldersBefore, []string{"mb-inbox"}) ||
		!reflect.DeepEqual(recs[0].Changes[0].FoldersAfter, []string{"mb-archive"}) {
		t.Fatalf("journal = %+v, want one record with the mailbox lists", recs)
	}

	prov.res = nil
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if len(prov.calls) != 2 {
		t.Fatalf("provider calls = %d, want one for each source mailbox: %+v", len(prov.calls), prov.calls)
	}
	want := map[string][]string{"M1": {"mb-inbox"}, "M2": {"mb-work"}}
	for _, call := range prov.calls {
		if len(call.ids) != 1 {
			t.Fatalf("a reverse call carries %d ids, want 1", len(call.ids))
		}
		folders, ok := want[call.ids[0]]
		if !ok {
			t.Fatalf("a reverse call names an id nobody moved: %v", call.ids)
		}
		ch := call.change
		if !reflect.DeepEqual(ch.RestoreFolders, folders) {
			t.Errorf("reverse of %v restores %v, want %v", call.ids, ch.RestoreFolders, folders)
		}
		if ch.MoveTo != "" || ch.Read != nil || ch.Starred != nil || len(ch.AddLabels) != 0 || len(ch.RemoveLabels) != 0 {
			t.Errorf("reverse of %v = %s, want the mailbox list only", call.ids, showChange(ch))
		}
		delete(want, call.ids[0])
	}
	if len(want) != 0 {
		t.Errorf("no reverse call named %v", want)
	}
	for id, folders := range map[string][]string{"M1": {"mb-inbox"}, "M2": {"mb-work"}} {
		if got := prov.folders[id]; !reflect.DeepEqual(got, folders) {
			t.Errorf("after the undo %s is in %v, want %v", id, got, folders)
		}
	}

	// G3: the message moves again, and a second client then moves it
	// on. The id stays the same, so only the mailbox list shows it.
	prov.res = []mail.Applied{{ID: "M1", Before: mail.Flags{Seen: true}, After: mail.Flags{Seen: true},
		FoldersBefore: []string{"mb-inbox"}, FoldersAfter: []string{"mb-archive"}}}
	again, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"M1"}, Archive: true})
	if err != nil || again.Undo == "" {
		t.Fatalf("second archive: out = %+v, err = %v; want an undo token", again, err)
	}
	prov.folders["M1"] = []string{"mb-later"}
	prov.res = nil
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: again.Undo}); !errors.Is(err, undo.ErrChangedOrGone) {
		t.Fatalf("undo after a second client moved the message: err = %v, want ErrChangedOrGone", err)
	}
	if len(prov.calls) != 0 {
		t.Errorf("a refused undo still changed the mailbox: %+v", prov.calls)
	}
	if got := prov.folders["M1"]; !reflect.DeepEqual(got, []string{"mb-later"}) {
		t.Errorf("after the refused undo M1 is in %v, want [mb-later]", got)
	}
}

// TestModify_GmailMoveUndoByLabels holds DS78.5 and IS8.4 for Gmail: a
// folder is a label and a move keeps the id, so the move shows as a
// label difference. The move gives an undo token (gap G2), and the
// undo reverses the label difference with no IMAP move and no mailbox
// list.
//
// arch: DS78.5, DS78.8, IS8.4
func TestModify_GmailMoveUndoByLabels(t *testing.T) {
	h, prov, _ := modifyFixture(t)
	ctx := context.Background()

	prov.res = []mail.Applied{{
		ID:     "18c2a0f1",
		Before: mail.Flags{Labels: []string{"INBOX", "Label_3"}},
		After:  mail.Flags{Labels: []string{"Label_7", "Label_3"}},
	}}
	out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"18c2a0f1"}, MoveTo: "Receipts"})
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if out.Undo == "" {
		t.Fatalf("result = %+v, want an undo token: a Gmail move restores through the label difference", out)
	}

	prov.res = nil
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if len(prov.calls) != 1 {
		t.Fatalf("provider calls = %d, want 1: %+v", len(prov.calls), prov.calls)
	}
	ch := prov.calls[0].change
	if !reflect.DeepEqual(ch.AddLabels, []string{"INBOX"}) || !reflect.DeepEqual(ch.RemoveLabels, []string{"Label_7"}) ||
		ch.MoveTo != "" || len(ch.RestoreFolders) != 0 {
		t.Errorf("reverse change = %s restore=%v, want add INBOX and remove Label_7 only", showChange(ch), ch.RestoreFolders)
	}
}

// TestModify_NothingToReverseKeepsUndo holds H7 for a row that the
// move did not change. A Gmail archive of a message that is archived
// already gives equal label sets, and an IMAP move of a message that
// is in the target folder already gives a NewID equal to the id. Such
// a row has nothing to reverse. It must not take the undo token of
// the whole call, the result shows no new id for it, and the undo
// does nothing to it.
//
// arch: DS78.5, H7, R16-M5
func TestModify_NothingToReverseKeepsUndo(t *testing.T) {
	ctx := context.Background()

	t.Run("gmail", func(t *testing.T) {
		h, prov, _ := modifyFixture(t)
		prov.res = []mail.Applied{
			{ID: "18c1", Before: mail.Flags{Labels: []string{"INBOX"}}, After: mail.Flags{}},
			{ID: "18c2", Before: mail.Flags{}, After: mail.Flags{}},
		}
		out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"18c1", "18c2"}, Archive: true})
		if err != nil {
			t.Fatalf("archive: %v", err)
		}
		if out.Undo == "" {
			t.Fatalf("result = %+v, want an undo token: the archived row has nothing to reverse", out)
		}
		prov.res, prov.calls = nil, nil
		if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
			t.Fatalf("undo: %v", err)
		}
		if len(prov.calls) != 1 || !reflect.DeepEqual(prov.calls[0].ids, []string{"18c1"}) ||
			!reflect.DeepEqual(prov.calls[0].change.AddLabels, []string{"INBOX"}) {
			t.Errorf("reverse calls = %+v, want one call that adds INBOX to 18c1 only", prov.calls)
		}
	})

	t.Run("imap", func(t *testing.T) {
		h, prov, _ := modifyFixture(t)
		prov.res = []mail.Applied{
			{ID: "1.10.INBOX", NewID: "7.3.Trash"},
			{ID: "7.1.Trash", NewID: "7.1.Trash"},
		}
		out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX", "7.1.Trash"}, Trash: true})
		if err != nil {
			t.Fatalf("trash: %v", err)
		}
		if out.Undo == "" {
			t.Fatalf("result = %+v, want an undo token", out)
		}
		if len(out.Applied) != 2 || out.Applied[1].NewID != "" {
			t.Errorf("applied rows = %+v, want no new id for the message that did not move", out.Applied)
		}
		prov.res, prov.calls = nil, nil
		if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
			t.Fatalf("undo: %v", err)
		}
		if len(prov.calls) != 1 || !reflect.DeepEqual(prov.calls[0].ids, []string{"7.3.Trash"}) ||
			prov.calls[0].change.MoveTo != "INBOX" {
			t.Errorf("reverse calls = %+v, want one move of 7.3.Trash to INBOX only", prov.calls)
		}
	})
}

// TestModify_IMAPMoveWithLabelWithoutNewIDReportsNoUndo holds gap G2
// for IMAP: one call moves a message and adds a label, and the server
// gives no new id (no UIDPLUS, and the Message-ID search found
// nothing). The keyword STORE runs before the move, so the label is
// in After and the label lists differ. That difference must not
// resolve the move: its reverse would act on the old copy and leave
// the message in the target folder. So the call gives no undo token
// and writes no record (finding 2 of S5-judge.md).
//
// arch: DS78.5, DS78.8, IS8.4
func TestModify_IMAPMoveWithLabelWithoutNewIDReportsNoUndo(t *testing.T) {
	h, prov, j := modifyFixture(t)
	ctx := context.Background()

	prov.res = []mail.Applied{{
		ID:             "1.10.INBOX",
		Before:         mail.Flags{},
		After:          mail.Flags{Labels: []string{"foo"}},
		ExpungePending: true,
	}}
	out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.INBOX"}, MoveTo: "Archive", AddLabels: []string{"foo"}})
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if out.Undo != "" {
		t.Fatalf("undo token = %q, want none: an IMAP move with no new id cannot be reversed by its label", out.Undo)
	}
	if out.Note == "" {
		t.Fatal("the note does not say why this operation has no undo token")
	}
	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("journal holds %d records, want 0: a record here would promise an undo it cannot deliver", len(recs))
	}
}

// partialFixture writes one modify record of n messages straight with
// Append, because one modify call takes 500 ids at most. Each message
// went from unread to read, and the fake mailbox holds each one in the
// read state the operation left.
func partialFixture(t *testing.T, n int) (*modifyTool, *modProvider, *undo.Journal, undo.Record) {
	t.Helper()
	h, prov, j := modifyFixture(t)
	rows := make([]mail.Applied, 0, n)
	prov.state = make(map[string]mail.Flags, n)
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("1.%d.INBOX", i)
		rows = append(rows, mail.Applied{ID: id, Before: mail.Flags{}, After: mail.Flags{Seen: true}})
		prov.state[id] = mail.Flags{Seen: true}
	}
	rec, err := j.Append("work", "bulk", fmt.Sprintf("read on %d messages", n), rows)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return h, prov, j, rec
}

// TestUndo_PartialReversesRest holds G17 and IS9.4: a record of 1000
// messages, one of which a second client starred after the operation.
// Undo reverses the 999 messages still in the recorded state, in calls
// of at most 500 ids, and never touches the changed one; it lists that
// id in Skipped with the fixed note. The record is reversed once: a
// second undo is refused and changes nothing (H3). This is the
// breaking scenario of DS9.12: before G17 the one changed message
// refused the whole undo for good.
//
// arch: DS9.5, DS9.12, IS9.4
func TestUndo_PartialReversesRest(t *testing.T) {
	h, prov, j, rec := partialFixture(t, 1000)
	ctx := context.Background()
	const changed = "1.500.INBOX"
	prov.state[changed] = mail.Flags{Seen: true, Flagged: true}

	out, err := h.handle(ctx, ModifyIn{Account: "work", Undo: rec.ID})
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	if !reflect.DeepEqual(out.Skipped, []string{changed}) {
		t.Errorf("skipped = %v, want [%s]", out.Skipped, changed)
	}
	if !strings.Contains(out.Note, "1 messages changed or gone since the operation were left as they are") {
		t.Errorf("note = %q, want the skipped note of DS9.5", out.Note)
	}
	if len(out.Applied) != 999 {
		t.Errorf("applied rows = %d, want 999", len(out.Applied))
	}

	// The provider calls: read false only, at most 500 ids each, 999
	// ids in all, the changed id in none of them.
	seen := make(map[string]bool, 999)
	for _, call := range prov.calls {
		if len(call.ids) > MaxModifyIDs {
			t.Errorf("a reverse call carries %d ids, want at most %d", len(call.ids), MaxModifyIDs)
		}
		if c := call.change; c.Read == nil || *c.Read || c.Starred != nil || c.MoveTo != "" {
			t.Errorf("reverse change = %s, want read false only", showChange(c))
		}
		for _, id := range call.ids {
			if id == changed {
				t.Fatalf("undo touched the message a second client changed (I16)")
			}
			seen[id] = true
		}
	}
	if len(seen) != 999 {
		t.Errorf("undo reversed %d distinct messages, want 999", len(seen))
	}
	for _, n := range prov.stateReads {
		if n > MaxModifyIDs {
			t.Errorf("a state read carries %d ids, want at most %d (S9-GAP5)", n, MaxModifyIDs)
		}
	}
	if got := prov.state[changed]; !got.Seen || !got.Flagged {
		t.Errorf("the changed message is now %+v, want read and starred as the second client left it", got)
	}
	if got := prov.state["1.1.INBOX"]; got.Seen {
		t.Errorf("1.1.INBOX is still read after the undo: %+v", got)
	}

	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 1 || !recs[0].Reversed() {
		t.Fatalf("journal = %d records, want the one record reversed", len(recs))
	}
	undone := 0
	for _, c := range recs[0].Changes {
		if c.Undone {
			undone++
		} else if c.ID != changed {
			t.Errorf("row %s is not marked undone", c.ID)
		}
	}
	if undone != 999 {
		t.Errorf("undone rows = %d, want 999", undone)
	}

	// H3: the record is reversed once.
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: rec.ID}); err == nil ||
		!strings.Contains(err.Error(), "reversed already") {
		t.Fatalf("second undo: err = %v, want the reversed-already refusal", err)
	}
	if len(prov.calls) != 0 {
		t.Errorf("a second undo reached the provider: %d calls", len(prov.calls))
	}
}

// TestUndo_StaleFolderSkipsOnlyItsIDs holds G17 for a folder that
// changed since the operation. A record holds messages in INBOX, in
// "Old", which the server built again (imap.ErrStaleID), and in
// "Gone", which another client deleted (imap.ErrFolderGone). The ids
// of those two folders are skipped, and undo reverses the INBOX
// messages, whatever the order of the folders in the record.
//
// arch: DS9.5, G17, R16-M6
func TestUndo_StaleFolderSkipsOnlyItsIDs(t *testing.T) {
	for _, order := range [][]string{
		{"1.1.INBOX", "5.1.Old", "6.1.Gone", "1.2.INBOX"},
		{"5.1.Old", "6.1.Gone", "1.1.INBOX", "1.2.INBOX"},
	} {
		t.Run(order[0], func(t *testing.T) {
			h, prov, j := modifyFixture(t)
			prov.state = make(map[string]mail.Flags, len(order))
			rows := make([]mail.Applied, 0, len(order))
			for _, id := range order {
				rows = append(rows, mail.Applied{ID: id, Before: mail.Flags{}, After: mail.Flags{Seen: true}})
				prov.state[id] = mail.Flags{Seen: true}
			}
			rec, err := j.Append("work", "modify", "read on 4 messages", rows)
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			prov.folderErr = map[string]error{
				"Old":  imap.ErrStaleID,
				"Gone": fmt.Errorf("%w %q", imap.ErrFolderGone, "Gone"),
			}

			out, err := h.handle(context.Background(), ModifyIn{Account: "work", Undo: rec.ID})
			if err != nil {
				t.Fatalf("undo: %v", err)
			}
			if !reflect.DeepEqual(out.Skipped, []string{"5.1.Old", "6.1.Gone"}) {
				t.Errorf("skipped = %v, want [5.1.Old 6.1.Gone]", out.Skipped)
			}
			if len(prov.calls) != 1 || !reflect.DeepEqual(prov.calls[0].ids, []string{"1.1.INBOX", "1.2.INBOX"}) {
				t.Errorf("reverse calls = %+v, want one call over the two INBOX ids", prov.calls)
			}
		})
	}
}

// TestUndo_AllChangedStaysOpen holds G17 and IS9.4: when every
// message of the record changed or went away, undo changes nothing,
// gives the fixed error and keeps the record open with no row marked
// undone. Once the state is back the same token reverses the record,
// once.
//
// arch: DS9.5, DS9.12, IS9.4
func TestUndo_AllChangedStaysOpen(t *testing.T) {
	h, prov, j, rec := partialFixture(t, 3)
	ctx := context.Background()
	saved := make(map[string]mail.Flags, len(prov.state))
	for id, f := range prov.state {
		saved[id] = f
	}
	prov.state["1.1.INBOX"] = mail.Flags{Seen: true, Flagged: true} // flags changed
	delete(prov.state, "1.2.INBOX")                                 // expunged
	prov.state["1.3.INBOX"] = mail.Flags{}                          // read cleared by hand

	_, err := h.handle(ctx, ModifyIn{Account: "work", Undo: rec.ID})
	if !errors.Is(err, undo.ErrChangedOrGone) {
		t.Fatalf("undo: err = %v, want ErrChangedOrGone", err)
	}
	if err.Error() != "undo: every message changed or gone since the operation" {
		t.Errorf("undo error text = %q, want the fixed text of DS9.5", err)
	}
	if len(prov.calls) != 0 {
		t.Fatalf("a refused undo changed the mailbox: %+v", prov.calls)
	}
	recs, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 1 || recs[0].Reversed() {
		t.Fatalf("journal = %+v, want the record open", recs)
	}
	for _, c := range recs[0].Changes {
		if c.Undone {
			t.Errorf("row %s is marked undone after a refused undo", c.ID)
		}
	}

	prov.state = saved
	out, err := h.handle(ctx, ModifyIn{Account: "work", Undo: rec.ID})
	if err != nil {
		t.Fatalf("undo with the state back: %v", err)
	}
	if len(out.Skipped) != 0 || len(out.Applied) != 3 {
		t.Errorf("undo result = %+v, want 3 rows and nothing skipped", out)
	}
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: rec.ID}); err == nil {
		t.Error("a second undo of the reversed record passed (H3)")
	}
}

// TestUndo_JunkMoveRestoresKeywords holds DS8.2d and §3.18: a move out
// of Junk changed the junk keywords, so its rows carry them in Before
// and After. The undo gives the old keywords back through the labels
// and marks the move back KeepJunkKeywords, so the provider does not
// apply the junk rule a second time. This holds for an IMAP move (a
// new id, a move back to the first folder) and a JMAP move (the same
// id, RestoreFolders).
//
// arch: DS8.2d, §3.18, DS78.5
func TestUndo_JunkMoveRestoresKeywords(t *testing.T) {
	h, prov, _ := modifyFixture(t)
	ctx := context.Background()

	prov.res = []mail.Applied{
		{ID: "1.10.Junk", NewID: "7.3.Work",
			Before: mail.Flags{Labels: []string{"$Junk"}}, After: mail.Flags{Labels: []string{"$NotJunk"}}},
		{ID: "J1", Before: mail.Flags{Labels: []string{"$junk"}}, After: mail.Flags{Labels: []string{"$notjunk"}},
			FoldersBefore: []string{"mb-junk"}, FoldersAfter: []string{"mb-work"}},
	}
	out, err := h.handle(ctx, ModifyIn{Account: "work", IDs: []string{"1.10.Junk", "J1"}, MoveTo: "Work"})
	if err != nil || out.Undo == "" {
		t.Fatalf("move: out = %+v, err = %v; want an undo token", out, err)
	}

	prov.res = nil
	prov.calls = nil
	if _, err := h.handle(ctx, ModifyIn{Account: "work", Undo: out.Undo}); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if len(prov.calls) != 2 {
		t.Fatalf("provider calls = %d, want one for each message: %+v", len(prov.calls), prov.calls)
	}
	for _, call := range prov.calls {
		ch := call.change
		if !ch.KeepJunkKeywords {
			t.Errorf("reverse of %v = %s, want KeepJunkKeywords", call.ids, showChange(ch))
		}
		switch call.ids[0] {
		case "7.3.Work":
			if ch.MoveTo != "Junk" || !reflect.DeepEqual(ch.AddLabels, []string{"$Junk"}) || !reflect.DeepEqual(ch.RemoveLabels, []string{"$NotJunk"}) {
				t.Errorf("IMAP reverse = %s, want move_to Junk, add $Junk, remove $NotJunk", showChange(ch))
			}
		case "J1":
			if !reflect.DeepEqual(ch.RestoreFolders, []string{"mb-junk"}) || !reflect.DeepEqual(ch.AddLabels, []string{"$junk"}) || !reflect.DeepEqual(ch.RemoveLabels, []string{"$notjunk"}) {
				t.Errorf("JMAP reverse = %s restore %v, want restore [mb-junk], add $junk, remove $notjunk", showChange(ch), ch.RestoreFolders)
			}
		default:
			t.Errorf("a reverse call names an id nobody moved: %v", call.ids)
		}
	}

	// A reverse with no move does not carry the mark.
	if back, _ := reverseChange(undo.Change{Before: mail.Flags{Seen: true}}); back.KeepJunkKeywords {
		t.Errorf("a flag-only reverse = %+v, want no KeepJunkKeywords", back)
	}
}
