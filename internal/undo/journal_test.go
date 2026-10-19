// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package undo

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// applied gives one mail.Applied entry, the input shape of Append.
func applied(id, newID string) []mail.Applied {
	return []mail.Applied{{
		ID:     id,
		NewID:  newID,
		Before: mail.Flags{Seen: false, Labels: []string{"INBOX"}},
		After:  mail.Flags{Seen: true, Labels: []string{"TRASH"}},
	}}
}

// TestUndo_ParallelWriters checks trap A10: several server processes
// run at one time, and a journal that reads one file, changes it and
// writes it back loses records. Each operation has its own file, so
// 32 writers at once give 32 whole records and no lost work.
//
// arch: T5.3, §3.18, §3.1, A10, H3
func TestUndo_ParallelWriters(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))

	const writers = 32
	ids := make([]string, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, err := j.Append("work", "modify", "trash 1 message", applied("imap:INBOX:1", ""))
			if err != nil {
				t.Errorf("writer %d: Append: %v", i, err)
				return
			}
			ids[i] = rec.ID
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for i, id := range ids {
		if id == "" {
			t.Fatalf("writer %d wrote no record", i)
		}
		if seen[id] {
			t.Fatalf("id %s was given to two writers", id)
		}
		seen[id] = true
		if _, err := j.read(id); err != nil {
			t.Errorf("record %s does not read back: %v", id, err)
		}
	}

	// Every record must be on disk as its own whole file.
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		t.Fatalf("read undo dir: %v", err)
	}
	if len(entries) != writers {
		t.Errorf("undo dir holds %d files, want %d (a lost record, or a left-over temporary file)", len(entries), writers)
	}
	list, err := j.List("work", writers)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != writers {
		t.Errorf("List gives %d records, want %d", len(list), writers)
	}
}

// TestUndo_Once checks H3: a second undo would put the change back,
// so reversed_at refuses it. The reverse action runs one time only.
//
// arch: T5.3, §3.18, A10, H3
func TestUndo_Once(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))

	rec, err := j.Append("work", "modify", "trash 1 message", applied("imap:INBOX:7", "imap:Trash:3"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if rec.Reversed() {
		t.Error("a new record is marked reversed")
	}

	var calls int
	first, err := reverse(j, rec.ID, func(got Record) error {
		calls++
		if len(got.Changes) != 1 || got.Changes[0].NewID != "imap:Trash:3" {
			t.Errorf("Reverse gave the wrong changes: %+v", got.Changes)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("first Reverse: %v", err)
	}
	if !first.Reversed() {
		t.Error("the reversed record carries no reversed_at")
	}

	if _, err := reverse(j, rec.ID, func(Record) error {
		calls++
		return nil
	}); !errors.Is(err, ErrAlreadyReversed) {
		t.Errorf("second Reverse = %v, want ErrAlreadyReversed", err)
	}
	if calls != 1 {
		t.Errorf("the reverse action ran %d times, want 1", calls)
	}

	// The refusal must survive a restart: it is in the file, not in
	// memory (§3.1, several processes).
	again, err := New(j.dir).read(rec.ID)
	if err != nil {
		t.Fatalf("read after reverse: %v", err)
	}
	if !again.Reversed() {
		t.Error("reversed_at is not on disk, so another process would undo the operation again")
	}
	if left, _ := filepath.Glob(filepath.Join(j.dir, "*"+claimExt)); len(left) != 0 {
		t.Errorf("a claim file stayed behind: %v", left)
	}
}

// TestUndo_UnknownID checks H3: an id that is not known is an error.
// An id of the wrong shape becomes a file name, so it is refused the
// same way and reaches no file outside the directory (B17).
//
// arch: T5.3, §3.18, H3
func TestUndo_UnknownID(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	if _, err := j.Append("work", "modify", "one", applied("imap:INBOX:1", "")); err != nil {
		t.Fatalf("Append: %v", err)
	}

	cases := []struct {
		name string
		id   string
	}{
		{"absent", "00112233445566ff"},
		{"empty", ""},
		{"too short", "0011"},
		{"not hex", "zzzzzzzzzzzzzzzz"},
		{"path escape", "../../../etc/passwd"},
		{"separator", "aa/bb/cc0011223344"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ran bool
			if _, err := reverse(j, c.id, func(Record) error { ran = true; return nil }); !errors.Is(err, ErrUnknown) {
				t.Errorf("Reverse(%q) = %v, want ErrUnknown", c.id, err)
			}
			if ran {
				t.Errorf("Reverse(%q) ran the reverse action", c.id)
			}
		})
	}

	// A refused id must leave nothing behind in the directory.
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		t.Fatalf("read undo dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("undo dir holds %d files, want 1", len(entries))
	}
}

// TestUndo_ParallelReversersRunOnce checks A10 together with H3: two
// server processes that undo the same operation at the same time must
// not both act. The claim file with O_EXCL lets one pass.
//
// arch: T5.3, §3.18, §3.1, A10, H3
func TestUndo_ParallelReversersRunOnce(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("work", "modify", "trash 1 message", applied("imap:INBOX:1", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	const racers = 16
	var applyCalls, okCalls atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := reverse(j, rec.ID, func(Record) error {
				applyCalls.Add(1)
				// The reverse action of the tool layer talks to a
				// mail server. Hold the claim while the others try,
				// so the test sees the window a weaker guard leaves
				// open.
				time.Sleep(20 * time.Millisecond)
				return nil
			})
			switch {
			case err == nil:
				okCalls.Add(1)
			case errors.Is(err, ErrAlreadyReversed):
			default:
				t.Errorf("Reverse: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := okCalls.Load(); got != 1 {
		t.Errorf("%d reversers passed, want 1", got)
	}
	if got := applyCalls.Load(); got != 1 {
		t.Errorf("the reverse action ran %d times, want 1", got)
	}
}

// TestUndo_ApplyFailureKeepsTheRecordOpen checks that a reverse which
// fails on the mail server does not mark the record reversed. The
// person can try again; a lost claim would make the operation
// impossible to undo.
//
// arch: T5.3, §3.18, A10, H3
func TestUndo_ApplyFailureKeepsTheRecordOpen(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("work", "modify", "trash 1 message", applied("imap:INBOX:1", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	boom := errors.New("imap: connection lost")
	if _, err := reverse(j, rec.ID, func(Record) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("Reverse = %v, want the apply error", err)
	}

	got, err := j.read(rec.ID)
	if err != nil {
		t.Fatalf("read after a failed reverse: %v", err)
	}
	if got.Reversed() {
		t.Error("a failed reverse marked the record reversed")
	}
	if left, _ := filepath.Glob(filepath.Join(j.dir, "*"+claimExt)); len(left) != 0 {
		t.Errorf("a claim file stayed behind, so a retry is refused for ever: %v", left)
	}
	if _, err := reverse(j, rec.ID, func(Record) error { return nil }); err != nil {
		t.Errorf("the retry after a failed reverse = %v, want nil", err)
	}
}

// TestUndo_RecordFileShape checks §3.18: one file for each operation,
// named <id>.json with an id of 16 hex characters, mode 0600 in a
// directory with mode 0700, and the field names of the design.
//
// arch: T5.3, §3.18, §3.1
func TestUndo_RecordFileShape(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("work", "modify", "trash 1 message", applied("imap:INBOX:1", "imap:Trash:9"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	if len(rec.ID) != 16 {
		t.Errorf("id %q has %d characters, want 16", rec.ID, len(rec.ID))
	}
	if _, err := hex.DecodeString(rec.ID); err != nil {
		t.Errorf("id %q is not hex: %v", rec.ID, err)
	}

	path := filepath.Join(j.dir, rec.ID+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("record mode is %#o, want 0600 (§3.3)", perm)
		}
		dir, err := os.Stat(j.dir)
		if err != nil {
			t.Fatalf("stat undo dir: %v", err)
		}
		if perm := dir.Mode().Perm(); perm != 0o700 {
			t.Errorf("undo dir mode is %#o, want 0700 (§3.3)", perm)
		}
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: path built by the test in its temp dir
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("the record is not JSON: %v", err)
	}
	for _, key := range []string{"id", "ts", "account", "tool", "summary", "changes"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("the record has no %q field (§3.18)", key)
		}
	}
	if _, ok := raw["reversed_at"]; ok {
		t.Error("a new record carries reversed_at already")
	}
	changes, ok := raw["changes"].([]any)
	if !ok || len(changes) != 1 {
		t.Fatalf("changes = %v, want one entry", raw["changes"])
	}
	change, ok := changes[0].(map[string]any)
	if !ok {
		t.Fatalf("changes[0] = %v, want an object", changes[0])
	}
	for _, key := range []string{"id", "new_id", "before", "after"} {
		if _, ok := change[key]; !ok {
			t.Errorf("changes[0] has no %q field (§3.18)", key)
		}
	}
}

// TestUndo_CleanupRemovesOldFiles checks §3.18: files older than 30
// days go at start. A left-over claim file of a process that died in
// the middle of a reversal goes the same way.
//
// arch: T5.3, §3.18, §3.1, A10
func TestUndo_CleanupRemovesOldFiles(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))

	old, err := j.Append("work", "modify", "old", applied("imap:INBOX:1", ""))
	if err != nil {
		t.Fatalf("Append old: %v", err)
	}
	fresh, err := j.Append("work", "modify", "fresh", applied("imap:INBOX:2", ""))
	if err != nil {
		t.Fatalf("Append fresh: %v", err)
	}
	stale := filepath.Join(j.dir, "00112233445566aa"+claimExt)
	if err := os.WriteFile(stale, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write stale claim: %v", err)
	}

	aged := time.Now().Add(-31 * 24 * time.Hour)
	for _, p := range []string{filepath.Join(j.dir, old.ID+".json"), stale} {
		if err := os.Chtimes(p, aged, aged); err != nil {
			t.Fatalf("chtimes %s: %v", p, err)
		}
	}

	removed, err := j.Cleanup(MaxAge)
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 2 {
		t.Errorf("Cleanup removed %d files, want 2", removed)
	}
	if _, err := j.read(old.ID); !errors.Is(err, ErrUnknown) {
		t.Errorf("the 31-day-old record is still there: %v", err)
	}
	if _, err := j.read(fresh.ID); err != nil {
		t.Errorf("Cleanup removed a fresh record: %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Error("Cleanup left the stale claim file, so that operation can never be undone")
	}

	// A directory that does not exist is a first run, not an error.
	empty := New(filepath.Join(t.TempDir(), "nothing-here"))
	if n, err := empty.Cleanup(MaxAge); err != nil || n != 0 {
		t.Errorf("Cleanup on a missing directory = (%d, %v), want (0, nil)", n, err)
	}
}

// TestUndo_ListNewestFirst checks §3.16: `undo: "list"` shows the
// last operations of the account. Another account never shows.
//
// arch: T5.3, §3.18, §3.16
func TestUndo_ListNewestFirst(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))

	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	step := 0
	j.now = func() time.Time { step++; return base.Add(time.Duration(step) * time.Minute) }

	want := []string{}
	for _, acct := range []string{"work", "home", "work", "work"} {
		rec, err := j.Append(acct, "modify", "one", applied("imap:INBOX:1", ""))
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		if acct == "work" {
			want = append([]string{rec.ID}, want...) // newest first
		}
	}

	got, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("List gives %d records, want %d", len(got), len(want))
	}
	for i, rec := range got {
		if rec.ID != want[i] {
			t.Errorf("record %d is %s, want %s (newest first)", i, rec.ID, want[i])
		}
		if rec.Account != "work" {
			t.Errorf("record %d belongs to account %q", i, rec.Account)
		}
	}

	if all, err := j.List("", 2); err != nil || len(all) != 2 {
		t.Errorf("List(\"\", 2) = (%d records, %v), want (2, nil)", len(all), err)
	}
	// A file that does not parse is skipped, not an error.
	if err := os.WriteFile(filepath.Join(j.dir, "ffffffffffffffff.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatalf("write broken record: %v", err)
	}
	if got, err := j.List("work", 0); err != nil || len(got) != len(want) {
		t.Errorf("List with one broken file = (%d records, %v), want (%d, nil)", len(got), err, len(want))
	}
}

// TestUndo_OpenUsesStateDir checks §3.3: the journal sits in the
// state directory, which MAILBAG_STATE_DIR replaces for a test.
//
// arch: T5.3, §3.3, §3.18
func TestUndo_OpenUsesStateDir(t *testing.T) {
	state := t.TempDir()
	t.Setenv("MAILBAG_STATE_DIR", state)

	j, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if want := filepath.Join(state, "undo"); j.dir != want {
		t.Errorf("Open() dir = %q, want %q", j.dir, want)
	}
}

// box is a mailbox that two clients share in TestUndo_ChangedOrGone.
// The key is the message id, which names the folder (§3.8), and the
// value is the flags the message has now.
type box map[string]mail.Flags

func (b box) copyOf() box {
	out := make(box, len(b))
	for id, f := range b {
		f.Labels = append([]string(nil), f.Labels...)
		out[id] = f
	}
	return out
}

// current gives the state that undo reads from the box: a copy of the
// flags of each message, with no mailbox list. An IMAP box has none;
// the folder is in the id (§3.8).
func (b box) current() map[string]Current {
	out := make(map[string]Current, len(b))
	for id, f := range b.copyOf() {
		out[id] = Current{Flags: f}
	}
	return out
}

// TestUndo_ChangedOrGone holds I16 on the journal: undo compares the
// state of each message now with the state the operation left, through
// Record.Partition. When a second client expunged the only message of
// the operation, moved it or changed its flags, no row is ok: undo
// changes nothing, keeps the record open and gives the fixed error. A
// wrong comparison would undo the wrong message in silence. The record
// is reversed once, after the state is back.
//
// arch: D5.4, DS9.5, DS9.12, IS9.4
func TestUndo_ChangedOrGone(t *testing.T) {
	t.Parallel()

	const (
		src   = "5.10.INBOX"
		moved = "8.3.Archive"
		other = "9.4.Later"
	)
	read := mail.Flags{Seen: true, Labels: []string{"Work", "todo"}}
	unread := mail.Flags{Labels: []string{"Work", "todo"}}

	cases := []struct {
		name    string
		applied mail.Applied
		after   box                       // the mailbox right after the operation
		second  func(b box)               // what the second client does
		want    error                     // nil: undo runs
		back    func(t *testing.T, b box) // the mailbox after an undo that ran
	}{
		{
			name:    "unchanged, labels in another order and case",
			applied: mail.Applied{ID: src, Before: unread, After: read},
			after:   box{src: read},
			second: func(b box) {
				b[src] = mail.Flags{Seen: true, Labels: []string{"TODO", "work"}}
			},
			back: func(t *testing.T, b box) {
				if b[src].Seen {
					t.Errorf("the message is still read: %+v", b[src])
				}
			},
		},
		{
			name:    "second client expunges",
			applied: mail.Applied{ID: src, Before: unread, After: read},
			after:   box{src: read},
			second:  func(b box) { delete(b, src) },
			want:    ErrChangedOrGone,
		},
		{
			name:    "second client moves",
			applied: mail.Applied{ID: src, Before: unread, After: read},
			after:   box{src: read},
			second: func(b box) {
				b[other] = b[src]
				delete(b, src)
			},
			want: ErrChangedOrGone,
		},
		{
			name:    "second client changes flags",
			applied: mail.Applied{ID: src, Before: unread, After: read},
			after:   box{src: read},
			second: func(b box) {
				f := b[src]
				f.Flagged = true
				b[src] = f
			},
			want: ErrChangedOrGone,
		},
		{
			name:    "second client removes a label",
			applied: mail.Applied{ID: src, Before: unread, After: read},
			after:   box{src: read},
			second: func(b box) {
				b[src] = mail.Flags{Seen: true, Labels: []string{"Work"}}
			},
			want: ErrChangedOrGone,
		},
		{
			name:    "a moved message: second client expunges the new copy",
			applied: mail.Applied{ID: src, NewID: moved, Before: read, After: read},
			after:   box{moved: read},
			second:  func(b box) { delete(b, moved) },
			want:    ErrChangedOrGone,
		},
		{
			name:    "a moved message: second client moves it on, the old id is back",
			applied: mail.Applied{ID: src, NewID: moved, Before: read, After: read},
			after:   box{moved: read},
			second: func(b box) {
				// A message now sits at the first id. Only the id
				// the operation left counts, so this is gone.
				b[src] = b[moved]
				delete(b, moved)
			},
			want: ErrChangedOrGone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			j := New(filepath.Join(t.TempDir(), "undo"))
			rec, err := j.Append("work", "modify", "one", []mail.Applied{tc.applied})
			if err != nil {
				t.Fatalf("Append: %v", err)
			}
			if got := rec.Changes[0].UIDValidity; got == 0 {
				t.Errorf("the record keeps no UIDVALIDITY for %q", tc.applied.ID)
			}

			mbox := tc.after.copyOf()
			tc.second(mbox)
			seen := mbox.copyOf()

			// The undo: read the state now, compare, and only then
			// put the flags back and the message in its folder.
			undo := func(r Record) error {
				ok, _ := r.Partition(mbox.current())
				if len(ok) == 0 {
					return ErrChangedOrGone
				}
				for _, i := range ok {
					c := r.Changes[i]
					if c.NewID != "" {
						delete(mbox, c.NewID)
					}
					mbox[c.ID] = c.Before
				}
				return nil
			}
			_, err = reverse(j, rec.ID, undo)

			if tc.want == nil {
				if err != nil {
					t.Fatalf("undo of an unchanged message: %v", err)
				}
				tc.back(t, mbox)
				return
			}

			if !errors.Is(err, tc.want) {
				t.Fatalf("undo error = %v, want %v", err, tc.want)
			}
			if err.Error() != "undo: every message changed or gone since the operation" {
				t.Errorf("undo error text = %q, want the fixed text of D5.4", err)
			}
			if len(mbox) != len(seen) {
				t.Errorf("undo changed the mailbox: %v, want %v", mbox, seen)
			}
			for id, f := range seen {
				if got, ok := mbox[id]; !ok || !sameFlags(got, f) {
					t.Errorf("undo changed %s: %+v, want %+v", id, got, f)
				}
			}

			// The record stays open: the list shows it not reversed,
			// and an undo runs once the state is back.
			list, err := j.List("work", 0)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(list) != 1 || list[0].Reversed() {
				t.Fatalf("the record is not open after a refused undo: %+v", list)
			}
			mbox = tc.after.copyOf()
			if _, err := reverse(j, rec.ID, undo); err != nil {
				t.Errorf("undo after the state came back: %v", err)
			}
			if _, err := reverse(j, rec.ID, undo); !errors.Is(err, ErrAlreadyReversed) {
				t.Errorf("a second undo: err = %v, want ErrAlreadyReversed (H3)", err)
			}
		})
	}
}

// TestUndo_StaleClaimRemoved holds IRV.9: a process that died in the
// middle of an undo leaves its claim file. A claim older than two tool
// deadlines (90 s) is dead, so the next undo removes it and goes on. A
// fresh claim still belongs to a live process and still refuses.
//
// arch: DRV.11
func TestUndo_StaleClaimRemoved(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("work", "modify", "read 1 message", applied("imap:INBOX:1", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	claim := filepath.Join(j.dir, rec.ID+claimExt)

	// A fresh claim: another process reverses the record now.
	if err := os.WriteFile(claim, nil, 0o600); err != nil {
		t.Fatalf("write the claim: %v", err)
	}
	if _, err := reverse(j, rec.ID, nil); !errors.Is(err, ErrAlreadyReversed) {
		t.Fatalf("Reverse with a fresh claim = %v, want ErrAlreadyReversed", err)
	}

	// The same claim, two minutes old: its process is dead.
	old := time.Now().Add(-2 * time.Minute)
	if err := os.Chtimes(claim, old, old); err != nil {
		t.Fatalf("age the claim: %v", err)
	}
	ran := false
	got, err := reverse(j, rec.ID, func(Record) error { ran = true; return nil })
	if err != nil {
		t.Fatalf("Reverse with a dead claim: %v", err)
	}
	if !ran || !got.Reversed() {
		t.Errorf("apply ran = %v, reversed = %v; want both", ran, got.Reversed())
	}
	if left, _ := filepath.Glob(filepath.Join(j.dir, "*"+claimExt)); len(left) != 0 {
		t.Errorf("claim files left: %v", left)
	}
}

// TestUndo_ClaimRefreshErrorStopsUndo checks T199 item 9: when the
// claim file cannot be refreshed after a step, the undo stops at that
// step boundary. The next step does not run, the error says "undo:
// refresh claim" and wraps the cause, the record stays open with the
// progress of the step that ran, and no claim file stays. A retry then
// reverses only the rest (DRV.11).
//
// arch: DS11.14, DS11.18
func TestUndo_ClaimRefreshErrorStopsUndo(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	two := append(applied("imap:INBOX:1", ""), applied("imap:INBOX:2", "")...)
	rec, err := j.Append("work", "modify", "trash 2 messages", two)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	// The claim refresh fails from the first step on (DS11.20 G2).
	j.chtimes = func(name string, _, _ time.Time) error {
		return &os.PathError{Op: "chtimes", Path: name, Err: os.ErrPermission}
	}
	var ran []int
	steps := func(r Record, progress Progress) error {
		for i, c := range r.Changes {
			if c.Undone {
				continue
			}
			ran = append(ran, i)
			if err := progress([]int{i}); err != nil {
				return err
			}
		}
		return nil
	}
	_, err = j.ReverseInSteps(rec.ID, steps)

	if err == nil || !strings.HasPrefix(err.Error(), "undo: refresh claim") {
		t.Fatalf("ReverseInSteps error = %v, want the text to start with %q", err, "undo: refresh claim")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("ReverseInSteps error = %v, want it to wrap the chtimes cause", err)
	}
	if len(ran) != 1 || ran[0] != 0 {
		t.Errorf("steps that ran = %v, want [0]: the undo must stop at the first step boundary", ran)
	}
	got, err := j.read(rec.ID)
	if err != nil {
		t.Fatalf("read after the stopped undo: %v", err)
	}
	if got.Reversed() {
		t.Error("the stopped undo marked the record reversed")
	}
	if !got.Changes[0].Undone || got.Changes[1].Undone {
		t.Errorf("undone = [%v %v], want [true false]: the record keeps the step that ran",
			got.Changes[0].Undone, got.Changes[1].Undone)
	}
	if left, _ := filepath.Glob(filepath.Join(j.dir, "*"+claimExt)); len(left) != 0 {
		t.Errorf("a claim file stayed behind, so a retry is refused: %v", left)
	}

	// The refresh works again: the retry reverses the second change only.
	j.chtimes = os.Chtimes
	ran = nil
	done, err := j.ReverseInSteps(rec.ID, steps)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !done.Reversed() || len(ran) != 1 || ran[0] != 1 {
		t.Errorf("retry: reversed = %v, steps that ran = %v; want true and [1]", done.Reversed(), ran)
	}
}

// takeClaim does what claim does for a dead claim, from a second
// process B: it removes the claim file at path and creates a new one
// at the same path with O_EXCL. It gives the file info of B's claim.
//
// On Windows a file that a process holds open cannot be removed, and A
// holds its claim open while apply runs. So B cannot take a live claim
// there, and the rule of the caller is POSIX only. takeClaim then
// checks that the remove of B fails, and skips the rest of the test.
func takeClaim(t *testing.T, path string) os.FileInfo {
	t.Helper()
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err == nil {
			t.Fatal("B removed the claim that A holds open; on Windows that must fail")
		}
		t.Skip("reason: POSIX-only rule: Windows refuses to remove the claim file that A holds open, so B cannot take it")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("B removes the old claim: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path built by the test in its temp dir
	if err != nil {
		t.Fatalf("B creates its claim: %v", err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat the claim of B: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close the claim of B: %v", err)
	}
	return info
}

// TestUndo_TakenClaimNotRenamed checks that a process renames only
// the claim file it owns. Process B takes the claim while process A
// runs apply. A then must not move the empty claim of B over the
// record: A gives an error, the record file still parses, List still
// shows the operation, and the claim of B stays.
//
// arch: REVIEW-2026-10-12 H8
func TestUndo_TakenClaimNotRenamed(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("work", "modify", "read 1 message", applied("imap:INBOX:1", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	claimPath := filepath.Join(j.dir, rec.ID+claimExt)

	var b os.FileInfo
	_, err = j.ReverseInSteps(rec.ID, func(Record, Progress) error {
		b = takeClaim(t, claimPath)
		return nil
	})
	if err == nil {
		t.Fatal("ReverseInSteps of A gave no error after B took the claim")
	}

	got, rerr := j.read(rec.ID)
	if rerr != nil {
		t.Fatalf("the record does not parse after A finished: %v", rerr)
	}
	if got.Reversed() {
		t.Error("A marked the record reversed with a claim it no longer owns")
	}
	list, lerr := j.List("work", 0)
	if lerr != nil {
		t.Fatalf("List: %v", lerr)
	}
	if len(list) != 1 || list[0].ID != rec.ID {
		t.Errorf("List = %d records, want the one record %s", len(list), rec.ID)
	}
	now, serr := os.Stat(claimPath)
	if serr != nil {
		t.Fatalf("the claim of B is gone: %v", serr)
	}
	if !os.SameFile(b, now) {
		t.Error("the file at the claim path is not the claim of B")
	}
}

// TestUndo_FailedApplyKeepsOtherClaim checks that a failed undo
// removes only the claim file it owns. Process B takes the claim while
// process A runs apply, and the apply of A then fails. The claim of B
// must stay, or a third process can claim the record too.
//
// arch: REVIEW-2026-10-12 H8
func TestUndo_FailedApplyKeepsOtherClaim(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("work", "modify", "read 1 message", applied("imap:INBOX:1", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	claimPath := filepath.Join(j.dir, rec.ID+claimExt)

	boom := errors.New("the server went away")
	var b os.FileInfo
	_, err = j.ReverseInSteps(rec.ID, func(Record, Progress) error {
		b = takeClaim(t, claimPath)
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("ReverseInSteps of A = %v, want the apply error", err)
	}

	now, serr := os.Stat(claimPath)
	if serr != nil {
		t.Fatalf("the failed undo of A removed the claim of B: %v", serr)
	}
	if !os.SameFile(b, now) {
		t.Error("the file at the claim path is not the claim of B")
	}
}

// TestUndo_RecordKeepsFolders holds DS78.5 on the journal: Append
// copies the mailbox lists of a JMAP row into the record, under the
// keys folders_before and folders_after. An IMAP row has no mailbox
// lists, and its record has neither key, so the IMAP record keeps the
// shape it had before.
//
// arch: DS78.5, DS78.8, IS8.4
func TestUndo_RecordKeepsFolders(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("home", "modify", "archive 2 messages", []mail.Applied{
		{ID: "M1", FoldersBefore: []string{"mb-inbox"}, FoldersAfter: []string{"mb-archive"}},
		{ID: "5.10.INBOX", NewID: "8.3.Archive"},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if got := rec.Changes[0]; len(got.FoldersBefore) != 1 || got.FoldersBefore[0] != "mb-inbox" ||
		len(got.FoldersAfter) != 1 || got.FoldersAfter[0] != "mb-archive" {
		t.Errorf("the JMAP change = %+v, want the mailbox lists of the row", got)
	}

	data, err := os.ReadFile(filepath.Join(j.dir, rec.ID+".json"))
	if err != nil {
		t.Fatalf("read the record: %v", err)
	}
	var raw struct {
		Changes []map[string]any `json:"changes"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("the record is not JSON: %v", err)
	}
	if len(raw.Changes) != 2 {
		t.Fatalf("changes = %d, want 2", len(raw.Changes))
	}
	jmapRow, imapRow := raw.Changes[0], raw.Changes[1]
	for key, want := range map[string]string{"folders_before": "mb-inbox", "folders_after": "mb-archive"} {
		list, ok := jmapRow[key].([]any)
		if !ok || len(list) != 1 || list[0] != want {
			t.Errorf("the JMAP change has %s = %v, want [%s]", key, jmapRow[key], want)
		}
	}
	for _, key := range []string{"folders_before", "folders_after"} {
		if _, ok := imapRow[key]; ok {
			t.Errorf("the IMAP change has the key %q; omitempty must keep the old record shape", key)
		}
	}

	back, err := j.read(rec.ID)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !SameFolders(back.Changes[0].FoldersBefore, []string{"mb-inbox"}) ||
		!SameFolders(back.Changes[0].FoldersAfter, []string{"mb-archive"}) {
		t.Errorf("the record read back = %+v, want the mailbox lists", back.Changes[0])
	}
}

// TestRecord_PartitionComparesFolders holds gap G3 of DS78.5: a JMAP
// move keeps the id, so a message that another client moved since the
// operation still has an entry. Partition compares the mailboxes of a
// change that has FoldersAfter with the mailboxes now, as a set, and
// skips the change when they differ or when the provider gave none. A
// change with no FoldersAfter (IMAP, Gmail) compares the flags only.
// It was TestUndo_CheckComparesFolders before Partition replaced
// Check; each case keeps its claim.
//
// arch: DS78.5, DS78.8, IS8.4, DS9.5
func TestRecord_PartitionComparesFolders(t *testing.T) {
	t.Parallel()
	jmapRec := Record{Changes: []Change{{
		ID:            "M1",
		FoldersBefore: []string{"mb-inbox"},
		FoldersAfter:  []string{"mb-archive", "mb-work"},
	}}}
	imapRec := Record{Changes: []Change{{ID: "5.10.INBOX"}}}

	cases := []struct {
		name    string
		rec     Record
		current map[string]Current
		want    error
	}{
		{"same mailboxes in another order", jmapRec,
			map[string]Current{"M1": {Folders: []string{"mb-work", "mb-archive"}}}, nil},
		{"moved on by a second client", jmapRec,
			map[string]Current{"M1": {Folders: []string{"mb-later"}}}, ErrChangedOrGone},
		{"one mailbox removed by a second client", jmapRec,
			map[string]Current{"M1": {Folders: []string{"mb-archive"}}}, ErrChangedOrGone},
		{"a mailbox name that differs in case", jmapRec,
			map[string]Current{"M1": {Folders: []string{"mb-Archive", "mb-work"}}}, ErrChangedOrGone},
		{"no mailboxes in the read", jmapRec,
			map[string]Current{"M1": {}}, ErrChangedOrGone},
		{"flags changed, mailboxes the same", jmapRec,
			map[string]Current{"M1": {Flags: mail.Flags{Flagged: true}, Folders: []string{"mb-archive", "mb-work"}}}, ErrChangedOrGone},
		{"gone", jmapRec, map[string]Current{}, ErrChangedOrGone},
		{"an IMAP change does not compare mailboxes", imapRec,
			map[string]Current{"5.10.INBOX": {Folders: []string{"anything"}}}, nil},
	}
	for _, tc := range cases {
		ok, skipped := tc.rec.Partition(tc.current)
		wantOK := tc.want == nil
		if wantOK && (len(ok) != 1 || len(skipped) != 0) {
			t.Errorf("%s: Partition = ok %v, skipped %v; want the change ok", tc.name, ok, skipped)
		}
		if !wantOK && (len(ok) != 0 || len(skipped) != 1) {
			t.Errorf("%s: Partition = ok %v, skipped %v; want the change skipped", tc.name, ok, skipped)
		}
	}
}

// TestRecord_Partition holds DS9.5 and G17: Partition gives the
// indexes of the changes still in the After state (ok) and of the ones
// that are gone or differ (skipped), in record order. A change that an
// earlier undo reversed is in neither list (DRV.11).
//
// arch: DS9.5, DS9.12, IS9.4
func TestRecord_Partition(t *testing.T) {
	t.Parallel()
	read := mail.Flags{Seen: true, Labels: []string{"Work"}}
	rec := Record{Changes: []Change{
		{ID: "1.10.INBOX", After: read},                                 // 0: unchanged
		{ID: "1.11.INBOX", After: read},                                 // 1: flags changed
		{ID: "1.12.INBOX", NewID: "2.5.Archive", After: read},           // 2: unchanged at its new id
		{ID: "1.13.INBOX", After: read},                                 // 3: gone
		{ID: "1.14.INBOX", After: read, Undone: true},                   // 4: reversed already
		{ID: "1.15.INBOX", NewID: "2.6.Archive", After: read},           // 5: the old id is back, the new one gone
		{ID: "1.16.INBOX", After: mail.Flags{Labels: []string{"work"}}}, // 6: label case differs only
	}}
	current := map[string]Current{
		"1.10.INBOX":  {Flags: read},
		"1.11.INBOX":  {Flags: mail.Flags{Seen: true, Flagged: true, Labels: []string{"Work"}}},
		"2.5.Archive": {Flags: read},
		"1.14.INBOX":  {Flags: mail.Flags{}},
		"1.15.INBOX":  {Flags: read},
		"1.16.INBOX":  {Flags: mail.Flags{Labels: []string{"WORK"}}},
	}
	ok, skipped := rec.Partition(current)
	if want := []int{0, 2, 6}; !equalInts(ok, want) {
		t.Errorf("ok = %v, want %v", ok, want)
	}
	if want := []int{1, 3, 5}; !equalInts(skipped, want) {
		t.Errorf("skipped = %v, want %v", skipped, want)
	}

	ok, skipped = rec.Partition(nil)
	if len(ok) != 0 || !equalInts(skipped, []int{0, 1, 2, 3, 5, 6}) {
		t.Errorf("with no state: ok %v, skipped %v; want every open change skipped", ok, skipped)
	}
}

// equalInts reports whether two index lists are equal, in order.
func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestJournal_Extend holds DS9.5 and IRV.9: Extend appends the rows
// of a later chunk to the open record, so one bulk operation is one
// file with one token. The rows of the first chunk stay as Append wrote
// them, a later reader sees every row, and the new rows keep their
// UIDVALIDITY the way Append rows do. Extend leaves no claim file.
//
// arch: DS9.5, DS9.12, IS9.4
func TestJournal_Extend(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "undo")
	j := New(dir)
	rec, err := j.Append("work", "bulk", "read on 2 messages", append(applied("1.10.INBOX", ""), applied("1.11.INBOX", "")...))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := j.Extend(rec.ID, append(applied("1.12.INBOX", ""), applied("1.13.INBOX", "2.4.Trash")...))
	if err != nil {
		t.Fatalf("Extend: %v", err)
	}
	if got.ID != rec.ID || len(got.Changes) != 4 {
		t.Fatalf("Extend gave %d rows for %s, want 4 rows for %s", len(got.Changes), got.ID, rec.ID)
	}

	list, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List gives %d records, want one record for the operation", len(list))
	}
	ids := make([]string, 0, 4)
	for _, c := range list[0].Changes {
		ids = append(ids, c.ID)
	}
	if want := "1.10.INBOX 1.11.INBOX 1.12.INBOX 1.13.INBOX"; strings.Join(ids, " ") != want {
		t.Errorf("record rows = %v, want %s", ids, want)
	}
	if c := list[0].Changes[3]; c.NewID != "2.4.Trash" || c.UIDValidity != 2 {
		t.Errorf("extended row = %+v, want NewID 2.4.Trash and UIDVALIDITY 2", c)
	}
	if list[0].Reversed() || list[0].Tool != "bulk" || list[0].Summary != "read on 2 messages" {
		t.Errorf("record header changed: %+v", list[0])
	}
	if _, err := os.Stat(filepath.Join(dir, rec.ID+claimExt)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Extend left its claim file: stat err = %v", err)
	}

	// The undo of the extended record sees every row.
	seen := 0
	if _, err := reverse(j, rec.ID, func(r Record) error { seen = len(r.Changes); return nil }); err != nil {
		t.Fatalf("Reverse: %v", err)
	}
	if seen != 4 {
		t.Errorf("undo saw %d rows, want 4", seen)
	}
}

// TestJournal_ExtendReversedFails holds DS9.5 and H3: Extend never
// adds rows to a record that is reversed, that an undo reverses now,
// or that does not exist. Each refusal leaves the record as it was.
//
// arch: DS9.5, DS9.12, IS9.4
func TestJournal_ExtendReversedFails(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "undo")
	j := New(dir)

	rec, err := j.Append("work", "bulk", "one", applied("1.10.INBOX", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := reverse(j, rec.ID, nil); err != nil {
		t.Fatalf("Reverse: %v", err)
	}
	if _, err := j.Extend(rec.ID, applied("1.11.INBOX", "")); !errors.Is(err, ErrAlreadyReversed) {
		t.Errorf("Extend of a reversed record: err = %v, want ErrAlreadyReversed", err)
	}
	list, err := j.List("work", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || len(list[0].Changes) != 1 || !list[0].Reversed() {
		t.Errorf("record after the refused Extend = %+v, want one row, reversed", list)
	}

	// An undo holds the claim now: Extend must not write under it.
	open, err := j.Append("work", "bulk", "two", applied("1.12.INBOX", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	claimPath := filepath.Join(dir, open.ID+claimExt)
	if err := os.WriteFile(claimPath, nil, 0o600); err != nil {
		t.Fatalf("write claim: %v", err)
	}
	if _, err := j.Extend(open.ID, applied("1.13.INBOX", "")); !errors.Is(err, ErrAlreadyReversed) {
		t.Errorf("Extend under a live claim: err = %v, want ErrAlreadyReversed", err)
	}
	if _, err := os.Stat(claimPath); err != nil {
		t.Errorf("Extend removed the claim of another process: %v", err)
	}

	for _, id := range []string{"0123456789abcdef", "../escape", ""} {
		if _, err := j.Extend(id, applied("1.14.INBOX", "")); !errors.Is(err, ErrUnknown) {
			t.Errorf("Extend(%q): err = %v, want ErrUnknown", id, err)
		}
	}
}

// reverse runs ReverseInSteps with an apply that takes no Progress. It
// keeps the one-step tests short; the old Journal.Reverse wrapper did
// the same.
func reverse(j *Journal, id string, apply func(Record) error) (Record, error) {
	var steps func(Record, Progress) error
	if apply != nil {
		steps = func(rec Record, _ Progress) error { return apply(rec) }
	}
	return j.ReverseInSteps(id, steps)
}
