// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package undo holds the undo journal (§3.18). One operation is one
// file: $XDG_STATE_HOME/mailbag-mcp/undo/<id>.json, mode 0600. The
// tool layer writes a record after the change succeeded and before it
// returns, and reverses an operation with the ids in that record. The
// journal never searches the mailbox again.
//
// Several server processes run at one time (§3.1). No file is changed
// in place: each write goes to a temporary file in the same directory
// and then a rename, so a reader never sees a half-written record and
// two writers never lose each other's work (trap A10).
//
// arch: T5.3, §3.18, §3.1, A10, H3
package undo

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// MaxAge is how long a record stays. Files older than this go at
// server start (§3.18).
const MaxAge = 30 * 24 * time.Hour

// ClaimMaxAge is the age at which a claim file counts as dead. It is
// two tool deadlines: a live undo finishes or fails inside one, so a
// claim this old belongs to a process that died (DRV.11).
const ClaimMaxAge = 90 * time.Second

// DefaultListLimit is how many records List returns when the caller
// asks for no limit. The list goes to the model, so it has an end.
const DefaultListLimit = 20

// idBytes is 8 bytes, which is 16 hex characters (§3.18).
const idBytes = 8

// ext is the file name suffix of a record. claimExt marks a reversal
// that runs now; see ReverseInSteps.
const (
	ext      = ".json"
	claimExt = ".json.reversing"
)

// Errors of this package. The tool layer maps them to a message for
// the model (H3).
var (
	// ErrUnknown says the id names no record. A record that the
	// 30-day cleanup removed also gives this error.
	ErrUnknown = errors.New("undo: unknown operation id")

	// ErrAlreadyReversed says the operation was reversed already, or
	// another process reverses it now. A second undo would put the
	// change back, so the journal refuses it (H3).
	ErrAlreadyReversed = errors.New("undo: this operation was reversed already")

	// ErrChangedOrGone says no message of the operation is in the
	// state the operation left it in: another client changed the
	// flags, moved or expunged each one. Undo then changes nothing and
	// keeps the record open. When only some messages changed, undo
	// reverses the rest and lists the changed ones (D5.4, I16, G17).
	ErrChangedOrGone = errors.New("undo: every message changed or gone since the operation")
)

// Change is what one message got in one operation. Before and After
// are the flags of that message, so the reverse of the operation is
// the step from After back to Before.
//
// UIDValidity is the UIDVALIDITY of the id the message has after the
// operation. MessageID is the Message-ID header of the message. Both
// are per message, because one operation can span folders. An empty
// value means the provider did not give it (D5.4).
//
// Undone is true when an undo that stopped part of the way reversed
// this message already. A retry of the undo skips it (DRV.11).
//
// FoldersBefore and FoldersAfter are the mailboxes of the message
// before and after the operation, for a provider whose move keeps the
// id (JMAP). They are empty for IMAP and Gmail, and omitempty keeps
// the record of those providers in its old shape (DS78.5).
//
// arch: T5.3, §3.18, D5.4, DRV.11, DS78.5
type Change struct {
	ID            string     `json:"id"`
	NewID         string     `json:"new_id,omitempty"` // set when the id changed (an imap move, C5)
	UIDValidity   uint32     `json:"uid_validity,omitempty"`
	MessageID     string     `json:"message_id,omitempty"`
	Before        mail.Flags `json:"before"`
	After         mail.Flags `json:"after"`
	FoldersBefore []string   `json:"folders_before,omitempty"`
	FoldersAfter  []string   `json:"folders_after,omitempty"`
	Undone        bool       `json:"undone,omitempty"`
}

// currentID gives the id the message has after the operation: the new
// id when a move changed it, the first id when it did not (C5).
func (c Change) currentID() string {
	if c.NewID != "" {
		return c.NewID
	}
	return c.ID
}

// Record is one operation of the journal, and one file.
//
// Summary is text the tool layer wrote. It can hold a folder name,
// which a person or a sender picked, so the tool layer fences it
// before it goes back to the model (§3.15). The journal stores it as
// it got it.
//
// arch: T5.3, §3.18, H3
type Record struct {
	ID         string     `json:"id"`
	TS         time.Time  `json:"ts"`
	Account    string     `json:"account"`
	Tool       string     `json:"tool"`
	Summary    string     `json:"summary"`
	Changes    []Change   `json:"changes"`
	ReversedAt *time.Time `json:"reversed_at,omitempty"`
}

// Reversed reports whether this record was reversed already.
func (r Record) Reversed() bool { return r.ReversedAt != nil }

// Current is the state of one message now, as undo reads it before a
// reversal. Folders holds the mailboxes of the message for a provider
// with mailbox lists (JMAP); it is empty for the other providers
// (DS78.5).
//
// arch: D5.4, DS78.5
type Current struct {
	Flags   mail.Flags
	Folders []string
}

// Partition compares the state of each message now with the state
// the operation left it in (D5.4, G17). current holds the state of each
// message the mailbox has now, by its current id. On IMAP the folder
// is part of the id (§3.8), so a message that another client moved or
// expunged has no entry. On JMAP a move keeps the id, so a change that
// has FoldersAfter compares the mailboxes too (DS78.5).
//
// ok holds the indexes of the changes whose message is in the After
// state: undo reverses these. skipped holds the indexes of the changes
// whose message has no entry, has flags that differ from After, or,
// when the change has FoldersAfter, has a set of mailboxes that
// differs from FoldersAfter: undo leaves these as they are. Both lists
// keep the order of r.Changes.
//
// A change that an earlier undo reversed already is in neither list:
// its message is back in the Before state (DRV.11).
//
// Partition replaces Check, which refused the whole undo when one
// message changed (G17).
//
// arch: D5.4, DRV.11, DS78.5, DS9.5, G17
func (r Record) Partition(current map[string]Current) (ok, skipped []int) {
	for i, c := range r.Changes {
		if c.Undone {
			continue
		}
		now, found := current[c.currentID()]
		switch {
		case !found, !sameFlags(now.Flags, c.After),
			len(c.FoldersAfter) > 0 && !SameFolders(now.Folders, c.FoldersAfter):
			skipped = append(skipped, i)
		default:
			ok = append(ok, i)
		}
	}
	return ok, skipped
}

// SameFolders reports whether two mailbox lists hold the same
// mailboxes. The order does not count. The case counts, because two
// JMAP mailboxes can have names that differ only in case (DS78.5).
func SameFolders(a, b []string) bool {
	return allIn(a, b) && allIn(b, a)
}

// allIn reports whether each entry of a is in b, with the case.
func allIn(a, b []string) bool {
	for _, x := range a {
		found := false
		for _, y := range b {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// sameFlags reports whether two flag states are equal. The label
// order does not count, and an IMAP keyword is case insensitive.
func sameFlags(a, b mail.Flags) bool {
	if a.Seen != b.Seen || a.Flagged != b.Flagged ||
		a.Answered != b.Answered || a.Draft != b.Draft {
		return false
	}
	return sameLabels(a.Labels, b.Labels) && sameLabels(b.Labels, a.Labels)
}

// sameLabels reports whether each label of a is in b.
func sameLabels(a, b []string) bool {
	for _, x := range a {
		found := false
		for _, y := range b {
			if strings.EqualFold(x, y) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Journal is the undo directory.
//
// arch: T5.3, §3.18, §3.1, A10
type Journal struct {
	dir string
	now func() time.Time // injected clock, for the 30-day rule

	// chtimes refreshes the claim file at each progress write. It is
	// os.Chtimes; a test puts a function that fails in its place
	// (DS11.20 G2).
	chtimes func(name string, atime, mtime time.Time) error
}

// New returns a Journal rooted at dir. dir is created with mode 0700
// on the first Append.
func New(dir string) *Journal {
	return &Journal{dir: dir, now: time.Now, chtimes: os.Chtimes}
}

// Open returns the Journal of the state directory: <state>/undo
// (§3.3). Each tool that writes or reverses an operation opens it
// this way, so every server process of the same user shares the one
// directory.
//
// arch: T5.3, §3.3, §3.18
func Open() (*Journal, error) {
	stateDir, err := config.StateDir()
	if err != nil {
		return nil, fmt.Errorf("undo: state directory: %w", err)
	}
	return New(filepath.Join(stateDir, "undo")), nil
}

// Append writes one record for an operation that succeeded, and gives
// the record back. The caller returns Record.ID to the model as the
// undo token (§3.16).
//
// The write is a temporary file and a rename, so a second process
// that reads the directory at the same time sees whole records only
// (trap A10).
//
// arch: T5.3, §3.18, §3.1, A10
func (j *Journal) Append(account, tool, summary string, applied []mail.Applied) (Record, error) {
	if err := os.MkdirAll(j.dir, 0o700); err != nil {
		return Record{}, fmt.Errorf("undo: create %s: %w", j.dir, err)
	}

	id, err := j.freeID()
	if err != nil {
		return Record{}, err
	}

	rec := Record{
		ID:      id,
		TS:      j.now().UTC(),
		Account: account,
		Tool:    tool,
		Summary: summary,
		Changes: make([]Change, 0, len(applied)),
	}
	for _, a := range applied {
		rec.Changes = append(rec.Changes, changeOf(a))
	}

	if err := j.writeNew(rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// changeOf gives the journal row of one changed message.
func changeOf(a mail.Applied) Change {
	c := Change{
		ID:            a.ID,
		NewID:         a.NewID,
		Before:        a.Before,
		After:         a.After,
		FoldersBefore: a.FoldersBefore,
		FoldersAfter:  a.FoldersAfter,
	}
	// An id that does not parse is not an IMAP id; it keeps no
	// UIDVALIDITY (D5.4).
	if v, _, _, err := mail.ParseIMAPID(c.currentID()); err == nil {
		c.UIDValidity = v
	}
	return c
}

// Extend appends rows to the open record id and gives the record back.
// bulk calls it once for each chunk after the first, which Append
// wrote, so one operation is one file (§3.18) and a stop after chunk n
// leaves the rows of chunks 1 to n on disk (IRV.9).
//
// Extend fails with ErrUnknown when id names no record, and with
// ErrAlreadyReversed when the record is reversed or another process
// reverses it now. It holds the claim file of the record while it
// writes, the same claim that ReverseInSteps takes. So an undo that
// runs at the same time never writes over the new rows, and Extend
// never adds rows to a record that an undo has read already (trap
// A10).
//
// arch: DS9.5, §3.18, A10, IRV.9, H3
func (j *Journal) Extend(id string, applied []mail.Applied) (Record, error) {
	rec, err := j.read(id)
	if err != nil {
		return Record{}, err
	}
	if rec.Reversed() {
		return Record{}, ErrAlreadyReversed
	}

	claimPath := filepath.Join(j.dir, id+claimExt)
	claim, owned, err := j.claim(claimPath)
	if errors.Is(err, os.ErrExist) {
		// Another process reverses the record now.
		return Record{}, ErrAlreadyReversed
	}
	if err != nil {
		return Record{}, fmt.Errorf("undo: claim %s: %w", claimPath, err)
	}
	done := false
	defer func() {
		if !done {
			_ = claim.Close()
			// Remove only the claim this process owns: another
			// process can have taken it (REVIEW-2026-10-12 H8).
			if ownsClaim(owned, claimPath) {
				_ = os.Remove(claimPath)
			}
		}
	}()

	// Read again under the claim: an undo may have finished between
	// the first read and the claim.
	rec, err = j.read(id)
	if err != nil {
		return Record{}, err
	}
	if rec.Reversed() {
		return Record{}, ErrAlreadyReversed
	}
	for _, a := range applied {
		rec.Changes = append(rec.Changes, changeOf(a))
	}
	if err := writeFile(claim, claimPath, rec); err != nil {
		return Record{}, err
	}
	if !ownsClaim(owned, claimPath) {
		return Record{}, fmt.Errorf("undo: another process took the claim of %s; the record stays as that process writes it", id)
	}
	if err := os.Rename(claimPath, j.path(id)); err != nil {
		return Record{}, fmt.Errorf("undo: rename %s: %w", claimPath, err)
	}
	done = true
	return rec, nil
}

// List gives the last operations of one account, newest first. An
// empty account gives every account. A limit of zero or less gives
// DefaultListLimit records.
//
// A file that does not parse is skipped, not an error: one bad file
// must never stop the tool.
//
// arch: T5.3, §3.18
func (j *Journal) List(account string, limit int) ([]Record, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}
	entries, err := os.ReadDir(j.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // nothing written yet
	}
	if err != nil {
		return nil, fmt.Errorf("undo: read %s: %w", j.dir, err)
	}

	out := make([]Record, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		rec, err := j.read(strings.TrimSuffix(e.Name(), ext))
		if err != nil {
			continue
		}
		if account != "" && rec.Account != account {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].TS.After(out[b].TS) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Progress records that the changes at the given indexes of the record
// are reversed. It writes the record at once, so a retry after a
// failure skips those changes (DRV.11).
type Progress func(done []int) error

// ReverseInSteps runs the undo of one operation. It claims the record,
// calls apply with it, and marks the record reversed only after apply
// returned nil. A failed apply leaves the record open, so the person
// can try again.
//
// A second undo is refused with ErrAlreadyReversed, because it would
// put the change back (H3). An id that names no record gives
// ErrUnknown.
//
// The claim is a file that ReverseInSteps creates with O_EXCL, so two
// server processes that undo the same operation at the same time
// cannot both pass: the kernel gives the file to one of them (trap
// A10). That file then becomes the new record, through the same
// rename every other write uses.
//
// An undo can run in more than one step. apply gets a Progress, and it
// calls it after each step that changed the mailbox. When a later step fails, the record stays open
// and keeps the progress, so the next undo finishes the rest (IRV.9).
//
// A claim file older than ClaimMaxAge belongs to a process that died.
// ReverseInSteps removes it and goes on. Each progress write touches
// the claim file, so a live undo keeps its claim fresh. When the touch
// fails, Progress gives the error "undo: refresh claim", and apply
// stops at that step boundary: a claim that is not fresh can go dead
// while the undo runs, and a second process can then take it. The
// record keeps the progress of the steps before the error, so the next
// undo finishes the rest (DS11.14).
//
// ReverseInSteps renames and removes only the claim file it created.
// When another process took the claim while apply ran, ReverseInSteps
// gives an error, does not mark the record reversed and leaves the
// claim file of that process in place (REVIEW-2026-10-12 H8).
//
// arch: T5.3, §3.18, §3.1, A10, H3, DRV.11, DS11.14, REVIEW-2026-10-12 H8
func (j *Journal) ReverseInSteps(id string, apply func(Record, Progress) error) (Record, error) {
	rec, err := j.read(id)
	if err != nil {
		return Record{}, err
	}
	if rec.Reversed() {
		return Record{}, ErrAlreadyReversed
	}

	claimPath := filepath.Join(j.dir, id+claimExt)
	claim, owned, err := j.claim(claimPath)
	if errors.Is(err, os.ErrExist) {
		// Another process holds the claim now.
		return Record{}, ErrAlreadyReversed
	}
	if err != nil {
		return Record{}, fmt.Errorf("undo: claim %s: %w", claimPath, err)
	}
	done := false
	defer func() {
		if !done {
			_ = claim.Close()
			// Remove only the claim this process owns: another
			// process can have taken it (REVIEW-2026-10-12 H8).
			if ownsClaim(owned, claimPath) {
				_ = os.Remove(claimPath)
			}
		}
	}()

	// Read again under the claim. The other process may have finished
	// its own reversal between the first read and this claim; its
	// rename removed the claim name, so O_EXCL alone cannot see that.
	rec, err = j.read(id)
	if err != nil {
		return Record{}, err
	}
	if rec.Reversed() {
		return Record{}, ErrAlreadyReversed
	}

	if apply != nil {
		progress := func(done []int) error {
			for _, i := range done {
				if i >= 0 && i < len(rec.Changes) {
					rec.Changes[i].Undone = true
				}
			}
			if err := j.writeNew(rec); err != nil {
				return err
			}
			now := j.now()
			if err := j.chtimes(claimPath, now, now); err != nil {
				return fmt.Errorf("undo: refresh claim: %w", err)
			}
			return nil
		}
		if err := apply(rec, progress); err != nil {
			return Record{}, err
		}
	}

	at := j.now().UTC()
	rec.ReversedAt = &at
	if err := writeFile(claim, claimPath, rec); err != nil {
		return Record{}, err
	}
	if !ownsClaim(owned, claimPath) {
		return Record{}, fmt.Errorf("undo: another process took the claim of %s; the record stays as that process writes it", id)
	}
	if err := os.Rename(claimPath, j.path(id)); err != nil {
		return Record{}, fmt.Errorf("undo: rename %s: %w", claimPath, err)
	}
	done = true
	return rec, nil
}

// claim creates the claim file with O_EXCL. When the file exists and
// is older than ClaimMaxAge, its process died: claim removes it and
// tries once more. A live claim gives an error that wraps
// os.ErrExist.
//
// claim also gives the file info of the new claim. The caller gives it
// to ownsClaim before each rename or remove of the claim path, because
// a second process can take the claim and put its own file at the
// same path (REVIEW-2026-10-12 H8).
//
// arch: A10, DRV.11, REVIEW-2026-10-12 H8
func (j *Journal) claim(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: path is the journal dir plus an id that read checked with validID
	if errors.Is(err, os.ErrExist) {
		info, serr := os.Stat(path)
		if serr != nil || j.now().Sub(info.ModTime()) < ClaimMaxAge {
			return nil, nil, err
		}
		if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			return nil, nil, fmt.Errorf("undo: remove the dead claim %s: %w", path, rerr)
		}
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the same checked claim path as above
	}
	if err != nil {
		return nil, nil, err
	}
	owned, err := f.Stat()
	if err != nil {
		// The file is new and still has this name, so the path
		// names the file of this process.
		_ = f.Close()
		_ = os.Remove(path)
		return nil, nil, fmt.Errorf("undo: stat the claim %s: %w", path, err)
	}
	return f, owned, nil
}

// ownsClaim reports whether the file at path is still the claim file
// owned, which claim gave. It is false when another process took the
// claim and created its own file at path, and when no file is there.
//
// arch: REVIEW-2026-10-12 H8
func ownsClaim(owned os.FileInfo, path string) bool {
	now, err := os.Stat(path)
	return err == nil && os.SameFile(owned, now)
}

// Cleanup removes every file of the directory that is older than
// maxAge, and gives the number it removed. The server calls it at
// start (§3.18). It removes a left-over claim file of a process that
// died in the middle of a reversal too, because that file is in the
// same directory and gets the same age rule.
//
// A missing directory is not an error: nothing was written yet.
//
// arch: T5.3, §3.18, §3.1
func (j *Journal) Cleanup(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(j.dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("undo: read %s: %w", j.dir, err)
	}

	cut := j.now().Add(-maxAge)
	removed := 0
	var firstErr error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // it went away under us; nothing to remove
		}
		if !info.ModTime().Before(cut) {
			continue
		}
		if err := os.Remove(filepath.Join(j.dir, e.Name())); err != nil {
			if !errors.Is(err, os.ErrNotExist) && firstErr == nil {
				firstErr = fmt.Errorf("undo: remove %s: %w", e.Name(), err)
			}
			continue
		}
		removed++
	}
	return removed, firstErr
}

// path gives the file of a record id. The caller checks the id first
// with validID.
func (j *Journal) path(id string) string { return filepath.Join(j.dir, id+ext) }

// read parses one record. An id of the wrong shape, or an id with no
// file, gives ErrUnknown.
func (j *Journal) read(id string) (Record, error) {
	if !validID(id) {
		// The id comes from the model, and it goes into a file path.
		// Do not repeat it in the error text: only a checked id is
		// safe to print (§3.15, B17).
		return Record{}, ErrUnknown
	}
	data, err := os.ReadFile(j.path(id))
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, fmt.Errorf("%w: %s", ErrUnknown, id)
	}
	if err != nil {
		return Record{}, fmt.Errorf("undo: read %s: %w", id, err)
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, fmt.Errorf("undo: parse %s: %w", id, err)
	}
	return rec, nil
}

// writeNew writes a record with a temporary file and a rename (trap
// A10). The rename replaces the file of a record that exists, so the
// progress of an undo uses it too.
func (j *Journal) writeNew(rec Record) error {
	tmp, err := os.CreateTemp(j.dir, rec.ID+".tmp*")
	if err != nil {
		return fmt.Errorf("undo: create temp file in %s: %w", j.dir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if err := writeFile(tmp, tmpPath, rec); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, j.path(rec.ID)); err != nil {
		return fmt.Errorf("undo: rename %s: %w", tmpPath, err)
	}
	return nil
}

// writeFile writes rec into the open file f and closes it. It sets
// mode 0600 itself, because the umask of the process changes what
// os.CreateTemp and os.OpenFile give (§3.3).
func writeFile(f *os.File, path string, rec Record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("undo: encode %s: %w", rec.ID, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("undo: write %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("undo: chmod %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("undo: sync %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("undo: close %s: %w", path, err)
	}
	return nil
}

// freeID gives an id of 16 hex characters that has no file yet
// (§3.18). The stat is a second guard only: 8 random bytes do not
// repeat in practice.
func (j *Journal) freeID() (string, error) {
	for try := 0; try < 5; try++ {
		var b [idBytes]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("undo: random id: %w", err)
		}
		id := hex.EncodeToString(b[:])
		if _, err := os.Stat(j.path(id)); errors.Is(err, os.ErrNotExist) {
			return id, nil
		}
	}
	return "", errors.New("undo: no free operation id")
}

// validID holds the id shape of §3.18: 16 hex characters. The id
// becomes a file name, so nothing else may pass (B17).
func validID(id string) bool {
	if len(id) != idBytes*2 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}
