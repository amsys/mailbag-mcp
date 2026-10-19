// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file tests replaceFile and its retry loop: a journal write must
// not fail when a reader holds the record open on Windows.

package undo

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// errSharing is ERROR_SHARING_VIOLATION (32) of Windows. The tests use
// the number on each system, because retryRename gets its error check
// from the caller.
const errSharing = syscall.Errno(32)

// isSharing is the error check that the retry tests give to
// retryRename.
func isSharing(err error) bool { return errors.Is(err, errSharing) }

// fakeRename sets renameFunc and sleepFunc for one test. The rename
// fails with errSharing for the first fails calls and then succeeds.
// It gives the number of calls and the total wait. The test must not
// call t.Parallel, because it changes package variables.
func fakeRename(t *testing.T, fails int) (calls *int, waited *time.Duration) {
	t.Helper()
	calls = new(int)
	waited = new(time.Duration)
	oldRename, oldSleep := renameFunc, sleepFunc
	t.Cleanup(func() { renameFunc, sleepFunc = oldRename, oldSleep })
	renameFunc = func(oldPath, newPath string) error {
		*calls++
		if *calls <= fails {
			return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: errSharing}
		}
		return nil
	}
	sleepFunc = func(d time.Duration) { *waited += d }
	return calls, waited
}

// TestReplace_RetriesSharingError checks that retryRename tries again
// after a sharing error and succeeds when the reader closed the file.
func TestReplace_RetriesSharingError(t *testing.T) {
	calls, waited := fakeRename(t, 3)
	if err := retryRename("a", "b", isSharing); err != nil {
		t.Fatalf("retryRename: %v, want nil after 3 sharing errors", err)
	}
	if *calls != 4 {
		t.Errorf("rename calls = %d, want 4", *calls)
	}
	if want := 7 * time.Millisecond; *waited != want {
		t.Errorf("total wait = %v, want %v (1 + 2 + 4 ms)", *waited, want)
	}
}

// TestReplace_GivesErrorAfterBudget checks that retryRename stops at
// replaceBudget and gives the last sharing error.
func TestReplace_GivesErrorAfterBudget(t *testing.T) {
	calls, waited := fakeRename(t, 1<<30)
	err := retryRename("a", "b", isSharing)
	if !errors.Is(err, errSharing) {
		t.Fatalf("retryRename: %v, want the sharing error", err)
	}
	if *waited != replaceBudget {
		t.Errorf("total wait = %v, want %v", *waited, replaceBudget)
	}
	if *calls < 2 || *calls > 20 {
		t.Errorf("rename calls = %d, want a few retries with a backoff", *calls)
	}
}

// TestReplace_OtherErrorAtOnce checks that retryRename gives an error
// that is not a sharing error at once, with no wait.
func TestReplace_OtherErrorAtOnce(t *testing.T) {
	calls, waited := fakeRename(t, 0)
	renameFunc = func(string, string) error { *calls++; return os.ErrNotExist }
	if err := retryRename("a", "b", isSharing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retryRename: %v, want os.ErrNotExist", err)
	}
	if *calls != 1 || *waited != 0 {
		t.Errorf("calls = %d, wait = %v; want 1 call and no wait", *calls, *waited)
	}
}

// TestJournal_ExtendWhileRecordOpen checks that Extend succeeds while a
// reader holds the record file open, and that the record then has all
// rows. On Windows, Go opens a file without FILE_SHARE_DELETE, so a
// rename over the open record fails with "Access is denied" when
// replaceFile does not try again. On other systems a rename ignores
// open handles, so there the test always passes.
func TestJournal_ExtendWhileRecordOpen(t *testing.T) {
	t.Parallel()
	j := New(filepath.Join(t.TempDir(), "undo"))
	rec, err := j.Append("work", "bulk", "read on 1 message", applied("1.10.INBOX", ""))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	f, err := os.Open(j.path(rec.ID))
	if err != nil {
		t.Fatalf("open the record: %v", err)
	}
	type result struct {
		rec Record
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := j.Extend(rec.ID, append(applied("1.11.INBOX", ""), applied("1.12.INBOX", "")...))
		done <- result{r, err}
	}()
	time.Sleep(100 * time.Millisecond)
	if err := f.Close(); err != nil {
		t.Fatalf("close the record: %v", err)
	}

	got := <-done
	if got.err != nil {
		t.Fatalf("Extend while the record is open: %v", got.err)
	}
	if len(got.rec.Changes) != 3 {
		t.Errorf("Extend gave %d rows, want 3", len(got.rec.Changes))
	}
	disk, err := j.read(rec.ID)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(disk.Changes) != 3 {
		t.Errorf("record on disk has %d rows, want 3", len(disk.Changes))
	}
}
