// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// TestFileStore_GetSetDelete checks the plain round trip and the
// ErrNotFound mapping the Store interface promises.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestFileStore_GetSetDelete(t *testing.T) {
	store := NewFileStore(t.TempDir())

	if _, err := store.Get("acct1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get of an absent key: got %v, want ErrNotFound", err)
	}
	if err := store.Set("acct1", `{"v":1}`); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get("acct1")
	if err != nil || got != `{"v":1}` {
		t.Fatalf("Get after Set: got (%q, %v)", got, err)
	}
	if err := store.Delete("acct1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get("acct1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: got %v, want ErrNotFound", err)
	}
	if store.Kind() != KindFile {
		t.Fatalf("Kind() = %q, want %q", store.Kind(), KindFile)
	}
}

// TestFileStore_Modes checks trap B16: Set creates the directory at
// mode 0700 and the file at mode 0600.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestFileStore_Modes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on Windows (B16)")
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	store := NewFileStore(dir)
	if err := store.Set("acct1", "value"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("secrets dir mode = %#o, want 0700", perm)
	}

	fileInfo, err := os.Stat(filepath.Join(dir, "acct1"))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("secrets file mode = %#o, want 0600", perm)
	}
}

// TestFileStore_RefusesWideMode checks trap B16: Get refuses a file
// that is readable by group or other, instead of returning its
// content.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestFileStore_RefusesWideMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on Windows (B16)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "acct1")
	if err := os.WriteFile(path, []byte("value"), 0o644); err != nil { //nolint:gosec // G306: the test needs a wide mode to prove the store refuses it
		t.Fatalf("write fixture: %v", err)
	}

	store := NewFileStore(dir)
	_, err := store.Get("acct1")
	if err == nil {
		t.Fatal("Get must refuse a file readable by group or other (B16)")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a wide-mode file is not absent, got ErrNotFound: %v", err)
	}
}

// TestFileStore_RefusesWritableDir checks that Get and Set refuse a
// store directory that group or other can write. Such a user can
// replace a key file with a file of their own. A directory that they
// can only read or search (0755) passes; doctor reports it.
//
// arch: B16, R16-L18
func TestFileStore_RefusesWritableDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on Windows (B16)")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "acct1"), []byte("value"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	store := NewFileStore(dir)
	if err := os.Chmod(dir, 0o775); err != nil { //nolint:gosec // G302: the test needs a wide directory mode to prove the store refuses it
		t.Fatal(err)
	}
	if _, err := store.Get("acct1"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Get in a 0775 dir: err = %v, want a refusal", err)
	}
	if err := store.Set("acct2", "v"); err == nil {
		t.Error("Set in a 0775 dir: err = nil, want a refusal")
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the test needs a wide directory mode to prove the store refuses it
		t.Fatal(err)
	}
	if v, err := store.Get("acct1"); err != nil || v != "value" {
		t.Errorf("Get in a 0755 dir = %q, %v, want \"value\", nil", v, err)
	}
	if err := store.Set("acct2", "v"); err != nil {
		t.Errorf("Set in a 0755 dir: %v", err)
	}
}

// TestFileStore_ParallelSet checks trap A10: concurrent Set calls for
// different keys each land in their own file (temp file + rename),
// so none of them lose data.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestFileStore_ParallelSet(t *testing.T) {
	store := NewFileStore(t.TempDir())

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("acct%d", i)
			if err := store.Set(key, key+"-value"); err != nil {
				t.Errorf("Set(%s): %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		key := fmt.Sprintf("acct%d", i)
		got, err := store.Get(key)
		if err != nil || got != key+"-value" {
			t.Errorf("Get(%s) = (%q, %v), want (%q, nil)", key, got, err, key+"-value")
		}
	}
}

// TestFileStore_RejectsPathTraversal checks that a key is never
// turned into a path that leaves the store directory (B17 covers
// where aliases come from; this is the store's own defense).
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestFileStore_RejectsPathTraversal(t *testing.T) {
	store := NewFileStore(t.TempDir())
	if _, err := store.Get("../evil"); err == nil {
		t.Fatal("Get must reject a key that would leave the store directory")
	}
	if err := store.Set("../evil", "x"); err == nil {
		t.Fatal("Set must reject a key that would leave the store directory")
	}
}
