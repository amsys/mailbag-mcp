// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package secrets

import (
	"errors"
	"testing"
)

// TestSelect_ReturnsStoreForRecordedKind checks the two known kinds.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestSelect_ReturnsStoreForRecordedKind(t *testing.T) {
	dir := t.TempDir()

	ks, err := Select(KindKeyring, "mailbag-test", dir)
	if err != nil {
		t.Fatalf("Select(keyring): %v", err)
	}
	if ks.Kind() != KindKeyring {
		t.Fatalf("Select(keyring).Kind() = %q, want %q", ks.Kind(), KindKeyring)
	}

	fs, err := Select(KindFile, "mailbag-test", dir)
	if err != nil {
		t.Fatalf("Select(file): %v", err)
	}
	if fs.Kind() != KindFile {
		t.Fatalf("Select(file).Kind() = %q, want %q", fs.Kind(), KindFile)
	}
}

// TestSelect_UnknownKindIsAnError checks that Select never guesses: an
// unrecognised or empty kind is an error, not a default store.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestSelect_UnknownKindIsAnError(t *testing.T) {
	if _, err := Select("cloud", "mailbag-test", t.TempDir()); err == nil {
		t.Fatal("Select must refuse a kind it does not know, never guess (B3)")
	}
	if _, err := Select("", "mailbag-test", t.TempDir()); err == nil {
		t.Fatal("Select must refuse an empty kind, never default to one store (B3)")
	}
}

// TestServer_NoSilentFallback proves trap B3: a Store recorded as
// "keyring" (the same construction Select's "keyring" case returns)
// never reads the file store, even when the keyring backend fails
// with an unlock error and a file for the same key exists with a
// different value. A silent fallback here is exactly what made
// accounts look signed out for no reason in the tool this replaces
// (§3.4: "The server never changes to the file store on its own").
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestServer_NoSilentFallback(t *testing.T) {
	dir := t.TempDir()

	fileStore := NewFileStore(dir)
	if err := fileStore.Set("acct1", "file-value"); err != nil {
		t.Fatalf("seed file store: %v", err)
	}

	backend := newFakeKeyringBackend()
	backend.getErr = errors.New("failed to unlock correct collection '/org/freedesktop/secrets/aliases/default'")
	keyringStore := newKeyringStore("mailbag-mcp", backend)

	got, err := keyringStore.Get("acct1")
	if err == nil {
		t.Fatalf("Get must fail when the keyring is locked, got value %q", got)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a locked keyring is not ErrNotFound (B3), got %v", err)
	}
	if got == "file-value" {
		t.Fatal("the keyring store must never read the file store's value")
	}
}
