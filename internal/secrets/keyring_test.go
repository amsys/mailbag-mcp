// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package secrets

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// fakeKeyringBackend is a keyringBackend a test controls completely,
// so no test in this package ever reaches the real Secret Service.
type fakeKeyringBackend struct {
	mu    sync.Mutex
	store map[string]string // "service\x00user" -> value

	getErr      error         // returned by every Get, if set
	setErr      error         // returned by every Set, if set
	getDelay    time.Duration // Get blocks this long before it answers
	setDelay    time.Duration // Set blocks this long before it answers
	deleteDelay time.Duration // Delete blocks this long before it answers
}

func newFakeKeyringBackend() *fakeKeyringBackend {
	return &fakeKeyringBackend{store: map[string]string{}}
}

func (f *fakeKeyringBackend) key(service, user string) string { return service + "\x00" + user }

func (f *fakeKeyringBackend) Set(service, user, pass string) error {
	if f.setDelay > 0 {
		time.Sleep(f.setDelay)
	}
	if f.setErr != nil {
		return f.setErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[f.key(service, user)] = pass
	return nil
}

func (f *fakeKeyringBackend) Get(service, user string) (string, error) {
	if f.getDelay > 0 {
		time.Sleep(f.getDelay)
	}
	if f.getErr != nil {
		return "", f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.store[f.key(service, user)]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (f *fakeKeyringBackend) Delete(service, user string) error {
	if f.deleteDelay > 0 {
		time.Sleep(f.deleteDelay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.key(service, user)
	if _, ok := f.store[k]; !ok {
		return keyring.ErrNotFound
	}
	delete(f.store, k)
	return nil
}

// TestKeyringStore_GetSetDelete checks the plain round trip and the
// ErrNotFound mapping the Store interface promises.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestKeyringStore_GetSetDelete(t *testing.T) {
	store := newKeyringStore("mailbag-test", newFakeKeyringBackend())

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
	if store.Kind() != KindKeyring {
		t.Fatalf("Kind() = %q, want %q", store.Kind(), KindKeyring)
	}
}

// TestKeyringStore_TooBig checks trap B1: a value the keyring refuses
// as too large comes back as an error that names the fallback.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestKeyringStore_TooBig(t *testing.T) {
	backend := newFakeKeyringBackend()
	backend.setErr = keyring.ErrSetDataTooBig
	store := newKeyringStore("mailbag-test", backend)

	err := store.Set("acct1", "a very long refresh token")
	if err == nil {
		t.Fatal("Set must fail when the keyring refuses the value")
	}
	if !errors.Is(err, keyring.ErrSetDataTooBig) {
		t.Fatalf("error must wrap keyring.ErrSetDataTooBig so a caller can test the cause, got %v", err)
	}
	if !strings.Contains(err.Error(), "MAILBAG_SECRETS=file") {
		t.Fatalf("error must name the fallback (B1), got %q", err.Error())
	}
}

// TestKeyringStore_Timeout checks trap B2: a Get that never answers
// -- a locked keyring with nobody at the desktop -- returns at the 30
// s limit, with an error that is not ErrNotFound (B3: "locked" must
// never look like "absent").
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func TestKeyringStore_Timeout(t *testing.T) {
	old := keyringTimeout
	keyringTimeout = 50 * time.Millisecond
	t.Cleanup(func() { keyringTimeout = old })

	backend := newFakeKeyringBackend()
	backend.getDelay = time.Second // longer than keyringTimeout
	store := newKeyringStore("mailbag-test", backend)

	start := time.Now()
	_, err := store.Get("acct1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Get on a keyring that never answers must return an error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a timeout must not look like ErrNotFound (trap B3), got %v", err)
	}
	if elapsed >= backend.getDelay {
		t.Fatalf("Get should return at the %s limit, took %s", keyringTimeout, elapsed)
	}
}

// TestKeyring_SetTimeout checks DRV.6: Set has the same 30 s limit as
// Get (trap B2 applies to a write, not only a read). A Set that never
// answers -- a locked keyring with nobody at the desktop -- must
// return at the keyringTimeout limit rather than block the caller
// forever.
//
// arch: DRV.6
func TestKeyring_SetTimeout(t *testing.T) {
	old := keyringTimeout
	keyringTimeout = 50 * time.Millisecond
	t.Cleanup(func() { keyringTimeout = old })

	backend := newFakeKeyringBackend()
	backend.setDelay = time.Second // longer than keyringTimeout
	store := newKeyringStore("mailbag-test", backend)

	start := time.Now()
	err := store.Set("acct1", "a refresh token")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Set on a keyring that never answers must return an error")
	}
	if elapsed >= backend.setDelay {
		t.Fatalf("Set should return at the %s limit, took %s", keyringTimeout, elapsed)
	}
}

// TestKeyring_DeleteTimeout is TestKeyring_SetTimeout's twin for
// Delete (DRV.6). A timeout must not look like ErrNotFound (B3): a
// keyring that never answered is not the same as one that answered
// "no such key".
//
// arch: DRV.6
func TestKeyring_DeleteTimeout(t *testing.T) {
	old := keyringTimeout
	keyringTimeout = 50 * time.Millisecond
	t.Cleanup(func() { keyringTimeout = old })

	backend := newFakeKeyringBackend()
	backend.deleteDelay = time.Second // longer than keyringTimeout
	store := newKeyringStore("mailbag-test", backend)

	start := time.Now()
	err := store.Delete("acct1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Delete on a keyring that never answers must return an error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("a timeout must not look like ErrNotFound (trap B3), got %v", err)
	}
	if elapsed >= backend.deleteDelay {
		t.Fatalf("Delete should return at the %s limit, took %s", keyringTimeout, elapsed)
	}
}
