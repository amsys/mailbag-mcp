// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zalando/go-keyring"
)

// keyringTimeout is the limit on one Get, so a locked keyring with
// nobody at the desktop does not block the server forever (trap B2).
// S0 (U1) found the underlying dbus call has no time limit of its
// own: a locked KeePassXC database blocks until a person answers the
// unlock dialog. Tests lower this to keep the suite fast.
var keyringTimeout = 30 * time.Second

// keyringBackend is the part of github.com/zalando/go-keyring that
// KeyringStore uses. A test supplies a fake here, so it never reaches
// the real Secret Service.
type keyringBackend interface {
	Set(service, user, pass string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type realKeyring struct{}

func (realKeyring) Set(service, user, pass string) error     { return keyring.Set(service, user, pass) }
func (realKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (realKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

// KeyringStore keeps secrets in the desktop's Secret Service (D13),
// under one keyring service name and one keyring user name for each
// key.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
type KeyringStore struct {
	service string
	backend keyringBackend
}

// NewKeyringStore returns a KeyringStore for the given keyring service
// name (§3.4: "mailbag-mcp").
func NewKeyringStore(service string) *KeyringStore {
	return newKeyringStore(service, realKeyring{})
}

func newKeyringStore(service string, backend keyringBackend) *KeyringStore {
	return &KeyringStore{service: service, backend: backend}
}

// Kind returns "keyring".
func (s *KeyringStore) Kind() string { return KindKeyring }

// Get reads key, with the 30 s limit of trap B2. A locked keyring
// that nobody unlocks in time, or a cancelled unlock dialog, comes
// back as a plain error -- never as ErrNotFound. That distinction is
// what keeps trap B3 from happening one layer up: a caller that only
// falls back to the file store on ErrNotFound never mistakes "locked"
// for "absent".
func (s *KeyringStore) Get(key string) (string, error) {
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		v, err := s.backend.Get(s.service, key)
		done <- result{v, err}
	}()

	select {
	case r := <-done:
		if errors.Is(r.err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		if r.err != nil {
			return "", fmt.Errorf("keyring locked or not available; open it and try again: %w", r.err)
		}
		return r.value, nil
	case <-time.After(keyringTimeout):
		return "", fmt.Errorf("keyring locked or not available; open it and try again (timed out after %s)", keyringTimeout)
	}
}

// Set writes key, with the same 30 s limit as Get (DRV.6): a locked
// keyring blocks a write exactly as it blocks a read, and a rotation
// save that never returns would otherwise hold its caller forever. On
// the too-big case of trap B1 -- Windows refuses a password above
// about 2560 bytes, macOS refuses the whole service+user+password
// above about 2.9 KB -- it names the fallback, because a refresh
// token that grows past that edge otherwise fails with no way out.
func (s *KeyringStore) Set(key, value string) error {
	done := make(chan error, 1)
	go func() {
		done <- s.backend.Set(s.service, key, value)
	}()

	select {
	case err := <-done:
		if errors.Is(err, keyring.ErrSetDataTooBig) {
			return fmt.Errorf("secret for %q is too large for the system keyring (about 2560 bytes on Windows, 2.9 KB on macOS); the store kind is recorded in accounts.toml, not chosen by MAILBAG_SECRETS=file alone -- set secrets = \"file\" there, then run %q to store the secret again: %w", key, reauthCommand(key, value), err)
		}
		if err != nil {
			return fmt.Errorf("keyring: set %q: %w", key, err)
		}
		return nil
	case <-time.After(keyringTimeout):
		return fmt.Errorf("keyring locked or not available; open it and try again (timed out after %s)", keyringTimeout)
	}
}

// reauthCommand names the command that stores alias's secret again.
// There is no `account reauth` subcommand (ORV.13). An OAuth secret
// needs `--reauth`; a password secret does not. value is the raw
// secret about to be written, so its "kind" field picks the form.
func reauthCommand(alias, value string) string {
	var v struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal([]byte(value), &v) == nil && v.Kind == "oauth" {
		return fmt.Sprintf("mailbag-mcp account add %s --reauth", alias)
	}
	return fmt.Sprintf("mailbag-mcp account add %s", alias)
}

// Delete removes key, with the same 30 s limit as Get and Set (DRV.6).
// A timeout is not ErrNotFound (B3): a keyring that never answered is
// not the same as one that answered "no such key".
func (s *KeyringStore) Delete(key string) error {
	done := make(chan error, 1)
	go func() {
		done <- s.backend.Delete(s.service, key)
	}()

	select {
	case err := <-done:
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("keyring: delete %q: %w", key, err)
		}
		return nil
	case <-time.After(keyringTimeout):
		return fmt.Errorf("keyring locked or not available; open it and try again (timed out after %s)", keyringTimeout)
	}
}
