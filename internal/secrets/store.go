// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package secrets stores account passwords, refresh tokens and OAuth
// client secrets, behind one Store interface with two kinds: the
// system keyring and a plain-file fallback (§3.4, D4, D13). The CLI
// picks the kind once and records it; nothing in this package changes
// that choice on its own (trap B3).
package secrets

import "errors"

// ErrNotFound is the error every Store returns when a key holds no
// value. Both store kinds map their own "not found" case to this one
// sentinel, so a caller never has to know which kind it is talking to.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
var ErrNotFound = errors.New("secrets: not found")

// Store kind names, as accounts.toml records them (§3.4).
const (
	KindKeyring = "keyring"
	KindFile    = "file"
)

// Store reads and writes account secrets. A key is an account alias
// or one of the fixed OAuth client keys ("oauth.google",
// "oauth.microsoft"); the value is the already-encoded JSON text §3.4
// describes. Set and Get pass that text through unchanged.
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
type Store interface {
	// Get returns ErrNotFound when key holds no value.
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
	// Kind is "keyring" or "file".
	Kind() string
}
