// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package secrets

import "fmt"

// Select turns the store kind that accounts.toml (or MAILBAG_SECRETS)
// records into a live Store. service names the keyring service
// (§3.4: "mailbag-mcp"); dir is the file store's directory.
//
// Select has exactly two cases and no default: an unrecognised or
// empty kind is an error, never a silent choice of one store over the
// other. The CLI picks the kind once; everything downstream obeys
// that record instead of guessing again (trap B3).
//
// arch: T1.3, §3.4, D4, D13, B1, B2, B3, B16, A10
func Select(kind, service, dir string) (Store, error) {
	switch kind {
	case KindKeyring:
		return NewKeyringStore(service), nil
	case KindFile:
		return NewFileStore(dir), nil
	default:
		return nil, fmt.Errorf("secrets: unknown store kind %q (want %q or %q)", kind, KindKeyring, KindFile)
	}
}
