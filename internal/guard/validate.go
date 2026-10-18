// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// ErrControlChar is returned when a text field holds a CR, LF or NUL
// byte. The caller must refuse the value. It must never strip the
// byte and continue, because that hides a header-injection attempt
// (M10, §3.15).
var ErrControlChar = errors.New("guard: value holds a CR, LF or NUL byte")

// ErrInvalidAlias is returned when an alias fails the pattern of B17.
var ErrInvalidAlias = errors.New("guard: invalid account alias")

// ErrInvalidAddress is returned when an address fails to parse. The
// error text never holds the address or a fragment of it, because a
// call-end log that writes the error text must not gain an address
// (§10.5).
var ErrInvalidAddress = errors.New("guard: invalid address")

// ValidateAddress parses addr as one RFC 5322 mail address and fails
// when it fails to parse. It never repairs or guesses at a bad
// address (§3.15, T2.6), and it never echoes addr, or the stdlib
// parse error, into the returned error, because both can hold a
// fragment of addr (§10.5).
//
// arch: T2.6, §3.15, M10, B17
func ValidateAddress(addr string) error {
	if _, err := mail.ParseAddress(addr); err != nil {
		return ErrInvalidAddress
	}
	return nil
}

// ValidateAddresses parses each address in addrs. It fails on the
// first bad address and names it in the error (§3.15, T2.6).
//
// arch: T2.6, §3.15, M10, B17
func ValidateAddresses(addrs []string) error {
	for _, a := range addrs {
		if err := ValidateAddress(a); err != nil {
			return err
		}
	}
	return nil
}

// ValidateField refuses a CR, LF or NUL byte anywhere in value, and
// returns the trimmed value on success. It trims trailing white
// space first, since a subject or file name typed by a person often
// carries a trailing space or newline that carries no attack; the
// caller must use the returned value, not its own original, so that
// trailing white space never reaches a raw header writer. A CR, LF
// or NUL is never removed: the caller must refuse the whole value
// (M10, §3.15).
//
// arch: T2.6, §3.15, M10, B17
func ValidateField(value string) (string, error) {
	trimmed := strings.TrimRight(value, " \t\r\n")
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", ErrControlChar
	}
	return trimmed, nil
}

// ValidateAlias checks alias against the pattern of B17 (§3.15,
// T2.6). It is the same rule as config.ValidAlias, kept in guard so
// every tool can run one input-validation pass from one package.
//
// arch: T2.6, §3.15, M10, B17
func ValidateAlias(alias string) error {
	if !config.ValidAlias(alias) {
		return fmt.Errorf("%w: %q", ErrInvalidAlias, alias)
	}
	return nil
}
