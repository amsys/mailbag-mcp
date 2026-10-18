// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ParsePastedRedirect extracts the authorization code from the full
// redirect URL a person pastes back after signing in over SSH, where
// no loopback listener can receive the browser's redirect (§3.6,
// --paste). It checks the URL's "state" against wantState with the
// same constant-time comparison the loopback server uses, so a stale
// or copied-from-elsewhere URL is rejected the same way.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
func ParsePastedRedirect(raw, wantState string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("oauth: that is not a URL")
	}
	q := u.Query()

	if errCode := q.Get("error"); errCode != "" {
		if desc := q.Get("error_description"); desc != "" {
			return "", fmt.Errorf("oauth: sign-in was refused: %s (%s)", errCode, desc)
		}
		return "", fmt.Errorf("oauth: sign-in was refused: %s", errCode)
	}

	state := q.Get("state")
	if !constantTimeEqual(state, wantState) {
		return "", errors.New("oauth: the pasted URL's state does not match this sign-in")
	}

	code := q.Get("code")
	if code == "" {
		return "", errors.New("oauth: the pasted URL carries no authorization code")
	}
	return code, nil
}
