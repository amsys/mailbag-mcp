// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mime

import (
	stdmime "mime"
	"strings"

	gomessage "github.com/emersion/go-message"
	gomail "github.com/emersion/go-message/mail"
)

// DecodeHeaderText decodes one RFC 2047 encoded-word header value (a
// Subject, a display name) to UTF-8. A header that fails to decode, or
// that names a charset go-message/charset does not know, comes back
// unchanged: the raw text is still readable (§3.14, C21, C22).
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func DecodeHeaderText(s string) string {
	dec := stdmime.WordDecoder{CharsetReader: gomessage.CharsetReader}
	out, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return out
}

// ParseAddressList parses an address-list header value (From, To, Cc).
// An empty or blank s gives a nil list and no error. A value that
// fails to parse — M15: a display name with a comma inside quotes,
// such as "Smith, John" <j@x>, must not be cut at the comma — is
// parsed by net/mail through go-message/mail, never by a hand-written
// pattern. When it still fails, the caller shows the raw header text
// instead of the parsed list (§3.14, C22).
//
// arch: T3.3, §3.14, §3.10, C20, C21, C22, M15
func ParseAddressList(s string) ([]*gomail.Address, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	return gomail.ParseAddressList(s)
}
