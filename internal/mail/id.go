// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mail

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidID is returned when a string is not an id FormatIMAPID
// built. A caller must refuse it, never guess at a repair.
var ErrInvalidID = errors.New("mail: invalid id")

// FormatIMAPID builds the id string the imap and outlook providers use:
// "<uidvalidity>-<uid>-<lowercase hex of the folder name bytes>". The
// hex keeps every folder name, which can be sender text, out of the id.
//
// arch: DU3.2, DU12.1
func FormatIMAPID(uidValidity, uid uint32, folder string) string {
	return fmt.Sprintf("%d-%d-%s", uidValidity, uid, hex.EncodeToString([]byte(folder)))
}

// ParseIMAPID reverses FormatIMAPID. It also reads the old form
// "<uidvalidity>.<uid>.<folder>", which the undo journal and an earlier
// session can still hold. The first separator tells the forms apart: a
// dot is the old form, a hyphen is the new one. An id is valid only
// together with the account it came from; this function checks only
// its shape.
//
// arch: DU3.2, DU12.1
func ParseIMAPID(id string) (uidValidity, uid uint32, folder string, err error) {
	bad := func() (uint32, uint32, string, error) {
		return 0, 0, "", fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	sep := strings.IndexAny(id, ".-")
	if sep < 0 {
		return bad()
	}
	parts := strings.SplitN(id, id[sep:sep+1], 3)
	if len(parts) != 3 || parts[2] == "" {
		return bad()
	}
	v, errV := strconv.ParseUint(parts[0], 10, 32)
	u, errU := strconv.ParseUint(parts[1], 10, 32)
	if errV != nil || errU != nil {
		return bad()
	}
	if id[sep] == '.' {
		return uint32(v), uint32(u), parts[2], nil
	}
	name, errH := hex.DecodeString(parts[2])
	if errH != nil || len(name) == 0 || parts[2] != strings.ToLower(parts[2]) {
		return bad()
	}
	return uint32(v), uint32(u), string(name), nil
}
