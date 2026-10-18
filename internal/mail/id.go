// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidID is returned when a string is not an id FormatIMAPID
// built. A caller must refuse it, never guess at a repair.
var ErrInvalidID = errors.New("mail: invalid id")

// FormatIMAPID builds the id string the imap and outlook providers use:
// "<uidvalidity>.<uid>.<folder>" (§3.8). The folder name is free to
// hold a dot itself; ParseIMAPID reads it back correctly because it
// only ever splits on the first two dots.
func FormatIMAPID(uidValidity, uid uint32, folder string) string {
	return fmt.Sprintf("%d.%d.%s", uidValidity, uid, folder)
}

// ParseIMAPID reverses FormatIMAPID with SplitN(id, ".", 3), so a
// folder name that holds a dot stays intact in the third field, exactly
// as §3.8 specifies. An id is valid only together with the account it
// came from; this function checks only its shape.
func ParseIMAPID(id string) (uidValidity, uid uint32, folder string, err error) {
	parts := strings.SplitN(id, ".", 3)
	if len(parts) != 3 || parts[2] == "" {
		return 0, 0, "", fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	v, errV := strconv.ParseUint(parts[0], 10, 32)
	u, errU := strconv.ParseUint(parts[1], 10, 32)
	if errV != nil || errU != nil {
		return 0, 0, "", fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	return uint32(v), uint32(u), parts[2], nil
}
