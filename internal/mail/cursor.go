// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Cursor is the decoded form of a search tool's cursor argument: the
// provider's own position marker for the next page, plus a hash of
// the query that produced it (§3.9). IMAP's Position is the lowest UID
// of the page; gmail's is a pageToken; jmap's is a position.
//
// HashQuery ties Position to one query, but does not sign it: any
// caller can build a valid cursor for any query and any Position value
// (§3.9-C). Position must carry only a place inside the result set
// that the query already bounds, such as a UID or a page token. It
// must never carry a value that decides what a caller may access,
// such as an account id, a folder name, or a mailbox id, because
// nothing stops a caller from putting a different one in.
type Cursor struct {
	Position  string `json:"position"`
	QueryHash string `json:"query_hash"`

	// UIDValidity ties Position to one IMAP folder incarnation
	// (DRV.12). A provider with no such idea of UIDVALIDITY leaves it
	// zero. A caller checks it against the folder's current value
	// before trusting Position, because a folder recreated since the
	// first page reuses old UID numbers for different messages.
	UIDValidity uint32 `json:"uid_validity,omitempty"`
}

// ErrCursorInvalid is returned when a cursor string is not one that
// EncodeCursor produced. The search tool comes from a model, so this
// string is untrusted input and must never be trusted enough to panic
// on (§3.9, §3.15).
var ErrCursorInvalid = errors.New("mail: cursor: invalid")

// ErrCursorMismatch is returned when a cursor's query hash does not
// match the query it is used with (§3.9: "a cursor with a different
// query hash is refused").
var ErrCursorMismatch = errors.New("mail: cursor: does not match this query")

// ErrCursorUIDValidityChanged is returned when a cursor's UIDValidity
// does not match the folder's current one. The folder was recreated
// since the first page, so a UID the cursor names can now belong to a
// different message; paging on would show the wrong rows instead of
// failing (DRV.12).
var ErrCursorUIDValidityChanged = errors.New("the folder changed since the first page; search again")

// cursorWire is the JSON shape EncodeCursor writes. Its fields are
// []byte, not string: encoding/json always base64-encodes a []byte
// field and reverses that exactly on unmarshal. A plain string field
// does not have this property, because json.Marshal replaces a byte
// that is not valid UTF-8 with U+FFFD, which would turn EncodeCursor
// into a lossy codec for a Position or QueryHash that holds such a
// byte (§3.9: the cursor must reverse to the exact value it was built
// from).
type cursorWire struct {
	Position  []byte `json:"position"`
	QueryHash []byte `json:"query_hash"`

	// UIDValidity is a plain number, not a []byte: it has no byte
	// string to preserve exactly, unlike Position and QueryHash.
	UIDValidity uint32 `json:"uid_validity,omitempty"`
}

// EncodeCursor turns c into the opaque base64url string a provider
// returns as next_cursor.
func EncodeCursor(c Cursor) string {
	b, _ := json.Marshal(cursorWire{Position: []byte(c.Position), QueryHash: []byte(c.QueryHash), UIDValidity: c.UIDValidity}) // []byte fields cannot fail to marshal
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

// DecodeCursor reverses EncodeCursor. Any string that EncodeCursor did
// not produce yields ErrCursorInvalid, never a panic: s comes from a
// tool call argument, so it is attacker-controlled.
func DecodeCursor(s string) (Cursor, error) {
	b, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
	if err != nil {
		return Cursor{}, fmt.Errorf("%w: %w", ErrCursorInvalid, err)
	}
	var w cursorWire
	if err := json.Unmarshal(b, &w); err != nil {
		return Cursor{}, fmt.Errorf("%w: %w", ErrCursorInvalid, err)
	}
	return Cursor{Position: string(w.Position), QueryHash: string(w.QueryHash), UIDValidity: w.UIDValidity}, nil
}

// HashQuery returns a short, stable hash of the parts of q that decide
// its result set (Raw text, Folder and Since all narrow which messages
// qualify), so a cursor built for one search cannot be replayed
// against a different one. Limit is not part of it: a caller asking
// for a smaller or larger page of the same search still walks the
// same position.
func HashQuery(q Query) string {
	// %q quotes and escapes each field on its own, so a quote,
	// backslash or NUL byte inside Folder or Raw cannot shift where
	// one field ends and the next begins (a plain "\x00" join can:
	// {Folder:"A", Raw:"\x00B"} and {Folder:"A\x00", Raw:"B"} would
	// hash the same).
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%q\x00%q\x00%q", q.Folder, q.Raw, q.Since.UTC().Format(time.RFC3339Nano))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// ValidateCursor decodes s and checks its query hash against q. An
// empty s is the first page and is always valid, with a zero Cursor.
func ValidateCursor(s string, q Query) (Cursor, error) {
	if s == "" {
		return Cursor{}, nil
	}
	c, err := DecodeCursor(s)
	if err != nil {
		return Cursor{}, err
	}
	if c.QueryHash != HashQuery(q) {
		return Cursor{}, ErrCursorMismatch
	}
	return c, nil
}
