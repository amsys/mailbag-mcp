// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// keyTTL is the time the key store of D5.3 keeps one done key: 24
// hours from the end of its send. The clock starts at the end and not
// at the first call, so a slow send never shortens the time in which
// a repeat sends nothing.
const keyTTL = 24 * time.Hour

// errKeyInFlight is the fixed error of D5.3 for a key that a send
// still holds. The text is server text only. It never names the key,
// because the key is model text.
var errKeyInFlight = errors.New("a send with this idempotency_key is still in progress, so this call sent nothing; wait for the first call to end, then call send again with the same idempotency_key to read its result")

// errKeyEmpty is the fixed error for an empty idempotency_key. The
// schema lists the field as required, and I9 must not depend on the
// model, so the store refuses the call.
var errKeyEmpty = errors.New("idempotency_key is empty, so nothing was sent; call send again with a new idempotency_key for this send")

// errKeyOtherDraft is the fixed error for a key that a call used with
// another draft_id. The stored result belongs to the other draft, so
// the store does not give it back for this draft.
var errKeyOtherDraft = errors.New("this idempotency_key was used with another draft_id, so this call sent nothing; use a new idempotency_key for each draft")

// keyStore is the idempotency key store of D5.3. It holds each
// (account, idempotency_key) pair in memory, per process, for
// [keyTTL]. A restart clears it; the \Answered flag and the Sent copy
// are the evidence after a restart.
//
// A key has two states. In flight: a call holds it and its send is
// not at an end. Done: the send ran, and the store holds its result.
// A key in no state is free.
//
// The rule that keeps I9 (one key sends at most one mail): a key
// becomes done as soon as the provider send starts, whatever the
// provider gives back. A send error can come after the mail left, so
// a send error is a result too, and a repeat gives that same error.
// Only a call that ends before the send starts releases its key.
//
// The zero value works and uses the wall clock. A test replaces now
// with its own clock, because a test must never wait 24 hours (C24).
//
// One send tool serves every MCP call of one process, and those calls
// can run at the same time, so every read and write of the map is
// under the mutex. The check and the claim of a key are one step
// under the lock, so two calls with one key cannot both pass.
//
// arch: D5.3, D8.3, I9
type keyStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[keyID]*keyEntry
}

// keyID names one key: the account alias and the key of the call.
// Two accounts can use the same key text for two different mails.
type keyID struct {
	account, key string
}

// keyEntry is the state of one key.
type keyEntry struct {
	// draftID is the draft_id of the call that claimed the key. A key
	// serves this draft only.
	draftID string
	// at is the time of the first call that used the key, and from
	// finish on, the time the send ended.
	at time.Time
	// done is true when the send started; out and err are then its
	// result.
	done bool
	out  SendOut
	err  error
}

// clock gives the time of the store.
func (s *keyStore) clock() time.Time {
	if s.now == nil {
		return time.Now()
	}
	return s.now()
}

// begin claims key for account and draftID. It gives:
//
//   - errKeyEmpty, when key is empty or holds only spaces. It claims
//     nothing.
//   - errKeyOtherDraft, when a call claimed the key for another
//     draft_id.
//   - replay true with the stored result, when the key is done. The
//     caller returns that result and sends nothing.
//   - errKeyInFlight, when another call holds the key.
//   - replay false and no error, when the key was free. The key is
//     now in flight, and the caller must call [keyStore.release] or
//     [keyStore.finish] for it.
//
// For an empty key, release and finish do nothing.
func (s *keyStore) begin(account, key, draftID string) (out SendOut, replay bool, err error) {
	if strings.TrimSpace(key) == "" {
		return SendOut{}, false, errKeyEmpty
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock()
	s.expire(now)
	id := keyID{account: account, key: key}
	if e, ok := s.entries[id]; ok {
		if e.draftID != draftID {
			return SendOut{}, false, errKeyOtherDraft
		}
		if !e.done {
			return SendOut{}, false, errKeyInFlight
		}
		return e.out, true, e.err
	}
	if s.entries == nil {
		s.entries = make(map[keyID]*keyEntry)
	}
	s.entries[id] = &keyEntry{at: now, draftID: draftID}
	return SendOut{}, false, nil
}

// finish stores the result of the send that key started. The key
// stays done until [keyTTL] after this call.
func (s *keyStore) finish(account, key string, out SendOut, err error) {
	if strings.TrimSpace(key) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := keyID{account: account, key: key}
	e, ok := s.entries[id]
	if !ok {
		// No path removes an entry in flight, so this branch is a
		// guard only. Store the result, so a repeat does not send.
		e = &keyEntry{}
		if s.entries == nil {
			s.entries = make(map[keyID]*keyEntry)
		}
		s.entries[id] = e
	}
	e.at, e.done, e.out, e.err = s.clock(), true, out, err
}

// release frees a key that is in flight, because its call ended
// before the send started: a check failed, or the human declined or
// cancelled (D8.3 step 7). A done key stays done.
func (s *keyStore) release(account, key string) {
	if strings.TrimSpace(key) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := keyID{account: account, key: key}
	if e, ok := s.entries[id]; ok && !e.done {
		delete(s.entries, id)
	}
}

// expire removes each done key older than [keyTTL]. A key in flight
// stays: its send may still run, and to free it would let a second
// call send.
func (s *keyStore) expire(now time.Time) {
	for id, e := range s.entries {
		if e.done && now.Sub(e.at) >= keyTTL {
			delete(s.entries, id)
		}
	}
}
