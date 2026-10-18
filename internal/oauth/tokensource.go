// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
	"golang.org/x/oauth2"
)

// freshWindow is the "refresh when less than 60 seconds of life
// remain" rule of §3.6. A cached access token inside this window of
// its expiry is treated as stale and refreshed early.
const freshWindow = 60 * time.Second

// storeReadTimeout bounds the B8 re-read of the store inside Token()
// (L2): that call runs while t.mu is held, so an unbounded keyring
// read there holds every other goroutine's Token() call, not just the
// one running it. This package cannot import internal/tools for its
// readSecret/secretTimeout (that would be an import cycle back into
// oauth), so it keeps its own copy of the same 30 s limit. It is a
// var, not a const, so a test can inject a short bound instead of
// waiting out the real one.
//
// arch: S6-close-judge L2, §3.4, B8
var storeReadTimeout = 30 * time.Second

// fresh reports whether tok can be handed to a caller as-is: it has
// an access token and more than freshWindow left before it expires.
//
// It compares wall time. golang.org/x/oauth2 sets Expiry from
// time.Now(), so Expiry carries a monotonic reading, and on Linux the
// monotonic clock stops during suspend. After 8 h of sleep the token
// would look fresh, the login would be refused once, and only the
// retry in tools.Factory.login would refresh it (T199).
//
// arch: T199, §3.6
func fresh(tok *oauth2.Token) bool {
	return tok != nil && tok.AccessToken != "" && !tok.Expiry.IsZero() && time.Until(tok.Expiry.Round(0)) > freshWindow
}

// Store is the persistence a TokenSource uses to read and save the
// refresh token behind one account's sign-in (§3.6, B7, B8). This
// package has no dependency on internal/secrets: T41 adapts the
// account's secrets.Store (keyed by alias, JSON-encoded) to this
// two-method shape, so oauth stays testable with a plain fake and
// secrets never has to import oauth.
type Store interface {
	// LoadRefreshToken returns the refresh token currently on file.
	LoadRefreshToken() (string, error)
	// SaveRefreshToken persists a new refresh token.
	SaveRefreshToken(token string) error
}

// TokenSource wraps an oauth2.Config's token source so that:
//   - a cached access token with more than 60s of life left is
//     returned without a network call (§3.6's refresh-early rule);
//   - a refresh token that rotates is saved back to the store, and a
//     response that carries none keeps the one already in hand (B7);
//   - a failed save is a warning, not a failed Token() call (B7);
//   - one invalid_grant re-reads the store and retries once, because
//     a second process can have refreshed and saved a newer token
//     first; a second failure returns the reauth text of §3.6 rather
//     than a raw oauth2 error (B8, DS6.9).
//
// Token() holds mu for the network call and for updating cur:
// golang.org/x/oauth2.TokenSource requires Token to be safe for
// concurrent use by multiple goroutines, and the package's own
// reuseTokenSource meets that the same way (serializing refreshes
// behind one mutex) rather than by refreshing concurrently and
// racing to pick a winner. It releases mu before it saves a rotated
// refresh token to the store (DRV.6, IRV.4): that write has its own
// time limit, but must not also hold every other goroutine's Token()
// call hostage to it.
//
// arch: T6.1, DS6.1, DS6.2, DS6.5, §3.6, B7, B8, B11
type TokenSource struct {
	cfg   *oauth2.Config
	store Store
	alias string
	ctx   context.Context // carries the plain HTTP client (DS6.2)
	warn  func(error)

	mu  sync.Mutex
	cur *oauth2.Token
}

// NewTokenSource builds a TokenSource for one account. refreshToken is
// the value currently on file. warn is called with a failed-save
// error (B7) and must not block; nil is treated as a no-op.
func NewTokenSource(ctx context.Context, cfg *oauth2.Config, store Store, alias, refreshToken string, warn func(error)) *TokenSource {
	if warn == nil {
		warn = func(error) {}
	}
	return &TokenSource{
		cfg:   cfg,
		store: store,
		alias: alias,
		ctx:   withClient(ctx),
		warn:  warn,
		cur:   &oauth2.Token{RefreshToken: refreshToken},
	}
}

// NeedsAuthText is the exact reauth error text of §3.6, returned by
// Token() when a re-read-and-retry (B8) still gets invalid_grant.
func NeedsAuthText(alias string) string {
	return fmt.Sprintf(`Sign-in for %q expired. Run: mailbag-mcp account add %s --reauth`, alias, alias)
}

// ErrNeedsAuth is the sentinel of DS6.9: the sign-in of an account
// expired and only "account add <alias> --reauth" can fix it. Token()
// wraps it in the error it gives in that case. A caller tests it with
// errors.Is, never by the text (DR1G.6.2).
//
// arch: DR1G.6, DS6.9
var ErrNeedsAuth = errors.New("oauth: sign-in expired")

// needsAuthError is the error Token() gives when the sign-in expired.
// Its text is NeedsAuthText, unchanged, and it unwraps to
// ErrNeedsAuth. With google set (GoogleNeedsAuth), its text is
// GoogleNeedsAuthText and it unwraps to ErrGoogleNeedsAuth, which
// wraps ErrNeedsAuth.
type needsAuthError struct {
	alias  string
	google bool
}

func (e *needsAuthError) Error() string {
	if e.google {
		return GoogleNeedsAuthText(e.alias)
	}
	return NeedsAuthText(e.alias)
}

func (e *needsAuthError) Unwrap() error {
	if e.google {
		return ErrGoogleNeedsAuth
	}
	return ErrNeedsAuth
}

// Token implements golang.org/x/oauth2.TokenSource.
//
// It does not defer-unlock t.mu for its whole body: applyRotation
// (DRV.6, IRV.4) releases the lock itself, before it saves a rotated
// refresh token, so a slow or locked keyring write blocks only the
// Token() call that triggered it, not every other goroutine's Token()
// call for this account. Every other return path below unlocks
// explicitly instead.
func (t *TokenSource) Token() (*oauth2.Token, error) {
	t.mu.Lock()

	if fresh(t.cur) {
		tok := t.cur
		t.mu.Unlock()
		return tok, nil
	}

	tok, err := t.refresh(t.cur.RefreshToken)
	if err == nil {
		t.applyRotation(tok) // unlocks t.mu itself; see the func doc.
		return tok, nil
	}
	if !isInvalidGrant(err) {
		// A transport error or a server error is not a sign-in state.
		// The text names the account, so a log line or a tool error
		// shows which sign-in failed (T199 item 6, DS11.14).
		t.mu.Unlock()
		return nil, fmt.Errorf("oauth: refresh access token for %s: %w", t.alias, err)
	}

	// B8: a different process may have refreshed and saved a newer
	// refresh token while we were talking to the token endpoint.
	// Re-read the store and try exactly once more before giving up.
	// Bounded (L2): this runs with t.mu held, so a locked keyring must
	// not hold it, or every other caller of Token(), past the limit.
	stored, serr := boundedLoadRefreshToken(t.store, storeReadTimeout)
	if serr != nil || stored == "" {
		t.mu.Unlock()
		return nil, &needsAuthError{alias: t.alias}
	}
	tok, err = t.refresh(stored)
	if err != nil {
		t.mu.Unlock()
		return nil, &needsAuthError{alias: t.alias}
	}
	t.cur.RefreshToken = stored
	t.applyRotation(tok) // unlocks t.mu itself; see the func doc.
	return tok, nil
}

// boundedLoadRefreshToken calls store.LoadRefreshToken under limit, so
// a store that never answers cannot hold the caller past it (L2).
// Token() has no context of its own to carry a deadline on (it
// implements golang.org/x/oauth2.TokenSource, whose Token() takes
// none), so this bounds with a timer instead of a context, the same
// shape internal/tools/provider.go's boundedGet uses with a context.
func boundedLoadRefreshToken(store Store, limit time.Duration) (string, error) {
	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		v, err := store.LoadRefreshToken()
		done <- result{v, err}
	}()

	select {
	case r := <-done:
		return r.value, r.err
	case <-time.After(limit):
		return "", fmt.Errorf("reading the refresh token from the store took longer than %s", limit)
	}
}

func isInvalidGrant(err error) bool {
	var rerr *oauth2.RetrieveError
	return errors.As(err, &rerr) && rerr.ErrorCode == "invalid_grant"
}

// refresh asks the wrapped oauth2 config for a token built from
// refreshToken. The base token carries no access token, so the
// wrapped source always goes to the network (a fresh refresh grant).
// Callers only reach this once the freshness check in Token() has
// already decided a network round trip is needed.
func (t *TokenSource) refresh(refreshToken string) (*oauth2.Token, error) {
	base := &oauth2.Token{RefreshToken: refreshToken}
	return t.cfg.TokenSource(t.ctx, base).Token()
}

// applyRotation keeps the prior refresh token when tok carries none
// (B7 — golang.org/x/oauth2 already backfills this from the request
// it just sent, but the fallback here does not depend on that), and
// saves a genuinely new one, warning rather than failing when the
// save itself errors (B7).
//
// The caller must hold t.mu on entry. applyRotation updates the
// in-memory token under that lock and releases it itself before it
// saves (DRV.6, IRV.4): KeyringStore.Set has its own 30 s bound, but a
// token-source lock held across the save would still block every
// other goroutine's Token() call for this account until the keyring
// answers, and Token() takes no context a caller could use to cut
// that wait short. A save that fails only warns — with no token text
// — and keeps the new token in memory; the next rotation tries the
// save again.
func (t *TokenSource) applyRotation(tok *oauth2.Token) {
	rotated := tok.RefreshToken != "" && tok.RefreshToken != t.cur.RefreshToken
	if tok.RefreshToken == "" {
		tok.RefreshToken = t.cur.RefreshToken
	}
	t.cur = tok
	t.mu.Unlock()

	if !rotated {
		return
	}
	// DRV.6 (was a LOW finding): register the new refresh token before
	// any log line, including the warn below, can hold it.
	guard.RegisterSecret(tok.RefreshToken)
	if err := t.store.SaveRefreshToken(tok.RefreshToken); err != nil {
		t.warn(fmt.Errorf("oauth: saving the rotated refresh token for %q: %w", t.alias, err))
	}
}
