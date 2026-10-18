// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	"github.com/amsys/mailbag-mcp/internal/mail"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// microsoftClientKey is the secret-store key of §3.4 that holds the
// Microsoft public client id: `oauth.microsoft` -> {"client_id":".."}.
// An alias can never collide with it because config.ValidAlias forbids
// ".".
const microsoftClientKey = "oauth.microsoft"

// googleClientKey is the secret-store key of §3.4 that holds the
// Google OAuth client: `oauth.google` -> {"client_id":"..",
// "client_secret":".."} (DS7.2). "oauth set google --file" writes it.
const googleClientKey = "oauth.google"

// keyringService is the keyring service name of §3.4.
const keyringService = "mailbag-mcp"

// oauthConfigFunc builds the oauth2.Config for one outlook account's
// token source. It is a variable and not a direct call to
// oauthpkg.Config so a test can point it at an httptest token
// endpoint and exercise the real credential()/dial() path — including
// the B14 defect a first T41 run shipped, where the token source kept
// the first dial's own context — without a network call to the real
// login.microsoftonline.com.
var oauthConfigFunc = oauthpkg.Config

// googleConfigFunc is oauthpkg.GoogleConfig as a variable, the seam
// that oauthConfigFunc gives for Microsoft: a test points the token
// endpoint at an httptest server, so no call goes to Google (IS78.1).
var googleConfigFunc = oauthpkg.GoogleConfig

// dialAccountFunc is imap.DialAccount as a variable, the same seam
// oauthConfigFunc above gives the token endpoint: a test can point it
// at a fake dial that returns an [imap.AuthError] on demand, so the
// retry branches of dial() (L3) can be proven without a real IMAP
// server.
var dialAccountFunc = imap.DialAccount

// selectStore is secrets.Select as a variable, the same seam as
// dialAccountFunc: a test can give a store that answers slowly, which
// a real keyring does only when a person must open it (DRV.10).
var selectStore = secrets.Select

// guardOptionsHook changes the options of each guarded JMAP client
// before openJMAP builds it. It is nil in production. A test sets
// LookupNetIP, so that a host name gives an address with no DNS, or
// Base, so that a fake server answers in process (DS78.11 G4).
var guardOptionsHook func(*guard.HTTPOptions)

// authRefusal is how long Factory refuses a new login with a
// credential that the server refused (ORV.6). A changed secret ends
// the refusal at once. It is a variable so a test can change it.
var authRefusal = 10 * time.Minute

// secretTimeout is the limit on one secret read (§3.4). A person must
// have time to open a locked keyring, and the tool call must still
// answer inside its own 45 s deadline (§3.1).
const secretTimeout = 30 * time.Second

// ErrUnknownAccount is the error of G10: a tool call named an alias
// that accounts.toml does not hold. Every mail tool checks the alias
// before it does anything else, so an unknown alias never reaches a
// network call. The text (D10.3) absorbs the account-add sentence
// that R1-A removed from Instructions.
//
// arch: D10.3
var ErrUnknownAccount = errors.New(`unknown account; add one in a terminal with "mailbag-mcp account add"`)

// Reader is the read half of [Writer] (§3.7): the methods the
// read-level tools of §3.17 call. It exists because the write half
// arrives one stage later, so a read tool must not wait for a
// provider to carry all its methods before it can run.
//
// arch: T4.5, §3.7, §3.16, §3.17, DRV.16a
type Reader interface {
	Folders(ctx context.Context) ([]mail.Folder, error)
	Search(ctx context.Context, q mail.Query) (mail.Page, error)
	Read(ctx context.Context, id string, o mail.ReadOpts) (*mail.Message, error)
	Thread(ctx context.Context, id string) (mail.ThreadResult, error)
	Raw(ctx context.Context, id string) ([]byte, error)
	Attachment(ctx context.Context, id, ref string) (io.ReadCloser, mail.AttachmentInfo, error)
}

// Writer is the one provider contract (DRV.16a, IRV.10): the whole
// read half plus the write half, the methods the draft-level and
// send-level tools of §3.17 call. It embeds [Reader], so a write tool
// reads the message it answers or forwards through the same value.
//
// Writer grows one task at a time, and it never names a method that
// internal/imap does not have yet: a Writer method with no
// implementation stops this package from compiling (owner gate
// decision D-S5.2, 2026-09-20). This stage adds SendDraft,
// SaveDraft, Modify, ModifyDetail and the three folder writes.
//
// Writer has no Send. After the draft/send split (D8.1) the send tool
// puts a stored draft on the wire through SendDraft, after the human
// accepts it. A Send method would send a message with no confirmation,
// and a later tool could use it to go around I8.
//
// §3.16 gives the send tool a draft_id that sends a stored draft, and
// only the provider can do that, because the stored source must go on
// the wire with the Bcc header removed and the Sent copy must keep it
// (C16). A later provider (gmail, jmap) must add the same method.
//
// arch: T5.2, T5.3, T5.5, §3.7, §3.16, §3.17, C11, C16, D5.4, D8.1, DRV.16a
type Writer interface {
	Reader
	SendDraft(ctx context.Context, id string) (mail.SendResult, error)
	SaveDraft(ctx context.Context, m *mail.Outgoing, replaceID string) (string, error)

	// Modify applies one change to a set of messages and reports what
	// it did, one row per message, so the undo journal of §3.18 can
	// reverse it.
	Modify(ctx context.Context, ids []string, c mail.Change) ([]mail.Applied, error)

	// ModifyDetail is Modify that also names the gone messages. With
	// an empty change it changes nothing and reads the current flags
	// of each id, so undo can refuse when another client changed a
	// message (D5.4, I16). A provider that cannot read the current
	// state must return an error. Undo then refuses and changes
	// nothing. An id with no row in Applied counts as changed or gone.
	ModifyDetail(ctx context.Context, ids []string, c mail.Change) (mail.ModifyResult, error)

	// CreateFolder, RenameFolder and DeleteFolder change the folder
	// tree (§3.10, §3.16). None of them reports a name: the provider
	// rewrites the name the caller gave to the spelling the server
	// needs (the hierarchy delimiter and the personal NAMESPACE
	// prefix, C11), so the folders tool lists the tree again after
	// the change and the caller reads the real name from that list.
	CreateFolder(ctx context.Context, name string) error
	RenameFolder(ctx context.Context, from, to string) error
	DeleteFolder(ctx context.Context, name string) error
}

// The IMAP write provider, the Gmail provider and the JMAP provider
// are the Writers of this stage. The checks are here and not in a test
// file, so a Writer method that internal/imap, internal/gmail or
// internal/jmap does not have breaks the build at once (T191, DS78.3,
// DS8.2).
var (
	_ Writer = (*imap.WriteProvider)(nil)
	_ Writer = (*gmail.Provider)(nil)
	_ Writer = (*jmap.Provider)(nil)
)

// Mail is what a mail tool needs from the account layer: the list of
// configured aliases, and one provider plus its account block for a
// named alias. [Factory] is the real one, over accounts.toml, the
// secret store and the IMAP pool. A test supplies its own.
//
// arch: T4.5, §3.16, §3.4, §3.1, G10
type Mail interface {
	// Aliases lists every configured account alias, sorted. A first
	// run with no accounts.toml yet gives an empty list, not an
	// error.
	Aliases() ([]string, error)

	// Open gives the provider of alias. It returns ErrUnknownAccount
	// when accounts.toml has no such alias.
	Open(ctx context.Context, alias string) (Reader, config.Account, error)

	// OpenWriter gives the write-capable provider of alias. It fails
	// the same way as Open. A read tool keeps Open, because a value
	// that carries no secret source at all is the right one for a
	// read call site (owner gate decision D-S5.1, 2026-09-20).
	OpenWriter(ctx context.Context, alias string) (Writer, config.Account, error)

	// AttachDirs lists the attach_dirs of accounts.toml: when it is
	// not empty, an outgoing attachment may come from those
	// directories only (§3.15, "Attach path"). An empty list leaves
	// the other attach-path rules in place. It is a method, and not a
	// value read once, for the reason DownloadDirs gives below.
	AttachDirs() []string

	// DownloadDirs lists the download_dirs of accounts.toml: the save
	// roots a person adds to ~/Downloads/mailbag-mcp and the system
	// temp directory (§3.15). An empty list means those two only. It
	// is a method of this interface, not a value read once, because
	// accounts.toml can change while the server runs (§3.3).
	DownloadDirs() []string
}

// Factory builds a provider for one account and owns the IMAP pool
// that those providers share.
//
// It reads a secret at the first use of an account, not at start-up,
// so a locked keyring never delays the reply to "initialize" (A9).
// The value stays in memory. After a login failure it reads the store
// one more time, because "account add" can have changed the password
// since (§3.4).
//
// After a login that the server refused ([imap.AuthError]), it does
// not log in again with the same credential for authRefusal. Each
// call in that time reads the store again: the same secret gives the
// refusal text, a changed secret ends the refusal (DRV.10, IRV.8). A
// model that calls again and again therefore cannot lock the account
// out on a wrong password.
//
// There is no fallback from one secret store to the other. The store
// kind comes from accounts.toml alone. An error from the keyring that
// is not [secrets.ErrNotFound] means "locked or not available", never
// "absent", and it comes back to the caller as it is (trap B3).
//
// arch: T4.5, §3.16, §3.4, §3.1, A9, B2, B3, B14, DRV.10
type Factory struct {
	logger *slog.Logger
	pool   *imap.Pool

	mu      sync.Mutex
	cfg     *config.Config
	creds   map[string]imap.Credential
	tokSrcs map[string]*oauthpkg.TokenSource

	// sums holds the SHA-256 of the stored secret that each alias
	// read or wrote last, and refused holds the logins the server
	// refused. Together they tell "the same credential" from a new one
	// without a second copy of the secret (DRV.10). A write that this
	// Factory makes goes through recordingStore, so a token rotation
	// by this process does not look like a new secret (DR1G.6.1).
	sums    map[string][sha256.Size]byte
	refused map[string]refusal

	// now gives the time of the refusal window. It is the wall clock
	// with no monotonic reading (Round(0)), so a suspend counts toward
	// the window: a 10 min refusal ends during a sleep and does not
	// last 10 awake minutes after it (T199 item 8, DS11.14). A test
	// puts a fake clock in its place; a fake must give wall-only times
	// too. The send window and the key TTL stay on the monotonic
	// clock, because a longer wait there is safe.
	now func() time.Time

	// states holds what this process knows about the sign-in of each
	// alias (DS6.9, OR1G.1). It lives in memory only and is never
	// written to disk. An alias that is absent is AuthUnknown.
	states map[string]AuthState

	// gmailState holds the caches of each Gmail alias (labels,
	// send-as). A Gmail provider is made for each call; it gets the
	// State of its alias, so two sessions share the caches (DS78.3,
	// G6). forget drops the State of the alias.
	gmailState map[string]*gmail.State

	// jmapClients holds the JMAP client of each alias with the values
	// that it was built from. The client keeps the session object and
	// its two HTTP transports keep their connections, so the next call
	// of the alias needs no new session GET and no new TLS handshake
	// (DS78.11 G6). openJMAP builds a new client when one of the values
	// changed; forget drops the client of the alias. Both close the
	// idle connections of the old client (R16-L25).
	jmapClients map[string]*jmapConn
}

// AuthState is what this server process knows about the sign-in of
// one account (DS6.9, OR1G.1). The accounts tool shows it. Only a
// login result sets a state; nothing reads it back from disk.
//
// arch: DR1G.6, DR1G.18, IR1G.8
type AuthState string

const (
	// AuthUnknown is the zero value: this process has no login result
	// for the account yet, or the secret changed since the last one.
	AuthUnknown AuthState = ""
	// AuthOK means that the last login succeeded.
	AuthOK AuthState = "ok"
	// AuthNeedsSignIn means that Token() gave [oauthpkg.ErrNeedsAuth]:
	// the sign-in expired and needs "account add <alias> --reauth".
	AuthNeedsSignIn AuthState = "needs_auth"
	// AuthLoginRefused means that the server refused the last login.
	AuthLoginRefused AuthState = "login_refused"
	// AuthAPIOff means that the last Gmail call got
	// [gmail.ErrAPIDisabled]: the sign-in is good, but the Gmail API
	// is off in the Google Cloud project of the OAuth client (DS7.7,
	// DS78.3).
	AuthAPIOff AuthState = "api_off"
)

// refusal is one login that the server refused: the hash of the
// secret it used, the time the refusal ends, and the server error.
type refusal struct {
	sum   [sha256.Size]byte
	until time.Time
	err   error
}

// NewFactory makes a Factory with its own IMAP pool. logger may be
// nil.
//
// arch: T4.5, §3.10, §3.16
func NewFactory(logger *slog.Logger) *Factory {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	f := &Factory{
		logger:  logger,
		creds:   make(map[string]imap.Credential),
		tokSrcs: make(map[string]*oauthpkg.TokenSource),
		sums:    make(map[string][sha256.Size]byte),
		refused: make(map[string]refusal),
		states:  make(map[string]AuthState),
		now:     func() time.Time { return time.Now().Round(0) },

		gmailState:  make(map[string]*gmail.State),
		jmapClients: make(map[string]*jmapConn),
	}
	f.pool = imap.NewPool(f.dial, logger)
	setDefaultTimeoutSource(f.ToolTimeout)
	return f
}

// ToolTimeout gives the tool_timeout of accounts.toml, the deadline
// that replaces DefaultTimeout for every call Wrap makes with it
// (ORV.3, ORV.10, DRV.14a). It is read at call time, because
// accounts.toml can change while the server runs.
//
// A config that cannot be read gives DefaultTimeout, the same
// fall-back DownloadDirs and AttachDirs use: every mail tool calls
// Open or OpenWriter first, which reads the same config and fails the
// call with the real reason.
//
// arch: T4.5, §3.1, §3.3, DRV.14a, ORV.3, ORV.10
func (f *Factory) ToolTimeout() time.Duration {
	cfg, err := f.config()
	if err != nil {
		return DefaultTimeout
	}
	return cfg.ToolTimeout()
}

// AuthState gives the sign-in state of alias as this process knows
// it (DR1G.6.2). An alias with no login result yet gives AuthUnknown.
// It takes f.mu only, so it is safe to call from any goroutine.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func (f *Factory) AuthState(alias string) AuthState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.states[alias]
}

// noteLogin sets the state of alias from the result of one login
// (DR1G.6.2). Success sets AuthOK, a needs-auth error sets
// AuthNeedsSignIn, and a refusal by the server sets AuthLoginRefused.
// For Gmail, [gmail.ErrAPIDisabled] sets AuthAPIOff, and
// [gmail.ErrScope] sets AuthNeedsSignIn, because a new sign-in with
// --reauth gives the missing scope (DS78.3). For JMAP, a
// [jmap.AuthError] (a 401) sets AuthLoginRefused (DS78.3, DRV.10).
// Any other error (network, keyring, config, a token refresh that
// failed in transport, an [imap.SMTPAuthError]) says nothing about
// the sign-in, so the state stays as it was. Such an error goes to the
// log at WARN with the alias, because the accounts tool still shows
// the old state while the calls fail (T199 item 6, DS11.14). The
// caller must not hold f.mu.
func (f *Factory) noteLogin(alias string, err error) {
	var state AuthState
	var authErr *imap.AuthError
	var jmapAuthErr *jmap.AuthError
	switch {
	case err == nil:
		state = AuthOK
	case errors.Is(err, oauthpkg.ErrNeedsAuth), errors.Is(err, gmail.ErrScope):
		state = AuthNeedsSignIn
	case errors.Is(err, gmail.ErrAPIDisabled):
		state = AuthAPIOff
	case errors.As(err, &authErr), errors.As(err, &jmapAuthErr):
		state = AuthLoginRefused
	default:
		f.logger.Warn("login failed; the sign-in state stays as it was", "alias", alias, "err", err)
		return
	}
	f.mu.Lock()
	f.states[alias] = state
	f.mu.Unlock()
}

// Pool gives the IMAP pool, so the process that owns this Factory can
// run its reaper and close every connection at shutdown (§3.1 steps 5
// and 7).
func (f *Factory) Pool() *imap.Pool { return f.pool }

// Close ends every pooled connection.
func (f *Factory) Close() { f.pool.CloseAll() }

// DownloadDirs gives the download_dirs list of accounts.toml, the
// extra save roots of §3.15.
//
// A config that cannot be read gives no extra root. Every mail tool
// calls Open first, which reads the same config and fails the call
// with the real reason, so this method never has to report one.
//
// arch: T4.5, §3.15, §3.3, G6
func (f *Factory) DownloadDirs() []string {
	cfg, err := f.config()
	if err != nil {
		return nil
	}
	return cfg.DownloadDirs()
}

// Aliases lists the configured account aliases.
func (f *Factory) Aliases() ([]string, error) {
	cfg, err := f.config()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // no accounts.toml yet: no accounts, not an error
		}
		return nil, err
	}
	return cfg.Aliases(), nil
}

// Open gives the provider of alias (§3.7): the IMAP provider for
// imap and outlook, the Gmail REST provider for gmail and the JMAP
// provider for jmap (DS78.3). An account with an other provider gets
// an error.
//
// arch: T4.5, §3.7, §3.16, G10, DS78.3
func (f *Factory) Open(ctx context.Context, alias string) (Reader, config.Account, error) {
	acct, err := f.account(alias)
	if err != nil {
		return nil, config.Account{}, err
	}
	switch acct.Provider {
	case "imap", "outlook":
		return imap.New(alias, f.pool), acct, nil
	case "gmail":
		p, err := f.openGmail(ctx, alias, acct)
		if err != nil {
			return nil, config.Account{}, err
		}
		return p, acct, nil
	case "jmap":
		p, err := f.openJMAP(ctx, alias, acct)
		if err != nil {
			return nil, config.Account{}, err
		}
		return p, acct, nil
	default:
		return nil, config.Account{}, fmt.Errorf("account %q uses provider %q, which this build cannot open yet", alias, acct.Provider)
	}
}

// OpenWriter gives the write-capable provider of alias (§3.7, §3.16):
// the IMAP write provider for imap and outlook, the Gmail REST
// provider for gmail and the JMAP provider for jmap (DS78.3).
//
// The credential reaches the provider as a function, not as a value.
// A token ends after about an hour, so a login that a caller read
// once and kept then fails every send after it (B14). The function
// reads the account block again on each call as well, so a password
// changed by "account add" in another process reaches the next send
// with no restart (§3.3). The provider also gets f.forget for alias,
// so a token that the SMTP server refuses is dropped and read fresh
// one time (DS11.14, G6).
//
// arch: T5.2, §3.7, §3.16, §3.4, §3.3, B14, G10, DS11.14, DS78.3
func (f *Factory) OpenWriter(ctx context.Context, alias string) (Writer, config.Account, error) {
	acct, err := f.account(alias)
	if err != nil {
		return nil, config.Account{}, err
	}
	switch acct.Provider {
	case "imap", "outlook":
		return imap.NewWriter(alias, f.pool, acct, f.credentialFunc(alias), func() { f.forget(alias) }), acct, nil
	case "gmail":
		p, err := f.openGmail(ctx, alias, acct)
		if err != nil {
			return nil, config.Account{}, err
		}
		return p, acct, nil
	case "jmap":
		p, err := f.openJMAP(ctx, alias, acct)
		if err != nil {
			return nil, config.Account{}, err
		}
		return p, acct, nil
	default:
		return nil, config.Account{}, fmt.Errorf("account %q uses provider %q, which this build cannot open yet", alias, acct.Provider)
	}
}

// openGmail gives the Gmail provider of alias (DS78.3). It checks the
// refusal window first (DRV.10): with no refusal, that check uses
// memory only and reads no secret. The provider gets the shared State
// of the alias (G6), and its REST client gets the token function and
// the auth-event function of the alias. No call goes to the network
// here: the token is read at the first API call.
//
// arch: DS78.3, DS7.2, DRV.10, IS7.2, IS78.4
func (f *Factory) openGmail(ctx context.Context, alias string, acct config.Account) (*gmail.Provider, error) {
	store, err := f.store()
	if err != nil {
		return nil, err
	}
	if err := f.checkRefusal(ctx, alias, store); err != nil {
		return nil, err
	}
	f.mu.Lock()
	st, ok := f.gmailState[alias]
	if !ok {
		st = &gmail.State{}
		f.gmailState[alias] = st
	}
	f.mu.Unlock()
	api := gmail.New(f.accessToken(alias), f.authEvent(alias))
	return gmail.NewProvider(alias, acct, api, st), nil
}

// accessToken gives the [gmail.TokenFunc] of alias (DS78.3). Each call
// reads the account block, then gets an access token from the
// TokenSource of the account through credential, which builds that
// TokenSource from the store at the first use (B14). A token sets
// AuthOK, because the sign-in worked; an API answer after it can still
// set AuthAPIOff or AuthNeedsSignIn. A needs-auth error starts the
// refusal window of the alias (DRV.10, IS78.4).
//
// arch: DS78.3, DS7.2, IS7.2, IS78.4, B14, DRV.10
func (f *Factory) accessToken(alias string) gmail.TokenFunc {
	return func(ctx context.Context) (string, error) {
		acct, err := f.account(alias)
		if err != nil {
			return "", err
		}
		store, err := f.store()
		if err != nil {
			return "", err
		}
		cred, _, err := f.credential(ctx, acct, store)
		if err != nil {
			if errors.Is(err, oauthpkg.ErrNeedsAuth) {
				// The Gmail text names the 7-day cause of B9.
				err = oauthpkg.GoogleNeedsAuth(alias)
				f.refuse(alias, err)
			}
			return "", err
		}
		if cred.Token == "" {
			return "", fmt.Errorf(`account %q signs in to Gmail with OAuth only; run "mailbag-mcp account add %s --reauth"`, alias, alias)
		}
		f.noteLogin(alias, nil)
		return cred.Token, nil
	}
}

// jmapConn is the JMAP client of one alias and the two guarded HTTP
// clients under it (DS8.3), with the key that they were built from.
type jmapConn struct {
	key  jmapKey
	c    *jmap.Client
	api  *http.Client
	blob *http.Client
}

// closeIdle closes the idle connections of the two HTTP clients of c.
// The Factory calls it when it drops or replaces c, so the sockets of
// the old clients do not stay open (R16-L25). A request that runs
// keeps its connection. The guarded transport of internal/guard
// passes the call on to the sockets.
func (c *jmapConn) closeIdle() {
	c.api.CloseIdleConnections()
	c.blob.CloseIdleConnections()
}

// jmapKey holds every value that a JMAP client of an alias is built
// from. When one of them changes (accounts.toml, or a credential that
// the store gave again after forget), openJMAP builds a new client.
type jmapKey struct {
	sessionURL  string
	privateHost bool
	tlsCA       string
	cred        imap.Credential
}

// openJMAP gives the JMAP provider of alias (DS78.3, DS8.3). It checks
// the refusal window first (DRV.10): with no refusal, that check uses
// memory only. It then reads the bearer token or the password through
// credential, and gives the provider the JMAP client of the alias,
// which it builds when the alias has none or when a value of jmapKey
// changed. No call goes to the network here: the first API call gets
// the session.
//
// arch: DS78.3, DS8.3, DS8.6, DRV.10, IS8.1, IS78.4, G11
func (f *Factory) openJMAP(ctx context.Context, alias string, acct config.Account) (*jmap.Provider, error) {
	store, err := f.store()
	if err != nil {
		return nil, err
	}
	if err := f.checkRefusal(ctx, alias, store); err != nil {
		return nil, err
	}
	sessionURL, err := config.JMAPSessionURL(acct)
	if err != nil {
		return nil, fmt.Errorf("account %q: %w", alias, err)
	}
	cred, _, err := f.credential(ctx, acct, store)
	if err != nil {
		return nil, err
	}
	key := jmapKey{sessionURL: sessionURL, privateHost: acct.PrivateHost, tlsCA: acct.TLSCA, cred: cred}
	f.mu.Lock()
	conn := f.jmapClients[alias]
	f.mu.Unlock()
	if conn == nil || conn.key != key {
		conn, err = newJMAPConn(alias, key)
		if err != nil {
			return nil, err
		}
		f.mu.Lock()
		old := f.jmapClients[alias]
		f.jmapClients[alias] = conn
		f.mu.Unlock()
		if old != nil {
			old.closeIdle()
		}
	}
	return jmap.NewProvider(acct, conn.c, f.authEvent(alias)), nil
}

// newJMAPConn builds the JMAP client of alias from k (DS8.3, G11). The
// API client and the blob client come from guard.NewHTTPClientFor with
// the options of jmap.GuardOptions: an 8 MiB and a 32 MiB body cap and
// no time limit of their own. PrivateHost is the session host when the
// account has private_host = true, else empty, so the guard refuses
// every private address. Without private_host, a session host that
// resolves to private addresses only gives an error that names the
// key. The credential becomes a Bearer header for a token and HTTP
// Basic for a password (F5).
//
// arch: DS78.3, DS8.3, DS8.6, IS8.1, G11, DS78.11 G4
func newJMAPConn(alias string, k jmapKey) (*jmapConn, error) {
	host := ""
	if u, err := url.Parse(k.sessionURL); err == nil {
		host = u.Hostname()
	}
	privateHost := ""
	if k.privateHost {
		privateHost = host
	}
	apiOpts, blobOpts := jmap.GuardOptions(privateHost)
	if k.tlsCA != "" {
		roots, err := jmapRoots(alias, k.tlsCA)
		if err != nil {
			return nil, err
		}
		apiOpts.RootCAs, blobOpts.RootCAs = roots, roots
	}
	for _, o := range []*guard.HTTPOptions{&apiOpts, &blobOpts} {
		if guardOptionsHook != nil {
			guardOptionsHook(o)
		}
		if !k.privateHost {
			o.LookupNetIP = privateHostHint(alias, host, o.LookupNetIP)
		}
	}
	api := guard.NewHTTPClientFor(apiOpts)
	blob := guard.NewHTTPClientFor(blobOpts)
	auth := jmap.BasicAuth(k.cred.Username, k.cred.Password)
	if k.cred.Token != "" {
		auth = jmap.BearerAuth(k.cred.Token)
	}
	return &jmapConn{key: k, c: jmap.New(k.sessionURL, auth, api, blob, k.privateHost), api: api, blob: blob}, nil
}

// privateHostHint wraps the resolver of a guarded JMAP client of an
// account without private_host (G11). When the session host resolves
// to private addresses only, it gives an error that names the key, so
// the person knows the fix (DS8.3, DS78.8 step 4). Every other answer
// passes unchanged, and the guard still checks each address. A nil
// lookup means the system resolver, as in the guard.
//
// arch: DS8.3, DS78.8, G11
func privateHostHint(alias, sessionHost string, lookup func(context.Context, string) ([]netip.Addr, error)) func(context.Context, string) ([]netip.Addr, error) {
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		addrs, err := lookup(ctx, host)
		if err != nil || len(addrs) == 0 || !strings.EqualFold(host, sessionHost) {
			return addrs, err
		}
		for _, a := range addrs {
			if !a.Unmap().IsPrivate() {
				return addrs, nil
			}
		}
		return nil, fmt.Errorf("jmap: %s resolves to a private address; set private_host = true for account %s to allow it", host, alias)
	}
}

// jmapRoots gives the system roots plus the certificates of the
// tls_ca file of a JMAP account, the same rule as the IMAP dial (the
// roots field of DS78.11 G4). There is no option that turns
// verification off.
func jmapRoots(alias, path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) //nolint:gosec // G304: the tls_ca path comes from the human's accounts.toml, not from mail data
	if err != nil {
		return nil, fmt.Errorf("account %q: read tls_ca: %w", alias, err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("account %q: tls_ca %s holds no certificate", alias, path)
	}
	return roots, nil
}

// authEvent gives the function that the Gmail REST client calls on an
// auth event (DS7.3, DS78.3). The first 401 of a call drops the
// cached token source of alias, so the retry gets a new token (IS7.2).
// [oauthpkg.ErrNeedsAuth] (the second 401) starts the refusal window
// and sets the state. [gmail.ErrAPIDisabled] and [gmail.ErrScope] set
// the state only: the person fixes them in the Cloud project or with
// --reauth, and a new secret is not needed for the first fix. The JMAP
// provider gives its [jmap.AuthError] (a 401) here too: the server
// refused the token or the password, so it starts the refusal window
// and sets AuthLoginRefused (DS78.3, DRV.10, IS78.4).
//
// arch: DS78.3, DS7.3, DS7.7, IS7.2, IS78.4, DRV.10
func (f *Factory) authEvent(alias string) func(error) {
	return func(err error) {
		var apiErr *gmail.APIError
		var jmapAuthErr *jmap.AuthError
		switch {
		case errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized:
			f.forget(alias)
		case errors.As(err, &jmapAuthErr):
			f.refuse(alias, err)
			f.noteLogin(alias, err)
		case errors.Is(err, oauthpkg.ErrNeedsAuth):
			f.refuse(alias, err)
			f.noteLogin(alias, err)
		case errors.Is(err, gmail.ErrAPIDisabled), errors.Is(err, gmail.ErrScope):
			f.noteLogin(alias, err)
		}
	}
}

// refuse starts the refusal window of alias for the secret that the
// Factory read last (DRV.10). checkRefusal ends it early when the
// stored secret changes.
func (f *Factory) refuse(alias string, err error) {
	f.mu.Lock()
	f.refused[alias] = refusal{sum: f.sums[alias], until: f.now().Add(authRefusal), err: err}
	f.mu.Unlock()
}

// AttachDirs gives the attach_dirs list of accounts.toml, the only
// permitted sources of an outgoing attachment when it is not empty
// (§3.15).
//
// A config that cannot be read gives no list. Every write tool calls
// OpenWriter first, which reads the same config and fails the call
// with the real reason, so this method never has to report one.
//
// arch: T5.2, §3.15, §3.3, G7
func (f *Factory) AttachDirs() []string {
	cfg, err := f.config()
	if err != nil {
		return nil
	}
	return cfg.AttachDirs()
}

// credentialFunc builds the [imap.CredentialFunc] of one account: it
// reads the account block and the login of alias each time it runs
// (B14).
func (f *Factory) credentialFunc(alias string) imap.CredentialFunc {
	return func(ctx context.Context) (imap.Credential, error) {
		acct, err := f.account(alias)
		if err != nil {
			return imap.Credential{}, err
		}
		store, err := f.store()
		if err != nil {
			return imap.Credential{}, err
		}
		cred, _, err := f.credential(ctx, acct, store)
		return cred, err
	}
}

// account reads the account block of alias from accounts.toml as it
// is now.
func (f *Factory) account(alias string) (config.Account, error) {
	if !config.ValidAlias(alias) {
		// §3.15: check the alias against the pattern and the config
		// before each other action. The alias becomes a keyring key
		// and a file name (B17).
		return config.Account{}, fmt.Errorf("%w: %q", ErrUnknownAccount, alias)
	}
	cfg, err := f.config()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return config.Account{}, fmt.Errorf("%w: %q; no account is configured yet", ErrUnknownAccount, alias)
		}
		return config.Account{}, err
	}
	acct, ok := cfg.Account(alias)
	if !ok {
		return config.Account{}, fmt.Errorf("%w: %q; call the accounts tool for the list", ErrUnknownAccount, alias)
	}
	return acct, nil
}

// config gives accounts.toml as it is now. The first call loads it;
// every later call asks Refresh, which reads the file again only when
// its modification time changed, so "account add" in another process
// shows without a restart (§3.1, §3.3).
func (f *Factory) config() (*config.Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cfg == nil {
		path, err := config.AccountsPath()
		if err != nil {
			return nil, err
		}
		cfg, err := config.Load(path)
		if err != nil {
			return nil, err
		}
		f.cfg = cfg
		return cfg, nil
	}
	if _, err := f.cfg.Refresh(); err != nil {
		return nil, err
	}
	return f.cfg, nil
}

// dial is the pool's [imap.DialFunc]. The pool calls it for the first
// connection of an account and again for every reconnect, so the
// credential is read here and not kept by the caller (B14).
//
// The pool puts no limit on this function. imap.DialAccount limits
// the network part, and the secret read keeps its own 30 s limit, so a
// slow keyring does not use up the dial limit (DRV.10).
//
// A login that the server refused starts a refusal of authRefusal for
// that alias and that secret (DRV.10, IRV.8).
//
// arch: T4.5, §3.4, §3.10, B3, B14, DRV.10
func (f *Factory) dial(ctx context.Context, alias string) (*imap.Client, error) {
	acct, err := f.account(alias)
	if err != nil {
		return nil, err
	}
	store, err := f.store()
	if err != nil {
		return nil, err
	}
	if err := f.checkRefusal(ctx, alias, store); err != nil {
		return nil, err
	}
	c, err := f.login(ctx, acct, store)
	var authErr *imap.AuthError
	if errors.As(err, &authErr) {
		f.refuse(alias, err)
	}
	f.noteLogin(alias, err)
	return c, err
}

// checkRefusal gives the refusal error when the server refused the
// last login of alias less than authRefusal ago and the store still
// holds the same secret. A changed secret ends the refusal and drops
// the cached login, so the next login uses the new one (DRV.10).
func (f *Factory) checkRefusal(ctx context.Context, alias string, store secrets.Store) error {
	f.mu.Lock()
	r, ok := f.refused[alias]
	if ok && !f.now().Before(r.until) {
		delete(f.refused, alias)
		ok = false
	}
	f.mu.Unlock()
	if !ok {
		return nil
	}
	raw, err := readSecret(ctx, store, alias)
	if err != nil {
		return err
	}
	if sha256.Sum256([]byte(raw)) != r.sum {
		// The refusal ends because the secret changed, so the state
		// goes back to unknown: the next login decides (DR1G.6.2).
		f.mu.Lock()
		delete(f.refused, alias)
		delete(f.states, alias)
		f.mu.Unlock()
		f.forget(alias)
		return nil
	}
	var v secretValue
	if json.Unmarshal([]byte(raw), &v) == nil && v.Kind == "oauth" {
		return fmt.Errorf(`login refused by the server; run "mailbag-mcp account add %s --reauth": %w`, alias, r.err)
	}
	return fmt.Errorf(`login refused by the server; run "mailbag-mcp account add %s" to store the new password: %w`, alias, r.err)
}

// login reads the credential of acct and dials with it. After an
// AuthError on a credential that can be stale, it reads the store one
// more time and dials once more (§3.4, L3).
func (f *Factory) login(ctx context.Context, acct config.Account, store secrets.Store) (*imap.Client, error) {
	cred, cached, err := f.credential(ctx, acct, store)
	if err != nil {
		return nil, err
	}
	c, err := dialAccountFunc(ctx, acct, cred, imap.WireDebug())

	var authErr *imap.AuthError
	if err == nil || !errors.As(err, &authErr) {
		return c, err
	}
	if !cached && cred.Token == "" {
		// A password credential just read fresh from the store (not
		// from memory) already failed the login: a second read would
		// hand back the same value, so there is nothing to retry.
		return c, err
	}
	// §3.4/L3: either the login used a value that came from memory
	// ("account add" can have written a new password since it was
	// cached), or it used a cached oauth access token that Outlook now
	// rejects even though fresh() still says it has time left (consent
	// withdrawn, IMAP turned off, an AADSTS condition) — an oauth
	// credential is never cached=true (B14), so cred.Token != "" is
	// what marks that case here. Either way, drop what is cached and
	// read the store one more time, and one time only.
	f.forget(acct.Alias)
	cred, _, reread := f.credential(ctx, acct, store)
	if reread != nil {
		return nil, errors.Join(err, reread)
	}
	return dialAccountFunc(ctx, acct, cred, imap.WireDebug())
}

// store gives the secret store that accounts.toml records. The server
// never picks a different one on its own (trap B3).
func (f *Factory) store() (secrets.Store, error) {
	cfg, err := f.config()
	if err != nil {
		return nil, err
	}
	dir, err := config.ConfigDir()
	if err != nil {
		return nil, err
	}
	return selectStore(cfg.Secrets(), keyringService, dir)
}

// credential gives the login of acct. cached is true when the value
// came from memory without a network call, so the caller knows that a
// second read can give a different answer.
//
// An outlook account never takes the cached path: it goes through
// tokenCredential on every call, so a redial always asks the token
// source for an access token with more than 60s of life left rather
// than reusing the one minted at the account's first use (B14).
func (f *Factory) credential(ctx context.Context, acct config.Account, store secrets.Store) (cred imap.Credential, cached bool, err error) {
	f.mu.Lock()
	ts, hasTS := f.tokSrcs[acct.Alias]
	f.mu.Unlock()
	if hasTS {
		return f.tokenCredential(acct, ts)
	}

	f.mu.Lock()
	c, ok := f.creds[acct.Alias]
	f.mu.Unlock()
	if ok {
		return c, true, nil
	}

	raw, err := readSecret(ctx, store, acct.Alias)
	if err != nil {
		return imap.Credential{}, false, err
	}
	f.mu.Lock()
	f.sums[acct.Alias] = sha256.Sum256([]byte(raw))
	f.mu.Unlock()
	res, err := parseCredential(ctx, acct, raw, &recordingStore{Store: store, f: f}, f.warnf)
	if err != nil {
		return imap.Credential{}, false, err
	}
	if res.tokSrc != nil {
		f.mu.Lock()
		f.tokSrcs[acct.Alias] = res.tokSrc
		f.mu.Unlock()
		return f.tokenCredential(acct, res.tokSrc)
	}

	f.mu.Lock()
	f.creds[acct.Alias] = res.cred
	f.mu.Unlock()
	return res.cred, false, nil
}

// recordingStore wraps the store that the Factory gives to a
// credential. After a Set that succeeded, it sets the Factory's hash
// for that key to the hash of the value written. Thus a refresh token
// that this process rotates does not end a refusal, but a secret that
// another process writes does (DR1G.18.4, G-RV.1).
//
// Lock rule: Set takes f.mu and no other lock, and it does not hold
// f.mu during the write to the store. No caller of Token() holds f.mu,
// so the write path credential -> tokenCredential -> Token() ->
// SaveRefreshToken -> Set cannot deadlock (DR1G.6.1).
//
// arch: DR1G.6, DR1G.18, IR1G.7
type recordingStore struct {
	secrets.Store
	f *Factory
}

// Set writes value to the wrapped store. Only after a write that
// succeeded does it record the hash of the exact string written. A
// failed write leaves the store as it was, so the old hash stays.
func (s *recordingStore) Set(key, value string) error {
	if err := s.Store.Set(key, value); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(value))
	s.f.mu.Lock()
	s.f.sums[key] = sum
	s.f.mu.Unlock()
	return nil
}

// tokenCredential asks ts for a live access token and wraps it as an
// imap.Credential (B14). It never reports cached=true: the caller
// must not treat this value as safe to keep past one dial, since the
// next dial calls this again and can get a different access token.
func (f *Factory) tokenCredential(acct config.Account, ts *oauthpkg.TokenSource) (imap.Credential, bool, error) {
	tok, err := ts.Token()
	if err != nil {
		if errors.Is(err, oauthpkg.ErrNeedsAuth) {
			// The send path reads the credential without dial, so the
			// state is set here too (DR1G.6.2).
			f.noteLogin(acct.Alias, err)
		}
		return imap.Credential{}, false, err
	}
	guard.RegisterSecret(tok.AccessToken)
	user := acct.Username
	if user == "" {
		user = acct.Email
	}
	return imap.Credential{Username: user, Token: tok.AccessToken}, false, nil
}

// warnf logs a non-fatal oauth warning (B7: a failed refresh-token
// save must not fail the Token() call it happened during).
func (f *Factory) warnf(err error) {
	f.logger.Warn(err.Error())
}

// forget drops the credential of alias, so the next read goes to the
// store again. It drops a cached token source too: a fresh
// authentication error from Microsoft, however unlikely once every
// dial already asks Token() for a live access token (B14), should
// still fall back to a full re-read rather than reuse a token source
// built from a secret that may itself be stale. It drops the Gmail
// caches and the JMAP client of alias too (G6), and closes the idle
// connections of that client (R16-L25).
func (f *Factory) forget(alias string) {
	f.mu.Lock()
	old := f.jmapClients[alias]
	delete(f.creds, alias)
	delete(f.tokSrcs, alias)
	delete(f.gmailState, alias)
	delete(f.jmapClients, alias)
	f.mu.Unlock()
	if old != nil {
		old.closeIdle()
	}
}

// readSecret reads one key with the 30 s limit of §3.4.
//
// A store error that is not [secrets.ErrNotFound] comes back as it
// is. A locked keyring, or a cancelled unlock dialog, must never read
// as "this account has no secret" (trap B3).
func readSecret(ctx context.Context, store secrets.Store, key string) (string, error) {
	v, err := boundedGet(ctx, store, key)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return "", fmt.Errorf("account %q has no stored secret; add it again with `mailbag-mcp account add`", key)
		}
		if errors.Is(err, errBoundedGetTimeout) {
			return "", fmt.Errorf("reading the secret of account %q took longer than %s; open the keyring and try again", key, secretTimeout)
		}
		return "", err
	}
	return v, nil
}

// errBoundedGetTimeout marks the error boundedGet returns when its
// 30 s limit (or a shorter caller deadline) elapses first, so a
// caller can give that case its own wording while everything else —
// including a genuine [secrets.ErrNotFound] — passes through as is.
var errBoundedGetTimeout = errors.New("bounded secret read: timed out")

// boundedGet reads one raw secret-store value under the §3.4 30 s
// limit (secretTimeout: it also honours a shorter deadline already on
// ctx). readSecret and microsoftClientID (L2) both route their store
// reads through this, so a locked keyring cannot hold either call
// site — the account-add path or the shared `oauth.microsoft` client
// id read at the first dial — past the limit. The store's own error
// (including [secrets.ErrNotFound]) comes back unwrapped, so each
// caller keeps its own message for "not found".
//
// arch: S6-close-judge L2, §3.4
func boundedGet(ctx context.Context, store secrets.Store, key string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, secretTimeout)
	defer cancel()

	type result struct {
		value string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		v, err := store.Get(key)
		done <- result{v, err}
	}()

	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		return "", errBoundedGetTimeout
	}
}

// secretValue is the JSON that a secret store holds for one account
// (§3.4). RefreshToken is set for kind "oauth" only.
type secretValue struct {
	Kind         string `json:"kind"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

// microsoftClientSecret is the JSON at the `oauth.microsoft` store key
// (§3.4's table): the public client id, no secret.
type microsoftClientSecret struct {
	ClientID string `json:"client_id"`
}

// credentialResult is what parseCredential builds from one stored
// secret. Exactly one field is set: cred for a password or bearer
// token that never changes on its own, tokSrc for an oauth secret
// whose access token must be re-minted before each dial (B14, DS6.4).
type credentialResult struct {
	cred   imap.Credential
	tokSrc *oauthpkg.TokenSource
}

// parseCredential turns the stored JSON into a login, or, for the
// oauth secret of an outlook or a gmail account, into a refreshing
// token source (DS6.4, DS7.2). It registers every secret value with
// the redactor, so a value that leaks into an error or a log line is
// replaced (§3.15, B4).
//
// No error text holds the stored value.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, DS7.2, §3.4, §3.6, B7, B8, B14, IS7.5
func parseCredential(ctx context.Context, acct config.Account, raw string, store secrets.Store, warn func(error)) (credentialResult, error) {
	var v secretValue
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return credentialResult{}, fmt.Errorf("the stored secret of account %q is not readable; add the account again", acct.Alias)
	}
	// accounts.toml wins (DRV.14b): the secret's own username field is
	// read only for an old account that has no username recorded in
	// accounts.toml.
	user := acct.Username
	if user == "" {
		user = v.Username
	}
	switch v.Kind {
	case "password":
		if v.Password == "" {
			return credentialResult{}, fmt.Errorf("the stored secret of account %q holds no password", acct.Alias)
		}
		guard.RegisterSecret(v.Password)
		return credentialResult{cred: imap.Credential{Username: user, Password: v.Password}}, nil
	case "token":
		if v.Token == "" {
			return credentialResult{}, fmt.Errorf("the stored secret of account %q holds no token", acct.Alias)
		}
		guard.RegisterSecret(v.Token)
		return credentialResult{cred: imap.Credential{Username: user, Token: v.Token}}, nil
	case "oauth":
		switch acct.Provider {
		case "outlook":
			return microsoftCredential(ctx, acct, v, store, warn)
		case "gmail":
			return googleCredential(ctx, acct, v, store, warn)
		default:
			// Only outlook and gmail sign in with OAuth (§3.4).
			return credentialResult{}, fmt.Errorf("account %q has an OAuth secret, but provider %q does not sign in with OAuth; add the account again", acct.Alias, acct.Provider)
		}
	default:
		return credentialResult{}, fmt.Errorf("the stored secret of account %q has kind %q, which this server does not know", acct.Alias, v.Kind)
	}
}

// microsoftCredential builds the refreshing token source for one
// outlook account (T6.2, DS6.4): the tenant comes from acct.Tenant
// (already validated and written at account add, DS6.3), and the
// public client id comes from the `oauth.microsoft` store key, never
// from the account block, because the client id is shared by every
// outlook account on this machine (§3.4).
//
// The incoming context is deliberately not the one the token source
// keeps (B14): it is the context of the current call, and it ends as
// soon as that call returns. This function runs once, at the first
// dial, but the *TokenSource it builds is cached on the Factory and
// its Token() is called again by every later dial. A token source
// built from a per-dial context would refresh its access token with
// an already-cancelled context on every dial after the first, so its
// own outgoing calls carry context.Background() instead, bounded only
// by the package's fixed 30s http.Client timeout (DS6.2), never by any
// one dial's lifetime.
func microsoftCredential(ctx context.Context, acct config.Account, v secretValue, store secrets.Store, warn func(error)) (credentialResult, error) {
	if v.RefreshToken == "" {
		return credentialResult{}, fmt.Errorf("the stored secret of account %q holds no refresh token", acct.Alias)
	}
	guard.RegisterSecret(v.RefreshToken)

	clientID, err := microsoftClientID(ctx, store)
	if err != nil {
		return credentialResult{}, err
	}
	if err := oauthpkg.ValidTenant(acct.Tenant); err != nil {
		// I-S6.2, validated a second time: the endpoint is about to be
		// built from this value.
		return credentialResult{}, fmt.Errorf("account %q: %w", acct.Alias, err)
	}
	cfg, err := oauthConfigFunc(clientID, acct.Tenant, "")
	if err != nil {
		return credentialResult{}, err
	}
	rtStore := &aliasRefreshTokenStore{store: store, alias: acct.Alias}
	ts := oauthpkg.NewTokenSource(context.Background(), cfg, rtStore, acct.Alias, v.RefreshToken, warn)
	return credentialResult{tokSrc: ts}, nil
}

// googleCredential builds the refreshing token source of one gmail
// account (DS7.2). The OAuth client comes from the `oauth.google`
// store key, never from the account block, because every gmail
// account on this machine shares it (§3.4). The token source keeps
// context.Background() and not ctx, for the reason that
// microsoftCredential gives (B14).
//
// arch: DS7.2, DS78.3, IS7.5, B14
func googleCredential(ctx context.Context, acct config.Account, v secretValue, store secrets.Store, warn func(error)) (credentialResult, error) {
	if v.RefreshToken == "" {
		return credentialResult{}, fmt.Errorf("the stored secret of account %q holds no refresh token", acct.Alias)
	}
	guard.RegisterSecret(v.RefreshToken)

	client, err := googleClient(ctx, store)
	if err != nil {
		return credentialResult{}, err
	}
	cfg := googleConfigFunc(client, "")
	rtStore := &aliasRefreshTokenStore{store: store, alias: acct.Alias}
	ts := oauthpkg.NewTokenSource(context.Background(), cfg, rtStore, acct.Alias, v.RefreshToken, warn)
	return credentialResult{tokSrc: ts}, nil
}

// googleClient reads the Google OAuth client at googleClientKey
// through boundedGet (the 30 s limit of §3.4, L2). It gives the client
// id, the client secret and the project number (the part of the
// client id before the first "-") to [guard.RegisterSecret] before it
// returns, so no error or log line shows them (IS7.5). The CLI has the
// same registration in registerGoogleClient, because internal/cli does
// not import this package. No error text holds the stored value.
//
// arch: DS7.2, IS7.5, L2
func googleClient(ctx context.Context, store secrets.Store) (oauthpkg.GoogleClient, error) {
	raw, err := boundedGet(ctx, store, googleClientKey)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return oauthpkg.GoogleClient{}, errors.New(`no Google OAuth client is configured; run "mailbag-mcp oauth set google --file client_secret.json"`)
		}
		if errors.Is(err, errBoundedGetTimeout) {
			return oauthpkg.GoogleClient{}, fmt.Errorf("reading the Google OAuth client took longer than %s; open the keyring and try again", secretTimeout)
		}
		return oauthpkg.GoogleClient{}, err
	}
	var c oauthpkg.GoogleClient
	if err := json.Unmarshal([]byte(raw), &c); err != nil || c.ClientID == "" || c.ClientSecret == "" {
		return oauthpkg.GoogleClient{}, errors.New(`the stored Google OAuth client is not readable; run "mailbag-mcp oauth set google --file client_secret.json" again`)
	}
	guard.RegisterSecret(c.ClientID)
	guard.RegisterSecret(c.ClientSecret)
	project, _, _ := strings.Cut(c.ClientID, "-")
	guard.RegisterSecret(project)
	return c, nil
}

// microsoftClientID reads the public client id every outlook account
// on this machine shares (§3.4: `oauth.microsoft` -> {"client_id":".."}),
// bounded by the same 30 s limit as an account's own secret (L2):
// before this fix the call went straight to store.Get and could hold
// a dial past its deadline behind a locked keyring.
//
// arch: S6-close-judge L2, §3.4
func microsoftClientID(ctx context.Context, store secrets.Store) (string, error) {
	raw, err := boundedGet(ctx, store, microsoftClientKey)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return "", errors.New(`no Microsoft OAuth client is configured; run "mailbag-mcp oauth set microsoft --client-id ID"`)
		}
		if errors.Is(err, errBoundedGetTimeout) {
			return "", fmt.Errorf("reading the Microsoft OAuth client id took longer than %s; open the keyring and try again", secretTimeout)
		}
		return "", err
	}
	var v microsoftClientSecret
	if err := json.Unmarshal([]byte(raw), &v); err != nil || v.ClientID == "" {
		return "", errors.New(`the stored Microsoft OAuth client id is not readable; run "mailbag-mcp oauth set microsoft --client-id ID" again`)
	}
	return v.ClientID, nil
}

// aliasRefreshTokenStore adapts one account's own secret (the
// `<alias>` key, kind "oauth") to [oauthpkg.Store]. It is the only
// place that reads or writes that key's refresh_token field, so the
// shape of §3.4's table stays in one place.
type aliasRefreshTokenStore struct {
	store secrets.Store
	alias string
}

func (s *aliasRefreshTokenStore) LoadRefreshToken() (string, error) {
	raw, err := s.store.Get(s.alias)
	if err != nil {
		return "", err
	}
	var v secretValue
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return "", fmt.Errorf("the stored secret of account %q is not readable", s.alias)
	}
	return v.RefreshToken, nil
}

// oauthSecretValue is the exact §3.4 shape of an oauth secret:
// {"v":1,"kind":"oauth","refresh_token":".."}. SaveRefreshToken writes
// this shape and not secretValue, so a rotated secret keeps "v" and
// gets no empty password-only fields.
type oauthSecretValue struct {
	V            int    `json:"v"`
	Kind         string `json:"kind"`
	RefreshToken string `json:"refresh_token"`
}

func (s *aliasRefreshTokenStore) SaveRefreshToken(token string) error {
	raw, err := json.Marshal(oauthSecretValue{V: 1, Kind: "oauth", RefreshToken: token}) //nolint:gosec // G117: this is the secret store value on purpose; it goes to the OS secret store, not to a log or a reply
	if err != nil {
		return err
	}
	return s.store.Set(s.alias, string(raw))
}
