// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package config loads and validates accounts.toml (§3.3). It resolves
// the config and state directories (paths.go) and holds the text
// splice functions that the CLI uses to add or remove an account
// without an encoder pass (splice.go, B18).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/amsys/mailbag-mcp/internal/mime"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// Sentinel errors. Wrap one of these with fmt.Errorf("...: %w", ...) so
// a caller can test the cause with errors.Is.
var (
	ErrInvalidAlias          = errors.New("config: invalid alias")
	ErrUnknownProvider       = errors.New("config: unknown provider")
	ErrUnknownAccess         = errors.New("config: unknown access level")
	ErrUnknownSecrets        = errors.New("config: unknown secrets store")
	ErrUnknownExtra          = errors.New("config: unknown extra")
	ErrMissingEmail          = errors.New("config: missing email")
	ErrInvalidEmail          = errors.New("config: email must be one bare address")
	ErrSpliceMismatch        = errors.New("config: splice changed the alias set by more than the intended edit")
	ErrVerifyPathNotAbsolute = errors.New("config: [verify] path must be absolute")
	ErrUnknownKey            = errors.New("config: unknown key")
	ErrUnknownSaveSent       = errors.New("config: unknown save_sent value")
	ErrToolTimeoutRange      = errors.New("config: tool_timeout out of range")
	ErrPrivateHostNotJMAP    = errors.New("config: private_host is for provider jmap only")
	ErrInvalidIdentity       = errors.New("config: invalid identity")
	ErrSessionURLNotHTTPS    = errors.New("config: session_url must be an https URL with a host")
	ErrJMAPNoSessionURL      = errors.New("config: jmap needs session_url or a domain in email")
)

// minToolTimeout and maxToolTimeout are the allowed range of
// tool_timeout (ORV.3, DRV.14a): 5 seconds to 10 minutes.
const (
	minToolTimeout = 5 * time.Second
	maxToolTimeout = 10 * time.Minute
)

// knownSaveSent lists every save_sent value accounts.toml may use,
// compared case-insensitively and trimmed, the same way
// imap.WriteProvider.savesSentCopy reads it (C13). The empty string is
// legal: it keeps the "auto" default.
var knownSaveSent = map[string]bool{
	"":       true,
	"auto":   true,
	"always": true,
	"never":  true,
}

// aliasPattern is the rule of B17: the alias becomes a keyring key, a
// file name and a part of a printed shell command.
var aliasPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidAlias reports whether alias is safe to use as a keyring key, a
// file name and a part of a printed command (B17).
//
// arch: T1.2, B17
func ValidAlias(alias string) bool {
	return aliasPattern.MatchString(alias)
}

// ValidEmail reports whether email is one bare mail address with no
// display name and no angle brackets. The account email goes into the
// From check and the SMTP envelope as is, so a name form is refused.
//
// arch: T1.2, §3.3, R16-M10
func ValidEmail(email string) bool {
	p, err := mail.ParseAddress(email)
	return err == nil && p.Name == "" && p.Address == email
}

// knownExtras lists every name accounts.toml's extras list may use.
// "modify" and "send" gate the write toolsets of 03-design-R1.md D2.1;
// before that stage RegisterCore added them with no extras entry at
// all, so an existing file with no extras key now loses both (the
// D2.1 migration; see OffToolsets). "decrypt" is the D7.1 toolset: it
// also needs both [decrypt] keys, see decryptMissing. The other four
// are the S9 toolsets (DS9.8). Each name is a group of
// tools.Toolsets, so no accepted name lacks code;
// TestServe_EveryKnownExtraHasCode holds this.
var knownExtras = map[string]bool{
	"modify":         true,
	"send":           true,
	"decrypt":        true,
	"gmail_settings": true,
	"templates":      true,
	"unsubscribe":    true,
	"bulk":           true,
}

// KnownExtras gives every name accounts.toml's extras list may use,
// sorted. Each call gives a new slice.
//
// It is a test seam: no production code calls it. The test
// TestServe_EveryKnownExtraHasCode uses it to prove that each accepted
// name has code. Keep it.
//
// arch: DS9.8
func KnownExtras() []string {
	names := make([]string, 0, len(knownExtras))
	for name := range knownExtras {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var knownProviders = map[string]bool{
	"imap":    true,
	"outlook": true,
	"gmail":   true,
	"jmap":    true,
}

var knownAccess = map[string]bool{
	"read":  true,
	"draft": true,
	"send":  true,
}

// Account is one [accounts.<alias>] block of accounts.toml, after
// validation and defaulting.
type Account struct {
	Alias      string
	Provider   string // imap | outlook | gmail | jmap
	Email      string
	Access     string // read | draft | send, default "draft"
	IMAP       string
	SMTP       string
	Username   string // default: Email
	Identities []string
	SaveSent   string // auto | always | never (trap C13)
	TLSCA      string
	Folders    map[string]string
	Tenant     string // outlook only
	SessionURL string // jmap only; JMAPSessionURL gives the default

	// IdentityList holds the identities of an account in identity
	// mode (DI2.0), in the order of DI1.5. It is nil for an account
	// that is not in identity mode, so the rules of that account stay
	// as before (I2).
	IdentityList []Identity

	// DefaultIdentity is the bare address of default_identity. "" means
	// Account.Email.
	DefaultIdentity string

	// PrivateHost is the jmap-only key private_host. When it is true,
	// the session host may resolve to a private address, and only that
	// host (G11, owner decision 2026-10-09 at the run gate). Load
	// refuses true on another provider. The default is false.
	PrivateHost bool

	// AllowWithoutElicitation is the file-level key
	// [send] allow_without_elicitation, copied into each account
	// block. The send tool reads it from the account that
	// OpenWriter gives back. When it is true, send sends to a client
	// that cannot ask the human (D5.2). The default is false.
	AllowWithoutElicitation bool

	// BulkAllowWithoutElicitation is the file-level key
	// [bulk] allow_without_elicitation, copied into each account
	// block. The bulk tool reads it from the account that OpenWriter
	// gives back. When it is true, bulk changes mail for a client that
	// cannot ask the human (DS9.4). The default is false.
	BulkAllowWithoutElicitation bool
}

// rawFile and rawAccount mirror the TOML shape of accounts.toml
// (§3.3), field for field. Load converts a rawFile into a snapshot
// after validation.
type rawFile struct {
	Secrets      string                `toml:"secrets"`
	Extras       []string              `toml:"extras"`
	DownloadDirs []string              `toml:"download_dirs"`
	AttachDirs   []string              `toml:"attach_dirs"`
	ToolTimeout  string                `toml:"tool_timeout"`
	Send         rawSend               `toml:"send"`
	Bulk         rawBulk               `toml:"bulk"`
	Verify       rawVerify             `toml:"verify"`
	Decrypt      rawDecrypt            `toml:"decrypt"`
	Accounts     map[string]rawAccount `toml:"accounts"`
}

// rawSend is the [send] table of accounts.toml (D5.2).
type rawSend struct {
	AllowWithoutElicitation bool `toml:"allow_without_elicitation"`
}

// rawBulk is the [bulk] table of accounts.toml (DS9.4). It has the
// same shape as rawSend.
type rawBulk struct {
	AllowWithoutElicitation bool `toml:"allow_without_elicitation"`
}

// rawVerify is the [verify] table of accounts.toml (D6.2).
type rawVerify struct {
	// AuthservID is the only Authentication-Results authority whose
	// DKIM result counts. Empty means no DKIM result counts.
	AuthservID string `toml:"authserv_id"`

	// PGPKeysDir is the directory of OpenPGP public keys that the
	// human controls. Only a key in this directory gives trust.
	PGPKeysDir string `toml:"pgp_keys_dir"`

	// SMIMECAFile is the PEM bundle of S/MIME trust roots that the
	// human writes. It can also hold CRLs. Empty gives trust unknown.
	SMIMECAFile string `toml:"smime_ca_file"`

	// SMIMECRLCheck adds a revocation check. It needs a CRL in
	// SMIMECAFile.
	SMIMECRLCheck bool `toml:"smime_crl_check"`

	// OpensslPath is the absolute path of the openssl binary. Empty
	// means the openssl on PATH.
	OpensslPath string `toml:"openssl_path"`
}

// rawDecrypt is the [decrypt] table of accounts.toml (D7.1). Both keys
// default to false. The decrypt toolset needs both keys true and
// "decrypt" in extras.
type rawDecrypt struct {
	Enabled                          bool `toml:"enabled"`
	AckPlaintextReachesModelProvider bool `toml:"ack_plaintext_reaches_model_provider"`
}

// The three names that decryptMissing reports. Each one is a fixed
// config key name. None of them holds text from the file.
const (
	DecryptKeyExtras  = "extras decrypt"
	DecryptKeyEnabled = "decrypt.enabled"
	DecryptKeyAck     = "decrypt.ack_plaintext_reaches_model_provider"
)

// decryptMissing gives the D7.1 keys that are not set, in a fixed
// order. An empty result means that all three keys are set.
func decryptMissing(raw rawFile) []string {
	var missing []string
	hasExtra := false
	for _, e := range raw.Extras {
		if e == "decrypt" {
			hasExtra = true
		}
	}
	if !hasExtra {
		missing = append(missing, DecryptKeyExtras)
	}
	if !raw.Decrypt.Enabled {
		missing = append(missing, DecryptKeyEnabled)
	}
	if !raw.Decrypt.AckPlaintextReachesModelProvider {
		missing = append(missing, DecryptKeyAck)
	}
	return missing
}

// gateExtras removes "decrypt" from extras when missing is not empty
// (D7.1). The result is a new slice. This is the only place that
// applies the gate, so each caller of Extras gets the gated list. A
// decrypt tool that exists by mistake sends plain text to the model
// provider (I13).
func gateExtras(extras, missing []string) []string {
	if len(missing) == 0 || extras == nil {
		return extras
	}
	out := make([]string, 0, len(extras))
	for _, e := range extras {
		if e != "decrypt" {
			out = append(out, e)
		}
	}
	return out
}

type rawAccount struct {
	Provider    string            `toml:"provider"`
	Email       string            `toml:"email"`
	Access      string            `toml:"access"`
	IMAP        string            `toml:"imap"`
	SMTP        string            `toml:"smtp"`
	Username    string            `toml:"username"`
	Identities  []string          `toml:"identities"`
	SaveSent    string            `toml:"save_sent"`
	TLSCA       string            `toml:"tls_ca"`
	Folders     map[string]string `toml:"folders"`
	Tenant      string            `toml:"tenant"`
	SessionURL  string            `toml:"session_url"`
	PrivateHost bool              `toml:"private_host"`

	Identity        []rawIdentity `toml:"identity"`
	DefaultIdentity string        `toml:"default_identity"`
}

// rawIdentity mirrors one [[accounts.<alias>.identity]] table (DI1.1).
// Every key is a plain field, so the strict unknown-key check stays on
// (I3). A *bool tells "not set" from false.
type rawIdentity struct {
	Email               string   `toml:"email"`
	Name                string   `toml:"name"`
	Signature           string   `toml:"signature"`
	SignatureHTML       string   `toml:"signature_html"`
	SignatureFile       string   `toml:"signature_file"`
	SignatureHTMLFile   string   `toml:"signature_html_file"`
	SignatureOnNew      *bool    `toml:"signature_on_new"`
	SignatureOnReply    *bool    `toml:"signature_on_reply"`
	SignatureOnForward  *bool    `toml:"signature_on_forward"`
	ReplyAboveQuote     *bool    `toml:"reply_above_quote"`
	SignatureBelowQuote *bool    `toml:"signature_below_quote"`
	ComposeHTML         *bool    `toml:"compose_html"`
	ReplyMatch          []string `toml:"reply_match"`
}

// snapshot is one validated read of accounts.toml. It never changes
// after Load or Refresh builds it; a new snapshot replaces it instead.
// That makes a read through Config's getters safe with no lock held
// over field access.
type snapshot struct {
	modTime      time.Time
	sigFiles     []sigFileStamp // signature files read by this load
	secrets      string
	extras       []string
	downloadDirs []string
	attachDirs   []string
	toolTimeout  time.Duration
	verify       verify.Config
	accounts     map[string]Account

	// decryptMissing holds the D7.1 keys that are not set. When it is
	// not empty, extras holds no "decrypt".
	decryptMissing []string
}

// Config is a loaded, validated accounts.toml. It is safe for
// concurrent use. Call Refresh before each tool call (§3.1) to pick up
// a change made by "account add" or "account remove" in another
// process, or by hand.
type Config struct {
	path string

	mu   sync.RWMutex
	snap *snapshot
}

// Load reads and validates the accounts.toml at path.
//
// arch: T1.2, §3.3, §3.1, D14, B17
func Load(path string) (*Config, error) {
	c := &Config{path: path}
	if _, err := c.Refresh(); err != nil {
		return nil, err
	}
	return c, nil
}

// Refresh reads accounts.toml again when its modification time
// changed since the last load, so a new account shows without a
// server restart (§3.3). It reports whether it reloaded.
//
// arch: T1.2, §3.1, §3.3
func (c *Config) Refresh() (bool, error) {
	info, err := os.Stat(c.path)
	if err != nil {
		return false, err
	}

	c.mu.RLock()
	unchanged := c.snap != nil && info.ModTime().Equal(c.snap.modTime) && sigFilesUnchanged(c.snap.sigFiles)
	c.mu.RUnlock()
	if unchanged {
		return false, nil
	}

	snap, err := loadSnapshot(c.path, info.ModTime())
	if err != nil {
		return false, err
	}

	c.mu.Lock()
	c.snap = snap
	c.mu.Unlock()
	return true, nil
}

func loadSnapshot(path string, modTime time.Time) (*snapshot, error) {
	var raw rawFile
	meta, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := checkUnknownKeys(meta); err != nil {
		return nil, err
	}
	return validateIn(raw, modTime, filepath.Dir(path))
}

// checkUnknownKeys rejects a key accounts.toml holds that this build
// does not decode into any field, naming each key and its table
// (ORV.2). A typo such as "acess" must stop the load: today it leaves
// the account at the "draft" default, which allows more than the
// human wrote (DRV.14a).
//
// arch: DRV.14a, ORV.2
func checkUnknownKeys(meta toml.MetaData) error {
	undecoded := meta.Undecoded()
	if len(undecoded) == 0 {
		return nil
	}
	parts := make([]string, 0, len(undecoded))
	for _, k := range undecoded {
		name := k[len(k)-1]
		table := "the top level"
		if len(k) > 1 {
			table = fmt.Sprintf("table %q", toml.Key(k[:len(k)-1]).String())
		}
		parts = append(parts, fmt.Sprintf("%q in %s", name, table))
	}
	return fmt.Errorf("config: unknown key %s: %w", strings.Join(parts, ", "), ErrUnknownKey)
}

// verifyPathAbsolute rejects a relative or "~"-prefixed [verify] path
// (F-D5). An empty value stays legal: it means "no directory" or "use
// PATH", not "current directory". filepath.IsAbs already rejects a
// "~"-prefixed path on this platform, since it never starts with "/".
func verifyPathAbsolute(key, path string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("config: verify.%s %q: %w", key, path, ErrVerifyPathNotAbsolute)
	}
	return nil
}

// checkHTTPS refuses a session URL that is not https or has no host
// name (DS8.6). The error does not hold the URL, because a URL can
// hold a password.
func checkHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return ErrSessionURLNotHTTPS
	}
	return nil
}

// JMAPSessionURL gives the JMAP session URL of acct. It is SessionURL
// when that is set, else https://<domain of Email>/.well-known/jmap.
// The result is always an https URL with a host name. Load, the CLI
// default, the Factory and the status lines use this one rule
// (DS78.11 G11). The error is ErrSessionURLNotHTTPS or
// ErrJMAPNoSessionURL.
//
// arch: DS8.6, G11
func JMAPSessionURL(acct Account) (string, error) {
	if acct.SessionURL != "" {
		if err := checkHTTPS(acct.SessionURL); err != nil {
			return "", err
		}
		return acct.SessionURL, nil
	}
	at := strings.LastIndexByte(acct.Email, '@')
	if at < 0 {
		return "", ErrJMAPNoSessionURL
	}
	domain := acct.Email[at+1:]
	s := "https://" + domain + "/.well-known/jmap"
	// The parsed host must be the whole domain, so a "/" or another
	// URL character in the email cannot point the URL at another host.
	u, err := url.Parse(s)
	if err != nil || u.Host != domain || u.Hostname() == "" {
		return "", ErrJMAPNoSessionURL
	}
	return s, nil
}

// validateIn checks raw. dir is the directory of accounts.toml; it
// anchors a relative signature_file or signature_html_file path (DI1.7).
func validateIn(raw rawFile, modTime time.Time, dir string) (*snapshot, error) {
	loader := &sigLoader{dir: dir}
	secrets := raw.Secrets
	if secrets == "" {
		secrets = "keyring"
	}
	if secrets != "keyring" && secrets != "file" {
		return nil, fmt.Errorf("config: secrets %q: %w", secrets, ErrUnknownSecrets)
	}

	for _, e := range raw.Extras {
		if !knownExtras[e] {
			return nil, fmt.Errorf("config: extras %q: %w", e, ErrUnknownExtra)
		}
	}

	timeout := 45 * time.Second
	if raw.ToolTimeout != "" {
		d, err := time.ParseDuration(raw.ToolTimeout)
		if err != nil {
			return nil, fmt.Errorf("config: tool_timeout %q: %w", raw.ToolTimeout, err)
		}
		if d < minToolTimeout || d > maxToolTimeout {
			return nil, fmt.Errorf("config: tool_timeout %q: must be between %s and %s: %w",
				raw.ToolTimeout, minToolTimeout, maxToolTimeout, ErrToolTimeoutRange)
		}
		timeout = d
	}

	if err := verifyPathAbsolute("pgp_keys_dir", raw.Verify.PGPKeysDir); err != nil {
		return nil, err
	}
	if err := verifyPathAbsolute("smime_ca_file", raw.Verify.SMIMECAFile); err != nil {
		return nil, err
	}
	if err := verifyPathAbsolute("openssl_path", raw.Verify.OpensslPath); err != nil {
		return nil, err
	}

	accounts := make(map[string]Account, len(raw.Accounts))
	for alias, ra := range raw.Accounts {
		if !ValidAlias(alias) {
			return nil, fmt.Errorf("config: account alias %q: %w", alias, ErrInvalidAlias)
		}
		if !knownProviders[ra.Provider] {
			return nil, fmt.Errorf("config: account %q: provider %q: %w", alias, ra.Provider, ErrUnknownProvider)
		}
		if ra.Email == "" {
			return nil, fmt.Errorf("config: account %q: %w", alias, ErrMissingEmail)
		}
		access := ra.Access
		if access == "" {
			access = "draft"
		}
		if !knownAccess[access] {
			return nil, fmt.Errorf("config: account %q: access %q: %w", alias, access, ErrUnknownAccess)
		}
		if !knownSaveSent[strings.ToLower(strings.TrimSpace(ra.SaveSent))] {
			return nil, fmt.Errorf("config: account %q: save_sent %q: %w", alias, ra.SaveSent, ErrUnknownSaveSent)
		}
		if ra.PrivateHost && ra.Provider != "jmap" {
			return nil, fmt.Errorf("config: account %q: provider %q: %w", alias, ra.Provider, ErrPrivateHostNotJMAP)
		}
		if ra.SessionURL != "" {
			if err := checkHTTPS(ra.SessionURL); err != nil {
				return nil, fmt.Errorf("config: account %q: %w", alias, err)
			}
		}
		username := ra.Username
		if username == "" {
			username = ra.Email
		}
		idents, err := buildIdentities(alias, ra, loader)
		if err != nil {
			return nil, err
		}
		acct := Account{
			Alias:      alias,
			Provider:   ra.Provider,
			Email:      ra.Email,
			Access:     access,
			IMAP:       ra.IMAP,
			SMTP:       ra.SMTP,
			Username:   username,
			Identities: idents.flat,
			SaveSent:   ra.SaveSent,
			TLSCA:      ra.TLSCA,
			Folders:    ra.Folders,
			Tenant:     ra.Tenant,
			SessionURL: ra.SessionURL,

			PrivateHost: ra.PrivateHost,

			IdentityList:    idents.list,
			DefaultIdentity: idents.def,

			AllowWithoutElicitation:     raw.Send.AllowWithoutElicitation,
			BulkAllowWithoutElicitation: raw.Bulk.AllowWithoutElicitation,
		}
		if acct.Provider == "jmap" {
			if _, err := JMAPSessionURL(acct); err != nil {
				return nil, fmt.Errorf("config: account %q: %w", alias, err)
			}
		}
		// This check comes after the jmap check, so a jmap email with
		// no domain still gives ErrJMAPNoSessionURL.
		if !ValidEmail(ra.Email) {
			return nil, fmt.Errorf("config: account %q: email %q: %w", alias, ra.Email, ErrInvalidEmail)
		}
		accounts[alias] = acct
	}

	missing := decryptMissing(raw)
	return &snapshot{
		modTime:        modTime,
		sigFiles:       loader.files,
		decryptMissing: missing,
		secrets:        secrets,
		extras:         gateExtras(raw.Extras, missing),
		downloadDirs:   raw.DownloadDirs,
		attachDirs:     raw.AttachDirs,
		toolTimeout:    timeout,
		verify: verify.Config{
			AuthservID:    raw.Verify.AuthservID,
			PGPKeysDir:    raw.Verify.PGPKeysDir,
			SMIMECAFile:   raw.Verify.SMIMECAFile,
			SMIMECRLCheck: raw.Verify.SMIMECRLCheck,
			OpensslPath:   raw.Verify.OpensslPath,
		},
		accounts: accounts,
	}, nil
}

func (c *Config) get() *snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snap
}

// Secrets is "keyring" or "file" (D4, D13, B3).
func (c *Config) Secrets() string { return c.get().secrets }

// Extras lists the off-by-default tool groups that are turned on
// (D3). It holds "decrypt" only when all three D7.1 keys are set; see
// DecryptMissing.
func (c *Config) Extras() []string { return c.get().extras }

// DownloadDirs lists the directories added to the default save
// directory.
func (c *Config) DownloadDirs() []string { return c.get().downloadDirs }

// AttachDirs returns the directories that may supply an attachment.
// When it is not empty, they are the only ones.
func (c *Config) AttachDirs() []string { return c.get().attachDirs }

// ToolTimeout is the default tool deadline (§3.1). It defaults to 45s.
func (c *Config) ToolTimeout() time.Duration { return c.get().toolTimeout }

// DecryptMissing gives the D7.1 keys that are not set, in a fixed
// order: DecryptKeyExtras, DecryptKeyEnabled, DecryptKeyAck. When the
// result is empty, the decrypt toolset is on. Otherwise Extras holds
// no "decrypt", and serve names these keys in its log line.
//
// arch: D7.1
func (c *Config) DecryptMissing() []string {
	m := c.get().decryptMissing
	return append([]string(nil), m...)
}

// Verify gives the [verify] keys for signature checks (D6.2).
func (c *Config) Verify() verify.Config { return c.get().verify }

// Account returns the account with the given alias.
func (c *Config) Account(alias string) (Account, bool) {
	a, ok := c.get().accounts[alias]
	return a, ok
}

// OffToolsets reports which names in known are absent from Extras,
// sorted. A caller passes the toolset names it actually has code for
// (03-design-R1.md D2.2's Registry groups); config does not import
// that list itself, so a name a later stage has not wired yet is
// never reported as off.
//
// This is the D2.1 migration check: an accounts.toml with no extras
// key returns every name in known, because "modify" and "send" used
// to run with no extras entry at all.
//
// arch: D2.1
func (c *Config) OffToolsets(known []string) []string {
	extras := c.Extras()
	on := make(map[string]bool, len(extras))
	for _, e := range extras {
		on[e] = true
	}
	off := make([]string, 0, len(known))
	for _, name := range known {
		if !on[name] {
			off = append(off, name)
		}
	}
	sort.Strings(off)
	return off
}

// Aliases lists every account alias, sorted.
func (c *Config) Aliases() []string {
	s := c.get()
	out := make([]string, 0, len(s.accounts))
	for a := range s.accounts {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// Identity is one sender of an account with its compose settings
// (arch: DI1.2).
type Identity struct {
	Email                     string // bare address, as written
	Name                      string
	Signature                 string // DI1.4 normal form; "" = none
	SignatureHTML             string // "" = derive from Signature (DI3.5)
	OnNew, OnReply, OnForward bool
	ReplyAboveQuote           bool
	SignatureBelowQuote       bool
	ComposeHTML               bool
	ReplyMatch                []string // lower case
}

// defaultIdentity gives an identity with the DI0 R6 defaults and no
// signature.
func defaultIdentity(email string) Identity {
	return Identity{
		Email:           email,
		OnNew:           true,
		OnReply:         true,
		ReplyAboveQuote: true,
	}
}

// IdentityMode reports whether the account is in identity mode: it has
// at least one identity table or a default_identity (DI2.0). The flat
// identities list alone never turns it on.
//
// arch: DI2.0
func (a Account) IdentityMode() bool {
	return len(a.IdentityList) > 0 || a.DefaultIdentity != ""
}

// Identity returns the identity whose Email equals addr (EqualFold).
//
// arch: DI1.2
func (a Account) Identity(addr string) (Identity, bool) {
	for _, id := range a.IdentityList {
		if strings.EqualFold(id.Email, addr) {
			return id, true
		}
	}
	return Identity{}, false
}

// Default returns the identity of DefaultIdentity, else of Email. The
// list of a loaded account always holds Email and a set
// DefaultIdentity. When the list holds neither (an Account built by
// hand), it gives an identity of Email with the defaults and no
// signature.
//
// arch: DI1.2
func (a Account) Default() Identity {
	for _, want := range []string{a.DefaultIdentity, a.Email} {
		if want == "" {
			continue
		}
		if id, ok := a.Identity(want); ok {
			return id
		}
	}
	return defaultIdentity(a.Email)
}

// MatchReply returns the first identity, in file order, that has a
// reply_match pattern matching addr.
//
// arch: DI1.2
func (a Account) MatchReply(addr string) (Identity, bool) {
	bare := bareLower(addr)
	for _, id := range a.IdentityList {
		for _, pat := range id.ReplyMatch {
			if matchReplyPattern(pat, bare) {
				return id, true
			}
		}
	}
	return Identity{}, false
}

// OwnsAddress reports whether addr is the account email, an identity
// email (flat or table), or matches a reply_match pattern (DI6.1).
// Outside identity mode it keeps the raw compare of the account email
// and the flat list (I2).
//
// arch: DI1.2, DI6.1
func (a Account) OwnsAddress(addr string) bool {
	if strings.TrimSpace(addr) == "" {
		return false
	}
	for _, want := range append([]string{a.Email}, a.Identities...) {
		if want != "" && strings.EqualFold(want, addr) {
			return true
		}
	}
	if !a.IdentityMode() {
		return false
	}
	if _, ok := a.Identity(addr); ok {
		return true
	}
	for _, flat := range a.Identities {
		if bare := bareLower(flat); bare != "" && strings.EqualFold(bare, bareLower(addr)) {
			return true
		}
	}
	_, ok := a.MatchReply(addr)
	return ok
}

// bareLower gives the bare address of one header value in lower case.
// A value that does not parse gives its trimmed lower-case self.
func bareLower(v string) string {
	v = strings.TrimSpace(v)
	if p, err := mail.ParseAddress(v); err == nil {
		return strings.ToLower(p.Address)
	}
	return strings.ToLower(v)
}

// matchReplyPattern matches a lower-case bare address against one
// reply_match pattern: the local part with "*" and "?" wildcards, the
// domain exact.
func matchReplyPattern(pat, addr string) bool {
	pi := strings.LastIndex(pat, "@")
	ai := strings.LastIndex(addr, "@")
	if pi < 0 || ai < 0 || pat[pi+1:] != addr[ai+1:] {
		return false
	}
	return globMatch([]rune(pat[:pi]), []rune(addr[:ai]))
}

// globMatch matches s against p; "*" is any run, "?" is one rune.
func globMatch(p, s []rune) bool {
	px, sx := 0, 0
	star, mark := -1, 0
	for sx < len(s) {
		switch {
		case px < len(p) && (p[px] == '?' || p[px] == s[sx]) && p[px] != '*':
			px++
			sx++
		case px < len(p) && p[px] == '*':
			star, mark = px, sx
			px++
		case star >= 0:
			px = star + 1
			mark++
			sx = mark
		default:
			return false
		}
	}
	for px < len(p) && p[px] == '*' {
		px++
	}
	return px == len(p)
}

// NormalizeSignature gives the DI1.4 normal form: CRLF becomes LF,
// leading and trailing empty lines are cut, and a first line that is
// exactly "-- " or "--" is cut with the empty lines after it. Every
// other byte stays. A lone CR is not touched; the load refuses it.
//
// arch: DI1.4
func NormalizeSignature(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for {
		for len(lines) > 0 && lines[0] == "" {
			lines = lines[1:]
		}
		if len(lines) > 0 && (lines[0] == "-- " || lines[0] == "--") {
			lines = lines[1:]
			continue
		}
		break
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// identitySet is the identity part of one validated account.
type identitySet struct {
	list []Identity
	flat []string
	def  string
}

// buildIdentities validates the identity tables and default_identity of
// one account and merges them with the flat list (DI1.3, DI1.5). For an
// account not in identity mode it gives the flat list back unchanged.
func buildIdentities(alias string, ra rawAccount, ld *sigLoader) (identitySet, error) {
	if len(ra.Identity) == 0 && ra.DefaultIdentity == "" {
		return identitySet{flat: ra.Identities}, nil
	}
	fail := func(idx int, key, why string) error {
		if idx < 0 {
			return fmt.Errorf("config: account %q: %s: %s: %w", alias, key, why, ErrInvalidIdentity)
		}
		return fmt.Errorf("config: account %q: identity[%d]: %s: %s: %w", alias, idx, key, why, ErrInvalidIdentity)
	}
	b := func(p *bool, def bool) bool {
		if p == nil {
			return def
		}
		return *p
	}
	var list []Identity
	seen := map[string]bool{}
	for i, ri := range ra.Identity {
		email := strings.TrimSpace(ri.Email)
		p, err := mail.ParseAddress(email)
		if err != nil || p.Name != "" || p.Address != email {
			return identitySet{}, fail(i, "email", "must be one bare address")
		}
		if seen[strings.ToLower(email)] {
			return identitySet{}, fail(i, "email", "same address as an earlier table")
		}
		seen[strings.ToLower(email)] = true

		sigText, htmlText := ri.Signature, ri.SignatureHTML
		if ri.SignatureFile != "" {
			if ri.Signature != "" {
				return identitySet{}, fail(i, "signature_file", "is set together with signature")
			}
			t, err := ld.load(ri.SignatureFile)
			if err != nil {
				return identitySet{}, fail(i, "signature_file", err.Error())
			}
			sigText = t
		}
		if ri.SignatureHTMLFile != "" {
			if ri.SignatureHTML != "" {
				return identitySet{}, fail(i, "signature_html_file", "is set together with signature_html")
			}
			t, err := ld.load(ri.SignatureHTMLFile)
			if err != nil {
				return identitySet{}, fail(i, "signature_html_file", err.Error())
			}
			// An editor adds a final newline; the inline value has none.
			htmlText = strings.TrimRight(t, "\r\n")
		}

		if strings.ContainsRune(sigText, 0) {
			return identitySet{}, fail(i, "signature", "holds a NUL byte")
		}
		sig := NormalizeSignature(sigText)
		if strings.ContainsRune(sig, '\r') {
			return identitySet{}, fail(i, "signature", "holds a lone CR")
		}
		for _, line := range strings.Split(sig, "\n") {
			if strings.HasPrefix(line, ">") {
				return identitySet{}, fail(i, "signature", "a line starts with \">\"")
			}
		}
		if n := len([]rune(sig)); n > 1000 {
			return identitySet{}, fail(i, "signature", "is longer than 1000 characters")
		}

		if htmlText != "" {
			if err := checkSignatureHTML(htmlText, sig); err != nil {
				return identitySet{}, fail(i, "signature_html", err.Error())
			}
		}

		var pats []string
		for _, pat := range ri.ReplyMatch {
			pat = strings.ToLower(strings.TrimSpace(pat))
			if err := checkReplyMatch(pat); err != nil {
				return identitySet{}, fail(i, "reply_match", fmt.Sprintf("%q: %s", pat, err))
			}
			pats = append(pats, pat)
		}

		id := defaultIdentity(email)
		id.Name = ri.Name
		id.Signature = sig
		id.SignatureHTML = htmlText
		id.OnNew = b(ri.SignatureOnNew, true)
		id.OnReply = b(ri.SignatureOnReply, true)
		id.OnForward = b(ri.SignatureOnForward, false)
		id.ReplyAboveQuote = b(ri.ReplyAboveQuote, true)
		id.SignatureBelowQuote = b(ri.SignatureBelowQuote, false)
		id.ComposeHTML = b(ri.ComposeHTML, false)
		id.ReplyMatch = pats
		list = append(list, id)
	}

	// DI1.5: tables, then flat entries with no table, then the account email.
	flat := append([]string(nil), ra.Identities...)
	for _, f := range ra.Identities {
		bare := bareLower(f)
		if bare == "" || seen[bare] {
			continue
		}
		seen[bare] = true
		list = append(list, defaultIdentity(bare))
	}
	if !seen[strings.ToLower(ra.Email)] {
		list = append(list, defaultIdentity(ra.Email))
	}

	// default_identity may name the account email, a table or a flat entry.
	def := strings.TrimSpace(ra.DefaultIdentity)
	if def != "" {
		ok := strings.EqualFold(def, ra.Email) || seen[strings.ToLower(def)]
		if !ok {
			return identitySet{}, fail(-1, "default_identity", "is neither the account email nor an identity email")
		}
	}
	// Table emails that the flat list lacks join Account.Identities.
	have := map[string]bool{}
	for _, f := range ra.Identities {
		have[bareLower(f)] = true
	}
	for _, ri := range ra.Identity {
		email := strings.TrimSpace(ri.Email)
		if !have[strings.ToLower(email)] {
			have[strings.ToLower(email)] = true
			flat = append(flat, email)
		}
	}
	return identitySet{list: list, flat: flat, def: def}, nil
}

// maxSigFile is the size limit of a signature file (DI1.7).
const maxSigFile = 64 << 10

// sigFileStamp records one signature file that a load read.
type sigFileStamp struct {
	path    string
	modTime time.Time
}

// sigLoader reads signature files for one load. dir anchors a relative
// path. files collects what it read, for Refresh.
type sigLoader struct {
	dir   string
	files []sigFileStamp
}

// resolve gives the path of a signature file: an absolute path as is,
// "~/" against the home directory, any other path against dir.
func (l *sigLoader) resolve(p string) (string, error) {
	switch {
	case filepath.IsAbs(p):
		return filepath.Clean(p), nil
	case strings.HasPrefix(p, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New("cannot find the home directory")
		}
		return filepath.Join(home, p[2:]), nil
	}
	return filepath.Join(l.dir, p), nil
}

// load reads the file named by p and records its modification time.
// An error text never holds the path (DI1.7).
func (l *sigLoader) load(p string) (string, error) {
	full, err := l.resolve(p)
	if err != nil {
		return "", err
	}
	// O_NONBLOCK makes the open of a FIFO return at once. The checks
	// then use the open file, so a swap after the open has no effect.
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: the path comes from the user's own config
	if err != nil {
		return "", errors.New("file cannot be read")
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", errors.New("file cannot be read")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("is not a regular file")
	}
	if info.Size() > maxSigFile {
		return "", errors.New("file is larger than 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSigFile+1))
	if err != nil {
		return "", errors.New("file cannot be read")
	}
	if len(data) > maxSigFile {
		return "", errors.New("file is larger than 64 KiB")
	}
	// Some editors write a UTF-8 byte order mark. Cut it, as the final
	// newline is cut, so U+FEFF never reaches a draft.
	data = bytes.TrimPrefix(data, []byte("\xEF\xBB\xBF"))
	if !utf8.Valid(data) {
		return "", errors.New("file is not valid UTF-8")
	}
	l.files = append(l.files, sigFileStamp{path: full, modTime: info.ModTime()})
	return string(data), nil
}

// sigFilesUnchanged reports whether every recorded signature file still
// exists with the recorded modification time.
func sigFilesUnchanged(files []sigFileStamp) bool {
	for _, f := range files {
		info, err := os.Stat(f.path)
		if err != nil || !info.ModTime().Equal(f.modTime) {
			return false
		}
	}
	return true
}

// checkSignatureHTML applies the DI1.3 item 4 rules to a signature_html
// value. sig is the normalised text signature.
func checkSignatureHTML(html, sig string) error {
	if sig == "" {
		return errors.New("needs a signature (the text form)")
	}
	if len(html) > 4000 {
		return errors.New("is longer than 4000 bytes")
	}
	if clean, _ := mime.AllowHTML(html); clean != html {
		return errors.New("holds markup that the HTML allowlist removes")
	}
	text, removed := mime.HTMLToTextCount(html)
	if removed > 0 {
		return errors.New("holds hidden or too deeply nested text")
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, ">") {
			return errors.New("a text line of it starts with \">\"")
		}
	}
	return nil
}

// checkReplyMatch checks one lower-case reply_match pattern: it is
// <local>@<domain>, only <local> may hold "*" or "?", and <local> is
// not empty (DI1.3 item 5).
func checkReplyMatch(pat string) error {
	i := strings.LastIndex(pat, "@")
	if i < 0 {
		return errors.New("must be <local>@<domain>")
	}
	local, domain := pat[:i], pat[i+1:]
	if local == "" || domain == "" {
		return errors.New("local part and domain must not be empty")
	}
	if strings.ContainsAny(domain, "*?") {
		return errors.New("the domain must hold no wildcard")
	}
	if strings.ContainsAny(pat, " \t\r\n,<>") || strings.Contains(local, "@") {
		return errors.New("must be one bare pattern")
	}
	return nil
}
