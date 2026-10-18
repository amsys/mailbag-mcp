// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/mail"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// keyringService is the keyring service name of §3.4. The server uses
// the same name (internal/tools).
const keyringService = "mailbag-mcp"

// keyringProbeKey is the key the first "account add" reads to learn
// whether the keyring works (§3.4). It holds a dot, so it can never
// collide with an alias.
const keyringProbeKey = "probe.keyring"

// loginTimeout bounds the live login of "account add" and "account
// test". It is longer than a tool call, because a person watches this
// one and a first TLS handshake to a cold server is slow.
const loginTimeout = 60 * time.Second

// account runs one "account ..." subcommand.
//
// arch: T4.6, §3.5
func account(args []string, env Env) int {
	if len(args) == 0 {
		return usageErrf(env, "account needs one of add, list, remove, test")
	}
	switch args[0] {
	case "add":
		return accountAdd(args[1:], env)
	case "list":
		return accountList(args[1:], env)
	case "remove":
		return accountRemove(args[1:], env)
	case "test":
		return accountTest(args[1:], env)
	default:
		return usageErrf(env, "unknown account subcommand %q", args[0])
	}
}

// accountAdd writes one new account and proves it works.
//
// The order is the order of §3.5 and B5: check the alias pattern,
// check that the alias is free, only then ask for the secret, save,
// test the login, and on a failed login remove both the account block
// and the secret. A piped stdin never reaches the prompt (B5).
//
// arch: T4.6, §3.5, §3.3, §3.4, §5.4, B5, B6, B17, B18, D15
func accountAdd(args []string, env Env) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usageErrf(env, "account add needs an alias as its first argument")
	}
	alias := args[0]

	set := flag.NewFlagSet("account add", flag.ContinueOnError)
	set.SetOutput(env.Stderr)
	set.Usage = func() { _, _ = fmt.Fprint(env.Stderr, usageText) }
	provider := set.String("provider", "imap", "imap, outlook, gmail or jmap")
	email := set.String("email", "", "the mailbox address")
	imapAddr := set.String("imap", "", "host:port; port 993 is TLS, any other port is STARTTLS")
	smtpAddr := set.String("smtp", "", "host:port; port 465 is TLS, any other port is STARTTLS")
	username := set.String("username", "", "login name; the default is the email address")
	access := set.String("access", "draft", "read, draft or send")
	tenant := set.String("tenant", "", "outlook only: common, organizations, consumers, a GUID or a DNS name; default from --email's domain")
	paste := set.Bool("paste", false, "paste the sign-in redirect URL back instead of using the loopback listener")
	reauth := set.Bool("reauth", false, "get a new sign-in for an existing OAuth account; leaves the account block as it is")
	sessionURL := set.String("session-url", "", "jmap only: the session URL; default https://<domain of --email>/.well-known/jmap")
	bearer := set.Bool("bearer", false, "jmap only: sign in with an API token instead of a password")
	privateHost := set.Bool("private-host", false, "jmap only: allow the session host to be at a private network address")
	if err := set.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if set.NArg() > 0 {
		return usageErrf(env, "unexpected argument %q", set.Arg(0))
	}
	// The three jmap flags have no effect for another provider. Refuse
	// them, so that a person does not think that they took effect.
	if *provider != "jmap" {
		var jmapOnly string
		set.Visit(func(fl *flag.Flag) {
			if jmapOnly == "" && (fl.Name == "session-url" || fl.Name == "bearer" || fl.Name == "private-host") {
				jmapOnly = fl.Name
			}
		})
		if jmapOnly != "" {
			return usageErrf(env, "--%s is for --provider jmap only", jmapOnly)
		}
	}

	// The alias is a keyring key, a file name and a part of a printed
	// command (B17). Check it before anything else happens.
	if err := guard.ValidateAlias(alias); err != nil {
		return usageErrf(env, "alias %q: use letters, digits, - and _ only", alias)
	}

	if *reauth {
		return accountReauth(alias, *paste, env)
	}

	switch *provider {
	case "imap":
	case "outlook":
		return accountAddOutlook(alias, *email, *tenant, *paste, *access, *username, env)
	case "gmail":
		return accountAddGmail(alias, *email, *paste, *access, env)
	case "jmap":
		return accountAddJMAP(alias, *email, *sessionURL, *bearer, *privateHost, *access, *username, env)
	default:
		return usageErrf(env, "unknown provider %q; the providers are imap, outlook, gmail and jmap", *provider)
	}
	if *email == "" {
		return usageErrf(env, "account add needs --email")
	}
	if !config.ValidEmail(*email) {
		return usageErrf(env, "--email must be one bare address, with no display name")
	}
	if *imapAddr == "" {
		return usageErrf(env, "account add --provider imap needs --imap host:port")
	}
	if *smtpAddr == "" {
		return usageErrf(env, "account add --provider imap needs --smtp host:port")
	}
	if *access != "read" && *access != "draft" && *access != "send" {
		return usageErrf(env, "unknown access level %q; use read, draft or send", *access)
	}

	fields := map[string]*string{
		"--email": email, "--imap": imapAddr, "--smtp": smtpAddr, "--username": username,
	}
	for name, value := range fields {
		clean, err := guard.ValidateField(*value)
		if err != nil || strings.ContainsAny(clean, "\"\\") {
			return usageErrf(env, "%s holds a character that accounts.toml cannot carry", name)
		}
		*value = clean
	}

	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	taken, err := aliasTaken(path, alias)
	if err != nil {
		return failf(env, "read %s: %v", path, err)
	}
	if taken != "" {
		// B5: the alias check comes before the prompt, so a duplicate
		// never costs a typed password.
		return failf(env, "account %q exists already; remove it first with `mailbag-mcp account remove %s`", taken, taken)
	}

	kind, err := storeKind(path, env)
	if err != nil {
		return failf(env, "%v", err)
	}

	password, err := env.ReadSecret(fmt.Sprintf("password for %s (the typing stays hidden): ", *email))
	if err != nil {
		if errors.Is(err, errNotTerminal) {
			return usageErrf(env, "%v", err)
		}
		return failf(env, "read the password: %v", err)
	}
	if password == "" {
		return failf(env, "the password is empty; nothing was written")
	}
	// B6: from here on, any error text that repeats the value prints
	// "<redacted>" instead. failf redacts every line it writes.
	guard.RegisterSecret(password)

	dir := filepath.Dir(path)
	if err := ensureFile(path, kind); err != nil {
		return failf(env, "write %s: %v", path, err)
	}
	store, err := secrets.Select(kind, keyringService, dir)
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}

	block := accountBlock(alias, *provider, *email, *access, *imapAddr, *smtpAddr, *username, "", "", false)
	if err := config.AddAccountBlock(path, alias, block); err != nil {
		return failf(env, "add the account block: %v", err)
	}
	value, err := json.Marshal(map[string]any{
		"v": 1, "kind": "password", "username": loginName(*username, *email), "password": password,
	})
	if err != nil {
		rollback(path, alias, store, env)
		return failf(env, "encode the secret: %v", err)
	}
	if err := store.Set(alias, string(value)); err != nil {
		rollback(path, alias, store, env)
		return failf(env, "save the secret in the %s store: %v", kind, err)
	}
	printf(env, "account %q written to %s, secret in the %s store", alias, path, kind)

	// The live test comes last. A failed login leaves nothing behind
	// (B5).
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	report, err := env.Login(ctx, alias)
	if err != nil {
		rollback(path, alias, store, env)
		return failf(env, "login as %s failed, so account %q was removed again: %v", loginName(*username, *email), alias, err)
	}
	_, _ = fmt.Fprint(env.Stdout, report)
	printf(env, "account %q is ready. Try it from your MCP client, or run: mailbag-mcp account test %s", alias, alias)
	return exitOK
}

// accountAddOutlook is the outlook branch of accountAdd (T6.3, DS6.3,
// DS6.5, DS6.8, §3.5, §3.6, B5, B11): no password prompt, an OAuth
// sign-in in its place. The order still holds B5's rule: the alias
// check already ran in accountAdd, the tenant is validated (I-S6.2)
// and the alias-free check runs before the sign-in ever starts a
// browser or a request to Microsoft.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func accountAddOutlook(alias, email, tenantFlag string, paste bool, access, username string, env Env) int {
	if email == "" {
		return usageErrf(env, "account add --provider outlook needs --email")
	}
	if !config.ValidEmail(email) {
		return usageErrf(env, "--email must be one bare address, with no display name")
	}
	if access != "read" && access != "draft" && access != "send" {
		return usageErrf(env, "unknown access level %q; use read, draft or send", access)
	}

	// DS6.8: an explicit --tenant always wins; its absence picks the
	// tenant from the email domain. Either way ValidTenant runs before
	// any prompt or request (I-S6.2), so an injected path or query
	// segment never reaches an endpoint.
	tenant := tenantFlag
	if tenant == "" {
		tenant = oauthpkg.DefaultTenant(email)
	}
	if err := oauthpkg.ValidTenant(tenant); err != nil {
		return usageErrf(env, "--tenant: %v", err)
	}

	fields := map[string]*string{"--email": &email, "--username": &username}
	for name, value := range fields {
		clean, err := guard.ValidateField(*value)
		if err != nil || strings.ContainsAny(clean, "\"\\") {
			return usageErrf(env, "%s holds a character that accounts.toml cannot carry", name)
		}
		*value = clean
	}

	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	taken, err := aliasTaken(path, alias)
	if err != nil {
		return failf(env, "read %s: %v", path, err)
	}
	if taken != "" {
		// B5: the alias check comes before the sign-in, so a duplicate
		// never costs a trip through the browser.
		return failf(env, "account %q exists already; remove it first with `mailbag-mcp account remove %s`", taken, taken)
	}

	kind, err := storeKind(path, env)
	if err != nil {
		return failf(env, "%v", err)
	}

	dir := filepath.Dir(path)
	store, err := secrets.Select(kind, keyringService, dir)
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}

	clientID, err := microsoftClientID(store)
	if err != nil {
		return failf(env, "%v", err)
	}

	refreshToken, err := signInMicrosoft(context.Background(), env, clientID, tenant, email, paste)
	if err != nil {
		if errors.Is(err, errNotTerminal) {
			return usageErrf(env, "%v", err)
		}
		return failf(env, "sign in with Microsoft: %v", err)
	}
	guard.RegisterSecret(refreshToken)

	// L1 (S6-close-judge): the file is created only once the sign-in
	// has succeeded, the same rule the imap path keeps by prompting
	// for the password before ensureFile runs. secrets.Select and
	// microsoftClientID above need only the directory, not the file,
	// so an abandoned or failed sign-in leaves no accounts.toml behind
	// and never fixes the store kind for a later add (B3).
	if err := ensureFile(path, kind); err != nil {
		return failf(env, "write %s: %v", path, err)
	}

	imapHost, smtpHost := oauthpkg.Hosts(tenant)
	block := accountBlock(alias, "outlook", email, access, imapHost, smtpHost, username, tenant, "", false)
	if err := config.AddAccountBlock(path, alias, block); err != nil {
		return failf(env, "add the account block: %v", err)
	}
	value, err := json.Marshal(map[string]any{"v": 1, "kind": "oauth", "refresh_token": refreshToken})
	if err != nil {
		rollback(path, alias, store, env)
		return failf(env, "encode the secret: %v", err)
	}
	if err := store.Set(alias, string(value)); err != nil {
		rollback(path, alias, store, env)
		return failf(env, "save the secret in the %s store: %v", kind, err)
	}
	printf(env, "account %q written to %s, secret in the %s store", alias, path, kind)

	// The live test comes last. A failed login leaves nothing behind
	// (B5).
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	report, err := env.Login(ctx, alias)
	if err != nil {
		rollback(path, alias, store, env)
		return failf(env, "login as %s failed, so account %q was removed again: %v", loginName(username, email), alias, err)
	}
	_, _ = fmt.Fprint(env.Stdout, report)
	printf(env, "account %q is ready. Try it from your MCP client, or run: mailbag-mcp account test %s", alias, alias)
	return exitOK
}

// accountAddGmail is the gmail branch of accountAdd (DS7.7, DS7.8,
// DS78.8): it mirrors accountAddOutlook with no tenant and with the
// Google config. The order holds B5's rule: the alias-free check runs
// before the sign-in starts a browser or a request to Google, and the
// file is created only after the sign-in succeeded (L1).
//
// The block it writes holds provider, email and access, and no imap or
// smtp key. The login test is the common login path (G10), whose first
// call is labels.list. A failed login rolls the account back (B5). For
// [gmail.ErrAPIDisabled] and [gmail.ErrScope] the text is the fixed
// reason of doctor and never the error text, so no project number and
// no server text reach the terminal (DS7.7, IS7.5).
//
// arch: DS7.7, DS7.8, DS78.6, DS78.8, DS78.9, IS7.5, B5
func accountAddGmail(alias, email string, paste bool, access string, env Env) int {
	if email == "" {
		return usageErrf(env, "account add --provider gmail needs --email")
	}
	if !config.ValidEmail(email) {
		return usageErrf(env, "--email must be one bare address, with no display name")
	}
	if access != "read" && access != "draft" && access != "send" {
		return usageErrf(env, "unknown access level %q; use read, draft or send", access)
	}
	clean, err := guard.ValidateField(email)
	if err != nil || strings.ContainsAny(clean, "\"\\") {
		return usageErrf(env, "--email holds a character that accounts.toml cannot carry")
	}
	email = clean

	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	taken, err := aliasTaken(path, alias)
	if err != nil {
		return failf(env, "read %s: %v", path, err)
	}
	if taken != "" {
		return failf(env, "account %q exists already; remove it first with `mailbag-mcp account remove %s`", taken, taken)
	}

	kind, err := storeKind(path, env)
	if err != nil {
		return failf(env, "%v", err)
	}
	store, err := secrets.Select(kind, keyringService, filepath.Dir(path))
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}
	client, err := googleClientFromStore(store)
	if err != nil {
		return failf(env, "%v", err)
	}

	refreshToken, err := signInGoogle(context.Background(), env, client, email, paste)
	if err != nil {
		if errors.Is(err, errNotTerminal) {
			return usageErrf(env, "%v", err)
		}
		return failf(env, "sign in with Google: %v", err)
	}
	guard.RegisterSecret(refreshToken)

	if err := ensureFile(path, kind); err != nil {
		return failf(env, "write %s: %v", path, err)
	}
	block := accountBlock(alias, "gmail", email, access, "", "", "", "", "", false)
	if err := config.AddAccountBlock(path, alias, block); err != nil {
		return failf(env, "add the account block: %v", err)
	}
	value, err := json.Marshal(map[string]any{"v": 1, "kind": "oauth", "refresh_token": refreshToken})
	if err != nil {
		rollback(path, alias, store, env)
		return failf(env, "encode the secret: %v", err)
	}
	if err := store.Set(alias, string(value)); err != nil {
		rollback(path, alias, store, env)
		return failf(env, "save the secret in the %s store: %v", kind, err)
	}
	printf(env, "account %q written to %s, secret in the %s store", alias, path, kind)

	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	report, err := env.Login(ctx, alias)
	if err != nil {
		rollback(path, alias, store, env)
		if reason, ok := gmailFixedReason(err); ok {
			return failf(env, "login as %s failed, so account %q was removed again: %s", email, alias, reason)
		}
		return failf(env, "login as %s failed, so account %q was removed again: %v", email, alias, err)
	}
	_, _ = fmt.Fprint(env.Stdout, report)
	printf(env, "account %q is ready. Try it from your MCP client, or run: mailbag-mcp account test %s", alias, alias)
	return exitOK
}

// gmailFixedReason gives the fixed text that "account add" prints after
// the rollback for [gmail.ErrAPIDisabled] and [gmail.ErrScope], and
// false for any other error. The reason is the doctor reason of
// DS78.4. The fix differs from the doctor hint for ErrScope, because
// after the rollback there is no account that --reauth can sign in
// again (DS7.7, IS7.5).
//
// arch: DS7.7, DS78.4, DS78.9, IS7.5, B5
func gmailFixedReason(err error) (string, bool) {
	switch {
	case errors.Is(err, gmail.ErrAPIDisabled):
		return gmailAPIOffReason + "; " + gmailAPIOffHint + ", then add the account again", true
	case errors.Is(err, gmail.ErrScope):
		return gmailScopeReason + "; add the account again and allow every Gmail permission on the Google consent screen", true
	}
	return "", false
}

// jmapTokenPrompt is the prompt of --bearer (DS8.6).
const jmapTokenPrompt = "API token: " //nolint:gosec // G101: this is a prompt text, not a credential

// accountAddJMAP is the jmap branch of accountAdd (DS8.6, DS78.6,
// DS78.8). It keeps the B5 order of the imap branch: check the flags
// and the session URL, check that the alias is free, only then ask for
// the secret, save, test the login, and on a failed login remove both
// the account block and the secret.
//
// The session URL is --session-url, else the default of
// [config.JMAPSessionURL] (G11). The block always holds the URL that
// the login used, so the file shows it. With --bearer the prompt asks
// for an API token, stored as kind "token" (a Bearer header); without
// it the prompt asks for a password, stored as kind "password" (HTTP
// Basic, F5). --private-host writes private_host = true, and the
// command tells the person what the key allows (G11). The login test
// is the common login path, whose first calls are the session and
// Mailbox/get (DS78.8 step 4).
//
// arch: DS8.6, DS78.4, DS78.6, DS78.8, IS8.1, B5, G11
func accountAddJMAP(alias, email, sessionURL string, bearer, privateHost bool, access, username string, env Env) int {
	if email == "" {
		return usageErrf(env, "account add --provider jmap needs --email")
	}
	if !config.ValidEmail(email) {
		return usageErrf(env, "--email must be one bare address, with no display name")
	}
	if access != "read" && access != "draft" && access != "send" {
		return usageErrf(env, "unknown access level %q; use read, draft or send", access)
	}
	fields := map[string]*string{"--email": &email, "--session-url": &sessionURL, "--username": &username}
	for name, value := range fields {
		clean, err := guard.ValidateField(*value)
		if err != nil || strings.ContainsAny(clean, "\"\\") {
			return usageErrf(env, "%s holds a character that accounts.toml cannot carry", name)
		}
		*value = clean
	}

	defaulted := sessionURL == ""
	resolved, err := config.JMAPSessionURL(config.Account{Provider: "jmap", Email: email, SessionURL: sessionURL})
	switch {
	case errors.Is(err, config.ErrSessionURLNotHTTPS):
		return usageErrf(env, "--session-url must be an https URL with a host name")
	case err != nil:
		return usageErrf(env, "the domain of --email gives no session URL; give --session-url")
	}
	u, err := url.Parse(resolved)
	if err != nil {
		return usageErrf(env, "--session-url must be an https URL with a host name")
	}
	host := u.Hostname()

	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	taken, err := aliasTaken(path, alias)
	if err != nil {
		return failf(env, "read %s: %v", path, err)
	}
	if taken != "" {
		// B5: the alias check comes before the prompt, so a duplicate
		// never costs a typed secret.
		return failf(env, "account %q exists already; remove it first with `mailbag-mcp account remove %s`", taken, taken)
	}

	kind, err := storeKind(path, env)
	if err != nil {
		return failf(env, "%v", err)
	}

	prompt, what := fmt.Sprintf("password for %s (the typing stays hidden): ", loginName(username, email)), "password"
	if bearer {
		prompt, what = jmapTokenPrompt, "API token"
	}
	secret, err := env.ReadSecret(prompt)
	if err != nil {
		if errors.Is(err, errNotTerminal) {
			return usageErrf(env, "%v", err)
		}
		return failf(env, "read the %s: %v", what, err)
	}
	if secret == "" {
		return failf(env, "the %s is empty; nothing was written", what)
	}
	// B6: from here on, any error text that repeats the value prints
	// "<redacted>" instead. failf redacts every line it writes.
	guard.RegisterSecret(secret)

	if err := ensureFile(path, kind); err != nil {
		return failf(env, "write %s: %v", path, err)
	}
	store, err := secrets.Select(kind, keyringService, filepath.Dir(path))
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}

	block := accountBlock(alias, "jmap", email, access, "", "", username, "", resolved, privateHost)
	if err := config.AddAccountBlock(path, alias, block); err != nil {
		return failf(env, "add the account block: %v", err)
	}
	stored := map[string]any{"v": 1, "kind": "password", "username": loginName(username, email), "password": secret}
	if bearer {
		stored = map[string]any{"v": 1, "kind": "token", "token": secret}
	}
	value, err := json.Marshal(stored)
	if err != nil {
		rollback(path, alias, store, env)
		return failf(env, "encode the secret: %v", err)
	}
	if err := store.Set(alias, string(value)); err != nil {
		rollback(path, alias, store, env)
		return failf(env, "save the secret in the %s store: %v", kind, err)
	}
	printf(env, "account %q written to %s, secret in the %s store", alias, path, kind)
	if defaulted {
		printf(env, "session URL %s (the default for --email; give --session-url when the server has another one)", resolved)
	}
	if privateHost {
		printf(env, "private_host = true: account %q may reach %s at a private network address; every other host must still be public, and loopback stays refused", alias, host)
	}

	// The live test comes last: the session, then Mailbox/get. A failed
	// login leaves nothing behind (B5).
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	report, err := env.Login(ctx, alias)
	if err != nil {
		rollback(path, alias, store, env)
		return failf(env, "login as %s at %s failed, so account %q was removed again: %v", loginName(username, email), host, alias, err)
	}
	_, _ = fmt.Fprint(env.Stdout, report)
	printf(env, "account %q is ready. Try it from your MCP client, or run: mailbag-mcp account test %s", alias, alias)
	return exitOK
}

// accountReauth gets a new sign-in for an existing outlook or gmail
// account and replaces its secret only (DS6.5, DS7.8): the account
// block (alias, provider, email, tenant, hosts) stays exactly as
// accountAddOutlook or accountAddGmail wrote it. It is the CLI side of
// the reauth text that the TokenSource of the account returns after
// B8's retry fails (DS6.9).
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, DS7.8, §3.5, §3.6, B5, B11
func accountReauth(alias string, paste bool, env Env) int {
	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return failf(env, "no account %q; accounts.toml does not exist yet", alias)
		}
		return failf(env, "read %s: %v", path, err)
	}
	acct, ok := cfg.Account(alias)
	if !ok {
		return failf(env, "no account %q in %s", alias, path)
	}
	if acct.Provider != "outlook" && acct.Provider != "gmail" {
		return failf(env, "account %q uses provider %q; --reauth works for outlook and gmail accounts", alias, acct.Provider)
	}

	kind := cfg.Secrets()
	store, err := secrets.Select(kind, keyringService, filepath.Dir(path))
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}

	var refreshToken, who string
	if acct.Provider == "gmail" {
		who = "Google"
		client, cerr := googleClientFromStore(store)
		if cerr != nil {
			return failf(env, "%v", cerr)
		}
		refreshToken, err = signInGoogle(context.Background(), env, client, acct.Email, paste)
	} else {
		who = "Microsoft"
		clientID, cerr := microsoftClientID(store)
		if cerr != nil {
			return failf(env, "%v", cerr)
		}
		refreshToken, err = signInMicrosoft(context.Background(), env, clientID, acct.Tenant, acct.Email, paste)
	}
	if err != nil {
		if errors.Is(err, errNotTerminal) {
			return usageErrf(env, "%v", err)
		}
		return failf(env, "sign in with %s: %v", who, err)
	}
	guard.RegisterSecret(refreshToken)

	value, err := json.Marshal(map[string]any{"v": 1, "kind": "oauth", "refresh_token": refreshToken})
	if err != nil {
		return failf(env, "encode the secret: %v", err)
	}
	if err := store.Set(alias, string(value)); err != nil {
		return failf(env, "save the secret in the %s store: %v", kind, err)
	}
	printf(env, "account %q signed in again; the secret was replaced", alias)
	return exitOK
}

// accountList prints one line for each account.
//
// arch: T4.6, §3.5, §3.3
func accountList(args []string, env Env) int {
	if len(args) > 0 {
		return usageErrf(env, "account list takes no argument")
	}
	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	cfg, err := config.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		printf(env, "no account yet. Add one with:")
		printf(env, "  mailbag-mcp account add work --provider imap --email you@example.com --imap mail.example.com:993 --smtp mail.example.com:465")
		return exitOK
	}
	if err != nil {
		return failf(env, "read %s: %v", path, err)
	}
	aliases := cfg.Aliases()
	if len(aliases) == 0 {
		printf(env, "%s holds no account", path)
		return exitOK
	}
	printf(env, "%-16s %-8s %-8s %s", "ALIAS", "PROVIDER", "ACCESS", "EMAIL")
	for _, alias := range aliases {
		a, _ := cfg.Account(alias)
		printf(env, "%-16s %-8s %-8s %s", alias, a.Provider, a.Access, a.Email)
	}
	printf(env, "secrets: %s", cfg.Secrets())
	return exitOK
}

// accountRemove cuts the account block and deletes the secret.
//
// arch: T4.6, §3.5, §3.3, B18
func accountRemove(args []string, env Env) int {
	if len(args) != 1 {
		return usageErrf(env, "account remove needs exactly one alias")
	}
	alias := args[0]
	if err := guard.ValidateAlias(alias); err != nil {
		return usageErrf(env, "alias %q: use letters, digits, - and _ only", alias)
	}
	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	// The lenient decode finds the alias and the store kind, so a
	// broken account, or a bad block of another account, can still be
	// removed. The strict load would refuse the whole file.
	aliases, kind, err := config.PeekFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return failf(env, "read %s: %v", path, err)
	}
	if _, ok := aliases[alias]; !ok {
		return failf(env, "no account %q in %s", alias, path)
	}
	// Open the store before the cut, so a bad secrets value stops the
	// command while the file is still unchanged.
	store, err := secrets.Select(kind, keyringService, filepath.Dir(path))
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}
	if err := config.RemoveAccountBlock(path, alias); err != nil {
		return failf(env, "remove the account block: %v; edit %s by hand", err, path)
	}
	if err := store.Delete(alias); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		return failf(env, "account %q left %s, but its secret stayed in the %s store: %v", alias, path, kind, err)
	}
	printf(env, "account %q removed", alias)
	return exitOK
}

// accountTest connects, lists the folders and runs one search. It
// writes nothing to the mailbox. It is the live smoke test of §3.5.
//
// arch: T4.6, §3.5, §8 S4
func accountTest(args []string, env Env) int {
	if len(args) != 1 {
		return usageErrf(env, "account test needs exactly one alias")
	}
	alias := args[0]
	if err := guard.ValidateAlias(alias); err != nil {
		return usageErrf(env, "alias %q: use letters, digits, - and _ only", alias)
	}
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	report, err := env.Login(ctx, alias)
	if err != nil {
		return failf(env, "account %q: %v", alias, err)
	}
	_, _ = fmt.Fprint(env.Stdout, report)
	return exitOK
}

// liveLogin is the real test: open the provider, list the folders,
// run one search of the newest messages and print the capability
// report of T91. Every call is a read.
//
// arch: T4.6, §3.5, §3.7, §8 S4, DR1G.11, DR1G.18.9
func liveLogin(ctx context.Context, alias string) (string, error) {
	lines, err := loginReport(ctx, alias)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// loginProvider is the part of [tools.Reader] loginReport needs to
// list folders and run the smoke-test search. A test gives a fake
// that holds only these two methods, and reportLines still performs
// the same [tools.CapsReporter] type assertion production code does,
// because that assertion checks the fake's concrete type, not this
// interface (DR1G.11).
type loginProvider interface {
	Folders(ctx context.Context) ([]mail.Folder, error)
	Search(ctx context.Context, q mail.Query) (mail.Page, error)
}

// loginReport opens alias and builds every line of its "account test"
// / "doctor" report. It splits from the old liveLogin so account_test.go
// can check the report text without printing it (DR1G.18.9).
//
// arch: T4.6, §3.5, §3.7, §8 S4, DR1G.11, DR1G.18.9
func loginReport(ctx context.Context, alias string) ([]string, error) {
	f := tools.NewFactory(nil)
	defer f.Close()

	p, acct, err := f.Open(ctx, alias)
	if err != nil {
		return nil, err
	}
	return reportLines(ctx, p, acct)
}

// reportLines is loginReport's body, taking an already-open provider
// so a test can give a fake in place of a live server. The login line
// names the host of [loginTarget].
//
// arch: T4.6, §3.5, §3.7, §8 S4, DR1G.11, DR1G.18.9, DS78.4
func reportLines(ctx context.Context, p loginProvider, acct config.Account) ([]string, error) {
	target, err := loginTarget(acct)
	if err != nil {
		return nil, err
	}
	folders, err := p.Folders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the folders: %w", err)
	}
	page, err := p.Search(ctx, mail.Query{Limit: 5})
	if err != nil {
		return nil, fmt.Errorf("search the inbox: %w", err)
	}

	lines := []string{
		fmt.Sprintf("login as %s at %s: ok", acct.Username, target),
		fmt.Sprintf("%d folders:", len(folders)),
	}
	for _, fl := range folders {
		// The folder name comes from the server. Strip the invisible
		// characters before a terminal sees it (§3.15).
		name, _ := guard.StripInvisible(fl.Name)
		role := fl.Role
		if role == "" {
			role = "-"
		}
		lines = append(lines, fmt.Sprintf("  %-24s role=%-8s total=%-6d unread=%d", name, role, fl.Total, fl.Unread))
	}
	lines = append(lines, fmt.Sprintf("search of the newest messages in the inbox: %d found", len(page.Messages)))
	lines = append(lines, capabilityLines(ctx, p, acct)...)
	return lines, nil
}

// gmailTarget is the host the login line names for a gmail account:
// the Gmail REST API, because a gmail account has no IMAP address
// (DS78.4).
const gmailTarget = "gmail.googleapis.com"

// loginTarget gives the <target> of the "login as <user> at <target>"
// line (DS78.4): gmailTarget for gmail, the host of the session URL
// for jmap, and acct.IMAP for every other provider. The jmap session
// URL comes from [config.JMAPSessionURL], the one rule for its
// default (DS78.11 G11). The host has no port.
//
// arch: DS78.4, DS78.11
func loginTarget(acct config.Account) (string, error) {
	switch acct.Provider {
	case "gmail":
		return gmailTarget, nil
	case "jmap":
		s, err := config.JMAPSessionURL(acct)
		if err != nil {
			return "", fmt.Errorf("the JMAP session URL: %w", err)
		}
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("the JMAP session URL: %w", err)
		}
		return u.Hostname(), nil
	default:
		return acct.IMAP, nil
	}
}

// capabilityLines builds the capability-report lines of T91
// (DR1G.11), or the one line a provider without [tools.CapsReporter]
// gives. For caps.Kind "imap" or "" it prints one line per IMAP field
// plus the save_sent advice. For another kind it prints each of
// caps.Lines through [serverText], because a line can hold words from
// the server, then the fixed Sent advice of that kind (DS78.4).
//
// cr.Caps leaves caps.SaveSent empty: [imap.Provider.Caps] carries no
// account config, only the live login does (DR1G.18.7). This is the
// one place that holds both the capability report and acct, so it
// fills caps.SaveSent from [imap.SaveSentAdvice] before printing,
// instead of printing a second, disconnected value that happens to
// agree (IR1G.15). The gmail and jmap advice is fixed text, and this
// function fills it in the same field.
//
// arch: DR1G.11, DR1G.18.7, DR1G.18.8, DR1G.18.9, IR1G.15, DS78.4
func capabilityLines(ctx context.Context, p loginProvider, acct config.Account) []string {
	cr, ok := p.(tools.CapsReporter)
	if !ok {
		return []string{"capabilities: not reported by this provider"}
	}
	caps, err := cr.Caps(ctx)
	if err != nil {
		return []string{"capabilities: " + serverText(err.Error())}
	}
	switch caps.Kind {
	case "", "imap":
		caps.SaveSent = imap.SaveSentAdvice(acct.SaveSent, acct.SMTP)
		return []string{
			fmt.Sprintf("UIDPLUS: %s", yesNo(caps.UIDPlus)),
			fmt.Sprintf("MOVE: %s", yesNo(caps.Move)),
			fmt.Sprintf("CONDSTORE: %s", yesNo(caps.CondStore)),
			fmt.Sprintf("KEYWORDS: %s", yesNo(caps.Keywords)),
			caps.SaveSent,
		}
	case "gmail":
		caps.SaveSent = "server keeps Sent"
	case "jmap":
		caps.SaveSent = "Sent through onSuccessUpdateEmail"
	default:
		// DS78.4 gives no Sent advice for another kind. Only this
		// function fills SaveSent (IR1G.15), so a value the provider
		// set is not printed.
		caps.SaveSent = ""
	}
	lines := make([]string, 0, len(caps.Lines)+1)
	for _, l := range caps.Lines {
		lines = append(lines, serverText(l))
	}
	if caps.SaveSent != "" {
		lines = append(lines, caps.SaveSent)
	}
	return lines
}

// yesNo prints a bool the way every capability line does.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// rollback undoes a half-written account. It reports what it could
// not undo, because a leftover block or secret must never stay quiet.
//
// arch: T4.6, §3.5, B5
func rollback(path, alias string, store secrets.Store, env Env) {
	if err := config.RemoveAccountBlock(path, alias); err != nil {
		_, _ = fmt.Fprintf(env.Stderr, "could not remove the account block of %q from %s: %s\n", alias, path, guard.Redact(err.Error()))
	}
	if err := store.Delete(alias); err != nil && !errors.Is(err, secrets.ErrNotFound) {
		_, _ = fmt.Fprintf(env.Stderr, "could not remove the secret of %q: %s\n", alias, guard.Redact(err.Error()))
	}
}

// accountBlock builds the raw TOML text of one account. The CLI never
// runs accounts.toml through an encoder, because that deletes the
// comments a person wrote (B18). Each value passed guard.ValidateField
// and holds no quote or backslash, so the text below stays valid TOML.
//
// tenant is empty for every provider but outlook (DS6.3): an outlook
// account writes the tenant it signed in against, so a later dial
// rebuilds the same token endpoint (I-S6.2) and imapAddr/smtpAddr for
// outlook are the DS6.3 hosts from oauth.Hosts, not a flag the person
// typed. imapAddr and smtpAddr are empty for gmail and jmap, and the
// block then has no imap and no smtp key (DS7.8). sessionURL is empty
// and privateHost is false for every provider but jmap (DS8.6).
//
// arch: T4.6, T6.3, §3.3, DS6.3, DS6.5, DS7.8, DS8.6, B18
func accountBlock(alias, provider, email, access, imapAddr, smtpAddr, username, tenant, sessionURL string, privateHost bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[accounts.%s]\n", alias)
	fmt.Fprintf(&b, "provider = %q\n", provider)
	fmt.Fprintf(&b, "email    = %q\n", email)
	fmt.Fprintf(&b, "access   = %q\n", access)
	if imapAddr != "" {
		fmt.Fprintf(&b, "imap     = %q\n", imapAddr)
	}
	if smtpAddr != "" {
		fmt.Fprintf(&b, "smtp     = %q\n", smtpAddr)
	}
	if tenant != "" {
		fmt.Fprintf(&b, "tenant   = %q\n", tenant)
	}
	if sessionURL != "" {
		fmt.Fprintf(&b, "session_url = %q\n", sessionURL)
	}
	if privateHost {
		b.WriteString("private_host = true\n")
	}
	if username != "" && username != email {
		fmt.Fprintf(&b, "username = %q\n", username)
	}
	return b.String()
}

// loginName gives the name the server sees: --username when it was
// given, the address when it was not (§3.3, §5.4).
func loginName(username, email string) string {
	if username == "" {
		return email
	}
	return username
}

// aliasTaken gives the alias of accounts.toml that equals alias under
// case folding, or "" when there is none. On a file system that
// ignores case (APFS, NTFS) "Work" and "work" are one secret file, so
// a new alias must differ from each old one in more than case. A file
// that is not there yet holds nothing.
//
// arch: B5, B17, R16-L19
func aliasTaken(path, alias string) (string, error) {
	cfg, err := config.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, have := range cfg.Aliases() {
		if strings.EqualFold(have, alias) {
			return have, nil
		}
	}
	return "", nil
}

// storeKind decides which secret store this run uses (§3.4).
//
// MAILBAG_SECRETS wins. After that comes the kind that accounts.toml
// records. Only a first "account add", with no accounts.toml yet,
// chooses: it reads one key that does not exist from the keyring, and
// asks the person before it writes down the file store. The server
// never makes this choice again on its own (trap B3).
//
// arch: T4.6, §3.4, B3
func storeKind(path string, env Env) (string, error) {
	if k := os.Getenv("MAILBAG_SECRETS"); k != "" {
		if k != secrets.KindKeyring && k != secrets.KindFile {
			return "", fmt.Errorf("MAILBAG_SECRETS is %q; use keyring or file", k)
		}
		// The server reads the kind that accounts.toml records, and
		// nothing else (trap B3). A different kind here writes the
		// secret where the server will not look for it.
		if recorded, err := recordedKind(path); err == nil && recorded != k {
			_, _ = fmt.Fprintf(env.Stderr, "warning: MAILBAG_SECRETS is %q but %s records %q; the server will read the %q store\n",
				k, path, recorded, recorded)
		}
		return k, nil
	}
	if _, err := os.Stat(path); err == nil {
		return recordedKind(path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	probe := secrets.NewKeyringStore(keyringService)
	_, err := probe.Get(keyringProbeKey)
	if errors.Is(err, secrets.ErrNotFound) {
		return secrets.KindKeyring, nil // the keyring answered, so it works
	}
	_, _ = fmt.Fprintf(env.Stderr, "the system keyring did not answer: %s\n", guard.Redact(fmt.Sprint(err)))
	_, _ = fmt.Fprintf(env.Stderr, "the other store keeps the password in a file at %s, readable by your user alone.\n", filepath.Dir(path))
	yes, cerr := env.Confirm("store the password in a file instead? [y/N] ")
	if cerr != nil {
		return "", fmt.Errorf("the keyring did not answer and the question could not be asked: %w", cerr)
	}
	if !yes {
		return "", errors.New("nothing was written; open your keyring and run the command again")
	}
	return secrets.KindFile, nil
}

// recordedKind reads the secret store kind that accounts.toml holds.
func recordedKind(path string) (string, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return "", err
	}
	return cfg.Secrets(), nil
}

// ensureFile creates the config directory and accounts.toml when they
// are not there yet, and writes the store kind at the top, before the
// first account table (§3.3, §3.4). An existing file stays as it is:
// its comments belong to the person who wrote them (B18).
func ensureFile(path, kind string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	header := fmt.Sprintf(`# mailbag-mcp accounts. Edit this file by hand when you want;
# "account add" and "account remove" keep your comments.
secrets = %q
`, kind)
	return os.WriteFile(path, []byte(header), 0o600)
}
