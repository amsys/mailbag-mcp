// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The "oauth set" command: it writes the OAuth client of one provider
// to the secret store (§3.4), and the Microsoft and Google sign-in
// flows that "account add" uses (§3.6, DS7.8).

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// microsoftClientKey is the secret-store key of §3.4 that holds the
// Microsoft public client id: `oauth.microsoft` -> {"client_id":".."}.
// internal/tools/provider.go reads the same key by the same name; the
// two packages share no code, only the string, because the server
// package must not depend on the CLI (§3.4).
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
const microsoftClientKey = "oauth.microsoft"

// googleClientKey is the secret-store key of §3.4 that holds the
// Google OAuth client that the person supplies: `oauth.google` -> the
// JSON of [oauthpkg.GoogleClient]. The server side reads the same key
// by the same name (internal/tools/provider.go, DS7.2).
//
// arch: DS7.8, DS7.2, IS7.5
const googleClientKey = "oauth.google"

// googlePasteRedirectURL is the redirect of the Google --paste flow
// (DS7.2): no listener is on this address, so the browser shows
// "cannot connect" and the person pastes the URL from the address bar.
// It is the same text as googlePasteRedirect in internal/oauth, which
// that package does not export.
//
// arch: DS7.2, DS7.8
const googlePasteRedirectURL = "http://127.0.0.1:17777/callback"

// pasteRedirectURL is the fixed, already-registered redirect URI that
// the --paste flow uses (U4, DS6.6): the owner's Azure app
// registration carries this URI with no port and no listener, so
// --paste works with the registration as it stands, unlike the
// loopback flow which needs `http://localhost` added.
const pasteRedirectURL = "https://localhost"

// oauthCmd runs one "oauth ..." subcommand.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func oauthCmd(args []string, env Env) int {
	if len(args) == 0 {
		return usageErrf(env, "oauth needs a subcommand: set")
	}
	switch args[0] {
	case "set":
		return oauthSet(args[1:], env)
	default:
		return usageErrf(env, "unknown oauth subcommand %q", args[0])
	}
}

// oauthSet runs "oauth set <provider> ...". The providers are
// microsoft and google.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, DS7.8, §3.5, §3.6, B5, B11
func oauthSet(args []string, env Env) int {
	if len(args) == 0 {
		return usageErrf(env, "oauth set needs a provider: microsoft or google")
	}
	switch args[0] {
	case "microsoft":
		return oauthSetMicrosoft(args[1:], env)
	case "google":
		return oauthSetGoogle(args[1:], env)
	default:
		return usageErrf(env, "unknown oauth provider %q; the providers are microsoft and google", args[0])
	}
}

// oauthSetMicrosoft writes the Microsoft public client id that every
// outlook account on this machine shares (§3.4's table). The client
// id is public, not a secret (DS6.4), but it lives in the same store
// as the account secrets so a fresh machine needs only one store to
// set up.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func oauthSetMicrosoft(args []string, env Env) int {
	set := flag.NewFlagSet("oauth set microsoft", flag.ContinueOnError)
	set.SetOutput(env.Stderr)
	set.Usage = func() { _, _ = fmt.Fprint(env.Stderr, usageText) }
	clientID := set.String("client-id", "", "the Microsoft public client id (Azure app registration)")
	answersStdin := set.Bool("answers-stdin", false, oauthAnswersHelp)
	if err := set.Parse(args); err != nil {
		return exitUsage
	}
	if set.NArg() > 0 {
		return usageErrf(env, "unexpected argument %q", set.Arg(0))
	}
	if *clientID == "" {
		return usageErrf(env, "oauth set microsoft needs --client-id")
	}
	if *answersStdin {
		var err error
		if env, err = oauthAnswers(env); err != nil {
			return usageErrf(env, "%v", err)
		}
	}

	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	kind, err := storeKind(path, env)
	if errors.Is(err, errUnanswered) {
		return usageErrf(env, "%v", err)
	}
	if err != nil {
		return failf(env, "%v", err)
	}
	if err := ensureFile(path, kind); err != nil {
		return failf(env, "write %s: %v", path, err)
	}
	store, err := secrets.Select(kind, keyringService, filepath.Dir(path))
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}

	value, err := json.Marshal(map[string]any{"client_id": *clientID})
	if err != nil {
		return failf(env, "encode the client id: %v", err)
	}
	if err := store.Set(microsoftClientKey, string(value)); err != nil {
		return failf(env, "save the client id in the %s store: %v", kind, err)
	}
	printf(env, "Microsoft OAuth client id written to the %s store", kind)
	return exitOK
}

// oauthSetGoogle writes the Google OAuth client that every gmail
// account on this machine shares (D11.4, §3.4). It reads the
// client_secret.json from the Google Cloud console, keeps the client id
// and the client secret, and stores them at googleClientKey. The file
// is read and parsed before anything is written, so a bad file leaves
// the store and accounts.toml as they were.
//
// The client id, the secret and the project number go to the redactor
// before any later step can print text, and the command prints a fixed
// line only: no terminal line shows them (IS7.5).
//
// arch: DS7.8, DS78.6, DS7.2, IS7.5
func oauthSetGoogle(args []string, env Env) int {
	set := flag.NewFlagSet("oauth set google", flag.ContinueOnError)
	set.SetOutput(env.Stderr)
	set.Usage = func() { _, _ = fmt.Fprint(env.Stderr, usageText) }
	file := set.String("file", "", "the client_secret.json file from the Google Cloud console")
	answersStdin := set.Bool("answers-stdin", false, oauthAnswersHelp)
	if err := set.Parse(args); err != nil {
		return exitUsage
	}
	if set.NArg() > 0 {
		return usageErrf(env, "unexpected argument %q", set.Arg(0))
	}
	if *file == "" {
		return usageErrf(env, "oauth set google needs --file")
	}
	if *answersStdin {
		var err error
		if env, err = oauthAnswers(env); err != nil {
			return usageErrf(env, "%v", err)
		}
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		return failf(env, "read the Google client file: %v", err)
	}
	client, err := oauthpkg.ParseGoogleClientFile(data)
	if err != nil {
		return failf(env, "%v", err)
	}
	registerGoogleClient(client)

	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}
	kind, err := storeKind(path, env)
	if errors.Is(err, errUnanswered) {
		return usageErrf(env, "%v", err)
	}
	if err != nil {
		return failf(env, "%v", err)
	}
	if err := ensureFile(path, kind); err != nil {
		return failf(env, "write %s: %v", path, err)
	}
	store, err := secrets.Select(kind, keyringService, filepath.Dir(path))
	if err != nil {
		return failf(env, "open the %s secret store: %v", kind, err)
	}

	value, err := json.Marshal(client) //nolint:gosec // G117: the client secret goes to the secret store, never to a log or a file
	if err != nil {
		return failf(env, "encode the Google client: %v", err)
	}
	if err := store.Set(googleClientKey, string(value)); err != nil {
		return failf(env, "save the Google client in the %s store: %v", kind, err)
	}
	printf(env, "stored the google OAuth client")
	return exitOK
}

// oauthAnswersHelp is the help text of the --answers-stdin flag of
// "oauth set".
const oauthAnswersHelp = `read the answers from one JSON document on stdin: {"use_file_store": B}`

// oauthAnswers reads the --answers-stdin document of "oauth set" and
// gives an Env whose prompts read it (DS13.5, review M3). The command
// asks one question only: the file-store question of storeKind. So the
// document must not hold "secret"; the client file or the client id
// comes from the command line, not from stdin. The CLI reads no lines
// (B5). A bad document is an error before a file is written.
//
// arch: DS13.5, IS13.2, B5
func oauthAnswers(env Env) (Env, error) {
	doc, err := readAnswers(env.Stdin)
	if err != nil {
		return env, err
	}
	if doc.Secret != nil {
		return env, errors.New(`--answers-stdin: "oauth set" asks for no secret, so the document must not hold "secret"; nothing was written`)
	}
	env.ReadSecret = doc.readSecret
	env.Confirm = doc.confirm
	env.ReadLine = unansweredLine
	return env, nil
}

// registerGoogleClient gives the client id, the client secret and the
// project number of a Google client to [guard.RegisterSecret], so that
// [guard.Redact] removes them from each later error and log line
// (IS7.5). The project number is the part of the client id before the
// first "-" (DS7.2).
//
// arch: DS7.8, DS7.2, IS7.5
func registerGoogleClient(c oauthpkg.GoogleClient) {
	guard.RegisterSecret(c.ClientID)
	guard.RegisterSecret(c.ClientSecret)
	project, _, _ := strings.Cut(c.ClientID, "-")
	guard.RegisterSecret(project)
}

// googleClientFromStore reads the Google OAuth client that "oauth set
// google" wrote at googleClientKey. internal/tools/provider.go has the
// same reader for the server side; this copy exists for the reason
// microsoftClientID gives. The error texts are fixed and hold no byte
// of the stored value (IS7.5).
//
// arch: DS7.8, DS7.2, IS7.5
func googleClientFromStore(store secrets.Store) (oauthpkg.GoogleClient, error) {
	raw, err := store.Get(googleClientKey)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return oauthpkg.GoogleClient{}, errors.New(`no Google OAuth client is configured; run "mailbag-mcp oauth set google --file client_secret.json"`)
		}
		return oauthpkg.GoogleClient{}, err
	}
	var c oauthpkg.GoogleClient
	if err := json.Unmarshal([]byte(raw), &c); err != nil || c.ClientID == "" || c.ClientSecret == "" {
		return oauthpkg.GoogleClient{}, errors.New(`the stored Google OAuth client is not readable; run "mailbag-mcp oauth set google --file client_secret.json" again`)
	}
	return c, nil
}

// microsoftClientID reads the public client id that "oauth set
// microsoft" wrote (§3.4's table). internal/tools/provider.go has the
// same lookup for the server side of DS6.4; this copy exists because
// the CLI does not import internal/tools and must not (the tools
// package pulls in the IMAP pool and the mail provider, neither of
// which "account add" needs).
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func microsoftClientID(store secrets.Store) (string, error) {
	raw, err := store.Get(microsoftClientKey)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return "", errors.New(`no Microsoft OAuth client is configured; run "mailbag-mcp oauth set microsoft --client-id ID"`)
		}
		return "", err
	}
	var v struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil || v.ClientID == "" {
		return "", errors.New(`the stored Microsoft OAuth client id is not readable; run "mailbag-mcp oauth set microsoft --client-id ID" again`)
	}
	return v.ClientID, nil
}

// loopback is the subset of *oauthpkg.Loopback that signInMicrosoft
// calls. A test replaces newLoopback with a fake that implements this,
// so it can drive the L4 DualBound() warning (S6-close-judge) without
// depending on the test machine's real ::1 binding.
type loopback interface {
	Start() (int, error)
	DualBound() bool
	Wait(ctx context.Context) (string, error)
	Close()
}

// newLoopback builds the real loopback listener. Tests reassign it.
var newLoopback = func(state string, timeout time.Duration) loopback {
	return oauthpkg.NewLoopback(state, timeout)
}

// signInMicrosoft runs the authorization-code-with-PKCE flow of §3.6
// end to end for one Microsoft account and returns the refresh token
// from the exchange. paste selects --paste's read-the-pasted-URL flow
// over the loopback listener; either way the authorize URL is always
// printed to stderr (§3.6), and only the loopback path also tries to
// open a browser on it.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func signInMicrosoft(ctx context.Context, env Env, clientID, tenant, email string, paste bool) (string, error) {
	pkce := oauthpkg.NewPKCE()
	state, err := oauthpkg.NewState()
	if err != nil {
		return "", fmt.Errorf("oauth: generating the sign-in state: %w", err)
	}

	if paste {
		cfg, err := env.OAuthConfig(clientID, tenant, pasteRedirectURL)
		if err != nil {
			return "", err
		}
		authURL := oauthpkg.AuthCodeURL(cfg, state, pkce, oauthpkg.AuthCodeOptions(email)...)
		_, _ = fmt.Fprintf(env.Stderr, "open this URL in a browser to sign in:\n%s\n", authURL)
		redirect, err := env.ReadLine("paste the full redirect URL here: ")
		if err != nil {
			return "", err
		}
		code, err := oauthpkg.ParsePastedRedirect(redirect, state)
		if err != nil {
			return "", err
		}
		tok, err := oauthpkg.Exchange(ctx, cfg, code, pkce)
		if err != nil {
			return "", err
		}
		if err := oauthpkg.RequireRefreshToken(tok); err != nil {
			return "", err
		}
		return tok.RefreshToken, nil
	}

	lb := newLoopback(state, 0)
	port, err := lb.Start()
	if err != nil {
		return "", err
	}
	defer lb.Close()
	// L4 (S6-close-judge): Start() treats a failed ::1 bind as best
	// effort, so a busy ::1 port on this machine can leave Microsoft's
	// http://localhost:<port>/callback landing on a closed ::1 while
	// this listener answers only on 127.0.0.1. The sign-in still works
	// for most browsers (they fall back to 127.0.0.1 for "localhost"),
	// so this warns and continues rather than failing.
	if !lb.DualBound() {
		_, _ = fmt.Fprintf(env.Stderr, "warning: could not bind [::1] for the loopback callback (the port may be busy on ::1 already); if the sign-in does not come back, run again with --paste\n")
	}
	redirectURL := fmt.Sprintf("http://localhost:%d/callback", port)
	cfg, err := env.OAuthConfig(clientID, tenant, redirectURL)
	if err != nil {
		return "", err
	}
	authURL := oauthpkg.AuthCodeURL(cfg, state, pkce, oauthpkg.AuthCodeOptions(email)...)
	_, _ = fmt.Fprintf(env.Stderr, "opening your browser to sign in. If it does not open, use this URL:\n%s\n", authURL)
	if err := openBrowser(authURL); err != nil {
		_, _ = fmt.Fprintf(env.Stderr, "could not open the browser on its own; use the URL above\n")
	}
	code, err := lb.Wait(ctx)
	if err != nil {
		return "", err
	}
	tok, err := oauthpkg.Exchange(ctx, cfg, code, pkce)
	if err != nil {
		return "", err
	}
	if err := oauthpkg.RequireRefreshToken(tok); err != nil {
		return "", err
	}
	return tok.RefreshToken, nil
}

// signInGoogle runs the authorization-code-with-PKCE flow for one
// Google account and returns the refresh token from the exchange
// (DS7.2, DS7.8). It mirrors signInMicrosoft with the Google config:
// the loopback redirect is http://127.0.0.1:<port>/callback, because
// Google accepts any loopback port for a Desktop client, and the paste
// redirect is googlePasteRedirectURL. The authorize parameters
// access_type=offline and prompt=consent make Google give a refresh
// token (B10).
//
// It first gives the client id, the client secret and the project
// number to the redactor, so that no later error line shows them
// (IS7.5). The authorize URL holds the client id; it is printed as it
// is, because the person must open it.
//
// arch: DS7.2, DS7.8, DS78.8, IS7.5, B10
func signInGoogle(ctx context.Context, env Env, client oauthpkg.GoogleClient, email string, paste bool) (string, error) {
	registerGoogleClient(client)
	pkce := oauthpkg.NewPKCE()
	state, err := oauthpkg.NewState()
	if err != nil {
		return "", fmt.Errorf("oauth: generating the sign-in state: %w", err)
	}

	var cfg *oauth2.Config
	var code string
	if paste {
		cfg = env.GoogleOAuthConfig(client, googlePasteRedirectURL)
		authURL := oauthpkg.AuthCodeURL(cfg, state, pkce, oauthpkg.GoogleAuthCodeOptions(email)...)
		_, _ = fmt.Fprintf(env.Stderr, "open this URL in a browser to sign in:\n%s\n", authURL)
		_, _ = fmt.Fprintf(env.Stderr, "the browser then shows \"cannot connect\"; that is expected\n")
		redirect, err := env.ReadLine("paste the full address bar URL here: ")
		if err != nil {
			return "", err
		}
		if code, err = oauthpkg.ParsePastedRedirect(redirect, state); err != nil {
			return "", err
		}
	} else {
		lb := newLoopback(state, 0)
		port, err := lb.Start()
		if err != nil {
			return "", err
		}
		defer lb.Close()
		cfg = env.GoogleOAuthConfig(client, fmt.Sprintf("http://127.0.0.1:%d/callback", port))
		authURL := oauthpkg.AuthCodeURL(cfg, state, pkce, oauthpkg.GoogleAuthCodeOptions(email)...)
		_, _ = fmt.Fprintf(env.Stderr, "opening your browser to sign in. If it does not open, use this URL:\n%s\n", authURL)
		if err := openBrowser(authURL); err != nil {
			_, _ = fmt.Fprintf(env.Stderr, "could not open the browser on its own; use the URL above\n")
		}
		if code, err = lb.Wait(ctx); err != nil {
			return "", err
		}
	}
	tok, err := oauthpkg.Exchange(ctx, cfg, code, pkce)
	if err != nil {
		return "", err
	}
	if err := oauthpkg.RequireRefreshToken(tok); err != nil {
		return "", err
	}
	return tok.RefreshToken, nil
}

// openBrowser opens rawURL in the person's browser (§3.6: "Open the
// browser"). It never blocks on the browser process: Start returns as
// soon as the command is launched, and a browser that never appears
// is not this call's failure to report, because the authorize URL is
// always printed too.
//
// It is a var, not a func, so a test of the loopback path (L4,
// S6-close-judge) can replace it and never launch a real browser
// process.
var openBrowser = func(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL) //nolint:gosec // G204: the command is a fixed opener and the URL is one argument, with no shell
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL) //nolint:gosec // G204: the command is a fixed opener and the URL is one argument, with no shell
	default:
		cmd = exec.Command("xdg-open", rawURL) //nolint:gosec // G204: the command is a fixed opener and the URL is one argument, with no shell
	}
	return cmd.Start()
}
