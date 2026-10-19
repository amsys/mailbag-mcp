// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package cli holds the terminal commands of §3.5: "account
// add|list|remove|test". It is the one package that may write to
// os.Stdout (A1), because these commands run in a terminal and never
// inside serve mode, where stdout carries the JSON-RPC stream alone.
//
// No tool adds, removes or tests an account (D15). A secret reaches
// this program through a terminal prompt here, or through one strict
// JSON document on stdin with --answers-stdin, and nowhere else (B5,
// DS13.5).
//
// arch: T4.6, §3.5, §3.3, §3.4, §5.4, B5, B6, B17, B18, D15, A1, DS13.5
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"golang.org/x/oauth2"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// Exit codes of §3.5. A usage error prints a line that starts with
// "usage:" and names the four providers.
const (
	exitOK    = 0
	exitFail  = 1 // failure at run time
	exitUsage = 2 // wrong usage
)

// usageText is the one usage block. Its first line starts with
// "usage:" and names the four providers (§3.5).
const usageText = `usage: mailbag-mcp account add <alias> --provider imap|outlook|gmail|jmap --email E --imap H:P --smtp H:P [--username U] [--access read|draft|send]
       mailbag-mcp account add <alias> --provider outlook --email E [--tenant T] [--paste]
       mailbag-mcp account add <alias> --provider gmail --email E [--paste]
       mailbag-mcp account add <alias> --provider jmap --email E [--session-url U] [--bearer] [--private-host]
       mailbag-mcp account add <alias> --reauth [--paste]
       mailbag-mcp account add <alias> ... --answers-stdin   (stdin: {"secret": S, "use_file_store": B})
       mailbag-mcp account list
       mailbag-mcp account remove <alias>
       mailbag-mcp account test <alias>
       mailbag-mcp identities detect <alias> [--sample N]
       mailbag-mcp oauth set microsoft --client-id ID [--answers-stdin]
       mailbag-mcp oauth set google --file client_secret.json [--answers-stdin]
                   (stdin: {"use_file_store": B}; "secret" is refused)
       mailbag-mcp tools size
       mailbag-mcp tools markdown
       mailbag-mcp doctor
       mailbag-mcp serve
       mailbag-mcp service install|uninstall
       mailbag-mcp service install --force
`

// Env holds what a command writes to and the two steps a test
// replaces: the secret prompt and the live login. A zero Env is the
// real terminal.
//
// arch: T4.6, §3.5, B5
type Env struct {
	Stdout io.Writer
	Stderr io.Writer

	// Stdin is where "account add --answers-stdin" and "oauth set
	// --answers-stdin" read their one JSON document (DS13.5). A nil
	// value means os.Stdin. No other command reads it.
	Stdin io.Reader

	// ReadSecret asks for one secret with no echo. A nil value means
	// the terminal reader of prompt.go, which refuses a pipe (B5).
	ReadSecret func(prompt string) (string, error)

	// Confirm asks one yes-or-no question. A nil value means the
	// terminal reader of prompt.go.
	Confirm func(prompt string) (bool, error)

	// Login connects to the account, lists its folders and runs one
	// search. It writes nothing to the mailbox. It gives back the
	// text to print. A nil value means the real IMAP login.
	Login func(ctx context.Context, alias string) (string, error)

	// ReadLine reads one line of visible text typed at the terminal:
	// the --paste redirect URL (§3.6, T6.3). A nil value means the
	// terminal reader of prompt.go, which refuses a pipe the same way
	// ReadSecret does (B5).
	ReadLine func(prompt string) (string, error)

	// OAuthConfig builds the oauth2.Config for one Microsoft sign-in
	// (T6.3, DS6.2). A nil value means [oauthpkg.Config], the real
	// Microsoft endpoints on login.microsoftonline.com. A test points
	// this at an httptest token endpoint, so the CLI's own PKCE and
	// token-exchange code runs with no network call leaving the
	// process.
	OAuthConfig func(clientID, tenant, redirectURL string) (*oauth2.Config, error)

	// GoogleOAuthConfig builds the oauth2.Config for one Google sign-in
	// (DS7.8). A nil value means [oauthpkg.GoogleConfig], the real
	// Google endpoints. A test points this at an httptest token
	// endpoint, as it does with OAuthConfig.
	GoogleOAuthConfig func(c oauthpkg.GoogleClient, redirectURL string) *oauth2.Config

	// OpenAccount opens one account for "identities detect" (DI7.1)
	// and gives a function that closes it. A nil value means the real
	// provider of [tools.NewFactory], as loginReport opens it. A test
	// gives a fake provider here, so detect runs with no server.
	OpenAccount func(ctx context.Context, alias string) (tools.Reader, config.Account, func(), error)
}

// withDefaults fills the fields a caller left empty with the real
// terminal and the real login.
func (e Env) withDefaults() Env {
	if e.Stdout == nil {
		e.Stdout = os.Stdout
	}
	if e.Stderr == nil {
		e.Stderr = os.Stderr
	}
	if e.Stdin == nil {
		e.Stdin = os.Stdin
	}
	if e.ReadSecret == nil {
		e.ReadSecret = readSecretFromTerminal
	}
	if e.Confirm == nil {
		e.Confirm = confirmOnTerminal
	}
	if e.Login == nil {
		e.Login = liveLogin
	}
	if e.ReadLine == nil {
		e.ReadLine = readLineFromTerminal
	}
	if e.OAuthConfig == nil {
		e.OAuthConfig = oauthpkg.Config
	}
	if e.GoogleOAuthConfig == nil {
		e.GoogleOAuthConfig = oauthpkg.GoogleConfig
	}
	if e.OpenAccount == nil {
		e.OpenAccount = openAccount
	}
	return e
}

// Run executes one command line. args starts at the subcommand, so
// the caller passes os.Args[1:]. The result is the process exit code.
//
// arch: T4.6, §3.5
func Run(args []string, env Env) int {
	env = env.withDefaults()
	if len(args) == 0 {
		return usageErrf(env, "no command")
	}
	switch args[0] {
	case "account":
		return account(args[1:], env)
	case "oauth":
		return oauthCmd(args[1:], env)
	case "tools":
		return toolsCmd(args[1:], env)
	case "doctor":
		return doctor(args[1:], env)
	case "identities":
		return identitiesCmd(args[1:], env)
	case "service":
		return serviceCmd(args[1:], env)
	default:
		return usageErrf(env, "unknown command %q", args[0])
	}
}

// printf writes one line to stdout.
func printf(env Env, format string, a ...any) {
	_, _ = fmt.Fprintf(env.Stdout, format+"\n", a...)
}

// serverText makes text that can hold words from a server safe to
// write to a terminal. It removes the hidden characters of §3.15 with
// [guard.StripInvisible] first, then masks secrets and paths with
// [guard.Redact]. The order is important: a hidden character inside a
// secret or a path cannot then hide it from the redactor.
//
// arch: DR1G.12, DR1G.18.9, §3.15, B6
func serverText(s string) string {
	s, _ = guard.StripInvisible(s)
	return guard.Redact(s)
}

// failf reports a failure at run time. Every text goes through
// [serverText] first, so a server error that repeats the password
// prints "<redacted>" (B6, §3.15) and a server error that holds
// terminal escapes prints none of them (DR1G.18.9).
func failf(env Env, format string, a ...any) int {
	_, _ = fmt.Fprintln(env.Stderr, serverText(fmt.Sprintf(format, a...)))
	return exitFail
}

// usageErrf reports a wrong command line. It prints the usage block
// first, so the first line starts with "usage:" and names the four
// providers (§3.5).
func usageErrf(env Env, format string, a ...any) int {
	_, _ = fmt.Fprint(env.Stderr, usageText)
	_, _ = fmt.Fprintln(env.Stderr, guard.Redact(fmt.Sprintf(format, a...)))
	return exitUsage
}
