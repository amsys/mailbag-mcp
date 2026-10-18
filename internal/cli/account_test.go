// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/oauth2"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	"github.com/amsys/mailbag-mcp/internal/mail"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// addArgs is one full "account add" command line for the imap
// provider (§3.5).
func addArgs(alias string) []string {
	return []string{
		"account", "add", alias,
		"--provider", "imap",
		"--email", "me@example.com",
		"--imap", "mail.example.com:993",
		"--smtp", "mail.example.com:465",
	}
}

// sandbox points the config directory and the secret store at a
// temporary directory, so no test touches the real accounts.toml or
// the system keyring (§3.3, §3.4).
func sandbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", dir)
	t.Setenv("MAILBAG_SECRETS", secrets.KindFile)
	return dir
}

// seedAccount writes an accounts.toml that already holds one account
// and one comment.
func seedAccount(t *testing.T, dir, alias string) string {
	t.Helper()
	path := filepath.Join(dir, "accounts.toml")
	text := `# a comment a person wrote
secrets = "file"

[accounts.` + alias + `]
provider = "imap"
email    = "me@example.com"
imap     = "mail.example.com:993"
smtp     = "mail.example.com:465"
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("seed accounts.toml: %v", err)
	}
	return path
}

// seedOutlookAccount writes an accounts.toml that already holds one
// outlook account, with the DS6.3 hosts and a tenant, plus its oauth
// secret in the file store — the state accountAddOutlook would have
// left behind, for tests of --reauth that must not depend on
// accountAdd itself having run first.
func seedOutlookAccount(t *testing.T, dir, alias, tenant, email string) {
	t.Helper()
	path := filepath.Join(dir, "accounts.toml")
	imapHost, smtpHost := "outlook.office365.com:993", "smtp.office365.com:587"
	if tenant == "consumers" {
		smtpHost = "smtp-mail.outlook.com:587"
	}
	text := `# a comment a person wrote
secrets = "file"

[accounts.` + alias + `]
provider = "outlook"
email    = "` + email + `"
access   = "draft"
imap     = "` + imapHost + `"
smtp     = "` + smtpHost + `"
tenant   = "` + tenant + `"
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("seed accounts.toml: %v", err)
	}
	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	if err := store.Set(alias, `{"v":1,"kind":"oauth","refresh_token":"rt-old"}`); err != nil {
		t.Fatalf("seed the oauth secret: %v", err)
	}
}

// refreshTokenOf reads back the refresh token that a file-store
// secret holds, for tests that check a reauth actually rotated it.
func refreshTokenOf(t *testing.T, dir, alias string) string {
	t.Helper()
	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	raw, err := store.Get(alias)
	if err != nil {
		t.Fatalf("read the secret of %q: %v", alias, err)
	}
	var v struct {
		Kind         string `json:"kind"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("decode the secret of %q: %v", alias, err)
	}
	if v.Kind != "oauth" {
		t.Fatalf("secret of %q has kind %q, want oauth", alias, v.Kind)
	}
	return v.RefreshToken
}

// hasAlias reports whether accounts.toml holds alias.
func hasAlias(t *testing.T, dir, alias string) bool {
	t.Helper()
	path := filepath.Join(dir, "accounts.toml")
	cfg, err := config.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	_, ok := cfg.Account(alias)
	return ok
}

// hasSecret reports whether the file secret store holds a value for
// alias.
func hasSecret(t *testing.T, dir, alias string) bool {
	t.Helper()
	store, err := secrets.Select(secrets.KindFile, "mailbag-mcp", dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	_, err = store.Get(alias)
	if errors.Is(err, secrets.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatalf("read the secret of %q: %v", alias, err)
	}
	return true
}

// TestCLI_AddRefusesPipe proves that "account add" never reads a
// secret from a pipe. Under "go test" stdin is not a terminal, so the
// real reader of prompt.go must refuse, exit with 2, and leave no
// account behind (B5, trap TS #39).
//
// arch: T4.6, §3.5, §3.3, §5.4, B5, B6, B17, B18, D15, §8 S4
func TestCLI_AddRefusesPipe(t *testing.T) {
	dir := sandbox(t)
	var out, errOut bytes.Buffer

	// ReadSecret stays nil on purpose: this test exercises the real
	// terminal reader, the one a piped agent would meet.
	code := Run(addArgs("work"), Env{
		Stdout: &out, Stderr: &errOut,
		Login: func(context.Context, string) (string, error) {
			t.Error("login ran although no password could be read")
			return "", nil
		},
	})

	if code != exitUsage {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
	}
	if !strings.Contains(errOut.String(), "not a terminal") {
		t.Errorf("stderr does not name the terminal rule:\n%s", errOut.String())
	}
	if !strings.HasPrefix(errOut.String(), "usage:") {
		t.Errorf("a usage error must start with a line that starts with \"usage:\":\n%s", errOut.String())
	}
	if hasAlias(t, dir, "work") {
		t.Error("a refused add wrote an account block")
	}
	if hasSecret(t, dir, "work") {
		t.Error("a refused add wrote a secret")
	}
}

// TestCLI_AliasBeforePrompt proves the order of §3.5: the alias check
// comes before the password prompt. An alias that exists must be
// refused with no prompt at all, so a person never types a password
// for a command that cannot work (B5, B17).
//
// arch: T4.6, §3.5, §3.3, §5.4, B5, B6, B17, B18, D15, §8 S4
func TestCLI_AliasBeforePrompt(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")

	cases := []struct {
		name  string
		alias string
		want  int
	}{
		{"alias that exists", "work", exitFail},
		{"alias with a path in it", "../../x", exitUsage},
		{"alias with a dot in it", "a.b", exitUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asked := false
			var out, errOut bytes.Buffer
			code := Run(addArgs(tc.alias), Env{
				Stdout: &out, Stderr: &errOut,
				ReadSecret: func(string) (string, error) {
					asked = true
					return "never-asked-for", nil
				},
				Login: func(context.Context, string) (string, error) {
					t.Error("login ran for an alias that must have been refused")
					return "", nil
				},
			})
			if asked {
				t.Error("the CLI asked for a password before it checked the alias")
			}
			if code != tc.want {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, tc.want, errOut.String())
			}
		})
	}

	// The existing account and the comment above it stay as they are.
	data, err := os.ReadFile(filepath.Join(dir, "accounts.toml")) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read accounts.toml: %v", err)
	}
	if !strings.Contains(string(data), "# a comment a person wrote") {
		t.Errorf("the refused add changed accounts.toml:\n%s", data)
	}
}

// TestCLI_AddRefusesAliasCaseFold checks that "account add" refuses an
// alias that equals an existing alias under case folding, before any
// prompt. On APFS and NTFS "Work" and "work" are one secret file, so
// the new secret would overwrite the old one.
//
// arch: §3.5, B5, B17, R16-L19
func TestCLI_AddRefusesAliasCaseFold(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	for _, provider := range []string{"imap", "outlook", "gmail", "jmap"} {
		t.Run(provider, func(t *testing.T) {
			args := []string{"account", "add", "Work", "--provider", provider, "--email", "me@example.com"}
			if provider == "imap" {
				args = append(args, "--imap", "mail.example.com:993", "--smtp", "mail.example.com:465")
			}
			var out, errOut bytes.Buffer
			code := Run(args, Env{
				Stdout: &out, Stderr: &errOut,
				ReadSecret: func(string) (string, error) {
					t.Error("an alias equal under case folding reached the password prompt")
					return "", nil
				},
				ReadLine: func(string) (string, error) {
					t.Error("an alias equal under case folding reached a prompt")
					return "", nil
				},
				Login: func(context.Context, string) (string, error) {
					t.Error("login ran for an alias equal under case folding")
					return "", nil
				},
			})
			if code != exitFail {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
			}
			if !strings.Contains(errOut.String(), `"work"`) {
				t.Errorf("stderr does not name the existing alias \"work\":\n%s", errOut.String())
			}
		})
	}
	if hasAlias(t, dir, "Work") {
		t.Error("accounts.toml holds the new alias Work")
	}
}

// TestCLI_LoginFailRollsBack proves that a failed login leaves
// nothing behind: no account block in accounts.toml and no value in
// the secret store (B5, trap TS #39).
//
// arch: T4.6, §3.5, §3.3, §5.4, B5, B6, B17, B18, D15, §8 S4
func TestCLI_LoginFailRollsBack(t *testing.T) {
	dir := sandbox(t)
	var out, errOut bytes.Buffer

	code := Run(addArgs("work"), Env{
		Stdout: &out, Stderr: &errOut,
		ReadSecret: func(string) (string, error) { return "rollback-password", nil },
		Login: func(_ context.Context, alias string) (string, error) {
			if alias != "work" {
				t.Errorf("login alias = %q, want \"work\"", alias)
			}
			// The account must exist while the test runs: the CLI
			// tests the login after it saved, not before.
			if !hasAlias(t, dir, "work") {
				t.Error("the login test ran before the account was written")
			}
			return "", errors.New("AUTHENTICATIONFAILED")
		},
	})

	if code != exitFail {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
	}
	if hasAlias(t, dir, "work") {
		t.Error("a failed login left the account block in accounts.toml")
	}
	if hasSecret(t, dir, "work") {
		t.Error("a failed login left the secret in the store")
	}
	if !strings.Contains(errOut.String(), "removed again") {
		t.Errorf("stderr does not say that the account was removed:\n%s", errOut.String())
	}
}

// TestCLI_PasswordNeverPrinted proves B6: a server error that repeats
// the password must never reach the terminal. The redactor replaces
// every registered value, so the text shows "<redacted>" instead.
//
// arch: T4.6, §3.5, §3.3, §5.4, B5, B6, B17, B18, D15, §8 S4
func TestCLI_PasswordNeverPrinted(t *testing.T) {
	dir := sandbox(t)
	const password = "correct-horse-battery"
	var out, errOut bytes.Buffer

	code := Run(addArgs("work"), Env{
		Stdout: &out, Stderr: &errOut,
		ReadSecret: func(string) (string, error) { return password, nil },
		Login: func(context.Context, string) (string, error) {
			// Some servers repeat the whole command in the error.
			return "", errors.New("imap: LOGIN \"me@example.com\" \"" + password + "\" failed")
		},
	})

	if code != exitFail {
		t.Errorf("exit code = %d, want %d", code, exitFail)
	}
	for name, text := range map[string]string{"stdout": out.String(), "stderr": errOut.String()} {
		if strings.Contains(text, password) {
			t.Errorf("%s holds the password:\n%s", name, text)
		}
	}
	if !strings.Contains(errOut.String(), "<redacted>") {
		t.Errorf("stderr holds no redaction mark:\n%s", errOut.String())
	}
	// The stored secret is gone with the rolled back account, so the
	// password cannot leak from the file either.
	if hasSecret(t, dir, "work") {
		t.Error("the secret stayed in the store after a failed login")
	}
}

// TestCLI_AddListRemoveRoundTrip proves the happy path: add writes a
// readable accounts.toml and a secret, list names the account, and
// remove cuts the block and deletes the secret while the comments of
// the person stay (§3.3, B18).
//
// arch: T4.6, §3.5, §3.3, §5.4, B5, B6, B17, B18, D15, §8 S4
func TestCLI_AddListRemoveRoundTrip(t *testing.T) {
	dir := sandbox(t)
	var out, errOut bytes.Buffer

	code := Run(addArgs("work"), Env{
		Stdout: &out, Stderr: &errOut,
		ReadSecret: func(string) (string, error) { return "round-trip-password", nil },
		Login:      func(context.Context, string) (string, error) { return "login ok\n", nil },
	})
	if code != exitOK {
		t.Fatalf("add: exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if !hasAlias(t, dir, "work") || !hasSecret(t, dir, "work") {
		t.Fatalf("add wrote no account or no secret")
	}

	cfg, err := config.Load(filepath.Join(dir, "accounts.toml"))
	if err != nil {
		t.Fatalf("load accounts.toml: %v", err)
	}
	acct, _ := cfg.Account("work")
	if acct.Provider != "imap" || acct.IMAP != "mail.example.com:993" || acct.Username != "me@example.com" {
		t.Errorf("account = %+v, want the values of the command line with the email as the user name", acct)
	}
	if cfg.Secrets() != secrets.KindFile {
		t.Errorf("recorded secret store = %q, want %q", cfg.Secrets(), secrets.KindFile)
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"account", "list"}, Env{Stdout: &out, Stderr: &errOut}); code != exitOK {
		t.Fatalf("list: exit code = %d\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "work") || !strings.Contains(out.String(), "me@example.com") {
		t.Errorf("list names no account:\n%s", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"account", "remove", "work"}, Env{Stdout: &out, Stderr: &errOut}); code != exitOK {
		t.Fatalf("remove: exit code = %d\nstderr: %s", code, errOut.String())
	}
	if hasAlias(t, dir, "work") {
		t.Error("remove left the account block")
	}
	if hasSecret(t, dir, "work") {
		t.Error("remove left the secret")
	}
}

// TestCLI_RemoveBrokenAccount checks that "account remove" works when
// the strict load fails: the account to remove names a missing
// signature_file, or another account block is bad. The command finds
// the alias and the store kind with the lenient decode of the splice.
//
// arch: T4.6, §3.5, B18, R16-L15
func TestCLI_RemoveBrokenAccount(t *testing.T) {
	const good = `
[accounts.%s]
provider = "imap"
email    = "me@example.com"
imap     = "mail.example.com:993"
smtp     = "mail.example.com:465"
`
	cases := map[string]string{
		"missing signature_file": "secrets = \"file\"\n" + fmt.Sprintf(good, "work") + `
[[accounts.work.identity]]
email          = "me@example.com"
signature_file = "gone.txt"
` + fmt.Sprintf(good, "home"),
		"bad other block": "secrets = \"file\"\n" + fmt.Sprintf(good, "work") + `
[accounts.home]
provider = "pigeon"
email    = "me@example.com"
`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			dir := sandbox(t)
			path := filepath.Join(dir, "accounts.toml")
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatalf("seed accounts.toml: %v", err)
			}
			store := secrets.NewFileStore(dir)
			if err := store.Set("work", `{"v":1,"kind":"password","password":"pw"}`); err != nil {
				t.Fatalf("seed the secret: %v", err)
			}

			var out, errOut bytes.Buffer
			if code := Run([]string{"account", "remove", "work"}, Env{Stdout: &out, Stderr: &errOut}); code != exitOK {
				t.Fatalf("remove: exit code = %d, want 0\nstderr: %s", code, errOut.String())
			}
			data, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
			if err != nil {
				t.Fatalf("read accounts.toml: %v", err)
			}
			if strings.Contains(string(data), "[accounts.work") {
				t.Errorf("remove left the block of work:\n%s", data)
			}
			if !strings.Contains(string(data), "[accounts.home]") {
				t.Errorf("remove cut the block of home:\n%s", data)
			}
			if _, err := store.Get("work"); !errors.Is(err, secrets.ErrNotFound) {
				t.Errorf("the secret of work: err = %v, want ErrNotFound", err)
			}
		})
	}
}

// TestCLI_UsageErrors proves the exit codes of §3.5 and §5.4: an
// unknown provider, an absent email, an unknown command, "tools" with
// no subcommand and an unknown tools subcommand all exit with 2, and
// the text names the four providers and the "tools markdown" line.
//
// arch: T4.6, §3.5, §3.3, §5.4, B5, B6, B17, B18, D15, §8 S4, DS10.1, DS10.6, DS10.13, IS10.9
func TestCLI_UsageErrors(t *testing.T) {
	sandbox(t)
	cases := map[string][]string{
		"unknown provider": {"account", "add", "work", "--provider", "pigeon", "--email", "me@example.com"},
		"no email":         {"account", "add", "work", "--provider", "imap"},
		"no alias":         {"account", "add", "--provider", "imap", "--email", "me@example.com"},
		"unknown command":  {"mailbox"},
		"no command":       {},
		"tools no subcmd":  {"tools"},
		"tools unknown":    {"tools", "--markdown"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(args, Env{
				Stdout: &out, Stderr: &errOut,
				ReadSecret: func(string) (string, error) {
					t.Error("a wrong command line reached the password prompt")
					return "", nil
				},
			})
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
			}
			text := errOut.String()
			if !strings.HasPrefix(text, "usage:") {
				t.Errorf("the first line does not start with \"usage:\":\n%s", text)
			}
			for _, p := range []string{"imap", "outlook", "gmail", "jmap"} {
				if !strings.Contains(text, p) {
					t.Errorf("the usage text does not name the provider %q:\n%s", p, text)
				}
			}
			if !strings.Contains(text, "mailbag-mcp tools markdown") {
				t.Errorf("the usage text does not name \"tools markdown\":\n%s", text)
			}
		})
	}
}

// TestCLI_AddRefusesNameFormEmail checks that each provider branch of
// "account add" refuses an --email with a display name before any
// prompt or sign-in. The config load refuses the same value.
//
// arch: §3.5, B5, R16-M10
func TestCLI_AddRefusesNameFormEmail(t *testing.T) {
	dir := sandbox(t)
	for _, provider := range []string{"imap", "outlook", "gmail", "jmap"} {
		t.Run(provider, func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := []string{"account", "add", "work", "--provider", provider, "--email", "Ann <me@example.com>"}
			code := Run(args, Env{
				Stdout: &out, Stderr: &errOut,
				ReadSecret: func(string) (string, error) {
					t.Error("a name-form --email reached the password prompt")
					return "", nil
				},
				ReadLine: func(string) (string, error) {
					t.Error("a name-form --email reached a prompt")
					return "", nil
				},
				Login: func(context.Context, string) (string, error) {
					t.Error("login ran for a name-form --email")
					return "", nil
				},
			})
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
			}
			if !strings.Contains(errOut.String(), "bare address") {
				t.Errorf("stderr does not say that --email must be a bare address:\n%s", errOut.String())
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("accounts.toml exists after the refusals: %v", err)
	}
}

// TestCLI_OutlookPasteWritesHostsAndSecret proves the outlook branch
// of accountAdd end to end against a fake token endpoint: --paste
// prints the authorize URL, reads the pasted redirect back through
// Env.ReadLine, exchanges it for a token with no offline_access gap,
// and writes the DS6.3 hosts and the oauth secret shape of §3.4. The
// alias check happens before the sign-in (B5): a duplicate is proven
// by TestCLI_OutlookAliasBeforePrompt instead of repeating it here.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_OutlookPasteWritesHostsAndSecret(t *testing.T) {
	dir := sandbox(t)
	seedMicrosoftClientID(t, dir, "public-client-1")
	var out, errOut bytes.Buffer

	code := Run([]string{
		"account", "add", "work",
		"--provider", "outlook",
		"--email", "ann@contoso.com",
		"--paste",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		OAuthConfig: fakeMicrosoftConfig(t, map[string]any{
			"access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600,
		}),
		ReadLine: func(string) (string, error) { return pasteRedirect(t, &errOut), nil },
		Login:    func(context.Context, string) (string, error) { return "login ok\n", nil },
	})
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "open this URL in a browser to sign in") {
		t.Errorf("the authorize URL was not printed to stderr:\n%s", errOut.String())
	}

	cfg, err := config.Load(filepath.Join(dir, "accounts.toml"))
	if err != nil {
		t.Fatalf("load accounts.toml: %v", err)
	}
	acct, ok := cfg.Account("work")
	if !ok {
		t.Fatalf("account %q was not written", "work")
	}
	if acct.Provider != "outlook" || acct.Email != "ann@contoso.com" {
		t.Errorf("account = %+v, want provider outlook and the given email", acct)
	}
	if acct.Tenant != "organizations" {
		t.Errorf("acct.Tenant = %q, want %q (DS6.8: contoso.com has no consumer suffix)", acct.Tenant, "organizations")
	}
	if acct.IMAP != "outlook.office365.com:993" || acct.SMTP != "smtp.office365.com:587" {
		t.Errorf("acct hosts = %q/%q, want the DS6.3 organizations hosts", acct.IMAP, acct.SMTP)
	}
	if got := refreshTokenOf(t, dir, "work"); got != "rt-1" {
		t.Errorf("stored refresh token = %q, want %q", got, "rt-1")
	}
}

// TestCLI_OutlookPasteRefusesPipe proves B5 and §3.5 for the --paste
// flow: the redirect URL comes from a terminal only. Under "go test"
// stdin is not a terminal, so the real reader of prompt.go must
// refuse with exit 2, not the run-time exit 1 that "sign in with
// Microsoft: %v" would otherwise give the same error text.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_OutlookPasteRefusesPipe(t *testing.T) {
	dir := sandbox(t)
	seedMicrosoftClientID(t, dir, "public-client-1")
	var out, errOut bytes.Buffer

	// ReadLine stays nil on purpose: this test exercises the real
	// terminal reader, the one a piped agent would meet.
	code := Run([]string{
		"account", "add", "work",
		"--provider", "outlook",
		"--email", "ann@contoso.com",
		"--paste",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		Login: func(context.Context, string) (string, error) {
			t.Error("login ran although no redirect URL could be read")
			return "", nil
		},
	})

	if code != exitUsage {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
	}
	if !strings.Contains(errOut.String(), "not a terminal") {
		t.Errorf("stderr does not name the terminal rule:\n%s", errOut.String())
	}
	// The authorize URL is printed to stderr before the redirect is
	// read (§3.6), so the usage block is not the first text here, but
	// one of its lines must still start with "usage:".
	usageSeen := false
	for _, line := range strings.Split(errOut.String(), "\n") {
		if strings.HasPrefix(line, "usage:") {
			usageSeen = true
			break
		}
	}
	if !usageSeen {
		t.Errorf("no line starts with \"usage:\":\n%s", errOut.String())
	}
	if hasAlias(t, dir, "work") {
		t.Error("a refused --paste sign-in wrote an account block")
	}
	if hasSecret(t, dir, "work") {
		t.Error("a refused --paste sign-in wrote a secret")
	}
}

// TestCLI_OutlookAliasBeforePrompt proves B5 for the outlook branch:
// an alias that exists already is refused before the sign-in ever
// reads a pasted URL. No Microsoft client id is seeded on purpose: the
// alias check must be what stops the run, not a later failure that
// would also exit 1 (a "not configured" client id fails the same way
// and would hide a disabled alias check, so the text is checked too).
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_OutlookAliasBeforePrompt(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")

	asked := false
	var out, errOut bytes.Buffer
	code := Run([]string{
		"account", "add", "work",
		"--provider", "outlook",
		"--email", "ann@contoso.com",
		"--paste",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		ReadLine: func(string) (string, error) { asked = true; return "", nil },
	})
	if asked {
		t.Error("the CLI read a pasted URL before it checked the alias")
	}
	if code != exitFail {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
	}
	if !strings.Contains(errOut.String(), "exists already") {
		t.Errorf("stderr does not name the alias-exists refusal (got a different failure instead):\n%s", errOut.String())
	}
}

// TestCLI_OutlookAbandonedSignInLeavesNoFile proves L1 of
// S6-close-judge: a first "account add --provider outlook" whose
// sign-in fails before it ever exchanges a code must leave no
// accounts.toml behind, the same rule the imap path already keeps by
// reading the password before ensureFile runs (B3: a header-only file
// would otherwise fix the store kind for every later add). This test
// starts from a sandbox with no accounts.toml at all — the Microsoft
// client id is seeded straight into the file store's directory
// (seedMicrosoftClientID), never through "oauth set microsoft", so the
// file genuinely does not exist yet when the sign-in is abandoned.
//
// arch: S6-close-judge L1/L4, §3.5, §3.6, B3, B11
func TestCLI_OutlookAbandonedSignInLeavesNoFile(t *testing.T) {
	dir := sandbox(t)
	seedMicrosoftClientID(t, dir, "public-client-1")
	if hasAlias(t, dir, "work") {
		t.Fatal("accounts.toml already holds an account before the test ran")
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts.toml")); err == nil {
		t.Fatal("accounts.toml exists before the sign-in was ever attempted")
	}

	var out, errOut bytes.Buffer
	code := Run([]string{
		"account", "add", "work",
		"--provider", "outlook",
		"--email", "ann@contoso.com",
		"--paste",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		OAuthConfig: fakeMicrosoftConfig(t, map[string]any{
			"access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600,
		}),
		// A bad paste: not a URL at all, so ParsePastedRedirect refuses
		// it before any exchange runs (the abandoned sign-in of L1).
		ReadLine: func(string) (string, error) { return "not a url and no state either", nil },
		Login: func(context.Context, string) (string, error) {
			t.Error("login ran although the sign-in was never completed")
			return "", nil
		},
	})
	if code != exitFail {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts.toml")); err == nil {
		t.Error("an abandoned outlook sign-in left accounts.toml behind")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stat accounts.toml: %v", err)
	}
	if hasSecret(t, dir, "work") {
		t.Error("an abandoned outlook sign-in left a secret behind")
	}
}

// TestCLI_OutlookBadTenantRefused proves I-S6.2: a tenant outside
// common/organizations/consumers/GUID/DNS-name is rejected before any
// prompt or request, with no account block left behind.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_OutlookBadTenantRefused(t *testing.T) {
	dir := sandbox(t)
	asked := false
	var out, errOut bytes.Buffer
	code := Run([]string{
		"account", "add", "work",
		"--provider", "outlook",
		"--email", "ann@contoso.com",
		"--tenant", "contoso.com/../evil",
		"--paste",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		ReadLine: func(string) (string, error) { asked = true; return "", nil },
	})
	if asked {
		t.Error("the CLI read a pasted URL for a tenant that must have been refused")
	}
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
	}
	if hasAlias(t, dir, "work") {
		t.Error("a refused tenant left an account block behind")
	}
}

// TestCLI_OutlookTenantFromEmail proves DS6.8: a consumer domain
// defaults to "consumers" (and its SMTP host), any other domain
// defaults to "organizations", and an explicit --tenant always wins.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_OutlookTenantFromEmail(t *testing.T) {
	cases := []struct {
		name, email, tenantFlag, wantTenant, wantSMTP string
	}{
		{"consumer domain", "ann@outlook.com", "", "consumers", "smtp-mail.outlook.com:587"},
		{"other domain", "ann@contoso.com", "", "organizations", "smtp.office365.com:587"},
		{"explicit override", "ann@contoso.com", "common", "common", "smtp.office365.com:587"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := sandbox(t)
			seedMicrosoftClientID(t, dir, "public-client-1")
			var out, errOut bytes.Buffer

			args := []string{"account", "add", "work", "--provider", "outlook", "--email", tc.email, "--paste"}
			if tc.tenantFlag != "" {
				args = append(args, "--tenant", tc.tenantFlag)
			}
			code := Run(args, Env{
				Stdout: &out, Stderr: &errOut,
				OAuthConfig: fakeMicrosoftConfig(t, map[string]any{
					"access_token": "at-1", "refresh_token": "rt-1", "token_type": "Bearer", "expires_in": 3600,
				}),
				ReadLine: func(string) (string, error) { return pasteRedirect(t, &errOut), nil },
				Login:    func(context.Context, string) (string, error) { return "ok\n", nil },
			})
			if code != exitOK {
				t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
			}

			cfg, err := config.Load(filepath.Join(dir, "accounts.toml"))
			if err != nil {
				t.Fatalf("load accounts.toml: %v", err)
			}
			acct, ok := cfg.Account("work")
			if !ok {
				t.Fatalf("account %q was not written", "work")
			}
			if acct.Tenant != tc.wantTenant {
				t.Errorf("acct.Tenant = %q, want %q", acct.Tenant, tc.wantTenant)
			}
			if acct.SMTP != tc.wantSMTP {
				t.Errorf("acct.SMTP = %q, want %q", acct.SMTP, tc.wantSMTP)
			}
		})
	}
}

// TestCLI_ReauthReplacesSecretOnly proves DS6.5: --reauth signs in
// again and rotates the stored refresh token, but leaves the account
// block — alias, provider, email, tenant, hosts and the comment above
// it — exactly as it was.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_ReauthReplacesSecretOnly(t *testing.T) {
	dir := sandbox(t)
	seedOutlookAccount(t, dir, "work", "organizations", "ann@contoso.com")
	seedMicrosoftClientID(t, dir, "public-client-1")

	before, err := os.ReadFile(filepath.Join(dir, "accounts.toml")) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read accounts.toml: %v", err)
	}

	var out, errOut bytes.Buffer
	code := Run([]string{"account", "add", "work", "--reauth", "--paste"}, Env{
		Stdout: &out, Stderr: &errOut,
		OAuthConfig: fakeMicrosoftConfig(t, map[string]any{
			"access_token": "at-2", "refresh_token": "rt-new", "token_type": "Bearer", "expires_in": 3600,
		}),
		ReadLine: func(string) (string, error) { return pasteRedirect(t, &errOut), nil },
		Login: func(context.Context, string) (string, error) {
			t.Error("--reauth ran the live login test; it must only replace the secret")
			return "", nil
		},
	})
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}

	after, err := os.ReadFile(filepath.Join(dir, "accounts.toml")) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read accounts.toml: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("--reauth changed the account block:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got := refreshTokenOf(t, dir, "work"); got != "rt-new" {
		t.Errorf("stored refresh token = %q, want %q", got, "rt-new")
	}
}

// TestCLI_ReauthUnknownAliasRefused proves --reauth refuses an alias
// that accounts.toml does not hold, whether the file is missing
// entirely or just does not carry that alias.
//
// arch: T6.3, DS6.3, DS6.5, DS6.8, §3.5, §3.6, B5, B11
func TestCLI_ReauthUnknownAliasRefused(t *testing.T) {
	t.Run("no accounts.toml yet", func(t *testing.T) {
		sandbox(t)
		var out, errOut bytes.Buffer
		code := Run([]string{"account", "add", "ghost", "--reauth"}, Env{Stdout: &out, Stderr: &errOut})
		if code != exitFail {
			t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
		}
		if !strings.Contains(errOut.String(), "ghost") {
			t.Errorf("stderr does not name the alias:\n%s", errOut.String())
		}
	})

	t.Run("alias not in accounts.toml", func(t *testing.T) {
		dir := sandbox(t)
		seedAccount(t, dir, "work")
		var out, errOut bytes.Buffer
		code := Run([]string{"account", "add", "ghost", "--reauth"}, Env{Stdout: &out, Stderr: &errOut})
		if code != exitFail {
			t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
		}
	})

	t.Run("alias is not an outlook account", func(t *testing.T) {
		// No Microsoft client id is seeded on purpose, for the same
		// reason as TestCLI_OutlookAliasBeforePrompt: a "not
		// configured" client id also exits 1, and would hide a
		// disabled provider check, so the text is checked too.
		dir := sandbox(t)
		seedAccount(t, dir, "work") // imap, from seedAccount
		var out, errOut bytes.Buffer
		code := Run([]string{"account", "add", "work", "--reauth"}, Env{Stdout: &out, Stderr: &errOut})
		if code != exitFail {
			t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
		}
		if !strings.Contains(errOut.String(), "uses provider") {
			t.Errorf("stderr does not name the wrong-provider refusal (got a different failure instead):\n%s", errOut.String())
		}
	})
}

// fakeLoginProvider is the network-free double reportLines needs: it
// answers Folders and Search only, so a test can check the report's
// text with no live server (T91).
type fakeLoginProvider struct {
	folders []mail.Folder
	found   int
}

func (p fakeLoginProvider) Folders(context.Context) ([]mail.Folder, error) {
	return p.folders, nil
}

func (p fakeLoginProvider) Search(context.Context, mail.Query) (mail.Page, error) {
	return mail.Page{Messages: make([]mail.Message, p.found)}, nil
}

// fakeCapsProvider adds Caps on top of fakeLoginProvider, so a test
// can check the capability lines liveLogin prints for a provider that
// has tools.CapsReporter. The concrete type asserts to that interface
// the same way a *imap.Provider does; reportLines never knows the
// difference (DR1G.11).
type fakeCapsProvider struct {
	fakeLoginProvider
	caps    mail.Caps
	capsErr error // when set, Caps fails with it
}

func (p fakeCapsProvider) Caps(context.Context) (mail.Caps, error) {
	return p.caps, p.capsErr
}

// TestLoginReport_Lines checks the folders/search/capability lines
// reportLines builds, with no live server: the plumbing loginReport
// adds on top is only opening the account and calling this function
// (DR1G.18.9).
//
// arch: DR1G.11, DR1G.18.9
func TestLoginReport_Lines(t *testing.T) {
	t.Parallel()

	p := fakeLoginProvider{
		folders: []mail.Folder{{Name: "INBOX", Role: "inbox", Total: 3, Unread: 1}},
		found:   2,
	}
	acct := config.Account{Username: "ann", IMAP: "imap.example.test:993"}

	lines, err := reportLines(context.Background(), p, acct)
	if err != nil {
		t.Fatalf("reportLines: %v", err)
	}

	want := []string{
		"login as ann at imap.example.test:993: ok",
		"1 folders:",
		fmt.Sprintf("  %-24s role=%-8s total=%-6d unread=%d", "INBOX", "inbox", 3, 1),
		"search of the newest messages in the inbox: 2 found",
		"capabilities: not reported by this provider",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%q", len(lines), len(want), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

// TestLoginReport_GmailTarget checks the report of a gmail account
// with no live server. The login line names gmail.googleapis.com, not
// the empty IMAP address. The capability lines are the provider's
// Lines through serverText, then the fixed gmail Sent advice. No IMAP
// capability line and no save_sent advice shows, also when the
// account sets save_sent.
//
// arch: DS78.4, DS78.1
func TestLoginReport_GmailTarget(t *testing.T) {
	t.Parallel()
	guard.RegisterSecret(hostileSecret)

	p := fakeCapsProvider{
		fakeLoginProvider: fakeLoginProvider{
			folders: []mail.Folder{{Name: "INBOX", Role: "inbox", Total: 3, Unread: 1}},
			found:   2,
		},
		caps: mail.Caps{Kind: "gmail", Lines: []string{
			"api: ok",
			"labels: 12",
			"send-as: 2\u202e verified",
			"api: " + hostileServerText,
		}},
	}
	acct := config.Account{
		Provider: "gmail",
		Email:    "ann@gmail.example",
		Username: "ann@gmail.example",
		SaveSent: "always",
	}

	lines, err := reportLines(context.Background(), p, acct)
	if err != nil {
		t.Fatalf("reportLines: %v", err)
	}

	// hostileAt is the line of the hostile Lines entry. Its clean
	// text depends on the redaction rules, so assertCleanServerText
	// checks it in place of an exact value.
	const hostileAt = 7
	want := []string{
		"login as ann@gmail.example at gmail.googleapis.com: ok",
		"1 folders:",
		fmt.Sprintf("  %-24s role=%-8s total=%-6d unread=%d", "INBOX", "inbox", 3, 1),
		"search of the newest messages in the inbox: 2 found",
		"api: ok",
		"labels: 12",
		"send-as: 2 verified",
		"", // hostileAt
		"server keeps Sent",
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%q", len(lines), len(want), lines)
	}
	for i := range want {
		if i == hostileAt {
			continue
		}
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
	if !strings.HasPrefix(lines[hostileAt], "api: ") {
		t.Errorf("line %d = %q, want the hostile Lines entry", hostileAt, lines[hostileAt])
	}
	assertCleanServerText(t, "gmail Lines entry", lines[hostileAt])
}

// TestLoginReport_JMAPTarget checks the report of a jmap account with
// no live server. The login line names the host of the session URL
// that config.JMAPSessionURL gives: the email domain when session_url
// is not set (DS78.11 G11), else the host of session_url without its
// port. The capability lines are the provider's Lines, then the fixed
// jmap Sent advice. A session URL that config refuses gives an error
// and no report.
//
// arch: DS78.4, DS78.1
func TestLoginReport_JMAPTarget(t *testing.T) {
	t.Parallel()

	capsLines := []string{
		"session: ok",
		"capabilities: core, mail, submission",
		"mailboxes: 4",
		"identities: 1",
		"maxSizeUpload: 50000000",
	}
	for _, tc := range []struct {
		name       string
		email      string
		sessionURL string
		target     string // the host the login line names
		wantErr    error  // when set, reportLines fails with it
	}{
		{name: "default session URL from the email domain", email: "ann@example.test", target: "example.test"},
		{name: "session_url with a port", email: "ann@example.test", sessionURL: "https://jmap.example.test:8443/jmap/session", target: "jmap.example.test"},
		{name: "session_url that is not https", email: "ann@example.test", sessionURL: "http://jmap.example.test/jmap/session", wantErr: config.ErrSessionURLNotHTTPS},
		{name: "no session_url and no email domain", email: "ann", wantErr: config.ErrJMAPNoSessionURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := fakeCapsProvider{
				fakeLoginProvider: fakeLoginProvider{found: 1},
				caps:              mail.Caps{Kind: "jmap", Lines: capsLines},
			}
			acct := config.Account{
				Provider:   "jmap",
				Email:      tc.email,
				Username:   tc.email,
				SessionURL: tc.sessionURL,
			}

			lines, err := reportLines(context.Background(), p, acct)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("reportLines error = %v, want %v", err, tc.wantErr)
				}
				if lines != nil {
					t.Errorf("reportLines gave lines with its error:\n%q", lines)
				}
				return
			}
			if err != nil {
				t.Fatalf("reportLines: %v", err)
			}

			want := []string{
				fmt.Sprintf("login as %s at %s: ok", tc.email, tc.target),
				"0 folders:",
				"search of the newest messages in the inbox: 1 found",
			}
			want = append(want, capsLines...)
			want = append(want, "Sent through onSuccessUpdateEmail")
			if len(lines) != len(want) {
				t.Fatalf("got %d lines, want %d:\n%q", len(lines), len(want), lines)
			}
			for i := range want {
				if lines[i] != want[i] {
					t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
				}
			}
		})
	}
}

// TestCLI_LoginPrintsCaps checks that "account test" prints the
// capability report of T91 for a provider that implements
// tools.CapsReporter, including the save_sent advice line, through
// the real CLI dispatch (Run -> account -> accountTest -> env.Login).
//
// arch: DR1G.11, DR1G.18.9, IR1G.15
func TestCLI_LoginPrintsCaps(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")

	acct := config.Account{
		Username: "ann",
		IMAP:     "imap.example.test:993",
		SaveSent: "always",
		SMTP:     "smtp.gmail.com:587",
	}
	p := fakeCapsProvider{
		fakeLoginProvider: fakeLoginProvider{found: 1},
		caps:              mail.Caps{Keywords: true, UIDPlus: true, Move: false, CondStore: true},
	}

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(ctx context.Context, _ string) (string, error) {
		lines, err := reportLines(ctx, p, acct)
		if err != nil {
			return "", err
		}
		return strings.Join(lines, "\n") + "\n", nil
	}}

	code := Run([]string{"account", "test", "work"}, env)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitOK, errOut.String())
	}
	for _, want := range []string{
		"UIDPLUS: yes",
		"MOVE: no",
		"CONDSTORE: yes",
		"KEYWORDS: yes",
		"save_sent = always: mailbag saves a copy in Sent",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report does not hold %q:\n%s", want, out.String())
		}
	}
}

// TestCLI_LoginNoCapsReporter checks that "account test" falls back
// to the fixed line of DR1G.11 for a provider that gives no
// capability report, through the real CLI dispatch.
//
// arch: DR1G.11, DR1G.18.9
func TestCLI_LoginNoCapsReporter(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")

	p := fakeLoginProvider{found: 1}
	acct := config.Account{Username: "ann", IMAP: "imap.example.test:993"}

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(ctx context.Context, _ string) (string, error) {
		lines, err := reportLines(ctx, p, acct)
		if err != nil {
			return "", err
		}
		return strings.Join(lines, "\n") + "\n", nil
	}}

	code := Run([]string{"account", "test", "work"}, env)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitOK, errOut.String())
	}
	if !strings.Contains(out.String(), "capabilities: not reported by this provider") {
		t.Errorf("report does not hold the no-CapsReporter line:\n%s", out.String())
	}
	for _, unwanted := range []string{"UIDPLUS:", "MOVE:", "CONDSTORE:", "KEYWORDS:", "save_sent ="} {
		if strings.Contains(out.String(), unwanted) {
			t.Errorf("report holds %q, want no capability lines at all", unwanted)
		}
	}
}

// TestCLI_LoginErrorStripsInvisible proves R1G-judge L4 for "account
// test": a login error that holds terminal escapes, a bidi override
// and a secret reaches stderr through [serverText], so stderr holds no
// hidden character and the secret is masked.
//
// arch: DR1G.11, DR1G.12, DR1G.18, DR1G.18.9
func TestCLI_LoginErrorStripsInvisible(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	guard.RegisterSecret(hostileSecret)

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
		return "", errors.New(hostileServerText)
	}}

	code := Run([]string{"account", "test", "work"}, env)
	if code != exitFail {
		t.Errorf("exit code = %d, want %d", code, exitFail)
	}
	if !strings.HasPrefix(errOut.String(), `account "work": `) {
		t.Errorf("stderr does not start with the account line:\n%q", errOut.String())
	}
	assertCleanServerText(t, "stderr", errOut.String())
}

// TestCLI_CapsErrorStripsInvisible proves R1G-judge L4 for the
// capability report: a Caps error that holds terminal escapes, a bidi
// override and a secret gives a clean "capabilities: " line.
//
// arch: DR1G.11, DR1G.12, DR1G.18, DR1G.18.9
func TestCLI_CapsErrorStripsInvisible(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	guard.RegisterSecret(hostileSecret)

	p := fakeCapsProvider{
		fakeLoginProvider: fakeLoginProvider{found: 1},
		capsErr:           errors.New(hostileServerText),
	}
	acct := config.Account{Username: "ann", IMAP: "imap.example.test:993"}

	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(ctx context.Context, _ string) (string, error) {
		lines, err := reportLines(ctx, p, acct)
		if err != nil {
			return "", err
		}
		return strings.Join(lines, "\n") + "\n", nil
	}}

	code := Run([]string{"account", "test", "work"}, env)
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitOK, errOut.String())
	}
	var capsLine string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "capabilities: ") {
			capsLine = line
		}
	}
	if capsLine == "" {
		t.Fatalf("report holds no capabilities line:\n%q", out.String())
	}
	assertCleanServerText(t, "capabilities line", capsLine)
	assertCleanServerText(t, "stdout", out.String())
}

// The made-up Google client of the gmail tests (IS7.1). The project
// number is the part of the client id before the first "-" (DS7.2).
const (
	gmailTestProject = "314159265358"
	gmailTestID      = gmailTestProject + "-test-client.apps.googleusercontent.com"
	gmailTestSecret  = "gmail-cli-add-test-secret" //nolint:gosec // G101: a fake test value, not a real credential
)

// seedGoogleClient writes the `oauth.google` store key directly, in
// place of an earlier "oauth set google --file" run.
func seedGoogleClient(t *testing.T, dir string) {
	t.Helper()
	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	value, err := json.Marshal(oauthpkg.GoogleClient{ClientID: gmailTestID, ClientSecret: gmailTestSecret}) //nolint:gosec // G117: the test stores a fake client secret in the secret store on purpose
	if err != nil {
		t.Fatalf("encode the Google client: %v", err)
	}
	if err := store.Set(googleClientKey, string(value)); err != nil {
		t.Fatalf("seed the Google client: %v", err)
	}
}

// seedGmailAccount writes an accounts.toml that holds one gmail account
// with no imap and no smtp key, and its oauth secret in the file store:
// the state that accountAddGmail leaves behind (DS7.8).
func seedGmailAccount(t *testing.T, dir, alias string) {
	t.Helper()
	text := `# a comment a person wrote
secrets = "file"

[accounts.` + alias + `]
provider = "gmail"
email    = "ann@example.com"
access   = "draft"
`
	if err := os.WriteFile(filepath.Join(dir, "accounts.toml"), []byte(text), 0o600); err != nil {
		t.Fatalf("seed accounts.toml: %v", err)
	}
	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	if err := store.Set(alias, `{"v":1,"kind":"oauth","refresh_token":"rt-gmail-old"}`); err != nil {
		t.Fatalf("seed the oauth secret: %v", err)
	}
}

// googleSeam records what the CLI gave to Env.GoogleOAuthConfig.
type googleSeam struct {
	client   oauthpkg.GoogleClient
	redirect string
	calls    int
}

// fakeGoogleConfig stands in for oauthpkg.GoogleConfig: the scopes and
// the client are the real ones, the endpoints are an httptest server
// that gives tokenResponse to each token request. No request leaves
// the machine.
func fakeGoogleConfig(t *testing.T, seam *googleSeam, tokenResponse map[string]any) func(oauthpkg.GoogleClient, string) *oauth2.Config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse)
	}))
	t.Cleanup(srv.Close)
	return func(c oauthpkg.GoogleClient, redirectURL string) *oauth2.Config {
		seam.client, seam.redirect = c, redirectURL
		seam.calls++
		cfg := oauthpkg.GoogleConfig(c, redirectURL)
		cfg.Endpoint.AuthURL = srv.URL + "/authorize"
		cfg.Endpoint.TokenURL = srv.URL + "/token"
		return cfg
	}
}

// googlePasteFor builds the address bar URL that a person pastes back
// after the Google --paste sign-in, with the state of this attempt.
func googlePasteFor(t *testing.T, stderr *bytes.Buffer) string {
	t.Helper()
	return googlePasteRedirectURL + "?state=" + extractState(t, stderr.String()) + "&code=the-code"
}

// codeLoopback is a loopback double whose Wait gives a code at once,
// so the loopback sign-in completes with no socket and no browser.
type codeLoopback struct{}

func (codeLoopback) Start() (int, error)                  { return 54321, nil }
func (codeLoopback) DualBound() bool                      { return false }
func (codeLoopback) Wait(context.Context) (string, error) { return "the-code", nil }
func (codeLoopback) Close()                               {}

// assertNoGoogleClientLeak fails when text holds the client secret, or
// when a line other than the authorize URL holds the project number
// (IS7.5). The authorize URL holds the client id by necessity: the
// person must open it.
func assertNoGoogleClientLeak(t *testing.T, name, text string) {
	t.Helper()
	if strings.Contains(text, gmailTestSecret) {
		t.Errorf("%s holds the client secret:\n%s", name, text)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, gmailTestProject) && !strings.Contains(line, "/authorize?") {
			t.Errorf("%s: a line that is not the authorize URL holds the project number: %q", name, line)
		}
	}
}

// TestCLI_AccountAddGmail proves the gmail branch of "account add"
// (DS7.8): the paste flow uses the fixed Google paste redirect, the
// loopback flow uses http://127.0.0.1:<port>/callback, both use the
// client of `oauth.google` and the Google authorize parameters, the
// block holds provider, email and access and no imap or smtp key, and
// the secret is kind oauth with the refresh token. No terminal line
// shows the client secret, and only the authorize URL shows the client
// id (IS7.5). A missing --email is a usage error whose block holds the
// DS78.6 gmail line.
//
// arch: DS7.7, DS7.8, DS78.4, DS78.6, DS78.8, DS78.9, IS7.5, B5
func TestCLI_AccountAddGmail(t *testing.T) {
	tokens := map[string]any{"access_token": "at-g", "refresh_token": "rt-gmail-1", "token_type": "Bearer", "expires_in": 3600} //nolint:gosec // G101: a fake test value, not a real credential

	check := func(t *testing.T, dir string, seam *googleSeam, wantRedirect string, out, errOut *bytes.Buffer) {
		t.Helper()
		if seam.redirect != wantRedirect {
			t.Errorf("redirect URL = %q, want %q", seam.redirect, wantRedirect)
		}
		if want := (oauthpkg.GoogleClient{ClientID: gmailTestID, ClientSecret: gmailTestSecret}); seam.client != want {
			t.Errorf("Google client = %+v, want the stored client", seam.client)
		}
		for _, p := range []string{"access_type=offline", "prompt=consent", "login_hint=ann%40example.com"} {
			if !strings.Contains(errOut.String(), p) {
				t.Errorf("the authorize URL does not hold %q:\n%s", p, errOut.String())
			}
		}
		raw, err := os.ReadFile(filepath.Join(dir, "accounts.toml")) //nolint:gosec // G304: the test reads a path it built in its own temp dir
		if err != nil {
			t.Fatalf("read accounts.toml: %v", err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			key := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
			if key == "imap" || key == "smtp" || key == "tenant" || key == "username" {
				t.Errorf("the gmail block holds the key %q:\n%s", key, raw)
			}
		}
		cfg, err := config.Load(filepath.Join(dir, "accounts.toml"))
		if err != nil {
			t.Fatalf("load accounts.toml: %v", err)
		}
		acct, ok := cfg.Account("mine")
		if !ok {
			t.Fatalf("account %q was not written:\n%s", "mine", raw)
		}
		if acct.Provider != "gmail" || acct.Email != "ann@example.com" || acct.Access != "send" {
			t.Errorf("account = %+v, want provider gmail, the given email and access send", acct)
		}
		if got := refreshTokenOf(t, dir, "mine"); got != "rt-gmail-1" {
			t.Errorf("stored refresh token = %q, want %q", got, "rt-gmail-1")
		}
		assertNoGoogleClientLeak(t, "stdout", out.String())
		assertNoGoogleClientLeak(t, "stderr", errOut.String())
	}

	t.Run("paste", func(t *testing.T) {
		dir := sandbox(t)
		seedGoogleClient(t, dir)
		seam := &googleSeam{}
		var out, errOut bytes.Buffer
		code := Run([]string{"account", "add", "mine", "--provider", "gmail", "--email", "ann@example.com", "--paste", "--access", "send"}, Env{
			Stdout: &out, Stderr: &errOut,
			GoogleOAuthConfig: fakeGoogleConfig(t, seam, tokens),
			OAuthConfig: func(string, string, string) (*oauth2.Config, error) {
				t.Error("a gmail sign-in used the Microsoft config")
				return nil, errors.New("not microsoft")
			},
			ReadLine: func(string) (string, error) { return googlePasteFor(t, &errOut), nil },
			Login:    func(context.Context, string) (string, error) { return "login ok\n", nil },
		})
		if code != exitOK {
			t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
		}
		check(t, dir, seam, "http://127.0.0.1:17777/callback", &out, &errOut)
	})

	t.Run("loopback", func(t *testing.T) {
		dir := sandbox(t)
		seedGoogleClient(t, dir)
		oldLoopback, oldBrowser := newLoopback, openBrowser
		t.Cleanup(func() { newLoopback, openBrowser = oldLoopback, oldBrowser })
		newLoopback = func(string, time.Duration) loopback { return codeLoopback{} }
		opened := ""
		openBrowser = func(u string) error { opened = u; return nil }

		seam := &googleSeam{}
		var out, errOut bytes.Buffer
		code := Run([]string{"account", "add", "mine", "--provider", "gmail", "--email", "ann@example.com", "--access", "send"}, Env{
			Stdout: &out, Stderr: &errOut,
			GoogleOAuthConfig: fakeGoogleConfig(t, seam, tokens),
			Login:             func(context.Context, string) (string, error) { return "login ok\n", nil },
		})
		if code != exitOK {
			t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
		}
		if !strings.Contains(opened, "redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback") {
			t.Errorf("the browser URL does not carry the loopback redirect: %q", opened)
		}
		if strings.Contains(errOut.String(), "[::1]") {
			t.Errorf("the gmail sign-in warned about ::1, but its redirect is 127.0.0.1 only:\n%s", errOut.String())
		}
		check(t, dir, seam, "http://127.0.0.1:54321/callback", &out, &errOut)
	})

	t.Run("no email", func(t *testing.T) {
		sandbox(t)
		var out, errOut bytes.Buffer
		code := Run([]string{"account", "add", "mine", "--provider", "gmail", "--paste"}, Env{Stdout: &out, Stderr: &errOut})
		if code != exitUsage {
			t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
		}
		if !strings.Contains(errOut.String(), "mailbag-mcp account add <alias> --provider gmail --email E [--paste]") {
			t.Errorf("the usage block does not hold the DS78.6 gmail line:\n%s", errOut.String())
		}
	})
}

// TestCLI_AccountAddGmailAPIOffRollsBack proves DS7.7 and DS78.9: when
// the login test meets [gmail.ErrAPIDisabled] or [gmail.ErrScope], the
// account block and the secret are removed again (B5), and the text is
// the fixed doctor reason, not the error text: the server words and
// the project number in the error never reach the terminal (IS7.5).
//
// arch: DS7.7, DS7.8, DS78.4, DS78.6, DS78.8, DS78.9, IS7.5, B5
func TestCLI_AccountAddGmailAPIOffRollsBack(t *testing.T) {
	cases := map[string]struct {
		err    error
		reason string
	}{
		"api off": {gmail.ErrAPIDisabled, gmailAPIOffReason},
		"scope":   {gmail.ErrScope, gmailScopeReason},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := sandbox(t)
			seedGoogleClient(t, dir)
			var out, errOut bytes.Buffer
			code := Run([]string{"account", "add", "mine", "--provider", "gmail", "--email", "ann@example.com", "--paste"}, Env{
				Stdout: &out, Stderr: &errOut,
				GoogleOAuthConfig: fakeGoogleConfig(t, &googleSeam{}, map[string]any{ //nolint:gosec // G101: a fake test value, not a real credential
					"access_token": "at-g", "refresh_token": "rt-gmail-2", "token_type": "Bearer", "expires_in": 3600,
				}),
				ReadLine: func(string) (string, error) { return googlePasteFor(t, &errOut), nil },
				Login: func(context.Context, string) (string, error) {
					return "", fmt.Errorf("list the folders: project 271000000001 says the service is off: %w", tc.err)
				},
			})
			if code != exitFail {
				t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
			}
			if hasAlias(t, dir, "mine") {
				t.Error("the account block stayed after the failed login")
			}
			if hasSecret(t, dir, "mine") {
				t.Error("the secret stayed after the failed login")
			}
			text := out.String() + errOut.String()
			if !strings.Contains(text, "was removed again: "+tc.reason) {
				t.Errorf("the output does not give the fixed reason %q:\n%s", tc.reason, text)
			}
			for _, leak := range []string{"271000000001", "says the service is off", "list the folders"} {
				if strings.Contains(text, leak) {
					t.Errorf("the output holds the error text %q:\n%s", leak, text)
				}
			}
			assertNoGoogleClientLeak(t, "output", text)
		})
	}
}

// TestCLI_ReauthGmail proves that --reauth works for a gmail account
// (DS7.8): it signs in with the Google config and the stored Google
// client, replaces the refresh token, leaves accounts.toml byte for
// byte as it was, and runs no login test.
//
// arch: DS7.7, DS7.8, DS78.4, DS78.6, DS78.8, DS78.9, IS7.5, B5
func TestCLI_ReauthGmail(t *testing.T) {
	dir := sandbox(t)
	seedGmailAccount(t, dir, "mine")
	seedGoogleClient(t, dir)
	before, err := os.ReadFile(filepath.Join(dir, "accounts.toml")) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read accounts.toml: %v", err)
	}

	seam := &googleSeam{}
	var out, errOut bytes.Buffer
	code := Run([]string{"account", "add", "mine", "--reauth", "--paste"}, Env{
		Stdout: &out, Stderr: &errOut,
		GoogleOAuthConfig: fakeGoogleConfig(t, seam, map[string]any{ //nolint:gosec // G101: a fake test value, not a real credential
			"access_token": "at-g", "refresh_token": "rt-gmail-new", "token_type": "Bearer", "expires_in": 3600,
		}),
		OAuthConfig: func(string, string, string) (*oauth2.Config, error) {
			t.Error("a gmail reauth used the Microsoft config")
			return nil, errors.New("not microsoft")
		},
		ReadLine: func(string) (string, error) { return googlePasteFor(t, &errOut), nil },
		Login: func(context.Context, string) (string, error) {
			t.Error("--reauth ran the live login test; it must only replace the secret")
			return "", nil
		},
	})
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if seam.calls == 0 || seam.redirect != googlePasteRedirectURL {
		t.Errorf("Google config calls = %d, redirect = %q; want the Google paste redirect", seam.calls, seam.redirect)
	}
	if seam.client.ClientID != gmailTestID {
		t.Errorf("the reauth did not use the stored Google client: %+v", seam.client)
	}
	after, err := os.ReadFile(filepath.Join(dir, "accounts.toml")) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read accounts.toml: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("--reauth changed accounts.toml:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if got := refreshTokenOf(t, dir, "mine"); got != "rt-gmail-new" {
		t.Errorf("stored refresh token = %q, want %q", got, "rt-gmail-new")
	}
	assertNoGoogleClientLeak(t, "output", out.String()+errOut.String())
}

// storedSecret reads back the JSON that the file store holds for alias.
func storedSecret(t *testing.T, dir, alias string) map[string]any {
	t.Helper()
	store, err := secrets.Select(secrets.KindFile, keyringService, dir)
	if err != nil {
		t.Fatalf("select the file store: %v", err)
	}
	raw, err := store.Get(alias)
	if err != nil {
		t.Fatalf("read the secret of %q: %v", alias, err)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("decode the secret of %q: %v", alias, err)
	}
	return v
}

// loadJMAPAccount loads accounts.toml from dir and gives the account
// alias, which must be a jmap account with no imap or smtp key.
func loadJMAPAccount(t *testing.T, dir, alias string) config.Account {
	t.Helper()
	path := filepath.Join(dir, "accounts.toml")
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read accounts.toml: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key := strings.TrimSpace(strings.SplitN(line, "=", 2)[0])
		if key == "imap" || key == "smtp" || key == "tenant" {
			t.Errorf("the jmap block holds the key %q:\n%s", key, raw)
		}
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load accounts.toml: %v", err)
	}
	acct, ok := cfg.Account(alias)
	if !ok {
		t.Fatalf("account %q was not written:\n%s", alias, raw)
	}
	if acct.Provider != "jmap" {
		t.Errorf("provider = %q, want jmap", acct.Provider)
	}
	return acct
}

// TestCLI_AccountAddJMAPBearer proves the --bearer branch of "account
// add --provider jmap" (DS8.6): the prompt is "API token:" through
// Env.ReadSecret, the secret is kind token, the block holds the
// session_url that was given and no private_host, and the token never
// reaches the terminal (B6).
//
// arch: DS8.6, DS78.4, DS78.6, DS78.8, IS8.1, B5, G11
func TestCLI_AccountAddJMAPBearer(t *testing.T) {
	dir := sandbox(t)
	const token = "fmu1-jmap-token-0123456789" //nolint:gosec // G101: a fake test value, not a real credential
	var prompts []string
	var out, errOut bytes.Buffer
	code := Run([]string{
		"account", "add", "home",
		"--provider", "jmap",
		"--email", "ann@example.com",
		"--session-url", "https://jmap.example.net/jmap/session",
		"--bearer",
		"--access", "send",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		ReadSecret: func(p string) (string, error) { prompts = append(prompts, p); return token, nil },
		Login: func(_ context.Context, alias string) (string, error) {
			if alias != "home" {
				t.Errorf("login alias = %q, want home", alias)
			}
			return "login ok\n", nil
		},
	})
	if code != exitOK {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
	}
	if len(prompts) != 1 || prompts[0] != "API token: " {
		t.Errorf("prompts = %q, want one \"API token: \"", prompts)
	}
	acct := loadJMAPAccount(t, dir, "home")
	if acct.SessionURL != "https://jmap.example.net/jmap/session" || acct.Email != "ann@example.com" || acct.Access != "send" || acct.PrivateHost {
		t.Errorf("account = %+v, want the given session URL, email, access send and no private_host", acct)
	}
	v := storedSecret(t, dir, "home")
	if v["kind"] != "token" || v["token"] != token {
		t.Errorf("secret = %v, want kind token with the typed token", v)
	}
	if _, ok := v["password"]; ok {
		t.Errorf("the token secret holds a password field: %v", v)
	}
	text := out.String() + errOut.String()
	if strings.Contains(text, token) {
		t.Errorf("the output holds the token:\n%s", text)
	}
	if !strings.Contains(out.String(), "login ok") || !strings.Contains(out.String(), `account "home" is ready`) {
		t.Errorf("the output does not hold the login report and the ready line:\n%s", out.String())
	}
}

// TestCLI_AccountAddJMAPPassword proves the branch without --bearer
// (DS8.6, F5): the prompt asks for the password of the address, the
// secret is kind password with the login name, and a login that the
// server refuses removes the block and the secret again (B5) without
// printing the password.
//
// arch: DS8.6, DS78.4, DS78.6, DS78.8, IS8.1, B5, G11
func TestCLI_AccountAddJMAPPassword(t *testing.T) {
	const password = "jmap-Passw0rd-xyz"
	args := []string{
		"account", "add", "home",
		"--provider", "jmap",
		"--email", "ann@example.com",
		"--session-url", "https://jmap.example.net/.well-known/jmap",
	}

	t.Run("ok", func(t *testing.T) {
		dir := sandbox(t)
		var prompt string
		var out, errOut bytes.Buffer
		code := Run(args, Env{
			Stdout: &out, Stderr: &errOut,
			ReadSecret: func(p string) (string, error) { prompt = p; return password, nil },
			Login:      func(context.Context, string) (string, error) { return "login ok\n", nil },
		})
		if code != exitOK {
			t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
		}
		if !strings.HasPrefix(prompt, "password for ann@example.com") {
			t.Errorf("prompt = %q, want the password prompt for the address", prompt)
		}
		acct := loadJMAPAccount(t, dir, "home")
		if acct.Access != "draft" || acct.Username != "ann@example.com" {
			t.Errorf("account = %+v, want access draft and the address as login name", acct)
		}
		v := storedSecret(t, dir, "home")
		if v["kind"] != "password" || v["password"] != password || v["username"] != "ann@example.com" {
			t.Errorf("secret = %v, want kind password with the address and the typed password", v)
		}
		if strings.Contains(out.String()+errOut.String(), password) {
			t.Errorf("the output holds the password:\n%s%s", out.String(), errOut.String())
		}
	})

	t.Run("refused login rolls back", func(t *testing.T) {
		dir := sandbox(t)
		var out, errOut bytes.Buffer
		code := Run(args, Env{
			Stdout: &out, Stderr: &errOut,
			ReadSecret: func(string) (string, error) { return password, nil },
			Login: func(context.Context, string) (string, error) {
				return "", fmt.Errorf("list the folders: %w", &jmap.AuthError{Status: 401})
			},
		})
		if code != exitFail {
			t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut.String())
		}
		if hasAlias(t, dir, "home") {
			t.Error("the account block stayed after the refused login")
		}
		if hasSecret(t, dir, "home") {
			t.Error("the secret stayed after the refused login")
		}
		text := out.String() + errOut.String()
		if !strings.Contains(text, `account "home" was removed again`) || !strings.Contains(text, "login refused by the server") {
			t.Errorf("the output does not say that the refused account was removed:\n%s", text)
		}
		if strings.Contains(text, password) {
			t.Errorf("the output holds the password:\n%s", text)
		}
	})
}

// TestCLI_AccountAddJMAPDefaultSessionURL proves the default of
// --session-url (G11): without the flag the block holds
// https://<domain of --email>/.well-known/jmap, the same URL that
// config.JMAPSessionURL gives, and the command says which URL it used.
// A session URL that is not https is a usage error that comes before
// the prompt and writes nothing.
//
// arch: DS8.6, DS78.4, DS78.6, DS78.8, IS8.1, B5, G11
func TestCLI_AccountAddJMAPDefaultSessionURL(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		dir := sandbox(t)
		var out, errOut bytes.Buffer
		code := Run([]string{"account", "add", "home", "--provider", "jmap", "--email", "ann@mail.example.org", "--bearer"}, Env{
			Stdout: &out, Stderr: &errOut,
			ReadSecret: func(string) (string, error) { return "tok-default", nil },
			Login:      func(context.Context, string) (string, error) { return "login ok\n", nil },
		})
		if code != exitOK {
			t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
		}
		const want = "https://mail.example.org/.well-known/jmap"
		acct := loadJMAPAccount(t, dir, "home")
		if acct.SessionURL != want {
			t.Errorf("session_url = %q, want %q", acct.SessionURL, want)
		}
		if got, err := config.JMAPSessionURL(config.Account{Email: acct.Email}); err != nil || got != want {
			t.Errorf("config.JMAPSessionURL = %q, %v; the CLI default and the config rule differ", got, err)
		}
		if !strings.Contains(out.String(), "session URL "+want) {
			t.Errorf("the output does not name the default session URL:\n%s", out.String())
		}
	})

	for name, u := range map[string]string{
		"http":    "http://mail.example.org/.well-known/jmap",
		"no host": "https:///.well-known/jmap",
	} {
		t.Run(name, func(t *testing.T) {
			dir := sandbox(t)
			var out, errOut bytes.Buffer
			code := Run([]string{"account", "add", "home", "--provider", "jmap", "--email", "ann@example.org", "--session-url", u}, Env{
				Stdout: &out, Stderr: &errOut,
				ReadSecret: func(string) (string, error) {
					t.Error("a bad --session-url reached the prompt")
					return "", nil
				},
			})
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
			}
			if !strings.Contains(errOut.String(), "mailbag-mcp account add <alias> --provider jmap --email E [--session-url U] [--bearer] [--private-host]") {
				t.Errorf("the usage block does not hold the DS78.6 jmap line:\n%s", errOut.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "accounts.toml")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a refused command wrote accounts.toml (stat: %v)", err)
			}
		})
	}
}

// privateAddr is the address that fakePrivateDNS gives for every name.
var privateAddr = [4]byte{10, 0, 0, 5}

// fakePrivateDNS points net.DefaultResolver at a DNS server in this
// process that answers every A question with privateAddr and every
// other question with no record. No packet leaves the process
// (IS78.1). The real Factory reads net.DefaultResolver when no test
// hook is set, so the private_host rule of the production path is
// what the test sees. tools.guardOptionsHook (DS78.11 G4) is not
// visible from this package.
func fakePrivateDNS(t *testing.T) {
	t.Helper()
	saved := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go serveFakeDNS(server)
			return client, nil
		},
	}
	t.Cleanup(func() { net.DefaultResolver = saved })
}

// serveFakeDNS answers DNS messages in the TCP framing (a 2-byte
// length first) on c until c closes. net.Pipe is not a PacketConn, so
// the Go resolver uses this framing for "udp" too.
func serveFakeDNS(c net.Conn) {
	defer func() { _ = c.Close() }()
	for {
		var size [2]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(msg)
		if err != nil {
			return
		}
		q, err := p.Question()
		if err != nil {
			return
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID: h.ID, Response: true, Authoritative: true,
			RecursionDesired: h.RecursionDesired, RecursionAvailable: true,
		})
		if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
			return
		}
		if q.Type == dnsmessage.TypeA {
			rh := dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}
			if b.AResource(rh, dnsmessage.AResource{A: privateAddr}) != nil {
				return
			}
		}
		answer, err := b.Finish()
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(size[:], uint16(len(answer))) //nolint:gosec // G115: a fake DNS answer is far below 65535 bytes
		if _, err := c.Write(append(size[:], answer...)); err != nil {
			return
		}
	}
}

// TestCLI_AccountAddJMAPPrivateHostRefusedWithoutKey proves G11 and
// IS8.1 through the real login path (Env.Login nil: the Factory, the
// JMAP client and the guarded HTTP client): a session host that
// resolves to a private address is refused when the account has no
// private_host, the error names the key and the alias, and the account
// is removed again (B5). With --private-host the block holds
// private_host = true and the command says what the key allows. The
// three jmap flags are refused for another provider.
//
// arch: DS8.6, DS78.4, DS78.6, DS78.8, IS8.1, B5, G11
func TestCLI_AccountAddJMAPPrivateHostRefusedWithoutKey(t *testing.T) {
	args := []string{
		"account", "add", "home",
		"--provider", "jmap",
		"--email", "ann@home.example",
		"--session-url", "https://jmap.home.example/.well-known/jmap",
		"--bearer",
	}

	t.Run("refused without the key", func(t *testing.T) {
		dir := sandbox(t)
		fakePrivateDNS(t)
		var out, errOut bytes.Buffer
		code := Run(args, Env{
			Stdout: &out, Stderr: &errOut,
			ReadSecret: func(string) (string, error) { return "tok-private", nil },
		})
		if code != exitFail {
			t.Fatalf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, exitFail, out.String(), errOut.String())
		}
		text := errOut.String()
		if !strings.Contains(text, "jmap.home.example resolves to a private address; set private_host = true for account home to allow it") {
			t.Errorf("the error does not name the private_host key:\n%s", text)
		}
		if !strings.Contains(text, `account "home" was removed again`) {
			t.Errorf("the error does not say that the account was removed:\n%s", text)
		}
		if hasAlias(t, dir, "home") {
			t.Error("the account block stayed after the refused dial")
		}
		if hasSecret(t, dir, "home") {
			t.Error("the secret stayed after the refused dial")
		}
	})

	t.Run("written with the key", func(t *testing.T) {
		dir := sandbox(t)
		var out, errOut bytes.Buffer
		code := Run(append(append([]string{}, args...), "--private-host"), Env{
			Stdout: &out, Stderr: &errOut,
			ReadSecret: func(string) (string, error) { return "tok-private", nil },
			Login:      func(context.Context, string) (string, error) { return "login ok\n", nil },
		})
		if code != exitOK {
			t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
		}
		if acct := loadJMAPAccount(t, dir, "home"); !acct.PrivateHost {
			t.Errorf("account = %+v, want private_host = true", acct)
		}
		if !strings.Contains(out.String(), `private_host = true: account "home" may reach jmap.home.example at a private network address`) {
			t.Errorf("the output does not say what private_host allows:\n%s", out.String())
		}
	})

	for _, flagArgs := range [][]string{{"--private-host"}, {"--bearer"}, {"--session-url", "https://jmap.example.net/"}} {
		t.Run("refused for imap "+flagArgs[0], func(t *testing.T) {
			sandbox(t)
			var out, errOut bytes.Buffer
			code := Run(append(addArgs("work"), flagArgs...), Env{
				Stdout: &out, Stderr: &errOut,
				ReadSecret: func(string) (string, error) {
					t.Error("a jmap flag on an imap account reached the prompt")
					return "", nil
				},
			})
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
			}
			if !strings.Contains(errOut.String(), flagArgs[0]+" is for --provider jmap only") {
				t.Errorf("the error does not name the jmap-only flag:\n%s", errOut.String())
			}
		})
	}
}

// dirNames gives the sorted names of the files in dir, for tests that
// prove a refused command wrote no file.
func dirNames(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return strings.Join(names, ",")
}

// TestCLI_AnswersStdin_WritesAccount proves that --answers-stdin gives
// the secret prompt its answer from one JSON document on stdin. The
// terminal reader is never asked, the secret goes to the store, and
// the secret is in no output.
//
// arch: DS13.5, IS13.2, IS13.6
func TestCLI_AnswersStdin_WritesAccount(t *testing.T) {
	cases := []struct {
		name string
		args []string
		kind string
	}{
		{"imap", addArgs("work"), "password"},
		{"jmap", []string{"account", "add", "work", "--provider", "jmap", "--email", "me@example.com", "--session-url", "https://jmap.example.com/session"}, "password"},
		{"jmap bearer", []string{"account", "add", "work", "--provider", "jmap", "--email", "me@example.com", "--session-url", "https://jmap.example.com/session", "--bearer"}, "token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := sandbox(t)
			var out, errOut bytes.Buffer
			const typed = "fake-stdin-value"
			code := Run(append(tc.args, "--answers-stdin"), Env{
				Stdout: &out, Stderr: &errOut,
				Stdin: strings.NewReader(`{"secret": "` + typed + `", "use_file_store": false}` + "\n"),
				ReadSecret: func(string) (string, error) {
					t.Error("the terminal secret reader ran although --answers-stdin was given")
					return "", errors.New("not used")
				},
				Login: func(context.Context, string) (string, error) { return "login ok\n", nil },
			})
			if code != exitOK {
				t.Fatalf("exit code = %d, want 0\nstderr: %s", code, errOut.String())
			}
			if !hasAlias(t, dir, "work") {
				t.Fatal("no account block was written")
			}
			v := storedSecret(t, dir, "work")
			if v["kind"] != tc.kind {
				t.Errorf("secret kind = %v, want %s", v["kind"], tc.kind)
			}
			if v["password"] != typed && v["token"] != typed {
				t.Errorf("the stored secret is not the one of the document: %v", v)
			}
			if strings.Contains(out.String()+errOut.String(), typed) {
				t.Errorf("the secret is in the output:\n%s%s", out.String(), errOut.String())
			}
		})
	}
}

// TestCLI_AnswersStdin_BadDocumentRefused proves the strict decode of
// DS13.5: an unknown field, a second document, a value of the wrong
// type, a document that is not an object, and a missing answer each
// stop the command with exit 2 before a file is written. No error text
// repeats the secret (IS13.2).
//
// arch: DS13.5, IS13.2, IS13.6
func TestCLI_AnswersStdin_BadDocumentRefused(t *testing.T) {
	const typed = "fake-refused-value"
	imap := addArgs("work")
	jmap := []string{"account", "add", "work", "--provider", "jmap", "--email", "me@example.com", "--session-url", "https://jmap.example.com/session"}
	gmail := []string{"account", "add", "work", "--provider", "gmail", "--email", "me@example.com"}
	cases := []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"unknown field", imap, `{"secret": "` + typed + `", "use_file_store": false, "password": "` + typed + `"}`, "unknown field"},
		{"unknown field named like the secret", imap, `{"` + typed + `": "x"}`, "unknown field"},
		{"two documents", imap, `{"secret": "` + typed + `"} {"secret": "` + typed + `"}`, "more than one JSON document"},
		{"trailing text", imap, `{"secret": "` + typed + `"} ` + typed, "more than one JSON document"},
		{"secret wrong type", imap, `{"secret": 1234}`, `"secret" has the wrong type`},
		{"use_file_store wrong type", imap, `{"secret": "` + typed + `", "use_file_store": "yes"}`, `"use_file_store" has the wrong type`},
		{"array", imap, `["` + typed + `"]`, "one JSON object"},
		{"null", imap, `null`, "one JSON object"},
		{"string", imap, `"` + typed + `"`, "one JSON object"},
		{"a line, not JSON", imap, typed + "\n", "one valid JSON document"},
		{"broken escape in the secret", imap, `{"secret": "` + typed + `\q"}`, "one valid JSON document"},
		{"empty stdin", imap, ``, "one valid JSON document"},
		{"cut-off document", imap, `{"secret": "` + typed, "one valid JSON document"},
		{"missing secret imap", imap, `{"use_file_store": false}`, "does not answer this prompt"},
		{"missing secret jmap", jmap, `{}`, "does not answer this prompt"},
		{"secret for gmail", gmail, `{"secret": "` + typed + `"}`, `must not hold "secret"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := sandbox(t)
			before := dirNames(t, dir)
			var out, errOut bytes.Buffer
			code := Run(append(append([]string{}, tc.args...), "--answers-stdin"), Env{
				Stdout: &out, Stderr: &errOut,
				Stdin: strings.NewReader(tc.stdin),
				Login: func(context.Context, string) (string, error) {
					t.Error("login ran although the document was refused")
					return "", nil
				},
			})
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
			}
			if !strings.HasPrefix(errOut.String(), "usage:") {
				t.Errorf("a usage error must start with a line that starts with \"usage:\":\n%s", errOut.String())
			}
			if !strings.Contains(errOut.String(), tc.want) {
				t.Errorf("stderr does not hold %q:\n%s", tc.want, errOut.String())
			}
			if strings.Contains(out.String()+errOut.String(), typed) {
				t.Errorf("the secret is in the output:\n%s%s", out.String(), errOut.String())
			}
			if after := dirNames(t, dir); after != before {
				t.Errorf("a refused document wrote a file: before [%s], after [%s]", before, after)
			}
		})
	}
}

// TestCLI_AnswersStdin_PasteUnanswered proves that a prompt the
// document cannot answer is an error and never a read from stdin: the
// --paste redirect URL stops the outlook sign-in with exit 2 and
// writes no file.
//
// arch: DS13.5, IS13.2, IS13.6
func TestCLI_AnswersStdin_PasteUnanswered(t *testing.T) {
	dir := sandbox(t)
	seedMicrosoftClientID(t, dir, "public-client-1")
	before := dirNames(t, dir)
	var out, errOut bytes.Buffer
	code := Run([]string{
		"account", "add", "work",
		"--provider", "outlook",
		"--email", "ann@contoso.com",
		"--paste", "--answers-stdin",
	}, Env{
		Stdout: &out, Stderr: &errOut,
		Stdin: strings.NewReader(`{"use_file_store": false}`),
		ReadLine: func(string) (string, error) {
			t.Error("the terminal line reader ran although --answers-stdin was given")
			return "", errors.New("not used")
		},
		Login: func(context.Context, string) (string, error) {
			t.Error("login ran although no redirect URL could be read")
			return "", nil
		},
	})
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut.String())
	}
	if !strings.Contains(errOut.String(), "does not answer this prompt") {
		t.Errorf("stderr does not name the unanswered prompt:\n%s", errOut.String())
	}
	if after := dirNames(t, dir); after != before {
		t.Errorf("a refused sign-in wrote a file: before [%s], after [%s]", before, after)
	}
}

// TestCLI_AnswersStdin_Confirm proves that use_file_store answers the
// file-store question of storeKind, and that a missing use_file_store
// is an error and never a default. The question comes only when the
// system keyring does not answer, so this test calls the Env.Confirm
// of the document directly.
//
// arch: DS13.5, IS13.2, IS13.6
func TestCLI_AnswersStdin_Confirm(t *testing.T) {
	for _, tc := range []struct {
		stdin string
		want  bool
		err   error
	}{
		{`{"use_file_store": true}`, true, nil},
		{`{"use_file_store": false}`, false, nil},
		{`{"secret": "s"}`, false, errUnanswered},
	} {
		doc, err := readAnswers(strings.NewReader(tc.stdin))
		if err != nil {
			t.Fatalf("%s: read: %v", tc.stdin, err)
		}
		got, err := doc.confirm("store the password in a file instead? [y/N] ")
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%s: confirm = %v, %v; want %v, %v", tc.stdin, got, err, tc.want, tc.err)
		}
	}
}

// TestCLI_AnswersStdin_OversizeRefused proves that the CLI reads at
// most maxAnswersBytes: a longer document is not one valid document.
//
// arch: DS13.5, IS13.2, IS13.6
func TestCLI_AnswersStdin_OversizeRefused(t *testing.T) {
	big := `{"secret": "` + strings.Repeat("a", maxAnswersBytes) + `"}`
	if _, err := readAnswers(strings.NewReader(big)); err == nil {
		t.Error("a document longer than maxAnswersBytes was accepted")
	}
}
