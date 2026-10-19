// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/tools"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// fakeOpenPath builds a temporary directory that holds stand-in
// openssl, gpg and gpgsm programs, so a doctor test gets a
// deterministic "ok" from DR1G.12 checks 4 and 5 with no dependency
// on what this machine has installed. openssl answers "version" with
// a real OpenSSL 3.x line (so [verify.OpensslStatus] passes) and exits
// 0 for anything else (the -no-CApath/-no-CAstore probe). gpg and
// gpgsm only need to exist and be executable: doctor's check never
// runs them, only exec.LookPath finds them.
func fakeOpenPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'OpenSSL 3.0.2 15 Mar 2022'; exit 0; fi\nexit 0\n")
	ext := ""
	if runtime.GOOS == "windows" {
		// Windows runs no shell script; PATH lookup finds a .bat file.
		script = []byte("@echo off\r\nif \"%1\"==\"version\" echo OpenSSL 3.0.2 15 Mar 2022\r\nexit /b 0\r\n")
		ext = ".bat"
	}
	for _, name := range []string{"openssl", "gpg", "gpgsm"} {
		if err := os.WriteFile(filepath.Join(dir, name+ext), script, 0o700); err != nil { //nolint:gosec // G306: the test needs this mode: it runs a script, opens a dir, or checks a mode test
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// snapshotDir walks every entry under dir, file and subdirectory
// alike, and gives a map from its path relative to dir to a
// fingerprint of its content (files) or mode (directories), so a test
// can prove a run left the whole tree alone, not just its top level --
// IR1G.1's "file tree" comparison. A subdirectory doctor is not
// supposed to create still shows up as a diff, because its own entry
// is recorded, not skipped.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == dir {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			out[rel] = fmt.Sprintf("<dir>|%o", info.Mode().Perm())
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
		if err != nil {
			return err
		}
		out[rel] = fmt.Sprintf("%x|%o", data, info.Mode().Perm())
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// okLogin is an Env.Login that succeeds for every alias with a fixed,
// one-line report, so a test that only cares about the other checks
// does not need a fake provider.
func okLogin(context.Context, string) (string, error) {
	return "login ok\n", nil
}

// TestDoctor_WritesNoFile proves IR1G.1: a clean "doctor" run with a
// login that needs no token rotation leaves both the config directory
// (accounts.toml and the file secret store, which share one
// directory, DR1G.18.9) and the state directory (the server log and
// the undo journal, [config.StateDir]) byte for byte and mode for
// mode as it found them. The design names both directories
// ("a temp state and config directory"): doctor itself never reaches
// the state directory, but the test still isolates and snapshots it,
// so a future call that did reach it would fail here instead of
// leaking into this machine's real state directory.
//
// arch: DR1G.12, DR1G.18, IR1G.1
func TestDoctor_WritesNoFile(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))

	stateDir := t.TempDir()
	t.Setenv("MAILBAG_STATE_DIR", stateDir)

	beforeConfig := snapshotDir(t, dir)
	beforeState := snapshotDir(t, stateDir)

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Login: okLogin}
	Run([]string{"doctor"}, env)

	afterConfig := snapshotDir(t, dir)
	if !reflect.DeepEqual(beforeConfig, afterConfig) {
		t.Errorf("doctor changed the config directory:\nbefore: %v\nafter:  %v", beforeConfig, afterConfig)
	}
	afterState := snapshotDir(t, stateDir)
	if !reflect.DeepEqual(beforeState, afterState) {
		t.Errorf("doctor changed the state directory:\nbefore: %v\nafter:  %v", beforeState, afterState)
	}
}

// TestDoctor_StatusLinesSameAsServe proves IR1G.10: doctor's toolsets
// and decrypt lines are exactly the lines [tools.StatusLines] gives,
// the same function serve calls, with no second copy of the words.
//
// arch: DR1G.12, DR1G.18, IR1G.10
func TestDoctor_StatusLinesSameAsServe(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))

	path, err := config.AccountsPath()
	if err != nil {
		t.Fatalf("config.AccountsPath: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	wantToolsets, wantDecrypt := tools.StatusLines(cfg)

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Login: okLogin}
	Run([]string{"doctor"}, env)

	for _, line := range wantToolsets {
		if !strings.Contains(out.String(), "ok "+line) {
			t.Errorf("doctor output does not hold the serve toolsets line %q:\n%s", line, out.String())
		}
	}
	for _, line := range wantDecrypt {
		if !strings.Contains(out.String(), "ok "+line) {
			t.Errorf("doctor output does not hold the serve decrypt line %q:\n%s", line, out.String())
		}
	}
}

// TestDoctor_ModeCheck proves DR1G.12 check 1's accounts.toml mode
// test: a mode with group or other bits set fails with a chmod hint,
// and a correct mode passes.
//
// arch: DR1G.12, DR1G.18
func TestDoctor_ModeCheck(t *testing.T) {
	dir := sandbox(t)
	path := seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))

	t.Run("group-readable mode fails", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("reason: POSIX-only rule: Windows has no group or other mode bits")
		}
		if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // G302: the test needs this mode: it runs a script, opens a dir, or checks a mode test
			t.Fatal(err)
		}
		var out, errOut strings.Builder
		code := Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
		if code != exitFail {
			t.Errorf("exit code = %d, want %d", code, exitFail)
		}
		if !strings.Contains(out.String(), "FAIL accounts.toml mode is 0640") {
			t.Errorf("output does not report the bad mode:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "Hint: chmod 600 "+path) {
			t.Errorf("output does not hold the chmod hint:\n%s", out.String())
		}
	})

	t.Run("0600 passes", func(t *testing.T) {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errOut strings.Builder
		Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
		if !strings.Contains(out.String(), "ok accounts.toml mode") {
			t.Errorf("output does not report the good mode:\n%s", out.String())
		}
	})
}

// TestDoctor_FileStoreModes proves DR1G.12 check 1's file-store half
// (DR1G.18.9): the directory [config.ConfigDir] gives -- the same
// directory Factory.store passes to secrets.Select -- and each
// regular file in it must have no group or other bits, with one
// combined hint.
//
// arch: DR1G.12, DR1G.18
func TestDoctor_FileStoreModes(t *testing.T) {
	dir := sandbox(t)
	path := seedAccount(t, dir, "work")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// t.TempDir() itself is mode 0755 (group- and world-readable), not
	// the 0700 a real file-secrets directory must have; fix that here
	// so the two subtests isolate the file mode from the directory
	// mode.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the test needs this mode: it runs a script, opens a dir, or checks a mode test
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeOpenPath(t))

	secretFile := filepath.Join(dir, "work")

	t.Run("world-readable secret file fails", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("reason: POSIX-only rule: Windows has no group or other mode bits")
		}
		if err := os.WriteFile(secretFile, []byte("x"), 0o644); err != nil { //nolint:gosec // G306: the test needs this mode: it runs a script, opens a dir, or checks a mode test
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(secretFile) })

		var out, errOut strings.Builder
		code := Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
		if code != exitFail {
			t.Errorf("exit code = %d, want %d", code, exitFail)
		}
		if !strings.Contains(out.String(), "FAIL file store permissions") {
			t.Errorf("output does not report bad file store permissions:\n%s", out.String())
		}
		if !strings.Contains(out.String(), fmt.Sprintf("Hint: chmod 700 %s; chmod 600 %s/*", dir, dir)) {
			t.Errorf("output does not hold the combined chmod hint:\n%s", out.String())
		}
	})

	t.Run("0600 secret file passes", func(t *testing.T) {
		if err := os.WriteFile(secretFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(secretFile) })

		var out, errOut strings.Builder
		Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
		if !strings.Contains(out.String(), "ok file store permissions") {
			t.Errorf("output does not report good file store permissions:\n%s", out.String())
		}
	})
}

// TestDoctor_FileStoreModeOnlyKeys checks that the file-store mode
// check reads only the key files of the store: each account alias and
// the oauth client keys. A signature file at 0644 in the same
// directory is no secret and does not fail; an oauth key at 0644 does.
//
// arch: DR1G.12, B16, R16-L16
func TestDoctor_FileStoreModeOnlyKeys(t *testing.T) {
	dir := sandbox(t)
	path := seedAccount(t, dir, "work")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the test needs this mode: it runs a script, opens a dir, or checks a mode test
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeOpenPath(t))
	for name, mode := range map[string]os.FileMode{"work": 0o600, "oauth.google": 0o600, "signature.txt": 0o644} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, name), mode); err != nil {
			t.Fatal(err)
		}
	}

	var out, errOut strings.Builder
	Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
	if !strings.Contains(out.String(), "ok file store permissions") {
		t.Errorf("a 0644 signature file failed the file store check:\n%s", out.String())
	}

	if runtime.GOOS == "windows" {
		t.Skip("reason: POSIX-only rule: Windows has no group or other mode bits")
	}
	if err := os.Chmod(filepath.Join(dir, "oauth.google"), 0o644); err != nil { //nolint:gosec // G302: the test needs this mode: it runs a script, opens a dir, or checks a mode test
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
	if !strings.Contains(out.String(), "FAIL file store permissions") {
		t.Errorf("a 0644 oauth key file passed the file store check:\n%s", out.String())
	}
}

// TestDoctor_ModesNotCheckedOnWindows checks DF.7.5: with no mode
// bits to read (Windows), doctor reports the accounts.toml mode and the
// file store permissions as not checked, and a wide mode does not fail
// the run. The test sets modesChecked, so it runs on each system.
//
// arch: DF.7.5, DR1G.12
func TestDoctor_ModesNotCheckedOnWindows(t *testing.T) {
	old := modesChecked
	modesChecked = false
	t.Cleanup(func() { modesChecked = old })

	dir := sandbox(t)
	path := seedAccount(t, dir, "work")
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: the test needs a wide mode to show that it is not checked
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "work"), []byte("x"), 0o644); err != nil { //nolint:gosec // G306: the test needs a wide mode to show that it is not checked
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeOpenPath(t))

	var out, errOut strings.Builder
	code := Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
	if code != exitOK {
		t.Errorf("exit code = %d, want %d\noutput:\n%s", code, exitOK, out.String())
	}
	for _, line := range []string{"ok accounts.toml mode not checked on Windows", "ok file store permissions not checked on Windows"} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("output does not hold %q:\n%s", line, out.String())
		}
	}
}

// TestDoctor_LoginLineFormat proves DR1G.12 check 2 and DR1G.18.9's
// line shape: "ok login <alias>", then the account's report lines,
// each indented by two spaces as information, not a check.
//
// arch: DR1G.12, DR1G.18
func TestDoctor_LoginLineFormat(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(_ context.Context, alias string) (string, error) {
		if alias != "work" {
			t.Errorf("alias = %q, want work", alias)
		}
		return "login as ann at mail.example.com:993: ok\n2 folders:\n", nil
	}}
	Run([]string{"doctor"}, env)

	want := "ok login work\n  login as ann at mail.example.com:993: ok\n  2 folders:\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("output does not hold the formatted login block:\ngot:\n%s\nwant substring:\n%s", out.String(), want)
	}
}

// TestDoctor_NeedsAuthHint proves DR1G.12 and DR1G.18.9's
// sign-in-expired branch: [oauthpkg.ErrNeedsAuth] gives the fixed
// reason "sign-in expired" and the --reauth hint, tested with
// errors.Is as the design requires, never by matching error text.
//
// arch: DR1G.12, DR1G.18
func TestDoctor_NeedsAuthHint(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
		return "", fmt.Errorf("token refresh: %w", oauthpkg.ErrNeedsAuth)
	}}
	code := Run([]string{"doctor"}, env)

	if code != exitFail {
		t.Errorf("exit code = %d, want %d", code, exitFail)
	}
	if !strings.Contains(out.String(), "FAIL login work: sign-in expired") {
		t.Errorf("output does not hold the sign-in-expired FAIL line:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "Hint: mailbag-mcp account add work --reauth") {
		t.Errorf("output does not hold the --reauth hint:\n%s", out.String())
	}
}

// TestDoctor_GmailNeedsAuthNamesTesting proves B9 in doctor: the
// needs-auth error of a Gmail account gives the reason "sign-in
// expired" and a hint that names the --reauth fix and the 7-day cause
// of a consent screen in "Testing".
//
// arch: DR1G.12, DR1G.18, B9, R16-L20
func TestDoctor_GmailNeedsAuthNamesTesting(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
		return "", fmt.Errorf("list the folders: %w", oauthpkg.GoogleNeedsAuth("work"))
	}}
	Run([]string{"doctor"}, env)

	if !strings.Contains(out.String(), "FAIL login work: sign-in expired") {
		t.Errorf("output does not hold the sign-in-expired FAIL line:\n%s", out.String())
	}
	want := "Hint: mailbag-mcp account add work --reauth. " + oauthpkg.GoogleTestingText
	if !strings.Contains(out.String(), want) {
		t.Errorf("output does not hold the Gmail hint %q:\n%s", want, out.String())
	}
}

// TestDoctor_ExitCode proves DR1G.12 item 6: exit 0 when no line is
// FAIL, exit 1 when any line is FAIL (here, a failed login).
//
// arch: DR1G.12, DR1G.18
func TestDoctor_ExitCode(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	// t.TempDir() is mode 0755; a real file-secrets directory must be
	// 0700 (DR1G.12 check 1), so fix that here to isolate this test's
	// subject (the exit code) from the directory-mode check.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the test needs this mode: it runs a script, opens a dir, or checks a mode test
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeOpenPath(t))

	t.Run("all checks pass", func(t *testing.T) {
		var out, errOut strings.Builder
		code := Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})
		if code != exitOK {
			t.Errorf("exit code = %d, want %d\noutput:\n%s", code, exitOK, out.String())
		}
	})

	t.Run("a failed login fails the run", func(t *testing.T) {
		var out, errOut strings.Builder
		env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
			return "", errors.New("connection refused")
		}}
		code := Run([]string{"doctor"}, env)
		if code != exitFail {
			t.Errorf("exit code = %d, want %d\noutput:\n%s", code, exitFail, out.String())
		}
	})
}

// pgpTestKey makes a new OpenPGP entity for email, for
// TestDoctor_PGPKeysCountFromVerify fixtures only.
func pgpTestKey(t *testing.T, name, email string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", email, nil)
	if err != nil {
		t.Fatalf("new entity: %v", err)
	}
	return e
}

// TestDoctor_PGPKeysCountFromVerify proves L3: doctor's pgp_keys_dir
// line is len(verify.LoadKeyring(dir)), the same count [verify] uses
// to check an incoming signature, not a second reader of its own. The
// fixture dir holds an armored key, a binary key, a symlink to the
// armored key file (os.Stat follows it, unlike the DirEntry.Info the
// old doctor-only copy used) and a file over verify's size limit, so
// a doctor reader that still followed its own, different rules would
// print a different count here.
//
// arch: DR1G.12
func TestDoctor_PGPKeysCountFromVerify(t *testing.T) {
	dir := sandbox(t)
	t.Setenv("PATH", fakeOpenPath(t))

	keysDir := t.TempDir()
	alice := pgpTestKey(t, "Alice", "alice@example.com")
	bob := pgpTestKey(t, "Bob", "bob@example.com")

	var aliceArmored bytes.Buffer
	aw, err := armor.Encode(&aliceArmored, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.Serialize(aw); err != nil {
		t.Fatal(err)
	}
	_ = aw.Close()
	if err := os.WriteFile(filepath.Join(keysDir, "alice.asc"), aliceArmored.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var bobBin bytes.Buffer
	if err := bob.Serialize(&bobBin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "bob.gpg"), bobBin.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Join(keysDir, "alice.asc"), filepath.Join(keysDir, "link.asc")); err != nil {
		t.Fatal(err)
	}

	big := bytes.Repeat([]byte("x"), (1<<20)+1)
	if err := os.WriteFile(filepath.Join(keysDir, "big.asc"), big, 0o600); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "accounts.toml")
	text := `secrets = "file"

[verify]
pgp_keys_dir = "` + filepath.ToSlash(keysDir) + `"

[accounts.work]
provider = "imap"
email    = "me@example.com"
imap     = "mail.example.com:993"
smtp     = "mail.example.com:465"
`
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("seed accounts.toml: %v", err)
	}

	want := len(verify.LoadKeyring(keysDir))

	var out, errOut strings.Builder
	Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: okLogin})

	wantLine := fmt.Sprintf("ok pgp_keys_dir: %d key(s)", want)
	if !strings.Contains(out.String(), wantLine) {
		t.Errorf("output does not hold %q:\n%s", wantLine, out.String())
	}
}

// TestDoctor_NoRawServerText proves the DR1G.12 intro rule that no
// doctor line holds raw server text: a registered secret and a
// pattern-shaped token inside a login error both come out redacted,
// through the same [guard.Redact] every other CLI error uses.
//
// arch: DR1G.12, DR1G.18
func TestDoctor_NoRawServerText(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))

	const secret = "s3cretPassw0rd"
	guard.RegisterSecret(secret)

	t.Run("AuthError hint is redacted", func(t *testing.T) {
		var out, errOut strings.Builder
		env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
			return "", &imap.AuthError{Err: fmt.Errorf("server said: bad password %s", secret)}
		}}
		Run([]string{"doctor"}, env)

		if strings.Contains(out.String(), secret) {
			t.Errorf("output leaks the raw secret:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "FAIL login work: login refused by the server") {
			t.Errorf("output does not hold the login-refused FAIL line:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "<redacted>") {
			t.Errorf("output does not show the redaction marker:\n%s", out.String())
		}
	})

	t.Run("cannot-connect hint is redacted", func(t *testing.T) {
		var out, errOut strings.Builder
		env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
			return "", fmt.Errorf("dial tcp: Bearer %s", "abcdef0123456789")
		}}
		Run([]string{"doctor"}, env)

		if strings.Contains(out.String(), "Bearer abcdef0123456789") {
			t.Errorf("output leaks the raw bearer token:\n%s", out.String())
		}
		if !strings.Contains(out.String(), "FAIL login work: cannot connect") {
			t.Errorf("output does not hold the cannot-connect FAIL line:\n%s", out.String())
		}
	})
}

// hostileSecret is a registered secret that hostileServerText splits
// with a zero-width space. Only [serverText]'s order (strip first,
// then redact) joins it again before the redactor looks for it.
const hostileSecret = "h1ddenPassw0rd"

// hostileToken is a token-like value that [guard.Redact] masks by its
// shape, not by registration.
const hostileToken = "ya29.a0AfH6SMBhostile" //nolint:gosec // G101: a fake test value, not a real credential

// hostileServerText is server text that tries to take control of a
// terminal: an ESC colour sequence, a bidi override (U+202E), a
// token-like value and a registered secret split by U+200B.
const hostileServerText = "\x1b[31mNO \u202e[AUTHENTICATIONFAILED] " + hostileToken + " pw=h1dden\u200bPassw0rd\x1b[0m"

// assertCleanServerText fails t when text holds a hidden character of
// §3.15, the raw token or the raw secret of hostileServerText, or no
// redaction marker.
func assertCleanServerText(t *testing.T, name, text string) {
	t.Helper()
	if strings.ContainsRune(text, 0x1b) {
		t.Errorf("%s holds ESC:\n%q", name, text)
	}
	if _, n := guard.StripInvisible(text); n != 0 {
		t.Errorf("%s holds %d hidden character(s):\n%q", name, n, text)
	}
	if strings.Contains(text, hostileToken) {
		t.Errorf("%s leaks the raw token:\n%q", name, text)
	}
	if strings.Contains(text, hostileSecret) || strings.Contains(text, "h1dden") {
		t.Errorf("%s leaks the secret:\n%q", name, text)
	}
	if !strings.Contains(text, "<redacted>") {
		t.Errorf("%s holds no redaction marker:\n%q", name, text)
	}
}

// hasLine reports whether text holds want as one complete line.
func hasLine(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if line == want {
			return true
		}
	}
	return false
}

// TestDoctor_RefusalHintStripsInvisible proves R1G-judge L4 for a
// refused login: the reason is the fixed DR1G.18.9 text, and the hint
// that carries the *imap.AuthError text holds no hidden character and
// no raw secret.
//
// arch: DR1G.11, DR1G.12, DR1G.18, DR1G.18.9
func TestDoctor_RefusalHintStripsInvisible(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))
	guard.RegisterSecret(hostileSecret)

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
		return "", &imap.AuthError{Err: errors.New(hostileServerText)}
	}}
	Run([]string{"doctor"}, env)

	if !hasLine(out.String(), "FAIL login work: login refused by the server") {
		t.Errorf("output does not hold the exact login-refused FAIL line:\n%q", out.String())
	}
	assertCleanServerText(t, "doctor stdout", out.String())
}

// TestDoctor_ConnectHintStripsInvisible proves R1G-judge L4 for a
// dial error: the reason is the fixed DR1G.18.9 text "cannot
// connect", and the hint holds no hidden character and no raw secret.
//
// arch: DR1G.11, DR1G.12, DR1G.18, DR1G.18.9
func TestDoctor_ConnectHintStripsInvisible(t *testing.T) {
	dir := sandbox(t)
	seedAccount(t, dir, "work")
	t.Setenv("PATH", fakeOpenPath(t))
	guard.RegisterSecret(hostileSecret)

	var out, errOut strings.Builder
	env := Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
		return "", fmt.Errorf("dial tcp mail.example.com:993: %s", hostileServerText)
	}}
	Run([]string{"doctor"}, env)

	if !hasLine(out.String(), "FAIL login work: cannot connect") {
		t.Errorf("output does not hold the exact cannot-connect FAIL line:\n%q", out.String())
	}
	assertCleanServerText(t, "doctor stdout", out.String())
}

// runDoctorGmail runs doctor over one gmail account whose login fails
// with err, and gives the exit code and stdout.
func runDoctorGmail(t *testing.T, err error) (int, string) {
	t.Helper()
	dir := sandbox(t)
	seedGmailAccount(t, dir, "mine")
	t.Setenv("PATH", fakeOpenPath(t))
	var out, errOut strings.Builder
	code := Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
		return "", err
	}})
	return code, out.String() + errOut.String()
}

// TestDoctor_GmailAPIOff proves DS78.4 and DS78.9: a login that meets
// [gmail.ErrAPIDisabled] gives the fixed reason and the fixed hint,
// found with errors.Is through the wrapping of the login path. The
// project number and the server words in the error never reach the
// terminal (IS7.5).
//
// arch: DS7.7, DS7.8, DS78.4, DS78.6, DS78.8, DS78.9, IS7.5, B5
func TestDoctor_GmailAPIOff(t *testing.T) {
	code, text := runDoctorGmail(t, fmt.Errorf("list the folders: project 271000000002 has it off: %w", gmail.ErrAPIDisabled))
	if code != exitFail {
		t.Errorf("exit code = %d, want %d", code, exitFail)
	}
	if !hasLine(text, "FAIL login mine: the Gmail API is not enabled in the Google Cloud project of the OAuth client") {
		t.Errorf("output does not hold the API-off FAIL line:\n%s", text)
	}
	if !hasLine(text, "Hint: enable gmail.googleapis.com there, or run mailbag-mcp oauth set google --file with a client whose project has it") {
		t.Errorf("output does not hold the API-off hint:\n%s", text)
	}
	for _, leak := range []string{"271000000002", "has it off", "cannot connect"} {
		if strings.Contains(text, leak) {
			t.Errorf("output holds %q:\n%s", leak, text)
		}
	}
}

// TestDoctor_GmailScope proves DS78.4: a login that meets
// [gmail.ErrScope] gives the fixed scope reason and the --reauth hint
// for the alias, with no error text (IS7.5).
//
// arch: DS7.7, DS7.8, DS78.4, DS78.6, DS78.8, DS78.9, IS7.5, B5
func TestDoctor_GmailScope(t *testing.T) {
	code, text := runDoctorGmail(t, fmt.Errorf("list the folders: token lacks scope xyz-271000000003: %w", gmail.ErrScope))
	if code != exitFail {
		t.Errorf("exit code = %d, want %d", code, exitFail)
	}
	if !hasLine(text, "FAIL login mine: the OAuth client lacks the Gmail scopes") {
		t.Errorf("output does not hold the scope FAIL line:\n%s", text)
	}
	if !hasLine(text, "Hint: sign in again with mailbag-mcp account add mine --reauth") {
		t.Errorf("output does not hold the --reauth hint:\n%s", text)
	}
	for _, leak := range []string{"271000000003", "token lacks scope", "cannot connect"} {
		if strings.Contains(text, leak) {
			t.Errorf("output holds %q:\n%s", leak, text)
		}
	}
}

// TestDoctor_JMAPLoginRefused proves DS78.4 and DS78.11 G14: a login
// whose JMAP server refused the token or the password
// ([jmap.AuthError], found with errors.As through the wrapping of the
// login path) gives the fixed reason "login refused by the server",
// not "cannot connect", and doctor exits 1.
//
// arch: DS8.6, DS78.4, DS78.6, DS78.8, IS8.1, B5, G11
func TestDoctor_JMAPLoginRefused(t *testing.T) {
	dir := sandbox(t)
	text := `secrets = "file"

[accounts.home]
provider = "jmap"
email    = "ann@example.com"
access   = "draft"
session_url = "https://jmap.example.net/.well-known/jmap"
`
	if err := os.WriteFile(filepath.Join(dir, "accounts.toml"), []byte(text), 0o600); err != nil {
		t.Fatalf("seed accounts.toml: %v", err)
	}
	t.Setenv("PATH", fakeOpenPath(t))

	var out, errOut strings.Builder
	code := Run([]string{"doctor"}, Env{Stdout: &out, Stderr: &errOut, Login: func(context.Context, string) (string, error) {
		return "", fmt.Errorf("list the folders: jmap: api: %w", &jmap.AuthError{Status: 401})
	}})
	if code != exitFail {
		t.Errorf("exit code = %d, want %d", code, exitFail)
	}
	if !hasLine(out.String(), "FAIL login home: login refused by the server") {
		t.Errorf("output does not hold the login-refused FAIL line:\n%s", out.String())
	}
	if !hasLine(out.String(), "Hint: list the folders: jmap: api: jmap: login refused by the server (HTTP 401)") {
		t.Errorf("output does not hold the hint with the fixed error text:\n%s", out.String())
	}
	if strings.Contains(out.String(), "cannot connect") {
		t.Errorf("a refused JMAP login reads as a connect failure:\n%s", out.String())
	}
}
