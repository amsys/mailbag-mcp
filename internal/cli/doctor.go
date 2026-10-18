// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file is "mailbag-mcp doctor" (T90). It runs the
// checks of 03-design-R1G.md DR1G.12 against the live config and the
// live server(s), using the same functions "account test" and serve
// use, so a human reads one answer for "is this installation set up
// right" with no state file of its own (OR1G.1, OR1G.6, IR1G.1).
//
// arch: DR1G.12, DR1G.18.9

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
	"github.com/amsys/mailbag-mcp/internal/secrets"
	"github.com/amsys/mailbag-mcp/internal/tools"
	"github.com/amsys/mailbag-mcp/internal/verify"
)

// doctor runs "mailbag-mcp doctor". It takes no arguments. Every line
// it prints is "ok <text>", "FAIL <text>" or, right after a FAIL, "Hint:
// <text>"; an "ok login <alias>" check line also carries the report
// lines of "account test", each indented by two spaces -- information,
// not a check of its own (DR1G.12, DR1G.18.9). The exit code is 0 when
// no line is FAIL, else 1 (DR1G.12 item 6).
//
// doctor writes no file: it takes the config and secret store as
// config.Load, secrets.Select and env.Login already leave them,
// through the one read path "account test" uses, and never writes
// accounts.toml or the state directory itself. The one exception,
// unchanged from "account test" today, is a secret store write that
// an oauth provider's own token rotation forces inside env.Login; a
// server left running would make the same write (IR1G.1, OR1G.6).
//
// arch: DR1G.12, DR1G.18.9, IR1G.1, IR1G.10
func doctor(args []string, env Env) int {
	if len(args) != 0 {
		return usageErrf(env, "doctor takes no arguments")
	}

	ok := true
	ctx := context.Background()

	path, err := config.AccountsPath()
	if err != nil {
		checkFail(env, "find the config directory", guard.Redact(err.Error()))
		return exitFail
	}

	info, statErr := os.Stat(path)
	if statErr != nil {
		checkFail(env, fmt.Sprintf("accounts.toml: cannot read %s", path),
			fmt.Sprintf(`run "mailbag-mcp account add" to create it (%s)`, guard.Redact(statErr.Error())))
		return exitFail
	}
	if info.Mode().Perm()&0o077 != 0 {
		checkFail(env, fmt.Sprintf("accounts.toml mode is %#o", info.Mode().Perm()), "chmod 600 "+path)
		ok = false
	} else {
		checkOK(env, "accounts.toml mode")
	}

	cfg, err := config.Load(path)
	if err != nil {
		checkFail(env, "accounts.toml parses", guard.Redact(err.Error()))
		return exitFail
	}
	checkOK(env, "accounts.toml parses")

	if cfg.Secrets() == secrets.KindFile {
		dir, err := config.ConfigDir()
		if err != nil {
			checkFail(env, "find the secret store directory", guard.Redact(err.Error()))
			ok = false
		} else if !checkFileStoreMode(env, dir, cfg.Aliases()) {
			ok = false
		}
	}

	if !doctorLogins(ctx, env, cfg) {
		ok = false
	}

	doctorToolsets(env, cfg)
	if !doctorVerify(ctx, env, cfg) {
		ok = false
	}
	if !doctorDecrypt(env, cfg) {
		ok = false
	}

	if ok {
		return exitOK
	}
	return exitFail
}

// checkOK prints one passing check line.
func checkOK(env Env, text string) {
	printf(env, "ok %s", text)
}

// checkFail prints one failing check line, then its fix hint on the
// next line, unless hint is empty (used only for a second FAIL line
// that has no hint of its own). No argument here may hold raw server
// text; every caller redacts or fences it first (DR1G.12 intro).
func checkFail(env Env, text, hint string) {
	printf(env, "FAIL %s", text)
	if hint != "" {
		printf(env, "Hint: %s", hint)
	}
}

// checkFileStoreMode is DR1G.12 check 1's file-store half: the
// directory config.ConfigDir gives is the same dir Factory.store
// passes to secrets.Select (DR1G.18.9), so this checks that directory
// and each key file of the store in it: a file named after an alias
// in aliases, or an "oauth." client key. Other files, such as a
// signature_file, hold no secret and are not checked (R16-L16). A
// directory that does not exist yet (no secret written there) is not
// a failure: there is nothing to read with the wrong mode. It prints
// exactly one check line.
func checkFileStoreMode(env Env, dir string, aliases []string) bool {
	keys := make(map[string]bool, len(aliases))
	for _, a := range aliases {
		keys[a] = true
	}
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		checkOK(env, "file store permissions")
		return true
	}
	bad := err != nil || info.Mode().Perm()&0o077 != 0
	if !bad {
		ents, rdErr := os.ReadDir(dir)
		if rdErr != nil {
			bad = true
		}
		for _, e := range ents {
			if !keys[e.Name()] && !strings.HasPrefix(e.Name(), "oauth.") {
				continue
			}
			fi, fiErr := e.Info()
			if fiErr != nil || !fi.Mode().IsRegular() {
				continue
			}
			if fi.Mode().Perm()&0o077 != 0 {
				bad = true
				break
			}
		}
	}
	if bad {
		checkFail(env, "file store permissions", fmt.Sprintf("chmod 700 %s; chmod 600 %s/*", dir, dir))
		return false
	}
	checkOK(env, "file store permissions")
	return true
}

// doctorLogins is DR1G.12 check 2: one "ok login <alias>" or "FAIL
// login <alias>: <reason>" line for each account in cfg, through
// env.Login -- the same function "account test" calls (DR1G.18.9).
// It reports whether every account passed.
func doctorLogins(ctx context.Context, env Env, cfg *config.Config) bool {
	ok := true
	for _, alias := range cfg.Aliases() {
		lctx, cancel := context.WithTimeout(ctx, loginTimeout)
		text, err := env.Login(lctx, alias)
		cancel()
		if err == nil {
			checkOK(env, "login "+alias)
			printReportLines(env, text)
			continue
		}
		ok = false
		reason, hint := loginFailure(alias, err)
		checkFail(env, "login "+alias+": "+reason, hint)
	}
	return ok
}

// printReportLines prints the report "account test" built for one
// account, each line indented by two spaces so it reads as
// information under the check line above it, never as a check of its
// own (DR1G.18.9).
func printReportLines(env Env, text string) {
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return
	}
	for _, line := range strings.Split(text, "\n") {
		printf(env, "  %s", line)
	}
}

// The fixed texts of DS78.4 for the two Gmail errors that the person
// must fix. They hold no project number and no server text (IS7.5).
// accountAddGmail prints the same reasons (DS7.7).
//
// arch: DS78.4, DS7.7, IS7.5
const (
	gmailAPIOffReason = "the Gmail API is not enabled in the Google Cloud project of the OAuth client"
	gmailAPIOffHint   = "enable gmail.googleapis.com there, or run mailbag-mcp oauth set google --file with a client whose project has it"
	gmailScopeReason  = "the OAuth client lacks the Gmail scopes"
)

// loginFailure classifies one env.Login error into the fixed reasons
// of DR1G.18.9: "sign-in expired", "login refused by the server" and
// "cannot connect", and the two Gmail reasons of DS78.4:
// [gmail.ErrAPIDisabled] and [gmail.ErrScope]. A [jmap.AuthError] (the
// JMAP server gave 401 to the token or the password) is "login refused
// by the server", the same reason as an [imap.AuthError] (DS78.4,
// DS78.11 G14). The reason is always
// one of these fixed texts and never holds server text. The two Gmail
// hints are fixed texts too. An expired Gmail sign-in
// ([oauthpkg.ErrGoogleNeedsAuth]) also names the 7-day cause of B9 in
// its hint. DR1G.18.9 gives a hint
// with the error text for "cannot connect" only. The owner ruled
// (R1G-judge L4) that "login refused by the server" also gets that
// hint, because it is the only text a person can act on. Both hints
// go through [serverText]: hidden characters are removed first, then
// secrets and paths are masked, so no raw server text reaches the
// terminal (DR1G.12 intro, DR1G.18.9).
//
// arch: DR1G.12, DR1G.18.9, DS78.4, DS78.9, DS78.11, IS7.5
func loginFailure(alias string, err error) (reason, hint string) {
	var authErr *imap.AuthError
	var jmapAuthErr *jmap.AuthError
	switch {
	case errors.Is(err, oauthpkg.ErrGoogleNeedsAuth):
		return "sign-in expired", fmt.Sprintf("mailbag-mcp account add %s --reauth. %s", alias, oauthpkg.GoogleTestingText)
	case errors.Is(err, oauthpkg.ErrNeedsAuth):
		return "sign-in expired", fmt.Sprintf("mailbag-mcp account add %s --reauth", alias)
	case errors.Is(err, gmail.ErrAPIDisabled):
		return gmailAPIOffReason, gmailAPIOffHint
	case errors.Is(err, gmail.ErrScope):
		return gmailScopeReason, fmt.Sprintf("sign in again with mailbag-mcp account add %s --reauth", alias)
	case errors.As(err, &authErr), errors.As(err, &jmapAuthErr):
		return "login refused by the server", serverText(err.Error())
	default:
		return "cannot connect", serverText(err.Error())
	}
}

// doctorToolsets is DR1G.12 check 3: the toolsets line of
// [tools.StatusLines], the same words serve logs at start (IR1G.10).
// It is never a FAIL: toolsets off by configuration is a normal state.
func doctorToolsets(env Env, cfg *config.Config) {
	toolsets, _ := tools.StatusLines(cfg)
	if len(toolsets) == 0 {
		checkOK(env, "toolsets: all on")
		return
	}
	for _, line := range toolsets {
		checkOK(env, line)
	}
}

// doctorVerify is DR1G.12 check 4: the [verify] block. It reports
// whether every part of it passed.
func doctorVerify(ctx context.Context, env Env, cfg *config.Config) bool {
	ok := true
	vcfg := cfg.Verify()

	if vcfg.AuthservID == "" {
		checkOK(env, "authserv_id: not set")
	} else {
		checkOK(env, "authserv_id: set")
	}

	switch vcfg.PGPKeysDir {
	case "":
		checkOK(env, "pgp_keys_dir: not set")
	default:
		if _, err := os.Stat(vcfg.PGPKeysDir); err != nil {
			checkFail(env, "pgp_keys_dir: "+vcfg.PGPKeysDir, "create the directory, or remove verify.pgp_keys_dir from accounts.toml")
			ok = false
		} else {
			checkOK(env, fmt.Sprintf("pgp_keys_dir: %d key(s)", len(verify.LoadKeyring(vcfg.PGPKeysDir))))
		}
	}

	if vcfg.SMIMECAFile == "" {
		checkOK(env, "smime_ca_file: not set")
	} else if f, err := os.Open(vcfg.SMIMECAFile); err != nil {
		checkFail(env, "smime_ca_file: "+vcfg.SMIMECAFile, guard.Redact(err.Error()))
		ok = false
	} else {
		_ = f.Close()
		checkOK(env, "smime_ca_file: readable")
	}

	if osslOK, reason := verify.OpensslStatus(ctx, vcfg); osslOK {
		checkOK(env, "openssl: usable for S/MIME")
	} else {
		checkFail(env, "openssl: "+reason, opensslHint(reason))
		ok = false
	}
	return ok
}

// opensslHint gives the fix for one [verify.OpensslStatus] reason
// word. It never repeats openssl output (I18): the reason is always
// one of the fixed words that function documents.
func opensslHint(reason string) string {
	switch reason {
	case "not_found":
		return "install openssl 3.x, or set verify.openssl_path"
	case "relative_path":
		return "set verify.openssl_path to an absolute path"
	case "no_store_flags":
		return "install an openssl 3.x build that has -no-CApath and -no-CAstore"
	default: // "not_openssl_3"
		return "install openssl 3.x"
	}
}

// doctorDecrypt is DR1G.12 check 5: the decrypt line of
// [tools.StatusLines] (IR1G.10), then gpg and gpgsm on PATH. A
// missing program is a FAIL only when decrypt is on; otherwise it is
// just a fact doctor reports, because D7.1 already requires every
// decrypt key to turn decrypt on, so "gpg missing, decrypt off" is
// not a problem a human must fix.
func doctorDecrypt(env Env, cfg *config.Config) bool {
	ok := true
	_, decrypt := tools.StatusLines(cfg)
	for _, line := range decrypt {
		checkOK(env, line)
	}
	decryptOn := len(cfg.DecryptMissing()) == 0
	for _, prog := range []string{"gpg", "gpgsm"} {
		if _, err := exec.LookPath(prog); err == nil {
			checkOK(env, prog+" on PATH")
			continue
		}
		if decryptOn {
			checkFail(env, prog+" not on PATH", "install "+prog+", or turn decrypt off in accounts.toml")
			ok = false
			continue
		}
		checkOK(env, prog+" not on PATH (decrypt is off)")
	}
	return ok
}
