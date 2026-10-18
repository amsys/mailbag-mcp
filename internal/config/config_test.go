// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAlias_Pattern checks the rule of B17: an alias becomes a keyring
// key, a file name and a part of a printed command, so it must match
// ^[a-zA-Z0-9_-]+$.
//
// arch: T1.2, §3.3, B17
func TestAlias_Pattern(t *testing.T) {
	valid := []string{"work", "home2", "hot-mail_alias", "A"}
	invalid := []string{"", "../../x", "a.b", "a b", "a/b", "a:b", "über"}

	for _, a := range valid {
		if !ValidAlias(a) {
			t.Errorf("ValidAlias(%q) = false, want true", a)
		}
	}
	for _, a := range invalid {
		if ValidAlias(a) {
			t.Errorf("ValidAlias(%q) = true, want false", a)
		}
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestConfig_Load_Defaults checks that a minimal file gets the
// documented defaults: secrets "keyring", tool_timeout 45s, account
// access "draft" (D4, D5, §3.1, §3.3).
//
// arch: T1.2, §3.3, §3.1, D14
func TestConfig_Load_Defaults(t *testing.T) {
	path := writeTemp(t, `
[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := c.Secrets(); got != "keyring" {
		t.Errorf("Secrets() = %q, want keyring", got)
	}
	if got := c.ToolTimeout(); got != 45*time.Second {
		t.Errorf("ToolTimeout() = %v, want 45s", got)
	}
	acc, ok := c.Account("work")
	if !ok {
		t.Fatalf("Account(work) not found")
	}
	if acc.Access != "draft" {
		t.Errorf("Access = %q, want draft", acc.Access)
	}
	if acc.Username != acc.Email {
		t.Errorf("Username = %q, want default of Email %q", acc.Username, acc.Email)
	}
}

// TestConfig_Load_RejectsInvalidAlias checks that the config loader
// enforces the alias pattern of B17, not only the CLI.
//
// arch: T1.2, §3.3, B17
func TestConfig_Load_RejectsInvalidAlias(t *testing.T) {
	path := writeTemp(t, `
[accounts."a.b"]
provider = "imap"
email    = "me@example.com"
`)
	_, err := Load(path)
	if !errors.Is(err, ErrInvalidAlias) {
		t.Fatalf("Load: err = %v, want ErrInvalidAlias", err)
	}
}

// TestConfig_Load_RejectsUnknownProvider checks the provider enum of
// §3.3 (imap | outlook | gmail | jmap).
//
// arch: T1.2, §3.3
func TestConfig_Load_RejectsUnknownProvider(t *testing.T) {
	path := writeTemp(t, `
[accounts.work]
provider = "yahoo"
email    = "me@example.com"
`)
	_, err := Load(path)
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("Load: err = %v, want ErrUnknownProvider", err)
	}
}

// TestConfig_Load_RejectsUnknownAccess checks the access enum of D5
// (read | draft | send).
//
// arch: T1.2, §3.3, D14
func TestConfig_Load_RejectsUnknownAccess(t *testing.T) {
	path := writeTemp(t, `
[accounts.work]
provider = "imap"
email    = "me@example.com"
access   = "admin"
`)
	_, err := Load(path)
	if !errors.Is(err, ErrUnknownAccess) {
		t.Fatalf("Load: err = %v, want ErrUnknownAccess", err)
	}
}

// TestConfig_Load_EmailMustBeBare checks that the account email is one
// bare address. A name form such as "Ann <me@example.com>" makes
// OwnsAddress("me@example.com") false and can reach the SMTP envelope.
//
// arch: T1.2, §3.3, R16-M10
func TestConfig_Load_EmailMustBeBare(t *testing.T) {
	for _, email := range []string{
		"Ann <me@example.com>",
		"<me@example.com>",
		"not an address",
	} {
		path := writeTemp(t, `
[accounts.work]
provider = "imap"
email    = "`+email+`"
`)
		_, err := Load(path)
		if !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("Load with email %q: err = %v, want ErrInvalidEmail", email, err)
		}
	}
}

// TestConfig_Refresh_PicksUpChange checks that the server reads
// accounts.toml again once its modification time changes, so a new
// account shows without a restart (§3.3).
//
// arch: T1.2, §3.3, §3.1
func TestConfig_Refresh_PicksUpChange(t *testing.T) {
	path := writeTemp(t, `
[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if changed, err := c.Refresh(); err != nil || changed {
		t.Fatalf("Refresh (unchanged) = (%v, %v), want (false, nil)", changed, err)
	}

	if err := os.WriteFile(path, []byte(`
[accounts.work]
provider = "imap"
email    = "me@example.com"

[accounts.home]
provider = "gmail"
email    = "me@gmail.com"
`), 0o600); err != nil {
		t.Fatalf("rewrite fixture: %v", err)
	}
	// Force a modification time strictly later than the first load, so
	// the test does not depend on filesystem timestamp resolution.
	future := time.Now().Add(time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	changed, err := c.Refresh()
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !changed {
		t.Fatalf("Refresh reported no change after the file changed")
	}
	if _, ok := c.Account("home"); !ok {
		t.Fatalf("Account(home) missing after Refresh")
	}
}

// TestConfig_ExtrasMigrationNamesOffSets checks the D2.1 migration: an
// accounts.toml with no extras key reports every known toolset name as
// off, since "modify" and "send" used to run with no extras entry at
// all and now need one.
//
// arch: D2.1
func TestConfig_ExtrasMigrationNamesOffSets(t *testing.T) {
	path := writeTemp(t, `
[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	known := []string{"modify", "send"}
	off := c.OffToolsets(known)
	if len(off) != 2 || off[0] != "modify" || off[1] != "send" {
		t.Errorf("OffToolsets(%v) = %v, want [modify send]", known, off)
	}
}

// TestConfig_ExtrasMigrationKeepsListedToolsetOn checks the other side
// of the D2.1 migration: naming a toolset in extras keeps it out of
// OffToolsets, and does not affect a name that is not in known.
//
// arch: D2.1
func TestConfig_ExtrasMigrationKeepsListedToolsetOn(t *testing.T) {
	path := writeTemp(t, `
extras = ["send", "bulk"]

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	off := c.OffToolsets([]string{"modify", "send"})
	if len(off) != 1 || off[0] != "modify" {
		t.Errorf("OffToolsets([modify send]) = %v, want [modify]", off)
	}
}

// TestConfig_Load_AcceptsModifyAndSendExtras checks that "modify" and
// "send" are valid extras entries (D2.1 migration): before this, only
// an operator who removed them from RegisterCore could turn them off,
// and accounts.toml had no way to name them at all.
//
// arch: D2.1
func TestConfig_Load_AcceptsModifyAndSendExtras(t *testing.T) {
	path := writeTemp(t, `
extras = ["modify", "send"]

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v, want modify and send to be known extras", err)
	}
	extras := c.Extras()
	if len(extras) != 2 || extras[0] != "modify" || extras[1] != "send" {
		t.Errorf("Extras() = %v, want [modify send]", extras)
	}
}

// TestPaths_EnvOverride checks that MAILBAG_CONFIG_DIR and
// MAILBAG_STATE_DIR replace the platform default, as §3.3 documents
// for tests.
//
// arch: T1.2, §3.3
func TestPaths_EnvOverride(t *testing.T) {
	cfg := t.TempDir()
	state := t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", cfg)
	t.Setenv("MAILBAG_STATE_DIR", state)

	if got, err := ConfigDir(); err != nil || got != cfg {
		t.Errorf("ConfigDir() = (%q, %v), want (%q, nil)", got, err, cfg)
	}
	if got, err := StateDir(); err != nil || got != state {
		t.Errorf("StateDir() = (%q, %v), want (%q, nil)", got, err, state)
	}
	want := filepath.Join(cfg, "accounts.toml")
	if got, err := AccountsPath(); err != nil || got != want {
		t.Errorf("AccountsPath() = (%q, %v), want (%q, nil)", got, err, want)
	}
}

// TestConfig_VerifyPathsAbsolute checks F-D5 (R1E-judge.md finding 6):
// pgp_keys_dir, smime_ca_file and openssl_path are refused at load when
// they are relative or "~"-prefixed, with ErrVerifyPathNotAbsolute; an
// empty value stays legal. It also parses every [verify] key on a
// success load, since no earlier test in this package touches [verify]
// at all.
//
// arch: D6.2
func TestConfig_VerifyPathsAbsolute(t *testing.T) {
	dir := t.TempDir()

	t.Run("all keys, absolute, load and carry through", func(t *testing.T) {
		path := writeTemp(t, `
[verify]
authserv_id     = "mx.example.net"
pgp_keys_dir    = "`+filepath.ToSlash(dir)+`"
smime_ca_file   = "`+filepath.ToSlash(dir)+`/ca.pem"
smime_crl_check = true
openssl_path    = "`+filepath.ToSlash(dir)+`/openssl"

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
		c, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		v := c.Verify()
		if v.AuthservID != "mx.example.net" {
			t.Errorf("AuthservID = %q, want mx.example.net", v.AuthservID)
		}
		if v.PGPKeysDir != dir {
			t.Errorf("PGPKeysDir = %q, want %q", v.PGPKeysDir, dir)
		}
		if v.SMIMECAFile != dir+"/ca.pem" {
			t.Errorf("SMIMECAFile = %q, want %q/ca.pem", v.SMIMECAFile, dir)
		}
		if !v.SMIMECRLCheck {
			t.Errorf("SMIMECRLCheck = false, want true")
		}
		if v.OpensslPath != dir+"/openssl" {
			t.Errorf("OpensslPath = %q, want %q/openssl", v.OpensslPath, dir)
		}
	})

	t.Run("empty paths stay legal", func(t *testing.T) {
		path := writeTemp(t, `
[verify]
authserv_id = "mx.example.net"

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
		if _, err := Load(path); err != nil {
			t.Fatalf("Load: %v, want empty [verify] paths to be legal", err)
		}
	})

	relative := []string{"keys", "./keys", "../keys", "~/keys", "~"}
	keys := []string{"pgp_keys_dir", "smime_ca_file", "openssl_path"}
	for _, key := range keys {
		for _, val := range relative {
			t.Run(key+"="+val, func(t *testing.T) {
				path := writeTemp(t, `
[verify]
`+key+` = "`+val+`"

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
				_, err := Load(path)
				if !errors.Is(err, ErrVerifyPathNotAbsolute) {
					t.Fatalf("Load: err = %v, want ErrVerifyPathNotAbsolute", err)
				}
			})
		}
	}
}

// TestDecrypt_ThreeKeys checks the D7.1 switch. Extras holds "decrypt"
// only when extras names it and both [decrypt] keys are true. With
// fewer keys, Extras has no "decrypt", OffToolsets names it, and
// DecryptMissing names each key that is not set. A reload that clears
// one key removes "decrypt" from Extras again. Serve and its toolset
// watcher give Extras to tools.RegisterToolsets, so no decrypt tool
// can exist without all three keys (I13).
//
// arch: D7.1
func TestDecrypt_ThreeKeys(t *testing.T) {
	file := func(extra, enabled, ack bool) string {
		s := ""
		if extra {
			s += "extras = [\"send\", \"decrypt\"]\n"
		} else {
			s += "extras = [\"send\"]\n"
		}
		s += fmt.Sprintf("\n[decrypt]\nenabled = %t\nack_plaintext_reaches_model_provider = %t\n", enabled, ack)
		s += "\n[accounts.work]\nprovider = \"imap\"\nemail    = \"me@example.com\"\n"
		return s
	}
	has := func(list []string, name string) bool {
		for _, e := range list {
			if e == name {
				return true
			}
		}
		return false
	}

	for mask := 0; mask < 8; mask++ {
		extra, enabled, ack := mask&1 != 0, mask&2 != 0, mask&4 != 0
		name := fmt.Sprintf("extra=%t,enabled=%t,ack=%t", extra, enabled, ack)
		t.Run(name, func(t *testing.T) {
			c, err := Load(writeTemp(t, file(extra, enabled, ack)))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			var want []string
			if !extra {
				want = append(want, DecryptKeyExtras)
			}
			if !enabled {
				want = append(want, DecryptKeyEnabled)
			}
			if !ack {
				want = append(want, DecryptKeyAck)
			}
			got := c.DecryptMissing()
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("DecryptMissing() = %v, want %v", got, want)
			}
			allSet := extra && enabled && ack
			if on := has(c.Extras(), "decrypt"); on != allSet {
				t.Errorf("Extras() = %v: decrypt on = %t, want %t", c.Extras(), on, allSet)
			}
			if !has(c.Extras(), "send") {
				t.Errorf("Extras() = %v, want send kept", c.Extras())
			}
			if off := has(c.OffToolsets([]string{"decrypt", "send"}), "decrypt"); off == allSet {
				t.Errorf("OffToolsets names decrypt = %t, want %t", off, !allSet)
			}
		})
	}

	// No [decrypt] table at all: both keys default to false.
	t.Run("no decrypt table", func(t *testing.T) {
		c, err := Load(writeTemp(t, "extras = [\"decrypt\"]\n\n[accounts.work]\nprovider = \"imap\"\nemail    = \"me@example.com\"\n"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if has(c.Extras(), "decrypt") {
			t.Errorf("Extras() = %v, want no decrypt", c.Extras())
		}
		want := []string{DecryptKeyEnabled, DecryptKeyAck}
		if got := c.DecryptMissing(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("DecryptMissing() = %v, want %v", got, want)
		}
	})

	// A reload that clears one key turns decrypt off. The toolset
	// watcher calls Sync with the new Extras after each Refresh.
	t.Run("reload clears key", func(t *testing.T) {
		path := writeTemp(t, file(true, true, true))
		c, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !has(c.Extras(), "decrypt") {
			t.Fatalf("Extras() = %v, want decrypt on with all three keys", c.Extras())
		}
		if err := os.WriteFile(path, []byte(file(true, true, false)), 0o600); err != nil {
			t.Fatalf("rewrite: %v", err)
		}
		future := time.Now().Add(time.Second)
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
		if changed, err := c.Refresh(); err != nil || !changed {
			t.Fatalf("Refresh = (%v, %v), want (true, nil)", changed, err)
		}
		if has(c.Extras(), "decrypt") {
			t.Errorf("Extras() after reload = %v, want no decrypt", c.Extras())
		}
		if got := c.DecryptMissing(); fmt.Sprint(got) != fmt.Sprint([]string{DecryptKeyAck}) {
			t.Errorf("DecryptMissing() after reload = %v, want [%s]", got, DecryptKeyAck)
		}
	})
}

// TestLoad_UnknownKey checks ORV.2: a key accounts.toml holds that
// this build does not know is an error that names the key and its
// table, not a silent default. A typo such as "acess" must not leave
// the account at "draft", which allows more than the human wrote.
//
// arch: DRV.14a
func TestLoad_UnknownKey(t *testing.T) {
	path := writeTemp(t, `
[accounts.work]
provider = "imap"
email    = "me@example.com"
acess    = "read"
`)
	_, err := Load(path)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Load: err = %v, want ErrUnknownKey", err)
	}
	if !strings.Contains(err.Error(), "acess") {
		t.Errorf("Load: err = %q, want it to name the key %q", err, "acess")
	}
	if !strings.Contains(err.Error(), "accounts.work") {
		t.Errorf("Load: err = %q, want it to name the table %q", err, "accounts.work")
	}
}

// TestLoad_BadSaveSent checks DRV.14a: save_sent accepts "always",
// "never" and "auto" only. Any other value is an error, not a silent
// fall-back to "auto" (today's bug).
//
// arch: DRV.14a
func TestLoad_BadSaveSent(t *testing.T) {
	path := writeTemp(t, `
[accounts.work]
provider  = "imap"
email     = "me@example.com"
save_sent = "sometimes"
`)
	_, err := Load(path)
	if !errors.Is(err, ErrUnknownSaveSent) {
		t.Fatalf("Load: err = %v, want ErrUnknownSaveSent", err)
	}
}

// TestLoad_ToolTimeoutRange checks ORV.3: tool_timeout is wired, with
// an allowed range of 5s to 10m. A value outside it is a config
// error, and the boundary values themselves load.
//
// arch: DRV.14a
func TestLoad_ToolTimeoutRange(t *testing.T) {
	tooShort := writeTemp(t, `
tool_timeout = "4s"

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	if _, err := Load(tooShort); !errors.Is(err, ErrToolTimeoutRange) {
		t.Fatalf("Load(4s): err = %v, want ErrToolTimeoutRange", err)
	}

	tooLong := writeTemp(t, `
tool_timeout = "11m"

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	if _, err := Load(tooLong); !errors.Is(err, ErrToolTimeoutRange) {
		t.Fatalf("Load(11m): err = %v, want ErrToolTimeoutRange", err)
	}

	atBounds := writeTemp(t, `
tool_timeout = "5s"

[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	c, err := Load(atBounds)
	if err != nil {
		t.Fatalf("Load(5s): %v", err)
	}
	if got := c.ToolTimeout(); got != 5*time.Second {
		t.Errorf("ToolTimeout() = %v, want 5s", got)
	}
}

// TestLoad_PrivateHostJMAPOnly checks the private_host key (DS8.6, G11).
// A jmap account loads with private_host = true and carries it into
// Account. Another provider with private_host = true fails to load with
// ErrPrivateHostNotJMAP, and the error names the alias. The false
// default loads on every provider, so the imap example block of the
// template can show the key.
//
// arch: DS8.6, G11
func TestLoad_PrivateHostJMAPOnly(t *testing.T) {
	t.Run("jmap with true loads", func(t *testing.T) {
		c, err := Load(writeTemp(t, `
[accounts.home]
provider     = "jmap"
email        = "me@example.com"
session_url  = "https://mail.example.com/.well-known/jmap"
private_host = true
`))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		acc, ok := c.Account("home")
		if !ok {
			t.Fatalf("Account(home) not found")
		}
		if !acc.PrivateHost {
			t.Errorf("PrivateHost = false, want true")
		}
	})

	t.Run("jmap without the key defaults to false", func(t *testing.T) {
		c, err := Load(writeTemp(t, `
[accounts.home]
provider = "jmap"
email    = "me@example.com"
`))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if acc, _ := c.Account("home"); acc.PrivateHost {
			t.Errorf("PrivateHost = true, want the false default")
		}
	})

	for _, provider := range []string{"imap", "outlook", "gmail"} {
		t.Run(provider+" with true is refused", func(t *testing.T) {
			_, err := Load(writeTemp(t, `
[accounts.work]
provider     = "`+provider+`"
email        = "me@example.com"
private_host = true
`))
			if !errors.Is(err, ErrPrivateHostNotJMAP) {
				t.Fatalf("Load: err = %v, want ErrPrivateHostNotJMAP", err)
			}
			if !strings.Contains(err.Error(), `"work"`) {
				t.Errorf("Load: err = %q, want it to name the alias %q", err, "work")
			}
		})
	}

	t.Run("imap with false loads", func(t *testing.T) {
		if _, err := Load(writeTemp(t, `
[accounts.work]
provider     = "imap"
email        = "me@example.com"
private_host = false
`)); err != nil {
			t.Fatalf("Load: %v, want private_host = false to load on imap", err)
		}
	})
}

// TestLoad_SessionURLMustBeHTTPS checks the session_url rules (DS8.6)
// and the default session URL rule of JMAPSessionURL (DS78.11 G11). A
// session_url that is set must be an https URL with a host, on any
// provider. A jmap account without session_url needs a domain in its
// email; JMAPSessionURL then gives https://<domain>/.well-known/jmap.
// The error does not hold the URL text.
//
// arch: DS8.6, G11
func TestLoad_SessionURLMustBeHTTPS(t *testing.T) {
	jmapFile := func(email, sessionURL string) string {
		s := "[accounts.home]\nprovider = \"jmap\"\nemail = \"" + email + "\"\n"
		if sessionURL != "" {
			s += "session_url = \"" + sessionURL + "\"\n"
		}
		return s
	}

	refused := []string{
		"http://mail.example.com/.well-known/jmap",
		"ftp://mail.example.com/jmap",
		"mail.example.com/.well-known/jmap",
		"https://",
		"https://:443/jmap",
		"https:mail.example.com",
		"//mail.example.com/jmap",
	}
	for _, u := range refused {
		t.Run("refused "+u, func(t *testing.T) {
			_, err := Load(writeTemp(t, jmapFile("me@example.com", u)))
			if !errors.Is(err, ErrSessionURLNotHTTPS) {
				t.Fatalf("Load: err = %v, want ErrSessionURLNotHTTPS", err)
			}
			if !strings.Contains(err.Error(), `"home"`) {
				t.Errorf("Load: err = %q, want it to name the alias %q", err, "home")
			}
		})
	}

	t.Run("refused on another provider too", func(t *testing.T) {
		_, err := Load(writeTemp(t, `
[accounts.work]
provider    = "imap"
email       = "me@example.com"
session_url = "http://mail.example.com/jmap"
`))
		if !errors.Is(err, ErrSessionURLNotHTTPS) {
			t.Fatalf("Load: err = %v, want ErrSessionURLNotHTTPS", err)
		}
	})

	t.Run("error does not hold the URL", func(t *testing.T) {
		_, err := Load(writeTemp(t, jmapFile("me@example.com", "http://user:s3cret@mail.example.com/jmap")))
		if !errors.Is(err, ErrSessionURLNotHTTPS) {
			t.Fatalf("Load: err = %v, want ErrSessionURLNotHTTPS", err)
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("Load: err = %q holds the URL text", err)
		}
	})

	t.Run("https session_url is kept", func(t *testing.T) {
		const u = "https://jmap.example.net:8443/.well-known/jmap"
		c, err := Load(writeTemp(t, jmapFile("me@example.com", u)))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		acc, _ := c.Account("home")
		if acc.SessionURL != u {
			t.Errorf("SessionURL = %q, want %q", acc.SessionURL, u)
		}
		if got, err := JMAPSessionURL(acc); err != nil || got != u {
			t.Errorf("JMAPSessionURL = (%q, %v), want (%q, nil)", got, err, u)
		}
	})

	t.Run("default from the email domain", func(t *testing.T) {
		c, err := Load(writeTemp(t, jmapFile("me@example.com", "")))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		acc, _ := c.Account("home")
		const want = "https://example.com/.well-known/jmap"
		if got, err := JMAPSessionURL(acc); err != nil || got != want {
			t.Errorf("JMAPSessionURL = (%q, %v), want (%q, nil)", got, err, want)
		}
	})

	for _, email := range []string{"me", "me@", "me@example.com/x", "me@exa mple.com", "me@:443"} {
		t.Run("no session_url and no domain in "+email, func(t *testing.T) {
			_, err := Load(writeTemp(t, jmapFile(email, "")))
			if !errors.Is(err, ErrJMAPNoSessionURL) {
				t.Fatalf("Load: err = %v, want ErrJMAPNoSessionURL", err)
			}
		})
	}

	t.Run("JMAPSessionURL refuses http", func(t *testing.T) {
		_, err := JMAPSessionURL(Account{Provider: "jmap", Email: "me@example.com", SessionURL: "http://example.com/jmap"})
		if !errors.Is(err, ErrSessionURLNotHTTPS) {
			t.Fatalf("JMAPSessionURL: err = %v, want ErrSessionURLNotHTTPS", err)
		}
	})
}

// TestLoad_BulkAllowWithoutElicitation checks the [bulk] table (DS9.4
// step 6). Its one key, allow_without_elicitation, is copied into each
// account, as the [send] key is. The default is false. The two keys are
// separate: one of them set to true does not set the other.
//
// arch: DS9.1, DS9.4, DS9.8
func TestLoad_BulkAllowWithoutElicitation(t *testing.T) {
	const accounts = `
[accounts.work]
provider = "imap"
email    = "me@example.com"

[accounts.home]
provider = "imap"
email    = "me@example.org"
`
	cases := []struct {
		name     string
		head     string
		wantBulk bool
		wantSend bool
	}{
		{"no tables gives false", "", false, false},
		{"bulk true", "[bulk]\nallow_without_elicitation = true\n", true, false},
		{"bulk false", "[bulk]\nallow_without_elicitation = false\n", false, false},
		{"send true leaves bulk false", "[send]\nallow_without_elicitation = true\n", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Load(writeTemp(t, c.head+accounts))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			for _, alias := range []string{"work", "home"} {
				acc, ok := cfg.Account(alias)
				if !ok {
					t.Fatalf("Account(%s) not found", alias)
				}
				if acc.BulkAllowWithoutElicitation != c.wantBulk {
					t.Errorf("%s: BulkAllowWithoutElicitation = %v, want %v", alias, acc.BulkAllowWithoutElicitation, c.wantBulk)
				}
				if acc.AllowWithoutElicitation != c.wantSend {
					t.Errorf("%s: AllowWithoutElicitation = %v, want %v", alias, acc.AllowWithoutElicitation, c.wantSend)
				}
			}
		})
	}

	t.Run("unknown key in [bulk] is refused", func(t *testing.T) {
		_, err := Load(writeTemp(t, "[bulk]\nallow_without_elicitaton = true\n"+accounts))
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("Load: err = %v, want ErrUnknownKey", err)
		}
	})
}

// idDoc is the arch line that every identity test cites.
const idDoc = "arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6"

// idLoad loads a one-account file whose body is appended to a flat
// account header, and returns the account or the load error.
func idLoad(t *testing.T, body string) (Account, error) {
	t.Helper()
	c, err := Load(writeTemp(t, "[accounts.w]\nprovider = \"imap\"\nemail = \"me@example.com\"\n"+body))
	if err != nil {
		return Account{}, err
	}
	a, ok := c.Account("w")
	if !ok {
		t.Fatal("account w missing")
	}
	return a, nil
}

// TestIdentity_DefaultsAndMerge checks the R6 defaults, the DI1.5 merge
// order and the Account.Identities additions.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestIdentity_DefaultsAndMerge(t *testing.T) {
	a, err := idLoad(t, `
identities = ["Flat Two <flat@example.com>", "ME2@example.com"]
[[accounts.w.identity]]
email = "me2@example.com"
name = "Two"
signature = "\n-- \nBest\nTwo\n\n"
reply_match = ["*@Example.com"]
[[accounts.w.identity]]
email = "tab@example.com"
signature_on_forward = true
signature_below_quote = true
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !a.IdentityMode() {
		t.Fatal("IdentityMode() = false, want true")
	}
	var order []string
	for _, id := range a.IdentityList {
		order = append(order, id.Email)
	}
	want := []string{"me2@example.com", "tab@example.com", "flat@example.com", "me@example.com"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("IdentityList order = %v, want %v (%s)", order, want, idDoc)
	}
	two, _ := a.Identity("ME2@EXAMPLE.COM")
	if two.Signature != "Best\nTwo" || two.Name != "Two" {
		t.Errorf("table 0 = %+v", two)
	}
	if !two.OnNew || !two.OnReply || two.OnForward || !two.ReplyAboveQuote || two.SignatureBelowQuote || two.ComposeHTML {
		t.Errorf("defaults wrong: %+v", two)
	}
	if len(two.ReplyMatch) != 1 || two.ReplyMatch[0] != "*@example.com" {
		t.Errorf("ReplyMatch = %v, want lower case", two.ReplyMatch)
	}
	tab, _ := a.Identity("tab@example.com")
	if !tab.OnForward || !tab.SignatureBelowQuote {
		t.Errorf("explicit keys lost: %+v", tab)
	}
	wantFlat := []string{"Flat Two <flat@example.com>", "ME2@example.com", "tab@example.com"}
	if strings.Join(a.Identities, "|") != strings.Join(wantFlat, "|") {
		t.Errorf("Identities = %v, want %v", a.Identities, wantFlat)
	}
}

// TestIdentity_ModeOff checks that the flat list alone leaves identity
// mode off, keeps the list as written and gives no IdentityList.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestIdentity_ModeOff(t *testing.T) {
	a, err := idLoad(t, "identities = [\"x@example.com\"]\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if a.IdentityMode() || a.IdentityList != nil || a.DefaultIdentity != "" {
		t.Errorf("flat account in identity mode: %+v", a)
	}
	if len(a.Identities) != 1 || a.Identities[0] != "x@example.com" {
		t.Errorf("Identities = %v", a.Identities)
	}
	if !a.OwnsAddress("X@example.com") || a.OwnsAddress("other@example.com") {
		t.Error("OwnsAddress must keep the raw compare outside identity mode")
	}
	d := a.Default()
	if d.Email != "me@example.com" || d.Signature != "" || !d.OnNew {
		t.Errorf("Default() = %+v", d)
	}
}

// TestIdentity_DefaultIdentityOnly checks that default_identity alone
// turns identity mode on and the default is found.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestIdentity_DefaultIdentityOnly(t *testing.T) {
	a, err := idLoad(t, "default_identity = \"ME@example.com\"\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !a.IdentityMode() {
		t.Error("IdentityMode() = false, want true")
	}
	if a.Default().Email != "me@example.com" {
		t.Errorf("Default() = %+v", a.Default())
	}
}

// TestIdentity_DefaultIdentityFlatEntry checks that default_identity may
// name a flat identities entry, in any letter case.
//
// arch: DI2.0, DI1.5
func TestIdentity_DefaultIdentityFlatEntry(t *testing.T) {
	a, err := idLoad(t, "identities = [\"Flat <flat@example.com>\"]\ndefault_identity = \"FLAT@example.com\"\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !a.IdentityMode() {
		t.Error("IdentityMode() = false, want true")
	}
	if d := a.Default(); d.Email != "flat@example.com" {
		t.Errorf("Default() = %+v, want flat@example.com", d)
	}
}

// TestIdentity_LoadRefuses checks every DI1.3 refusal and that the
// error names the account and the key.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestIdentity_LoadRefuses(t *testing.T) {
	long := strings.Repeat("a", 1001)
	cases := []struct{ name, body, key string }{
		{"email name part", `[[accounts.w.identity]]
email = "A <a@example.com>"`, "email"},
		{"email empty", `[[accounts.w.identity]]
name = "x"`, "email"},
		{"duplicate email", `[[accounts.w.identity]]
email = "a@example.com"
[[accounts.w.identity]]
email = "A@example.com"`, "email"},
		{"default unknown", `default_identity = "zz@example.com"
[[accounts.w.identity]]
email = "a@example.com"`, "default_identity"},
		{"sig NUL", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \"a\\u0000b\"", "signature"},
		{"sig lone CR", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \"a\\rb\"", "signature"},
		{"sig quote line", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \"a\\n> b\"", "signature"},
		{"sig long", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \"" + long + "\"", "signature"},
		{"html without text", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature_html = \"<p>x</p>\"", "signature_html"},
		{"html script", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \"x\"\nsignature_html = \"<p>x</p><script>1</script>\"", "signature_html"},
		{"html quote line", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \"x\"\nsignature_html = \"<p>&gt; x</p>\"", "signature_html"},
		{"html long", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \"x\"\nsignature_html = \"<p>" + strings.Repeat("a", 4000) + "</p>\"", "signature_html"},
		{"match no at", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nreply_match = [\"*\"]", "reply_match"},
		{"match domain star", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nreply_match = [\"*@*\"]", "reply_match"},
		{"match domain glob", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nreply_match = [\"a@*.com\"]", "reply_match"},
		{"match empty local", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nreply_match = [\"@example.com\"]", "reply_match"},
		{"unknown key", "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsigature = \"x\"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := idLoad(t, tc.body)
			if err == nil {
				t.Fatalf("Load accepted the file (%s)", idDoc)
			}
			if tc.key == "" {
				return
			}
			if !errors.Is(err, ErrInvalidIdentity) {
				t.Errorf("err = %v, want ErrInvalidIdentity", err)
			}
			if !strings.Contains(err.Error(), `"w"`) || !strings.Contains(err.Error(), tc.key) {
				t.Errorf("error %q must name the account and key %q", err, tc.key)
			}
		})
	}
}

// TestIdentity_LoadAccepts checks values at the edge of the DI1.3 rules.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestIdentity_LoadAccepts(t *testing.T) {
	a, err := idLoad(t, "[[accounts.w.identity]]\nemail = \"a@example.com\"\nsignature = \""+strings.Repeat("a", 1000)+
		"\"\nsignature_html = \"<p>Best<br>Me</p>\"\nreply_match = [\"*@example.com\", \"s?les@example.com\"]\n")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	id, _ := a.Identity("a@example.com")
	if id.SignatureHTML != "<p>Best<br>Me</p>" {
		t.Errorf("SignatureHTML = %q", id.SignatureHTML)
	}
}

// TestIdentity_RefreshKeepsOldSet checks I3: a bad identity key fails
// the reload and Config keeps the old set.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestIdentity_RefreshKeepsOldSet(t *testing.T) {
	path := writeTemp(t, "[accounts.w]\nprovider = \"imap\"\nemail = \"me@example.com\"\n[[accounts.w.identity]]\nemail = \"a@example.com\"\n")
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	bad := "[accounts.w]\nprovider = \"imap\"\nemail = \"me@example.com\"\n[[accounts.w.identity]]\nemail = \"a@example.com\"\nbogus = 1\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(); err == nil {
		t.Fatal("Refresh accepted an unknown identity key")
	}
	a, _ := c.Account("w")
	if _, ok := a.Identity("a@example.com"); !ok {
		t.Error("old identity set lost after a failed reload")
	}
}

// TestNormalizeSignature checks the DI1.4 normal form.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestNormalizeSignature(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"\n\n", ""},
		{"a", "a"},
		{"a\r\nb\r\n", "a\nb"},
		{"\n\nA\n\nB  \n\n\n", "A\n\nB  "},
		{"-- \nA", "A"},
		{"--\n\n\nA", "A"},
		{"\n-- \nA\n-- \nB", "A\n-- \nB"},
		{"-- ", ""},
		{"A B\n  ", "A B\n  "},
		{"x\n-- \ny", "x\n-- \ny"},
	}
	for _, tc := range cases {
		if got := NormalizeSignature(tc.in); got != tc.want {
			t.Errorf("NormalizeSignature(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if again := NormalizeSignature(NormalizeSignature(tc.in)); again != NormalizeSignature(tc.in) {
			t.Errorf("NormalizeSignature is not stable for %q", tc.in)
		}
	}
}

// TestMatchReply checks first-in-file-order and the wildcard rules.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestMatchReply(t *testing.T) {
	a, err := idLoad(t, `
[[accounts.w.identity]]
email = "one@example.com"
reply_match = ["*@shop.example.com"]
[[accounts.w.identity]]
email = "two@example.com"
reply_match = ["*@shop.example.com", "sales?@example.com", "a*b@example.com"]
`)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		addr, want string
	}{
		{"x@shop.example.com", "one@example.com"},
		{"X@SHOP.example.com", "one@example.com"},
		{"Name <x@shop.example.com>", "one@example.com"},
		{"sales1@example.com", "two@example.com"},
		{"sales@example.com", ""},
		{"sales12@example.com", ""},
		{"ab@example.com", "two@example.com"},
		{"axxb@example.com", "two@example.com"},
		{"axxb@other.com", ""},
		{"x@sub.shop.example.com", ""},
		{"", ""},
	}
	for _, tc := range cases {
		id, ok := a.MatchReply(tc.addr)
		if tc.want == "" {
			if ok {
				t.Errorf("MatchReply(%q) = %q, want none", tc.addr, id.Email)
			}
			continue
		}
		if !ok || id.Email != tc.want {
			t.Errorf("MatchReply(%q) = %q,%v, want %q", tc.addr, id.Email, ok, tc.want)
		}
	}
}

// TestOwnsAddress checks the account email, table, flat and pattern
// routes in identity mode.
//
// arch: DI2.0, DI1.1, DI1.2, DI1.3, DI1.4, DI1.5, DI1.6
func TestOwnsAddress(t *testing.T) {
	a, err := idLoad(t, `
identities = ["Flat <flat@example.com>"]
[[accounts.w.identity]]
email = "tab@example.com"
reply_match = ["*@catch.example.com"]
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{"me@example.com", "ME@example.com", "tab@example.com", "flat@example.com",
		"Flat <flat@example.com>", "anyone@catch.example.com"} {
		if !a.OwnsAddress(ok) {
			t.Errorf("OwnsAddress(%q) = false, want true", ok)
		}
	}
	for _, no := range []string{"", "other@example.com", "x@catch.example.org", "x@sub.catch.example.com"} {
		if a.OwnsAddress(no) {
			t.Errorf("OwnsAddress(%q) = true, want false", no)
		}
	}
}

const ownerSig = "Thanking you in anticipation,\n\nYours faithfully,\nAnn Example"

// sigDirFixture writes accounts.toml with one identity table in a new
// directory. body holds the extra identity keys. It returns the
// directory and the accounts.toml path.
func sigDirFixture(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.toml")
	text := "[accounts.w]\nprovider = \"imap\"\nemail = \"me@example.com\"\n" +
		"[[accounts.w.identity]]\nemail = \"a@example.com\"\n" + body
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

func sigOf(t *testing.T, c *Config) string {
	t.Helper()
	a, _ := c.Account("w")
	id, ok := a.Identity("a@example.com")
	if !ok {
		t.Fatal("identity a@example.com missing")
	}
	return id.Signature
}

// TestIdentity_SignatureFile checks DI1.7: the file text loads
// byte-exact after NormalizeSignature, with the blank line kept, for a
// relative, a "~/" and an absolute path.
//
// arch: DI1.7, DI1.4
func TestIdentity_SignatureFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, "sig.txt"), []byte(ownerSig+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(t.TempDir(), "abs.txt")
	if err := os.WriteFile(abs, []byte(ownerSig+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, key string }{
		{"relative", "sig.txt"},
		{"home", "~/sig.txt"},
		{"absolute", abs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := sigDirFixture(t, "signature_file = \""+tc.key+"\"\n")
			if err := os.WriteFile(filepath.Join(dir, "sig.txt"), []byte(ownerSig+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := sigOf(t, c); got != ownerSig {
				t.Errorf("Signature = %q, want %q", got, ownerSig)
			}
		})
	}
	t.Run("byte order mark", func(t *testing.T) {
		dir, path := sigDirFixture(t, "signature_file = \"bom.txt\"\n")
		if err := os.WriteFile(filepath.Join(dir, "bom.txt"), []byte("\xEF\xBB\xBF"+ownerSig+"\r\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if got := sigOf(t, c); got != ownerSig {
			t.Errorf("Signature = %q, want %q", got, ownerSig)
		}
	})
}

// TestIdentity_SignatureHTMLFile checks that signature_html_file loads
// and runs the same checks as the inline value.
//
// arch: DI1.7, DI1.3
func TestIdentity_SignatureHTMLFile(t *testing.T) {
	dir, path := sigDirFixture(t, "signature = \"Best\\nMe\"\nsignature_html_file = \"s.html\"\n")
	if err := os.WriteFile(filepath.Join(dir, "s.html"), []byte("<p>Best<br>Me</p>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	a, _ := c.Account("w")
	id, _ := a.Identity("a@example.com")
	if id.SignatureHTML != "<p>Best<br>Me</p>" {
		t.Errorf("SignatureHTML = %q", id.SignatureHTML)
	}
	if err := os.WriteFile(filepath.Join(dir, "s.html"), []byte("<script>x</script>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("Load with bad HTML file: err = %v, want ErrInvalidIdentity", err)
	}
}

// TestIdentity_SignatureFileRefuses checks each refusal of DI1.7, and
// that no error text holds the file path.
//
// arch: DI1.7
func TestIdentity_SignatureFileRefuses(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		file  []byte // content of sig.txt; nil = no file
		dir   bool   // make sig.txt a directory
	}{
		{"both signature keys", "signature = \"A\"\nsignature_file = \"sig.txt\"\n", []byte("B"), false},
		{"both html keys", "signature = \"A\"\nsignature_html = \"<p>A</p>\"\nsignature_html_file = \"sig.txt\"\n", []byte("<p>A</p>"), false},
		{"directory", "signature_file = \"sig.txt\"\n", nil, true},
		{"missing", "signature_file = \"sig.txt\"\n", nil, false},
		{"too large", "signature_file = \"sig.txt\"\n", []byte(strings.Repeat("a", 64<<10+1)), false},
		{"not UTF-8", "signature_file = \"sig.txt\"\n", []byte{0xff, 0xfe, 'a'}, false},
		{"NUL", "signature_file = \"sig.txt\"\n", []byte("a\x00b"), false},
		{"lone CR", "signature_file = \"sig.txt\"\n", []byte("a\rb"), false},
		{"quote line", "signature_file = \"sig.txt\"\n", []byte("a\n> b"), false},
		{"over 1000 runes", "signature_file = \"sig.txt\"\n", []byte(strings.Repeat("é", 1001)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, path := sigDirFixture(t, tc.extra)
			p := filepath.Join(dir, "sig.txt")
			if tc.dir {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if tc.file != nil {
				if err := os.WriteFile(p, tc.file, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := Load(path)
			if !errors.Is(err, ErrInvalidIdentity) {
				t.Fatalf("Load: err = %v, want ErrInvalidIdentity", err)
			}
			if strings.Contains(err.Error(), dir) {
				t.Errorf("error holds the directory: %v", err)
			}
		})
	}
}

// TestIdentity_RefreshSignatureFile checks that editing only the
// signature file makes Refresh reload, and that a deleted file keeps
// the old set.
//
// arch: DI1.7, DI2.0
func TestIdentity_RefreshSignatureFile(t *testing.T) {
	dir, path := sigDirFixture(t, "signature_file = \"sig.txt\"\n")
	sigPath := filepath.Join(dir, "sig.txt")
	if err := os.WriteFile(sigPath, []byte("One"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if again, err := c.Refresh(); err != nil || again {
		t.Fatalf("Refresh with no change = %v, %v", again, err)
	}

	if err := os.WriteFile(sigPath, []byte("Two"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(sigPath, future, future); err != nil {
		t.Fatal(err)
	}
	if reloaded, err := c.Refresh(); err != nil || !reloaded {
		t.Fatalf("Refresh after file edit = %v, %v, want true, nil", reloaded, err)
	}
	if got := sigOf(t, c); got != "Two" {
		t.Errorf("Signature = %q, want Two", got)
	}

	if err := os.Remove(sigPath); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(); err == nil {
		t.Fatal("Refresh with the file deleted gave no error")
	}
	if got := sigOf(t, c); got != "Two" {
		t.Errorf("old set lost: Signature = %q", got)
	}
}
