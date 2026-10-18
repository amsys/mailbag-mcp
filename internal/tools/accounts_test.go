// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/secrets"
)

// TestAccounts_NoConfigYet checks the first-run case of §3.1 step 3:
// no accounts.toml yet is not an error, and the result names the
// command that adds an account.
//
// arch: T1.5, §3.16, G1
func TestAccounts_NoConfigYet(t *testing.T) {
	t.Setenv("MAILBAG_CONFIG_DIR", t.TempDir())

	out, err := accountsHandler(nil)(context.Background(), AccountsIn{})
	if err != nil {
		t.Fatalf("accountsHandler: %v", err)
	}
	if len(out.Accounts) != 0 {
		t.Errorf("Accounts = %+v, want none", out.Accounts)
	}
	if out.AddHint == "" {
		t.Error("AddHint is empty with no accounts.toml")
	}
	if out.Secrets != secrets.KindKeyring {
		t.Errorf("Secrets = %q, want %q (the documented default)", out.Secrets, secrets.KindKeyring)
	}
}

// TestAccounts_ListsConfiguredAccounts checks that each configured
// account's alias, email, provider, access and identities reach the
// result, sorted by alias (config.Config.Aliases), and that AddHint
// is unset once there is at least one account.
//
// arch: T1.5, §3.16
func TestAccounts_ListsConfiguredAccounts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", dir)

	toml := `
secrets = "file"

[accounts.work]
provider   = "imap"
email      = "me@work.example"
access     = "read"
identities = ["me@work.example", "me+alias@work.example"]

[accounts.home]
provider = "gmail"
email    = "me@home.example"
`
	if err := os.WriteFile(filepath.Join(dir, "accounts.toml"), []byte(toml), 0o600); err != nil {
		t.Fatalf("write accounts.toml: %v", err)
	}

	out, err := accountsHandler(nil)(context.Background(), AccountsIn{})
	if err != nil {
		t.Fatalf("accountsHandler: %v", err)
	}
	if out.AddHint != "" {
		t.Errorf("AddHint = %q, want empty with accounts configured", out.AddHint)
	}
	if out.Secrets != secrets.KindFile {
		t.Errorf("Secrets = %q, want %q", out.Secrets, secrets.KindFile)
	}
	want := []AccountRow{
		{Alias: "home", Email: "me@home.example", Provider: "gmail", Access: "draft"},
		{Alias: "work", Email: "me@work.example", Provider: "imap", Access: "read",
			Identities: []string{"me@work.example", "me+alias@work.example"}},
	}
	if len(out.Accounts) != len(want) {
		t.Fatalf("Accounts = %+v, want %+v", out.Accounts, want)
	}
	for i, row := range out.Accounts {
		w := want[i]
		if row.Alias != w.Alias || row.Email != w.Email || row.Provider != w.Provider || row.Access != w.Access {
			t.Errorf("Accounts[%d] = %+v, want %+v", i, row, w)
			continue
		}
		if len(row.Identities) != len(w.Identities) {
			t.Errorf("Accounts[%d].Identities = %v, want %v", i, row.Identities, w.Identities)
			continue
		}
		for j := range row.Identities {
			if row.Identities[j] != w.Identities[j] {
				t.Errorf("Accounts[%d].Identities = %v, want %v", i, row.Identities, w.Identities)
				break
			}
		}
	}
}

// TestAccounts_StateColumn checks that each row carries the state that
// the states function gives for its alias, that an unknown state
// leaves the column out of the JSON, and that a nil function leaves
// it empty.
//
// arch: DR1G.6, DR1G.18, IR1G.8
func TestAccounts_StateColumn(t *testing.T) {
	writeAccounts(t, `
secrets = "file"

[accounts.home]
provider = "imap"
email = "me@home.example"

[accounts.work]
provider = "imap"
email = "me@work.example"
`)
	states := map[string]AuthState{"work": AuthNeedsSignIn}

	out, err := accountsHandler(func(alias string) AuthState { return states[alias] })(context.Background(), AccountsIn{})
	if err != nil {
		t.Fatalf("accountsHandler: %v", err)
	}
	if len(out.Accounts) != 2 || out.Accounts[0].State != AuthUnknown || out.Accounts[1].State != AuthNeedsSignIn {
		t.Fatalf("Accounts = %+v, want home unknown and work needs_auth", out.Accounts)
	}
	b, err := json.Marshal(out.Accounts)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(b); strings.Count(got, `"state"`) != 1 || !strings.Contains(got, `"state":"needs_auth"`) {
		t.Fatalf("JSON = %s, want one state field, needs_auth on work", got)
	}

	out, err = accountsHandler(nil)(context.Background(), AccountsIn{})
	if err != nil {
		t.Fatalf("accountsHandler(nil): %v", err)
	}
	for _, row := range out.Accounts {
		if row.State != AuthUnknown {
			t.Fatalf("row %s state = %q with nil states, want empty", row.Alias, row.State)
		}
	}
}

// TestAccounts_IdentitySettings checks that an account in identity mode
// returns identity_settings without signature text, and that an account
// outside identity mode leaves the key out of the JSON.
//
// arch: DI4
func TestAccounts_IdentitySettings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", dir)

	toml := `
secrets = "file"

[accounts.plain]
provider = "gmail"
email    = "me@plain.example"

[accounts.work]
provider         = "imap"
email            = "me@work.example"
imap             = "imap.work.example:993"
smtp             = "smtp.work.example:587"
default_identity = "boss@work.example"

[[accounts.work.identity]]
email     = "me@work.example"
signature = "SECRET-SIG-ONE"

[[accounts.work.identity]]
email           = "boss@work.example"
name            = "The Boss"
signature       = "SECRET-SIG-THREE"
signature_html  = "<p>SECRET-SIG-TWO</p>"
reply_match     = ["*@boss.example"]
`
	if err := os.WriteFile(filepath.Join(dir, "accounts.toml"), []byte(toml), 0o600); err != nil {
		t.Fatalf("write accounts.toml: %v", err)
	}

	out, err := accountsHandler(nil)(context.Background(), AccountsIn{})
	if err != nil {
		t.Fatalf("accountsHandler: %v", err)
	}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "SECRET-SIG") {
		t.Errorf("result holds signature text: %s", raw)
	}
	byAlias := map[string]AccountRow{}
	for _, r := range out.Accounts {
		byAlias[r.Alias] = r
	}
	if got := byAlias["plain"].IdentitySettings; got != nil {
		t.Errorf("plain.IdentitySettings = %+v, want none", got)
	}
	rows := byAlias["work"].IdentitySettings
	if len(rows) != 2 {
		t.Fatalf("work.IdentitySettings = %+v, want 2 rows", rows)
	}
	if rows[0].Default || !rows[0].Signature || rows[0].SignatureHTML {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if !rows[1].Default || !rows[1].Signature || !rows[1].SignatureHTML || rows[1].Name != "The Boss" {
		t.Errorf("row 1 = %+v", rows[1])
	}
	if len(rows[1].ReplyMatch) != 1 {
		t.Errorf("row 1 ReplyMatch = %v", rows[1].ReplyMatch)
	}
}
