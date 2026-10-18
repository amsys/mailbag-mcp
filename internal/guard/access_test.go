// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// TestAccess_LevelOrder holds the order of §3.17: read is the lowest
// level, draft adds a change of a mailbox, and send adds a message
// that leaves. Each level covers the levels below it, so one account
// with access = "send" also reads and drafts.
//
// arch: T5.4, §3.17, §9 U7, G9, D5, §10.5, §10.11, §5.3
func TestAccess_LevelOrder(t *testing.T) {
	cases := []struct {
		have Level
		need Level
		want bool
	}{
		{LevelRead, LevelRead, true},
		{LevelRead, LevelDraft, false},
		{LevelRead, LevelSend, false},
		{LevelDraft, LevelRead, true},
		{LevelDraft, LevelDraft, true},
		{LevelDraft, LevelSend, false},
		{LevelSend, LevelRead, true},
		{LevelSend, LevelDraft, true},
		{LevelSend, LevelSend, true},
	}
	for _, c := range cases {
		t.Run(string(c.have)+"-needs-"+string(c.need), func(t *testing.T) {
			if got := Permits(c.have, c.need); got != c.want {
				t.Errorf("Permits(%q, %q) = %v, want %v", c.have, c.need, got, c.want)
			}
			err := Require(config.Account{Alias: "work", Access: string(c.have)}, c.need)
			if c.want && err != nil {
				t.Errorf("Require: %v, want nil", err)
			}
			if !c.want {
				if err == nil {
					t.Fatalf("Require gave nil; access=%s must not permit %s (§10.5)", c.have, c.need)
				}
				if !errors.Is(err, ErrAccessDenied) {
					t.Errorf("Require gave %v, want an ErrAccessDenied (§3.17)", err)
				}
			}
		})
	}
}

// TestAccess_UnknownLevelDoesNotSend holds the fail-closed rule: a
// level this build cannot read never permits a message to leave. Only
// a hand-built [config.Account] carries such a value, because
// config.Load fills in "draft" for an account that names no level and
// refuses every other value (D5).
//
// arch: T5.4, §3.17, D5, §10.5
func TestAccess_UnknownLevelDoesNotSend(t *testing.T) {
	for _, access := range []string{"", "admin", "SEND", "owner"} {
		t.Run("access="+access, func(t *testing.T) {
			acct := config.Account{Alias: "work", Access: access}
			if got := LevelOf(acct); got != LevelDraft {
				t.Errorf("LevelOf(%q) = %q, want %q (D5)", access, got, LevelDraft)
			}
			if err := Require(acct, LevelSend); !errors.Is(err, ErrAccessDenied) {
				t.Errorf("Require(send) = %v; a level this build cannot read must not send", err)
			}
			if err := Require(acct, LevelDraft); err != nil {
				t.Errorf("Require(draft) = %v, want nil: D5 gives an account with no level the draft level", err)
			}
		})
	}
}

// TestAccess_ConfigAlwaysNamesALevel proves the fact the rule above
// rests on: an account block of accounts.toml with no access line
// reaches a tool with access = "draft", not with an empty string
// (D5). A test that only read LevelOf would pass even if config.Load
// stopped defaulting, so this one goes through the real loader.
//
// arch: T5.4, §3.17, §3.3, D5
func TestAccess_ConfigAlwaysNamesALevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.toml")
	toml := `
[accounts.work]
provider = "imap"
email    = "me@work.example"
imap     = "imap.work.example:993"
`
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatalf("write accounts.toml: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	acct, ok := cfg.Account("work")
	if !ok {
		t.Fatal("config.Account(work) is absent")
	}
	if acct.Access != string(LevelDraft) {
		t.Errorf("Access = %q, want %q: a new account gets draft (D5)", acct.Access, LevelDraft)
	}
	if err := Require(acct, LevelSend); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("Require(send) = %v; a new account must not send (§10.5)", err)
	}
}

// TestAccess_ErrorNamesTheFixAndNoAddress holds two rules at one
// time. The refusal must tell the person how to change it, because a
// model that reads "denied" and nothing else asks for a password
// next. And the text goes into a tool result and a call-end log, so
// it must hold no address and no secret (§10.5, §3.19).
//
// arch: T5.4, §3.17, §3.19, G9, §10.5
func TestAccess_ErrorNamesTheFixAndNoAddress(t *testing.T) {
	acct := config.Account{
		Alias:      "work",
		Access:     string(LevelRead),
		Email:      "me@work.example",
		Identities: []string{"alt@work.example"},
	}
	err := Require(acct, LevelDraft)
	if err == nil {
		t.Fatal("Require gave nil for a read account that must change a mailbox")
	}
	text := err.Error()
	for _, want := range []string{"work", "access=read", "access=draft", "accounts.toml"} {
		if !strings.Contains(text, want) {
			t.Errorf("error %q holds no %q", text, want)
		}
	}
	for _, unwanted := range []string{"me@work.example", "alt@work.example", "@"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("error %q holds %q; a refusal carries no address (§10.5)", text, unwanted)
		}
	}
}
