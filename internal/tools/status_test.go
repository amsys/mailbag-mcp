// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// loadStatusConfig writes body as accounts.toml under a fresh
// directory and loads it, so each test below states only the keys
// that bear on [StatusLines].
func loadStatusConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write accounts.toml: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// TestStatusLines_Toolsets checks the D2.1 migration half of
// [StatusLines]: an accounts.toml with no extras key names every
// known toolset as off, in one line, and decrypt is reported
// separately (both keys below are unset, so decrypt is off too, but
// that is TestStatusLines_DecryptOff's claim, not this one's).
//
// arch: DR1G.10, IR1G.10
func TestStatusLines_Toolsets(t *testing.T) {
	cfg := loadStatusConfig(t, `
[accounts.work]
provider = "imap"
email    = "me@example.com"
`)
	toolsets, _ := StatusLines(cfg)
	if len(toolsets) != 1 {
		t.Fatalf("toolsets = %v, want exactly one line", toolsets)
	}
	for _, name := range ToolsetNames() {
		if !strings.Contains(toolsets[0], name) {
			t.Errorf("toolsets line %q does not name off toolset %q", toolsets[0], name)
		}
	}
}

// TestStatusLines_ToolsetsAllOn checks the other side of the same
// half: every known toolset in extras gives an empty toolsets slice,
// so a caller writes nothing (there is nothing off to report).
//
// arch: DR1G.10, IR1G.10
func TestStatusLines_ToolsetsAllOn(t *testing.T) {
	names := ToolsetNames()
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = `"` + n + `"`
	}
	cfg := loadStatusConfig(t, `
extras = [`+strings.Join(quoted, ", ")+`]

[accounts.work]
provider = "imap"
email    = "me@example.com"

[decrypt]
enabled = true
ack_plaintext_reaches_model_provider = true
`)
	toolsets, _ := StatusLines(cfg)
	if len(toolsets) != 0 {
		t.Errorf("toolsets = %v, want none (every toolset is on)", toolsets)
	}
}

// TestStatusLines_DecryptOn checks the D7.1 half: with all three
// [decrypt] keys set, the one decrypt line starts "decrypt-on: " and
// holds [DecryptWarning] in full, so a caller can both log it and
// write it to stderr as the exact warning text D7.1 asks for.
//
// arch: DR1G.10, IR1G.10
func TestStatusLines_DecryptOn(t *testing.T) {
	cfg := loadStatusConfig(t, `
extras = ["decrypt"]

[accounts.work]
provider = "imap"
email    = "me@example.com"

[decrypt]
enabled = true
ack_plaintext_reaches_model_provider = true
`)
	_, decrypt := StatusLines(cfg)
	if len(decrypt) != 1 {
		t.Fatalf("decrypt = %v, want exactly one line", decrypt)
	}
	rest, ok := strings.CutPrefix(decrypt[0], "decrypt-on: ")
	if !ok {
		t.Fatalf("decrypt line = %q, want it to start \"decrypt-on: \"", decrypt[0])
	}
	if rest != DecryptWarning {
		t.Errorf("decrypt line holds %q after the prefix, want %s exactly", rest, DecryptWarning)
	}
}

// TestStatusLines_DecryptOff checks the other D7.1 case: one key
// missing (here, the ack) gives a "decrypt-off: " line that names
// that key and no other, so a caller never writes [DecryptWarning] to
// stderr while decrypt tool access is actually off.
//
// arch: DR1G.10, IR1G.10
func TestStatusLines_DecryptOff(t *testing.T) {
	cfg := loadStatusConfig(t, `
extras = ["decrypt"]

[accounts.work]
provider = "imap"
email    = "me@example.com"

[decrypt]
enabled = true
`)
	_, decrypt := StatusLines(cfg)
	if len(decrypt) != 1 {
		t.Fatalf("decrypt = %v, want exactly one line", decrypt)
	}
	if !strings.HasPrefix(decrypt[0], "decrypt-off: ") {
		t.Fatalf("decrypt line = %q, want it to start \"decrypt-off: \"", decrypt[0])
	}
	if !strings.Contains(decrypt[0], config.DecryptKeyAck) {
		t.Errorf("decrypt line = %q, want it to name %s", decrypt[0], config.DecryptKeyAck)
	}
	if strings.Contains(decrypt[0], config.DecryptKeyEnabled) {
		t.Errorf("decrypt line = %q, names %s though it is set", decrypt[0], config.DecryptKeyEnabled)
	}
	if strings.Contains(decrypt[0], DecryptWarning) {
		t.Errorf("decrypt-off line = %q, must never hold the on warning", decrypt[0])
	}
}
