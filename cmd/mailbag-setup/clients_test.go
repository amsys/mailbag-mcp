// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests for the client config writers. They use temp directories only.
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 19, 8, 30, 5, 0, time.UTC) }

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	// applyDesktop resolves links in the path; on macOS t.TempDir() is
	// under /var, a link to /private/var.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "claude_desktop_config.json")
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestClients_DesktopMerge_NoFile checks that a missing file is made
// with a private mode and no backup.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopMerge_NoFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "c.json")
	bak, err := applyDesktop(p, "/opt/mailbag-mcp", nil, fixedNow)
	if err != nil || bak != "" {
		t.Fatalf("bak=%q err=%v", bak, err)
	}
	if got := readFile(t, p); !strings.Contains(got, `"command": "/opt/mailbag-mcp"`) {
		t.Fatalf("got %s", got)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

// TestClients_DesktopMerge_EmptyObject checks the merge into {}.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopMerge_EmptyObject(t *testing.T) {
	p := writeTemp(t, "{}")
	bak, err := applyDesktop(p, "/b/mailbag-mcp", nil, fixedNow)
	if err != nil {
		t.Fatal(err)
	}
	if want := p + ".bak-20261019T083005Z"; bak != want {
		t.Fatalf("backup %q want %q", bak, want)
	}
	if readFile(t, bak) != "{}" {
		t.Fatal("backup differs from the original")
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
}

// TestClients_DesktopMerge_OtherServers checks that other servers and
// other keys stay.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopMerge_OtherServers(t *testing.T) {
	p := writeTemp(t, `{"mcpServers":{"other":{"command":"x","args":["a"]}},"theme":"dark"}`)
	if _, err := applyDesktop(p, "/b/mailbag-mcp", nil, fixedNow); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, p)
	for _, w := range []string{`"other"`, `"args"`, `"theme": "dark"`, `"mailbag"`} {
		if !strings.Contains(got, w) {
			t.Fatalf("missing %s in %s", w, got)
		}
	}
	if strings.Index(got, `"other"`) > strings.Index(got, `"mailbag"`) {
		t.Fatal("new server must come after the old ones")
	}
}

// TestClients_DesktopMerge_OldMailbagPath checks that an old mailbag
// entry is replaced, not duplicated.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopMerge_OldMailbagPath(t *testing.T) {
	p := writeTemp(t, `{"mcpServers":{"mailbag":{"command":"/old/path"},"z":{}}}`)
	if _, err := applyDesktop(p, "/new/path", nil, fixedNow); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, p)
	if strings.Contains(got, "/old/path") || strings.Count(got, `"mailbag"`) != 1 || !strings.Contains(got, "/new/path") {
		t.Fatalf("got %s", got)
	}
	if strings.Index(got, `"mailbag"`) > strings.Index(got, `"z"`) {
		t.Fatal("the entry must keep its place")
	}
}

// TestClients_DesktopMerge_BadJSON checks that bad JSON is never
// replaced and makes no backup.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopMerge_BadJSON(t *testing.T) {
	for _, bad := range []string{"{", "", "[]", `{"a":1} x`, `{"mcpServers":[]}`, `{"a":1,}`} {
		p := writeTemp(t, bad)
		bak, err := applyDesktop(p, "/b", nil, fixedNow)
		if err == nil || bak != "" {
			t.Fatalf("input %q: bak=%q err=%v", bad, bak, err)
		}
		if readFile(t, p) != bad {
			t.Fatalf("input %q was changed", bad)
		}
		ents, _ := os.ReadDir(filepath.Dir(p))
		if len(ents) != 1 {
			t.Fatalf("input %q left extra files", bad)
		}
		if _, err := planDesktop(p, "/b"); err == nil {
			t.Fatalf("plan accepted %q", bad)
		}
	}
}

// TestClients_DesktopMerge_KeyOrder checks that the key order of the
// file stays, also inside the values.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopMerge_KeyOrder(t *testing.T) {
	p := writeTemp(t, `{"zeta":1,"mcpServers":{"b":{"y":1,"x":2},"a":{}},"alpha":2}`)
	if _, err := applyDesktop(p, "/b", nil, fixedNow); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, p)
	last := -1
	for _, k := range []string{`"zeta"`, `"mcpServers"`, `"b"`, `"y"`, `"x"`, `"a"`, `"mailbag"`, `"alpha"`} {
		i := strings.Index(got, k)
		if i <= last {
			t.Fatalf("%s out of order in %s", k, got)
		}
		last = i
	}
}

// TestClients_DesktopApp_RunningRefused checks that a running app
// stops the write and that the tool does nothing to the app.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopApp_RunningRefused(t *testing.T) {
	p := writeTemp(t, "{}")
	_, err := applyDesktop(p, "/b", func() bool { return true }, fixedNow)
	if !errors.Is(err, errAppRunning) || readFile(t, p) != "{}" {
		t.Fatalf("err=%v", err)
	}
}

// TestClients_DesktopMerge_Symlink checks that a symlinked config
// stays a symlink and the target changes.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopMerge_Symlink(t *testing.T) {
	real := writeTemp(t, "{}")
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := applyDesktop(link, "/b", nil, fixedNow); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("link replaced")
	}
	if !strings.Contains(readFile(t, real), `"mailbag"`) {
		t.Fatal("target not changed")
	}
}

// TestClients_DesktopPath checks the config path per system.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_DesktopPath(t *testing.T) {
	if got := desktopConfigPath("/h", "darwin"); got != "/h/Library/Application Support/Claude/claude_desktop_config.json" {
		t.Fatal(got)
	}
	if desktopConfigPath("/h", "plan9") != "" {
		t.Fatal("unknown system must give no path")
	}
}

// TestClients_ClaudeCode_Args checks the claude call: user scope, the
// path as the person gave it (a symlink is not resolved), and a stub
// runner so no real claude runs.
//
// arch: DS13.3, DS13.8, IS13.4
func TestClients_ClaudeCode_Args(t *testing.T) {
	var got []string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		got = append([]string{name}, args...)
		return nil, nil
	}
	if err := applyClaudeCode(context.Background(), run, "/opt/homebrew/bin/mailbag-mcp"); err != nil {
		t.Fatal(err)
	}
	want := "claude mcp add --scope user mailbag -- /opt/homebrew/bin/mailbag-mcp"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %q", got)
	}
	fail := func(context.Context, string, ...string) ([]byte, error) { return []byte("boom"), errors.New("exit 1") }
	if err := applyClaudeCode(context.Background(), fail, "/b"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err=%v", err)
	}
	cur := func(context.Context, string, ...string) ([]byte, error) { return []byte("mailbag: /old"), nil }
	if out, same := claudeCodeCurrent(context.Background(), cur, "/new"); same || out == "" {
		t.Fatal("different path must not match")
	}
}
