// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAttachPath_HiddenRefused checks that AttachPath refuses a path
// with a hidden component, the way a prompt injection reaches a
// private key such as "~/.ssh/id_ed25519".
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func TestAttachPath_HiddenRefused(t *testing.T) {
	dir := t.TempDir()
	hidden := filepath.Join(dir, ".secret")
	if err := os.WriteFile(hidden, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	visible := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(visible, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"hidden file refused", hidden, true},
		{"visible file allowed", visible, false},
		{"empty path refused", "", true},
		{"NUL byte refused", visible + "\x00", true},
		{"missing file refused", filepath.Join(dir, "nope.txt"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := AttachPath(tt.path, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AttachPath(%q) err=%v, wantErr=%v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// TestAttachPath_AllowList checks that a non-empty attach_dirs list
// (§3.15, G7) permits only paths under one of its entries, and that a
// directory (not a regular file) is refused even when it sits inside
// an allowed root.
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func TestAttachPath_AllowList(t *testing.T) {
	allowed := t.TempDir()
	other := t.TempDir()

	inFile := filepath.Join(allowed, "ok.txt")
	if err := os.WriteFile(inFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(other, "ok.txt")
	if err := os.WriteFile(outFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	subDir := filepath.Join(allowed, "sub")
	if err := os.Mkdir(subDir, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		path      string
		allowDirs []string
		wantErr   bool
	}{
		{"no allow list, any file passes", outFile, nil, false},
		{"inside the allowed dir", inFile, []string{allowed}, false},
		{"outside every allowed dir", outFile, []string{allowed}, true},
		{"a directory is not a regular file", subDir, []string{allowed}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, size, err := AttachPath(tt.path, tt.allowDirs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AttachPath(%q, %v) err=%v, wantErr=%v", tt.path, tt.allowDirs, err, tt.wantErr)
			}
			if err == nil {
				if size != 1 {
					t.Errorf("size = %d, want 1", size)
				}
				if filepath.Base(resolved) != filepath.Base(tt.path) {
					t.Errorf("resolved base = %q, want %q", filepath.Base(resolved), filepath.Base(tt.path))
				}
			}
		})
	}
}

// TestAttachPath_RefusesProcSysDev reproduces the S2 judge finding
// that AttachPath accepted "/proc/self/environ" (a regular file, 0
// bytes by Stat, no dot component) and would have handed a prompt
// injection the server's own environment (§3.15, G7).
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func TestAttachPath_RefusesProcSysDev(t *testing.T) {
	tests := []string{
		"/proc/self/environ",
		"/proc",
		"/sys",
		"/dev/null",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			if _, err := os.Lstat(path); err != nil {
				t.Skipf("%s not present on this system: %v", path, err)
			}
			_, _, err := AttachPath(path, nil)
			if err == nil {
				t.Fatalf("AttachPath(%q) = nil error, want refused", path)
			}
		})
	}
}

// TestAttach_Caps checks the 25 MB cap of M11: a file at the cap
// passes and a file one byte over it is refused.
//
// arch: T2.4, §3.15, §3.14, §5.4, G7, M11
func TestAttach_Caps(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		size    int64
		wantErr bool
	}{
		{"at the cap", MaxAttachBytes, false},
		{"one byte over the cap", MaxAttachBytes + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_")+".bin")
			f, err := os.Create(path) //nolint:gosec // G304: the path is built from t.TempDir() in this test
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(tt.size); err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			_ = f.Close()

			_, size, err := AttachPath(path, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AttachPath size=%d err=%v, wantErr=%v", tt.size, err, tt.wantErr)
			}
			if err == nil && size != tt.size {
				t.Errorf("size = %d, want %d", size, tt.size)
			}
		})
	}
}

// TestAttachPath_RefusesConfigAndStateDirs checks that AttachPath
// refuses a file under the config dir or the state dir of mailbag,
// also when neither path holds a dot component (the macOS config dir
// "~/Library/Application Support/mailbag-mcp"). The secrets file of
// `secrets = "file"` sits in the config dir. A symbolic link to such a
// file, and a config dir named through a symbolic link, are refused
// too.
//
// arch: T2.4, §3.15, G7, R16-M2
func TestAttachPath_RefusesConfigAndStateDirs(t *testing.T) {
	cfg := t.TempDir()
	state := t.TempDir()
	other := t.TempDir()

	secret := filepath.Join(cfg, "secrets-file")
	logFile := filepath.Join(state, "server.log")
	plain := filepath.Join(other, "report.txt")
	for _, p := range []string{secret, logFile, plain} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(other, "innocent.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	cfgLink := filepath.Join(other, "cfglink")
	if err := os.Symlink(cfg, cfgLink); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfgEnv  string
		path    string
		wantErr bool
	}{
		{"file in the config dir", cfg, secret, true},
		{"file in the state dir", cfg, logFile, true},
		{"link to a file in the config dir", cfg, link, true},
		{"config dir named through a link", cfgLink, secret, true},
		{"file outside both dirs", cfg, plain, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MAILBAG_CONFIG_DIR", tt.cfgEnv)
			t.Setenv("MAILBAG_STATE_DIR", state)
			_, _, err := AttachPath(tt.path, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("AttachPath(%q) err=%v, wantErr=%v", tt.path, err, tt.wantErr)
			}
		})
	}
}
