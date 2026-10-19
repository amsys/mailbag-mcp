// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package guard

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSavePath_Attacks walks the save-path containment cases ported
// from the TypeScript suite (G6, §5.4): a target must resolve, after
// symlinks, inside one of the permitted roots, and a look-alike name
// or a link that walks outside must not pass.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestSavePath_Attacks(t *testing.T) {
	root := realTempDir(t)
	outside := realTempDir(t)
	roots := []string{root}

	mustSymlink := func(t *testing.T, oldname, newname string) {
		t.Helper()
		if err := os.Symlink(oldname, newname); err != nil {
			t.Fatalf("Symlink(%q, %q): %v", oldname, newname, err)
		}
	}

	// setup returns the roots to check against and the target path to
	// resolve; it runs inside the subtest so each case gets its own
	// temporary files.
	cases := []struct {
		name    string
		setup   func(t *testing.T) (roots []string, target string)
		wantErr bool
	}{
		{
			name: "root itself",
			setup: func(_ *testing.T) ([]string, string) {
				return roots, root
			},
		},
		{
			name: "subdirectory of root",
			setup: func(t *testing.T) ([]string, string) {
				sub := filepath.Join(root, "sub")
				if err := os.Mkdir(sub, 0o700); err != nil {
					t.Fatal(err)
				}
				return roots, sub
			},
		},
		{
			name: "unrelated directory",
			setup: func(_ *testing.T) ([]string, string) {
				return roots, outside
			},
			wantErr: true,
		},
		{
			name: "sibling with root as a string prefix (/tmp-fake vs /tmp)",
			setup: func(_ *testing.T) ([]string, string) {
				return roots, root + "-fake"
			},
			wantErr: true,
		},
		{
			name: "trailing separator on root",
			setup: func(_ *testing.T) ([]string, string) {
				return roots, root + string(filepath.Separator)
			},
		},
		{
			name: "dot-dot that stays inside root",
			setup: func(t *testing.T) ([]string, string) {
				sub := filepath.Join(root, "sub2")
				if err := os.Mkdir(sub, 0o700); err != nil {
					t.Fatal(err)
				}
				return roots, filepath.Join(root, "sub2", "..", "sub2")
			},
		},
		{
			name: "dot-dot that escapes then mentions root in text only",
			setup: func(_ *testing.T) ([]string, string) {
				return roots, filepath.Join(root, "..", filepath.Base(root)+"-fake")
			},
			wantErr: true,
		},
		{
			name: "symlink inside root pointing outside root",
			setup: func(t *testing.T) ([]string, string) {
				link := filepath.Join(root, "out-link")
				mustSymlink(t, outside, link)
				return roots, link
			},
			wantErr: true,
		},
		{
			name: "symlink inside root pointing to another spot inside root",
			setup: func(t *testing.T) ([]string, string) {
				realDir := filepath.Join(root, "real-dir")
				if err := os.Mkdir(realDir, 0o700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(root, "in-link")
				mustSymlink(t, realDir, link)
				return roots, link
			},
		},
		{
			name: "path that does not exist below a link that stays inside root",
			setup: func(t *testing.T) ([]string, string) {
				realDir := filepath.Join(root, "real-dir2")
				if err := os.Mkdir(realDir, 0o700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(root, "in-link2")
				mustSymlink(t, realDir, link)
				return roots, filepath.Join(link, "not-created-yet")
			},
		},
		{
			name: "path that does not exist below a link that leaves root",
			setup: func(t *testing.T) ([]string, string) {
				link := filepath.Join(root, "out-link2")
				mustSymlink(t, outside, link)
				return roots, filepath.Join(link, "not-created-yet")
			},
			wantErr: true,
		},
		{
			name: "the permitted root is itself a symlink",
			setup: func(t *testing.T) ([]string, string) {
				realDir := realTempDir(t)
				link := filepath.Join(realTempDir(t), "root-link")
				mustSymlink(t, realDir, link)
				return []string{link}, link
			},
		},
		{
			name: "empty roots list",
			setup: func(_ *testing.T) ([]string, string) {
				return nil, root
			},
			wantErr: true,
		},
		{
			name: "root not yet created on disk",
			setup: func(_ *testing.T) ([]string, string) {
				r := filepath.Join(root, "future-root")
				return []string{r}, filepath.Join(r, "sub", "file.txt")
			},
		},
		{
			name: "root not yet created, target outside it",
			setup: func(_ *testing.T) ([]string, string) {
				r := filepath.Join(root, "future-root2")
				return []string{r}, filepath.Join(root, "other-future", "file.txt")
			},
			wantErr: true,
		},
		{
			name: "relative path resolved against the working directory",
			setup: func(t *testing.T) ([]string, string) {
				t.Chdir(root)
				return roots, "."
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			caseRoots, target := tc.setup(t)
			got, err := ResolveSaveDir(target, caseRoots)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveSaveDir(%q) = %q, want error", target, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveSaveDir(%q): unexpected error: %v", target, err)
			}
			if got == "" {
				t.Fatalf("ResolveSaveDir(%q): empty result with no error", target)
			}
		})
	}
}

// TestSavePath_NoFollowOnCreate checks that CreateSaveFile never opens
// through a symbolic link left at the target name: os.O_EXCL already
// refuses a path that exists, symlink or not, so the call must move on
// to "name (1).ext" and must never write through the link (G6, §10.9).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestSavePath_NoFollowOnCreate(t *testing.T) {
	dir := realTempDir(t)
	victim := filepath.Join(realTempDir(t), "victim.txt")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "report.txt")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	f, path, err := CreateSaveFile(dir, "report.txt", []string{dir})
	if err != nil {
		t.Fatalf("CreateSaveFile: %v", err)
	}
	defer func() { _ = f.Close() }()

	if path == link {
		t.Fatalf("CreateSaveFile opened the symlinked name %q instead of a fresh one", path)
	}
	wantPath := filepath.Join(dir, "report (1).txt")
	if path != wantPath {
		t.Fatalf("CreateSaveFile path = %q, want %q", path, wantPath)
	}
	if _, err := f.WriteString("new content"); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(victim) //nolint:gosec // G304: the path is built from t.TempDir() in this test
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "do not touch" {
		t.Fatalf("victim file was written through the symlink: %q", content)
	}

	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink at %q was replaced", link)
	}
}

// TestSavePath_ExistingFileNeverOverwritten checks the plain
// collision path: an existing regular file is never opened for
// writing again, and the next free name is used instead (§3.15).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestSavePath_ExistingFileNeverOverwritten(t *testing.T) {
	dir := realTempDir(t)
	first := filepath.Join(dir, "invoice.pdf")
	if err := os.WriteFile(first, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, path, err := CreateSaveFile(dir, "invoice.pdf", []string{dir})
	if err != nil {
		t.Fatalf("CreateSaveFile: %v", err)
	}
	_ = f.Close()

	if path == first {
		t.Fatalf("CreateSaveFile reused the existing path %q", path)
	}
	content, err := os.ReadFile(first) //nolint:gosec // G304: the path is built from t.TempDir() in this test
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("existing file was overwritten: %q", content)
	}
}

// TestSavePath_SwappedDirSymlink reproduces the S2 judge finding: a
// directory validated by ResolveSaveDir is later swapped for a
// symbolic link to a directory outside every permitted root, before
// CreateSaveFile runs. CreateSaveFile must refuse the create and must
// never write into the victim directory (G6, §3.15).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestSavePath_SwappedDirSymlink(t *testing.T) {
	root := realTempDir(t)
	victim := realTempDir(t)
	roots := []string{root}

	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	cdir, err := ResolveSaveDir(sub, roots)
	if err != nil {
		t.Fatalf("ResolveSaveDir(%q): unexpected error: %v", sub, err)
	}

	// The race: "sub" is removed and replaced with a symlink to a
	// directory outside every permitted root, after the check above
	// and before the create below.
	if err := os.Remove(sub); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, sub); err != nil {
		t.Fatal(err)
	}

	_, _, err = CreateSaveFile(cdir, "evil.desktop", roots)
	if err == nil {
		t.Fatalf("CreateSaveFile(%q) after the swap: want error, got nil", cdir)
	}
	if _, statErr := os.Stat(filepath.Join(victim, "evil.desktop")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("CreateSaveFile wrote into the victim directory: Stat error = %v", statErr)
	}
}

// TestCreateSaveFile_RejectsPathName reproduces the S2 judge finding
// that CreateSaveFile trusted name and would create a file outside
// dir when name held its own path components (G6, §3.15).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestCreateSaveFile_RejectsPathName(t *testing.T) {
	root := realTempDir(t)

	tests := []string{"../escape.txt", "sub/escape.txt", "/etc/escape.txt"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := CreateSaveFile(root, name, []string{root})
			if err == nil {
				t.Fatalf("CreateSaveFile(%q, %q): want error, got nil", root, name)
			}
			if _, statErr := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatalf("CreateSaveFile(%q, %q) escaped root: Stat error = %v", root, name, statErr)
			}
		})
	}
}

// TestSavePath_TildeRoot reproduces the S2 judge finding that a root
// written as "~/Downloads" in config never matched, because
// ResolveSaveDir canonicalized roots without expanding "~" first, so
// the root was read as "<cwd>/~/Downloads" (G6, §3.15).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestSavePath_TildeRoot(t *testing.T) {
	home := realTempDir(t)
	t.Setenv("HOME", home)

	downloads := filepath.Join(home, "Downloads")
	if err := os.Mkdir(downloads, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveSaveDir(downloads, []string{"~/Downloads"})
	if err != nil {
		t.Fatalf("ResolveSaveDir(%q, [\"~/Downloads\"]): unexpected error: %v", downloads, err)
	}
	if got != downloads {
		t.Fatalf("ResolveSaveDir(%q) = %q, want %q", downloads, got, downloads)
	}
}

// TestSaveName_Table checks each cleanup rule of §3.15 in isolation:
// path separators, control and hidden characters, leading dots,
// refused names, the byte limit that keeps the extension, and the
// Windows device name guard.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestSaveName_Table(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "ordinary name", in: "invoice.pdf", want: "invoice.pdf"},
		{
			name: "forward slash from the server (TS #24)",
			in:   "a/../../etc/passwd",
			want: "passwd",
		},
		{name: "backslash is a separator on every OS", in: `a\b\c.txt`, want: "c.txt"},
		{name: "windows path from the server", in: `..\..\Windows\win.ini`, want: "win.ini"},
		{name: "root slash only", in: "/", want: "_"},
		{name: "invalid UTF-8 byte removed", in: "a\xffb.txt", want: "ab.txt"},
		{name: "control character removed", in: "bad\x01name.txt", want: "badname.txt"},
		{name: "hidden character removed", in: "bad\u200bname.txt", want: "badname.txt"},
		{name: "newline removed", in: "bad\nname.txt", want: "badname.txt"},
		{name: "leading dots stripped", in: "...secret.txt", want: "secret.txt"},
		{name: "empty after cleanup", in: "", wantErr: true},
		{name: "dot only", in: ".", wantErr: true},
		{name: "dot dot only", in: "..", wantErr: true},
		{name: "all dots", in: "....", wantErr: true},
		{
			name: "windows device name gets a prefix",
			in:   "CON.txt",
			want: "_CON.txt",
		},
		{
			name: "windows device name is case-insensitive",
			in:   "com1",
			want: "_com1",
		},
		{name: "windows device name with two extensions", in: "con.tar.gz", want: "_con.tar.gz"},
		{name: "windows device name with trailing space", in: "aux .txt", want: "_aux .txt"},
		{
			name: "ordinary name that merely contains a device word",
			in:   "reconnect.txt",
			want: "reconnect.txt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SaveName(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("SaveName(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SaveName(%q): unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("SaveName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("long name truncated but extension kept", func(t *testing.T) {
		long := strings.Repeat("a", 500) + ".pdf"
		got, err := SaveName(long)
		if err != nil {
			t.Fatalf("SaveName: %v", err)
		}
		if len(got) > maxSaveNameBytes {
			t.Fatalf("SaveName result is %d bytes, want <= %d", len(got), maxSaveNameBytes)
		}
		if !strings.HasSuffix(got, ".pdf") {
			t.Fatalf("SaveName(%q) = %q, extension lost", long, got)
		}
	})

	t.Run("long name with multi-byte characters cuts on a rune boundary", func(t *testing.T) {
		long := strings.Repeat("é", 300) + ".txt"
		got, err := SaveName(long)
		if err != nil {
			t.Fatalf("SaveName: %v", err)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("SaveName(%q) produced invalid UTF-8: %q", long, got)
		}
	})

	t.Run("reserved name after a cut keeps the byte limit", func(t *testing.T) {
		// The cut leaves "con" and a 197-byte extension: a device name.
		in := "conxyz." + strings.Repeat("e", 196)
		got, err := SaveName(in)
		if err != nil {
			t.Fatalf("SaveName: %v", err)
		}
		if len(got) > maxSaveNameBytes || !strings.HasPrefix(got, "_") {
			t.Fatalf("SaveName(%q) = %q (%d bytes), want a \"_\" prefix within %d bytes", in, got, len(got), maxSaveNameBytes)
		}
	})

	t.Run("multi-byte first rune beside a long extension gets no leading dot", func(t *testing.T) {
		in := "é." + strings.Repeat("e", 198)
		got, err := SaveName(in)
		if err != nil {
			t.Fatalf("SaveName: %v", err)
		}
		if strings.HasPrefix(got, ".") || len(got) > maxSaveNameBytes {
			t.Fatalf("SaveName(%q) = %q (%d bytes)", in, got, len(got))
		}
	})
}

// FuzzSaveName checks that SaveName's invariants hold for arbitrary
// input: the result, when there is no error, never carries a path
// separator or a hidden character, is never empty, never exceeds the
// byte limit, and is valid UTF-8 (G6, §10.9).
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func FuzzSaveName(f *testing.F) {
	seeds := []string{
		"invoice.pdf",
		"../../etc/passwd",
		`..\..\Windows\system32`,
		"",
		".",
		"..",
		"CON.txt",
		strings.Repeat("a", 1000) + ".pdf",
		"bad\x00name",
		"a\u200bb.txt",
		"仕事.pdf",
		"\xff",
		"conxyz." + strings.Repeat("e", 196),
		"é." + strings.Repeat("e", 198),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := SaveName(in)
		if err != nil {
			return
		}
		if got == "" {
			t.Fatalf("SaveName(%q) = empty, nil error", in)
		}
		if strings.ContainsAny(got, `/\`) {
			t.Fatalf("SaveName(%q) = %q, still holds a path separator", in, got)
		}
		if len(got) > maxSaveNameBytes {
			t.Fatalf("SaveName(%q) = %q, %d bytes > limit %d", in, got, len(got), maxSaveNameBytes)
		}
		if !utf8.ValidString(got) {
			t.Fatalf("SaveName(%q) = %q, invalid UTF-8", in, got)
		}
		if strings.HasPrefix(got, ".") {
			t.Fatalf("SaveName(%q) = %q, leading dot", in, got)
		}
		if isWindowsReserved(got) {
			t.Fatalf("SaveName(%q) = %q, a Windows device name", in, got)
		}
		for _, r := range got {
			if r < 0x20 || isInvisible(r) {
				t.Fatalf("SaveName(%q) = %q, still holds a control/hidden character %U", in, got, r)
			}
		}
	})
}

// TestSavePath_ResolveErrorNoPanic guards CreateSaveFile against a
// directory that cannot be written to at all: it must return an error,
// never panic, and never fall back to a different directory silently.
//
// arch: T2.3, §3.15, §5.4, G6, §10.9
func TestSavePath_ResolveErrorNoPanic(t *testing.T) {
	root := realTempDir(t)
	dir := filepath.Join(root, "does-not-exist")
	_, _, err := CreateSaveFile(dir, "file.txt", []string{root})
	if err == nil {
		t.Fatal("CreateSaveFile into a missing directory: want error, got nil")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("CreateSaveFile error = %v, want an fs.ErrNotExist", err)
	}
}

// TestSavePath_HiddenBelowRootRefused checks that ResolveSaveDir
// refuses a directory whose part below the matched root has a hidden
// component. With download_dirs = ["~"], a save_dir of
// "~/.config/autostart" would let a sender-named file run at the next
// desktop login. A dot component above the root is the choice of the
// owner and passes. A link that resolves to a hidden directory is
// refused too.
//
// arch: T2.3, §3.15, G6, R16-M3
func TestSavePath_HiddenBelowRootRefused(t *testing.T) {
	root := realTempDir(t)
	if err := os.MkdirAll(filepath.Join(root, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "visible", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	dotRoot := filepath.Join(root, ".mail")
	if err := os.MkdirAll(filepath.Join(dotRoot, "in"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "keys")
	if err := os.Symlink(filepath.Join(root, ".ssh"), link); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		roots   []string
		dir     string
		wantErr bool
	}{
		{"hidden dir that does not exist yet", []string{root}, filepath.Join(root, ".config", "autostart"), true},
		{"hidden dir that exists", []string{root}, filepath.Join(root, ".ssh"), true},
		{"hidden component deeper down", []string{root}, filepath.Join(root, "visible", ".hidden"), true},
		{"link to a hidden dir", []string{root}, link, true},
		{"visible subdirectory", []string{root}, filepath.Join(root, "visible", "sub"), false},
		{"root itself", []string{root}, root, false},
		{"root with a dot component of its own", []string{dotRoot}, filepath.Join(dotRoot, "in"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveSaveDir(tt.dir, tt.roots)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveSaveDir(%q, %v) = %q, err=%v, wantErr=%v", tt.dir, tt.roots, got, err, tt.wantErr)
			}
		})
	}
}

// realTempDir returns t.TempDir() with its symbolic links resolved.
// The guard compares canonical paths, and on macOS t.TempDir() is
// under /var, a link to /private/var; on Windows it can hold an 8.3
// short name. A test root must be in the form the guard returns.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
