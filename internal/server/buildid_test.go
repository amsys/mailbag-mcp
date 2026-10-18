// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the build id and the config id (DS11.5): the format, the
// value that the first call fixes, the directories that the first
// ConfigID call of a new process reads, and a different id for another
// build or another pair of directories.

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// TestBuildID_Format checks that BuildID gives
// "<version>/<size>/<mtime>" for the test binary, with no space, and
// the same value on each call.
//
// arch: DS11.5, DS11.16, IS11.5
func TestBuildID_Format(t *testing.T) {
	id := BuildID()
	if !regexp.MustCompile(`^[^\s/]+/[0-9]+/-?[0-9]+$`).MatchString(id) {
		t.Fatalf("BuildID() = %q, want <version>/<size>/<mtime> with no space", id)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	fi, err := os.Stat(exe)
	if err != nil {
		t.Fatalf("stat %s: %v", exe, err)
	}
	want := mainVersion() + "/" + strconv.FormatInt(fi.Size(), 10) + "/" +
		strconv.FormatInt(fi.ModTime().UnixNano(), 10)
	if id != want {
		t.Errorf("BuildID() = %q, want %q", id, want)
	}
	if again := BuildID(); again != id {
		t.Errorf("second BuildID() = %q, want %q", again, id)
	}
}

// TestBuildID_ChangesWithMtime checks that a new mtime of the
// executable gives a new id, and that the value of the first call stays
// after the file changes, as when go build replaces the file under a
// running daemon. The test sets whole-second file times. After each
// os.Chtimes it reads the mtime back with os.Stat and makes the
// expected id from that value, because Windows keeps file times in
// units of 100 ns (G7a in DS11.20).
//
// arch: DS11.5, DS11.16, IS11.5
func TestBuildID_ChangesWithMtime(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "mailbag-mcp")
	if err := os.WriteFile(exe, []byte("build one"), 0o600); err != nil {
		t.Fatal(err)
	}
	// setMtime sets the mtime of exe and gives the expected id: the
	// size of "build one" and the mtime that os.Stat reads back.
	setMtime := func(mtime time.Time) string {
		t.Helper()
		if err := os.Chtimes(exe, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(exe)
		if err != nil {
			t.Fatalf("stat %s: %v", exe, err)
		}
		return mainVersion() + "/9/" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
	}

	old := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
	wantFirst := setMtime(old)
	get := onceBuildID(func() (string, error) { return exe, nil })
	first := get()
	if first != wantFirst {
		t.Fatalf("first id = %q, want %q", first, wantFirst)
	}

	// Same size, new mtime: a rebuild that gives a file of equal size.
	wantNow := setMtime(old.Add(time.Second))
	now := buildIDOf(mainVersion(), exe)
	if now == first {
		t.Fatalf("id after the mtime change = %q, want a value other than %q", now, first)
	}
	if now != wantNow {
		t.Errorf("id after the mtime change = %q, want %q", now, wantNow)
	}
	if again := get(); again != first {
		t.Errorf("id of a later call = %q, want the value of the first call %q", again, first)
	}

	// An executable that cannot be found gives size and mtime 0.
	none := onceBuildID(func() (string, error) { return "", os.ErrNotExist })
	if got, want := none(), mainVersion()+"/0/0"; got != want {
		t.Errorf("id with no executable = %q, want %q", got, want)
	}
}

// configIDOutEnv names the file where a child process of the test
// binary writes the value of its first ConfigID call. Only
// configIDInNewProcess sets it.
const configIDOutEnv = "MAILBAG_TEST_CONFIGID_OUT"

// TestConfigID_StableAndDistinct checks that ConfigID gives 16 hex
// digits of sha256(configDir + "\x00" + stateDir), the same value on
// each call, also after the directories change, and a different id for
// another pair of directories. A new process of the test binary makes
// the first ConfigID call: it must read the directories from
// config.ConfigDir and config.StateDir (MAILBAG_CONFIG_DIR and
// MAILBAG_STATE_DIR), and make a relative directory absolute. In this
// process, an earlier test or an earlier -count run can make the first
// call.
//
// arch: DS11.5, DS11.16, IS11.5
func TestConfigID_StableAndDistinct(t *testing.T) {
	if out := os.Getenv(configIDOutEnv); out != "" {
		writeFirstConfigID(t, out)
		return
	}

	cfgA, stateA := t.TempDir(), t.TempDir()
	cfgB, stateB := t.TempDir(), t.TempDir()
	t.Setenv("MAILBAG_CONFIG_DIR", cfgA)
	t.Setenv("MAILBAG_STATE_DIR", stateA)

	first, err := ConfigID()
	if err != nil {
		t.Fatalf("ConfigID: %v", err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(first) {
		t.Fatalf("ConfigID() = %q, want 16 hex digits", first)
	}

	t.Setenv("MAILBAG_CONFIG_DIR", cfgB)
	t.Setenv("MAILBAG_STATE_DIR", stateB)
	if again, err := ConfigID(); err != nil || again != first {
		t.Errorf("ConfigID() after the directories changed = %q, %v; want %q, nil", again, err, first)
	}

	idOf := func(cfg, state string) string {
		t.Helper()
		id, err := configIDOf(cfg, state)
		if err != nil {
			t.Fatalf("configIDOf(%q, %q): %v", cfg, state, err)
		}
		return id
	}
	sum := sha256.Sum256([]byte(cfgA + "\x00" + stateA))
	a := idOf(cfgA, stateA)
	if want := hex.EncodeToString(sum[:])[:16]; a != want {
		t.Errorf("configIDOf(A) = %q, want %q", a, want)
	}
	if again := idOf(cfgA, stateA); again != a {
		t.Errorf("second configIDOf(A) = %q, want %q", again, a)
	}
	for name, id := range map[string]string{
		"other pair":          idOf(cfgB, stateB),
		"other state dir":     idOf(cfgA, stateB),
		"directories swapped": idOf(stateA, cfgA),
	} {
		if id == a {
			t.Errorf("%s: id %q is the id of pair A", name, id)
		}
	}
	if b := idOf(cfgB, stateB); b == first {
		t.Errorf("ConfigID() = %q, the id of the new pair B: the value did not stay", first)
	}

	// The first ConfigID call of a new process reads the two
	// directories. A relative MAILBAG_CONFIG_DIR gives the id of its
	// absolute path.
	if got := configIDInNewProcess(t, "", cfgA, stateA); got != a {
		t.Errorf("ConfigID() in a new process for pair A = %q, want %q", got, a)
	}
	if got, want := configIDInNewProcess(t, filepath.Dir(cfgB), filepath.Base(cfgB), stateB), idOf(cfgB, stateB); got != want {
		t.Errorf("ConfigID() in a new process for pair B (relative config dir) = %q, want %q", got, want)
	}

	// A relative directory gives the id of its absolute path.
	t.Chdir(filepath.Dir(cfgA))
	if rel := idOf(filepath.Base(cfgA), stateA); rel != a {
		t.Errorf("configIDOf(relative A) = %q, want %q", rel, a)
	}
}

// configIDInNewProcess runs TestConfigID_StableAndDistinct in a new
// process of the test binary, with dir as the working directory (""
// keeps the current one) and cfg and state as MAILBAG_CONFIG_DIR and
// MAILBAG_STATE_DIR. It returns the value of the first ConfigID call of
// that process.
func configIDInNewProcess(t *testing.T, dir, cfg, state string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	out := filepath.Join(t.TempDir(), "configid")
	cmd := exec.Command(exe, "-test.run=^TestConfigID_StableAndDistinct$", "-test.count=1") //nolint:gosec // G204: test code; the program and its arguments are built by the test
	cmd.Dir = dir
	// cmd.Environ, not os.Environ: with Dir set, it adds PWD=dir. With
	// no PWD for dir, os.Getwd in the child gives the path with the
	// symbolic links resolved (on macOS, /var is a link to /private/var),
	// and the relative directory then gives another id.
	cmd.Env = append(cmd.Environ(),
		"MAILBAG_CONFIG_DIR="+cfg,
		"MAILBAG_STATE_DIR="+state,
		configIDOutEnv+"="+out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child test process: %v\n%s", err, b)
	}
	id, err := os.ReadFile(out) //nolint:gosec // G304: test code; the path is built by the test
	if err != nil {
		t.Fatalf("the child test process wrote no config id: %v", err)
	}
	return string(id)
}

// writeFirstConfigID runs in the child process of
// configIDInNewProcess. It makes the first ConfigID call of the process
// and writes the value to the file out.
func writeFirstConfigID(t *testing.T, out string) {
	id, err := ConfigID()
	if err != nil {
		t.Fatalf("ConfigID: %v", err)
	}
	if err := os.WriteFile(out, []byte(id), 0o600); err != nil { //nolint:gosec // G703: out is the path the test run was told to write, not mail data
		t.Fatalf("write %s: %v", out, err)
	}
}
