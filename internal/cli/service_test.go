// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of "service install|uninstall" (DS11.11). Every test writes into
// its own temp HOME and XDG_CONFIG_HOME, never into the owner's
// ~/.config/systemd/user, and puts a fake systemctl first in PATH that
// records a run, so the tests prove that the CLI never runs systemctl.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// serviceSandbox points HOME and XDG_CONFIG_HOME at temp directories
// and replaces PATH with one temp directory. With withSystemctl, that
// directory holds a fake systemctl that writes the returned marker file
// when something runs it. It gives back the unit directory and the
// marker path.
func serviceSandbox(t *testing.T, withSystemctl bool) (unitDir, marker string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)

	bin := t.TempDir()
	marker = filepath.Join(t.TempDir(), "systemctl-ran")
	if withSystemctl {
		name := "systemctl"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		script := "#!/bin/sh\necho ran > '" + marker + "'\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil { //nolint:gosec // G306: the test needs this mode: it runs a script, opens a dir, or checks a mode test
			t.Fatalf("write the fake systemctl: %v", err)
		}
	}
	t.Setenv("PATH", bin)
	return filepath.Join(cfg, "systemd", "user"), marker
}

// runService runs one "service ..." command line and gives back the
// exit code, stdout and stderr.
func runService(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(append([]string{"service"}, args...), Env{Stdout: &out, Stderr: &errOut})
	return code, out.String(), errOut.String()
}

// wantServiceText gives the mailbag.service text that install writes
// for the executable of this test process.
func wantServiceText(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	execStart, err := execStartPath(exe)
	if err != nil {
		t.Fatalf("execStartPath(%q): %v", exe, err)
	}
	if !strings.Contains(serviceUnit, unitExecStart) {
		t.Fatalf("the embedded mailbag.service has no %q line:\n%s", unitExecStart, serviceUnit)
	}
	return strings.Replace(serviceUnit, unitExecStart, "ExecStart="+execStart+" serve", 1)
}

// readFile gives the text of path, or fails the test.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test reads a path it built in its own temp dir
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// assertSystemctlNeverRan fails the test when the fake systemctl ran.
func assertSystemctlNeverRan(t *testing.T, marker string) {
	t.Helper()
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("the CLI ran systemctl; it must only print the command (owner rule 12)")
	}
}

// TestCLI_ServiceInstallWritesUnits proves that install writes the two
// embedded units into $XDG_CONFIG_HOME/systemd/user with mode 0644,
// sets ExecStart to the absolute path of this executable, prints the
// daemon-reload and enable command, and never runs systemctl. No daemon
// runs in the test, so the command also needs none.
//
// arch: DS11.11, IS11.10
func TestCLI_ServiceInstallWritesUnits(t *testing.T) {
	dir, marker := serviceSandbox(t, true)

	code, out, errOut := runService(t, "install")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitOK, errOut)
	}

	socket := filepath.Join(dir, socketUnitName)
	service := filepath.Join(dir, serviceUnitName)
	if got := readFile(t, socket); got != socketUnit {
		t.Errorf("mailbag.socket =\n%s\nwant the embedded text\n%s", got, socketUnit)
	}
	got := readFile(t, service)
	if want := wantServiceText(t); got != want {
		t.Errorf("mailbag.service =\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(got, "%h") {
		t.Errorf("mailbag.service still holds the %%h placeholder:\n%s", got)
	}
	exe, _ := os.Executable()
	if !filepath.IsAbs(exe) || !strings.Contains(got, exe) {
		t.Errorf("mailbag.service does not name the absolute executable %q:\n%s", exe, got)
	}
	if !strings.Contains(readFile(t, socket), "ListenStream=%t/mailbag/mailbag.sock") {
		t.Errorf("mailbag.socket has no ListenStream=%%t/mailbag/mailbag.sock line")
	}
	if !strings.Contains(got, "TimeoutStopSec=620") {
		t.Errorf("mailbag.service has no TimeoutStopSec=620 line:\n%s", got)
	}

	if runtime.GOOS != "windows" {
		for _, path := range []string{socket, service} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if mode := info.Mode().Perm(); mode != 0o644 {
				t.Errorf("%s mode = %o, want 644", path, mode)
			}
		}
	}

	for _, want := range []string{socket, service, enableCommand} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout does not hold %q:\n%s", want, out)
		}
	}
	assertSystemctlNeverRan(t, marker)
}

// TestCLI_ServiceInstallRefusesDifferentFileWithoutForce proves that an
// existing unit file with other content stops install with exit 1 and
// its path, and that the refusal writes no file. The same files again
// need no --force, and --force replaces the differing file.
//
// arch: DS11.11, IS11.10
func TestCLI_ServiceInstallRefusesDifferentFileWithoutForce(t *testing.T) {
	dir, marker := serviceSandbox(t, true)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	service := filepath.Join(dir, serviceUnitName)
	socket := filepath.Join(dir, socketUnitName)
	const handWritten = "[Service]\nExecStart=/opt/old/mailbag-mcp serve\n"
	if err := os.WriteFile(service, []byte(handWritten), 0o644); err != nil { //nolint:gosec // G306: the test needs this mode: it runs a script, opens a dir, or checks a mode test
		t.Fatal(err)
	}

	code, _, errOut := runService(t, "install")
	if code != exitFail {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitFail, errOut)
	}
	if !strings.Contains(errOut, service) {
		t.Errorf("stderr does not name the differing file %s:\n%s", service, errOut)
	}
	if !strings.Contains(errOut, "--force") {
		t.Errorf("stderr does not name --force:\n%s", errOut)
	}
	if got := readFile(t, service); got != handWritten {
		t.Errorf("the refused install changed mailbag.service:\n%s", got)
	}
	if _, err := os.Stat(socket); err == nil {
		t.Errorf("the refused install wrote %s", socket)
	}

	if code, _, errOut := runService(t, "install", "--force"); code != exitOK {
		t.Fatalf("install --force: exit code = %d, want %d\nstderr: %s", code, exitOK, errOut)
	}
	if got, want := readFile(t, service), wantServiceText(t); got != want {
		t.Errorf("after --force mailbag.service =\n%s\nwant\n%s", got, want)
	}

	if code, _, errOut := runService(t, "install"); code != exitOK {
		t.Errorf("install over the same files: exit code = %d, want %d\nstderr: %s", code, exitOK, errOut)
	}
	assertSystemctlNeverRan(t, marker)
}

// TestCLI_ServiceUninstallRemoves proves that uninstall removes the two
// unit files and no other file, prints the disable command, never runs
// systemctl, and exits 0 when it runs again on the empty directory.
//
// arch: DS11.11, IS11.10
func TestCLI_ServiceUninstallRemoves(t *testing.T) {
	dir, marker := serviceSandbox(t, true)
	if code, _, errOut := runService(t, "install"); code != exitOK {
		t.Fatalf("install: exit code = %d\nstderr: %s", code, errOut)
	}
	other := filepath.Join(dir, "other.service")
	if err := os.WriteFile(other, []byte("[Service]\n"), 0o644); err != nil { //nolint:gosec // G306: the test needs this mode: it runs a script, opens a dir, or checks a mode test
		t.Fatal(err)
	}

	code, out, errOut := runService(t, "uninstall")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitOK, errOut)
	}
	for _, name := range []string{socketUnitName, serviceUnitName} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still there after uninstall (stat error %v)", name, err)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("uninstall touched another unit file: %v", err)
	}
	if !strings.Contains(out, disableCommand) {
		t.Errorf("stdout does not hold %q:\n%s", disableCommand, out)
	}

	if code, _, errOut := runService(t, "uninstall"); code != exitOK {
		t.Errorf("second uninstall: exit code = %d, want %d\nstderr: %s", code, exitOK, errOut)
	}
	assertSystemctlNeverRan(t, marker)
}

// TestCLI_ServiceInstallWithoutSystemctl proves that on a host with no
// systemctl in PATH, install still writes the two files, names the shim
// spawn path and prints no systemctl command.
//
// arch: DS11.11, IS11.10
func TestCLI_ServiceInstallWithoutSystemctl(t *testing.T) {
	dir, _ := serviceSandbox(t, false)

	code, out, errOut := runService(t, "install")
	if code != exitOK {
		t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitOK, errOut)
	}
	for _, name := range []string{socketUnitName, serviceUnitName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("install wrote no %s: %v", name, err)
		}
	}
	if !strings.Contains(out, "shim spawn path") {
		t.Errorf("stdout does not name the shim spawn path:\n%s", out)
	}
	if strings.Contains(out, enableCommand) {
		t.Errorf("stdout prints the systemctl command on a host with no systemctl:\n%s", out)
	}
}

// TestCLI_ServiceInstallDefaultDir proves that with XDG_CONFIG_HOME
// empty or relative, install writes into ~/.config/systemd/user.
//
// arch: DS11.11, IS11.10
func TestCLI_ServiceInstallDefaultDir(t *testing.T) {
	for name, value := range map[string]string{"empty": "", "relative": "relative/config"} {
		t.Run(name, func(t *testing.T) {
			serviceSandbox(t, true)
			t.Setenv("XDG_CONFIG_HOME", value)
			// A relative value that the code used by mistake lands here,
			// not in the package directory.
			t.Chdir(t.TempDir())
			home, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}

			if code, _, errOut := runService(t, "install"); code != exitOK {
				t.Fatalf("exit code = %d, want %d\nstderr: %s", code, exitOK, errOut)
			}
			path := filepath.Join(home, ".config", "systemd", "user", socketUnitName)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("install wrote no %s: %v", path, err)
			}
		})
	}
}

// TestCLI_ServiceUsageErrors proves that a wrong "service" command line
// exits 2 with the usage block, which names service install|uninstall.
//
// arch: DS11.11, IS11.10
func TestCLI_ServiceUsageErrors(t *testing.T) {
	serviceSandbox(t, true)
	cases := map[string][]string{
		"no subcommand":      {},
		"unknown subcommand": {"start"},
		"install extra":      {"install", "now"},
		"install bad flag":   {"install", "--now"},
		"uninstall force":    {"uninstall", "--force"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := runService(t, args...)
			if code != exitUsage {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitUsage, errOut)
			}
			if !strings.HasPrefix(errOut, "usage:") {
				t.Errorf("the first line does not start with \"usage:\":\n%s", errOut)
			}
			if !strings.Contains(errOut, "service install|uninstall") {
				t.Errorf("the usage text does not name service install|uninstall:\n%s", errOut)
			}
			if out != "" {
				t.Errorf("a usage error wrote to stdout:\n%s", out)
			}
		})
	}
}

// TestCLI_ServiceExecStartEscapes proves the quoting rule of the
// ExecStart path (systemd.service(5), "Command lines").
//
// arch: DS11.11, IS11.10
func TestCLI_ServiceExecStartEscapes(t *testing.T) {
	cases := []struct {
		path, want string
		fails      bool
	}{
		{path: "/home/me/.local/bin/mailbag-mcp", want: "/home/me/.local/bin/mailbag-mcp"},
		{path: "/opt/100%/mailbag-mcp", want: "/opt/100%%/mailbag-mcp"},
		{path: "/home/me/My Apps/mailbag-mcp", want: `"/home/me/My Apps/mailbag-mcp"`},
		{path: `/opt/a"b\c/mailbag-mcp`, want: `"/opt/a\"b\\c/mailbag-mcp"`},
		{path: "/opt/it's/mailbag-mcp", want: `"/opt/it's/mailbag-mcp"`},
		{path: "/opt/$HOME/mailbag-mcp", fails: true},
		{path: "/opt/a\nb/mailbag-mcp", fails: true},
	}
	for _, c := range cases {
		got, err := execStartPath(c.path)
		if c.fails {
			if err == nil {
				t.Errorf("execStartPath(%q) = %q, want an error", c.path, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("execStartPath(%q) = %q, %v; want %q, nil", c.path, got, err, c.want)
		}
	}
}
