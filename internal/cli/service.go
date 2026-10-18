// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The "service install|uninstall" command: it writes or removes the
// systemd user units of the daemon (DS11.11). It never runs systemctl.

package cli

import (
	_ "embed" // needed by the embed directives below
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"
)

// The unit texts live once, in the systemd directory next to this file
// (DS11.11). The release archive carries the same files.
var (
	//go:embed systemd/mailbag.socket
	socketUnit string

	//go:embed systemd/mailbag.service
	serviceUnit string
)

// Names of the two unit files and the commands the person runs next.
// The CLI prints these commands and never runs them (owner rule 12).
const (
	socketUnitName   = "mailbag.socket"
	serviceUnitName  = "mailbag.service"
	unitExecStart    = "ExecStart=%h/.local/bin/mailbag-mcp serve"
	enableCommand    = "systemctl --user daemon-reload && systemctl --user enable --now mailbag.socket"
	disableCommand   = "systemctl --user disable --now mailbag.socket"
	unitFileMode     = 0o644
	unitDirMode      = 0o755
	systemctlProgram = "systemctl"
)

// serviceCmd handles "service install" and "service uninstall".
// install writes mailbag.socket and mailbag.service to
// $XDG_CONFIG_HOME/systemd/user/ (default ~/.config/systemd/user/), with
// ExecStart set to the absolute path of this executable, mode 0644, and
// prints the one command the person runs next:
//
//	systemctl --user daemon-reload && systemctl --user enable --now mailbag.socket
//
// uninstall removes the two files and prints the command to run:
//
//	systemctl --user disable --now mailbag.socket
//
// The CLI never runs systemctl itself (owner rule 12). On a host without
// systemd (no systemctl in PATH) install still writes the files and says
// that the shim spawn path (DS11.8) is the path on this host.
//
// arch: DS11.11, IS11.10
func serviceCmd(args []string, env Env) int {
	if len(args) == 0 {
		return usageErrf(env, "service needs a subcommand: install or uninstall")
	}
	switch args[0] {
	case "install":
		return serviceInstall(args[1:], env)
	case "uninstall":
		if len(args) > 1 {
			return usageErrf(env, "unexpected argument %q", args[1])
		}
		return serviceUninstall(env)
	default:
		return usageErrf(env, "unknown service subcommand %q", args[0])
	}
}

// serviceInstall writes the two unit files. An existing file with other
// content is replaced only with --force; without it, the command writes
// nothing, prints each differing path and exits 1.
func serviceInstall(args []string, env Env) int {
	set := flag.NewFlagSet("service install", flag.ContinueOnError)
	// The flag package prints its error before the usage. usageErrf
	// prints the usage first, so the first line starts with "usage:".
	set.SetOutput(io.Discard)
	force := set.Bool("force", false, "replace a unit file that holds other content")
	if err := set.Parse(args); err != nil {
		return usageErrf(env, "service install: %v", err)
	}
	if set.NArg() > 0 {
		return usageErrf(env, "unexpected argument %q", set.Arg(0))
	}

	dir, err := unitDir()
	if err != nil {
		return failf(env, "service install: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return failf(env, "service install: find this executable: %v", err)
	}
	execStart, err := execStartPath(exe)
	if err != nil {
		return failf(env, "service install: %v", err)
	}
	units := []struct{ name, text string }{
		{socketUnitName, socketUnit},
		{serviceUnitName, strings.Replace(serviceUnit, unitExecStart, "ExecStart="+execStart+" serve", 1)},
	}

	// Compare first, write after: a refusal leaves both files as they are.
	if !*force {
		code := exitOK
		for _, u := range units {
			path := filepath.Join(dir, u.name)
			old, err := os.ReadFile(path) //nolint:gosec // G304: the path is a unit file in the user's own systemd directory
			switch {
			case errors.Is(err, fs.ErrNotExist):
			case err != nil:
				return failf(env, "service install: %v", err)
			case string(old) != u.text:
				code = failf(env, "service install: %s holds other content; run again with --force to replace it", path)
			}
		}
		if code != exitOK {
			return code
		}
	}

	if err := os.MkdirAll(dir, unitDirMode); err != nil {
		return failf(env, "service install: %v", err)
	}
	for _, u := range units {
		path := filepath.Join(dir, u.name)
		if err := os.WriteFile(path, []byte(u.text), unitFileMode); err != nil {
			return failf(env, "service install: %v", err)
		}
		// WriteFile applies the umask to a new file and keeps the mode of
		// an old file. Chmod sets 0644 in both cases.
		if err := os.Chmod(path, unitFileMode); err != nil {
			return failf(env, "service install: %v", err)
		}
		printf(env, "wrote %s", path)
	}

	if _, err := exec.LookPath(systemctlProgram); err != nil {
		printf(env, "systemctl is not in PATH, so this host does not use these units.")
		printf(env, "Here the shim starts the daemon when a client needs it (the shim spawn path).")
		return exitOK
	}
	printf(env, "To start the daemon socket, run:")
	printf(env, "  %s", enableCommand)
	return exitOK
}

// serviceUninstall removes the two unit files. A file that is not there
// is not an error, so the command is safe to run again.
func serviceUninstall(env Env) int {
	dir, err := unitDir()
	if err != nil {
		return failf(env, "service uninstall: %v", err)
	}
	for _, name := range []string{socketUnitName, serviceUnitName} {
		path := filepath.Join(dir, name)
		err := os.Remove(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			printf(env, "%s does not exist", path)
		case err != nil:
			return failf(env, "service uninstall: %v", err)
		default:
			printf(env, "removed %s", path)
		}
	}
	printf(env, "To stop and disable the daemon socket, run:")
	printf(env, "  %s", disableCommand)
	return exitOK
}

// unitDir gives the directory of the systemd user units:
// $XDG_CONFIG_HOME/systemd/user, or ~/.config/systemd/user when
// XDG_CONFIG_HOME is empty. A relative XDG_CONFIG_HOME is not valid
// (XDG base directory specification), so it counts as empty.
func unitDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "systemd", "user"), nil
}

// execStartPath writes an executable path as the first word of an
// ExecStart= line (systemd.service(5), "Command lines"). "%" starts a
// specifier, so it becomes "%%". A path with a space, a quote or a
// backslash goes in double quotes, with "\" and the double quote
// escaped. A path with "$" or a control character gets an error: the
// unit file cannot carry it as plain text.
func execStartPath(path string) (string, error) {
	if strings.ContainsRune(path, '$') || strings.ContainsFunc(path, unicode.IsControl) {
		return "", fmt.Errorf("the path %q holds a character that a unit file cannot carry; move the program to another path", path)
	}
	path = strings.ReplaceAll(path, "%", "%%")
	if !strings.ContainsAny(path, " \"'\\") {
		return path, nil
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(path) + `"`, nil
}
