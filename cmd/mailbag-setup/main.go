// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Command mailbag-setup serves one local web page that sets up
// mailbag-mcp. It changes the mailbag state only through the
// mailbag-mcp CLI, and it stops at "Finish", after 20 minutes with no
// API request, or at SIGINT or SIGTERM.
//
// This file holds the start: the flags, the lookup of the mailbag-mcp
// binary, the listener and the browser. server.go holds the server.
//
// arch: DS13.1, DS13.2, DS13.7, DS13.9, IS13.5
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
)

// cliName is the name of the main binary that mailbag-setup runs.
const cliName = "mailbag-mcp"

// setupName is the name of this binary. Its version line starts with
// it, as the version line of the CLI starts with cliName.
const setupName = "mailbag-setup"

// idleLimit is the time with no API request after which the server
// stops (DS13.6 rule 10).
const idleLimit = 20 * time.Minute

// usageText is the help text of mailbag-setup.
const usageText = `usage: mailbag-setup [--no-browser]
       mailbag-setup version

Serves the mailbag setup page on 127.0.0.1 and opens it in the browser.
--no-browser prints the address only.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run starts the setup server and blocks until it stops. It writes
// every message to stderr: stdout is not used (A1 scan of
// TestNoStdoutWrites). It returns the exit code.
//
// arch: DS13.1, DS13.7, DS13.9, IS13.5
func run(args []string, stderr io.Writer) int {
	set := flag.NewFlagSet(setupName, flag.ContinueOnError)
	set.SetOutput(stderr)
	set.Usage = func() { _, _ = fmt.Fprint(stderr, usageText) }
	noBrowser := set.Bool("no-browser", false, "print the address only; do not open a browser")
	if err := set.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	switch {
	case set.NArg() == 1 && set.Arg(0) == "version":
		_, _ = fmt.Fprintln(stderr, setupName+" "+buildVersion())
		return 0
	case set.NArg() > 0:
		_, _ = fmt.Fprintf(stderr, "unexpected argument %q\n%s", set.Arg(0), usageText)
		return 2
	}

	// DS13.9: over SSH, the page and the CLI sign-in need a browser on
	// this host. Say so, and do not start a browser here.
	if os.Getenv("SSH_CONNECTION") != "" {
		_, _ = fmt.Fprintf(stderr, "%s: this is an SSH session. Run %s on the desktop, or use \"%s account add ... --paste\" here.\n",
			setupName, setupName, cliName)
		*noBrowser = true
	}

	cli, err := findCLI(os.Args[0], os.Getenv("PATH"))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", setupName, err)
		return 1
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: listen on 127.0.0.1: %v\n", setupName, err)
		return 1
	}
	s, err := newServer(serverConfig{
		CLIPath:      cli,
		SetupVersion: setupName + " " + buildVersion(),
		Idle:         idleLimit,
	}, ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", setupName, err)
		return 1
	}

	url := "http://" + s.host + "/#k=" + s.token
	_, _ = fmt.Fprintf(stderr, "%s: open %s\n", setupName, url)
	if !*noBrowser {
		openBrowser(url, stderr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s.serve(ctx, ln)
	_, _ = fmt.Fprintf(stderr, "%s: stopped\n", setupName)
	return 0
}

// buildVersion gives the version of the module from the Go build
// info, as mailbag-mcp does. Both binaries are in one module, so one
// build gives the same text to both.
//
// arch: DS13.7
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}

// findCLI gives the path of the mailbag-mcp binary that the server
// runs (DS13.7): first the binary in the directory of mailbag-setup,
// else the binary on PATH. The path stays as found, before symlinks
// are resolved, because a Homebrew Cellar path changes at each
// upgrade (M5). argv0 is os.Args[0].
//
// arch: DS13.7
func findCLI(argv0, pathEnv string) (string, error) {
	if dir := selfDir(argv0, pathEnv); dir != "" {
		p := filepath.Join(dir, cliName)
		if isExecFile(p) {
			return p, nil
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue // a relative PATH entry depends on the working directory
		}
		p := filepath.Join(dir, cliName)
		if isExecFile(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("found no %s next to %s and none on PATH", cliName, setupName)
}

// selfDir gives the directory of this binary as the person started
// it, before symlinks are resolved. It gives "" when it cannot tell.
func selfDir(argv0, pathEnv string) string {
	if strings.ContainsRune(argv0, filepath.Separator) {
		abs, err := filepath.Abs(argv0)
		if err != nil {
			return ""
		}
		return filepath.Dir(abs)
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir != "" && filepath.IsAbs(dir) && isExecFile(filepath.Join(dir, argv0)) {
			return dir
		}
	}
	return ""
}

// isExecFile reports whether p is a regular file with an execute bit.
func isExecFile(p string) bool {
	info, err := os.Stat(p) //nolint:gosec // G703: p is a PATH entry or the directory of this binary joined with a fixed name; Stat reads no file content
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return runtime.GOOS == "windows" || info.Mode().Perm()&0o111 != 0
}

// newToken gives the 32-byte random token of DS13.6 rule 2, hex
// encoded.
//
// arch: DS13.6
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// openBrowser opens url with xdg-open (Linux) or open (macOS). The
// command runs with a fixed name and no shell. A failure is a note
// only: the address is on the terminal.
//
// arch: DS13.9, IS13.5
func openBrowser(url string, stderr io.Writer) {
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "open"
	case "linux", "freebsd", "openbsd", "netbsd":
		name = "xdg-open"
	default:
		return
	}
	cmd := exec.Command(name, url) //nolint:gosec // G204: a fixed program name and one URL argument, no shell
	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: could not start %s: %v; open the address by hand\n", setupName, name, err)
		return
	}
	go func() { _ = cmd.Wait() }()
}
