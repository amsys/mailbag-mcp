// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Command mailbag-mcp is a stdio MCP server for N mailboxes. With no
// argument it is the shim, the MCP entry that the client starts;
// "serve" runs the daemon; the other commands are the CLI (DS11.1,
// DS11.13). See docs/features/mailbag/03-design.md for the design.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/amsys/mailbag-mcp/internal/cli"
	"github.com/amsys/mailbag-mcp/internal/server"
	"github.com/amsys/mailbag-mcp/internal/shim"
)

// main reads the build id and the config id before anything else
// (DS11.5): go build can replace the executable under a running
// process, and the first call fixes both values. Then it runs the
// mode of the first argument (DS11.13).
//
// arch: DS11.1, DS11.5, DS11.13
func main() {
	buildID := server.BuildID()
	configID, configErr := server.ConfigID()

	if len(os.Args) < 2 {
		os.Exit(runShim(buildID, configID, configErr))
	}

	switch os.Args[1] {
	case "version":
		printVersion()
	case "serve":
		os.Exit(server.ServeSocket(version()))
	case "account":
		os.Exit(cli.Run(os.Args[1:], cli.Env{}))
	case "oauth":
		os.Exit(cli.Run(os.Args[1:], cli.Env{}))
	case "tools":
		os.Exit(cli.Run(os.Args[1:], cli.Env{}))
	case "doctor":
		os.Exit(cli.Run(os.Args[1:], cli.Env{}))
	case "service":
		os.Exit(cli.Run(os.Args[1:], cli.Env{}))
	default:
		fmt.Fprintf(os.Stderr, "usage: mailbag-mcp [serve|version|account|oauth|tools|doctor|service install|uninstall]: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

// runShim runs the MCP entry: shim.Run with the seams of production
// (DS11.13). Dial dials SocketName in SocketDir, Spawn starts
// "<os.Executable()> serve", and Fallback runs server.Serve on the
// stdio of this process. When the socket directory or the config id
// is not available, Dial and Spawn stay nil and Run calls Fallback
// at once (DS11.8 step 2): Serve then reports a config failure itself.
// runShim closes the log of the shim before it returns.
//
// arch: DS11.8, DS11.13, DS11.20, IS11.1
func runShim(buildID, configID string, configErr error) int {
	in, out := stdio()
	logger, closeLog, _ := server.OpenLog() // a failure gives the stderr logger (§3.19)
	if closeLog != nil {
		defer func() { _ = closeLog.Close() }()
	}

	o := shim.Options{
		Version:  version(),
		BuildID:  buildID,
		ConfigID: configID,
		In:       in,
		Out:      out,
		Logger:   logger,
		Fallback: func() int { return server.Serve(version(), in, out) },
		Ppid:     os.Getppid,
	}
	if dir, err := server.SocketDir(); err == nil && configErr == nil {
		sock := filepath.Join(dir, server.SocketName)
		o.LockDir = dir
		o.Dial = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
		o.Spawn = func(ctx context.Context) error {
			self, err := os.Executable()
			if err != nil {
				return err
			}
			return shim.Spawn(ctx, self)
		}
	}
	return shim.Run(context.Background(), o)
}

// printVersion writes the version to stdout. It is the one write to
// os.Stdout this file makes outside serve mode: A1 (§4) bans
// fmt.Print* and os.Stdout outside internal/cli because a stray
// stdout line breaks the JSON-RPC stream, but that stream only opens
// inside server.Serve, which this "version" branch never reaches.
// T11's TestNoStdoutWrites should allow this function by name.
//
// arch: A1
func printVersion() {
	fmt.Println(version())
}

// stdio returns the process stdio for the MCP entry. It is the one
// function outside internal/cli and printVersion that names os.Stdout
// (TestNoStdoutWrites allows it by name, G5). The JSON-RPC stream of
// the session goes to the writer it returns, and nothing else in
// serve mode writes to os.Stdout (A1, IS11.1).
//
// arch: DS11.13, IS11.1, G5
func stdio() (io.ReadCloser, io.Writer) {
	return os.Stdin, os.Stdout
}

// version reports the build version from the Go module system. It falls
// back to "(devel)" when no build info is present, such as a plain
// "go run".
func version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "mailbag-mcp (devel)"
	}
	return "mailbag-mcp " + info.Main.Version
}
