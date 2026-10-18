// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build windows

// Daemon mode on Windows. There is no daemon on Windows: the MCP entry
// runs the in-process server (owner decision 2026-10-09 at the run
// gate, G8). Windows has no flock and no peer uid, so socket.go is not
// built here (G5 in DS11.20).

package server

import (
	"fmt"
	"os"
)

// serveWindowsText is the text of "mailbag-mcp serve" on Windows (G8).
const serveWindowsText = "serve is not available on Windows; the MCP entry runs the in-process server"

// ServeSocket writes the text of G8 to stderr and returns the exit
// code 2. It opens no socket and starts no Service.
//
// arch: DS11.4, DS11.20
func ServeSocket(_ string) int {
	fmt.Fprintf(os.Stderr, "mailbag-mcp: %s\n", serveWindowsText)
	return 2
}
