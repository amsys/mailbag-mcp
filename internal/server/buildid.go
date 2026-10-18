// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The build id and the config id of the process (DS11.5). The shim
// sends both in the handshake (DS11.6). The daemon compares them with
// its own, which it took once when it started.

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/amsys/mailbag-mcp/internal/config"
)

// BuildID identifies the running build: the main module version from
// debug.ReadBuildInfo (no space), the size and the mtime (Unix
// nanoseconds) of the executable, taken once when the process starts.
// Format: "<version>/<size>/<mtime>". A hash of the binary costs 11 ms
// and does not fit the 20 ms shim budget; vcs.revision alone cannot
// tell two dirty builds apart (R§7).
//
// The first call fixes the value for the life of the process, because
// go build replaces the file under a running daemon. When the
// executable cannot be found or read, size and mtime are 0: the id then
// tells builds apart by the version only.
//
// arch: DS11.5, DS11.16, IS11.5
func BuildID() string {
	return buildIDValue()
}

// ConfigID identifies the pair of directories a Service serves: the
// first 16 hex digits of sha256(configDir + "\x00" + stateDir). The
// directories come from config.ConfigDir and config.StateDir, made
// absolute, so that a relative override that points to two different
// directories never gives one id. The first call fixes the value and
// the error for the life of the process.
//
// arch: DS11.5, IS11.5
func ConfigID() (string, error) {
	return configIDValue()
}

// buildIDValue and configIDValue hold the values of the first call.
var (
	buildIDValue  = onceBuildID(os.Executable)
	configIDValue = sync.OnceValues(func() (string, error) {
		cfg, err := config.ConfigDir()
		if err != nil {
			return "", err
		}
		state, err := config.StateDir()
		if err != nil {
			return "", err
		}
		return configIDOf(cfg, state)
	})
)

// onceBuildID returns a function that computes the build id of the file
// that executable names on its first call, and then gives that value
// again on each later call. The tests give a temp file as executable.
func onceBuildID(executable func() (string, error)) func() string {
	return sync.OnceValue(func() string {
		path, err := executable()
		if err != nil {
			path = ""
		}
		return buildIDOf(mainVersion(), path)
	})
}

// buildIDOf gives "<version>/<size>/<mtime>" for the file at path. An
// empty path, or a file that os.Stat cannot read, gives size and mtime
// 0.
func buildIDOf(version, path string) string {
	var size, mtime int64
	if path != "" {
		if fi, err := os.Stat(path); err == nil {
			size = fi.Size()
			mtime = fi.ModTime().UnixNano()
		}
	}
	return version + "/" + strconv.FormatInt(size, 10) + "/" + strconv.FormatInt(mtime, 10)
}

// mainVersion gives the version of the main module, such as
// "v0.1.0" or "v0.0.0-20261004220714-3c97a0399d26+dirty". A module
// version has no space. It gives "(devel)" when the binary has no
// version, such as a test binary.
func mainVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "(devel)"
	}
	return info.Main.Version
}

// configIDOf gives the first 16 hex digits of
// sha256(abs(configDir) + "\x00" + abs(stateDir)).
func configIDOf(configDir, stateDir string) (string, error) {
	cfg, err := filepath.Abs(configDir)
	if err != nil {
		return "", err
	}
	state, err := filepath.Abs(stateDir)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(cfg + "\x00" + state))
	return hex.EncodeToString(sum[:])[:16], nil
}
