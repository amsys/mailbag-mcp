// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds replaceFile for all systems other than Windows.

//go:build !windows

package undo

import "os"

// replaceFile renames oldPath to newPath and replaces newPath when it
// exists. A POSIX rename does not look at open handles, so one
// os.Rename is enough.
func replaceFile(oldPath, newPath string) error {
	return os.Rename(oldPath, newPath)
}
