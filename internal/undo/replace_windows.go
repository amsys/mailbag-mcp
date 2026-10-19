// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds replaceFile for Windows. On Windows a rename over a
// file that another handle holds open can fail, so replaceFile tries
// again for a short time.

//go:build windows

package undo

import (
	"errors"

	"golang.org/x/sys/windows"
)

// replaceFile renames oldPath to newPath and replaces newPath when it
// exists.
//
// Go opens a file on Windows without FILE_SHARE_DELETE. While a reader
// holds a record open (a List in this process, the CLI, a second
// server, an antivirus or indexer scan), a rename over that record
// fails with ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION. Such a
// reader closes the file soon, so replaceFile tries again with a short
// backoff (see retryRename). A share flag in read alone cannot fix
// this, because other processes open the file with their own flags.
func replaceFile(oldPath, newPath string) error {
	return retryRename(oldPath, newPath, isShareError)
}

// isShareError reports whether err says that another handle holds the
// file open.
func isShareError(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
