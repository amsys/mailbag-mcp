// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build !race

package mime

// raceFactor widens timing bounds in html_test.go. The plain run has
// no race detector overhead, so the bound stays as written.
// arch: DRV.20.2
const raceFactor = 1
