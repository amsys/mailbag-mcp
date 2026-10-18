// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

//go:build race

package mime

// raceFactor widens timing bounds in html_test.go. The race detector
// slows the runtime, so a bound that is tight in a plain run can fail
// under -race on a loaded machine. arch: DRV.20.2
const raceFactor = 4
