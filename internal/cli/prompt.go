// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// errNotTerminal is the refusal of B5: a secret comes from a terminal
// and from nowhere else. A pipe lost lines and left a half-written
// account behind, so the CLI refuses a pipe instead of reading one.
//
// arch: T4.6, §3.5, B5
var errNotTerminal = errors.New("stdin is not a terminal; type the password in a terminal, because a pipe or a file is not accepted")

// readSecretFromTerminal asks for one secret with no echo. The prompt
// and the closing newline go to stderr, so a person sees them while
// stdout stays free for the result.
//
// arch: T4.6, §3.5, B5
func readSecretFromTerminal(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errNotTerminal
	}
	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// confirmOnTerminal asks one yes-or-no question. Anything but "y" or
// "yes" is a no.
//
// arch: T4.6, §3.4, §3.5
func confirmOnTerminal(prompt string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errNotTerminal
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// readLineFromTerminal reads one line of visible text typed at the
// terminal: the --paste sign-in flow's full redirect URL (§3.6,
// T6.3). It refuses a pipe the same way readSecretFromTerminal does
// (B5): a stalled pipe cost a half-written account before (TS #39),
// and --paste is exactly the kind of prompt that must never silently
// read from a script's stdout instead of a person's terminal.
//
// arch: T6.3, §3.5, §3.6, B5
func readLineFromTerminal(prompt string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errNotTerminal
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
