// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// errUnanswered is the refusal of a prompt that the --answers-stdin
// document does not answer. A missing answer is an error and never a
// default (DS13.5).
//
// arch: DS13.5, IS13.6, B5
var errUnanswered = errors.New("--answers-stdin: the JSON document on stdin does not answer this prompt; nothing was written")

// maxAnswersBytes is the largest --answers-stdin document that the CLI
// reads. A longer input is not one valid document.
const maxAnswersBytes = 64 << 10

// answers is the one JSON document of --answers-stdin:
// {"secret": "...", "use_file_store": false}. A nil field is a prompt
// that the document does not answer.
//
// arch: DS13.5, IS13.2
type answers struct {
	Secret       *string `json:"secret"`
	UseFileStore *bool   `json:"use_file_store"`
}

// readAnswers reads one strict JSON document from r. An unknown field,
// a second document, a value of the wrong type or a document that is
// not an object is an error. The CLI reads no lines: the cause of B5
// was a reader that lost lines. The error texts are fixed and hold no
// part of the input, so a secret cannot get into them (IS13.2).
//
// arch: DS13.5, IS13.2, B5
func readAnswers(r io.Reader) (answers, error) {
	dec := json.NewDecoder(io.LimitReader(r, maxAnswersBytes))
	dec.DisallowUnknownFields()
	var doc *answers
	if err := dec.Decode(&doc); err != nil {
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &typeErr) && (typeErr.Field == "secret" || typeErr.Field == "use_file_store"):
			return answers{}, fmt.Errorf("--answers-stdin: the field %q has the wrong type; nothing was written", typeErr.Field)
		case errors.As(err, &typeErr):
			return answers{}, errors.New("--answers-stdin: the document on stdin must be one JSON object; nothing was written")
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return answers{}, errors.New(`--answers-stdin: the document holds an unknown field; the fields are "secret" and "use_file_store"; nothing was written`)
		default:
			return answers{}, errors.New("--answers-stdin: stdin does not hold one valid JSON document; nothing was written")
		}
	}
	if doc == nil {
		return answers{}, errors.New("--answers-stdin: the document on stdin must be one JSON object; nothing was written")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return answers{}, errors.New("--answers-stdin: stdin holds more than one JSON document; nothing was written")
	}
	return *doc, nil
}

// readSecret gives the secret of the document in place of the terminal
// prompt. It is the Env.ReadSecret of --answers-stdin.
//
// arch: DS13.5
func (a answers) readSecret(string) (string, error) {
	if a.Secret == nil {
		return "", errUnanswered
	}
	return *a.Secret, nil
}

// confirm gives use_file_store in place of the terminal question. It is
// the Env.Confirm of --answers-stdin.
//
// arch: DS13.5
func (a answers) confirm(string) (bool, error) {
	if a.UseFileStore == nil {
		return false, errUnanswered
	}
	return *a.UseFileStore, nil
}

// unansweredLine is the Env.ReadLine of --answers-stdin: the document
// has no answer for a visible line, such as the --paste redirect URL.
//
// arch: DS13.5
func unansweredLine(string) (string, error) {
	return "", errUnanswered
}
