// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The error form of a tool result. Every error result starts with the
// nonce of the response and a class word. Server text follows in
// plain form. Text of unknown origin follows in one fence of the
// nonce, so a sender or a mail server can never put words outside a
// fence.
//
// arch: DU6.1, DU6.2, DU12.1

package tools

import (
	"context"
	"errors"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
)

// errClasses is the closed set of class words of an error result
// (DU6.2). Each word matches the strict kind word.
//
// arch: DU6.2
var errClasses = map[string]bool{
	"timeout":         true,
	"canceled":        true,
	"unknown_account": true,
	"needs_auth":      true,
	"invalid_input":   true,
	"not_found":       true,
	"refused":         true,
	"limit":           true,
	"unavailable":     true,
	"output_refused":  true,
	"internal":        true,
	"error":           true,
}

// publicError is an error whose text is server text. The model reads
// text as written. detail holds text of unknown origin, for example
// model input that the error names. [WrapReq] puts detail in a fence.
//
// arch: DU6.2, DU12.1
type publicError struct {
	class, text, detail string
}

// Error gives text when detail is empty, else text, ": " and detail
// (DU12.1 item 4). The log never gets it: the call-end line has the
// class only.
//
// arch: DU6.2, DU12.1
func (e *publicError) Error() string {
	if e.detail == "" {
		return e.text
	}
	return e.text + ": " + e.detail
}

// public gives an error with the class word class and the server text
// text. text must be a string literal or a constant; a test scans the
// package for this.
//
// arch: DU6.2
func public(class, text string) error {
	return &publicError{class: class, text: text}
}

// publicDetail is [public] with a detail of unknown origin, for
// example the model input that the error names. The error result
// shows detail in a fence of the nonce.
//
// arch: DU6.2
func publicDetail(class, text, detail string) error {
	return &publicError{class: class, text: text, detail: detail}
}

// classOf gives the class word of err (DU6.2). A [publicError] gives
// its own class when the class is in the closed set. A context error,
// [ErrUnknownAccount] and the sign-in errors that set an [AuthState]
// have a fixed class. Every other error is "error".
//
// The call-end log line gets the class, never the error text: §3.19
// keeps a subject, an address, a query and a tool argument out of the
// log, and an error text can hold all four.
//
// arch: DU6.2, §3.19, G5
func classOf(err error) string {
	var pe *publicError
	var imapAuth *imap.AuthError
	var jmapAuth *jmap.AuthError
	switch {
	case errors.As(err, &pe):
		if errClasses[pe.class] {
			return pe.class
		}
		return "error"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrUnknownAccount):
		return "unknown_account"
	case errors.Is(err, oauthpkg.ErrNeedsAuth), errors.Is(err, gmail.ErrScope):
		return "needs_auth"
	case errors.Is(err, gmail.ErrAPIDisabled):
		return "unavailable"
	case errors.As(err, &imapAuth), errors.As(err, &jmapAuth):
		return "refused"
	default:
		return "error"
	}
}

// errParts gives the public text and the detail of err for the error
// form (DU6.2). A [publicError] gives its text and its detail. Any
// other error gives no public text and its whole text as detail, so
// text of unknown origin is always in a fence.
//
// arch: DU6.2
func errParts(err error) (public, detail string) {
	var pe *publicError
	if errors.As(err, &pe) {
		return pe.text, pe.detail
	}
	return "", err.Error()
}

// errForm gives the text of an error result (DU6.1):
//
//	_fence: <nonce>
//	error: <class>
//	<public>          (only when not empty)
//	<fence of detail> (only when detail is not empty)
//
// public and detail each pass [guard.Redact] on their own. A redact of
// the whole text could take a close marker into a match. detail then
// goes into one fence of f. A class outside the closed set is written
// as "error". The design calls this function errText; that name is
// taken by a test helper in this package.
//
// arch: DU6.1, DU6.2, DU9.1, DU12.2
func errForm(f guard.Fencer, class, public, detail string) string {
	if !errClasses[class] {
		class = "error"
	}
	var b strings.Builder
	b.WriteString("_fence: ")
	b.WriteString(f.Nonce())
	b.WriteString("\nerror: ")
	b.WriteString(class)
	if public != "" {
		b.WriteString("\n")
		b.WriteString(guard.Redact(public))
	}
	if detail != "" {
		b.WriteString("\n")
		b.WriteString(f.Wrap(guard.Redact(detail)))
	}
	return b.String()
}
