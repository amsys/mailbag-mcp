// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The errors of the Gmail REST client (DS7.3, DS7.7). APIError is one
// failed call. Its text gives the HTTP status and the reason code, and
// never the server message: the message goes to the log only, after
// guard.Redact (IS7.5). ErrAPIDisabled and ErrScope are fixed texts
// for the two errors that the person must fix.

package gmail

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrAPIDisabled is the answer of a project that has the Gmail API off:
// 403 with the reason accessNotConfigured or SERVICE_DISABLED. Its text
// is fixed and holds no project number (DS7.3, DS7.7, IS7.5).
var ErrAPIDisabled = errors.New("gmail: the Gmail API is not enabled in the Google Cloud project of the OAuth client")

// ErrScope is the answer to a token that lacks a scope: 403 with the
// reason insufficientPermissions or ACCESS_TOKEN_SCOPE_INSUFFICIENT
// (DS7.3).
var ErrScope = errors.New("gmail: the OAuth client lacks a scope this call needs; sign in again with --reauth")

// errBodyTooLarge is the fixed error of an answer above the body cap
// (DS7.3).
var errBodyTooLarge = errors.New("gmail: the answer is larger than 64 MiB")

// APIError is one failed call. Error() gives
// "gmail: HTTP <status> <reason>" and never the server message (IS7.5).
type APIError struct {
	Status int
	// Reason is errors[0].reason, else the reason of an ErrorInfo
	// detail, else the status code word of the answer. It holds an
	// identifier only; a value with other characters is dropped.
	Reason string

	// message is the server text. Only the log gets it, after
	// guard.Redact (DS7.7).
	message string
	// reasons holds every reason code of the answer, for the rules of
	// retryable and fixed.
	reasons []string
}

// Error gives the status and the reason code only (IS7.5).
func (e *APIError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("gmail: HTTP %d", e.Status)
	}
	return fmt.Sprintf("gmail: HTTP %d %s", e.Status, e.Reason)
}

// errorBody is the JSON error object of a Google API answer.
type errorBody struct {
	Error struct {
		Message string `json:"message"`
		Status  string `json:"status"`
		Errors  []struct {
			Reason string `json:"reason"`
		} `json:"errors"`
		Details []struct {
			Type   string `json:"@type"`
			Reason string `json:"reason"`
		} `json:"details"`
	} `json:"error"`
}

// maxLogBody caps the part of an answer that is not a Google error
// object and goes to the log as the message.
const maxLogBody = 512

// parseError reads the error object of a failed answer. An answer that
// is not a Google error object gives an APIError with no reason.
func parseError(status int, data []byte) *APIError {
	e := &APIError{Status: status}
	var b errorBody
	if err := json.Unmarshal(data, &b); err != nil {
		e.message = string(data[:min(len(data), maxLogBody)])
		return e
	}
	e.message = b.Error.Message
	for _, x := range b.Error.Errors {
		e.addReason(x.Reason)
	}
	for _, d := range b.Error.Details {
		if strings.HasSuffix(d.Type, "google.rpc.ErrorInfo") {
			e.addReason(d.Reason)
		}
	}
	e.addReason(b.Error.Status)
	if len(e.reasons) > 0 {
		e.Reason = e.reasons[0]
	}
	return e
}

// addReason keeps r when it is an identifier. A reason is a code word
// such as rateLimitExceeded; a value with other characters can hold
// server text, so it is not kept (IS7.5).
func (e *APIError) addReason(r string) {
	if isReason(r) {
		e.reasons = append(e.reasons, r)
	}
}

// isReason reports whether r has 1 to 64 characters from A-Z, a-z,
// 0-9, "_", "." and "-".
func isReason(r string) bool {
	if r == "" || len(r) > 64 {
		return false
	}
	for _, c := range r {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '_' || c == '.' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// has reports whether the answer holds one of the reason codes.
func (e *APIError) has(codes ...string) bool {
	for _, r := range e.reasons {
		for _, c := range codes {
			if r == c {
				return true
			}
		}
	}
	return false
}

// fixed gives ErrAPIDisabled or ErrScope for a 403 that the person
// must fix, else nil (DS7.3).
func (e *APIError) fixed() error {
	if e.Status != http.StatusForbidden {
		return nil
	}
	switch {
	case e.has("accessNotConfigured", "SERVICE_DISABLED"):
		return ErrAPIDisabled
	case e.has("insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"):
		return ErrScope
	}
	return nil
}

// retryable reports whether a new try can help (DS7.3): 429, a 403
// rate limit, or a 5xx. A call marked sendOnce (drafts.send) is tried
// again on 429 only, because after a 5xx the message can be sent
// already (IS7.3).
func (e *APIError) retryable(sendOnce bool) bool {
	switch {
	case e.Status == http.StatusTooManyRequests:
		return true
	case sendOnce:
		return false
	case e.Status == http.StatusForbidden:
		return e.has("rateLimitExceeded", "userRateLimitExceeded")
	default:
		return e.Status >= 500 && e.Status <= 599
	}
}
