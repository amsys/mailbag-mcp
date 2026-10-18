// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The errors of the JMAP client (DS8.1). MethodError is an "error"
// invocation in an answer (RFC 8620 §3.6.2). AuthError is a 401 from
// the server; the Factory maps it to a refused login and its refusal
// window (DRV.10, IS78.4).

package jmap

import "fmt"

// MethodError is an "error" invocation in the answer to Call (RFC 8620
// §3.6.2). Type is the error type, such as "unknownMethod" or
// "invalidArguments". Description is the optional free text of the
// server; it is for the log only.
type MethodError struct{ Type, Description string }

// Error gives "jmap: method error <type>". It gives the type only when
// the type is an identifier (safeType), and never the description, so
// no free text of the server reaches an error text.
func (e *MethodError) Error() string {
	if t := safeType(e.Type); t != "" {
		return "jmap: method error " + t
	}
	return "jmap: method error"
}

// AuthError is a 401 from the server: it refused the credential. A
// session GET, a Call that gets a 401 again after the session refetch,
// a Download and an Upload give it (DS8.1, DRV.10).
type AuthError struct{ Status int }

// Error gives a fixed text with the HTTP status.
func (e *AuthError) Error() string {
	return fmt.Sprintf("jmap: login refused by the server (HTTP %d)", e.Status)
}
