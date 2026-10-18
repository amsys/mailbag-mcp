// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools gives, in detach.go, the context of a write tool after its
// point of no return (DS11.9). From that point, the end of the MCP
// session does not stop the write.
package tools

import (
	"context"
	"time"
)

// detach returns a context that outlives the session. It keeps the
// deadline of ctx (or sets timeout when ctx has none) and is not
// cancelled when the client goes away. A tool calls it at its point of
// no return: send after the human accepted, modify and bulk when the
// provider call starts. Before that point the end of the session means
// "not done"; after it the result goes where a retry finds it (the send
// key store, the undo journal).
//
// The SDK cancels the request context of each call in flight when the
// peer's read side ends, and the SMTP and IMAP sockets close with that
// context. The detached context keeps the values of ctx but not its
// cancel, so the provider call completes.
//
// The caller must call the returned CancelFunc when the write ends.
//
// arch: D11.1, DS11.9
func detach(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	free := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(free, deadline)
	}
	return context.WithTimeout(free, timeout)
}
