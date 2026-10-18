// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds the tool framework every tool call goes
// through: the wrapper that gives each call a deadline and a panic
// guard (§3.1), the registry that adds a tool group to a live
// *mcp.Server and can take one off again (§3.16), the accounts tool,
// and the server instructions text (Appendix C).
//
// arch: T1.5, §3.1, §3.16, §3.15, App B, App C, §9 U7, A7, A12, B4, G1, D15
package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// DefaultTimeout is the deadline of §3.1 for a tool call with no
// longer limit of its own. accounts.toml's tool_timeout (ORV.3,
// ORV.10, DRV.14a) replaces it alone: a handler wrapped with
// LongTimeout or any other explicit duration is never touched by it.
const DefaultTimeout = 45 * time.Second

// LongTimeout is the deadline for attachment, export and bulk (§3.1),
// the three tools whose work can outrun the default.
const LongTimeout = 120 * time.Second

// defaultTimeoutSource, when not nil, gives the current tool_timeout
// of accounts.toml in place of the DefaultTimeout constant (ORV.3,
// DRV.14a). tools/provider.go's Factory installs it, reading the
// config at call time so a value changed while the server runs takes
// effect with no restart. Nothing installs it in a build with no
// Factory, so Wrap and WrapReq keep the constant for direct callers
// and tests.
var (
	defaultTimeoutMu     sync.RWMutex
	defaultTimeoutSource func() time.Duration
)

// setDefaultTimeoutSource installs get as the source resolveTimeout
// consults for a handler wrapped with DefaultTimeout. A nil get goes
// back to the constant.
func setDefaultTimeoutSource(get func() time.Duration) {
	defaultTimeoutMu.Lock()
	defaultTimeoutSource = get
	defaultTimeoutMu.Unlock()
}

// resolveTimeout gives the deadline a call actually gets. Only a
// handler registered with the exact value of DefaultTimeout can be
// overridden, so LongTimeout and the decrypt limit stay fixed
// (ORV.10).
func resolveTimeout(timeout time.Duration) time.Duration {
	if timeout != DefaultTimeout {
		return timeout
	}
	defaultTimeoutMu.RLock()
	get := defaultTimeoutSource
	defaultTimeoutMu.RUnlock()
	if get == nil {
		return timeout
	}
	return get()
}

// Handler is one tool's business logic: read the typed input, do the
// work, return the typed output or an error. [Wrap] adds everything
// around it that every tool needs (§3.1), so a handler never sets its
// own deadline, never recovers its own panics and never redacts its
// own errors.
type Handler[In, Out any] func(ctx context.Context, in In) (Out, error)

// HandlerReq is a [Handler] that also gets the MCP request. A tool
// that talks back to the client during the call uses it: send asks
// the human through the session of req (D5.2). Every other tool
// keeps [Handler], so its file does not change.
//
// arch: D5.2
type HandlerReq[In, Out any] func(ctx context.Context, req *mcp.CallToolRequest, in In) (Out, error)

// Wrap turns a [Handler] into the mcp.ToolHandlerFor that
// mcp.AddTool wants, adding the four things §3.1 requires of every
// tool call:
//
//   - a deadline of timeout on ctx;
//   - a recover that turns a panic in h into an isError result
//     instead of taking down the process (A7);
//   - a call-start line before h runs and a call-end line after,
//     on logger, with an error class and never the error text
//     (§3.19, see errClass);
//   - the redactor (§3.15) on the text of a failed call, so a secret
//     that leaked into an error can never reach the client or the
//     model (B4).
//
// Why Wrap builds the *mcp.CallToolResult itself on error, rather
// than returning the error to the SDK: go-sdk's generic AddTool path
// calls [mcp.CallToolResult.SetError] with the raw error text when the
// handler returns a non-nil error (go-sdk v1.7.0 mcp/protocol.go:347-351),
// and that text never passes through a redactor. Wrap redacts first
// and returns a ready-made result with a nil error, so that path never
// runs on a Wrap-built handler.
//
// Wrap is [WrapReq] with the request dropped, so the two pairs give
// the same four guarantees from one body.
//
// arch: T1.5, §3.1, §3.15, A7, B4
func Wrap[In, Out any](logger *slog.Logger, name string, timeout time.Duration, h Handler[In, Out]) mcp.ToolHandlerFor[In, Out] {
	return WrapReq(logger, name, timeout, func(ctx context.Context, _ *mcp.CallToolRequest, in In) (Out, error) {
		return h(ctx, in)
	})
}

// WrapReq is [Wrap] for a [HandlerReq]: the same deadline, recover,
// log lines and redactor, and h also gets the request (D5.2).
//
// When h gives an [inputRequired] error, WrapReq gives a result with
// its input requests and request state and no content, and the
// call-end line has the outcome input_required (DS14.8).
//
// The deadline covers the work of the server only. A wait for the
// human does not count against it (D5.2): h gets that wait's context
// from [untimed], and after the wait it takes a new full deadline.
//
// arch: D5.2, DS14.8, T1.5, §3.1, §3.15, A7, B4
func WrapReq[In, Out any](logger *slog.Logger, name string, timeout time.Duration, h HandlerReq[In, Out]) mcp.ToolHandlerFor[In, Out] {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (res *mcp.CallToolResult, out Out, err error) {
		effTimeout := resolveTimeout(timeout)
		parent := ctx
		ctx, cancel := context.WithTimeout(ctx, effTimeout)
		defer cancel()
		ctx = context.WithValue(ctx, untimedKey{}, untimedCall{parent: parent, timeout: effTimeout})

		start := time.Now()
		logger.Info("call-start", "tool", name)

		defer func() {
			if r := recover(); r != nil {
				res = errResult(fmt.Sprintf("panic: %v", r))
				var zero Out
				out, err = zero, nil
				logger.Error("call-end", "tool", name, "duration", time.Since(start).String(), "error", "panic")
			}
		}()

		var hErr error
		out, hErr = h(ctx, req, in)
		// DS14.8: an input-required signal is not a failure. The
		// result carries the input requests and the request state and
		// no content, so go-sdk marks it input_required.
		var ir *inputRequired
		if errors.As(hErr, &ir) {
			logger.Info("call-end", "tool", name, "duration", time.Since(start).String(), "outcome", "input_required")
			var zero Out
			return &mcp.CallToolResult{InputRequests: ir.requests, RequestState: ir.state}, zero, nil
		}
		if hErr != nil {
			logger.Info("call-end", "tool", name, "duration", time.Since(start).String(), "error", errClass(hErr))
			// go-sdk's generic AddTool path marshals out into
			// res.StructuredContent whenever the returned err is nil
			// (mcp/server.go toolForErr), with no regard for
			// res.IsError. Wrap always returns a nil err (see the
			// package doc above), so a handler that returns a
			// non-zero Out alongside hErr would otherwise put
			// unredacted handler output on the wire on every error
			// call, bypassing the guard.Redact above (B4, §3.15).
			// Zero it out here, the same way the panic branch below
			// already does.
			var zero Out
			return errResult(hErr.Error()), zero, nil
		}
		logger.Info("call-end", "tool", name, "duration", time.Since(start).String())
		return nil, out, nil
	}
}

// inputRequired is the signal of a [HandlerReq] that needs an answer
// from the client before it can complete (MRTR, SEP-2322). The
// handler gives it as its error value. [WrapReq] turns it into a
// result with requests and state and no content (DS14.8).
//
// arch: DS14.8
type inputRequired struct {
	// requests are the input requests that the client must fulfil.
	requests mcp.InputRequestMap
	// state is the request state that the client gives back on the
	// retry.
	state string
}

// Error gives a fixed text. No path shows it to the client, because
// [WrapReq] does not treat the value as a failure.
//
// arch: DS14.8
func (e *inputRequired) Error() string {
	return "the call needs input from the client"
}

// untimedKey is the context key of the value [WrapReq] stores for
// [untimed].
type untimedKey struct{}

// untimedCall holds the call context before the tool deadline and the
// length of that deadline.
type untimedCall struct {
	parent  context.Context
	timeout time.Duration
}

// untimed gives the call context of a [WrapReq] handler without the
// tool deadline, and the length of that deadline. A cancel from the
// client still ends the returned context. ok is false when ctx did
// not come from WrapReq; then the returned context is ctx itself.
//
// A handler uses it for a wait on the human only (D5.2), and then
// takes a new deadline of timeout for the work after the wait.
//
// arch: D5.2, §3.1
func untimed(ctx context.Context) (wait context.Context, timeout time.Duration, ok bool) {
	c, ok := ctx.Value(untimedKey{}).(untimedCall)
	if !ok {
		return ctx, 0, false
	}
	return c.parent, c.timeout, true
}

// errClass names the kind of a failed call in one word, for the
// call-end log line.
//
// The log gets the class, never the error text. §3.19 keeps a
// subject, an address, a query and a tool argument out of the log,
// and an error text can hold all four: a folder name, a search term,
// a message id and a sender-chosen file name all reach it from the
// mail layer. guard.Redact removes a secret and a home path, not
// those. The caller still gets the full, redacted text in the tool
// result (errResult), and the wire log of MAILBAG_DEBUG still shows
// the protocol.
//
// arch: T1.5, §3.15, §3.19, B4, G5
func errClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, ErrUnknownAccount):
		return "unknown-account"
	default:
		return "error"
	}
}

// errResult builds an isError tool result whose text has passed
// through guard.Redact (§3.15, B4).
func errResult(text string) *mcp.CallToolResult {
	res := &mcp.CallToolResult{IsError: true}
	res.Content = []mcp.Content{&mcp.TextContent{Text: guard.Redact(text)}}
	return res
}
