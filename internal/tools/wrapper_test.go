// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// textOf returns the text of the first content item of res, failing
// the test if res has none.
func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatalf("result has no content: %+v", res)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("result content is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// TestWrapper_RecoversPanic checks A7: a panic in a tool handler ends
// the call, not the process. Wrap must recover it and return an
// isError result instead of letting it propagate.
//
// arch: T1.5, §3.1, A7
func TestWrapper_RecoversPanic(t *testing.T) {
	h := Wrap(nil, "boom", time.Second, func(context.Context, struct{}) (struct{}, error) {
		panic("kaboom")
	})

	res, _, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil {
		t.Fatalf("Wrap returned an error instead of an isError result: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want an isError result, got %+v", res)
	}
	if text := textOf(t, res); !strings.Contains(text, "kaboom") {
		t.Errorf("result text = %q, want it to name the panic reason", text)
	}
}

// TestWrapper_RedactsErrorText checks B4 and §3.15: a business error
// that happens to carry something that looks like a secret must not
// reach the caller unredacted, because a tool result is client-visible
// and can land in the model's context.
//
// arch: T1.5, §3.15, B4
func TestWrapper_RedactsErrorText(t *testing.T) {
	h := Wrap(nil, "leaky", time.Second, func(context.Context, struct{}) (struct{}, error) {
		return struct{}{}, errors.New("imap login failed: Authorization: Bearer sekrit-access-token-value")
	})

	res, _, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil {
		t.Fatalf("Wrap returned an error instead of an isError result: %v", err)
	}
	text := textOf(t, res)
	if strings.Contains(text, "sekrit-access-token-value") {
		t.Errorf("result text still carries the token: %q", text)
	}
	if !strings.Contains(text, "<redacted>") {
		t.Errorf("result text = %q, want the redacted placeholder", text)
	}
}

// TestCallEnd_ErrorIsRedacted checks §3.15 and §3.19 on the log side
// of a failed call. The tool result passes through guard.Redact; the
// call-end line used to carry the raw error text beside it, and an
// error text from the mail layer holds a message id, a folder name, a
// search term, an address and a sender-chosen file name. §3.19 asks
// the log for an error class, not that text.
//
// arch: T1.5, §3.15, §3.19, B4, G5
func TestCallEnd_ErrorIsRedacted(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := Wrap(logger, "search", time.Second, func(context.Context, struct{}) (struct{}, error) {
		return struct{}{}, errors.New(`imap: folder "Payroll" search for ann@example.test failed: Authorization: Bearer sekrit-access-token-value`)
	})

	if _, _, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{}); err != nil {
		t.Fatalf("Wrap returned an error instead of an isError result: %v", err)
	}

	line := buf.String()
	if !strings.Contains(line, "call-end") || !strings.Contains(line, "search") {
		t.Fatalf("no call-end line for the failed call: %q", line)
	}
	for _, leak := range []string{"sekrit-access-token-value", "Bearer", "ann@example.test", "Payroll"} {
		if strings.Contains(line, leak) {
			t.Errorf("the call-end line carries %q, which §3.19 keeps out of the log:\n%s", leak, line)
		}
	}
	if !strings.Contains(line, "error=") {
		t.Errorf("the call-end line names no error at all; it must say the class:\n%s", line)
	}
}

// TestCallEnd_ErrorClassNamesTheKind checks that the class of
// errClass is useful: the three kinds a person debugs from the log
// are told apart, and anything else is a plain "error".
//
// arch: T1.5, §3.19
func TestCallEnd_ErrorClassNamesTheKind(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
		{fmt.Errorf("%w: %q", ErrUnknownAccount, "work"), "unknown-account"},
		{errors.New("imap: folder \"Payroll\" is gone"), "error"},
	}
	for _, c := range cases {
		if got := errClass(c.err); got != c.want {
			t.Errorf("errClass(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// wrapOut is a non-empty Out type for TestWrapper_ErrorClearsOutput: a
// Handler[_, struct{}] error path would zero-marshal to "{}" either
// way, which would let the bug the test guards against pass unnoticed.
type wrapOut struct {
	Data string `json:"data"`
}

// TestWrapper_ErrorClearsOutput checks B4/§3.15 on the output side of
// a failed call, not just the error text: go-sdk's generic AddTool
// path (mcp/server.go toolForErr, go-sdk v1.7.0) marshals the out
// value returned by a ToolHandlerFor into res.StructuredContent
// whenever the returned err is nil, with no regard for
// res.IsError. Wrap always returns a nil err by design (see the
// package doc), so a handler that returns a non-zero Out alongside
// its error would otherwise put unredacted handler output on the
// wire on every failed call. Wrap must zero it.
//
// arch: T1.5, §3.1, §3.15, B4
func TestWrapper_ErrorClearsOutput(t *testing.T) {
	h := Wrap(nil, "leaky-out", time.Second, func(context.Context, struct{}) (wrapOut, error) {
		return wrapOut{Data: "should not leak"}, errors.New("business error")
	})

	res, out, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil {
		t.Fatalf("Wrap returned an error instead of an isError result: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want an isError result, got %+v", res)
	}
	if out.Data != "" {
		t.Errorf("out = %+v after an error, want the zero value: the SDK marshals out into StructuredContent regardless of IsError, so this leaks handler output unredacted", out)
	}
}

// TestWrapper_SetsDeadline checks §3.1: Wrap gives the handler's
// context a deadline instead of leaving it to run forever.
//
// arch: T1.5, §3.1
func TestWrapper_SetsDeadline(t *testing.T) {
	var sawDeadline bool
	h := Wrap(slog.New(slog.DiscardHandler), "timed", 30*time.Second, func(ctx context.Context, _ struct{}) (struct{}, error) {
		_, sawDeadline = ctx.Deadline()
		return struct{}{}, nil
	})

	if _, _, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{}); err != nil {
		t.Fatalf("Wrap returned an error: %v", err)
	}
	if !sawDeadline {
		t.Error("handler's context has no deadline; Wrap must call context.WithTimeout")
	}
}

// TestWrapper_UsesConfigTimeout checks ORV.3/ORV.10 (DRV.14a): a
// handler wrapped with DefaultTimeout gets accounts.toml's
// tool_timeout instead, read at call time rather than fixed at
// registration. A handler wrapped with any other duration, such as
// LongTimeout, is never touched by the installed source.
//
// arch: DRV.14a, ORV.3, ORV.10
func TestWrapper_UsesConfigTimeout(t *testing.T) {
	t.Cleanup(func() { setDefaultTimeoutSource(nil) })

	configured := 7 * time.Second
	setDefaultTimeoutSource(func() time.Duration { return configured })

	var gotDefault time.Duration
	h := Wrap(nil, "cfgtimeout", DefaultTimeout, func(ctx context.Context, _ struct{}) (struct{}, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("handler ctx has no deadline")
		}
		gotDefault = time.Until(deadline)
		return struct{}{}, nil
	})
	if _, _, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{}); err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if gotDefault <= 5*time.Second || gotDefault > configured {
		t.Errorf("handler deadline = %v, want close to the installed %v, not the DefaultTimeout constant", gotDefault, configured)
	}

	var gotLong time.Duration
	long := Wrap(nil, "longtimeout", LongTimeout, func(ctx context.Context, _ struct{}) (struct{}, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("handler ctx has no deadline")
		}
		gotLong = time.Until(deadline)
		return struct{}{}, nil
	})
	if _, _, err := long(context.Background(), &mcp.CallToolRequest{}, struct{}{}); err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if gotLong <= 100*time.Second {
		t.Errorf("LongTimeout handler deadline = %v, want close to %v: the installed source must not touch it (ORV.10)", gotLong, LongTimeout)
	}

	// Going back to nil restores the constant.
	setDefaultTimeoutSource(nil)
	var gotAfterReset time.Duration
	again := Wrap(nil, "cfgtimeout2", DefaultTimeout, func(ctx context.Context, _ struct{}) (struct{}, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("handler ctx has no deadline")
		}
		gotAfterReset = time.Until(deadline)
		return struct{}{}, nil
	})
	if _, _, err := again(context.Background(), &mcp.CallToolRequest{}, struct{}{}); err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if gotAfterReset <= 40*time.Second {
		t.Errorf("after setDefaultTimeoutSource(nil), handler deadline = %v, want close to DefaultTimeout (%v)", gotAfterReset, DefaultTimeout)
	}
}

// TestWrapReq_PassesRequestAndFreesTheWait checks the handler pair of
// D5.2: WrapReq gives the handler the request, and untimed gives a
// context without the tool deadline for the wait on the human. The
// call context keeps its deadline.
//
// arch: D5.2, D8.3, D10.3
func TestWrapReq_PassesRequestAndFreesTheWait(t *testing.T) {
	want := &mcp.CallToolRequest{}
	var gotReq *mcp.CallToolRequest
	var callHasDeadline, waitHasDeadline, ok bool
	var gotTimeout time.Duration
	h := WrapReq(nil, "ask", time.Minute, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (struct{}, error) {
		gotReq = req
		_, callHasDeadline = ctx.Deadline()
		var wait context.Context
		wait, gotTimeout, ok = untimed(ctx)
		_, waitHasDeadline = wait.Deadline()
		return struct{}{}, nil
	})
	if _, _, err := h(context.Background(), want, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if gotReq != want {
		t.Error("the handler did not get the request")
	}
	if !callHasDeadline {
		t.Error("the call context has no deadline (§3.1)")
	}
	if !ok || waitHasDeadline {
		t.Errorf("untimed ok = %v, deadline = %v; want a context with no tool deadline (D5.2)", ok, waitHasDeadline)
	}
	if gotTimeout != time.Minute {
		t.Errorf("untimed timeout = %v, want 1m", gotTimeout)
	}
}

// TestWrapReq_RecoversPanicAndRedacts checks that WrapReq keeps the
// guarantees of Wrap (§3.1, A7, B4): a panic ends the call and not the
// process, and an error text passes through the redactor.
//
// arch: D5.2, D8.3, D10.3
func TestWrapReq_RecoversPanicAndRedacts(t *testing.T) {
	boom := WrapReq(nil, "boom", time.Second, func(context.Context, *mcp.CallToolRequest, struct{}) (struct{}, error) {
		panic("kaboom")
	})
	res, _, err := boom(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("panic gave res %+v, err %v; want an isError result", res, err)
	}

	leaky := WrapReq(nil, "leaky", time.Second, func(context.Context, *mcp.CallToolRequest, struct{}) (struct{}, error) {
		return struct{}{}, errors.New("Authorization: Bearer sekrit-access-token-value")
	})
	res, _, _ = leaky(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if text := textOf(t, res); strings.Contains(text, "sekrit-access-token-value") {
		t.Errorf("result text still carries the token: %q", text)
	}
}

// TestWrapReq_InputRequiredResult holds DS14.8: a handler that gives
// an [inputRequired] value gets a result with its input requests and
// its request state, with no content and no error flag. The typed
// output is the zero value, and the call-end line has the outcome
// input_required.
//
// arch: DS14.8
func TestWrapReq_InputRequiredResult(t *testing.T) {
	var logs bytes.Buffer
	ask := &mcp.ElicitParams{Mode: "form", Message: "Send this message?"}
	h := WrapReq(slog.New(slog.NewTextHandler(&logs, nil)), "send", time.Second, func(context.Context, *mcp.CallToolRequest, struct{}) (SendOut, error) {
		return SendOut{Account: "work", Sent: true}, &inputRequired{requests: mcp.InputRequestMap{"confirm": ask}, state: "s-1"}
	})
	res, out, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil {
		t.Fatalf("WrapReq gave an error: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("result = %+v, want an input-required result with no error flag", res)
	}
	if res.InputRequests["confirm"] != ask || len(res.InputRequests) != 1 {
		t.Errorf("input requests = %+v, want the one request of the handler", res.InputRequests)
	}
	if res.RequestState != "s-1" {
		t.Errorf("request state = %q, want %q", res.RequestState, "s-1")
	}
	if len(res.Content) != 0 || res.StructuredContent != nil {
		t.Errorf("result has content %+v, want none", res.Content)
	}
	if out != (SendOut{}) {
		t.Errorf("output = %+v, want the zero value", out)
	}
	if !strings.Contains(logs.String(), "outcome=input_required") {
		t.Errorf("log has no input_required outcome:\n%s", logs.String())
	}
}

// headOut is an Out type with Head as its first field, for the tests
// of DU2.1 and DU2.2.
type headOut struct {
	Head
	Data string `json:"data"`
}

// TestWrapReq_SetsFenceAfterHandler holds DU2.1 and DU2.2: WrapReq
// gives the handler one Fencer in the context and, after the handler,
// writes the nonce of that Fencer into Head. A value that the handler
// writes into Head does not reach the result. "fence" is the first key
// of the JSON of the result (INV-4).
//
// arch: DU2.1, DU2.2
func TestWrapReq_SetsFenceAfterHandler(t *testing.T) {
	var seen string
	h := WrapReq(nil, "head", time.Second, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (headOut, error) {
		seen = fencer(ctx).Nonce()
		out := headOut{Data: "x"}
		out.Fence = "forged"
		return out, nil
	})
	res, out, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil || res != nil {
		t.Fatalf("WrapReq gave res %+v, err %v; want a success with no ready-made result", res, err)
	}
	if !guard.Strict("nonce", seen) {
		t.Fatalf("handler saw nonce %q, want 16 lowercase hex characters", seen)
	}
	if out.Fence != seen {
		t.Errorf("fence = %q, want the nonce of the handler's Fencer %q", out.Fence, seen)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"fence":"` + seen + `",`; !strings.HasPrefix(string(b), want) {
		t.Errorf("result JSON = %s, want it to start with %s", b, want)
	}
}

// TestWrapReq_NonceIsNewForEachCall holds INV-2 and INV-6: each call
// gets a new nonce, and an Out that the handler keeps (as the send key
// store does) gets the nonce of the response that replays it. The kept
// value itself never holds a nonce.
//
// arch: DU2.1, DU2.2
func TestWrapReq_NonceIsNewForEachCall(t *testing.T) {
	cached := headOut{Data: "cached"}
	var seen string
	h := WrapReq(nil, "replay", time.Second, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (headOut, error) {
		seen = fencer(ctx).Nonce()
		return cached, nil
	})
	nonces := map[string]bool{}
	for i := range 3 {
		_, out, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if out.Fence != seen || !guard.Strict("nonce", out.Fence) {
			t.Errorf("call %d: fence = %q, handler saw %q; want the same 16-hex nonce", i, out.Fence, seen)
		}
		if out.Data != "cached" {
			t.Errorf("call %d: data = %q, want the kept value", i, out.Data)
		}
		nonces[out.Fence] = true
	}
	if len(nonces) != 3 {
		t.Errorf("3 calls gave %d distinct nonces, want 3: %v", len(nonces), nonces)
	}
	if cached.Fence != "" {
		t.Errorf("kept Out holds fence %q, want none (INV-6)", cached.Fence)
	}
}

// TestWrapReq_NoNonceGivesInternalError holds DU2.2 step 1: when
// WrapReq cannot make a nonce, the handler does not run, the result is
// an error with the class internal and no nonce line, and the typed
// output is the zero value.
//
// arch: DU2.1, DU2.2
func TestWrapReq_NoNonceGivesInternalError(t *testing.T) {
	t.Cleanup(func() { newFencer = guard.NewFencer })
	newFencer = func() (guard.Fencer, error) {
		return guard.NewFencerFrom(iotest.ErrReader(errors.New("no entropy")))
	}

	var logs bytes.Buffer
	called := false
	h := WrapReq(slog.New(slog.NewTextHandler(&logs, nil)), "nononce", time.Second, func(context.Context, *mcp.CallToolRequest, struct{}) (headOut, error) {
		called = true
		return headOut{Data: "should not be sent"}, nil
	})
	res, out, err := h(context.Background(), &mcp.CallToolRequest{}, struct{}{})
	if err != nil {
		t.Fatalf("WrapReq gave an error instead of an isError result: %v", err)
	}
	if called {
		t.Error("the handler ran with no nonce")
	}
	if res == nil || !res.IsError {
		t.Fatalf("result = %+v, want an isError result", res)
	}
	text := textOf(t, res)
	if !strings.HasPrefix(text, "error: internal\n") {
		t.Errorf("error text = %q, want it to start with the class line %q", text, "error: internal")
	}
	if strings.Contains(text, "fence") || strings.Contains(text, "UNTRUSTED") || strings.Contains(text, "entropy") {
		t.Errorf("error text = %q, want no nonce line, no marker and no source error text", text)
	}
	if out != (headOut{}) {
		t.Errorf("output = %+v, want the zero value", out)
	}
	if !strings.Contains(logs.String(), "error=internal") {
		t.Errorf("call-end line has no class internal:\n%s", logs.String())
	}
}

// TestFencer_FromContext holds DU2.2 step 3: fencer gives the Fencer
// that withFencer put in the context, and the zero Fencer when the
// context has none. Wrap of the zero Fencer panics, so no marker with
// no nonce can be written.
//
// arch: DU2.1, DU2.2
func TestFencer_FromContext(t *testing.T) {
	f := fencer(withFencer(context.Background(), testFencer(t)))
	if f.Nonce() != testNonce {
		t.Errorf("fencer nonce = %q, want %q", f.Nonce(), testNonce)
	}
	if w := f.Wrap("hello"); !f.Holds(w) {
		t.Errorf("Wrap gave %q, which the same Fencer does not hold", w)
	}

	zero := fencer(context.Background())
	if zero.Nonce() != "" {
		t.Errorf("fencer of a bare context has nonce %q, want none", zero.Nonce())
	}
	defer func() {
		if recover() == nil {
			t.Error("Wrap on the Fencer of a bare context did not panic")
		}
	}()
	_ = zero.Wrap("hello")
}
