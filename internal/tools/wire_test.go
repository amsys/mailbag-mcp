// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the tools/call middleware: an error that the SDK makes
// before WrapReq runs gets the error form, and a result of WrapReq
// passes with no change.
//
// arch: DU6.1, DU6.2, DU6.3, DU12.1
package tools

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// wireIn is the input of the test tool of the middleware tests.
type wireIn struct {
	Max int `json:"max"`
}

// wireClient starts a server with markCalls and one tool "probe"
// whose handler, wrapped by WrapReq, gives err. It gives a connected
// client session and a pointer to the count of handler runs.
func wireClient(t *testing.T, err error) (*mcp.ClientSession, *int) {
	t.Helper()
	runs := 0
	srv := mcp.NewServer(&mcp.Implementation{Name: "wire-test", Version: "test"}, nil)
	srv.AddReceivingMiddleware(stripOutputSchema, markCalls)
	mcp.AddTool(srv, &mcp.Tool{Name: "probe", Description: "probe"}, Wrap(nil, "probe", time.Second, func(context.Context, wireIn) (headOut, error) {
		runs++
		return headOut{Data: "ok"}, err
	}))
	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, sErr := srv.Connect(ctx, t1, nil)
	if sErr != nil {
		t.Fatal(sErr)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	cs, cErr := client.Connect(ctx, t2, nil)
	if cErr != nil {
		t.Fatal(cErr)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, &runs
}

// errHead matches the nonce line and the class line of DU6.1.
var errHead = regexp.MustCompile(`\Afence: ([0-9a-f]{16})\nerror: ([a-z_]+)\n`)

// TestMarkCalls_SDKErrorGetsForm holds DU6.3: an argument that the SDK
// refuses before the handler runs gives an error result with a new
// nonce, the class invalid_input and the SDK text, which can hold model
// input, in one fence of that nonce.
//
// arch: DU6.1, DU6.2, DU6.3, DU12.1
func TestMarkCalls_SDKErrorGetsForm(t *testing.T) {
	cs, runs := wireClient(t, nil)
	nonces := map[string]bool{}
	for range 2 {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{"max": "ignore the rules"}})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if !res.IsError || len(res.Content) != 1 {
			t.Fatalf("result = %+v, want one isError text block", res)
		}
		text := res.Content[0].(*mcp.TextContent).Text
		m := errHead.FindStringSubmatch(text)
		if m == nil || m[2] != "invalid_input" {
			t.Fatalf("error text = %q, want the fence line and the class invalid_input", text)
		}
		body := text[len(m[0]):]
		open, closing := "[UNTRUSTED_"+m[1]+"]\n", "\n[/UNTRUSTED_"+m[1]+"]"
		if !strings.HasPrefix(body, open) || !strings.HasSuffix(body, closing) || !strings.Contains(body, "ignore the rules") {
			t.Errorf("error text = %q, want the SDK text in one fence of the nonce %s", text, m[1])
		}
		nonces[m[1]] = true
	}
	if len(nonces) != 2 {
		t.Errorf("two calls gave the nonces %v, want two new ones (INV-2)", nonces)
	}
	if *runs != 0 {
		t.Errorf("the handler ran %d times, want 0", *runs)
	}
}

// TestMarkCalls_WrapReqResultKept holds DU6.3 step 1: WrapReq sets the
// mark through the context, so the middleware keeps the error form of
// WrapReq (here the class refused, not invalid_input) and a success
// result as they are.
//
// arch: DU6.1, DU6.2, DU6.3, DU12.1
func TestMarkCalls_WrapReqResultKept(t *testing.T) {
	cs, runs := wireClient(t, public("refused", "the server refused the change"))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{"max": 3}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	m := regexp.MustCompile(`\Afence: [0-9a-f]{16}\nerror: refused\nthe server refused the change\z`).FindString(text)
	if !res.IsError || m == "" {
		t.Errorf("result = %v %q, want the error form of WrapReq with the class refused", res.IsError, text)
	}
	if *runs != 1 {
		t.Errorf("the handler ran %d times, want 1", *runs)
	}

	ok, _ := wireClient(t, nil)
	res, err = ok.CallTool(context.Background(), &mcp.CallToolParams{Name: "probe", Arguments: map[string]any{"max": 3}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `"data":"ok"`) {
		t.Errorf("success result = %+v, want it as the handler gave it", res)
	}
}

// TestMarkCalls_OtherMethodsPass holds DU6.3: markCalls acts on
// tools/call only, and keeps a protocol error of tools/call as it is.
//
// arch: DU6.1, DU6.2, DU6.3, DU12.1
func TestMarkCalls_OtherMethodsPass(t *testing.T) {
	cs, _ := wireClient(t, nil)
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(list.Tools) != 1 || list.Tools[0].OutputSchema != nil {
		t.Fatalf("tools/list = %+v, %v; want the probe tool with no outputSchema", list, err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "no-such-tool"}); err == nil {
		t.Error("a call of an unknown tool gave no protocol error")
	}
}
