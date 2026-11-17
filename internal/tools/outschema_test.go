// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Wire shape of the Out types of the tools (DU12.2). The SDK writes
// the keys of a result in byte order, so each top-level key must sort
// after "_fence". No Out type embeds a struct with a JSON tag, because
// jsonschema-go flattens it and the SDK then refuses the output. A
// filled Out of each registered tool must pass the output schema that
// the SDK infers, on the SDK's own call path.
//
// arch: DU12.2, DU2.1, DU5.1, DU6.1, DU9.1
package tools

import (
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fenceKey is the JSON key of Head.Fence (DU12.2).
const fenceKey = "_fence"

// outKeyRe is the character set of a top-level key of an Out type.
var outKeyRe = regexp.MustCompile(`\A[a-z0-9_]+\z`)

// outKeys gives the top-level JSON keys of the struct type tp, in
// field order, as encoding/json writes them. The fields of an embedded
// struct with no JSON name are promoted to this level.
func outKeys(tp reflect.Type) []string {
	var keys []string
	for i := 0; i < tp.NumField(); i++ {
		sf := tp.Field(i)
		name, _, skip := jsonField(sf)
		if skip {
			continue
		}
		if name == "" {
			et := sf.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			keys = append(keys, outKeys(et)...)
			continue
		}
		keys = append(keys, name)
	}
	return keys
}

// outKeyProblems gives one text for each top-level key of the Out type
// tp that breaks the key rule of DU12.2: the key "_fence" is there,
// and each other key holds only [a-z0-9_], does not start with "_",
// and sorts after "_fence".
func outKeyProblems(tp reflect.Type) []string {
	var probs []string
	found := false
	for _, k := range outKeys(tp) {
		switch {
		case k == fenceKey:
			found = true
		case !outKeyRe.MatchString(k):
			probs = append(probs, tp.Name()+"."+k+": the key holds a character outside [a-z0-9_]")
		case strings.HasPrefix(k, "_"):
			probs = append(probs, tp.Name()+"."+k+": only _fence can start with _")
		case k <= fenceKey:
			probs = append(probs, tp.Name()+"."+k+": the key sorts before _fence")
		}
	}
	if !found {
		probs = append(probs, tp.Name()+": the result has no _fence key")
	}
	return probs
}

// TestOut_KeysSortAfterFence holds INV-4 as DU12.2 states it: go-sdk
// writes the keys of structuredContent and of the text block in byte
// order, so "_fence" is the first key only when every other top-level
// key sorts after it. It walks the Out type of every registered tool.
//
// arch: DU12.2, DU2.1, DU9.1
func TestOut_KeysSortAfterFence(t *testing.T) {
	if got := outKeys(headType); !slices.Equal(got, []string{fenceKey}) {
		t.Fatalf("the JSON keys of Head = %q, want [%s] (DU12.2)", got, fenceKey)
	}
	for name, tp := range toolOutTypes {
		for _, p := range outKeyProblems(tp) {
			t.Errorf("tool %s: %s", name, p)
		}
	}
}

// TestOut_KeyRuleFindsEachFault shows that the key rule of DU12.2 is
// not blind: each type below breaks it once.
//
// arch: DU12.2
func TestOut_KeyRuleFindsEachFault(t *testing.T) {
	type upper struct {
		Head
		Name string `json:"Name"`
	}
	type digit struct {
		Head
		First string `json:"1st"`
	}
	type under struct {
		Head
		Meta string `json:"_meta"`
	}
	type dash struct {
		Head
		Draft string `json:"draft-id"`
	}
	type noHead struct {
		Name string `json:"name"`
	}
	cases := []struct {
		tp   reflect.Type
		want string
	}{
		{reflect.TypeOf(upper{}), "upper.Name: "},
		{reflect.TypeOf(digit{}), "digit.1st: "},
		{reflect.TypeOf(under{}), "under._meta: "},
		{reflect.TypeOf(dash{}), "dash.draft-id: "},
		{reflect.TypeOf(noHead{}), "noHead: "},
	}
	for _, c := range cases {
		probs := outKeyProblems(c.tp)
		if len(probs) != 1 || !strings.HasPrefix(probs[0], c.want) {
			t.Errorf("%s: problems = %q, want one at %s", c.tp.Name(), probs, c.want)
		}
	}
	type good struct {
		Head
		Account string `json:"account"`
		Rows    []int  `json:"rows"`
		Hidden  int    `json:"hidden_removed"`
		Skip    string `json:"-"`
	}
	if p := outKeyProblems(reflect.TypeOf(good{})); len(p) != 0 {
		t.Errorf("good type: problems = %q, want none", p)
	}
}

// embedProblems gives one text for each embedded field in the type tp,
// found at path, other than Head as the first field of the Out type.
// An embedded struct with a JSON tag is a named key for encoding/json,
// but jsonschema-go flattens it, so the SDK refuses the output.
func embedProblems(tp reflect.Type, path string, top bool, seen map[reflect.Type]bool) []string {
	switch tp.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return embedProblems(tp.Elem(), path, false, seen)
	case reflect.Struct:
	default:
		return nil
	}
	if seen[tp] {
		return nil
	}
	seen[tp] = true
	var probs []string
	for i := 0; i < tp.NumField(); i++ {
		sf := tp.Field(i)
		fp := path + "." + sf.Name
		_, tagged := sf.Tag.Lookup("json")
		if sf.Anonymous {
			switch {
			case top && i == 0 && sf.Type == headType && !tagged:
				continue
			case tagged:
				probs = append(probs, fp+": an embedded struct with a json tag; make it a named field (DU12.2)")
			default:
				probs = append(probs, fp+": an embedded struct; Head is the only one in an Out type (DU12.2)")
			}
		}
		if !sf.IsExported() && !sf.Anonymous {
			continue
		}
		probs = append(probs, embedProblems(sf.Type, fp, false, seen)...)
	}
	return probs
}

// TestOut_NoTaggedEmbed holds the second rule of DU12.2: Head is the
// only embedded struct in an Out type, and it has no JSON tag. It
// walks the Out type of every registered tool, with every nested type.
//
// arch: DU12.2, DU5.1
func TestOut_NoTaggedEmbed(t *testing.T) {
	for name, tp := range toolOutTypes {
		for _, p := range embedProblems(tp, tp.Name(), true, map[reflect.Type]bool{}) {
			t.Errorf("tool %s: %s", name, p)
		}
	}
}

// TestOut_EmbedRuleFindsEachFault shows that the embed rule is not
// blind: the row shape that DU12.2 found in unsubscribe fails, and so
// does a second embedded struct with no tag.
//
// arch: DU12.2
func TestOut_EmbedRuleFindsEachFault(t *testing.T) {
	type Zone struct {
		URL string `json:"url,omitempty"`
	}
	type row struct {
		ID   string `json:"id" strict:"id"`
		Zone `json:"untrusted,omitzero"`
	}
	type taggedRow struct {
		Head
		Rows []row `json:"rows"`
	}
	type extra struct {
		Head
		Zone
	}
	type taggedHead struct {
		Head `json:"head"`
	}
	cases := []struct {
		tp   reflect.Type
		want string
	}{
		{reflect.TypeOf(taggedRow{}), "taggedRow.Rows.Zone: "},
		{reflect.TypeOf(extra{}), "extra.Zone: "},
		{reflect.TypeOf(taggedHead{}), "taggedHead.Head: "},
	}
	for _, c := range cases {
		probs := embedProblems(c.tp, c.tp.Name(), true, map[reflect.Type]bool{})
		if len(probs) != 1 || !strings.HasPrefix(probs[0], c.want) {
			t.Errorf("%s: problems = %q, want one at %s", c.tp.Name(), probs, c.want)
		}
	}
}

// The fill modes of a probe call.
const (
	// fillFull sets every field: each string, number and bool, and one
	// element in each list.
	fillFull = "full"
	// fillSparse makes each list, pointer and struct, but leaves each
	// string, number and bool at its zero value, so omitempty and
	// omitzero drop keys at every level.
	fillSparse = "sparse"
	// fillZero sets only Head.Fence: the structuredContent of an error
	// result (DU6.1).
	fillZero = "zero"
)

// probeIn is the input of a probe tool: the fill mode of its result.
type probeIn struct {
	Mode string `json:"mode"`
}

// fillDepth stops the fill of a type that holds itself.
const fillDepth = 8

// fillValue fills v for the mode. In fillSparse it makes containers
// only. It does not touch an unexported field.
func fillValue(v reflect.Value, mode string, depth int) {
	if depth > fillDepth {
		return
	}
	full := mode == fillFull
	switch v.Kind() {
	case reflect.String:
		if full {
			v.SetString("x")
		}
	case reflect.Bool:
		if full {
			v.SetBool(true)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if full {
			v.SetInt(1)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if full {
			v.SetUint(1)
		}
	case reflect.Float32, reflect.Float64:
		if full {
			v.SetFloat(1)
		}
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fillValue(p.Elem(), mode, depth+1)
		v.Set(p)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fillValue(s.Index(0), mode, depth+1)
		v.Set(s)
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			fillValue(v.Index(i), mode, depth+1)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				fillValue(v.Field(i), mode, depth+1)
			}
		}
	}
}

// probeOut gives the result of a probe of type Out for the mode. Head
// is the first field of Out, so its Fence is set at index 0.
func probeOut[Out any](mode string) Out {
	var out Out
	v := reflect.ValueOf(&out).Elem()
	if mode != fillZero {
		fillValue(v, mode, 0)
	}
	v.Field(0).Field(0).SetString(testNonce)
	return out
}

// addProbe registers a tool with the given name whose result is a
// filled value of Out. It has no WrapReq and no gate, so the SDK
// validates the bare value against the schema that it infers for Out.
// It gives the type Out, so a caller can match it to toolOutTypes.
func addProbe[Out any](srv *mcp.Server, name string) reflect.Type {
	mcp.AddTool(srv, &mcp.Tool{Name: name, Description: "probe"},
		func(_ context.Context, _ *mcp.CallToolRequest, in probeIn) (*mcp.CallToolResult, Out, error) {
			return nil, probeOut[Out](in.Mode), nil
		})
	return reflect.TypeFor[Out]()
}

// probeAdders registers a probe of the Out type of each tool. Each
// entry must give the type that toolOutTypes names for the tool.
var probeAdders = map[string]func(*mcp.Server, string) reflect.Type{
	"accounts":       addProbe[AccountsOut],
	"folders":        addProbe[FoldersOut],
	"search":         addProbe[SearchOut],
	"read":           addProbe[ReadOut],
	"attachment":     addProbe[AttachmentOut],
	"export":         addProbe[ExportOut],
	"decrypt":        addProbe[DecryptOut],
	"modify":         addProbe[ModifyOut],
	"draft":          addProbe[DraftOut],
	"send":           addProbe[SendOut],
	"unsubscribe":    addProbe[UnsubscribeOut],
	"bulk":           addProbe[BulkOut],
	"templates":      addProbe[TemplatesOut],
	"gmail_settings": addProbe[GmailSettingsOut],
}

// connect gives a client session on srv over in-memory transports.
func connect(t *testing.T, srv *mcp.Server) *mcp.ClientSession {
	t.Helper()
	t1, t2 := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := srv.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "client", Version: "test"}, nil)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// outputSchemas gives the output schema of each tool of cs, by name,
// as tools/list gives it.
func outputSchemas(t *testing.T, cs *mcp.ClientSession) map[string]any {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := map[string]any{}
	for _, tool := range res.Tools {
		got[tool.Name] = tool.OutputSchema
	}
	return got
}

// realOutputSchemas registers every tool as RegisterCore and every
// group of Toolsets do, but with no middleware, so tools/list keeps
// the output schema that the SDK inferred (D1.2 strips it on the
// wire). It checks that the names are the names that ListTools gives
// with every toolset on, so a new core tool cannot be missed here.
func realOutputSchemas(t *testing.T) map[string]any {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	srv := mcp.NewServer(&mcp.Implementation{Name: "mailbag-mcp", Version: "test"}, nil)
	f := NewFactory(logger)
	t.Cleanup(f.Close)
	AddAccounts(srv, logger, f.AuthState)
	AddFolders(srv, logger, f)
	AddSearch(srv, logger, f)
	AddRead(srv, logger, f)
	AddAttachment(srv, logger, f)
	AddExport(srv, logger, f)
	var sets []string
	for _, g := range Toolsets() {
		g.Add(srv, logger, f)
		sets = append(sets, g.Name)
	}
	got := outputSchemas(t, connect(t, srv))

	listed, err := ListTools(logger, sets...)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var want, have []string
	for _, tool := range listed.Tools {
		want = append(want, tool.Name)
	}
	for name := range got {
		have = append(have, name)
	}
	slices.Sort(want)
	slices.Sort(have)
	if !slices.Equal(want, have) {
		t.Fatalf("tools = %q, want the tools of ListTools %q", have, want)
	}
	return got
}

// callProbe calls the probe tool name in the mode and gives the text
// block of the result, or the error of the call.
func callProbe(cs *mcp.ClientSession, name, mode string) (string, error) {
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: probeIn{Mode: mode}})
	if err != nil {
		return "", err
	}
	if res.IsError || len(res.Content) != 1 {
		return "", &probeError{res: res}
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return "", &probeError{res: res}
	}
	return tc.Text, nil
}

// probeError is a probe result that is not one text block.
type probeError struct {
	res *mcp.CallToolResult
}

func (e *probeError) Error() string {
	b, _ := json.Marshal(e.res)
	return "the result is not one text block: " + string(b)
}

// firstKey gives the first key of the JSON object text.
func firstKey(text string) string {
	dec := json.NewDecoder(strings.NewReader(text))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return ""
	}
	tok, err := dec.Token()
	if err != nil {
		return ""
	}
	k, _ := tok.(string)
	return k
}

// TestOut_FilledOutPassesSDKSchema holds the second rule of DU12.2 on
// the SDK's own call path: a tool cannot pass its handler tests and
// fail on the wire. For each registered tool it registers a probe of
// the same Out type, checks that tools/list gives the probe the same
// output schema as the real tool, and calls the probe three times: a
// full fill, a sparse fill (lists and structs with zero scalars, so
// omitempty and omitzero drop keys) and the zero Out with only the
// fence (the structuredContent of an error result, DU6.1). The SDK
// validates each result against the schema that it inferred. The text
// block of each result must start with the key "_fence" (INV-4).
//
// arch: DU12.2, DU2.1, DU5.1, DU6.1, DU9.1
func TestOut_FilledOutPassesSDKSchema(t *testing.T) {
	registered := realOutputSchemas(t)

	srv := mcp.NewServer(&mcp.Implementation{Name: "probe", Version: "test"}, nil)
	for name, tp := range toolOutTypes {
		add, ok := probeAdders[name]
		if !ok {
			t.Errorf("tool %s has no probe in probeAdders; add it", name)
			continue
		}
		if got := add(srv, name); got != tp {
			t.Errorf("probe %s has the type %v, want %v of toolOutTypes", name, got, tp)
		}
	}
	for name := range probeAdders {
		if _, ok := toolOutTypes[name]; !ok {
			t.Errorf("probeAdders names %s, which toolOutTypes does not", name)
		}
	}
	cs := connect(t, srv)
	probes := outputSchemas(t, cs)

	for name, want := range registered {
		got, ok := probes[name]
		if !ok {
			t.Errorf("tool %s has no probe", name)
			continue
		}
		if want == nil || !reflect.DeepEqual(got, want) {
			t.Errorf("tool %s: the probe schema is not the schema of the registered tool, so its Out type in toolOutTypes is wrong", name)
		}
		for _, mode := range []string{fillFull, fillSparse, fillZero} {
			text, err := callProbe(cs, name, mode)
			if err != nil {
				t.Errorf("tool %s, %s Out: the SDK refuses the result: %v", name, mode, err)
				continue
			}
			if k := firstKey(text); k != fenceKey {
				t.Errorf("tool %s, %s Out: the first key is %q, want %s (INV-4): %.120s", name, mode, k, fenceKey, text)
			}
		}
	}
}

// TestOut_SDKSchemaProbeFindsTaggedEmbed shows that the probe path is
// not blind: the row shape that DU12.2 found in unsubscribe, an
// embedded struct with a JSON tag, makes the SDK refuse the output.
//
// arch: DU12.2
func TestOut_SDKSchemaProbeFindsTaggedEmbed(t *testing.T) {
	type Zone struct {
		URL string `json:"url,omitempty"`
	}
	type row struct {
		ID   string `json:"id"`
		Zone `json:"untrusted,omitzero"`
	}
	type badOut struct {
		Head
		Rows []row `json:"rows"`
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "probe", Version: "test"}, nil)
	addProbe[badOut](srv, "bad")
	cs := connect(t, srv)
	_, err := callProbe(cs, "bad", fillFull)
	if err == nil || !strings.Contains(err.Error(), "validating tool output") {
		t.Errorf("CallTool error = %v, want the SDK to refuse the output", err)
	}
}
