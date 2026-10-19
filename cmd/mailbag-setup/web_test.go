// web_test.go checks the embedded web files of the setup page.
//
// arch: DS13.4, DS13.8, DF.5

package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestWeb_NoHTMLSinks fails when an embedded web file holds a sink that
// parses a string as HTML or code.
//
// arch: DS13.4, DS13.8, DF.5
func TestWeb_NoHTMLSinks(t *testing.T) {
	sinks := []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("}
	n := 0
	err := fs.WalkDir(webFiles(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(webFiles(), p)
		if err != nil {
			return err
		}
		n++
		for _, s := range sinks {
			if strings.Contains(string(b), s) {
				t.Errorf("%s holds the sink %q", p, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatalf("found %d web files, want at least 4", n)
	}
}

// TestWeb_PageShape checks that the page has no inline script, no
// request to another host, and that each file stays under 500 lines.
//
// arch: DS13.4, DS13.8, DF.5
func TestWeb_PageShape(t *testing.T) {
	fsys := webFiles()
	html, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(html), "<script>") || strings.Contains(string(html), "onclick=") {
		t.Error("index.html holds an inline script")
	}
	for _, f := range []string{"index.html", "app.js", "style.css", "presets.json"} {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(b), "\n"); n >= 500 {
			t.Errorf("%s has %d lines, want fewer than 500", f, n)
		}
		if f != "app.js" && strings.Contains(string(b), "src=\"http") {
			t.Errorf("%s loads a script from another host", f)
		}
	}
}

// TestWeb_Presets checks the preset file: valid JSON, the seven cards
// of DS13.8, and a link for each preset that needs an app password.
//
// arch: DS13.4, DS13.8, DF.5
func TestWeb_Presets(t *testing.T) {
	b, err := fs.ReadFile(webFiles(), "presets.json")
	if err != nil {
		t.Fatal(err)
	}
	var ps map[string]struct {
		Provider string `json:"provider"`
		IMAP     string `json:"imap"`
		HelpURL  string `json:"help_url"`
	}
	if err := json.Unmarshal(b, &ps); err != nil {
		t.Fatal(err)
	}
	if len(ps) != 7 {
		t.Errorf("got %d presets, want 7", len(ps))
	}
	for _, k := range []string{"icloud", "yahoo", "fastmail"} {
		if !strings.HasPrefix(ps[k].HelpURL, "https://") {
			t.Errorf("preset %s has no help link", k)
		}
	}
	if ps["icloud"].IMAP == "" || ps["yahoo"].IMAP == "" {
		t.Error("an IMAP preset has no host")
	}
}

// serverMapKeys gives the string keys of the answer maps that server.go
// builds. A group is the keys of one map literal plus the keys that a
// function assigns with out["key"] = ... in the same function. It reads
// the source of server.go, so a new key in an answer shows up here.
func serverMapKeys(t *testing.T) map[string]map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	str := func(e ast.Expr) (string, bool) {
		l, ok := e.(*ast.BasicLit)
		if !ok || l.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(l.Value)
		return v, err == nil
	}
	groups := map[string]map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if _, ok := x.Type.(*ast.MapType); !ok {
					return true
				}
				keys := map[string]bool{}
				for _, el := range x.Elts {
					if kv, ok := el.(*ast.KeyValueExpr); ok {
						if k, ok := str(kv.Key); ok {
							keys[k] = true
						}
					}
				}
				for k := range keys {
					if groups[fn.Name.Name] == nil {
						groups[fn.Name.Name] = map[string]bool{}
					}
					groups[fn.Name.Name][k] = true
				}
			case *ast.IndexExpr:
				if k, ok := str(x.Index); ok {
					if groups[fn.Name.Name] == nil {
						groups[fn.Name.Name] = map[string]bool{}
					}
					groups[fn.Name.Name][k] = true
				}
			}
			return true
		})
	}
	return groups
}

// jsonTags gives the json tag names of the fields of a struct type.
func jsonTags(v any) map[string]bool {
	out := map[string]bool{}
	rt := reflect.TypeOf(v)
	for i := 0; i < rt.NumField(); i++ {
		if name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			out[name] = true
		}
	}
	return out
}

// TestWeb_JSONFieldsMatchServer checks that each field the page reads
// from an API answer is a field the server sends. The tags come from
// the Go answer types by reflection. The keys of answers that the
// server builds as maps come from the source of server.go. A new field
// in app.js that the server does not send fails this test.
//
// arch: DS13.8, DF.5
func TestWeb_JSONFieldsMatchServer(t *testing.T) {
	js, err := fs.ReadFile(webFiles(), "app.js")
	if err != nil {
		t.Fatal(err)
	}
	maps := serverMapKeys(t)
	union := func(sets ...map[string]bool) map[string]bool {
		out := map[string]bool{}
		for _, s := range sets {
			for k := range s {
				out[k] = true
			}
		}
		return out
	}
	// The variable names of app.js and the answer each one holds.
	// r in app.js is the Response in api() and the job start answer in
	// runJob(); ok, status and json are members of the Response.
	// c is one clientView of GET /api/clients; c is also the cards
	// element in pickProvider(), so c.append is allowed. ap is the
	// answer of POST /api/clients/<name>.
	allowed := map[string]map[string]bool{
		"r":    union(maps["runAsync"], map[string]bool{"ok": true, "status": true, "json": true}),
		"j":    jsonTags(jobView{}),
		"s":    maps["handleState"],
		"a":    jsonTags(stateAccount{}),
		"c":    union(jsonTags(clientView{}), map[string]bool{"append": true}),
		"ap":   jsonTags(clientApplied{}),
		"data": maps["writeError"],
	}
	re := regexp.MustCompile(`(?:^|[^\w.$])(r|j|s|a|c|ap|data)\.([a-z_]+)\b`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(js), -1) {
		v, field := m[1], m[2]
		seen[v+"."+field] = true
		if !allowed[v][field] {
			t.Errorf("app.js reads %s.%s, but the server sends no field %q for it", v, field, field)
		}
	}
	for _, must := range []string{
		"r.job", "j.lines", "j.next", "j.done", "j.exit", "s.cli_path",
		"c.name", "c.present", "c.current", "c.same", "c.running", "c.before", "c.after", "c.error",
		"ap.changed", "ap.backup",
	} {
		if !seen[must] {
			t.Errorf("app.js no longer reads %s: the test does not see it", must)
		}
	}
}
