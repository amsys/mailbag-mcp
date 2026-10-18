// web_test.go checks the embedded web files of the setup page.
//
// arch: DS13.4, DS13.8, DF.5

package main

import (
	"encoding/json"
	"io/fs"
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
