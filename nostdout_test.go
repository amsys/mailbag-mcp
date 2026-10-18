// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// A source scan that keeps stdout for the JSON-RPC stream only (A1,
// IS11.1).

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowedStdoutFuncs are the functions outside internal/cli that may
// name os.Stdout or call fmt.Print*. They are allowed in
// allowedStdoutFile only. printVersion runs the "version" subcommand,
// before serve mode opens the JSON-RPC stream (see its doc comment in
// main.go). stdio gives os.Stdout to server.Serve as the JSON-RPC
// stream itself (G5, DS11.13).
var allowedStdoutFuncs = map[string]bool{"printVersion": true, "stdio": true}

// allowedStdoutFile is the one file that holds allowedStdoutFuncs.
const allowedStdoutFile = "main.go"

// allowedStdoutDir is the one package allowed to write to stdout: the
// CLI commands print to the terminal, and never run inside serve mode
// (§3.1 step 1 only ignores signals "in serve mode").
const allowedStdoutDir = "internal/cli"

// TestNoStdoutWrites scans every non-test .go source file below the
// module root for os.Stdout and fmt.Print*: a source-level guarantee
// to back up TestE2E_StdoutIsOnlyJSONRPC's runtime check that stdout
// carries JSON-RPC only (A1). It parses each file instead of grepping
// it, so a string literal or a comment that happens to contain
// "os.Stdout" is not a false positive. The functions of
// allowedStdoutFuncs are allowed by name in main.go only (G5).
//
// arch: T1.6, §5.3, §5.1, A1, A2, A3, A5, A9, A11, A13, §10.1, §10.2, DS11.13, IS11.1, G5
func TestNoStdoutWrites(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}

	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "graphify-out":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == allowedStdoutDir || strings.HasPrefix(relSlash, allowedStdoutDir+"/") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}

		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && relSlash == allowedStdoutFile && allowedStdoutFuncs[fn.Name.Name] {
				return false // do not walk into an allowed function
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			line := fset.Position(sel.Pos()).Line
			switch {
			case pkg.Name == "os" && sel.Sel.Name == "Stdout":
				t.Errorf("%s:%d: os.Stdout used outside %s (A1)", rel, line, allowedStdoutDir)
			case pkg.Name == "fmt" && strings.HasPrefix(sel.Sel.Name, "Print"):
				t.Errorf("%s:%d: fmt.%s used outside %s (A1)", rel, line, sel.Sel.Name, allowedStdoutDir)
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walk source tree: %v", walkErr)
	}
}
