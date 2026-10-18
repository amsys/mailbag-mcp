// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Document tests (DS10.10): the tool reference in docs/USER-GUIDE.md
// and the tool counts in README.md agree with the code, and the
// published documents hold no banned word and no real secret.

package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/cli"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// userGuide is the document that holds the generated tool reference.
const userGuide = "docs/USER-GUIDE.md"

// The two marker lines around the generated block (DS10.4, DS10.6).
// Nothing hand-written goes between them.
const (
	toolsBegin = "<!-- tools:begin -->\n"
	toolsEnd   = "<!-- tools:end -->\n"
)

// TestDocs_ToolsReferenceCurrent runs "tools markdown" in process and
// compares its output with the block between the markers in
// docs/USER-GUIDE.md. UPDATE_GOLDEN=1 rewrites the block and keeps
// the rest of the file as it is.
//
// arch: DS10.1, DS10.4, DS10.6, DS10.10, IS10.1, IS10.3, IS10.4
func TestDocs_ToolsReferenceCurrent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"tools", "markdown"}, cli.Env{Stdout: &stdout, Stderr: &stderr}); code != 0 {
		t.Fatalf("tools markdown: exit %d: %s", code, stderr.String())
	}
	want := "\n" + stdout.String() + "\n"

	raw, err := os.ReadFile(userGuide)
	if err != nil {
		t.Fatalf("read %s: %v", userGuide, err)
	}
	doc := string(raw)
	head, rest, ok := strings.Cut(doc, toolsBegin)
	if !ok || strings.Count(doc, toolsBegin) != 1 {
		t.Fatalf("%s must hold the line %q one time", userGuide, strings.TrimSpace(toolsBegin))
	}
	got, tail, ok := strings.Cut(rest, toolsEnd)
	if !ok || strings.Count(doc, toolsEnd) != 1 {
		t.Fatalf("%s must hold the line %q one time, after the begin marker", userGuide, strings.TrimSpace(toolsEnd))
	}

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		out := head + toolsBegin + want + toolsEnd + tail
		if err := os.WriteFile(userGuide, []byte(out), 0o600); err != nil { //nolint:gosec // G703: the path is a fixed doc file of this repo
			t.Fatalf("write %s: %v", userGuide, err)
		}
		return
	}
	if got != want {
		t.Errorf("the tool reference in %s is not current (IS10.1). Run UPDATE_GOLDEN=1 go test -run '^TestDocs_ToolsReferenceCurrent$' . and read the diff.\n--- want\n%s\n--- got\n%s",
			userGuide, want, got)
	}
}

// TestDocs_ReadmeNumbers fails when the tool counts in README.md
// differ from the code. The core count comes from tools.ListTools with
// no toolset, the total from tools.ListTools with every toolset of
// tools.Toolsets. The README must hold "<core> core tools" and
// "<total> tools with every toolset on" as whole words, so the
// Features bullet cannot drift from the registry.
//
// arch: DS10.1, DS10.2, DS10.10, IS10.1, IS10.3, IS10.4
func TestDocs_ReadmeNumbers(t *testing.T) {
	core, err := tools.ListTools(nil)
	if err != nil {
		t.Fatalf("list core tools: %v", err)
	}
	var every []string
	for _, g := range tools.Toolsets() {
		every = append(every, g.Name)
	}
	all, err := tools.ListTools(nil, every...)
	if err != nil {
		t.Fatalf("list tools with every toolset: %v", err)
	}

	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	readme := string(raw)
	for _, phrase := range []string{
		fmt.Sprintf("%d core tools", len(core.Tools)),
		fmt.Sprintf("%d tools with every toolset on", len(all.Tools)),
	} {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(phrase) + `\b`)
		if !re.MatchString(readme) {
			t.Errorf("README.md does not hold %q; the code has %d core tools and %d with every toolset (IS10.1)",
				phrase, len(core.Tools), len(all.Tools))
		}
	}
}

// docFiles gives the published documents of DS10.10 that exist now:
// README.md, SUPPORT.md, CHANGELOG.md, docs/*.md and
// skills/**/SKILL.md. A later row adds some of these files, so a
// file that does not exist yet is not an error. The design notes in
// docs/features/ are not published documents and are not scanned.
func docFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, name := range []string{"README.md", "SUPPORT.md", "CHANGELOG.md"} {
		_, err := os.Stat(name)
		switch {
		case err == nil:
			files = append(files, name)
		case !os.IsNotExist(err):
			t.Fatalf("stat %s: %v", name, err)
		}
	}
	guides, err := filepath.Glob("docs/*.md")
	if err != nil {
		t.Fatalf("glob docs/*.md: %v", err)
	}
	files = append(files, guides...)
	err = filepath.WalkDir("skills", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "SKILL.md" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("walk skills: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no document to scan; docs/USER-GUIDE.md at least must exist")
	}
	return files
}

// bannedWords is the word list of the owner (RULES.md 7). The match
// rule is G3 of DS10.14: case-insensitive, whole word, a phrase with
// any run of white space between its words. "leverage" and "harness"
// are not in the list, because a word list cannot tell the verb from
// a noun such as "test harness"; the judge reads for them.
var bannedWords = []string{
	"idempotent", "upsert", "delve", "seamless", "robust", "comprehensive",
	"elevate", "unlock", "empower", "meticulous", "testament", "tapestry",
	"landscape", "realm", "embark", "journey", "crucial", "pivotal", "vital",
	"underscore", "foster", "facilitate", "navigate", "streamline",
	"cutting-edge", "game-changer", "holistic", "synergy", "paradigm",
	"notably", "moreover", "furthermore", "it's worth noting",
	"in today's world", "footgun", "battle-tested", "production-ready",
	"rock-solid", "bulletproof", "blazingly fast", "world-class",
	"best-in-class", "state-of-the-art", "next-level", "deep dive",
	"dive into", "unpack", "supercharge", "low-hanging fruit", "no-brainer",
	"silver bullet", "utilize", "plethora", "myriad", "aforementioned",
	"elegant", "elegantly", "simply put", "great question",
}

// bannedPattern makes the G3 pattern of one entry: whole word, any
// case, flexible white space, and a straight or a curly apostrophe.
func bannedPattern(word string) *regexp.Regexp {
	parts := strings.Fields(word)
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(regexp.QuoteMeta(p), "'", `['’]`)
	}
	return regexp.MustCompile(`(?i)\b` + strings.Join(parts, `\s+`) + `\b`)
}

// TestDocs_NoBannedWords fails on each banned word in a published
// document, with the file and the line.
//
// arch: DS10.1, DS10.4, DS10.6, DS10.10, IS10.1, IS10.3, IS10.4
func TestDocs_NoBannedWords(t *testing.T) {
	patterns := make([]*regexp.Regexp, len(bannedWords))
	for i, w := range bannedWords {
		patterns[i] = bannedPattern(w)
	}
	for _, path := range docFiles(t) {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the repo doc list, not from user input
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(raw)
		for i, re := range patterns {
			for _, loc := range re.FindAllStringIndex(text, -1) {
				t.Errorf("%s:%d: banned word %q (RULES.md 7): %q",
					path, lineOf(text, loc[0]), bannedWords[i], text[loc[0]:loc[1]])
			}
		}
	}
}

// The patterns of TestDocs_NoRealSecrets (DS10.10, G4).
var (
	// mailAddress finds a mail address.
	mailAddress = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b`)
	// googleClientID finds a Google OAuth client id.
	googleClientID = regexp.MustCompile(`[A-Za-z0-9_-]+\.apps\.googleusercontent\.com`)
	// bearerToken finds "Bearer" and the word after it. That word is a
	// token when it is 12 or more token characters with a letter and a
	// digit; "Bearer <token>" and "Bearer header" are not.
	bearerToken = regexp.MustCompile(`\bBearer\s+([A-Za-z0-9._~+/-]+=*)`)
	hasLetter   = regexp.MustCompile(`[A-Za-z]`)
	hasDigit    = regexp.MustCompile(`[0-9]`)
)

// secretPrefixes start a real Google token or client secret: an
// access token ("ya29.") and a client secret ("GOCSPX-"). No example
// needs either one.
var secretPrefixes = []string{"ya29.", "GOCSPX-"}

// allowedAddress reports whether a mail address may appear in a
// published document (G4): the one contact address, or an address at
// a domain that RFC 2606 keeps for examples.
func allowedAddress(addr, domain string) bool {
	if strings.EqualFold(addr, "dev@amsys.cz") {
		return true
	}
	d := strings.ToLower(domain)
	switch d {
	case "example.com", "example.org", "example.net":
		return true
	}
	for _, base := range []string{".example.com", ".example.org", ".example.net", ".test", ".invalid"} {
		if strings.HasSuffix(d, base) {
			return true
		}
	}
	return false
}

// TestDocs_NoRealSecrets fails when a published document holds a mail
// address other than dev@amsys.cz or an example address, a Google
// client id other than test-client, a Google token or client secret,
// or a Bearer header with a token in it.
//
// arch: DS10.1, DS10.4, DS10.6, DS10.10, IS10.1, IS10.3, IS10.4
func TestDocs_NoRealSecrets(t *testing.T) {
	for _, path := range docFiles(t) {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: the path comes from the repo doc list, not from user input
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(raw)
		for _, m := range mailAddress.FindAllStringSubmatchIndex(text, -1) {
			addr, domain := text[m[0]:m[1]], text[m[2]:m[3]]
			if !allowedAddress(addr, domain) {
				t.Errorf("%s:%d: mail address %q is not dev@amsys.cz and not an example address (IS10.3)", path, lineOf(text, m[0]), addr)
			}
		}
		for _, loc := range googleClientID.FindAllStringIndex(text, -1) {
			if id := text[loc[0]:loc[1]]; id != "test-client.apps.googleusercontent.com" {
				t.Errorf("%s:%d: Google client id %q (IS10.3)", path, lineOf(text, loc[0]), id)
			}
		}
		for _, p := range secretPrefixes {
			for off := 0; ; {
				i := strings.Index(text[off:], p)
				if i < 0 {
					break
				}
				t.Errorf("%s:%d: text that starts a real Google secret: %q (IS10.3)", path, lineOf(text, off+i), p)
				off += i + len(p)
			}
		}
		for _, m := range bearerToken.FindAllStringSubmatchIndex(text, -1) {
			tok := text[m[2]:m[3]]
			if len(tok) >= 12 && hasLetter.MatchString(tok) && hasDigit.MatchString(tok) {
				t.Errorf("%s:%d: a Bearer header with a token (IS10.3)", path, lineOf(text, m[0]))
			}
		}
	}
}

// lineOf gives the 1-based line number of the byte offset i in text.
func lineOf(text string, i int) int {
	return strings.Count(text[:i], "\n") + 1
}
