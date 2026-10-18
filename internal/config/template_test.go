// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package config: tests for docs/accounts.example.toml (T94).
package config

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

// templatePath is the repo-relative location of the template, found
// from this package's directory so the test works from any cwd.
const templatePath = "../../docs/accounts.example.toml"

// TestTemplate_Parses checks that the shipped template is valid
// accounts.toml: config.Load must accept it with no error, and the one
// example account must come back.
//
// arch: DR1G.13
func TestTemplate_Parses(t *testing.T) {
	c, err := Load(templatePath)
	if err != nil {
		t.Fatalf("Load(%s): %v", templatePath, err)
	}
	if _, ok := c.Account("example"); !ok {
		t.Fatalf("Load(%s): account %q not found", templatePath, "example")
	}
}

// tomlTags lists the toml tags of a struct type's exported fields,
// skipping a field tagged "-". A nested struct field (not a map) is
// not followed; callers that need its tags reflect over it directly.
func tomlTags(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct {
		t.Fatalf("tomlTags: %v is not a struct", rt)
	}
	var tags []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		tags = append(tags, tag)
	}
	return tags
}

// TestTemplate_HasEveryKey reads every toml tag of rawFile, rawSend,
// rawBulk, rawVerify, rawDecrypt and rawAccount by reflection, then
// fails when a key is missing from the template. So a new config key
// cannot be added to the code without the template gaining it too.
//
// arch: DR1G.13, IR1G.16, DS9.1, DS9.4, DS9.8
func TestTemplate_HasEveryKey(t *testing.T) {
	var raw rawFile
	meta, err := toml.DecodeFile(templatePath, &raw)
	if err != nil {
		t.Fatalf("DecodeFile(%s): %v", templatePath, err)
	}

	for _, tag := range tomlTags(t, rawFile{}) {
		switch tag {
		case "send", "bulk", "verify", "decrypt", "accounts":
			// Sub-tables, checked below by their own structs.
			continue
		}
		if !meta.IsDefined(tag) {
			t.Errorf("template is missing top-level key %q", tag)
		}
	}
	for _, tag := range tomlTags(t, rawSend{}) {
		if !meta.IsDefined("send", tag) {
			t.Errorf("template is missing key %q in [send]", tag)
		}
	}
	for _, tag := range tomlTags(t, rawBulk{}) {
		if !meta.IsDefined("bulk", tag) {
			t.Errorf("template is missing key %q in [bulk]", tag)
		}
	}
	for _, tag := range tomlTags(t, rawVerify{}) {
		if !meta.IsDefined("verify", tag) {
			t.Errorf("template is missing key %q in [verify]", tag)
		}
	}
	for _, tag := range tomlTags(t, rawDecrypt{}) {
		if !meta.IsDefined("decrypt", tag) {
			t.Errorf("template is missing key %q in [decrypt]", tag)
		}
	}

	if len(raw.Accounts) == 0 {
		t.Fatal("template has no [accounts.*] block to check rawAccount keys against")
	}
	for alias := range raw.Accounts {
		for _, tag := range tomlTags(t, rawAccount{}) {
			if tag == "folders" {
				// folders is a map; an empty table still counts as
				// present, and IsDefined needs at least one entry
				// under it to report true, so check the table itself.
				if !meta.IsDefined("accounts", alias, "folders") {
					t.Errorf("template account %q is missing key %q", alias, tag)
				}
				continue
			}
			if !meta.IsDefined("accounts", alias, tag) {
				t.Errorf("template account %q is missing key %q", alias, tag)
			}
		}
	}

	// arch: DI1.6. Every key of an identity table is in the first
	// table of the example account. IsDefined does not index an array
	// of tables, so the file is read again as a plain map.
	var generic map[string]any
	if _, err := toml.DecodeFile(templatePath, &generic); err != nil {
		t.Fatalf("DecodeFile(%s) as map: %v", templatePath, err)
	}
	for alias, ra := range raw.Accounts {
		if len(ra.Identity) == 0 {
			continue
		}
		accts, _ := generic["accounts"].(map[string]any)
		acct, _ := accts[alias].(map[string]any)
		tables, _ := acct["identity"].([]map[string]any)
		if len(tables) == 0 {
			t.Errorf("template account %q has no identity table", alias)
			continue
		}
		for _, tag := range tomlTags(t, rawIdentity{}) {
			if _, ok := tables[0][tag]; !ok {
				t.Errorf("template account %q identity table is missing key %q", alias, tag)
			}
		}
	}
}

// TestTemplate_DefaultsMatch checks that every template value which
// the code treats as a default equals the value an empty accounts.toml
// would give. It parses the template and an empty file, runs both
// through validateIn (dropping the template's one example account,
// which has no default), and compares the fields validateIn fills from
// a default. The raw booleans that validateIn passes straight through
// (D7.1's two keys, send.allow_without_elicitation and
// bulk.allow_without_elicitation) are compared on the raw struct
// directly, since no account is needed to read them.
//
// arch: DR1G.13, IR1G.16, DS9.1, DS9.4, DS9.8
func TestTemplate_DefaultsMatch(t *testing.T) {
	var tmplRaw rawFile
	if _, err := toml.DecodeFile(templatePath, &tmplRaw); err != nil {
		t.Fatalf("DecodeFile(%s): %v", templatePath, err)
	}
	tmplRaw.Accounts = nil // has no default; compared in TestTemplate_Parses instead

	var emptyRaw rawFile
	if _, err := toml.Decode("", &emptyRaw); err != nil {
		t.Fatalf("Decode(\"\"): %v", err)
	}

	now := modTimeForTest(t)
	tmplSnap, err := validateIn(tmplRaw, now, "")
	if err != nil {
		t.Fatalf("validateIn(template): %v", err)
	}
	emptySnap, err := validateIn(emptyRaw, now, "")
	if err != nil {
		t.Fatalf("validateIn(empty file): %v", err)
	}

	if tmplSnap.secrets != emptySnap.secrets {
		t.Errorf("secrets default: template %q, empty file %q", tmplSnap.secrets, emptySnap.secrets)
	}
	if !sameStrings(tmplSnap.extras, emptySnap.extras) {
		t.Errorf("extras default: template %v, empty file %v", tmplSnap.extras, emptySnap.extras)
	}
	if !sameStrings(tmplSnap.downloadDirs, emptySnap.downloadDirs) {
		t.Errorf("download_dirs default: template %v, empty file %v", tmplSnap.downloadDirs, emptySnap.downloadDirs)
	}
	if !sameStrings(tmplSnap.attachDirs, emptySnap.attachDirs) {
		t.Errorf("attach_dirs default: template %v, empty file %v", tmplSnap.attachDirs, emptySnap.attachDirs)
	}
	if tmplSnap.toolTimeout != emptySnap.toolTimeout {
		t.Errorf("tool_timeout default: template %v, empty file %v", tmplSnap.toolTimeout, emptySnap.toolTimeout)
	}
	if tmplSnap.verify != emptySnap.verify {
		t.Errorf("verify default: template %+v, empty file %+v", tmplSnap.verify, emptySnap.verify)
	}

	if tmplRaw.Decrypt.Enabled != emptyRaw.Decrypt.Enabled {
		t.Errorf("decrypt.enabled default: template %v, empty file %v", tmplRaw.Decrypt.Enabled, emptyRaw.Decrypt.Enabled)
	}
	if tmplRaw.Decrypt.AckPlaintextReachesModelProvider != emptyRaw.Decrypt.AckPlaintextReachesModelProvider {
		t.Errorf("decrypt.ack_plaintext_reaches_model_provider default: template %v, empty file %v",
			tmplRaw.Decrypt.AckPlaintextReachesModelProvider, emptyRaw.Decrypt.AckPlaintextReachesModelProvider)
	}
	if tmplRaw.Send.AllowWithoutElicitation != emptyRaw.Send.AllowWithoutElicitation {
		t.Errorf("send.allow_without_elicitation default: template %v, empty file %v",
			tmplRaw.Send.AllowWithoutElicitation, emptyRaw.Send.AllowWithoutElicitation)
	}
	if tmplRaw.Bulk.AllowWithoutElicitation != emptyRaw.Bulk.AllowWithoutElicitation {
		t.Errorf("bulk.allow_without_elicitation default: template %v, empty file %v",
			tmplRaw.Bulk.AllowWithoutElicitation, emptyRaw.Bulk.AllowWithoutElicitation)
	}
}

// sameStrings compares two string slices by content, treating nil and
// an empty slice as equal: TOML decodes "x = []" as a non-nil empty
// slice, while an absent key leaves the Go zero value, nil.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// modTimeForTest gives a mod time for validateIn, which only stores it
// for Refresh's unchanged check; its value plays no part in this test.
func modTimeForTest(t *testing.T) time.Time {
	t.Helper()
	info, err := os.Stat(templatePath)
	if err != nil {
		t.Fatalf("Stat(%s): %v", templatePath, err)
	}
	return info.ModTime()
}
