// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the JMAP identity reader for "identities detect" (DI6.2).

package jmap

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// TestProviderIdentities_JMAP checks that ProviderIdentities sends one
// Identity/get with the five properties, gives name, email and both
// signatures, and leaves the identity cache empty, so the send path is
// not changed.
//
// arch: DI6.2
func TestProviderIdentities_JMAP(t *testing.T) {
	store := draftStore()
	store.identities = []map[string]any{
		{"id": "I1", "name": "Me", "email": "me@example.test", "textSignature": "Ann\n-- x", "htmlSignature": "<p>Ann</p>"},
		{"id": "I2", "name": "Alias", "email": "*@alias.test", "textSignature": "", "htmlSignature": ""},
	}
	p, f := newTestProvider(t, store, nil)
	got, err := p.ProviderIdentities(context.Background())
	if err != nil {
		t.Fatalf("ProviderIdentities: %v", err)
	}
	want := []mail.ProviderIdentity{
		{Email: "me@example.test", Name: "Me", TextSignature: "Ann\n-- x", HTMLSignature: "<p>Ann</p>", Source: "jmap Identity"},
		{Email: "*@alias.test", Name: "Alias", Source: "jmap Identity"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("identities = %+v, want %+v", got, want)
	}
	calls := callsNamed(f, "Identity/get")
	if len(calls) != 1 {
		t.Fatalf("%d Identity/get calls, want 1", len(calls))
	}
	props, _ := calls[0].Args["properties"].([]any)
	var names []string
	for _, v := range props {
		s, _ := v.(string)
		names = append(names, s)
	}
	slices.Sort(names)
	if !reflect.DeepEqual(names, []string{"email", "htmlSignature", "id", "name", "textSignature"}) {
		t.Errorf("properties = %v", names)
	}
	if _, ok := p.idents.get(p.now()); ok {
		t.Error("ProviderIdentities filled the identity cache")
	}
}
