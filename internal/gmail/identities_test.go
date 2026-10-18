// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Gmail send-as reader for "identities detect" (DI6.2).

package gmail

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// TestProviderIdentities_Gmail checks that ProviderIdentities makes one
// settings/sendAs call and decodes name, signature and default. A
// signature in the exact form of signatureHTML gives its text; HTML
// that another client wrote gives an empty text and stays in
// HTMLSignature. The send-as cache stays empty.
//
// arch: DI6.2
func TestProviderIdentities_Gmail(t *testing.T) {
	calls := 0
	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		if !strings.HasSuffix(r.URL.Path, "settings/sendAs") || r.Method != http.MethodGet {
			return step{status: 404, body: googleError(404, "NOT_FOUND", "notFound", "", "not found")}
		}
		calls++
		return step{status: 200, body: `{"sendAs":[` +
			`{"sendAsEmail":"me@example.com","displayName":"Me","isDefault":true,"isPrimary":true,"signature":"Ann &amp; Co<br>Tel"},` +
			`{"sendAsEmail":"alias@example.com","displayName":"Alias","signature":"<div>Hi <b>there</b></div>"},` +
			`{"sendAsEmail":"bare@example.com"}]}`}
	})
	p, _ := f.provider(nil)
	got, err := p.ProviderIdentities(context.Background())
	if err != nil {
		t.Fatalf("ProviderIdentities: %v", err)
	}
	want := []mail.ProviderIdentity{
		{Email: "me@example.com", Name: "Me", TextSignature: "Ann & Co\nTel", HTMLSignature: "Ann &amp; Co<br>Tel", Default: true, Source: "gmail sendAs"},
		{Email: "alias@example.com", Name: "Alias", HTMLSignature: "<div>Hi <b>there</b></div>", Source: "gmail sendAs"},
		{Email: "bare@example.com", Source: "gmail sendAs"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("identities = %+v, want %+v", got, want)
	}
	if calls != 1 {
		t.Errorf("%d settings/sendAs calls, want 1", calls)
	}
	if _, ok := p.sendAs.get(p.now()); ok {
		t.Error("ProviderIdentities filled the send-as cache")
	}
}
