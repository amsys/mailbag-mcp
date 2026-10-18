// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// TestMicrosoft_TenantRejectsInjection holds I-S6.2: a tenant outside
// common/organizations/consumers/GUID/DNS name is rejected before any
// endpoint is built, including a value that tries to break out of the
// URL path or add a query string.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func TestMicrosoft_TenantRejectsInjection(t *testing.T) {
	bad := []string{
		"",
		"common/../token",
		"consumers/../../evil",
		"contoso.com/token?x=1",
		"contoso.com#fragment",
		"contoso .com",
		"contoso.com\nHost: evil",
		"tenant with spaces",
		".",
		"..",
		"...",
		"-",
		"a..b",
		".contoso.com",
		"contoso.com.",
		"-contoso.com",
		"contoso-.com",
	}
	for _, tenant := range bad {
		if err := ValidTenant(tenant); err == nil {
			t.Errorf("ValidTenant(%q) = nil, want an error", tenant)
		}
		if _, _, err := Endpoints(tenant); err == nil {
			t.Errorf("Endpoints(%q) = nil error, want a rejection and no URL built", tenant)
		}
	}

	good := []string{"common", "organizations", "consumers", "contoso.com", "sub.contoso.co.uk", "my-tenant.onmicrosoft.com", "12345678-1234-1234-1234-123456789abc"}
	for _, tenant := range good {
		if err := ValidTenant(tenant); err != nil {
			t.Errorf("ValidTenant(%q) = %v, want nil", tenant, err)
		}
	}
}

// TestMicrosoft_EndpointsForTenant checks that the authorize and token
// URLs are built from the validated tenant only after validation
// passes, on the login.microsoftonline.com/<tenant>/oauth2/v2.0 shape
// of §3.6.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func TestMicrosoft_EndpointsForTenant(t *testing.T) {
	authURL, tokenURL, err := Endpoints("contoso.com")
	if err != nil {
		t.Fatalf("Endpoints: %v", err)
	}
	wantAuth := microsoftBase + "/contoso.com/oauth2/v2.0/authorize"
	wantToken := microsoftBase + "/contoso.com/oauth2/v2.0/token"
	if authURL != wantAuth {
		t.Errorf("authURL = %q, want %q", authURL, wantAuth)
	}
	if tokenURL != wantToken {
		t.Errorf("tokenURL = %q, want %q", tokenURL, wantToken)
	}

	if _, _, err := Endpoints("bad tenant"); err == nil {
		t.Error("Endpoints accepted an invalid tenant")
	}

	// microsoftBase is package-private and reassignable, which is what
	// lets T42's httptest-backed tests stand in for the real host
	// without any exported override.
	saved := microsoftBase
	microsoftBase = "http://127.0.0.1:0"
	defer func() { microsoftBase = saved }()
	authURL2, _, err := Endpoints("common")
	if err != nil {
		t.Fatalf("Endpoints after base override: %v", err)
	}
	if !strings.HasPrefix(authURL2, "http://127.0.0.1:0/common/") {
		t.Errorf("authURL2 = %q, want it built from the overridden base", authURL2)
	}
}

// TestMicrosoft_Hosts checks the DS6.3 host table: the IMAP host is
// fixed, and the SMTP host depends on whether the tenant is the
// consumer tenant.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func TestMicrosoft_Hosts(t *testing.T) {
	cases := []struct {
		tenant   string
		wantIMAP string
		wantSMTP string
	}{
		{"consumers", "outlook.office365.com:993", "smtp-mail.outlook.com:587"},
		{"organizations", "outlook.office365.com:993", "smtp.office365.com:587"},
		{"common", "outlook.office365.com:993", "smtp.office365.com:587"},
		{"contoso.com", "outlook.office365.com:993", "smtp.office365.com:587"},
	}
	for _, c := range cases {
		imapHost, smtpHost := Hosts(c.tenant)
		if imapHost != c.wantIMAP {
			t.Errorf("Hosts(%q) imap = %q, want %q", c.tenant, imapHost, c.wantIMAP)
		}
		if smtpHost != c.wantSMTP {
			t.Errorf("Hosts(%q) smtp = %q, want %q", c.tenant, smtpHost, c.wantSMTP)
		}
	}
}

// TestMicrosoft_NoRefreshTokenError checks the exact text for a token
// exchange whose response carries no refresh token, and that a token
// which does carry one passes. The text names the Microsoft cause
// (offline_access missing) and, since DS7.2, the Google cause
// (access_type=offline and prompt=consent missing); DS78.11 G8 gives
// the text.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14, DS7.2, B10
func TestMicrosoft_NoRefreshTokenError(t *testing.T) {
	if err := RequireRefreshToken(nil); err != ErrNoRefreshToken {
		t.Errorf("RequireRefreshToken(nil) = %v, want ErrNoRefreshToken", err)
	}
	tok := &oauth2.Token{}
	if err := RequireRefreshToken(tok); err != ErrNoRefreshToken {
		t.Errorf("RequireRefreshToken(empty) = %v, want ErrNoRefreshToken", err)
	}
	if got := ErrNoRefreshToken.Error(); got != "no refresh token (Microsoft: is offline_access missing? Google: are access_type=offline and prompt=consent missing?)" {
		t.Errorf("ErrNoRefreshToken text = %q", got)
	}

	tok.RefreshToken = "rt-1"
	if err := RequireRefreshToken(tok); err != nil {
		t.Errorf("RequireRefreshToken(with token) = %v, want nil", err)
	}
}

// TestMicrosoft_DefaultTenant holds DS6.8: a consumer domain (with and
// without a country suffix), an organization domain, and the rule that
// an explicit --tenant always overrides this pick (checked at the call
// site in account add, not here — DefaultTenant itself never consults
// a flag).
//
// arch: T6.2, DS6.3, DS6.8, §3.6
func TestMicrosoft_DefaultTenant(t *testing.T) {
	cases := []struct {
		email string
		want  string
	}{
		{"ann@outlook.com", "consumers"},
		{"ann@hotmail.co.uk", "consumers"},
		{"ann@live.com", "consumers"},
		{"ann@msn.com", "consumers"},
		{"ANN@OUTLOOK.COM", "consumers"},
		{"ann@contoso.com", "organizations"},
		{"ann@example.test", "organizations"},
		{"not-an-email", "organizations"},
	}
	for _, c := range cases {
		if got := DefaultTenant(c.email); got != c.want {
			t.Errorf("DefaultTenant(%q) = %q, want %q", c.email, got, c.want)
		}
	}
}
