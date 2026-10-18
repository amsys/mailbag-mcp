// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package oauth

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/oauth2"
)

// microsoftBase is the host every Microsoft authorize/token endpoint
// is built against (DS6.2: a fixed constant, not a URL the model or
// mail content supplies). A test in this package replaces it with an
// httptest server's URL so no call reaches the real
// login.microsoftonline.com.
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
var microsoftBase = "https://login.microsoftonline.com"

// MicrosoftScopes are the §3.6 scopes for the Outlook IMAP/SMTP grant.
// offline_access is required: without it the token endpoint returns no
// refresh token (ErrNoRefreshToken below).
var MicrosoftScopes = []string{
	"offline_access",
	"https://outlook.office.com/IMAP.AccessAsUser.All",
	"https://outlook.office.com/SMTP.Send",
}

// guidPattern matches a GUID tenant id (dashed hex, per Microsoft's
// directory id shape).
var guidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// dnsNamePattern matches a tenant given as a verified domain. Each
// label has 1 to 63 letters, digits or `-`, and starts and ends with a
// letter or digit. Single dots join the labels. Thus a `/`, `?`, `#`,
// space or other byte is rejected, and also a dot segment such as
// `.`, `..` or `a..b` that would change the URL path (I-S6.2).
var dnsNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// ValidTenant reports whether tenant is safe to interpolate into a
// Microsoft authorize/token URL: `common`, `organizations`,
// `consumers`, a GUID, or a DNS name (labels of letters, digits and
// `-`, joined by single dots). Anything else — a path segment, a query string, whitespace,
// an empty value — is rejected here, before Endpoints or Config sends
// anything (I-S6.2, DS6.2).
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func ValidTenant(tenant string) error {
	switch tenant {
	case "common", "organizations", "consumers":
		return nil
	}
	if tenant != "" && (guidPattern.MatchString(tenant) || dnsNamePattern.MatchString(tenant)) {
		return nil
	}
	return fmt.Errorf("oauth: %q is not a valid Microsoft tenant (common, organizations, consumers, a GUID, or a DNS name)", tenant)
}

// Endpoints builds the Microsoft v2.0 authorize and token URLs for
// tenant, validating it first so an injected path or query segment
// never reaches the endpoint (I-S6.2, DS6.2).
func Endpoints(tenant string) (authURL, tokenURL string, err error) {
	if err := ValidTenant(tenant); err != nil {
		return "", "", err
	}
	base := microsoftBase + "/" + tenant + "/oauth2/v2.0"
	return base + "/authorize", base + "/token", nil
}

// Config builds the oauth2.Config for one Microsoft account: the
// tenant's validated endpoints, the public client id (Microsoft's
// desktop/public client flow carries no secret, §3.6), and the §3.6
// scopes. redirectURL is filled in by the loopback/paste sign-in flow;
// it plays no part in a token refresh, so a refreshing TokenSource may
// pass "".
//
// arch: T6.2, DS6.1, DS6.2, DS6.3, DS6.4, DS6.5, §3.4, §3.6, B7, B8, B14
func Config(clientID, tenant, redirectURL string) (*oauth2.Config, error) {
	authURL, tokenURL, err := Endpoints(tenant)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURL,
		Scopes:      MicrosoftScopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   authURL,
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}, nil
}

// AuthCodeOptions returns the §3.6 authorize-request parameters for
// Microsoft: select_account so a person with several signed-in
// Microsoft accounts is asked which one, and login_hint so the
// account being added is preselected.
func AuthCodeOptions(email string) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("prompt", "select_account"),
		oauth2.SetAuthURLParam("login_hint", email),
	}
}

// ErrNoRefreshToken is the error for a token response that carries no
// refresh token: the sign-in went through, but nothing can be stored
// for later refreshes. The text names the cause for each provider
// (DS7.2, gap answer G8 of DS78.11): for Microsoft, offline_access was
// not consented; for Google, access_type=offline and prompt=consent
// were not sent (B10).
var ErrNoRefreshToken = errors.New("no refresh token (Microsoft: is offline_access missing? Google: are access_type=offline and prompt=consent missing?)")

// RequireRefreshToken checks a freshly exchanged token against
// ErrNoRefreshToken (§3.6, DS7.2). It is called once, right after the
// authorization-code exchange; a TokenSource's own refresh never
// raises this error because B7 keeps the prior refresh token when a
// later response omits one.
func RequireRefreshToken(tok *oauth2.Token) error {
	if tok == nil || tok.RefreshToken == "" {
		return ErrNoRefreshToken
	}
	return nil
}

// Hosts returns the IMAP and SMTP host:port pair for tenant (DS6.3,
// §3.6's table). It does not validate tenant: by the time an account
// is added, the tenant was already checked by ValidTenant (I-S6.2),
// and Hosts is a pure lookup only.
func Hosts(tenant string) (imapHost, smtpHost string) {
	imapHost = "outlook.office365.com:993"
	if tenant == "consumers" {
		smtpHost = "smtp-mail.outlook.com:587"
	} else {
		smtpHost = "smtp.office365.com:587"
	}
	return imapHost, smtpHost
}

// consumerDomains are the domains DS6.8 treats as personal Microsoft
// accounts: the token endpoint accepts these only under the
// `consumers` tenant, never `organizations`.
var consumerDomains = map[string]bool{
	"outlook.com": true,
	"msn.com":     true,
}

// consumerDomainPrefixes are the domain families of DS6.8 that carry a
// country or brand suffix (hotmail.co.uk, live.com, ...).
var consumerDomainPrefixes = []string{"hotmail.", "live."}

// DefaultTenant picks the tenant `account add --provider outlook`
// uses when `--tenant` is absent (DS6.8): the domain of email decides
// between the two tenants that actually work for a personal inbox.
// An explicit `--tenant` always overrides this and is validated by
// ValidTenant regardless of what DefaultTenant would have picked.
func DefaultTenant(email string) string {
	domain := domainOf(email)
	if consumerDomains[domain] {
		return "consumers"
	}
	for _, prefix := range consumerDomainPrefixes {
		if strings.HasPrefix(domain, prefix) {
			return "consumers"
		}
	}
	return "organizations"
}

// domainOf lowercases the part of email after the last '@'. An email
// with no '@' gives "", which DefaultTenant treats as non-consumer.
func domainOf(email string) string {
	i := strings.LastIndex(email, "@")
	if i < 0 {
		return ""
	}
	return strings.ToLower(email[i+1:])
}
