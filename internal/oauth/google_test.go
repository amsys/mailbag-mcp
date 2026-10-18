// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Google sign-in pieces (DS7.2): the config and its
// authorize parameters, the client_secret.json parser and its errors,
// and the needs-auth text. The tests use only the made-up client id
// test-client.apps.googleusercontent.com (IS7.1) and send no request.

package oauth

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// testGoogleClientID is the made-up client id of IS7.1. No real
// client id or secret is in the repo.
const testGoogleClientID = "test-client.apps.googleusercontent.com"

// TestGoogleConfig_OfflineConsent checks that the config carries the
// client secret, the two G12 scopes and the fixed Google endpoints,
// and that the authorize URL always asks for access_type=offline and
// prompt=consent (B10), with login_hint. The secret is not in the
// authorize URL.
//
// arch: DS7.2, DS78.1, IS7.1, IS7.5, G12, B9, B10
func TestGoogleConfig_OfflineConsent(t *testing.T) {
	c := GoogleClient{ClientID: testGoogleClientID, ClientSecret: "test-secret-value"}
	cfg := GoogleConfig(c, googlePasteRedirect)

	if cfg.ClientID != testGoogleClientID || cfg.ClientSecret != "test-secret-value" {
		t.Errorf("config client = %q / %q, want the id and the secret of the client", cfg.ClientID, cfg.ClientSecret)
	}
	if cfg.RedirectURL != googlePasteRedirect {
		t.Errorf("RedirectURL = %q, want %q", cfg.RedirectURL, googlePasteRedirect)
	}
	wantScopes := []string{
		"https://www.googleapis.com/auth/gmail.modify",
		"https://www.googleapis.com/auth/gmail.settings.basic",
	}
	if !reflect.DeepEqual(cfg.Scopes, wantScopes) {
		t.Errorf("Scopes = %v, want %v (G12)", cfg.Scopes, wantScopes)
	}
	if cfg.Endpoint.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" {
		t.Errorf("AuthURL = %q", cfg.Endpoint.AuthURL)
	}
	if cfg.Endpoint.TokenURL != "https://oauth2.googleapis.com/token" {
		t.Errorf("TokenURL = %q", cfg.Endpoint.TokenURL)
	}

	raw := cfg.AuthCodeURL("state-1", GoogleAuthCodeOptions("ann@example.com")...)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	q := u.Query()
	want := map[string]string{
		"access_type":   "offline",
		"prompt":        "consent",
		"login_hint":    "ann@example.com",
		"client_id":     testGoogleClientID,
		"redirect_uri":  googlePasteRedirect,
		"response_type": "code",
		"state":         "state-1",
		"scope":         strings.Join(wantScopes, " "),
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("authorize URL %s = %q, want %q", k, got, v)
		}
	}
	if strings.Contains(raw, "test-secret-value") || q.Has("client_secret") {
		t.Errorf("authorize URL %q carries the client secret; only the token request may", raw)
	}
}

// TestParseGoogleClientFile_InstalledAndWeb checks that the parser
// reads the "installed" object of a Desktop client and the "web"
// object of a web client, that "installed" wins when the two are both
// complete, and that an incomplete "installed" object falls through to
// a complete "web" object.
//
// arch: DS7.2, DS78.1, IS7.1, IS7.5, G12, B9, B10
func TestParseGoogleClientFile_InstalledAndWeb(t *testing.T) {
	cases := []struct {
		name string
		file string
		want GoogleClient
	}{
		{
			name: "installed",
			file: `{"installed":{"client_id":"test-client.apps.googleusercontent.com","project_id":"test-project","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","client_secret":"installed-secret","redirect_uris":["http://localhost"]}}`,
			want: GoogleClient{ClientID: testGoogleClientID, ClientSecret: "installed-secret"},
		},
		{
			name: "web",
			file: `{"web":{"client_id":"test-client.apps.googleusercontent.com","client_secret":"web-secret","redirect_uris":["http://127.0.0.1:17777/callback"]}}`,
			want: GoogleClient{ClientID: testGoogleClientID, ClientSecret: "web-secret"},
		},
		{
			name: "both, installed wins",
			file: `{"web":{"client_id":"test-client.apps.googleusercontent.com","client_secret":"web-secret"},"installed":{"client_id":"test-client.apps.googleusercontent.com","client_secret":"installed-secret"}}`,
			want: GoogleClient{ClientID: testGoogleClientID, ClientSecret: "installed-secret"},
		},
		{
			name: "incomplete installed, complete web",
			file: `{"installed":{"client_secret":"installed-secret"},"web":{"client_id":"test-client.apps.googleusercontent.com","client_secret":"web-secret"}}`,
			want: GoogleClient{ClientID: testGoogleClientID, ClientSecret: "web-secret"},
		},
	}
	for _, c := range cases {
		got, err := ParseGoogleClientFile([]byte(c.file))
		if err != nil {
			t.Errorf("%s: ParseGoogleClientFile error = %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: ParseGoogleClientFile = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// TestParseGoogleClientFile_ErrorHasNoContent checks IS7.5 for the
// parser: for a file that is not JSON, that has the wrong shape, or
// that lacks a field, the error is one of the two fixed errors, it
// holds no client id, secret or other value of the file, and no part
// of the client comes back.
//
// arch: DS7.2, DS78.1, IS7.1, IS7.5, G12, B9, B10
func TestParseGoogleClientFile_ErrorHasNoContent(t *testing.T) {
	const marker = "SECRETMARKER42"
	cases := []struct {
		name string
		file string
		want error
	}{
		{"empty", ``, errGoogleClientJSON},
		{"not JSON", marker + ` client_secret=` + marker, errGoogleClientJSON},
		{"bad value byte", `{"installed":{"client_id":"test-client.apps.googleusercontent.com","client_secret":` + marker + `}}`, errGoogleClientJSON},
		{"cut off", `{"installed":{"client_id":"test-client.apps.googleusercontent.com","client_secret":"` + marker, errGoogleClientJSON},
		{"object is a string", `{"installed":"` + marker + `"}`, errGoogleClientJSON},
		{"top level is an array", `["` + marker + `"]`, errGoogleClientJSON},
		{"no secret", `{"installed":{"client_id":"test-client.apps.googleusercontent.com","project_id":"` + marker + `"}}`, errGoogleClientFields},
		{"no id", `{"web":{"client_secret":"` + marker + `"}}`, errGoogleClientFields},
		{"other object", `{"service_account":{"client_id":"test-client.apps.googleusercontent.com","client_secret":"` + marker + `"}}`, errGoogleClientFields},
		{"empty object", `{}`, errGoogleClientFields},
	}
	for _, c := range cases {
		got, err := ParseGoogleClientFile([]byte(c.file))
		if err == nil {
			t.Errorf("%s: ParseGoogleClientFile = %+v, nil error; want an error", c.name, got)
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: error = %q, want the fixed %q", c.name, err, c.want)
		}
		if got != (GoogleClient{}) {
			t.Errorf("%s: ParseGoogleClientFile gave %+v with the error, want the zero client", c.name, got)
		}
		text := err.Error()
		for _, leak := range []string{marker, "MARKER", "test-client", "googleusercontent", "project_id", "'S'"} {
			if strings.Contains(text, leak) {
				t.Errorf("%s: error %q holds %q from the file", c.name, text, leak)
			}
		}
	}
}

// TestGoogleNeedsAuthTextNamesTesting checks B9: the needs-auth text
// for a Gmail account starts with the common NeedsAuthText (the fix
// for each provider), and then names the 7-day cause of a consent
// screen in "Testing" and the fix "In production".
//
// arch: DS7.2, DS78.1, IS7.1, IS7.5, G12, B9, B10
func TestGoogleNeedsAuthTextNamesTesting(t *testing.T) {
	got := GoogleNeedsAuthText("work")
	if !strings.HasPrefix(got, NeedsAuthText("work")) {
		t.Errorf("GoogleNeedsAuthText = %q, want it to start with %q", got, NeedsAuthText("work"))
	}
	for _, part := range []string{`"Testing"`, "7 days", `"In production"`, "OAuth consent screen", "account add work --reauth"} {
		if !strings.Contains(got, part) {
			t.Errorf("GoogleNeedsAuthText = %q, want it to name %q", got, part)
		}
	}
}

// TestGoogleNeedsAuth_Error checks the error of a Gmail sign-in that
// expired: its text is GoogleNeedsAuthText, and errors.Is finds both
// ErrGoogleNeedsAuth and ErrNeedsAuth, so each caller that tests
// ErrNeedsAuth still sees it.
//
// arch: DS7.2, DS6.9, B9, R16-L20
func TestGoogleNeedsAuth_Error(t *testing.T) {
	err := GoogleNeedsAuth("work")
	if err.Error() != GoogleNeedsAuthText("work") {
		t.Errorf("error = %q, want %q", err.Error(), GoogleNeedsAuthText("work"))
	}
	if !errors.Is(err, ErrNeedsAuth) {
		t.Error("errors.Is(err, ErrNeedsAuth) = false, want true")
	}
	if !errors.Is(err, ErrGoogleNeedsAuth) {
		t.Error("errors.Is(err, ErrGoogleNeedsAuth) = false, want true")
	}
	if !strings.HasSuffix(GoogleNeedsAuthText("work"), GoogleTestingText) {
		t.Errorf("GoogleNeedsAuthText = %q, want it to end with GoogleTestingText", GoogleNeedsAuthText("work"))
	}
}
