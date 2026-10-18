// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Google sign-in for the gmail provider (DS7.2): the fixed endpoints,
// the scopes of G12, the parser for the client_secret.json that the
// person supplies, the oauth2 config with the client secret, the
// authorize parameters of B10 and the needs-auth text of B9.

package oauth

import (
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
)

// googleAuthURL and googleTokenURL are the fixed Google endpoints
// (DS6.2, DS7.2). A test in this package can replace them with an
// httptest server's URL, so that no call goes to Google.
var (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token" //nolint:gosec // G101: a public token endpoint URL, not a credential
)

// googlePasteRedirect is the redirect of the --paste flow. No listener
// is on this address. The browser shows "cannot connect", and the
// person pastes the URL from the address bar (DS7.2).
const googlePasteRedirect = "http://127.0.0.1:17777/callback"

// GoogleScopes are the scopes of the first Google sign-in. The owner
// decision of 2026-10-09 at the run gate (G12) asks for both at once:
// gmail.modify for mail, and gmail.settings.basic for the S9 settings
// tool, so that the person gives consent one time only.
var GoogleScopes = []string{
	"https://www.googleapis.com/auth/gmail.modify",
	"https://www.googleapis.com/auth/gmail.settings.basic",
}

// GoogleClient is the OAuth client that the person supplies (D11.4):
// the two fields of client_secret.json that the token endpoint needs.
type GoogleClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// googleClientFile is the shape of client_secret.json from the Google
// Cloud console. A Desktop client has the "installed" object. A web
// client has the "web" object.
type googleClientFile struct {
	Installed *GoogleClient `json:"installed"`
	Web       *GoogleClient `json:"web"`
}

// errGoogleClientJSON and errGoogleClientFields are the only errors of
// ParseGoogleClientFile. Their texts are fixed and hold no byte of the
// file (IS7.5).
var (
	errGoogleClientJSON   = errors.New("oauth: the Google client file is not a JSON object of the expected shape")
	errGoogleClientFields = errors.New(`oauth: the Google client file has no "installed" or "web" object with client_id and client_secret`)
)

// ParseGoogleClientFile reads the "installed" or the "web" object of a
// client_secret.json from the Google Cloud console. When the two are
// both complete, "installed" is used. The error never holds the file
// content (IS7.5).
//
// arch: DS7.2, IS7.5
func ParseGoogleClientFile(data []byte) (GoogleClient, error) {
	var f googleClientFile
	if err := json.Unmarshal(data, &f); err != nil {
		// The json error is not wrapped: a SyntaxError names a byte of
		// the file, and that byte can be part of the secret.
		return GoogleClient{}, errGoogleClientJSON
	}
	for _, c := range []*GoogleClient{f.Installed, f.Web} {
		if c != nil && c.ClientID != "" && c.ClientSecret != "" {
			return *c, nil
		}
	}
	return GoogleClient{}, errGoogleClientFields
}

// GoogleConfig builds the oauth2 config for one Google client. Google
// wants the client secret also for an installed app and also with PKCE
// (R§2.3). The secret goes in the form body of the token request
// (AuthStyleInParams), as for Microsoft; Google accepts it there.
// redirectURL comes from the loopback or the paste flow. It has no
// function in a token refresh, so a refreshing TokenSource can give "".
//
// arch: DS7.2, G12, B10
func GoogleConfig(c GoogleClient, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       GoogleScopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   googleAuthURL,
			TokenURL:  googleTokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

// GoogleAuthCodeOptions gives the authorize parameters for Google.
// Google gives a refresh token only with access_type=offline, and
// again after an earlier consent only with prompt=consent (B10), so
// both are always sent. login_hint selects the account that is added.
//
// arch: DS7.2, B10
func GoogleAuthCodeOptions(email string) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("access_type", "offline"),
		oauth2.SetAuthURLParam("prompt", "consent"),
		oauth2.SetAuthURLParam("login_hint", email),
	}
}

// GoogleTestingText names the cause of B9 and its fix: when the OAuth
// consent screen of the Google Cloud project is in "Testing", the
// refresh token ends after 7 days. doctor adds it to its hint.
//
// arch: DS7.2, B9, R16-L20
const GoogleTestingText = `If the OAuth consent screen of the Google Cloud project is in "Testing", Google ends the sign-in after 7 days; set the publishing status to "In production".`

// GoogleNeedsAuthText is the needs-auth text for a Gmail account. It
// starts with NeedsAuthText, because the fix is the same for each
// provider, and then it names the cause of B9 (GoogleTestingText).
//
// arch: DS7.2, B9
func GoogleNeedsAuthText(alias string) string {
	return fmt.Sprintf(`%s. %s`, NeedsAuthText(alias), GoogleTestingText)
}

// ErrGoogleNeedsAuth is the sentinel of an expired Gmail sign-in. It
// wraps ErrNeedsAuth, so a caller that tests ErrNeedsAuth finds it
// too. A caller tests it with errors.Is, never by the text.
//
// arch: DS7.2, DS6.9, B9, R16-L20
var ErrGoogleNeedsAuth = fmt.Errorf("%w: Google", ErrNeedsAuth)

// GoogleNeedsAuth gives the error of an expired Gmail sign-in. Its
// text is GoogleNeedsAuthText(alias), and it unwraps to
// ErrGoogleNeedsAuth. The Gmail token function of the Factory gives
// it in place of the needs-auth error of Token(), so the person sees
// the 7-day cause of B9.
//
// arch: DS7.2, DS6.9, B9, R16-L20
func GoogleNeedsAuth(alias string) error {
	return &needsAuthError{alias: alias, google: true}
}
