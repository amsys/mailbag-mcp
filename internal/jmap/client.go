// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package jmap reads and changes the mail of a JMAP account (RFC 8620,
// RFC 8621). This file holds the client, written by hand on net/http
// and encoding/json (owner decision 2026-10-09 at the run gate, G10).
// The client gets the session object and keeps it, posts method calls
// to the API URL, and gets and sends blobs. Every URL must be https,
// and each request goes through a guarded client of DS8.3.
//
// A client sends at most maxConcurrentRequests API requests at the
// same time, and it sends a request again after the request error
// "limit" (RFC 8620 §2, §3.6.1).
//
// arch: DS8.1, DS8.3, IS8.1, IS8.3, G10, G11
package jmap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// The capabilities that Call puts in "using" (§3.13, F1).
const (
	usingCore       = "urn:ietf:params:jmap:core"
	usingMail       = "urn:ietf:params:jmap:mail"
	usingSubmission = "urn:ietf:params:jmap:submission"
)

// The body caps of the two guarded clients (DS8.3). An API answer with
// message bodies is larger than the 64 KiB default of the guard. A
// blob holds a message of up to 25 MB (M11) plus overhead (T176).
const (
	MaxAPIBody  = 8 << 20
	MaxBlobBody = 32 << 20
)

// defaultConcurrentRequests is the number of API requests that a
// client sends at the same time when the session gives no
// maxConcurrentRequests, or 0.
const defaultConcurrentRequests = 4

// limitTries is the number of tries of one API request when the server
// gives the request error limitType each time. limitWait is the wait
// before the second try; each next wait is two times the last.
const (
	limitTries = 4
	limitWait  = 100 * time.Millisecond
	limitType  = "urn:ietf:params:jmap:error:limit"
)

// maxErrorBody caps the part of a failed answer that the client reads
// to find the problem type.
const maxErrorBody = 4096

// GuardOptions gives the options of the two guarded clients that New
// takes (DS8.3, DS78.11 G5): api for the session and the method calls,
// blob for Download and Upload. privateHost is the session host when
// the account has private_host = true, else "" (G11). The clients have
// no time limit of their own: the ctx deadline of each call bounds it.
func GuardOptions(privateHost string) (api, blob guard.HTTPOptions) {
	api = guard.HTTPOptions{MaxBody: MaxAPIBody, Timeout: guard.NoTimeout, PrivateHost: privateHost}
	blob = guard.HTTPOptions{MaxBody: MaxBlobBody, Timeout: guard.NoTimeout, PrivateHost: privateHost}
	return api, blob
}

// AuthFunc adds the credential to a request: Bearer <token> or Basic.
type AuthFunc func(*http.Request)

// BearerAuth gives an AuthFunc that sends token as a bearer token. A
// Fastmail account needs it, because Fastmail refuses a password for
// JMAP (F5).
func BearerAuth(token string) AuthFunc {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

// BasicAuth gives an AuthFunc that sends user and password with HTTP
// Basic (F5, DS8.6).
func BasicAuth(user, password string) AuthFunc {
	return func(r *http.Request) { r.SetBasicAuth(user, password) }
}

// Session holds the fields of the JMAP session object that the client
// uses (RFC 8620 §2).
type Session struct {
	APIURL      string
	DownloadURL string // template with {accountId} {blobId} {name} {type}
	UploadURL   string // template with {accountId}
	// AccountID is primaryAccounts[urn:ietf:params:jmap:mail].
	AccountID string
	// MaxSizeUpload is the maxSizeUpload of the core capability; 0
	// when the server gives none.
	MaxSizeUpload int64
	// MaxConcurrentRequests is the maxConcurrentRequests of the core
	// capability; 0 when the server gives none.
	MaxConcurrentRequests int
	Capabilities          map[string]json.RawMessage
}

// sessionWire is the session object as the server sends it.
type sessionWire struct {
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	PrimaryAccounts map[string]string          `json:"primaryAccounts"`
	APIURL          string                     `json:"apiUrl"`
	DownloadURL     string                     `json:"downloadUrl"`
	UploadURL       string                     `json:"uploadUrl"`
}

// Client is the JMAP client of one account. It is safe for calls from
// more than one goroutine: mu guards the kept session, slotsOnce makes
// slots one time, and no call changes another field.
type Client struct {
	api         *http.Client // the session and the method calls (DS8.3)
	blob        *http.Client // Download and Upload (DS8.3)
	auth        AuthFunc
	sessionURL  string
	sessionHost string
	privateHost bool

	mu      sync.Mutex
	session *Session

	// slots holds one value for each API request in flight. Its size
	// comes from the first session that a Call gets.
	slotsOnce sync.Once
	slots     chan struct{}
}

// New gives the client of the account with the session URL sessionURL
// (DS8.1, DS78.11 G5). auth adds the credential to each request; nil
// adds none. api and blob are guarded clients built from GuardOptions.
// With privateHost, each URL of the session must be on the host of
// sessionURL (G11). New sends no request: the first call gets the
// session, and checks sessionURL then.
func New(sessionURL string, auth AuthFunc, api, blob *http.Client, privateHost bool) *Client {
	if auth == nil {
		auth = func(*http.Request) {}
	}
	host := ""
	if u, err := url.Parse(sessionURL); err == nil {
		host = u.Hostname()
	}
	return &Client{
		api:         api,
		blob:        blob,
		auth:        auth,
		sessionURL:  sessionURL,
		sessionHost: host,
		privateHost: privateHost,
	}
}

// Session gets the session object once and keeps it. After a 401 or a
// 404 on the API URL, Call gets it one more time and repeats the call
// once (§3.13). The caller must not change the Session.
func (c *Client) Session(ctx context.Context) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		return c.session, nil
	}
	s, err := c.fetchSession(ctx)
	if err != nil {
		return nil, err
	}
	c.session = s
	return s, nil
}

// refetch gets the session one more time after stale failed on the API
// URL. When another call has replaced stale already, refetch gives that
// session and sends no request. When the fetch fails, the client keeps
// no session, so the next call tries again.
func (c *Client) refetch(ctx context.Context, stale *Session) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil && c.session != stale {
		return c.session, nil
	}
	c.session = nil
	s, err := c.fetchSession(ctx)
	if err != nil {
		return nil, err
	}
	c.session = s
	return s, nil
}

// fetchSession sends the GET for the session object and checks each URL
// of the answer (F4, IS8.1).
func (c *Client) fetchSession(ctx context.Context) (*Session, error) {
	if err := c.checkURL("session_url", c.sessionURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.sessionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("jmap: get the session: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	data, err := c.send(c.api, req, "session", http.StatusOK)
	if err != nil {
		return nil, err
	}
	var w sessionWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("jmap: decode the session: %w", err)
	}
	for _, u := range []struct{ which, raw string }{
		{"apiUrl", w.APIURL},
		{"downloadUrl", w.DownloadURL},
		{"uploadUrl", w.UploadURL},
	} {
		if err := c.checkURL(u.which, u.raw); err != nil {
			return nil, err
		}
	}
	s := &Session{
		APIURL:       w.APIURL,
		DownloadURL:  w.DownloadURL,
		UploadURL:    w.UploadURL,
		AccountID:    w.PrimaryAccounts[usingMail],
		Capabilities: w.Capabilities,
	}
	if s.AccountID == "" {
		return nil, errors.New("jmap: the session names no primary mail account")
	}
	if raw, ok := w.Capabilities[usingCore]; ok {
		var core struct {
			MaxSizeUpload         int64 `json:"maxSizeUpload"`
			MaxConcurrentRequests int   `json:"maxConcurrentRequests"`
		}
		if err := json.Unmarshal(raw, &core); err != nil {
			return nil, fmt.Errorf("jmap: decode the core capability: %w", err)
		}
		s.MaxSizeUpload = core.MaxSizeUpload
		s.MaxConcurrentRequests = core.MaxConcurrentRequests
	}
	return s, nil
}

// checkURL applies the URL rules of DS8.1 (F4, IS8.1) to the URL raw,
// which the error names as which: it must be https, and with
// privateHost its host must be the session host (G11). Without
// privateHost any host passes here, and the guard refuses a private
// address at dial time (DS8.3).
func (c *Client) checkURL(which, raw string) error {
	if raw == "" {
		return refused(which, "it is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return refused(which, "it is not a valid URL")
	}
	if u.Scheme != "https" {
		return refused(which, fmt.Sprintf("the scheme %q is not https", u.Scheme))
	}
	if u.Hostname() == "" {
		return refused(which, "it has no host")
	}
	if c.privateHost && !strings.EqualFold(u.Hostname(), c.sessionHost) {
		return refused(which, fmt.Sprintf("the host %q is not the session host %q, and private_host allows that host only", u.Hostname(), c.sessionHost))
	}
	return nil
}

// refused gives the error of a URL that breaks a rule of DS8.1.
func refused(which, reason string) error {
	return fmt.Errorf("jmap: server URL %s refused: %s", which, reason)
}

// Invocation is one method call or one method response: the JSON array
// [name, arguments, call id] (RFC 8620 §3.2).
type Invocation struct {
	Name string
	Args map[string]any
	ID   string
}

// MarshalJSON writes the invocation as [name, arguments, call id]. A
// nil Args is written as an empty object.
func (i Invocation) MarshalJSON() ([]byte, error) {
	args := i.Args
	if args == nil {
		args = map[string]any{}
	}
	return json.Marshal([3]any{i.Name, args, i.ID})
}

// UnmarshalJSON reads the array [name, arguments, call id].
func (i *Invocation) UnmarshalJSON(b []byte) error {
	var parts []json.RawMessage
	if err := json.Unmarshal(b, &parts); err != nil {
		return err
	}
	if len(parts) != 3 {
		return fmt.Errorf("jmap: an invocation has %d parts, not 3", len(parts))
	}
	var v Invocation
	if err := json.Unmarshal(parts[0], &v.Name); err != nil {
		return err
	}
	if err := json.Unmarshal(parts[1], &v.Args); err != nil {
		return err
	}
	if err := json.Unmarshal(parts[2], &v.ID); err != nil {
		return err
	}
	*i = v
	return nil
}

// Err gives the *MethodError of an "error" response (RFC 8620 §3.6.2),
// and nil for every other invocation.
func (i Invocation) Err() error {
	if i.Name != "error" {
		return nil
	}
	e := &MethodError{}
	e.Type, _ = i.Args["type"].(string)
	e.Description, _ = i.Args["description"].(string)
	return e
}

// Response is the answer to Call (RFC 8620 §3.4).
type Response struct {
	MethodResponses []Invocation `json:"methodResponses"`
}

// request is the body of an API POST (RFC 8620 §3.3).
type request struct {
	Using       []string     `json:"using"`
	MethodCalls []Invocation `json:"methodCalls"`
}

// using gives the capabilities of a batch: core and mail, and
// submission when a call of the batch is in the submission capability.
// RFC 8621 §6 and §7 put both Identity and EmailSubmission there, so
// an Identity/get alone needs it too (F1, IS8.3).
func using(calls []Invocation) []string {
	u := []string{usingCore, usingMail}
	for _, call := range calls {
		if strings.HasPrefix(call.Name, "EmailSubmission/") || strings.HasPrefix(call.Name, "Identity/") {
			return append(u, usingSubmission)
		}
	}
	return u
}

// Call posts the method calls to apiUrl. using holds core and mail, and
// submission when a submission call is in the batch (F1). After a 401
// or a 404, Call gets the session one more time and repeats the call
// once (§3.13). A second 401 gives *AuthError. Call sends each POST
// through postCapped, which caps the requests in flight and tries again
// after the limit error. A method error does not fail Call: it is an invocation in the answer, and Invocation.Err
// gives it.
func (c *Client) Call(ctx context.Context, calls ...Invocation) (*Response, error) {
	if calls == nil {
		calls = []Invocation{}
	}
	body, err := json.Marshal(request{Using: using(calls), MethodCalls: calls})
	if err != nil {
		return nil, fmt.Errorf("jmap: encode the request: %w", err)
	}
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	resp, status, err := c.postCapped(ctx, s, body)
	if status == http.StatusUnauthorized || status == http.StatusNotFound {
		if s, err = c.refetch(ctx, s); err != nil {
			return nil, err
		}
		resp, _, err = c.postCapped(ctx, s, body)
	}
	return resp, err
}

// postCapped sends body with post. It waits for a free slot first, so
// that the client has at most maxConcurrentRequests of the session in
// flight (RFC 8620 §2). When the answer is the request error limitType
// (§3.6.1), the server did not process the request, so postCapped
// sends it again, at most limitTries times in total. It waits before
// each new try and frees the slot during the wait. Another error gives
// no new try. When ctx ends, postCapped stops and gives the ctx error.
func (c *Client) postCapped(ctx context.Context, s *Session, body []byte) (*Response, int, error) {
	c.slotsOnce.Do(func() {
		n := s.MaxConcurrentRequests
		if n <= 0 {
			n = defaultConcurrentRequests
		}
		c.slots = make(chan struct{}, n)
	})
	wait := limitWait
	for try := 1; ; try++ {
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return nil, 0, fmt.Errorf("jmap: api: %w", ctx.Err())
		}
		resp, status, err := c.post(ctx, s, body)
		<-c.slots
		var se *statusError
		if try == limitTries || !errors.As(err, &se) || se.typ != limitType {
			return resp, status, err
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return nil, 0, fmt.Errorf("jmap: api: %w", ctx.Err())
		}
		wait *= 2
	}
}

// post sends body to the API URL of s once. It gives the HTTP status of
// a failed answer, so that Call can decide on the refetch, and 0 when
// no answer came.
func (c *Client) post(ctx context.Context, s *Session, body []byte) (*Response, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.APIURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("jmap: api: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	data, err := c.send(c.api, req, "api", http.StatusOK)
	if err != nil {
		var se *statusError
		if errors.As(err, &se) {
			return nil, se.status, err
		}
		var ae *AuthError
		if errors.As(err, &ae) {
			return nil, ae.Status, err
		}
		return nil, 0, err
	}
	var r Response
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, 0, fmt.Errorf("jmap: decode the answer: %w", err)
	}
	return &r, 0, nil
}

// Download fills the download template and gets the blob through the
// blob client (DS8.3). A field in the path of the template gets
// url.PathEscape; a field in the query gets a query escape, because
// PathEscape keeps "&", "=" and "+", and a "+" in a query reads as a
// space ("image/svg+xml"). It gives the body and its length, -1 when
// the server sends none. The caller closes the body.
func (c *Client) Download(ctx context.Context, blobID, name, typ string) (io.ReadCloser, int64, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, 0, err
	}
	u := fillTemplate(s.DownloadURL, map[string]string{
		"accountId": s.AccountID,
		"blobId":    blobID,
		"name":      name,
		"type":      typ,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("jmap: download: %w", err)
	}
	c.auth(req)
	resp, err := c.blob.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("jmap: download: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer func() { _ = resp.Body.Close() }()
		return nil, 0, failed("download", resp)
	}
	return resp.Body, resp.ContentLength, nil
}

// Upload posts the bytes of r to the upload URL with typ as the
// Content-Type, the media type of the blob (RFC 8620 §6.1), and gives
// the blobId. An empty typ sends application/octet-stream. size is the
// length of r, or -1 when it is not known.
func (c *Client) Upload(ctx context.Context, typ string, r io.Reader, size int64) (string, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return "", err
	}
	if typ == "" {
		typ = "application/octet-stream"
	}
	u := fillTemplate(s.UploadURL, map[string]string{"accountId": s.AccountID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, r)
	if err != nil {
		return "", fmt.Errorf("jmap: upload: %w", err)
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", typ)
	req.Header.Set("Accept", "application/json")
	data, err := c.send(c.blob, req, "upload", http.StatusCreated, http.StatusOK)
	if err != nil {
		return "", err
	}
	var out struct {
		BlobID string `json:"blobId"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("jmap: decode the upload answer: %w", err)
	}
	if out.BlobID == "" {
		return "", errors.New("jmap: the upload answer has no blobId")
	}
	return out.BlobID, nil
}

// send adds the credential to req, sends it through hc and reads the
// whole answer under the body cap of hc. A status that is not in ok
// gives the error of failed. what names the request in each error.
func (c *Client) send(hc *http.Client, req *http.Request, what string, ok ...int) ([]byte, error) {
	c.auth(req)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jmap: %s: %w", what, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if !slices.Contains(ok, resp.StatusCode) {
		return nil, failed(what, resp)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("jmap: %s: read the answer: %w", what, err)
	}
	return data, nil
}

// statusError is a failed answer that is not a 401. Its text gives the
// HTTP status and the problem type of RFC 8620 §3.6.1 when the type
// holds safe characters only; it never gives the free text "detail".
type statusError struct {
	what   string
	status int
	typ    string
}

func (e *statusError) Error() string {
	if e.typ == "" {
		return fmt.Sprintf("jmap: %s: HTTP %d", e.what, e.status)
	}
	return fmt.Sprintf("jmap: %s: HTTP %d %s", e.what, e.status, e.typ)
}

// failed gives the error of a failed answer: *AuthError for a 401, else
// a *statusError.
func failed(what string, resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized {
		return &AuthError{Status: resp.StatusCode}
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var p struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(data, &p)
	return &statusError{what: what, status: resp.StatusCode, typ: safeType(p.Type)}
}

// safeType gives t when it holds letters, digits and ":._-" only, and
// at most 100 bytes; else "". So no text of the server that is not an
// identifier reaches an error text.
func safeType(t string) string {
	if len(t) > 100 {
		return ""
	}
	for _, r := range t {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune(":._-", r) {
			return ""
		}
	}
	return t
}

// fillTemplate puts the value of each {field} of vars into the URL
// template tmpl (RFC 8620 §2: RFC 6570 level 1). A field before the
// first "?" gets url.PathEscape. A field after it gets url.QueryEscape
// with "%20" for a space, so that "&", "=" and "+" in a value cannot
// change the query. A field that vars does not name stays as it is.
func fillTemplate(tmpl string, vars map[string]string) string {
	query := strings.IndexByte(tmpl, '?')
	var b strings.Builder
	for i := 0; i < len(tmpl); {
		if tmpl[i] == '{' {
			if end := strings.IndexByte(tmpl[i:], '}'); end > 0 {
				if v, ok := vars[tmpl[i+1:i+end]]; ok {
					if query >= 0 && i > query {
						b.WriteString(strings.ReplaceAll(url.QueryEscape(v), "+", "%20"))
					} else {
						b.WriteString(url.PathEscape(v))
					}
					i += end + 1
					continue
				}
			}
		}
		b.WriteByte(tmpl[i])
		i++
	}
	return b.String()
}
