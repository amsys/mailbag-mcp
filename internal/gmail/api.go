// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package gmail reads and changes the mail of a Gmail account through
// the Gmail REST API (D11). This file holds the REST client (DS7.3):
// it tries a rate limit and a server error again with backoff, gets a
// new token once after a 401, gives fixed texts for the errors that
// the person must fix, and caps the body of each answer at 64 MiB.
//
// arch: DS7.3, DS7.7, IS7.2, IS7.3, IS7.5
package gmail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/amsys/mailbag-mcp/internal/guard"
	oauthpkg "github.com/amsys/mailbag-mcp/internal/oauth"
)

// baseURL and uploadURL are the fixed hosts of the Gmail API. No URL
// from mail or from the model reaches them, so the client is the plain
// oauth client and not the SSRF guard (DS6.2, DS7.3).
var (
	baseURL   = "https://gmail.googleapis.com/gmail/v1/users/me/"
	uploadURL = "https://gmail.googleapis.com/upload/gmail/v1/users/me/"
)

const (
	// maxTries is the number of tries of one call that gets a rate
	// limit or a server error (DS7.3, §3.12).
	maxTries = 4
	// maxBodyBytes caps the body of one answer. A raw message of 35 MB
	// in base64 fits (DS7.3).
	maxBodyBytes = 64 << 20
)

// TokenFunc gives a bearer token. The function of the Factory gets a
// new token after onAuth dropped the old one (DS78.3).
type TokenFunc func(ctx context.Context) (string, error)

// API is the thin REST client of D11 (DS7.3). One API is safe for
// calls from more than one goroutine: New sets each field, and no call
// changes one.
type API struct {
	http    *http.Client // oauthpkg.Client(): 30 s, no proxy change
	token   TokenFunc
	onAuth  func(error) // the Factory: forget the token, note the state
	sleep   func(context.Context, time.Duration) error
	jitter  func() time.Duration // 0 to 1 s
	base    string               // baseURL when New ran
	upload  string               // uploadURL when New ran
	maxBody int64
	log     *slog.Logger
}

// New gives an API that gets each bearer token from token and reports
// each auth event to onAuth: the first 401 of a call, then
// oauthpkg.ErrNeedsAuth, ErrAPIDisabled or ErrScope (DS7.3, DS78.3).
// A nil onAuth reports nothing. The server message of a failed call
// goes to slog.Default after guard.Redact (DS7.7).
func New(token TokenFunc, onAuth func(error)) *API {
	if onAuth == nil {
		onAuth = func(error) {}
	}
	return &API{
		http:    oauthpkg.Client(),
		token:   token,
		onAuth:  onAuth,
		sleep:   sleepCtx,
		jitter:  jitter,
		base:    baseURL,
		upload:  uploadURL,
		maxBody: maxBodyBytes,
		log:     slog.Default(),
	}
}

// Get calls GET on path below baseURL with the query q and decodes the
// JSON answer into out. The caller escapes each id in path.
func (a *API) Get(ctx context.Context, path string, q url.Values, out any) error {
	return a.do(ctx, call{method: http.MethodGet, path: path, url: join(a.base, path, q)}, out)
}

// Post calls POST on path below baseURL with the query q and the JSON
// of body (none when body is nil), and decodes the answer into out.
func (a *API) Post(ctx context.Context, path string, q url.Values, body, out any) error {
	c, err := jsonCall(http.MethodPost, path, join(a.base, path, q), body)
	if err != nil {
		return err
	}
	return a.do(ctx, c, out)
}

// Patch calls PATCH on path below baseURL with the JSON of body and
// decodes the answer into out.
func (a *API) Patch(ctx context.Context, path string, body, out any) error {
	c, err := jsonCall(http.MethodPatch, path, join(a.base, path, nil), body)
	if err != nil {
		return err
	}
	return a.do(ctx, c, out)
}

// Delete calls DELETE on path below baseURL.
func (a *API) Delete(ctx context.Context, path string) error {
	return a.do(ctx, call{method: http.MethodDelete, path: path, url: join(a.base, path, nil)}, nil)
}

// Upload sends multipart/related to path below uploadURL with
// uploadType=multipart: part 1 is the JSON of meta, part 2 is raw as
// message/rfc822 (§3.12 Send row). It decodes the answer into out.
func (a *API) Upload(ctx context.Context, method, path string, meta any, raw []byte, out any) error {
	body, ctype, err := related(meta, raw)
	if err != nil {
		return err
	}
	q := url.Values{"uploadType": {"multipart"}}
	c := call{method: method, path: path, url: join(a.upload, path, q), ctype: ctype, body: body}
	return a.do(ctx, c, out)
}

// sendOnce is Post for drafts.send: it tries again on 429 only. After
// a 5xx or a 403 the message can be sent already, and a second try
// can send it twice (IS7.3). A 401 still gets one try with a new
// token: the server refused the call before it did the work (IS7.2).
func (a *API) sendOnce(ctx context.Context, path string, body, out any) error {
	c, err := jsonCall(http.MethodPost, path, join(a.base, path, nil), body)
	if err != nil {
		return err
	}
	c.sendOnce = true
	return a.do(ctx, c, out)
}

// call is one request that do can send more than once.
type call struct {
	method   string
	path     string // for the log; it holds no query
	url      string
	ctype    string
	body     []byte // nil: no body
	sendOnce bool
}

// jsonCall makes a call with the JSON of body, or with no body when
// body is nil.
func jsonCall(method, path, u string, body any) (call, error) {
	c := call{method: method, path: path, url: u}
	if body == nil {
		return c, nil
	}
	data, err := json.Marshal(body)
	if err != nil {
		return call{}, fmt.Errorf("gmail: encode the request: %w", err)
	}
	c.ctype = "application/json"
	c.body = data
	return c, nil
}

// join gives base plus path plus the query q.
func join(base, path string, q url.Values) string {
	u := base + strings.TrimPrefix(path, "/")
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// related encodes the multipart/related body of Upload and gives its
// Content-Type.
func related(meta any, raw []byte) ([]byte, string, error) {
	js, err := json.Marshal(meta)
	if err != nil {
		return nil, "", fmt.Errorf("gmail: encode the upload metadata: %w", err)
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	parts := []struct {
		ctype string
		data  []byte
	}{
		{"application/json; charset=UTF-8", js},
		{"message/rfc822", raw},
	}
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", p.ctype)
		pw, err := w.CreatePart(h)
		if err != nil {
			return nil, "", fmt.Errorf("gmail: encode the upload: %w", err)
		}
		if _, err := pw.Write(p.data); err != nil {
			return nil, "", fmt.Errorf("gmail: encode the upload: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", fmt.Errorf("gmail: encode the upload: %w", err)
	}
	return buf.Bytes(), "multipart/related; boundary=" + w.Boundary(), nil
}

// do sends c until it succeeds or a rule of DS7.3 stops it:
//
//   - 401: report it to onAuth, which drops the token, and try once
//     more with a new token. A second 401 gives oauthpkg.ErrNeedsAuth
//     (IS7.2).
//   - 403 accessNotConfigured or SERVICE_DISABLED gives ErrAPIDisabled;
//     403 insufficientPermissions or ACCESS_TOKEN_SCOPE_INSUFFICIENT
//     gives ErrScope. onAuth gets both.
//   - 429, a 403 rate limit and a 5xx get maxTries tries in total. The
//     wait is 1 s × 2ⁿ plus jitter; Retry-After wins when it is there.
//     A wait that ends after the ctx deadline stops the call. A
//     sendOnce call tries again on 429 only (IS7.3).
//
// A failed call writes one WARN line with the server message after
// guard.Redact (DS7.7).
func (a *API) do(ctx context.Context, c call, out any) error {
	refreshed := false
	try := 1
	for {
		status, header, data, err := a.send(ctx, c)
		if err != nil {
			return err
		}
		if status >= 200 && status <= 299 {
			return decode(data, out)
		}
		e := parseError(status, data)
		if status == http.StatusUnauthorized {
			if !refreshed {
				refreshed = true
				a.onAuth(e)
				continue
			}
			a.warn(c, e)
			a.onAuth(oauthpkg.ErrNeedsAuth)
			return oauthpkg.ErrNeedsAuth
		}
		if fixed := e.fixed(); fixed != nil {
			a.warn(c, e)
			a.onAuth(fixed)
			return fixed
		}
		if !e.retryable(c.sendOnce) || try >= maxTries {
			a.warn(c, e)
			return e
		}
		wait := a.wait(try, header)
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < wait {
			a.warn(c, e)
			return e
		}
		if err := a.sleep(ctx, wait); err != nil {
			a.warn(c, e)
			return fmt.Errorf("%w: %w", e, err)
		}
		try++
	}
}

// send makes one request of c with a token from a.token and reads the
// answer under the body cap.
func (a *API) send(ctx context.Context, c call) (int, http.Header, []byte, error) {
	tok, err := a.token(ctx)
	if err != nil {
		return 0, nil, nil, err
	}
	var body io.Reader
	if c.body != nil {
		body = bytes.NewReader(c.body)
	}
	req, err := http.NewRequestWithContext(ctx, c.method, c.url, body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("gmail: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if c.ctype != "" {
		req.Header.Set("Content-Type", c.ctype)
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("gmail: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, a.maxBody+1))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("gmail: read the answer: %w", err)
	}
	if int64(len(data)) > a.maxBody {
		return 0, nil, nil, errBodyTooLarge
	}
	return resp.StatusCode, resp.Header, data, nil
}

// decode reads the JSON answer into out. An empty answer or a nil out
// decodes nothing.
func decode(data []byte, out any) error {
	if out == nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("gmail: decode the answer: %w", err)
	}
	return nil
}

// wait gives the wait before try number try+1: Retry-After when the
// answer has a valid one, else 1 s × 2^(try-1) plus jitter (DS7.3).
func (a *API) wait(try int, h http.Header) time.Duration {
	if d, ok := retryAfter(h.Get("Retry-After")); ok {
		return d
	}
	return time.Second<<(try-1) + a.jitter()
}

// retryAfter reads a Retry-After value: a number of seconds or an HTTP
// date. A date in the past gives 0. A value that is not valid, or a
// number of seconds that does not fit in a time.Duration, gives false.
func retryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 || n > math.MaxInt64/int64(time.Second) {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0), true
	}
	return 0, false
}

// warn writes the one log line of a failed call. The server message
// goes through guard.Redact first (DS7.7, IS7.5).
func (a *API) warn(c call, e *APIError) {
	a.log.Warn("gmail call failed",
		"method", c.method,
		"path", c.path,
		"status", e.Status,
		"reason", e.Reason,
		"message", guard.Redact(e.message))
}

// sleepCtx waits d, or less when ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// jitter gives a random wait from 0 to 1 s, so that clients that got a
// rate limit at the same time do not try again at the same time.
func jitter() time.Duration {
	return rand.N(time.Second) //nolint:gosec // G404: a retry delay needs no secure random number
}
