//go:build live

// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Live test of the Gmail provider against a real account (T7.6, G15).
// It runs only with the build tag "live" and only when
// MAILBAG_LIVE_GMAIL names an alias; there is no default. The owner
// runs it. It prints field names and counts only, never a message
// value, and fails on a JSON key that the testdata/gmail fixtures do
// not have.

package gmail_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// recorder wraps http.DefaultTransport, which the Gmail REST client
// uses, and keeps the body of each Gmail API answer and the last
// Authorization header.
type recorder struct {
	next   http.RoundTripper
	mu     sync.Mutex
	bodies map[string][][]byte // URL path -> bodies
	auth   string
}

// RoundTrip sends req and keeps the answer body of a Gmail API call.
func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if err != nil || req.URL.Host != "gmail.googleapis.com" {
		return resp, err
	}
	b, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	if rerr != nil {
		return resp, err
	}
	r.mu.Lock()
	r.bodies[req.URL.Path] = append(r.bodies[req.URL.Path], b)
	r.auth = req.Header.Get("Authorization")
	r.mu.Unlock()
	return resp, err
}

// collectKeys adds each object key of v, at any depth, to keys.
func collectKeys(v any, keys map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			keys[k] = true
			collectKeys(e, keys)
		}
	case []any:
		for _, e := range x {
			collectKeys(e, keys)
		}
	}
}

// keysOf gives the object keys of the JSON in b.
func keysOf(t *testing.T, b []byte) map[string]bool {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode a JSON answer: %v", err)
	}
	keys := map[string]bool{}
	collectKeys(v, keys)
	return keys
}

// fixtureKeys gives the union of the object keys of the fixtures in
// testdata/gmail.
func fixtureKeys(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "gmail", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures in testdata/gmail: %v", err)
	}
	all := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read a fixture: %v", err)
		}
		for k := range keysOf(t, b) {
			all[k] = true
		}
	}
	return all
}

// sorted gives the keys of m in order.
func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestLive_Gmail runs labels.list, one search page, one read and
// settings/sendAs against the account that MAILBAG_LIVE_GMAIL names.
//
// arch: DS7.9, DS8.7, DS78.9, IS78.1, G15
func TestLive_Gmail(t *testing.T) {
	alias := os.Getenv("MAILBAG_LIVE_GMAIL")
	if alias == "" {
		t.Skip("MAILBAG_LIVE_GMAIL is not set; set it to a gmail alias to run the live test")
	}
	rec := &recorder{next: http.DefaultTransport, bodies: map[string][][]byte{}}
	http.DefaultTransport = rec
	t.Cleanup(func() { http.DefaultTransport = rec.next })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := tools.NewFactory(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer f.Close()
	r, _, err := f.Open(ctx, alias)
	if err != nil {
		t.Fatalf("open %q: %v", alias, err)
	}

	// DS78.9: the first assertion is that labels.list works.
	folders, err := r.Folders(ctx)
	if errors.Is(err, gmail.ErrAPIDisabled) || errors.Is(err, gmail.ErrScope) {
		t.Fatalf("labels.list: %v", err)
	}
	if err != nil {
		t.Fatalf("labels.list: %v", err)
	}
	t.Logf("labels.list: %d folders", len(folders))

	page, err := r.Search(ctx, mail.Query{Limit: 5})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	t.Logf("search: %d messages, next cursor set: %t", len(page.Messages), page.NextCursor != "")

	if len(page.Messages) > 0 {
		m, err := r.Read(ctx, page.Messages[0].ID, mail.ReadOpts{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		t.Logf("read: body %d chars, %d to, %d cc", len(m.Body), len(m.To), len(m.Cc))
	} else {
		t.Log("read: skipped, the search page is empty")
	}

	rec.mu.Lock()
	auth := rec.auth
	rec.mu.Unlock()
	if auth == "" {
		t.Fatal("no Gmail API call was recorded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://gmail.googleapis.com/gmail/v1/users/me/settings/sendAs", nil)
	if err != nil {
		t.Fatalf("settings/sendAs request: %v", err)
	}
	req.Header.Set("Authorization", auth)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("settings/sendAs: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings/sendAs: status %d", resp.StatusCode)
	}

	allowed := fixtureKeys(t)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	paths := make([]string, 0, len(rec.bodies))
	for p := range rec.bodies {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		keys := map[string]bool{}
		for _, b := range rec.bodies[p] {
			for k := range keysOf(t, b) {
				keys[k] = true
			}
		}
		name := p
		if i := strings.LastIndex(p, "/messages/"); i >= 0 {
			name = p[:i] + "/messages/<id>"
		}
		t.Logf("%s: %d answers, keys %s", name, len(rec.bodies[p]), strings.Join(sorted(keys), ","))
		for _, k := range sorted(keys) {
			if !allowed[k] {
				t.Errorf("%s: JSON key %q is not in the testdata/gmail fixtures", name, k)
			}
		}
	}
}
