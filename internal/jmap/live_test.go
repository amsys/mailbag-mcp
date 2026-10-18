//go:build live

// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Live test of the JMAP provider against a real account (the JMAP
// "account test", G15). It runs only with the build tag "live" and
// only when MAILBAG_LIVE_JMAP names an alias; there is no default. The
// owner runs it. It prints counts and key names only, never a message
// value.

package jmap_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// filledFields gives the names of the fields of v that are not zero.
func filledFields(v any) string {
	rv := reflect.ValueOf(v)
	var names []string
	for i := 0; i < rv.NumField(); i++ {
		if rv.Type().Field(i).IsExported() && !rv.Field(i).IsZero() {
			names = append(names, rv.Type().Field(i).Name)
		}
	}
	return strings.Join(names, ",")
}

// TestLive_JMAP runs the session, Mailbox/get, one query page and one
// read against the account that MAILBAG_LIVE_JMAP names.
//
// arch: DS7.9, DS8.7, DS78.9, IS78.1, G15
func TestLive_JMAP(t *testing.T) {
	alias := os.Getenv("MAILBAG_LIVE_JMAP")
	if alias == "" {
		t.Skip("MAILBAG_LIVE_JMAP is not set; set it to a jmap alias to run the live test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f := tools.NewFactory(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer f.Close()
	r, _, err := f.Open(ctx, alias)
	if err != nil {
		t.Fatalf("open %q: %v", alias, err)
	}

	// The session: Caps fetches it and reports the account kind.
	if c, ok := r.(interface {
		Caps(context.Context) (mail.Caps, error)
	}); ok {
		caps, err := c.Caps(ctx)
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		t.Logf("session: caps keys %s, %d lines", filledFields(caps), len(caps.Lines))
	}

	folders, err := r.Folders(ctx)
	if err != nil {
		t.Fatalf("Mailbox/get: %v", err)
	}
	roles := 0
	for _, fo := range folders {
		if fo.Role != "" {
			roles++
		}
	}
	t.Logf("Mailbox/get: %d mailboxes, %d with a role", len(folders), roles)

	page, err := r.Search(ctx, mail.Query{Limit: 5})
	if err != nil {
		t.Fatalf("Email/query: %v", err)
	}
	t.Logf("Email/query: %d messages, next cursor set: %t", len(page.Messages), page.NextCursor != "")
	if len(page.Messages) == 0 {
		t.Log("Email/get: skipped, the query page is empty")
		return
	}
	t.Logf("Email/query row keys: %s", filledFields(page.Messages[0]))
	m, err := r.Read(ctx, page.Messages[0].ID, mail.ReadOpts{})
	if err != nil {
		t.Fatalf("Email/get: %v", err)
	}
	t.Logf("Email/get keys: %s; body %d chars", filledFields(*m), len(m.Body))
}
