// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds, in caps.go, the optional capability-report
// interface of T91.
package tools

import (
	"context"

	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/imap"
	"github.com/amsys/mailbag-mcp/internal/jmap"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// CapsReporter is an extra a value [Factory.Open] or [Factory.OpenWriter]
// gives may offer on top of [Reader]: a capability report for a human
// (T91). liveLogin asserts it on that value; a provider without it
// gives no capability lines. Adding it as its own interface, instead
// of a new Reader method, keeps the four existing fake Readers
// unchanged (DR1G.17).
//
// arch: DR1G.11, DR1G.18.8, IR1G.15
type CapsReporter interface {
	Caps(ctx context.Context) (mail.Caps, error)
}

// This assertion checks, at every build, that *imap.Provider still
// gives a CapsReporter. It lives here and not in internal/imap: this
// package (tools) imports imap, and imap imports no tools package, so
// an assertion that names tools.CapsReporter cannot sit in package
// imap without an import loop. Factory.Open (provider.go:382) returns
// the same imap.Provider value, so the live login path and this
// check cover the same type (R1G-judge M1, IR1G.15).
//
// arch: DR1G.11, DR1G.18.8, IR1G.15
var _ CapsReporter = (*imap.Provider)(nil)

// The Gmail provider gives a CapsReporter too (DS78.4). Factory.Open
// returns a *gmail.Provider for a gmail account, so this check covers
// the value that liveLogin asserts on (T191 guard, DS78.3).
//
// arch: DS78.3, DS78.4, IR1G.15
var _ CapsReporter = (*gmail.Provider)(nil)

// The JMAP provider gives a CapsReporter too (DS78.4, DS8.2).
// Factory.Open returns a *jmap.Provider for a jmap account, so this
// check covers the value that liveLogin asserts on (DS78.3).
//
// arch: DS78.3, DS78.4, IR1G.15
var _ CapsReporter = (*jmap.Provider)(nil)

// IdentitySource is an optional extra of a value [Factory.Open] gives:
// the sending identities and signatures as the provider stores them.
// "identities detect" asserts it. It is its own interface, like
// [CapsReporter], so the existing fake Readers stay unchanged. IMAP
// and Outlook do not implement it (DI6.2).
//
// arch: DI6.2
type IdentitySource interface {
	ProviderIdentities(ctx context.Context) ([]mail.ProviderIdentity, error)
}

// These assertions check, at every build, that the Gmail and JMAP
// providers still give an IdentitySource (DI6.2).
//
// arch: DI6.2
var (
	_ IdentitySource = (*gmail.Provider)(nil)
	_ IdentitySource = (*jmap.Provider)(nil)
)
