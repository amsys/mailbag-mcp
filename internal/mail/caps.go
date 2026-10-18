// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds the capability-report type of T91.

package mail

// Caps is what one account's live login found about the server's
// capabilities and about the save_sent rule. tools.CapsReporter is
// optional, so a provider that cannot answer gives no Caps value at
// all; this type never carries a "not reported" state of its own.
//
// Caps holds a slice (Lines), so two values do not compare with ==.
// A test compares them with reflect.DeepEqual.
//
// arch: DR1G.11, DR1G.18.8, IR1G.15, DS78.4
type Caps struct {
	// Keywords is true when a folder takes a keyword the client
	// invents: the PERMANENTFLAGS answer of an examine of INBOX held
	// \* (C17).
	Keywords bool

	// UIDPlus, Move and CondStore are the IMAP capabilities UIDPLUS,
	// MOVE and CONDSTORE, read with go-imap's Has on the live login's
	// capability list.
	UIDPlus   bool
	Move      bool
	CondStore bool

	// SaveSent is the fixed advice line of the save_sent table
	// (DR1G.18.7): what the account's save_sent setting means for
	// this SMTP host. imap.Provider.Caps leaves it empty, because
	// Provider carries no account config; the caller that holds
	// both the capability report and the account (cli's
	// capabilityLines) fills it before the report is printed. For
	// "gmail" and "jmap" that caller fills the fixed Sent advice of
	// DS78.4 in place of the save_sent table.
	SaveSent string

	// Kind is the provider that made the report: "imap", "gmail" or
	// "jmap". The empty value means "imap", because
	// imap.Provider.Caps does not set it. The printer (cli's
	// capabilityLines) prints the four IMAP fields above for "imap"
	// and "", and Lines for every other kind (DS78.4).
	Kind string

	// Lines is the report of a provider that is not IMAP, one fact
	// per line, for example "labels: 12". A line can hold words from
	// the server, so the printer removes the hidden characters and
	// masks secrets before a terminal sees it. A provider that fills
	// Lines leaves the four IMAP fields false.
	Lines []string
}
