// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The map from JMAP objects to the mail types (DS8.2, DS8.2b): the
// keywords of an email to mail.Flags, a mailbox role to the folder
// role, and a JMAP address list to mail.Address values. The other way,
// for a draft: address strings to a JMAP address list, and Message-ID
// values to the bare ids of inReplyTo and references. For Modify: a
// label to the escaped key of a keyword patch, and the mailboxIds of an
// email to the sorted id list of FoldersBefore and FoldersAfter.

package jmap

import (
	"fmt"
	gomail "net/mail"
	"slices"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// The four keywords that are flags (RFC 8621 §4.1.1). Every other
// keyword is a label (DS8.2b).
const (
	keywordSeen     = "$seen"
	keywordFlagged  = "$flagged"
	keywordAnswered = "$answered"
	keywordDraft    = "$draft"
)

// flagsOf gives the flags of an email from its keywords (DS8.2b).
// $seen, $flagged, $answered and $draft set the four flags. Each other
// keyword with the value true goes to Labels, sorted, so that two reads
// of one email give the same list. The keyword names are compared in
// lower case, because JMAP keywords ignore case (RFC 8621 §4.1.1).
// Labels never holds a mailbox: the mailboxes of an email travel in
// FoldersBefore and FoldersAfter (DS78.5), so a keyword and a mailbox
// with one name cannot collide.
//
// arch: DS8.2b
func flagsOf(keywords map[string]bool) mail.Flags {
	var f mail.Flags
	for k, on := range keywords {
		if !on {
			continue
		}
		switch strings.ToLower(k) {
		case keywordSeen:
			f.Seen = true
		case keywordFlagged:
			f.Flagged = true
		case keywordAnswered:
			f.Answered = true
		case keywordDraft:
			f.Draft = true
		default:
			f.Labels = append(f.Labels, k)
		}
	}
	slices.Sort(f.Labels)
	return f
}

// roles gives the folder role of a JMAP mailbox role (RFC 8621 §2,
// the IMAP mailbox attributes of RFC 8457). A role that is not in the
// table, such as "flagged" or "important", gives no folder role.
var roles = map[string]string{
	"inbox":   "inbox",
	"sent":    "sent",
	"drafts":  "drafts",
	"trash":   "trash",
	"junk":    "junk",
	"archive": "archive",
	"all":     "all",
}

// roleOf gives the folder role of the JMAP role r, or "".
func roleOf(r string) string { return roles[strings.ToLower(r)] }

// emailAddress is one EmailAddress object (RFC 8621 §4.1.2.3).
type emailAddress struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// addresses gives the mail.Address values of a JMAP address list. A
// nil list gives nil.
func addresses(in []emailAddress) []mail.Address {
	if len(in) == 0 {
		return nil
	}
	out := make([]mail.Address, len(in))
	for i, a := range in {
		out[i] = mail.Address{Name: a.Name, Address: a.Email}
	}
	return out
}

// firstAddress gives the first address of a list, or the zero value.
func firstAddress(in []emailAddress) mail.Address {
	if len(in) == 0 {
		return mail.Address{}
	}
	return mail.Address{Name: in[0].Name, Address: in[0].Email}
}

// wireAddresses gives the JMAP address list of address strings, such
// as "Ann <ann@example.test>" (RFC 5322). An empty string is left out.
func wireAddresses(in []string) ([]emailAddress, error) {
	var out []emailAddress
	for _, one := range in {
		if strings.TrimSpace(one) == "" {
			continue
		}
		a, err := gomail.ParseAddress(one)
		if err != nil {
			return nil, fmt.Errorf("jmap: recipient address: %w", err)
		}
		out = append(out, emailAddress{Name: a.Name, Email: a.Address})
	}
	return out, nil
}

// bareMessageIDs gives the ids of Message-ID values without the angle
// brackets, the form of inReplyTo and references (RFC 8621 §4.1.2.5).
// A value can hold more than one id; an empty value is left out.
func bareMessageIDs(values []string) []string {
	var out []string
	for _, v := range values {
		for _, f := range strings.Fields(v) {
			if id := strings.Trim(f, "<>,;"); id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}

// pointerEscape escapes a map key for the path of a PatchObject. The
// path is a JSON Pointer (RFC 8620 §5.3, RFC 6901), so "~" becomes
// "~0" and "/" becomes "~1".
var pointerEscape = strings.NewReplacer("~", "~0", "/", "~1")

// pointerUnescape is the reverse of pointerEscape.
var pointerUnescape = strings.NewReplacer("~1", "/", "~0", "~")

// labelKeyword gives the escaped patch key of the label for the path
// "keywords/<key>" (DS8.2b). A JMAP keyword has the characters of an
// IMAP flag keyword (RFC 8621 §4.1.1), so the check refuses a control
// character, a space, a character outside ASCII and the IMAP atom
// specials. It also refuses the four flag keywords: read and starred
// set $seen and $flagged, and a label must not do this past the flag
// rules.
//
// arch: DS8.2, DS8.2b
func labelKeyword(label string) (string, error) {
	if label == "" {
		return "", fmt.Errorf("jmap: a label must have a name")
	}
	switch strings.ToLower(label) {
	case keywordSeen, keywordFlagged, keywordAnswered, keywordDraft:
		return "", fmt.Errorf("jmap: %q is a flag, not a label; use read or starred", label)
	}
	for _, r := range label {
		if r <= ' ' || r > '~' || strings.ContainsRune(`(){]%*"\`, r) {
			return "", fmt.Errorf("jmap: the label %q holds a character that a JMAP keyword does not take", label)
		}
	}
	return pointerEscape.Replace(label), nil
}

// mailboxList gives the ids of the mailboxes that ids marks true,
// sorted. It is the form of Applied.FoldersBefore and FoldersAfter
// (DS78.5): mailbox ids, which do not change when a mailbox gets a new
// name.
func mailboxList(ids map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for id, in := range ids {
		if in {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}
