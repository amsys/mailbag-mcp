// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// Role discovery has three sources, in this order (C10):
//
//  1. the SPECIAL-USE attribute the server gives (RFC 6154),
//  2. the name table below, for a role that no folder of the list
//     carries as an attribute, and only for a top-level folder or a
//     folder directly below INBOX,
//  3. the [accounts.<alias>.folders] table of the account, which
//     wins over both.
//
// The account table is config, not server state, so the provider
// does not read it. The caller holds the config and applies it with
// ApplyRoleOverrides after it has the folder list.
//
// arch: T4.4, §3.10, C10

// roleNames maps a folder name to a role. Folder names are in the
// language of the person, so the table holds the names of §3.10.
// The compare is case insensitive.
//
// arch: T4.4, §3.10, C10
var roleNames = map[string]string{
	"inbox": "inbox",

	"sent":           "sent",
	"sent items":     "sent",
	"sent messages":  "sent",
	"gesendet":       "sent",
	"envoyés":        "sent",
	"odeslaná pošta": "sent",

	"trash":         "trash",
	"deleted items": "trash",
	"bin":           "trash",
	"papierkorb":    "trash",
	"koš":           "trash",

	"drafts":   "drafts",
	"entwürfe": "drafts",
	"koncepty": "drafts",
	"junk":     "junk",
	"spam":     "junk",
	"archive":  "archive",
	"archives": "archive",
	"all mail": "archive",
}

// knownRoles is every role a folder can carry. ApplyRoleOverrides
// drops a config key that is not in this set, so a typo in
// accounts.toml cannot invent a role that no tool knows.
var knownRoles = map[string]bool{
	"inbox": true, "sent": true, "drafts": true,
	"trash": true, "junk": true, "archive": true, "all": true,
}

// listRoles reads the role of each folder of one LIST answer from the
// server, in the order of the list. The special-use attribute comes
// first. The name table gives a role only when no folder of the list
// carries the attribute for that role. Thus "Bin" does not take the
// trash role from the folder with \Trash.
//
// arch: T4.4, §3.10, C10, R16-M8
func listRoles(list []*imap.ListData) []string {
	roles := make([]string, len(list))
	byAttr := make(map[string]bool)
	for i, d := range list {
		roles[i] = specialUseRole(d)
		if roles[i] != "" {
			byAttr[roles[i]] = true
		}
	}
	for i, d := range list {
		if roles[i] != "" {
			continue
		}
		if r := nameRole(d); !byAttr[r] {
			roles[i] = r
		}
	}
	return roles
}

// specialUseRole reads the role from the special-use attributes of
// RFC 6154.
//
// arch: T4.4, §3.10, C10
func specialUseRole(d *imap.ListData) string {
	for _, a := range d.Attrs {
		switch a {
		case imap.MailboxAttrSent:
			return "sent"
		case imap.MailboxAttrDrafts:
			return "drafts"
		case imap.MailboxAttrTrash:
			return "trash"
		case imap.MailboxAttrJunk:
			return "junk"
		case imap.MailboxAttrArchive:
			return "archive"
		case imap.MailboxAttrAll:
			return "all"
		}
	}
	return ""
}

// nameRole reads the role of one folder from the name table. The
// table reads a top-level folder, and a folder directly below INBOX,
// because a server may put the sent folder there, as "INBOX.Sent".
// A folder deeper in the tree is a folder of the person, so
// "Projects/Archive" gets no role. A delimiter of 0 means the server
// has a flat namespace.
//
// arch: T4.4, §3.10, C10, R16-M8
func nameRole(d *imap.ListData) string {
	name := d.Mailbox
	if d.Delim != 0 {
		parts := strings.Split(d.Mailbox, string(d.Delim))
		switch {
		case len(parts) == 1:
		case len(parts) == 2 && isInbox(parts[0]):
			name = parts[1]
		default:
			return ""
		}
	}
	return roleNames[strings.ToLower(name)]
}

// ApplyRoleOverrides puts the [accounts.<alias>.folders] table over
// the roles the server gave. The table maps a role to a folder name,
// as in sent = "Sent Items".
//
// A role that the table names belongs to that folder only: the same
// role on any other folder goes away. A name that the account has no
// folder for does nothing, and so does a role that no tool knows.
//
// arch: T4.4, §3.10, C10
func ApplyRoleOverrides(folders []mail.Folder, table map[string]string) {
	for role, name := range table {
		role = strings.ToLower(strings.TrimSpace(role))
		if !knownRoles[role] || strings.TrimSpace(name) == "" {
			continue
		}
		at := -1
		for i := range folders {
			if folders[i].Name == name {
				at = i
				break
			}
		}
		if at < 0 {
			for i := range folders {
				if strings.EqualFold(folders[i].Name, name) {
					at = i
					break
				}
			}
		}
		if at < 0 {
			continue
		}
		for i := range folders {
			if folders[i].Role == role {
				folders[i].Role = ""
			}
		}
		folders[at].Role = role
	}
}
