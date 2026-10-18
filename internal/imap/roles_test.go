// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"context"
	"testing"

	"github.com/emersion/go-imap/v2"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// TestFolders_RoleDiscovery checks trap C10: a role comes from three
// sources in one order. The special-use attribute of the server wins
// first, then the name table for a server that gives no attribute,
// then the folders table of the account, which wins over both.
//
// arch: T4.4, §3.10, C10
func TestFolders_RoleDiscovery(t *testing.T) {
	t.Parallel()

	t.Run("special-use attribute and name table", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name    string
			mailbox string
			delim   rune
			attrs   []imap.MailboxAttr
			want    string
		}{
			{"attribute wins over the name", "Papierkorb", '/', []imap.MailboxAttr{imap.MailboxAttrSent}, "sent"},
			{"attribute all", "Everything", '/', []imap.MailboxAttr{imap.MailboxAttrAll}, "all"},
			{"attribute junk", "Whatever", '/', []imap.MailboxAttr{imap.MailboxAttrJunk}, "junk"},
			{"attribute archive", "Old", '/', []imap.MailboxAttr{imap.MailboxAttrArchive}, "archive"},
			{"attribute drafts", "X", '/', []imap.MailboxAttr{imap.MailboxAttrDrafts}, "drafts"},
			{"attribute trash", "Y", '/', []imap.MailboxAttr{imap.MailboxAttrTrash}, "trash"},
			{"inbox by name", "INBOX", '/', nil, "inbox"},
			{"inbox in another case", "Inbox", '/', nil, "inbox"},
			{"english sent", "Sent Items", '/', nil, "sent"},
			{"german sent", "Gesendet", '/', nil, "sent"},
			{"french sent", "Envoyés", '/', nil, "sent"},
			{"czech sent", "Odeslaná pošta", '/', nil, "sent"},
			{"english trash", "Deleted Items", '/', nil, "trash"},
			{"czech trash", "Koš", '/', nil, "trash"},
			{"german drafts", "Entwürfe", '/', nil, "drafts"},
			{"spam is junk", "Spam", '/', nil, "junk"},
			{"all mail is archive", "All Mail", '/', nil, "archive"},
			{"below the inbox", "INBOX.Sent", '.', nil, "sent"},
			{"flat namespace keeps the whole name", "Sent", 0, nil, "sent"},
			{"a plain folder has no role", "Projects", '/', nil, ""},
			{"a name that only holds a role word", "Sent Reports", '/', nil, ""},
			{"a role word below a user folder", "Projects/Archive", '/', nil, ""}, // arch: R16-M8
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				d := &imap.ListData{Mailbox: c.mailbox, Delim: c.delim, Attrs: c.attrs}
				if got := listRoles([]*imap.ListData{d})[0]; got != c.want {
					t.Fatalf("listRoles(%q) = %q, want %q", c.mailbox, got, c.want)
				}
			})
		}
	})

	t.Run("the account table wins over both", func(t *testing.T) {
		t.Parallel()
		folders := []mail.Folder{
			{Name: "INBOX", Role: "inbox"},
			{Name: "Sent Items", Role: "sent"},
			{Name: "Archiv", Role: ""},
			{Name: "Odeslané", Role: ""},
		}
		ApplyRoleOverrides(folders, map[string]string{
			"sent":    "Odeslané",
			"archive": "Archiv",
			"trash":   "No Such Folder", // the account has no such folder
			"banana":  "Archiv",         // no tool knows this role
		})
		want := map[string]string{
			"INBOX":      "inbox",
			"Sent Items": "", // the table moved the role away
			"Archiv":     "archive",
			"Odeslané":   "sent",
		}
		for _, f := range folders {
			if got := want[f.Name]; f.Role != got {
				t.Fatalf("%q role = %q, want %q", f.Name, f.Role, got)
			}
		}
	})

	t.Run("the folder list carries the name table role", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, fixtureOpts{folders: []string{"Sent Items", "Projects"}})
		list, err := f.prov.Folders(context.Background())
		if err != nil {
			t.Fatalf("Folders: %v", err)
		}
		if got := folderByName(t, list, "Sent Items").Role; got != "sent" {
			t.Fatalf("Sent Items role = %q, want %q", got, "sent")
		}
		if got := folderByName(t, list, "Projects").Role; got != "" {
			t.Fatalf("Projects role = %q, want none", got)
		}
		if got := folderByName(t, list, "INBOX").Role; got != "inbox" {
			t.Fatalf("INBOX role = %q, want %q", got, "inbox")
		}
	})
}

// TestFolders_SpecialUseWinsOverNameTable checks the C10 order over
// the whole folder list. A folder with a special-use attribute holds
// that role, and the name table then gives the role to no other
// folder. The name table reads only a top-level folder or a folder
// directly below INBOX, so "Projects/Archive" is a user folder.
//
// arch: T4.4, §3.10, C10, R16-M8
func TestFolders_SpecialUseWinsOverNameTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	x := newSpecialUseFixture(t, map[string][]imap.MailboxAttr{
		"Bin":              nil,
		"Projects":         nil,
		"Projects/Archive": nil,
		"Trash":            {imap.MailboxAttrTrash},
	})

	list, err := x.prov.Folders(ctx)
	if err != nil {
		t.Fatalf("Folders: %v", err)
	}
	want := map[string]string{
		"INBOX":            "inbox",
		"Bin":              "", // the \Trash folder holds the role
		"Projects":         "",
		"Projects/Archive": "", // not top level, not below INBOX
		"Trash":            "trash",
	}
	for name, role := range want {
		if got := folderByName(t, list, name).Role; got != role {
			t.Errorf("%q role = %q, want %q", name, got, role)
		}
	}

	var trash string
	err = x.pool.WithWrite(ctx, "acct", func(c *Conn) error {
		folders, err := x.w.roleFolders(c)
		if err != nil {
			return err
		}
		trash, _ = folderNamed(folders, "trash")
		return nil
	})
	if err != nil {
		t.Fatalf("roleFolders: %v", err)
	}
	if trash != "Trash" {
		t.Errorf("the trash folder is %q, want the \\Trash folder %q", trash, "Trash")
	}

	if err := x.w.DeleteFolder(ctx, "Projects/Archive"); err != nil {
		t.Errorf("DeleteFolder(Projects/Archive): %v; a user folder carries no role", err)
	}
}
