// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/imap"
)

// The four actions of the folders tool (§3.16). An empty action is
// list, so a caller that only wants the folder list sends the
// account alone.
const (
	folderActionList   = "list"
	folderActionCreate = "create"
	folderActionRename = "rename"
	folderActionDelete = "delete"
)

// FoldersIn is the input of the folders tool (App B). list reads,
// and create, rename and delete change the folder tree at draft
// level (§3.17).
//
// Account has no omitempty, so the schema makes it required (A12,
// G10). The other three fields are optional, because list needs
// none of them.
type FoldersIn struct {
	Account string `json:"account"`
	Action  string `json:"action,omitempty"`
	Name    string `json:"name,omitempty"`
	NewName string `json:"new_name,omitempty"`
}

// FolderRow is one line of the folders result (§3.16). A folder name
// is not sender-controlled, so it carries no fence (§3.15). It comes
// from the server, so the handler takes its hidden characters and any
// fence marker out before it goes in here.
type FolderRow struct {
	Name   string `json:"name"`
	Role   string `json:"role,omitempty"`
	Total  int    `json:"total"`
	Unread int    `json:"unread"`
}

// FoldersOut is the folders tool result (§3.16).
//
// Every action answers with the folder list as it is after the call.
// A create, a rename and a delete report nothing of their own for
// two reasons. The server decides the real name: the provider adds
// the hierarchy delimiter and the personal NAMESPACE prefix, so the
// name that a caller sent is often not the name the folder has
// (C11). And a list after the change is the proof that the change
// happened, in the shape the caller already knows.
type FoldersOut struct {
	Account string      `json:"account"`
	Folders []FolderRow `json:"folders"`
}

// AddFolders adds the "folders" tool to srv (§3.16): one account,
// four actions, read level for the list and draft level for the
// three that write (§3.17).
//
// The tool claims no annotation. §3.16 gives ReadOnlyHint to accounts,
// search and read only, and this tool is not one of them: it also
// carries the create, rename and delete actions, which write. A
// ReadOnlyHint here would tell a client it may run a folder delete
// with no question.
//
// arch: T4.5, T5.4, T5.5, §3.16, §3.10, §3.17, §9 U7, G10, A12
func AddFolders(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &foldersTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "folders",
		Description: "List folders, or create, rename or delete one (draft level). The server delimiter and personal namespace prefix set the real path. Delete refuses INBOX, a role folder and a folder that holds mail; INBOX cannot be renamed. Each action answers with the list after it.",
	}, Wrap(logger, "folders", DefaultTimeout, h.handle))
}

type foldersTool struct{ mail Mail }

// handle runs one action on the folders of one account. The alias is
// checked first: an unknown one fails here and never reaches a
// network call (G10).
//
// The role of each folder comes from the server (special use, then
// the name table of T4.4). The [accounts.<alias>.folders] table of
// accounts.toml goes over that answer, so a person can name the Sent
// folder that their server does not mark (C10).
//
// arch: T4.5, T5.5, §3.16, §3.10, §3.1, §3.17, G10, C10, C11
func (t *foldersTool) handle(ctx context.Context, in FoldersIn) (FoldersOut, error) {
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action == "" {
		action = folderActionList
	}
	if action == folderActionList {
		p, acct, err := t.mail.Open(ctx, in.Account)
		if err != nil {
			return FoldersOut{}, err
		}
		return t.list(ctx, p, acct, in.Account)
	}
	if err := checkFolderArgs(action, in); err != nil {
		return FoldersOut{}, err
	}

	w, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return FoldersOut{}, err
	}
	// §3.17: a change of the folder tree needs draft level.
	if err := guard.Require(acct, guard.LevelDraft); err != nil {
		return FoldersOut{}, err
	}
	switch action {
	case folderActionCreate:
		err = w.CreateFolder(ctx, in.Name)
	case folderActionRename:
		err = w.RenameFolder(ctx, in.Name, in.NewName)
	case folderActionDelete:
		err = w.DeleteFolder(ctx, in.Name)
	}
	if err != nil {
		return FoldersOut{}, err
	}
	// The list after the change carries the name the server gave the
	// folder, which the provider may have changed (C11).
	return t.list(ctx, w, acct, in.Account)
}

// checkFolderArgs holds the arguments each action needs, so a call
// that names no folder fails before it opens an account.
func checkFolderArgs(action string, in FoldersIn) error {
	switch action {
	case folderActionCreate, folderActionRename, folderActionDelete:
	default:
		return fmt.Errorf("folders: action %q is not one of list, create, rename, delete", action)
	}
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("folders: action %q needs name", action)
	}
	if action == folderActionRename && strings.TrimSpace(in.NewName) == "" {
		return fmt.Errorf("folders: action %q needs new_name", action)
	}
	return nil
}

// list reads the folder tree of one account and builds the result.
//
// arch: T4.5, §3.16, §3.10, C10
func (t *foldersTool) list(ctx context.Context, p Reader, acct config.Account, alias string) (FoldersOut, error) {
	list, err := p.Folders(ctx)
	if err != nil {
		return FoldersOut{}, err
	}
	imap.ApplyRoleOverrides(list, acct.Folders)

	rows := make([]FolderRow, 0, len(list))
	for _, f := range list {
		// The name comes from the server and stays outside every
		// fence (§3.15). Take the hidden characters out, the same as
		// internal/cli does before a terminal sees the same value,
		// and delete a fence marker prefix, so a name cannot forge a
		// fence boundary in the model's view (G2).
		name, _ := guard.StripInvisible(f.Name)
		rows = append(rows, FolderRow{
			Name:   guard.StripFenceMarkers(name),
			Role:   f.Role,
			Total:  f.Total,
			Unread: f.Unread,
		})
	}
	return FoldersOut{Account: alias, Folders: rows}, nil
}
