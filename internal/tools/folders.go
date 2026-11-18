// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package tools

import (
	"context"
	"log/slog"
	"strings"
	"unicode"

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
	Name    string `json:"name,omitempty" jsonschema:"name (create); name or folder_ref (rename, delete)"`
	NewName string `json:"new_name,omitempty" jsonschema:"name"`
}

// FolderRow is one line of the folders result (§3.16, DU5.5). The
// folder_ref, the role and the counts are outside: the ref is the hex
// of the raw name (DU3.3) and the role is a word of this server. The
// display name is under Untrusted in one fence, because a folder name
// can be a sender (a shared folder, a Gmail label).
//
// arch: DU5.5, DU3.3, DU5.1
type FolderRow struct {
	FolderRef string          `json:"folder_ref,omitempty" strict:"folder"`
	Role      string          `json:"role,omitempty" strict:"word"`
	Total     int             `json:"total"`
	Unread    int             `json:"unread"`
	Untrusted FolderUntrusted `json:"untrusted"`
}

// FolderUntrusted is the untrusted zone of one folder row: the display
// name in one fence of the nonce of the response.
type FolderUntrusted struct {
	Name string `json:"name,omitempty"`
}

// FoldersOut is the folders tool result (§3.16, DU5.5). Head gives the
// nonce. Account and the rows are outside, except the fenced name of
// each row.
//
// Every action answers with the folder list as it is after the call.
// A create, a rename and a delete report nothing of their own for
// two reasons. The server decides the real name: the provider adds
// the hierarchy delimiter and the personal NAMESPACE prefix, so the
// name that a caller sent is often not the name the folder has
// (C11). And a list after the change is the proof that the change
// happened, in the shape the caller already knows.
type FoldersOut struct {
	Head
	Account string      `json:"account" strict:"alias"`
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
// arch: T4.5, T5.5, §3.16, §3.10, §3.1, §3.17, G10, C10, C11, DU5.5, DU8.1
func (t *foldersTool) handle(ctx context.Context, in FoldersIn) (FoldersOut, error) {
	f := fencer(ctx)
	action := strings.ToLower(strings.TrimSpace(in.Action))
	if action == "" {
		action = folderActionList
	}
	if action == folderActionList {
		p, acct, err := t.mail.Open(ctx, in.Account)
		if err != nil {
			return FoldersOut{}, err
		}
		return t.list(ctx, f, p, acct, in.Account)
	}
	if err := checkFolderArgs(action, in); err != nil {
		return FoldersOut{}, err
	}

	name, newName, err := folderNames(action, in)
	if err != nil {
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
		err = w.CreateFolder(ctx, name)
	case folderActionRename:
		err = w.RenameFolder(ctx, name, newName)
	case folderActionDelete:
		err = w.DeleteFolder(ctx, name)
	}
	if err != nil {
		return FoldersOut{}, err
	}
	// The list after the change carries the name the server gave the
	// folder, which the provider may have changed (C11).
	return t.list(ctx, f, w, acct, in.Account)
}

// checkFolderArgs holds the arguments each action needs, so a call
// that names no folder fails before it opens an account.
func checkFolderArgs(action string, in FoldersIn) error {
	switch action {
	case folderActionCreate, folderActionRename, folderActionDelete:
	default:
		return publicDetail("invalid_input", "folders: action is not one of list, create, rename, delete", action)
	}
	if strings.TrimSpace(in.Name) == "" {
		return publicDetail("invalid_input", "folders: this action needs name", action)
	}
	if action == folderActionRename && strings.TrimSpace(in.NewName) == "" {
		return publicDetail("invalid_input", "folders: this action needs new_name", action)
	}
	return nil
}

// folderNames turns the name arguments into the raw names the provider
// gets (DU3.3, DU8.1). A rename or delete accepts a folder_ref or a
// name for the existing folder. A name that create or rename makes is
// refused when the strip of a fence marker or of a hidden character
// changes it, or when it holds a control character: the folder would
// carry text that looks like a fence or an instruction. It is also
// refused when it starts with "=": the create name and new_name take
// no folder_ref, and a folder with such a name could be given only by
// its ref (DU12.3 item 4). Each refusal comes before any provider
// call. The error text echoes no part of the name.
//
// arch: DU8.1, DU3.3, DU12.3
func folderNames(action string, in FoldersIn) (name, newName string, err error) {
	switch action {
	case folderActionCreate:
		if err := checkNewFolderName(in.Name); err != nil {
			return "", "", err
		}
		return in.Name, "", nil
	case folderActionRename:
		if name, err = folderArg(in.Name); err != nil {
			return "", "", errFolderRefInput
		}
		if err := checkNewFolderName(in.NewName); err != nil {
			return "", "", err
		}
		return name, in.NewName, nil
	}
	name, err = folderArg(in.Name)
	if err != nil {
		return "", "", errFolderRefInput
	}
	return name, "", nil
}

// errFolderName is the refusal of a new folder name that holds fence
// marker text, a hidden character or a control character (DU8.1).
var errFolderName = public("invalid_input", "the folder name holds fence marker text, a hidden character or a control character; choose a plain name")

// errFolderRefInput is the refusal of a bad folder_ref in an input.
var errFolderRefInput = public("invalid_input", "a folder value that starts with \"=\" must be a folder_ref: \"=\" and 2 to 1024 lowercase hex digits")

// errFolderNameRef is the refusal of a new folder name that starts
// with "=" (DU12.3 item 4).
var errFolderNameRef = public("invalid_input", "a new folder name must not start with \"=\"; give the plain name, because a folder_ref names an existing folder only")

// checkNewFolderName refuses a name that starts with "=" after the trim
// of its outer spaces, that changes under guard.StripFenceMarkers or
// guard.StripInvisible, or that holds a control character. The trim
// matters because a server can trim a new name (DU12.4 item 1).
//
// arch: DU8.1, DU12.3, DU12.4
func checkNewFolderName(s string) error {
	if strings.HasPrefix(strings.TrimSpace(s), folderRefPrefix) {
		return errFolderNameRef
	}
	if guard.StripFenceMarkers(s) != s {
		return errFolderName
	}
	if clean, n := guard.StripInvisible(s); n != 0 || clean != s {
		return errFolderName
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errFolderName
		}
	}
	return nil
}

// list reads the folder tree of one account and builds the result.
//
// arch: T4.5, §3.16, §3.10, C10
func (t *foldersTool) list(ctx context.Context, f guard.Fencer, p Reader, acct config.Account, alias string) (FoldersOut, error) {
	list, err := p.Folders(ctx)
	if err != nil {
		return FoldersOut{}, err
	}
	imap.ApplyRoleOverrides(list, acct.Folders)

	rows := make([]FolderRow, 0, len(list))
	for _, fo := range list {
		// The name is under untrusted in one fence; Wrap runs the
		// escaper on it (DU5.1, INV-5). The ref holds the raw name.
		rows = append(rows, FolderRow{
			FolderRef: folderRef(fo.Name),
			Role:      fo.Role,
			Total:     fo.Total,
			Unread:    fo.Unread,
			Untrusted: FolderUntrusted{Name: wrapIf(f, fo.Name)},
		})
	}
	return FoldersOut{Account: alias, Folders: rows}, nil
}
