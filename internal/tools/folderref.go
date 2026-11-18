// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package tools holds, in folderref.go, the folder ref helpers
// (DU3.3). A folder ref is "=" plus the lowercase hex of the raw
// bytes of a folder or label name. A result gives the ref outside the
// untrusted zone. An input field that takes a folder accepts a ref or
// a name.
package tools

import (
	"context"
	"encoding/hex"
	"strings"

	"github.com/amsys/mailbag-mcp/internal/guard"
)

// folderRefPrefix starts every folder ref (DU3.1 kind folder).
const folderRefPrefix = "="

// folderRefMaxBytes is the largest name, in bytes, that a ref can
// hold. The grammar of the kind folder allows 1 to 512 hex pairs
// (DU3.1).
const folderRefMaxBytes = 512

// errFolderRef is the error of a value that starts with "=" and is not
// a valid folder ref. The text echoes no part of the value (INV-10).
var errFolderRef = public("invalid_input", `a folder value that starts with "=" must be a folder_ref: "=" and 2 to 1024 lowercase hex digits`)

// folderRef gives the ref of the folder or label name. The ref holds
// the raw bytes of the name as the provider gave them, so it is the
// same for each provider and it decodes with one function. An empty
// name, or a name of more than 512 bytes, gives "": the grammar of the
// kind folder cannot hold it, and the field is then omitted.
//
// arch: DU3.3, DU3.1
func folderRef(name string) string {
	if name == "" || len(name) > folderRefMaxBytes {
		return ""
	}
	return folderRefPrefix + hex.EncodeToString([]byte(name))
}

// folderArg reads one folder input value (DU3.3). A value that starts
// with "=" must be a valid ref, and folderArg gives the raw name that
// the ref holds. Any other value is a name: it passes
// guard.StripFenceMarkers, so a fenced name that the model copies back
// loses its markers. When the strip changed the value, the line feeds
// at the two ends go too, because the fence puts a line feed after
// the open marker and before the close marker (DU1.1). An empty value
// stays empty, so the default of the field applies.
//
// A real name that starts with "=" must be given as its ref.
//
// arch: DU3.3, DU12.1
func folderArg(s string) (string, error) {
	if strings.HasPrefix(s, folderRefPrefix) {
		return decodeFolderRef(s)
	}
	clean := guard.StripFenceMarkers(s)
	if clean != s {
		clean = strings.Trim(clean, "\n")
	}
	return clean, nil
}

// decodeFolderRef checks ref against the grammar of the kind folder,
// `^=([0-9a-f]{2}){1,512}$`, and gives the raw name bytes. Upper case
// hex is refused: the grammar is lowercase only, so each name has
// exactly one ref.
func decodeFolderRef(ref string) (string, error) {
	h := ref[len(folderRefPrefix):]
	if len(h) == 0 || len(h)%2 != 0 || len(h) > 2*folderRefMaxBytes {
		return "", errFolderRef
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", errFolderRef
		}
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", errFolderRef
	}
	return string(b), nil
}

// errRefTarget is the refusal of a move_to or add_labels value that
// would make a new folder or label with a name that folders create
// refuses (DU12.4 item 1). The text echoes no part of the name.
var errRefTarget = public("invalid_input", "no folder or label of the account has this name, and it is not a plain name for a new one: it starts with \"=\", or holds fence marker text, a hidden character or a control character; give an existing folder or label, or a plain name")

// checkRefTarget holds DU12.4 item 1 for the input fields that can
// make a folder or a label: move_to of modify and of bulk, and each
// add_labels name of modify (a Gmail label that the account does not
// have is made by the change, E4). names are the values that the
// provider gets, after the trim, the decode of a folder_ref and the
// strip of the fence markers. A name that passes checkNewFolderName
// passes with no folder read. For any other name, checkRefTarget reads
// the folder list of p, once for the call, and the name passes only
// when a folder or label with exactly that raw name exists. Else it
// gives errRefTarget. It does not matter whether the call gave the
// name plain, fenced or as a folder_ref. A call thus cannot make a
// folder or label whose name folders create refuses (DU8.1).
//
// arch: DU12.4, DU12.3, DU8.1, DU3.3
func checkRefTarget(ctx context.Context, p Reader, names ...string) error {
	var have map[string]bool
	for _, name := range names {
		if checkNewFolderName(name) == nil {
			continue
		}
		if have == nil {
			list, err := p.Folders(ctx)
			if err != nil {
				return err
			}
			have = make(map[string]bool, len(list))
			for _, fo := range list {
				have[fo.Name] = true
			}
		}
		if !have[name] {
			return errRefTarget
		}
	}
	return nil
}
