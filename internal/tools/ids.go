// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Id normalizer for the tool results. A tool writes an id only after
// it passes this check, so an id from a hostile server never reaches
// the outside zone of a result in a form the strict grammar refuses.

package tools

import (
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
)

// normalizeID returns id in the form the server writes for the
// provider kind, and true when the id is valid. The kinds imap and
// outlook run ParseIMAPID then FormatIMAPID, so an old-form id leaves
// in the new form. The kinds gmail and jmap keep the id when it
// matches the strict grammar "id". Any other kind gives false.
//
// An imap or outlook id must also match the strict grammar "id" after
// the format. A folder name of more than 512 bytes gives a hex part
// that the grammar refuses. The caller then drops that one row, not
// the whole result (DU12.3 item 6).
//
// arch: DU3.2, DU12.1, DU12.3
func normalizeID(kind, id string) (string, bool) {
	switch kind {
	case "imap", "outlook":
		v, u, folder, err := mail.ParseIMAPID(id)
		if err != nil {
			return "", false
		}
		out := mail.FormatIMAPID(v, u, folder)
		if !guard.Strict("id", out) {
			return "", false
		}
		return out, true
	case "gmail", "jmap":
		if guard.Strict("id", id) {
			return id, true
		}
	}
	return "", false
}
