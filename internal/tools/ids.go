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
// arch: DU3.2, DU12.1
func normalizeID(kind, id string) (string, bool) {
	switch kind {
	case "imap", "outlook":
		v, u, folder, err := mail.ParseIMAPID(id)
		if err != nil {
			return "", false
		}
		return mail.FormatIMAPID(v, u, folder), true
	case "gmail", "jmap":
		if guard.Strict("id", id) {
			return id, true
		}
	}
	return "", false
}
