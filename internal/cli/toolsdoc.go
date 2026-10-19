// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The tool reference of "tools markdown" (DS10.6): one sentence of
// reference text for each tool input field, and the generator that
// joins that text to the live tools/list schema.

package cli

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/tools"
)

// fieldText gives one sentence for each input field, keyed
// "<tool>.<field>". The schema text stays short to keep the tools/list
// budget (D1), so the reference reads from here. Generator-side text
// costs no budget (DS10.13). TestToolsDoc_EveryFieldHasText fails on a
// field with no entry and on an entry with no field.
//
// arch: DS10.6, DS10.13
var fieldText = map[string]string{
	"attachment.account":  "The alias of the account that holds the message.",
	"attachment.id":       "The message id from search or read.",
	"attachment.ref":      "The file name or the part id of the attachment, as read lists it.",
	"attachment.save_dir": "The directory for the file. The default is ~/Downloads/mailbag-mcp.",

	"bulk.account": "The alias of the account to change.",
	"bulk.action":  "The change for each match: read, unread, star, unstar, archive, trash or move.",
	"bulk.dry_run": "Set true to count the matches and list up to 50 rows with their dates. Nothing changes and nobody is asked. It works with read access. Call it before a change by sender, and keep receipts, invoices and account mail out of the query.",
	"bulk.folder":  "The folder to search. The default is INBOX.",
	"bulk.max":     "The largest count of messages to change. The default is 500 and the limit is 5000.",
	"bulk.move_to": "The target folder of the move action.",
	"bulk.query":   "The search query that selects the messages, in the syntax of search.",
	"bulk.undo":    "An undo token reverses one earlier bulk change. The value list shows the recent tokens.",

	"decrypt.account": "The alias of the account that holds the message.",
	"decrypt.id":      "The message id from search.",

	"draft.account":     "The alias of the account that keeps the draft.",
	"draft.attachments": "The absolute paths of the files to attach.",
	"draft.bcc":         "The blind copy recipients.",
	"draft.body":        "The plain text body.",
	"draft.cc":          "The copy recipients.",
	"draft.draft_id":    "The id of a saved draft that this draft replaces.",
	"draft.forward_id":  "The id of a message to forward with its attachments.",
	"draft.from":        "The sender address. It must be an identity of the account. Without it, mailbag picks the identity.",
	"draft.html":        "The HTML body.",
	"draft.quote":       "Quote the earlier message in a reply or a forward. The default is true.",
	"draft.reply_all":   "Reply to all recipients of the earlier message, not only to the sender.",
	"draft.reply_to_id": "The id of the message to reply to. It fills the recipients and the subject.",
	"draft.subject":     "The subject line.",
	"draft.to":          "The recipients.",

	"export.account":  "The alias of the account that holds the message.",
	"export.format":   "The file format: eml (the default) or md.",
	"export.id":       "The message id from search or read.",
	"export.save_dir": "The directory for the file. The default is ~/Downloads/mailbag-mcp.",
	"export.thread":   "Save the full conversation, not only the message.",

	"folders.account":  "The alias of the account.",
	"folders.action":   "The action: list (the default), create, rename or delete.",
	"folders.name":     "The folder to create, rename or delete.",
	"folders.new_name": "The new name of the folder for rename.",

	"gmail_settings.account":        "The alias of a Gmail account.",
	"gmail_settings.action":         "The action: list_filters, create_filter, delete_filter, get_vacation, set_vacation, get_signature or set_signature.",
	"gmail_settings.add_labels":     "The labels that a new filter adds.",
	"gmail_settings.body":           "The text of the vacation reply or of the signature.",
	"gmail_settings.enabled":        "Turn the vacation reply on or off.",
	"gmail_settings.end":            "The last day of the vacation reply, as YYYY-MM-DD.",
	"gmail_settings.filter_id":      "The id of the filter to delete.",
	"gmail_settings.from":           "The sender that a new filter matches.",
	"gmail_settings.has_attachment": "A new filter matches only messages with an attachment.",
	"gmail_settings.mark_read":      "A new filter marks each match as read.",
	"gmail_settings.query":          "The Gmail search query that a new filter matches.",
	"gmail_settings.remove_labels":  "The labels that a new filter removes.",
	"gmail_settings.send_as":        "The send-as address of the signature. The default is the primary address.",
	"gmail_settings.star":           "A new filter stars each match.",
	"gmail_settings.start":          "The first day of the vacation reply, as YYYY-MM-DD.",
	"gmail_settings.subject":        "The subject that a new filter matches, or the subject of the vacation reply.",
	"gmail_settings.to":             "The recipient that a new filter matches.",

	"modify.account":       "The alias of the account to change.",
	"modify.add_labels":    "The labels or keywords to add.",
	"modify.archive":       "Move the messages to the archive.",
	"modify.ids":           "The message ids from search. The limit is 500.",
	"modify.move_to":       "The folder to move the messages to. A move out of junk removes $junk and adds $notjunk. A move into junk does the reverse.",
	"modify.read":          "Mark the messages as read (true) or unread (false).",
	"modify.remove_labels": "The labels or keywords to remove.",
	"modify.starred":       "Star (true) or unstar (false) the messages.",
	"modify.trash":         "Move the messages to the trash.",
	"modify.undo":          "An undo token reverses one earlier change. The value list shows the recent tokens.",

	"read.account":   "The alias of the account that holds the message.",
	"read.format":    "The body format: text (the default) or html.",
	"read.id":        "The message id from search.",
	"read.mark_read": "Mark the message as read.",
	"read.max_chars": "The largest body length in characters. The default is 20000 and the limit is 100000.",
	"read.offset":    "The character position to continue a truncated body from.",
	"read.thread":    "Read the full conversation, not only the message.",

	"search.account": "The alias of the account to search. With no alias, the search covers all accounts.",
	"search.cursor":  "The next_cursor value of an earlier result, to get the next page. It works for one account only.",
	"search.folder":  "The folder to search. The default is INBOX.",
	"search.limit":   "The largest count of results. The default is 20 and the limit is 100.",
	"search.query":   "The search terms, for example from:, subject:, is:unread or after:YYYY-MM-DD. All terms must match. An empty query gives the newest messages.",
	"search.since":   "An RFC 3339 time. The search gives only messages that are newer.",

	"send.account":         "The alias of the account that sends.",
	"send.draft_id":        "The id of the saved draft to send.",
	"send.idempotency_key": "A key that you choose for this send. A second call with the same key gives the first result and sends nothing.",

	"templates.account": "The alias of the account. The draft action saves the draft in this account.",
	"templates.action":  "The action: list, save, delete or draft.",
	"templates.body":    "The body of the template to save. It can hold {{name}} placeholders.",
	"templates.cc":      "The copy recipients of the draft.",
	"templates.name":    "The template name. It follows the rule of an account alias.",
	"templates.subject": "The subject of the template to save.",
	"templates.to":      "The recipients of the draft.",
	"templates.vars":    "The values for the {{name}} placeholders of the template.",

	"unsubscribe.account": "The alias of the account that holds the messages.",
	"unsubscribe.ids":     "The message ids from search. The limit is 50.",
}

// refTool is one tool of the reference, in the order of the output.
type refTool struct {
	set  string
	tool *mcp.Tool
}

// refSchema is the part of an input schema that the reference reads.
type refSchema struct {
	Properties map[string]refProp `json:"properties"`
	Required   []string           `json:"required"`
}

// refProp is one input field of a schema.
type refProp struct {
	Type  any `json:"type"`
	Items *struct {
		Type any `json:"type"`
	} `json:"items"`
}

// referenceTools lists every tool of the full tools/list with its
// toolset: "core" first in tools/list order, then one toolset at a
// time in [tools.Toolsets] order, each in its ExtraGroup.Tools order.
func referenceTools() ([]refTool, error) {
	sets := tools.Toolsets()
	all := make([]string, len(sets))
	owned := map[string]bool{}
	for i, g := range sets {
		all[i] = g.Name
		for _, name := range g.Tools {
			owned[name] = true
		}
	}
	res, err := tools.ListTools(slog.New(slog.DiscardHandler), all...)
	if err != nil {
		return nil, err
	}
	byName := map[string]*mcp.Tool{}
	var core []*mcp.Tool
	for _, t := range res.Tools {
		byName[t.Name] = t
		if !owned[t.Name] {
			core = append(core, t)
		}
	}
	sort.Slice(core, func(i, j int) bool { return core[i].Name < core[j].Name })

	out := make([]refTool, 0, len(res.Tools))
	for _, t := range core {
		out = append(out, refTool{set: "core", tool: t})
	}
	for _, g := range sets {
		for _, name := range g.Tools {
			t, ok := byName[name]
			if !ok {
				return nil, fmt.Errorf("toolset %s names tool %s, which tools/list does not give", g.Name, name)
			}
			out = append(out, refTool{set: g.Name, tool: t})
		}
	}
	return out, nil
}

// inputSchema decodes the input schema of t. The client side of the
// SDK gives it as a plain JSON value, so a round trip through JSON
// reads it.
func inputSchema(t *mcp.Tool) (refSchema, error) {
	var s refSchema
	b, err := json.Marshal(t.InputSchema)
	if err != nil {
		return s, fmt.Errorf("tool %s: marshal input schema: %w", t.Name, err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("tool %s: read input schema: %w", t.Name, err)
	}
	return s, nil
}

// orderedFields gives the field names of s: the required fields
// first, then the others, each part in name order.
func orderedFields(s refSchema) (names []string, required map[string]bool) {
	required = map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if required[names[i]] != required[names[j]] {
			return required[names[i]]
		}
		return names[i] < names[j]
	})
	return names, required
}

// typeName gives the JSON type of p for the table. It drops "null"
// from a type list, and it names the item type of an array.
func typeName(p refProp) string {
	t := jsonType(p.Type)
	if t == "array" && p.Items != nil {
		if it := jsonType(p.Items.Type); it != "" {
			return "array of " + it
		}
	}
	return t
}

// jsonType reads a JSON Schema "type" value: a string, or a list of
// strings where "null" does not count.
func jsonType(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		var parts []string
		for _, e := range t {
			if s, ok := e.(string); ok && s != "null" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " or ")
	}
	return ""
}

// cell makes s safe for one cell of a Markdown table.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

// toolsReference gives the lines of the tool reference (DS10.6): a
// "### <toolset>" heading for core and for each toolset, and under it
// a "#### <tool>" heading, the tool description and a table of the
// input fields. The output is the same on each call.
//
// arch: DS10.6
func toolsReference() ([]string, error) {
	list, err := referenceTools()
	if err != nil {
		return nil, err
	}
	var lines []string
	set := ""
	for _, rt := range list {
		if rt.set != set {
			if set != "" {
				lines = append(lines, "")
			}
			lines = append(lines, "### "+rt.set)
			set = rt.set
		}
		s, err := inputSchema(rt.tool)
		if err != nil {
			return nil, err
		}
		lines = append(lines, "", "#### "+rt.tool.Name, "", rt.tool.Description, "")
		names, required := orderedFields(s)
		if len(names) == 0 {
			lines = append(lines, "No input fields.")
			continue
		}
		lines = append(lines, "| field | type | required | meaning |", "|---|---|---|---|")
		for _, name := range names {
			req := "no"
			if required[name] {
				req = "yes"
			}
			lines = append(lines, fmt.Sprintf("| `%s` | %s | %s | %s |",
				name, cell(typeName(s.Properties[name])), req, cell(fieldText[rt.tool.Name+"."+name])))
		}
	}
	return lines, nil
}
