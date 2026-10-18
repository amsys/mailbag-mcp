// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The templates tool of S9 (DS9.6). It
// keeps mail templates as files under the config directory and makes
// a draft from one of them. It never sends (G19, IS9.6).

package tools

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
)

// TemplatesIn is the input of the templates tool. Name, Subject and
// Body are for save; Name, To, Cc and Vars are for draft; Name alone
// is for delete. Account is required for every action, because the
// access check needs it (G10, G22).
//
// arch: DS9.6
type TemplatesIn struct {
	Account string            `json:"account"`
	Action  string            `json:"action" jsonschema:"list save delete draft"`
	Name    string            `json:"name,omitempty" jsonschema:"alias pattern"`
	Subject string            `json:"subject,omitempty"`
	Body    string            `json:"body,omitempty"`
	To      []string          `json:"to,omitempty"`
	Cc      []string          `json:"cc,omitempty"`
	Vars    map[string]string `json:"vars,omitempty" jsonschema:"fills {{name}}"`
}

// TemplateRow is one template of a list result.
//
// arch: DS9.6
type TemplateRow struct {
	Name    string `json:"name"`
	Subject string `json:"subject"` // fenced: it was tool input once
	Size    int    `json:"size"`
}

// TemplatesOut is the result of the templates tool. Templates is set
// by list, DraftID by draft. Note is text this server wrote.
//
// arch: DS9.6
type TemplatesOut struct {
	Templates []TemplateRow `json:"templates,omitempty"`
	DraftID   string        `json:"draft_id,omitempty"`
	Note      string        `json:"note,omitempty"`
}

// templateMaxBytes is the largest template file, line 1 included.
const templateMaxBytes = 64 << 10

// templatesDirName is the directory of the templates under
// config.ConfigDir().
const templatesDirName = "templates"

// templatesListMax is the most rows one list gives.
const templatesListMax = 200

// templateSuffix is the file name suffix of a template.
const templateSuffix = ".md"

// subjectPrefix starts line 1 of a template file.
const subjectPrefix = "Subject: "

// templateVar finds one {{key}} of a template. The key is literal
// text; there is no template engine (DS9.13).
var templateVar = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// AddTemplates adds the "templates" tool to srv. The tool is not in
// a toolset until T270 registers it (DS9.8).
//
// arch: DS9.6, G22
func AddTemplates(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &templatesTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "templates",
		Description: "List, save or delete mail templates, or fill one into a draft.",
	}, Wrap(logger, "templates", DefaultTimeout, h.handle))
}

type templatesTool struct {
	mail Mail
}

// handle runs one action. OpenWriter runs first, so an unknown alias
// fails as in every other tool (G10). The level check comes next:
// list needs read, the other three need draft (G22). No file is read
// or written before both checks pass.
//
// arch: DS9.6, G10, G22
func (t *templatesTool) handle(ctx context.Context, in TemplatesIn) (TemplatesOut, error) {
	_, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return TemplatesOut{}, err
	}
	need := guard.LevelDraft
	switch in.Action {
	case "list":
		need = guard.LevelRead
	case "save", "delete", "draft":
	default:
		return TemplatesOut{}, fmt.Errorf("templates: action %q is not one of list, save, delete, draft", in.Action)
	}
	if err := guard.Require(acct, need); err != nil {
		return TemplatesOut{}, err
	}
	dir, err := templatesDir()
	if err != nil {
		return TemplatesOut{}, err
	}
	if in.Action == "list" {
		return listTemplates(dir)
	}
	if !config.ValidAlias(in.Name) {
		return TemplatesOut{}, fmt.Errorf("templates: action %q needs a name of letters, digits, '-' and '_' only", in.Action)
	}
	switch in.Action {
	case "save":
		return TemplatesOut{}, saveTemplate(dir, in.Name, in.Subject, in.Body)
	case "delete":
		return TemplatesOut{}, deleteTemplate(dir, in.Name)
	}
	return t.draft(ctx, dir, in)
}

// templatesDir gives <config dir>/templates.
func templatesDir() (string, error) {
	base, err := config.ConfigDir()
	if err != nil {
		return "", fmt.Errorf("templates: no config directory: %w", err)
	}
	return filepath.Join(base, templatesDirName), nil
}

// errTemplateMissing names a template that does not exist.
func errTemplateMissing(name string) error {
	return fmt.Errorf("template %q does not exist", name)
}

// errTemplateSize names a template larger than templateMaxBytes.
func errTemplateSize(name string) error {
	return fmt.Errorf("template %q is larger than %d bytes", name, templateMaxBytes)
}

// listTemplates gives the name, line 1 and size of each template,
// sorted by name, at most templatesListMax. Every read goes through
// os.OpenRoot, so a link that leaves the directory is skipped and
// never read (IS9.5). A missing directory is an empty list: no
// template was saved yet.
//
// arch: DS9.6, IS9.5
func listTemplates(dir string) (TemplatesOut, error) {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return TemplatesOut{}, nil
	}
	if err != nil {
		return TemplatesOut{}, fmt.Errorf("templates: %w", err)
	}
	defer func() { _ = root.Close() }()

	d, err := root.Open(".")
	if err != nil {
		return TemplatesOut{}, fmt.Errorf("templates: %w", err)
	}
	entries, err := d.Readdirnames(-1)
	_ = d.Close()
	if err != nil {
		return TemplatesOut{}, fmt.Errorf("templates: %w", err)
	}
	var names []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e, templateSuffix)
		if ok && config.ValidAlias(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)

	var out TemplatesOut
	total := len(names)
	if total > templatesListMax {
		names = names[:templatesListMax]
	}
	skipped := 0
	for _, name := range names {
		subject, size, err := templateLine1(root, name+templateSuffix)
		if err != nil {
			skipped++
			continue
		}
		out.Templates = append(out.Templates, TemplateRow{
			Name:    name,
			Subject: guard.Fence("TEMPLATE", subject),
			Size:    size,
		})
	}
	if total > templatesListMax {
		out.Note = fmt.Sprintf("%d of %d templates shown.", templatesListMax, total)
	}
	if skipped > 0 {
		out.Note = addNote(out.Note, fmt.Sprintf("%d templates could not be read: each is not a regular file in the templates directory.", skipped))
	}
	return out, nil
}

// templateLine1 reads line 1 of one template through root and gives
// the subject in it and the file size. It reads no further than
// line 1.
func templateLine1(root *os.Root, file string) (string, int, error) {
	fi, err := root.Stat(file)
	if err != nil {
		return "", 0, err
	}
	if !fi.Mode().IsRegular() {
		return "", 0, errors.New("not a regular file")
	}
	f, err := root.Open(file)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(io.LimitReader(f, templateMaxBytes)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", 0, err
	}
	line = strings.TrimRight(line, "\r\n")
	return strings.TrimPrefix(line, subjectPrefix), int(fi.Size()), nil
}

// readTemplate reads one whole template through os.OpenRoot (IS9.5).
// A link that leaves the directory, a file that is not regular and a
// file larger than templateMaxBytes are refused.
//
// arch: DS9.6, IS9.5
func readTemplate(dir, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errTemplateMissing(name)
	}
	if err != nil {
		return nil, fmt.Errorf("templates: %w", err)
	}
	defer func() { _ = root.Close() }()

	file := name + templateSuffix
	fi, err := root.Stat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errTemplateMissing(name)
	}
	if err != nil {
		return nil, fmt.Errorf("template %q cannot be read: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("template %q is not a regular file", name)
	}
	if fi.Size() > templateMaxBytes {
		return nil, errTemplateSize(name)
	}
	f, err := root.Open(file)
	if err != nil {
		return nil, fmt.Errorf("template %q cannot be read: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, templateMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("template %q cannot be read: %w", name, err)
	}
	if len(data) > templateMaxBytes {
		return nil, errTemplateSize(name)
	}
	return data, nil
}

// saveTemplate writes one template: line 1 "Subject: <subject>", one
// empty line, then the body. The data goes to a new temporary file
// in the directory, gets mode 0600 and is renamed onto <name>.md. A
// rename replaces a template of the same name, and it replaces a
// planted link; it never writes through one (IS9.5). The directory
// is made with mode 0700 when it does not exist.
//
// arch: DS9.6, IS9.5
func saveTemplate(dir, name, subject, body string) error {
	if strings.ContainsAny(subject, "\r\n") {
		return errors.New("templates: subject must be one line")
	}
	content := subjectPrefix + subject + "\n\n" + body
	if len(content) > templateMaxBytes {
		return errTemplateSize(name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("templates: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("save template %q: %w", name, err)
	}
	tmpPath := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save template %q: %w", name, err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, name+templateSuffix)); err != nil {
		return fail(err)
	}
	return nil
}

// deleteTemplate removes <name>.md through os.OpenRoot. A missing
// template is an error that names it.
//
// arch: DS9.6
func deleteTemplate(dir, name string) error {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return errTemplateMissing(name)
	}
	if err != nil {
		return fmt.Errorf("templates: %w", err)
	}
	defer func() { _ = root.Close() }()
	err = root.Remove(name + templateSuffix)
	if errors.Is(err, fs.ErrNotExist) {
		return errTemplateMissing(name)
	}
	if err != nil {
		return fmt.Errorf("delete template %q: %w", name, err)
	}
	return nil
}

// draft reads the template, fills each {{key}} with Vars[key] and
// saves the result as a draft through the draft tool. A {{key}} with
// no value fails the call with the sorted list of missing keys, and
// no draft is saved. A value is put in once and never read again for
// keys. The person sends the draft with the send tool (G19, IS9.6).
//
// arch: DS9.6, G19, IS9.6
func (t *templatesTool) draft(ctx context.Context, dir string, in TemplatesIn) (TemplatesOut, error) {
	data, err := readTemplate(dir, in.Name)
	if err != nil {
		return TemplatesOut{}, err
	}
	subject, body, err := parseTemplate(in.Name, string(data))
	if err != nil {
		return TemplatesOut{}, err
	}
	missing := map[string]bool{}
	fill := func(s string) string {
		return templateVar.ReplaceAllStringFunc(s, func(m string) string {
			key := m[2 : len(m)-2]
			if v, ok := in.Vars[key]; ok {
				return v
			}
			missing[key] = true
			return m
		})
	}
	subject, body = fill(subject), fill(body)
	if len(missing) > 0 {
		keys := make([]string, 0, len(missing))
		for k := range missing {
			keys = append(keys, fmt.Sprintf("%q", k))
		}
		slices.Sort(keys)
		return TemplatesOut{}, fmt.Errorf("template %q needs values in vars for: %s", in.Name, strings.Join(keys, ", "))
	}
	h := &draftTool{mail: t.mail}
	out, err := h.handle(ctx, DraftIn{
		Account: in.Account,
		To:      in.To,
		Cc:      in.Cc,
		Subject: subject,
		Body:    body,
	})
	if err != nil {
		return TemplatesOut{}, err
	}
	return TemplatesOut{DraftID: out.DraftID, Note: out.Note}, nil
}

// parseTemplate splits a template file into its subject (line 1) and
// its body (after the one empty line).
func parseTemplate(name, data string) (string, string, error) {
	line, rest, _ := strings.Cut(data, "\n")
	line = strings.TrimSuffix(line, "\r")
	subject, ok := strings.CutPrefix(line, subjectPrefix)
	if !ok {
		return "", "", fmt.Errorf("template %q has no %q line 1", name, strings.TrimSpace(subjectPrefix))
	}
	if r, ok := strings.CutPrefix(rest, "\r\n"); ok {
		rest = r
	} else {
		rest = strings.TrimPrefix(rest, "\n")
	}
	return subject, rest, nil
}
