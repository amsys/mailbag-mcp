// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The Gmail labels (DS7.4, DS7.4a, DS7.4b). This file holds the label
// cache of 10 minutes (name to id, id to name), the role table of the
// system labels, the labels that are marks and not folders, the map
// from the labelIds of a message to mail.Flags, the map from a label
// name to its id, and the three folder writes on labels.

package gmail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// The system label ids that this provider reads (DS7.4, DS7.4b).
const (
	labelInbox     = "INBOX"
	labelSent      = "SENT"
	labelDraft     = "DRAFT"
	labelTrash     = "TRASH"
	labelSpam      = "SPAM"
	labelUnread    = "UNREAD"
	labelStarred   = "STARRED"
	labelImportant = "IMPORTANT"
	labelChat      = "CHAT"
	categoryPrefix = "CATEGORY_"
)

// labelTTL is the life of the label cache on the wall clock (DS7.4).
const labelTTL = 10 * time.Minute

// roles gives the folder role of a system label id (DS7.4). A user
// label has no role. The role comes from the id and never from the
// name, so a user label named "Trash" has no role (E5).
var roles = map[string]string{
	labelInbox: "inbox",
	labelSent:  "sent",
	labelDraft: "drafts",
	labelTrash: "trash",
	labelSpam:  "junk",
}

// label is one label resource of labels.list and labels.get. Only
// labels.get gives the counts.
type label struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"` // "system" or "user"
	MessagesTotal  int    `json:"messagesTotal"`
	MessagesUnread int    `json:"messagesUnread"`
}

// notFolder reports whether the label id is a mark and not a folder:
// STARRED, UNREAD, IMPORTANT, CHAT and each CATEGORY_* label (DS7.4).
func notFolder(id string) bool {
	switch id {
	case labelStarred, labelUnread, labelImportant, labelChat:
		return true
	}
	return strings.HasPrefix(id, categoryPrefix)
}

// flagsOf gives the flags of a message from its labelIds (DS7.4b):
// Seen is no UNREAD, Flagged is STARRED, Draft is DRAFT, and Answered
// is false because the REST API has no such field. Labels holds every
// id but UNREAD, STARRED, DRAFT, IMPORTANT, CHAT and CATEGORY_*. So
// INBOX, SENT, TRASH, SPAM and the user labels are in it, and a move
// shows as a label difference that undo can reverse (DS78.5). Gmail
// changes IMPORTANT and CATEGORY_* on its own; with them in Labels,
// the undo check would refuse each later undo (R§7.3).
func flagsOf(ids []string) mail.Flags {
	f := mail.Flags{Seen: true}
	for _, id := range ids {
		switch id {
		case labelUnread:
			f.Seen = false
		case labelStarred:
			f.Flagged = true
		case labelDraft:
			f.Draft = true
		}
		if id != labelDraft && !notFolder(id) {
			f.Labels = append(f.Labels, id)
		}
	}
	return f
}

// labelTable is one answer of labels.list with its two indexes. It
// does not change after newLabelTable, so more than one goroutine can
// read it.
type labelTable struct {
	list   []label           // the order of labels.list
	byID   map[string]string // id to name
	byName map[string]string // lower-case name to id
	system map[string]bool   // the ids of the labels of type "system"
}

// newLabelTable indexes the labels of one labels.list answer. When two
// names differ in case only, a user label keeps the name before a
// system label, so a user label named "Trash" never gives TRASH (E5);
// a system label stays known by its id (DS7.4a). Else the first label
// in the list keeps the name.
func newLabelTable(list []label) *labelTable {
	t := &labelTable{
		list:   list,
		byID:   make(map[string]string, len(list)),
		byName: make(map[string]string, len(list)),
		system: make(map[string]bool),
	}
	user := make(map[string]bool, len(list)) // the byName id is a user label
	for _, l := range list {
		t.byID[l.ID] = l.Name
		if l.Type == "system" {
			t.system[l.ID] = true
		}
		key := strings.ToLower(l.Name)
		if _, ok := t.byName[key]; !ok || (l.Type == "user" && !user[key]) {
			t.byName[key] = l.ID
			user[key] = l.Type == "user"
		}
	}
	return t
}

// labelCache keeps the last labelTable for labelTTL on the wall clock.
// The zero value is empty and ready to use. The Factory shares one
// cache between the providers of one account through State (G6).
type labelCache struct {
	mu  sync.Mutex
	at  time.Time   // wall time of the labels.list answer in tab
	tab *labelTable // nil: no answer yet
}

// get gives the table when it is younger than labelTTL at now, else
// nil. A negative age means the wall clock stepped back, so the age is
// not known and the table counts as old.
func (c *labelCache) get(now time.Time) *labelTable {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tab == nil {
		return nil
	}
	if age := now.Sub(c.at); age < 0 || age >= labelTTL {
		return nil
	}
	return c.tab
}

// put keeps tab as the answer of labels.list at now.
func (c *labelCache) put(tab *labelTable, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tab = tab
	c.at = now
}

// drop empties the cache, so the next read calls labels.list. A label
// write calls it, because the table no longer agrees with the server.
func (c *labelCache) drop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tab = nil
}

// listLabels calls labels.list, keeps the answer in the label cache and
// gives it.
func (p *Provider) listLabels(ctx context.Context) (*labelTable, error) {
	var ans struct {
		Labels []label `json:"labels"`
	}
	if err := p.api.Get(ctx, "labels", nil, &ans); err != nil {
		return nil, err
	}
	tab := newLabelTable(ans.Labels)
	p.labels.put(tab, p.now())
	return tab, nil
}

// cachedLabels gives the label table from the cache while it is
// younger than labelTTL, else from a new labels.list call.
func (p *Provider) cachedLabels(ctx context.Context) (*labelTable, error) {
	if tab := p.labels.get(p.now()); tab != nil {
		return tab, nil
	}
	return p.listLabels(ctx)
}

// labelIDPattern is the form of a label id (DS7.4a): a user label id
// is Label_<n>, a system label id is upper case.
var labelIDPattern = regexp.MustCompile(`^(Label_\d+|[A-Z][A-Z0-9_]*)$`)

// errSystemLabel is the fixed text of a folder write on a system label
// (DS7.4). Gmail owns these labels.
var errSystemLabel = errors.New("gmail: this is a system label (INBOX, SENT, DRAFT, TRASH, SPAM and the others); a system label is not created, renamed or deleted")

// unknownLabel gives the error of a label name that the account does
// not have, with the names of the labels that it has (DS7.4a).
func unknownLabel(name string, tab *labelTable) error {
	names := make([]string, 0, len(tab.list))
	for _, l := range tab.list {
		names = append(names, l.Name)
	}
	return fmt.Errorf("gmail: the account has no label %q; the labels are: %s", name, strings.Join(names, ", "))
}

// resolveLabel gives the label id of name (DS7.4a). A known label id
// is the id. Else the label with the name in any case gives the id;
// when a user label and a system label have one name in any case, the
// user label wins, so "Trash" never gives TRASH (E5). A name that tab
// does not know gets one new labels.list call, because the label can
// be new. When create is true (add_labels and move_to), a name that is
// still unknown gives the id "" and no error: the caller creates the
// label with createLabel just before the write, so a change that is
// refused or that finds no message leaves no empty label. A name in
// the form of a label id never gets the id "": that form names a label
// that is gone, and a new label with that name is not what the caller
// asked for. Else the error lists the labels. The check for a system
// label is the job of the caller, on the id that this function gives
// (E5). It gives the table that it used last.
func (p *Provider) resolveLabel(ctx context.Context, tab *labelTable, name string, create bool) (string, *labelTable, error) {
	if strings.TrimSpace(name) == "" {
		return "", tab, errors.New("gmail: a label name is empty")
	}
	if id, ok := tab.lookup(name); ok {
		return id, tab, nil
	}
	tab, err := p.listLabels(ctx)
	if err != nil {
		return "", nil, err
	}
	if id, ok := tab.lookup(name); ok {
		return id, tab, nil
	}
	if !create || labelIDPattern.MatchString(name) {
		return "", tab, unknownLabel(name, tab)
	}
	return "", tab, nil
}

// labelExists gives the error of a folder write whose new name is the
// name of a label that the account has. The IMAP and JMAP providers
// refuse an existing folder in the same way.
func labelExists(name string) error {
	return fmt.Errorf("gmail: the account already has a label %q", name)
}

// isConflict reports whether err is the 409 answer of Gmail to a label
// name that a label has.
func isConflict(err error) bool {
	ae, ok := errors.AsType[*APIError](err)
	return ok && ae.Status == http.StatusConflict
}

// postLabel calls labels.create for a user label with the name that
// shows in the label list and the message list, and gives its id. It
// empties the label cache.
func (p *Provider) postLabel(ctx context.Context, name string) (string, error) {
	body := map[string]string{
		"name":                  name,
		"labelListVisibility":   "labelShow",
		"messageListVisibility": "show",
	}
	var l label
	err := p.api.Post(ctx, "labels", nil, body, &l)
	p.labels.drop()
	if err != nil {
		return "", err
	}
	if !labelIDPattern.MatchString(l.ID) {
		return "", fmt.Errorf("gmail: labels.create gave a label id of an unknown form for %q", name)
	}
	return l.ID, nil
}

// createLabel makes the missing user label of add_labels or move_to
// with postLabel and gives its id. When a second client made the label
// at the same time (409), the label is the one the caller asked for,
// so its id comes from a new labels.list call. CreateFolder does not
// use this path: there a 409 is a refusal.
func (p *Provider) createLabel(ctx context.Context, name string) (string, error) {
	id, err := p.postLabel(ctx, name)
	if isConflict(err) {
		tab, lerr := p.listLabels(ctx)
		if lerr != nil {
			return "", lerr
		}
		if id, found := tab.lookup(name); found {
			return id, nil
		}
	}
	return id, err
}

// folderLabel gives the id of the user label name for a folder write,
// and the label table that it used. It refuses a system label with
// errSystemLabel; the check runs on the id, so a user label named
// "Trash" is a user label (E5).
func (p *Provider) folderLabel(ctx context.Context, name string) (string, *labelTable, error) {
	tab, err := p.listLabels(ctx)
	if err != nil {
		return "", nil, err
	}
	id, tab, err := p.resolveLabel(ctx, tab, name, false)
	if err != nil {
		return "", nil, err
	}
	if tab.system[id] {
		return "", nil, errSystemLabel
	}
	return id, tab, nil
}

// newNameFree checks the new name of a folder write against tab before
// the write (DS7.4, DS7.4a). The name matches as in resolveLabel: an id,
// or a name in any case. A name that gives a system label is refused
// with errSystemLabel, so "inbox" is refused as INBOX is. A name that
// gives another label is refused with labelExists. self is the id of
// the label that the write changes ("" for a new label), so a rename
// that changes only the case of the name is allowed.
func newNameFree(tab *labelTable, name, self string) error {
	id, ok := tab.lookup(name)
	switch {
	case !ok || id == self:
		return nil
	case tab.system[id]:
		return errSystemLabel
	}
	return labelExists(name)
}

// CreateFolder makes the user label name with labels.create (DS7.4).
// A name that gives a system label (in any case) is refused with
// errSystemLabel, and a name that gives a user label is refused with
// labelExists; both send no write. When a second client makes the
// label first, Gmail answers 409 and the refusal is labelExists too.
//
// arch: DS7.4, DS7.4a, E5
func (p *Provider) CreateFolder(ctx context.Context, name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("gmail: a label name is empty")
	}
	tab, err := p.listLabels(ctx)
	if err != nil {
		return err
	}
	if err := newNameFree(tab, name, ""); err != nil {
		return err
	}
	_, err = p.postLabel(ctx, name)
	if isConflict(err) {
		return labelExists(name)
	}
	return err
}

// RenameFolder gives the user label from the name to with labels.patch
// (DS7.4). The label keeps its id, so the messages keep it. A system
// label is refused with errSystemLabel, as the source and as the new
// name. A new name that another user label has is refused with
// labelExists, also when Gmail answers 409.
//
// arch: DS7.4, DS7.4a, E5
func (p *Provider) RenameFolder(ctx context.Context, from, to string) error {
	if strings.TrimSpace(to) == "" {
		return errors.New("gmail: a label name is empty")
	}
	id, tab, err := p.folderLabel(ctx, from)
	if err != nil {
		return err
	}
	if err := newNameFree(tab, to, id); err != nil {
		return err
	}
	err = p.api.Patch(ctx, "labels/"+url.PathEscape(id), map[string]string{"name": to}, nil)
	p.labels.drop()
	if isConflict(err) {
		return labelExists(to)
	}
	return err
}

// DeleteFolder removes the user label name with labels.delete (DS7.4).
// The messages stay in the account; only the label goes. A system
// label is refused with errSystemLabel.
//
// arch: DS7.4, DS7.4a, E5
func (p *Provider) DeleteFolder(ctx context.Context, name string) error {
	id, _, err := p.folderLabel(ctx, name)
	if err != nil {
		return err
	}
	err = p.api.Delete(ctx, "labels/"+url.PathEscape(id))
	p.labels.drop()
	return err
}
