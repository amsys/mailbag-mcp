// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The gmail_settings tool of S9 (DS9.7). It reads and changes the
// filters, the vacation auto-reply and the signature of a Gmail
// account through the gmail.Settings interface. An account of another
// provider gets a note and no error. The access level depends on the
// action (G21). Filter criteria, label names, vacation text and the
// signature are fenced (§3.15).

package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/amsys/mailbag-mcp/internal/gmail"
	"github.com/amsys/mailbag-mcp/internal/guard"
)

// GmailSettingsIn is the input of the gmail_settings tool. Action
// selects which of the other fields count: the filter fields for
// create_filter, FilterID for delete_filter, Enabled, Subject, Body,
// Start and End for set_vacation, SendAs and Body for the signature.
//
// arch: DS9.7
type GmailSettingsIn struct {
	Account       string   `json:"account"`
	Action        string   `json:"action" jsonschema:"list_filters create_filter delete_filter get_vacation set_vacation get_signature set_signature"`
	FilterID      string   `json:"filter_id,omitempty"`
	From          string   `json:"from,omitempty"`
	To            string   `json:"to,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	Query         string   `json:"query,omitempty"`
	HasAttachment *bool    `json:"has_attachment,omitempty"`
	AddLabels     []string `json:"add_labels,omitempty"`
	RemoveLabels  []string `json:"remove_labels,omitempty"`
	MarkRead      bool     `json:"mark_read,omitempty"`
	Star          bool     `json:"star,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty" jsonschema:"vacation on or off"`
	Body          string   `json:"body,omitempty" jsonschema:"vacation or signature"`
	Start         string   `json:"start,omitempty" jsonschema:"date"`
	End           string   `json:"end,omitempty" jsonschema:"date"`
	SendAs        string   `json:"send_as,omitempty" jsonschema:"default primary"`
}

// FilterRow is one Gmail filter of a result (S9-GAP8). The ID is the
// id Gmail gave. The criteria and the label names are fenced. A
// filter with no criteria or no action has empty fields (E13).
//
// arch: DS9.7
type FilterRow struct {
	ID            string   `json:"id"`
	From          string   `json:"from,omitempty"`    // fenced
	To            string   `json:"to,omitempty"`      // fenced
	Subject       string   `json:"subject,omitempty"` // fenced
	Query         string   `json:"query,omitempty"`   // fenced
	HasAttachment *bool    `json:"has_attachment,omitempty"`
	AddLabels     []string `json:"add_labels,omitempty"`    // names, fenced
	RemoveLabels  []string `json:"remove_labels,omitempty"` // names, fenced
	MarkRead      bool     `json:"mark_read,omitempty"`
	Star          bool     `json:"star,omitempty"`
}

// VacationRow is the vacation auto-reply of a result (S9-GAP8). The
// subject and the body are fenced. Start and End are YYYY-MM-DD in
// the local zone of the host (S9-GAP7); End is the last day.
//
// arch: DS9.7
type VacationRow struct {
	Enabled bool   `json:"enabled"`
	Subject string `json:"subject,omitempty"` // fenced
	Body    string `json:"body,omitempty"`    // fenced
	Start   string `json:"start,omitempty"`   // YYYY-MM-DD
	End     string `json:"end,omitempty"`
}

// GmailSettingsOut is the result of the gmail_settings tool. Filters
// is set by list_filters and create_filter, Vacation by get_vacation,
// Signature (fenced) by get_signature. Note is text this server wrote.
//
// arch: DS9.7
type GmailSettingsOut struct {
	Filters   []FilterRow  `json:"filters,omitempty"`
	Vacation  *VacationRow `json:"vacation,omitempty"`
	Signature string       `json:"signature,omitempty"` // fenced
	Note      string       `json:"note,omitempty"`
}

// dayLayout is the date form of Start and End (DS9.7).
const dayLayout = "2006-01-02"

// AddGmailSettings adds the "gmail_settings" tool to srv. The tool is
// not in a toolset until T270 registers it (DS9.8).
//
// arch: DS9.7, G21
func AddGmailSettings(srv *mcp.Server, logger *slog.Logger, m Mail) {
	h := &gmailSettingsTool{mail: m}
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "gmail_settings",
		Description: "Read or change Gmail filters, vacation reply and signature.",
	}, Wrap(logger, "gmail_settings", DefaultTimeout, h.handle))
}

type gmailSettingsTool struct {
	mail Mail
}

// handle runs one action. The order is fixed (S9-GAP6): OpenWriter,
// so an unknown alias fails as in every other tool (G10); then the
// level check of the action (G21); then the gmail.Settings type
// assertion. So an account of another provider at a level too low
// gets the denial, and at a level high enough it gets the note.
//
// arch: DS9.7, DS9.11, G10, G21
func (t *gmailSettingsTool) handle(ctx context.Context, in GmailSettingsIn) (GmailSettingsOut, error) {
	p, acct, err := t.mail.OpenWriter(ctx, in.Account)
	if err != nil {
		return GmailSettingsOut{}, err
	}
	need, err := settingsLevel(in)
	if err != nil {
		return GmailSettingsOut{}, err
	}
	if err := guard.Require(acct, need); err != nil {
		return GmailSettingsOut{}, err
	}
	s, ok := p.(gmail.Settings)
	if !ok {
		alias := acct.Alias
		if alias == "" {
			alias = in.Account
		}
		return GmailSettingsOut{Note: fmt.Sprintf("gmail_settings works for Gmail accounts only; %s uses %s", alias, acct.Provider)}, nil
	}
	out, err := runSettings(ctx, s, in)
	if errors.Is(err, gmail.ErrScope) {
		// The fixed text of DS7.3: it tells the person how to get the
		// missing scope, and nothing else.
		return GmailSettingsOut{}, gmail.ErrScope
	}
	return out, err
}

// settingsLevel gives the level an action needs (G21): the three
// reads need read; filter create and delete, the signature and
// vacation off need draft; vacation on needs send, because Gmail then
// sends mail to each writer. set_vacation with no enabled is an error,
// so a missing value never picks the lower level.
//
// arch: DS9.7, G21
func settingsLevel(in GmailSettingsIn) (guard.Level, error) {
	switch in.Action {
	case "list_filters", "get_vacation", "get_signature":
		return guard.LevelRead, nil
	case "create_filter", "delete_filter", "set_signature":
		return guard.LevelDraft, nil
	case "set_vacation":
		if in.Enabled == nil {
			return "", errors.New("gmail_settings: set_vacation needs enabled true or false")
		}
		if *in.Enabled {
			return guard.LevelSend, nil
		}
		return guard.LevelDraft, nil
	default:
		return "", fmt.Errorf("gmail_settings: action %q is not one of list_filters, create_filter, delete_filter, get_vacation, set_vacation, get_signature, set_signature", in.Action)
	}
}

// runSettings does one action on s. The level check is done.
func runSettings(ctx context.Context, s gmail.Settings, in GmailSettingsIn) (GmailSettingsOut, error) {
	switch in.Action {
	case "list_filters":
		fs, err := s.ListFilters(ctx)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		out := GmailSettingsOut{Filters: make([]FilterRow, 0, len(fs))}
		for _, f := range fs {
			out.Filters = append(out.Filters, filterRow(f))
		}
		if len(fs) == 0 {
			out.Note = "the account has no filters"
		}
		return out, nil
	case "create_filter":
		f, err := s.CreateFilter(ctx, gmail.Filter{
			From: in.From, To: in.To, Subject: in.Subject, Query: in.Query,
			HasAttachment: in.HasAttachment,
			AddLabels:     in.AddLabels, RemoveLabels: in.RemoveLabels,
			MarkRead: in.MarkRead, Star: in.Star,
		})
		if err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Filters: []FilterRow{filterRow(f)}, Note: "filter created"}, nil
	case "delete_filter":
		if strings.TrimSpace(in.FilterID) == "" {
			return GmailSettingsOut{}, errors.New("gmail_settings: delete_filter needs filter_id")
		}
		if err := s.DeleteFilter(ctx, in.FilterID); err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Note: "filter deleted"}, nil
	case "get_vacation":
		v, err := s.Vacation(ctx)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Vacation: vacationRow(v)}, nil
	case "set_vacation":
		// Gmail replaces the whole setting, so read it first: a field
		// the call does not give keeps its value (R16-L7).
		cur, err := s.Vacation(ctx)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		v, err := vacationOf(in, cur)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		if err := s.SetVacation(ctx, v); err != nil {
			return GmailSettingsOut{}, err
		}
		if v.Enabled {
			return GmailSettingsOut{Note: "vacation reply on"}, nil
		}
		return GmailSettingsOut{Note: "vacation reply off"}, nil
	case "get_signature":
		sig, err := s.Signature(ctx, in.SendAs)
		if err != nil {
			return GmailSettingsOut{}, err
		}
		if sig == "" {
			return GmailSettingsOut{Note: "the address has no signature"}, nil
		}
		return GmailSettingsOut{Signature: guard.Fence("SIGNATURE", sig)}, nil
	default: // set_signature; settingsLevel refused every other action
		if err := s.SetSignature(ctx, in.SendAs, in.Body); err != nil {
			return GmailSettingsOut{}, err
		}
		return GmailSettingsOut{Note: "signature saved"}, nil
	}
}

// fenceIf fences a non-empty value. An empty value stays empty, so
// omitempty drops it and a filter with missing parts shows only the
// parts it has (E13).
func fenceIf(kind, s string) string {
	if s == "" {
		return ""
	}
	return guard.Fence(kind, s)
}

// fenceAll fences each name of a label list.
func fenceAll(kind string, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = guard.Fence(kind, n)
	}
	return out
}

// filterRow gives the result row of f with every text part fenced.
// A user can name a label, so the label names are fenced too.
//
// arch: DS9.7
func filterRow(f gmail.Filter) FilterRow {
	return FilterRow{
		ID:            f.ID,
		From:          fenceIf("FILTER", f.From),
		To:            fenceIf("FILTER", f.To),
		Subject:       fenceIf("FILTER", f.Subject),
		Query:         fenceIf("FILTER", f.Query),
		HasAttachment: f.HasAttachment,
		AddLabels:     fenceAll("LABEL", f.AddLabels),
		RemoveLabels:  fenceAll("LABEL", f.RemoveLabels),
		MarkRead:      f.MarkRead,
		Star:          f.Star,
	}
}

// vacationRow gives the result row of v. The subject and the body are
// fenced. End on the wire is the first instant with no reply, so the
// row shows the day before it as the last day (see vacationOf).
//
// arch: DS9.7, S9-GAP7
func vacationRow(v gmail.Vacation) *VacationRow {
	row := &VacationRow{
		Enabled: v.Enabled,
		Subject: fenceIf("VACATION", v.Subject),
		Body:    fenceIf("VACATION", v.Body),
	}
	if !v.Start.IsZero() {
		row.Start = v.Start.In(time.Local).Format(dayLayout)
	}
	if !v.End.IsZero() {
		row.End = v.End.Add(-time.Millisecond).In(time.Local).Format(dayLayout)
	}
	return row
}

// vacationOf gives the vacation of a set_vacation call over cur, the
// setting that Gmail holds now. A field that the call does not give
// keeps its value in cur, so "vacation off" keeps the stored reply
// (R16-L7). A date is a day in the local zone of the host (S9-GAP7):
// Start is the first instant of its day, and End, the last day,
// becomes the first instant of the day after it, so the reply runs
// through the whole last day. An end before the start is an error.
//
// arch: DS9.7, S9-GAP7, R16-L7
func vacationOf(in GmailSettingsIn, cur gmail.Vacation) (gmail.Vacation, error) {
	v := cur
	v.Enabled = *in.Enabled
	if in.Subject != "" {
		v.Subject = in.Subject
	}
	if in.Body != "" {
		v.Body = in.Body
	}
	if in.Start != "" {
		d, err := time.ParseInLocation(dayLayout, in.Start, time.Local)
		if err != nil {
			return gmail.Vacation{}, fmt.Errorf("gmail_settings: start %q is not a date of the form YYYY-MM-DD", in.Start)
		}
		v.Start = d
	}
	if in.End != "" {
		d, err := time.ParseInLocation(dayLayout, in.End, time.Local)
		if err != nil {
			return gmail.Vacation{}, fmt.Errorf("gmail_settings: end %q is not a date of the form YYYY-MM-DD", in.End)
		}
		v.End = d.AddDate(0, 0, 1)
	}
	if !v.Start.IsZero() && !v.End.IsZero() && !v.Start.Before(v.End) {
		return gmail.Vacation{}, errors.New("gmail_settings: end is before start")
	}
	return v, nil
}
