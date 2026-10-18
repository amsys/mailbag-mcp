// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The Gmail settings of the gmail_settings tool (DS9.7). This file
// holds the Settings interface, which only the Gmail provider has, and
// its calls to settings/filters, settings/vacation and
// settings/sendAs. A filter has no forward field on the wire, so a
// filter can never forward (IS9.7). The label names of a filter become
// ids first, and TRASH and SPAM are then refused (E5).
//
// arch: DS9.1, DS9.7, IS9.7

package gmail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mime"
)

// Settings is the optional interface of §3.7. Only the Gmail provider
// has it; the tool uses a type assertion and a compile-time check
// (DS9.7).
type Settings interface {
	ListFilters(ctx context.Context) ([]Filter, error)
	CreateFilter(ctx context.Context, f Filter) (Filter, error)
	DeleteFilter(ctx context.Context, id string) error
	Vacation(ctx context.Context) (Vacation, error)
	SetVacation(ctx context.Context, v Vacation) error
	Signature(ctx context.Context, sendAs string) (string, error)
	SetSignature(ctx context.Context, sendAs, text string) error
}

// Filter is one Gmail filter. It has criteria and label changes only;
// it has no forward field (IS9.7).
type Filter struct {
	ID                       string
	From, To, Subject, Query string
	HasAttachment            *bool
	AddLabels                []string // names in the tool; ids on the wire
	RemoveLabels             []string
	MarkRead                 bool // removeLabelIds UNREAD
	Star                     bool // addLabelIds STARRED
}

// Vacation is the auto-reply of the account (DS9.7).
type Vacation struct {
	Enabled bool
	Body    string    // responseBodyPlainText
	Subject string    // responseSubject
	Start   time.Time // startTime ms; zero = none
	End     time.Time // endTime ms; zero = none
}

var _ Settings = (*Provider)(nil)

// wireFilter is the filter resource on the wire. It holds the criteria
// and the label ids only. There is no forward field, so no request can
// set one and an answer that has one loses it (IS9.7).
type wireFilter struct {
	ID       string       `json:"id,omitempty"`
	Criteria wireCriteria `json:"criteria"`
	Action   wireAction   `json:"action"`
}

// wireCriteria is the criteria object of a filter.
type wireCriteria struct {
	From          string `json:"from,omitempty"`
	To            string `json:"to,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Query         string `json:"query,omitempty"`
	HasAttachment *bool  `json:"hasAttachment,omitempty"`
}

// wireAction is the action object of a filter: label ids only.
type wireAction struct {
	AddLabelIDs    []string `json:"addLabelIds,omitempty"`
	RemoveLabelIDs []string `json:"removeLabelIds,omitempty"`
}

// errFilterTrashSpam is the fixed text of a filter that adds TRASH or
// SPAM (E5, IS9.7). Such a filter would hide mail with no undo.
var errFilterTrashSpam = errors.New("gmail: a filter cannot add the system label TRASH or SPAM")

// errFilterEmpty is the fixed text of a filter with no criteria. Gmail
// refuses it, and it would match each new message.
var errFilterEmpty = errors.New("gmail: a filter needs at least one of from, to, subject, query or has_attachment")

// ListFilters gives the filters of the account (DS9.7). The label ids
// become names through the label list; an id that the list does not
// have stays an id. UNREAD in removeLabelIds gives MarkRead and
// STARRED in addLabelIds gives Star.
//
// arch: DS9.7, IS9.7
func (p *Provider) ListFilters(ctx context.Context) ([]Filter, error) {
	var ans struct {
		Filter []wireFilter `json:"filter"`
	}
	if err := p.api.Get(ctx, "settings/filters", nil, &ans); err != nil {
		return nil, err
	}
	if len(ans.Filter) == 0 {
		return nil, nil
	}
	tab, err := p.cachedLabels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Filter, 0, len(ans.Filter))
	for _, w := range ans.Filter {
		out = append(out, filterOf(w, tab))
	}
	return out, nil
}

// filterOf gives the Filter of a wire filter, with label names from
// tab.
func filterOf(w wireFilter, tab *labelTable) Filter {
	f := Filter{
		ID:            w.ID,
		From:          w.Criteria.From,
		To:            w.Criteria.To,
		Subject:       w.Criteria.Subject,
		Query:         w.Criteria.Query,
		HasAttachment: w.Criteria.HasAttachment,
	}
	name := func(id string) string {
		if n, ok := tab.byID[id]; ok {
			return n
		}
		return id
	}
	for _, id := range w.Action.AddLabelIDs {
		if id == labelStarred {
			f.Star = true
			continue
		}
		f.AddLabels = append(f.AddLabels, name(id))
	}
	for _, id := range w.Action.RemoveLabelIDs {
		if id == labelUnread {
			f.MarkRead = true
			continue
		}
		f.RemoveLabels = append(f.RemoveLabels, name(id))
	}
	return f
}

// CreateFilter makes the filter f with settings/filters.create and
// gives it as the server stored it (DS9.7). Each label name becomes an
// id first, as in resolveLabel: an id, or a name in any case, where a
// user label wins over a system label. A name that the account does
// not have is an error that lists the labels; no label is created.
// After that step an added TRASH or SPAM is refused, so a user label
// named "Trash" passes (E5). A removed SPAM is allowed: that is "never
// send it to spam". The request has no forward field (IS9.7).
//
// arch: DS9.7, IS9.7, E5
func (p *Provider) CreateFilter(ctx context.Context, f Filter) (Filter, error) {
	crit := wireCriteria{
		From:          f.From,
		To:            f.To,
		Subject:       f.Subject,
		Query:         f.Query,
		HasAttachment: f.HasAttachment,
	}
	if crit == (wireCriteria{}) {
		return Filter{}, errFilterEmpty
	}
	tab, err := p.cachedLabels(ctx)
	if err != nil {
		return Filter{}, err
	}
	var act wireAction
	if act.AddLabelIDs, tab, err = p.filterLabelIDs(ctx, tab, f.AddLabels); err != nil {
		return Filter{}, err
	}
	if act.RemoveLabelIDs, tab, err = p.filterLabelIDs(ctx, tab, f.RemoveLabels); err != nil {
		return Filter{}, err
	}
	for _, id := range act.AddLabelIDs {
		if id == labelTrash || id == labelSpam {
			return Filter{}, errFilterTrashSpam
		}
	}
	if f.Star {
		act.AddLabelIDs = appendNew(act.AddLabelIDs, labelStarred)
	}
	if f.MarkRead {
		act.RemoveLabelIDs = appendNew(act.RemoveLabelIDs, labelUnread)
	}
	if len(act.AddLabelIDs) == 0 && len(act.RemoveLabelIDs) == 0 {
		return Filter{}, errors.New("gmail: a filter needs at least one action: add_labels, remove_labels, mark_read or star")
	}
	var got wireFilter
	if err := p.api.Post(ctx, "settings/filters", nil, wireFilter{Criteria: crit, Action: act}, &got); err != nil {
		return Filter{}, err
	}
	return filterOf(got, tab), nil
}

// filterLabelIDs gives the label ids of names, without a repeat. It
// creates no label. It gives the table that it used last.
func (p *Provider) filterLabelIDs(ctx context.Context, tab *labelTable, names []string) ([]string, *labelTable, error) {
	var ids []string
	for _, n := range names {
		id, t, err := p.resolveLabel(ctx, tab, n, false)
		if err != nil {
			return nil, nil, err
		}
		tab = t
		ids = appendNew(ids, id)
	}
	return ids, tab, nil
}

// appendNew appends s to list when list does not hold it.
func appendNew(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// DeleteFilter removes the filter id with settings/filters.delete
// (DS9.7).
//
// arch: DS9.7
func (p *Provider) DeleteFilter(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("gmail: a filter id is empty")
	}
	return p.api.Delete(ctx, "settings/filters/"+url.PathEscape(id))
}

// epochMS is a time in ms since the epoch. Google sends an int64 as a
// JSON string; a number is read too. 0 or no value is no time.
type epochMS int64

// MarshalJSON gives the ms as a JSON string, as Google sends an int64.
func (m epochMS) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(strconv.FormatInt(int64(m), 10))), nil
}

// UnmarshalJSON reads a JSON string or a JSON number.
func (m *epochMS) UnmarshalJSON(b []byte) error {
	s := string(bytes.Trim(b, `"`))
	if s == "" || s == "null" {
		*m = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("gmail: a time in ms is not a number: %w", err)
	}
	*m = epochMS(n)
	return nil
}

// msOf gives the ms of t; the zero time gives 0.
func msOf(t time.Time) epochMS {
	if t.IsZero() {
		return 0
	}
	return epochMS(t.UnixMilli())
}

// timeOf gives the time of ms; 0 gives the zero time.
func timeOf(ms epochMS) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(ms))
}

// wireVacation is the vacation resource on the wire. Gmail uses
// responseBodyHtml before the plain text when both are set, so a write
// sends no HTML body.
type wireVacation struct {
	EnableAutoReply       bool    `json:"enableAutoReply"`
	ResponseSubject       string  `json:"responseSubject,omitempty"`
	ResponseBodyPlainText string  `json:"responseBodyPlainText,omitempty"`
	ResponseBodyHTML      string  `json:"responseBodyHtml,omitempty"`
	RestrictToContacts    bool    `json:"restrictToContacts,omitempty"`
	RestrictToDomain      bool    `json:"restrictToDomain,omitempty"`
	StartTime             epochMS `json:"startTime,omitempty"`
	EndTime               epochMS `json:"endTime,omitempty"`
}

// Vacation gives the auto-reply of the account (DS9.7). When the
// server has an HTML body only, Body is its text.
//
// arch: DS9.7
func (p *Provider) Vacation(ctx context.Context) (Vacation, error) {
	var w wireVacation
	if err := p.api.Get(ctx, "settings/vacation", nil, &w); err != nil {
		return Vacation{}, err
	}
	body := w.ResponseBodyPlainText
	if body == "" && w.ResponseBodyHTML != "" {
		body = mime.HTMLToText(w.ResponseBodyHTML)
	}
	return Vacation{
		Enabled: w.EnableAutoReply,
		Body:    body,
		Subject: w.ResponseSubject,
		Start:   timeOf(w.StartTime),
		End:     timeOf(w.EndTime),
	}, nil
}

// SetVacation writes the auto-reply v with settings/updateVacation, a
// PUT that replaces the whole resource (DS9.7). It reads the resource
// first and keeps restrictToContacts and restrictToDomain, which v
// does not hold, so a write never sends the reply to more people. The
// times go as ms since the epoch; a zero time sends none.
//
// arch: DS9.7
func (p *Provider) SetVacation(ctx context.Context, v Vacation) error {
	var cur wireVacation
	if err := p.api.Get(ctx, "settings/vacation", nil, &cur); err != nil {
		return err
	}
	w := wireVacation{
		EnableAutoReply:       v.Enabled,
		ResponseSubject:       v.Subject,
		ResponseBodyPlainText: v.Body,
		RestrictToContacts:    cur.RestrictToContacts,
		RestrictToDomain:      cur.RestrictToDomain,
		StartTime:             msOf(v.Start),
		EndTime:               msOf(v.End),
	}
	// The API client has no Put; updateVacation takes PUT only.
	const path = "settings/vacation"
	c, err := jsonCall(http.MethodPut, path, join(p.api.base, path, nil), w)
	if err != nil {
		return err
	}
	return p.api.do(ctx, c, nil)
}

// primarySendAs gives the primary address from settings/sendAs.
func (p *Provider) primarySendAs(ctx context.Context) (string, error) {
	var ans struct {
		SendAs []struct {
			SendAsEmail string `json:"sendAsEmail"`
			IsPrimary   bool   `json:"isPrimary"`
		} `json:"sendAs"`
	}
	if err := p.api.Get(ctx, "settings/sendAs", nil, &ans); err != nil {
		return "", err
	}
	for _, s := range ans.SendAs {
		if s.IsPrimary && s.SendAsEmail != "" {
			return s.SendAsEmail, nil
		}
	}
	return "", errors.New("gmail: the account has no primary send-as address")
}

// sendAsPath gives the path of the send-as address sendAs; an empty
// sendAs gives the primary address.
func (p *Provider) sendAsPath(ctx context.Context, sendAs string) (string, error) {
	if strings.TrimSpace(sendAs) == "" {
		var err error
		if sendAs, err = p.primarySendAs(ctx); err != nil {
			return "", err
		}
	}
	return "settings/sendAs/" + url.PathEscape(sendAs), nil
}

// Signature gives the signature of the send-as address sendAs (the
// primary address when empty) as plain text (DS9.7). A signature that
// SetSignature wrote comes back as the same text. Other HTML gives its
// text.
//
// arch: DS9.7
func (p *Provider) Signature(ctx context.Context, sendAs string) (string, error) {
	path, err := p.sendAsPath(ctx, sendAs)
	if err != nil {
		return "", err
	}
	var ans struct {
		Signature string `json:"signature"`
	}
	if err := p.api.Get(ctx, path, nil, &ans); err != nil {
		return "", err
	}
	return signatureText(ans.Signature), nil
}

// SetSignature writes text as the signature of the send-as address
// sendAs (the primary address when empty) with settings/sendAs.patch
// (DS9.7). The text is HTML-escaped and each line break is <br>, so
// the person sees the text as written and no markup of the text runs.
//
// arch: DS9.7
func (p *Provider) SetSignature(ctx context.Context, sendAs, text string) error {
	path, err := p.sendAsPath(ctx, sendAs)
	if err != nil {
		return err
	}
	return p.api.Patch(ctx, path, map[string]string{"signature": signatureHTML(text)}, nil)
}

// signatureHTML gives the wire form of a plain-text signature.
func signatureHTML(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.ReplaceAll(html.EscapeString(text), "\n", "<br>")
}

// signatureText gives the plain text of a wire signature. A value in
// the form of signatureHTML gives its text back exactly; other HTML
// goes through mime.HTMLToText.
func signatureText(s string) string {
	text := html.UnescapeString(strings.ReplaceAll(s, "<br>", "\n"))
	if signatureHTML(text) == s {
		return text
	}
	return mime.HTMLToText(s)
}
