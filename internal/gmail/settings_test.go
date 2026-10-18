// SPDX-FileCopyrightText: 2026 Ann <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Gmail settings (DS9.7) against fakeGmail: a filter has
// no forward field, a filter that adds TRASH or SPAM is refused after
// the name-to-id step, a user label named "Trash" passes, the
// signature goes HTML-escaped on the wire and comes back as the plain
// text, and the vacation times go as ms since the epoch (S9-GAP6).

package gmail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// filterRoutes gives a route with the labels of the fixtures, a
// settings/filters.create that gives the request back with the id
// "F1", and a settings/filters.list that gives list.
func filterRoutes(t *testing.T, list string) func(r *http.Request) step {
	t.Helper()
	m := labelRoutes(t)
	m["GET settings/filters"] = step{status: 200, body: list}
	base := routes(m)
	return func(r *http.Request) step {
		if r.Method == http.MethodPost && r.URL.Path == apiPrefix+"settings/filters" {
			b, _ := io.ReadAll(r.Body)
			var w map[string]any
			if err := json.Unmarshal(b, &w); err != nil {
				return step{status: 400, body: googleError(400, "INVALID_ARGUMENT", "invalidArgument", "", "bad json")}
			}
			w["id"] = "F1"
			out, _ := json.Marshal(w)
			return step{status: 200, body: string(out)}
		}
		return base(r)
	}
}

// filterPosts gives the bodies of the settings/filters.create calls.
func filterPosts(f *fakeGmail) [][]byte {
	var out [][]byte
	for _, r := range f.requests() {
		if r.Method == http.MethodPost && r.Path == apiPrefix+"settings/filters" {
			out = append(out, r.Body)
		}
	}
	return out
}

// TestGmailSettings_NoForwardField holds IS9.7: no type of a filter has
// a forward field, a create request has no forward key, and a forward
// in a server answer does not reach the Filter.
//
// arch: DS9.1, DS9.7, IS9.7
func TestGmailSettings_NoForwardField(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[Filter](), reflect.TypeFor[wireFilter](),
		reflect.TypeFor[wireCriteria](), reflect.TypeFor[wireAction](),
	} {
		for i := range typ.NumField() {
			fld := typ.Field(i)
			if strings.Contains(strings.ToLower(fld.Name+" "+fld.Tag.Get("json")), "forward") {
				t.Errorf("%s has the field %s %q: a filter must not forward", typ, fld.Name, fld.Tag)
			}
		}
	}

	list := `{"filter":[{"id":"F9","criteria":{"from":"a@example.com"},` +
		`"action":{"addLabelIds":["Label_1"],"forward":"evil@example.com"}}]}`
	f := newFakeGmailRoutes(t, filterRoutes(t, list))
	p, _ := f.provider(nil)
	ctx := context.Background()

	yes := true
	got, err := p.CreateFilter(ctx, Filter{From: "b@example.com", HasAttachment: &yes, AddLabels: []string{"Receipts"}, MarkRead: true})
	if err != nil {
		t.Fatalf("CreateFilter: %v", err)
	}
	posts := filterPosts(f)
	if len(posts) != 1 {
		t.Fatalf("got %d create calls, want 1", len(posts))
	}
	if strings.Contains(strings.ToLower(string(posts[0])), "forward") {
		t.Fatalf("the create request has a forward key: %s", posts[0])
	}
	var sent wireFilter
	if err := json.Unmarshal(posts[0], &sent); err != nil {
		t.Fatalf("decode the request: %v", err)
	}
	want := wireAction{AddLabelIDs: []string{"Label_1"}, RemoveLabelIDs: []string{"UNREAD"}}
	if !reflect.DeepEqual(sent.Action, want) {
		t.Fatalf("the action on the wire = %+v, want %+v", sent.Action, want)
	}
	if got.ID != "F1" || !slices.Equal(got.AddLabels, []string{"Receipts"}) || !got.MarkRead {
		t.Fatalf("CreateFilter gave %+v", got)
	}

	filters, err := p.ListFilters(ctx)
	if err != nil {
		t.Fatalf("ListFilters: %v", err)
	}
	if len(filters) != 1 || filters[0].ID != "F9" || !slices.Equal(filters[0].AddLabels, []string{"Receipts"}) {
		t.Fatalf("ListFilters gave %+v", filters)
	}
	again, err := json.Marshal(wireFilter{Action: wireAction{AddLabelIDs: []string{"Label_1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(again), "forward") {
		t.Fatalf("a wire filter encodes a forward key: %s", again)
	}
}

// TestGmailSettings_FilterRefusesTrashSpam holds E5 and IS9.7: a filter
// that adds TRASH or SPAM, by id or by a name that maps to the system
// label, is refused after the name-to-id step and sends no create
// call. A filter that removes SPAM ("never send it to spam") passes.
//
// arch: DS9.1, DS9.7, IS9.7
func TestGmailSettings_FilterRefusesTrashSpam(t *testing.T) {
	ctx := context.Background()
	for _, add := range [][]string{
		{"TRASH"},
		{"SPAM"},
		{"spam"}, // no user label has this name: it maps to SPAM
		{"Receipts", "SPAM"},
		{"Label_1", "TRASH"},
	} {
		t.Run(strings.Join(add, ","), func(t *testing.T) {
			f := newFakeGmailRoutes(t, filterRoutes(t, `{}`))
			p, _ := f.provider(nil)
			_, err := p.CreateFilter(ctx, Filter{From: "x@example.com", AddLabels: add})
			if !errors.Is(err, errFilterTrashSpam) {
				t.Fatalf("CreateFilter(add %q) = %v, want errFilterTrashSpam", add, err)
			}
			if n := len(filterPosts(f)); n != 0 {
				t.Fatalf("a refused filter sent %d create calls", n)
			}
		})
	}

	f := newFakeGmailRoutes(t, filterRoutes(t, `{}`))
	p, _ := f.provider(nil)
	if _, err := p.CreateFilter(ctx, Filter{From: "x@example.com", RemoveLabels: []string{"SPAM"}}); err != nil {
		t.Fatalf("CreateFilter(remove SPAM): %v", err)
	}
	posts := filterPosts(f)
	if len(posts) != 1 {
		t.Fatalf("got %d create calls, want 1", len(posts))
	}
	var sent wireFilter
	if err := json.Unmarshal(posts[0], &sent); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sent.Action.RemoveLabelIDs, []string{"SPAM"}) || len(sent.Action.AddLabelIDs) != 0 {
		t.Fatalf("the action on the wire = %+v", sent.Action)
	}
}

// TestGmailSettings_LabelNamedTrash holds E5: the user label "Trash"
// (Label_3 in the fixture) maps to its own id in any case and passes;
// the filter adds Label_3, never TRASH.
//
// arch: DS9.1, DS9.7, IS9.7
func TestGmailSettings_LabelNamedTrash(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"Trash", "trash"} {
		t.Run(name, func(t *testing.T) {
			f := newFakeGmailRoutes(t, filterRoutes(t, `{}`))
			p, _ := f.provider(nil)
			got, err := p.CreateFilter(ctx, Filter{Subject: "old", AddLabels: []string{name}, Star: true})
			if err != nil {
				t.Fatalf("CreateFilter(add %q): %v", name, err)
			}
			posts := filterPosts(f)
			if len(posts) != 1 {
				t.Fatalf("got %d create calls, want 1", len(posts))
			}
			var sent wireFilter
			if err := json.Unmarshal(posts[0], &sent); err != nil {
				t.Fatal(err)
			}
			if want := []string{"Label_3", "STARRED"}; !slices.Equal(sent.Action.AddLabelIDs, want) {
				t.Fatalf("addLabelIds = %q, want %q", sent.Action.AddLabelIDs, want)
			}
			if !slices.Equal(got.AddLabels, []string{"Trash"}) || !got.Star {
				t.Fatalf("CreateFilter gave %+v", got)
			}
		})
	}
}

// sigServer is a fake settings/sendAs: it keeps the signature of each
// address that a PATCH writes and gives it on GET.
type sigServer struct {
	mu  sync.Mutex
	sig map[string]string
}

func (s *sigServer) route(r *http.Request) step {
	rest, ok := strings.CutPrefix(r.URL.Path, apiPrefix+"settings/sendAs")
	if !ok {
		return step{status: 404, body: googleError(404, "NOT_FOUND", "notFound", "", "not found")}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	addr := strings.TrimPrefix(rest, "/")
	switch {
	case addr == "" && r.Method == http.MethodGet:
		return step{status: 200, body: `{"sendAs":[{"sendAsEmail":"alias@example.com","verificationStatus":"accepted"},` +
			`{"sendAsEmail":"me@example.com","isPrimary":true}]}`}
	case r.Method == http.MethodPatch:
		var b struct {
			Signature string `json:"signature"`
		}
		data, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(data, &b); err != nil {
			return step{status: 400, body: googleError(400, "INVALID_ARGUMENT", "invalidArgument", "", "bad json")}
		}
		s.sig[addr] = b.Signature
		out, _ := json.Marshal(map[string]string{"sendAsEmail": addr, "signature": b.Signature})
		return step{status: 200, body: string(out)}
	case r.Method == http.MethodGet:
		out, _ := json.Marshal(map[string]string{"sendAsEmail": addr, "signature": s.sig[addr]})
		return step{status: 200, body: string(out)}
	}
	return step{status: 405, body: googleError(405, "", "", "", "method")}
}

// TestGmailSettings_SignatureRoundTrip holds DS9.7: the signature goes
// to settings/sendAs/{sendAs} HTML-escaped, with <br> for a line
// break, and comes back as the text the person wrote. An empty sendAs
// is the primary address. HTML that another client wrote gives its
// text.
//
// arch: DS9.1, DS9.7, IS9.7
func TestGmailSettings_SignatureRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := &sigServer{sig: map[string]string{"other@example.com": "<div>Hi <b>there</b></div>"}}
	f := newFakeGmailRoutes(t, s.route)
	p, _ := f.provider(nil)

	text := "Ann <b>not bold</b>\nTel: \"+1\" & co\n\n-- \nfoot's <script>x</script>"
	if err := p.SetSignature(ctx, "", text); err != nil {
		t.Fatalf("SetSignature: %v", err)
	}
	s.mu.Lock()
	wire, ok := s.sig["me@example.com"]
	s.mu.Unlock()
	if !ok {
		t.Fatalf("an empty sendAs did not write the primary address; wrote %v", s.sig)
	}
	for _, bad := range []string{"<b>", "<script>", "\n", `"+1"`} {
		if strings.Contains(wire, bad) {
			t.Fatalf("the wire signature %q holds %q: it is not escaped", wire, bad)
		}
	}
	if !strings.Contains(wire, "&lt;b&gt;") || strings.Count(wire, "<br>") != 4 {
		t.Fatalf("the wire signature = %q", wire)
	}
	got, err := p.Signature(ctx, "")
	if err != nil {
		t.Fatalf("Signature: %v", err)
	}
	if got != text {
		t.Fatalf("Signature = %q, want %q", got, text)
	}

	if err := p.SetSignature(ctx, "alias@example.com", "A & B"); err != nil {
		t.Fatalf("SetSignature(alias): %v", err)
	}
	if got, err := p.Signature(ctx, "alias@example.com"); err != nil || got != "A & B" {
		t.Fatalf("Signature(alias) = %q, %v", got, err)
	}
	if got, err := p.Signature(ctx, "other@example.com"); err != nil || got != "Hi there" {
		t.Fatalf("Signature(HTML) = %q, %v; want %q", got, err, "Hi there")
	}
	for _, r := range f.requests() {
		if r.Method == http.MethodPatch && !strings.HasPrefix(r.Path, apiPrefix+"settings/sendAs/") {
			t.Fatalf("a PATCH went to %s", r.Path)
		}
	}
}

// TestGmailSettings_VacationMillis holds DS9.7: the vacation times go
// as ms since the epoch with PUT, a zero time sends none, the answer's
// ms (a string or a number) come back as times, and a write keeps
// restrictToContacts.
//
// arch: DS9.1, DS9.7
func TestGmailSettings_VacationMillis(t *testing.T) {
	ctx := context.Background()
	f := newFakeGmailRoutes(t, func(r *http.Request) step {
		switch r.Method {
		case http.MethodGet:
			return step{status: 200, body: `{"enableAutoReply":true,"responseSubject":"Away",` +
				`"responseBodyPlainText":"Back soon","restrictToContacts":true,` +
				`"startTime":"1760000000000","endTime":1760086400000}`}
		case http.MethodPut:
			return step{status: 200, body: `{}`}
		}
		return step{status: 405, body: `{}`}
	})
	p, _ := f.provider(nil)

	v, err := p.Vacation(ctx)
	if err != nil {
		t.Fatalf("Vacation: %v", err)
	}
	if !v.Enabled || v.Subject != "Away" || v.Body != "Back soon" ||
		v.Start.UnixMilli() != 1760000000000 || v.End.UnixMilli() != 1760086400000 {
		t.Fatalf("Vacation = %+v", v)
	}

	start := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if err := p.SetVacation(ctx, Vacation{Enabled: true, Body: "Out", Start: start}); err != nil {
		t.Fatalf("SetVacation: %v", err)
	}
	var put []byte
	for _, r := range f.requests() {
		if r.Method == http.MethodPut {
			if r.Path != apiPrefix+"settings/vacation" {
				t.Fatalf("the PUT went to %s", r.Path)
			}
			put = r.Body
		}
	}
	var sent map[string]any
	if err := json.Unmarshal(put, &sent); err != nil {
		t.Fatalf("decode the PUT %q: %v", put, err)
	}
	want := map[string]any{
		"enableAutoReply":       true,
		"responseBodyPlainText": "Out",
		"restrictToContacts":    true,
		"startTime":             "1792454400000",
	}
	if !reflect.DeepEqual(sent, want) {
		t.Fatalf("the PUT body = %v, want %v", sent, want)
	}
}
