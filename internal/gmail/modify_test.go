// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Tests of the Gmail writes on labels against a fake mailbox with state
// (DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5): the map from a label name to
// its id, the creation of a missing label, Modify with its read before
// the change and its batchModify chunks, the undo of a move through
// the label difference, the folder writes and the capability lines.

package gmail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// writerMethods is the write half of tools.Writer. The tools package
// imports this package, so a test here cannot name tools.Writer; this
// copy makes the build fail when a method of the contract is missing.
type writerMethods interface {
	Modify(ctx context.Context, ids []string, c mail.Change) ([]mail.Applied, error)
	ModifyDetail(ctx context.Context, ids []string, c mail.Change) (mail.ModifyResult, error)
	CreateFolder(ctx context.Context, name string) error
	RenameFolder(ctx context.Context, from, to string) error
	DeleteFolder(ctx context.Context, name string) error
	Caps(ctx context.Context) (mail.Caps, error)
}

var _ writerMethods = (*Provider)(nil)

// mailState is the state of the fake mailbox: the labels of the
// account and the labelIds of each message. It applies labels.create
// and messages.batchModify as Gmail does, so a test can read the state
// after a change and undo it.
type mailState struct {
	t           *testing.T
	mu          sync.Mutex
	labels      []label
	msgs        map[string][]string // message id to labelIds
	next        int                 // number of the next Label_<n>
	batches     [][]string          // the ids of each batchModify call
	inflight    int                 // messages.get calls that run now
	maxInflight int
	getDelay    time.Duration // the time each messages.get call takes
	// raced is a label name that a second client creates just before
	// the provider writes it, so the write gets the 409 of Gmail.
	raced string
}

// takenBy gives the id of a label other than self with name in any
// case, as Gmail checks a new label name. The caller holds s.mu.
func (s *mailState) takenBy(name, self string) (string, bool) {
	if name == s.raced {
		s.labels = append(s.labels, label{ID: fmt.Sprintf("Label_%d", s.next), Name: name, Type: "user"})
		s.next++
		s.raced = ""
	}
	for _, l := range s.labels {
		if l.ID != self && strings.EqualFold(l.Name, name) {
			return l.ID, true
		}
	}
	return "", false
}

// conflict is the answer of Gmail to a label name that a label has.
func conflict() step {
	return step{status: 409, body: googleError(409, "ALREADY_EXISTS", "duplicate", "", "Label name exists or conflicts")}
}

// The fake uses jsonStep, notFound and count of drafts_test.go.

// newMailFake starts a fake mailbox with the labels of
// labels.list.json and the messages msgs.
func newMailFake(t *testing.T, msgs map[string][]string) (*fakeGmail, *mailState) {
	t.Helper()
	var ans struct {
		Labels []label `json:"labels"`
	}
	if err := json.Unmarshal([]byte(fixture(t, "labels.list.json")), &ans); err != nil {
		t.Fatalf("labels.list.json: %v", err)
	}
	st := &mailState{t: t, labels: ans.Labels, msgs: msgs, next: 100}
	return newFakeGmailRoutes(t, st.route), st
}

func (s *mailState) route(r *http.Request) step {
	path := strings.TrimPrefix(r.URL.Path, apiPrefix)
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodGet && path == "labels":
		s.mu.Lock()
		defer s.mu.Unlock()
		return jsonStep(map[string]any{"labels": s.labels})
	case r.Method == http.MethodPost && path == "labels":
		var in struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &in); err != nil || in.Name == "" {
			return step{status: 400, body: googleError(400, "INVALID_ARGUMENT", "invalidArgument", "", "bad label")}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, taken := s.takenBy(in.Name, ""); taken {
			return conflict()
		}
		l := label{ID: fmt.Sprintf("Label_%d", s.next), Name: in.Name, Type: "user"}
		s.next++
		s.labels = append(s.labels, l)
		return jsonStep(l)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "labels/"):
		var in struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(body, &in)
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, taken := s.takenBy(in.Name, strings.TrimPrefix(path, "labels/")); taken {
			return conflict()
		}
		return step{status: 204}
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "labels/"):
		return step{status: 204}
	case r.Method == http.MethodGet && path == "settings/sendAs":
		return step{status: 200, body: fixture(s.t, "sendAs.list.json")}
	case r.Method == http.MethodPost && path == "messages/batchModify":
		var in struct {
			IDs    []string `json:"ids"`
			Add    []string `json:"addLabelIds"`
			Remove []string `json:"removeLabelIds"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			return step{status: 400, body: googleError(400, "INVALID_ARGUMENT", "invalidArgument", "", "bad body")}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.batches = append(s.batches, in.IDs)
		// The fake applies the change by its own code, not by the
		// labelDelta of the provider under test.
		for _, id := range in.IDs {
			var next []string
			for _, l := range s.msgs[id] {
				if !slices.Contains(in.Remove, l) {
					next = append(next, l)
				}
			}
			for _, l := range in.Add {
				if !slices.Contains(next, l) {
					next = append(next, l)
				}
			}
			s.msgs[id] = next
		}
		return step{status: 204}
	case r.Method == http.MethodGet && strings.HasPrefix(path, "messages/"):
		id := strings.TrimPrefix(path, "messages/")
		s.mu.Lock()
		s.inflight++
		s.maxInflight = max(s.maxInflight, s.inflight)
		s.mu.Unlock()
		time.Sleep(s.getDelay)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.inflight--
		ids, ok := s.msgs[id]
		if !ok {
			return notFound()
		}
		return jsonStep(map[string]any{"id": id, "threadId": id, "labelIds": ids})
	}
	return notFound()
}

// labelsOf gives a copy of the labelIds of the message id.
func (s *mailState) labelsOf(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.msgs[id])
}

// setLabels sets the labelIds of the message id, as a change by Gmail
// or by another client.
func (s *mailState) setLabels(id string, ids ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs[id] = ids
}

// batchBodies gives the decoded bodies of the batchModify requests.
func batchBodies(t *testing.T, f *fakeGmail) []map[string][]string {
	t.Helper()
	var out []map[string][]string
	for _, r := range f.requests() {
		if r.Method != http.MethodPost || strings.TrimPrefix(r.Path, apiPrefix) != "messages/batchModify" {
			continue
		}
		var b map[string][]string
		if err := json.Unmarshal(r.Body, &b); err != nil {
			t.Fatalf("batchModify body %s: %v", r.Body, err)
		}
		out = append(out, b)
	}
	return out
}

// writes gives the requests that change labels: POST, PATCH and DELETE.
func writes(f *fakeGmail) []fakeReq {
	var out []fakeReq
	for _, r := range f.requests() {
		if r.Method != http.MethodGet {
			out = append(out, r)
		}
	}
	return out
}

func ptr[T any](v T) *T { return &v }

// TestGmail_LabelNameToID holds DS7.4a: a label name matches with no
// regard to case, a known label id is the id, and Modify sends the ids
// of the names in batchModify. One labels.list call serves all the
// names of one call.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_LabelNameToID(t *testing.T) {
	f, _ := newMailFake(t, map[string][]string{"m1": {"INBOX", "Label_2"}})
	p, _ := f.provider(nil)
	ctx := context.Background()
	tab, err := p.listLabels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"receipts":       "Label_1",
		"RECEIPTS":       "Label_1",
		"PROJECTS/alpha": "Label_2",
		"Label_2":        "Label_2",
		"INBOX":          "INBOX",
		"inbox":          "INBOX",
		"Starred":        "STARRED",
	} {
		got, _, err := p.resolveLabel(ctx, tab, name, false)
		if err != nil || got != want {
			t.Errorf("resolveLabel(%q) = %q, %v; want %q", name, got, err, want)
		}
	}

	p2, _ := f.provider(nil)
	before := count(f, http.MethodGet, apiPrefix+"labels")
	_, err = p2.Modify(ctx, []string{"m1"}, mail.Change{AddLabels: []string{"receipts"}, RemoveLabels: []string{"projects/ALPHA"}})
	if err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if n := count(f, http.MethodGet, apiPrefix+"labels") - before; n != 1 {
		t.Errorf("labels.list calls = %d, want 1", n)
	}
	got := batchBodies(t, f)
	want := []map[string][]string{{"ids": {"m1"}, "addLabelIds": {"Label_1"}, "removeLabelIds": {"Label_2"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("batchModify bodies = %v, want %v", got, want)
	}
}

// TestGmail_LabelNamedTrashIsNotSystem holds E5: a user label named
// "Trash" maps to its own id and never to TRASH, and the check for a
// system label runs on the id, so that label can be deleted while
// TRASH cannot.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_LabelNamedTrashIsNotSystem(t *testing.T) {
	f, st := newMailFake(t, map[string][]string{"m1": {"INBOX"}})
	p, _ := f.provider(nil)
	ctx := context.Background()
	tab, err := p.listLabels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"Trash": "Label_3", "trash": "Label_3", "TRASH": "TRASH"} {
		got, _, err := p.resolveLabel(ctx, tab, name, false)
		if err != nil || got != want {
			t.Errorf("resolveLabel(%q) = %q, %v; want %q", name, got, err, want)
		}
	}

	res, err := p.Modify(ctx, []string{"m1"}, mail.Change{AddLabels: []string{"Trash"}})
	if err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if got := st.labelsOf("m1"); !reflect.DeepEqual(got, []string{"INBOX", "Label_3"}) {
		t.Errorf("labels after = %v, want [INBOX Label_3]", got)
	}
	if len(res) != 1 || !reflect.DeepEqual(res[0].After.Labels, []string{"INBOX", "Label_3"}) {
		t.Errorf("Applied = %+v, want After.Labels [INBOX Label_3]", res)
	}

	if err := p.DeleteFolder(ctx, "TRASH"); !errors.Is(err, errSystemLabel) {
		t.Errorf("DeleteFolder(TRASH) = %v, want errSystemLabel", err)
	}
	if err := p.DeleteFolder(ctx, "Trash"); err != nil {
		t.Fatalf("DeleteFolder(Trash): %v", err)
	}
	if n := count(f, http.MethodDelete, apiPrefix+"labels/Label_3"); n != 1 {
		t.Errorf("DELETE labels/Label_3 calls = %d, want 1", n)
	}
	if n := count(f, http.MethodDelete, apiPrefix+"labels/TRASH"); n != 0 {
		t.Errorf("DELETE labels/TRASH calls = %d, want 0", n)
	}
}

// TestGmail_UnknownLabelListsLabels holds DS7.4a: a name that the
// account does not have, after one more labels.list call, fails with
// the names of the labels, and nothing changes. A name in the form of
// a label id is never created, also for add_labels.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_UnknownLabelListsLabels(t *testing.T) {
	f, _ := newMailFake(t, map[string][]string{"m1": {"INBOX"}})
	p, _ := f.provider(nil)
	ctx := context.Background()

	_, err := p.Modify(ctx, []string{"m1"}, mail.Change{RemoveLabels: []string{"Nope"}})
	if err == nil {
		t.Fatal("Modify with an unknown label: no error")
	}
	for _, want := range []string{`"Nope"`, "Receipts, Projects/Alpha, Trash", "INBOX"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not hold %q", err, want)
		}
	}
	if n := count(f, http.MethodGet, apiPrefix+"labels"); n != 2 {
		t.Errorf("labels.list calls = %d, want 2 (the cache, then one more)", n)
	}

	_, err = p.Modify(ctx, []string{"m1"}, mail.Change{AddLabels: []string{"Label_99"}})
	if err == nil || !strings.Contains(err.Error(), `"Label_99"`) || !strings.Contains(err.Error(), "Receipts") {
		t.Errorf("Modify add Label_99 = %v, want the unknown label error", err)
	}
	if w := writes(f); len(w) != 0 {
		t.Errorf("write requests = %+v, want none", w)
	}
	if n := count(f, http.MethodGet, apiPrefix+"messages/m1"); n != 0 {
		t.Errorf("messages.get calls = %d, want 0: the labels fail before a message is read", n)
	}
}

// TestGmail_AddLabelCreates holds DS7.4a: add_labels and move_to
// create a user label that the account does not have, and the next call
// finds the new label and does not create it again.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_AddLabelCreates(t *testing.T) {
	f, st := newMailFake(t, map[string][]string{"m1": {"INBOX"}, "m2": {"INBOX"}})
	p, _ := f.provider(nil)
	ctx := context.Background()

	if _, err := p.Modify(ctx, []string{"m1"}, mail.Change{AddLabels: []string{"Newsletters"}}); err != nil {
		t.Fatalf("Modify add: %v", err)
	}
	if got := st.labelsOf("m1"); !reflect.DeepEqual(got, []string{"INBOX", "Label_100"}) {
		t.Errorf("m1 labels = %v, want [INBOX Label_100]", got)
	}
	if _, err := p.Modify(ctx, []string{"m2"}, mail.Change{MoveTo: "Clients/Acme"}); err != nil {
		t.Fatalf("Modify move_to: %v", err)
	}
	if got := st.labelsOf("m2"); !reflect.DeepEqual(got, []string{"Label_101"}) {
		t.Errorf("m2 labels = %v, want [Label_101]", got)
	}
	if _, err := p.Modify(ctx, []string{"m2"}, mail.Change{AddLabels: []string{"newsletters"}}); err != nil {
		t.Fatalf("Modify add again: %v", err)
	}
	if got := st.labelsOf("m2"); !reflect.DeepEqual(got, []string{"Label_101", "Label_100"}) {
		t.Errorf("m2 labels = %v, want [Label_101 Label_100]", got)
	}

	var created []string
	for _, r := range writes(f) {
		if r.Method == http.MethodPost && strings.TrimPrefix(r.Path, apiPrefix) == "labels" {
			var b map[string]string
			if err := json.Unmarshal(r.Body, &b); err != nil {
				t.Fatal(err)
			}
			created = append(created, b["name"])
			if b["labelListVisibility"] != "labelShow" || b["messageListVisibility"] != "show" {
				t.Errorf("labels.create body = %v, want a label that shows", b)
			}
		}
	}
	if !reflect.DeepEqual(created, []string{"Newsletters", "Clients/Acme"}) {
		t.Errorf("created labels = %v, want [Newsletters Clients/Acme]", created)
	}
}

// TestGmail_NoLabelCreatedWithoutWrite holds DS7.4a: a new label of
// add_labels or move_to is created only just before batchModify. A
// change that is refused, or that finds no message, creates no label.
// A name both in move_to and in add_labels is created once.
//
// arch: DS7.4, DS7.4a, R16-L11
func TestGmail_NoLabelCreatedWithoutWrite(t *testing.T) {
	cases := []struct {
		name    string
		ids     []string
		change  mail.Change
		wantErr bool
	}{
		{"unknown remove", []string{"m1"}, mail.Change{AddLabels: []string{"New"}, RemoveLabels: []string{"Nope"}}, true},
		{"add and remove", []string{"m1"}, mail.Change{AddLabels: []string{"New"}, RemoveLabels: []string{"new"}}, true},
		{"move and remove", []string{"m1"}, mail.Change{MoveTo: "New", RemoveLabels: []string{"NEW"}}, true},
		{"all gone", []string{"gone1", "gone2"}, mail.Change{AddLabels: []string{"New"}}, false},
		{"move to gone", []string{"gone1"}, mail.Change{MoveTo: "New"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, st := newMailFake(t, map[string][]string{"m1": {"INBOX"}})
			p, _ := f.provider(nil)
			_, err := p.Modify(context.Background(), tc.ids, tc.change)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Modify = %v, want error %v", err, tc.wantErr)
			}
			if w := writes(f); len(w) != 0 {
				t.Errorf("write requests = %+v, want none", w)
			}
			if got := st.labelsOf("m1"); !reflect.DeepEqual(got, []string{"INBOX"}) {
				t.Errorf("m1 labels = %v, want [INBOX]", got)
			}
		})
	}

	f, st := newMailFake(t, map[string][]string{"m1": {"INBOX"}})
	p, _ := f.provider(nil)
	if _, err := p.Modify(context.Background(), []string{"m1"}, mail.Change{MoveTo: "New", AddLabels: []string{"new"}}); err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if n := count(f, http.MethodPost, apiPrefix+"labels"); n != 1 {
		t.Errorf("labels.create calls = %d, want 1", n)
	}
	if got := st.labelsOf("m1"); !reflect.DeepEqual(got, []string{"Label_100"}) {
		t.Errorf("m1 labels = %v, want [Label_100]", got)
	}
}

// TestGmail_MoveReversesByLabelDiff holds IS8.4 and DS78.5: a move on
// Gmail keeps the id and leaves a record whose Before and After labels
// differ. The undo that reverseChange builds from that difference (add
// Before minus After, remove After minus Before) puts the message back.
// A label that Gmail changes on its own (IMPORTANT) is not in the
// record, so the state read of undo still matches. Trash is reversed
// the same way.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_MoveReversesByLabelDiff(t *testing.T) {
	cases := []struct {
		name   string
		change mail.Change
		before []string
		after  []string
	}{
		{"move_to", mail.Change{MoveTo: "receipts"}, []string{"INBOX"}, []string{"Label_1"}},
		{"trash", mail.Change{Trash: true}, []string{"INBOX"}, []string{"TRASH"}},
		{"archive", mail.Change{Archive: true}, []string{"INBOX"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, st := newMailFake(t, map[string][]string{"m1": {"INBOX", "UNREAD", "IMPORTANT", "CATEGORY_UPDATES"}})
			p, _ := f.provider(nil)
			ctx := context.Background()

			res, err := p.ModifyDetail(ctx, []string{"m1"}, tc.change)
			if err != nil {
				t.Fatalf("ModifyDetail: %v", err)
			}
			if len(res.Applied) != 1 {
				t.Fatalf("Applied = %+v, want 1 row", res.Applied)
			}
			rec := res.Applied[0]
			if rec.ID != "m1" || rec.NewID != "" || rec.FoldersBefore != nil || rec.FoldersAfter != nil || rec.ExpungePending {
				t.Errorf("row = %+v, want the same id and no folder lists", rec)
			}
			if !reflect.DeepEqual(rec.Before.Labels, tc.before) || !reflect.DeepEqual(rec.After.Labels, tc.after) {
				t.Errorf("labels before/after = %v/%v, want %v/%v", rec.Before.Labels, rec.After.Labels, tc.before, tc.after)
			}

			// Gmail drops IMPORTANT on its own; the state read of undo
			// must still match the record.
			st.setLabels("m1", slices.DeleteFunc(st.labelsOf("m1"), func(s string) bool { return s == "IMPORTANT" })...)
			cur, err := p.ModifyDetail(ctx, []string{"m1"}, mail.Change{})
			if err != nil || len(cur.Applied) != 1 || !reflect.DeepEqual(cur.Applied[0].Before, rec.After) {
				t.Fatalf("state read = %+v, %v; want Before %+v", cur, err, rec.After)
			}

			var back mail.Change
			for _, l := range rec.Before.Labels {
				if !slices.Contains(rec.After.Labels, l) {
					back.AddLabels = append(back.AddLabels, l)
				}
			}
			for _, l := range rec.After.Labels {
				if !slices.Contains(rec.Before.Labels, l) {
					back.RemoveLabels = append(back.RemoveLabels, l)
				}
			}
			if _, err := p.ModifyDetail(ctx, []string{"m1"}, back); err != nil {
				t.Fatalf("undo: %v", err)
			}
			final, err := p.ModifyDetail(ctx, []string{"m1"}, mail.Change{})
			if err != nil || len(final.Applied) != 1 || !reflect.DeepEqual(final.Applied[0].Before, rec.Before) {
				t.Errorf("after undo = %+v, %v; want %+v", final, err, rec.Before)
			}
		})
	}
}

// TestGmail_MoveTakesOutOfTrashAndSpam holds DS7.4: move_to X also
// removes TRASH and SPAM, unless X is that label. Without this, a
// "move to INBOX" from Trash gives [TRASH INBOX], and the message stays
// on the delete timer of Trash.
//
// arch: DS7.4, R16-M1
func TestGmail_MoveTakesOutOfTrashAndSpam(t *testing.T) {
	cases := []struct {
		name   string
		before []string
		moveTo string
		after  []string
	}{
		{"trash to inbox", []string{"TRASH"}, "INBOX", []string{"INBOX"}},
		{"spam to inbox", []string{"SPAM", "UNREAD"}, "INBOX", []string{"UNREAD", "INBOX"}},
		{"trash to label", []string{"TRASH"}, "receipts", []string{"Label_1"}},
		{"spam to trash", []string{"SPAM"}, "TRASH", []string{"TRASH"}},
		{"inbox to spam", []string{"INBOX", "TRASH"}, "SPAM", []string{"SPAM"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, st := newMailFake(t, map[string][]string{"m1": tc.before})
			p, _ := f.provider(nil)
			if _, err := p.Modify(context.Background(), []string{"m1"}, mail.Change{MoveTo: tc.moveTo}); err != nil {
				t.Fatalf("Modify: %v", err)
			}
			if got := st.labelsOf("m1"); !reflect.DeepEqual(got, tc.after) {
				t.Errorf("labels after = %v, want %v", got, tc.after)
			}
		})
	}
}

// TestGmail_BatchModifyChunks1000 holds E3 and DS7.4: the read before
// the change runs at most 10 messages.get calls at a time, and
// batchModify takes at most 1000 ids for each call, each id once.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_BatchModifyChunks1000(t *testing.T) {
	const n = 2001
	msgs := make(map[string][]string, n)
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("m%04d", i)
		msgs[ids[i]] = []string{"INBOX", "UNREAD"}
	}
	f, st := newMailFake(t, msgs)
	st.getDelay = time.Millisecond
	p, _ := f.provider(nil)

	res, err := p.ModifyDetail(context.Background(), ids, mail.Change{Read: ptr(true)})
	if err != nil {
		t.Fatalf("ModifyDetail: %v", err)
	}
	if len(res.Applied) != n || len(res.Gone) != 0 {
		t.Fatalf("Applied %d, Gone %d; want %d, 0", len(res.Applied), len(res.Gone), n)
	}
	var sizes []int
	var all []string
	for _, b := range st.batches {
		sizes = append(sizes, len(b))
		all = append(all, b...)
	}
	if !reflect.DeepEqual(sizes, []int{1000, 1000, 1}) {
		t.Errorf("batchModify sizes = %v, want [1000 1000 1]", sizes)
	}
	if !reflect.DeepEqual(all, ids) {
		t.Error("batchModify ids are not each id once, in order")
	}
	if st.maxInflight > modifyFanout {
		t.Errorf("messages.get at the same time = %d, want at most %d", st.maxInflight, modifyFanout)
	}
	for _, a := range res.Applied {
		if a.Before.Seen || !a.After.Seen {
			t.Fatalf("row %+v: want Seen false before and true after", a)
		}
	}
}

// TestGmail_GoneBeforeChange holds DS7.4 and D5.4: an id that gives
// 404 before the change is in Gone and has no row, batchModify gets
// the other ids only, and ExpungePending stays false. When all ids are
// gone, or the change is empty, no batchModify goes out.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_GoneBeforeChange(t *testing.T) {
	f, st := newMailFake(t, map[string][]string{"m1": {"INBOX"}, "m2": {"INBOX", "STARRED"}})
	p, _ := f.provider(nil)
	ctx := context.Background()

	res, err := p.ModifyDetail(ctx, []string{"m1", "gone1", "m2", "m1"}, mail.Change{Starred: ptr(true)})
	if err != nil {
		t.Fatalf("ModifyDetail: %v", err)
	}
	if !reflect.DeepEqual(res.Gone, []string{"gone1"}) || res.ExpungePending {
		t.Errorf("Gone %v, ExpungePending %v; want [gone1], false", res.Gone, res.ExpungePending)
	}
	var rows []string
	for _, a := range res.Applied {
		rows = append(rows, a.ID)
		if a.ExpungePending || !a.After.Flagged {
			t.Errorf("row %+v: want Flagged after and no ExpungePending", a)
		}
	}
	if !reflect.DeepEqual(rows, []string{"m1", "m2"}) {
		t.Errorf("rows = %v, want [m1 m2]", rows)
	}
	if !reflect.DeepEqual(st.batches, [][]string{{"m1", "m2"}}) {
		t.Errorf("batchModify ids = %v, want [[m1 m2]]", st.batches)
	}

	res, err = p.ModifyDetail(ctx, []string{"gone1", "gone2"}, mail.Change{Archive: true})
	if err != nil || len(res.Applied) != 0 || !reflect.DeepEqual(res.Gone, []string{"gone1", "gone2"}) {
		t.Errorf("all gone = %+v, %v; want no rows and Gone [gone1 gone2]", res, err)
	}
	res, err = p.ModifyDetail(ctx, []string{"m2"}, mail.Change{})
	if err != nil || len(res.Applied) != 1 || !reflect.DeepEqual(res.Applied[0].Before, res.Applied[0].After) {
		t.Errorf("empty change = %+v, %v; want one row with Before equal to After", res, err)
	}
	if len(st.batches) != 1 {
		t.Errorf("batchModify calls = %d, want 1", len(st.batches))
	}

	if _, err := p.ModifyDetail(ctx, []string{"../labels"}, mail.Change{Archive: true}); !errors.Is(err, mail.ErrInvalidID) {
		t.Errorf("bad id = %v, want mail.ErrInvalidID", err)
	}
}

// TestGmail_SystemLabelWriteRefused holds DS7.4: CreateFolder,
// RenameFolder and DeleteFolder refuse a system label with a fixed
// text and send no write; a user label goes to labels.create,
// labels.patch and labels.delete.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_SystemLabelWriteRefused(t *testing.T) {
	f, _ := newMailFake(t, map[string][]string{})
	p, _ := f.provider(nil)
	ctx := context.Background()

	refused := map[string]error{
		"create INBOX":   p.CreateFolder(ctx, "INBOX"),
		"rename SENT":    p.RenameFolder(ctx, "SENT", "Out"),
		"rename starred": p.RenameFolder(ctx, "starred", "Stars"),
		"delete TRASH":   p.DeleteFolder(ctx, "TRASH"),
		"delete spam":    p.DeleteFolder(ctx, "spam"),
	}
	for name, err := range refused {
		if !errors.Is(err, errSystemLabel) {
			t.Errorf("%s = %v, want errSystemLabel", name, err)
		}
	}
	if w := writes(f); len(w) != 0 {
		t.Fatalf("write requests = %+v, want none", w)
	}

	if err := p.CreateFolder(ctx, "Clients"); err != nil {
		t.Errorf("CreateFolder(Clients): %v", err)
	}
	if err := p.RenameFolder(ctx, "receipts", "Bills"); err != nil {
		t.Errorf("RenameFolder(receipts): %v", err)
	}
	if err := p.DeleteFolder(ctx, "Projects/Alpha"); err != nil {
		t.Errorf("DeleteFolder(Projects/Alpha): %v", err)
	}
	if err := p.RenameFolder(ctx, "Nope", "x"); err == nil || !strings.Contains(err.Error(), `"Nope"`) {
		t.Errorf("RenameFolder(Nope) = %v, want the unknown label error", err)
	}
	var got []string
	for _, r := range writes(f) {
		got = append(got, r.Method+" "+strings.TrimPrefix(r.Path, apiPrefix)+" "+string(r.Body))
	}
	want := []string{
		`POST labels {"labelListVisibility":"labelShow","messageListVisibility":"show","name":"Clients"}`,
		`PATCH labels/Label_1 {"name":"Bills"}`,
		`DELETE labels/Label_2 `,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("writes =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestGmail_FolderWriteRefusesTakenName holds DS7.4 and DS7.4a: the
// new name of CreateFolder and RenameFolder matches as a label name
// does, with no regard to case. A name that gives a system label is
// refused with errSystemLabel, and a name that gives another label is
// refused as an existing label, as IMAP and JMAP refuse an existing
// folder; neither sends a write. When a second client takes the name
// first, the 409 of Gmail is that refusal too, but add_labels takes
// the label that the second client made.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_FolderWriteRefusesTakenName(t *testing.T) {
	f, st := newMailFake(t, map[string][]string{"m1": {"INBOX"}})
	p, _ := f.provider(nil)
	ctx := context.Background()

	system := map[string]error{
		"create inbox":           p.CreateFolder(ctx, "inbox"),
		"create Spam":            p.CreateFolder(ctx, "Spam"),
		"rename to Inbox":        p.RenameFolder(ctx, "Receipts", "Inbox"),
		"rename to CHAT":         p.RenameFolder(ctx, "Receipts", "CHAT"),
		"create CATEGORY_SOCIAL": p.CreateFolder(ctx, "CATEGORY_SOCIAL"),
	}
	for name, err := range system {
		if !errors.Is(err, errSystemLabel) {
			t.Errorf("%s = %v, want errSystemLabel", name, err)
		}
	}
	taken := map[string]error{
		`"receipts"`:       p.CreateFolder(ctx, "receipts"),
		`"Trash"`:          p.CreateFolder(ctx, "Trash"),
		`"projects/ALPHA"`: p.RenameFolder(ctx, "Receipts", "projects/ALPHA"),
		`"trash"`:          p.RenameFolder(ctx, "Receipts", "trash"),
	}
	for name, err := range taken {
		if err == nil || err.Error() != "gmail: the account already has a label "+name {
			t.Errorf("write to %s = %v, want the existing label error", name, err)
		}
	}
	if w := writes(f); len(w) != 0 {
		t.Fatalf("write requests = %+v, want none", w)
	}

	// A rename that changes only the case keeps the label.
	if err := p.RenameFolder(ctx, "Receipts", "RECEIPTS"); err != nil {
		t.Errorf("RenameFolder(Receipts, RECEIPTS): %v", err)
	}

	// A second client takes the name between labels.list and the write.
	st.raced = "Clients"
	if err := p.CreateFolder(ctx, "Clients"); err == nil || err.Error() != `gmail: the account already has a label "Clients"` {
		t.Errorf("CreateFolder(Clients) after a race = %v, want the existing label error", err)
	}
	st.raced = "Bills"
	if err := p.RenameFolder(ctx, "Receipts", "Bills"); err == nil || err.Error() != `gmail: the account already has a label "Bills"` {
		t.Errorf("RenameFolder(Receipts, Bills) after a race = %v, want the existing label error", err)
	}
	st.raced = "Later"
	if _, err := p.Modify(ctx, []string{"m1"}, mail.Change{AddLabels: []string{"Later"}}); err != nil {
		t.Fatalf("Modify add after a race: %v", err)
	}
	if got := st.labelsOf("m1"); !reflect.DeepEqual(got, []string{"INBOX", "Label_102"}) {
		t.Errorf("m1 labels = %v, want [INBOX Label_102] (the label of the second client)", got)
	}

	var got []string
	for _, r := range writes(f) {
		got = append(got, r.Method+" "+strings.TrimPrefix(r.Path, apiPrefix))
	}
	want := []string{"PATCH labels/Label_1", "POST labels", "PATCH labels/Label_1", "POST labels", "POST messages/batchModify"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("writes = %v, want %v", got, want)
	}
}

// TestGmail_CapsLines holds DS78.4: the report has Kind "gmail" and the
// lines "api: ok", "labels: <n>" and "send-as: <k> verified", where k
// counts the primary address and the accepted ones, not a pending one.
// The IMAP fields stay false.
//
// arch: DS7.4, DS7.4a, DS7.4b, DS78.4, DS78.5, IS8.4
func TestGmail_CapsLines(t *testing.T) {
	f, _ := newMailFake(t, map[string][]string{})
	p, _ := f.provider(nil)

	got, err := p.Caps(context.Background())
	if err != nil {
		t.Fatalf("Caps: %v", err)
	}
	want := mail.Caps{Kind: "gmail", Lines: []string{"api: ok", "labels: 17", "send-as: 2 verified"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Caps = %+v, want %+v", got, want)
	}
	if n := count(f, http.MethodGet, apiPrefix+"labels") + count(f, http.MethodGet, apiPrefix+"settings/sendAs"); n != 2 {
		t.Errorf("calls = %d, want 2 (labels.list and settings/sendAs)", n)
	}
	if list, ok := p.sendAs.get(p.now()); !ok || len(list) != 2 {
		t.Errorf("send-as cache = %v, %v; want the 2 addresses", list, ok)
	}
}
