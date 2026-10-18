// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

package imap

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// Search runs the common query grammar of §3.9 against one folder.
//
// Every command is a UID command (C1). The folder opens with EXAMINE
// (C3), so no row of a search ever gets the \Seen flag, and every
// body fetch peeks (C2).
//
// arch: T4.3, §3.9, §3.10, C1, C2, C3, C7, C8, C28
func (p *Provider) Search(ctx context.Context, q mail.Query) (mail.Page, error) {
	pq := mail.ParseQuery(q.Raw)
	crit, filt, err := buildCriteria(pq, q.Since, time.Now())
	if err != nil {
		return mail.Page{}, err
	}
	if filt.folder != "" && q.Folder != "" && filt.folder != q.Folder {
		return mail.Page{}, fmt.Errorf("imap: search: in:%q conflicts with folder %q; name one", filt.folder, q.Folder)
	}
	cur, err := mail.ValidateCursor(q.Cursor, q)
	if err != nil {
		return mail.Page{}, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	folder := filt.folder
	if folder == "" {
		folder = q.Folder
	}
	if folder == "" {
		folder = "INBOX"
	}
	hash := mail.HashQuery(q)

	var page mail.Page
	err = p.pool.WithRead(ctx, p.alias, func(c *Conn) error {
		name, err := resolveFolder(c, folder)
		if err != nil {
			return err
		}
		sel, err := examine(c, name)
		if err != nil {
			return err
		}
		page, err = searchIn(c, name, sel.UIDValidity, crit, filt, cur, limit, hash, q.IDsOnly)
		return err
	})
	if err != nil {
		return mail.Page{}, err
	}
	return page, nil
}

// filters holds the parts of a query that no server can answer, plus
// the folder that an in: term names.
type filters struct {
	folder       string
	attachment   bool      // has:attachment, read from BODYSTRUCTURE
	noAttachment bool      // -has:attachment: keep only messages with none
	sinceExact   time.Time // C8: SINCE has a precision of one day
	nonASCII     bool      // C7: the server searches the raw RFC 2047 text
	words        []string  // lower case, for the envelope scan of §3.9
	hasNot       bool
	hasBody      bool
	hasToOrCC    bool // DRV.12: a to: or cc: term, which the scan cannot check
}

// clientSide reports whether a filter runs after the fetch. The page
// then comes out of a larger candidate window, because the server
// sent rows that the client drops.
func (f filters) clientSide() bool {
	return f.attachment || f.noAttachment || !f.sinceExact.IsZero()
}

// keep applies the client-side filters to one fetched row.
func (f filters) keep(r *imapclient.FetchMessageBuffer) bool {
	if !f.sinceExact.IsZero() && r.InternalDate.Before(f.sinceExact) {
		return false
	}
	has := r.BodyStructure != nil && hasAttachment(r.BodyStructure)
	if f.attachment && !has {
		return false
	}
	if f.noAttachment && has {
		return false
	}
	return true
}

// canScan reports whether the envelope fallback of §3.9 can stand in
// for the server. The scan sees the subject and the sender only, so a
// query with a body term, a negated term, or a to:/cc: term would
// give a wrong answer and the fallback stays off; to: and cc: reach
// the server instead (DRV.12).
func (f filters) canScan() bool {
	return f.nonASCII && !f.hasNot && !f.hasBody && !f.hasToOrCC && len(f.words) > 0
}

// buildCriteria turns the parsed query into IMAP search criteria plus
// the filters the client applies itself.
//
// A term the grammar cannot read fails the call. The query grammar
// has no error channel of its own: a bad date or size would otherwise
// go to the server unchecked and come back as "no results", which
// tells the caller nothing. One clear error is worth more than a
// silent empty page (§3.9).
//
// arch: T4.3, §3.9, §3.10, C6, C7, C8
func buildCriteria(pq mail.ParsedQuery, since, now time.Time) (imap.SearchCriteria, filters, error) {
	var crit imap.SearchCriteria
	var filt filters

	if !since.IsZero() {
		// The wire form carries the date only, so the server also
		// sends messages from earlier in that same day. The exact
		// time runs on INTERNALDATE after the fetch (C8).
		crit.Since = since
		filt.sinceExact = since
	}

	// smaller holds the least non-zero smaller: limit. It stays out of
	// the And merge: go-imap And sets Smaller back to 0 when a later
	// term has Smaller 0, so "smaller:1M from:bob" lost its limit.
	var smaller int64
	for _, t := range pq.Terms {
		sub, err := termCriteria(t, now, &filt)
		if err != nil {
			return crit, filt, err
		}
		if sub == nil {
			continue
		}
		if t.Not {
			filt.hasNot = true
			crit.Not = append(crit.Not, *sub)
			continue
		}
		if sub.Smaller > 0 && (smaller == 0 || sub.Smaller < smaller) {
			smaller = sub.Smaller
		}
		sub.Smaller = 0
		crit.And(sub)
	}
	crit.Smaller = smaller
	return crit, filt, nil
}

// termCriteria turns one term into criteria. It returns nil when the
// term needs no server command (has:attachment, in:).
func termCriteria(t mail.QueryTerm, now time.Time, filt *filters) (*imap.SearchCriteria, error) {
	var c imap.SearchCriteria
	switch t.Field {
	case "from", "to", "cc", "subject":
		noteWord(filt, t)
		if t.Field == "to" || t.Field == "cc" {
			filt.hasToOrCC = true
		}
		c.Header = []imap.SearchCriteriaHeaderField{{Key: headerName(t.Field), Value: t.Value}}
	case "body":
		filt.hasBody = true
		noteWord(filt, t)
		c.Body = []string{t.Value}
	case "text":
		if strings.EqualFold(t.Value, "OR") || strings.EqualFold(t.Value, "AND") {
			// mail.ParseQuery has no operator: a bare OR becomes a
			// text term and the search then asks for messages that
			// hold the word "OR", which finds almost nothing and says
			// nothing. Fail instead (§3.9).
			return nil, fmt.Errorf("imap: search: %q is not an operator here; every term is joined with AND, and OR works on Gmail accounts only", t.Value)
		}
		noteWord(filt, t)
		c.Text = []string{t.Value}
	case "has":
		if !strings.EqualFold(t.Value, "attachment") {
			return nil, fmt.Errorf("imap: search: has:%q is not known; only has:attachment exists", t.Value)
		}
		if t.Not {
			filt.noAttachment = true
		} else {
			filt.attachment = true
		}
		return nil, nil
	case "is":
		switch strings.ToLower(t.Value) {
		case "unread":
			c.NotFlag = []imap.Flag{imap.FlagSeen}
		case "read":
			c.Flag = []imap.Flag{imap.FlagSeen}
		case "starred":
			c.Flag = []imap.Flag{imap.FlagFlagged}
		default:
			return nil, fmt.Errorf("imap: search: is:%q is not known; use is:unread, is:read or is:starred", t.Value)
		}
	case "in":
		if t.Not {
			return nil, fmt.Errorf("imap: search: -in: is not supported; name the folder to search with in: or the folder field")
		}
		filt.folder = t.Value
		return nil, nil
	case "before", "after":
		d, err := time.ParseInLocation("2006-01-02", t.Value, time.UTC)
		if err != nil {
			return nil, fmt.Errorf("imap: search: %s:%q is not a date; use YYYY-MM-DD", t.Field, t.Value)
		}
		if t.Field == "before" {
			c.Before = d
		} else {
			c.Since = d
		}
	case "newer_than", "older_than":
		d, err := mail.ParseSpan(t.Value)
		if err != nil {
			return nil, fmt.Errorf("imap: search: %s:%q is not a time span; use 7d, 2m or 1y", t.Field, t.Value)
		}
		if t.Field == "newer_than" {
			c.Since = now.Add(-d)
		} else {
			c.Before = now.Add(-d)
		}
	case "larger", "smaller":
		n, err := mail.ParseSize(t.Value)
		if err != nil {
			return nil, fmt.Errorf("imap: search: %s:%q is not a size; use 5M, 200K or a number of bytes", t.Field, t.Value)
		}
		if t.Field == "larger" {
			c.Larger = n
		} else {
			c.Smaller = n
		}
	default:
		return nil, fmt.Errorf("imap: search: %q is not a known term", t.Field)
	}
	return &c, nil
}

// noteWord records a word for the envelope scan and says whether the
// query holds a character the server cannot match (C7).
func noteWord(filt *filters, t mail.QueryTerm) {
	if t.Value == "" || t.Not {
		return
	}
	for _, r := range t.Value {
		if r > unicode.MaxASCII {
			filt.nonASCII = true
			break
		}
	}
	filt.words = append(filt.words, strings.ToLower(t.Value))
}

// headerName gives the header a field term searches.
func headerName(field string) string {
	switch field {
	case "from":
		return "From"
	case "to":
		return "To"
	case "cc":
		return "Cc"
	default:
		return "Subject"
	}
}

// scanCutNote is the page note when the C7 envelope scan stopped at
// scanLimit, so older messages were never matched.
var scanCutNote = fmt.Sprintf("the newest %d messages were scanned; more could match further back", scanLimit)

// clientMatchNote is the page note when a caller asked for ids only
// but the client, not the server, decided the matches (S9-GAP1).
const clientMatchNote = "a term of this query is checked on the client, so the match set can be incomplete"

// searchIn runs the search on the open folder and builds one page.
//
// With idsOnly, a page whose matches the server decided in full
// skips the row fetch and carries the ids only (DS9.4). When a
// client-side filter or the envelope scan decided the matches, the
// page is a normal one with Partial set (S9-GAP1).
//
// arch: T4.3, §3.9, §3.10, C1, C7, C8, C28, DRV.12, DS9.4
func searchIn(c *Conn, folder string, uidValidity uint32, crit imap.SearchCriteria, filt filters, cur mail.Cursor, limit int, hash string, idsOnly bool) (mail.Page, error) {
	if cur.Position != "" {
		// The cursor's UIDVALIDITY must still match the folder's: a
		// folder recreated since the first page reuses old UID
		// numbers for different messages, so an old Position would
		// now point at the wrong rows (DRV.12).
		if cur.UIDValidity != uidValidity {
			return mail.Page{}, fmt.Errorf("imap: search: %w", mail.ErrCursorUIDValidityChanged)
		}
		// A cursor holds a position inside a result set, never a
		// right of access: the query already bounds what the page can
		// hold, and the position only moves down the UID list (§3.9).
		pos, err := strconv.ParseUint(cur.Position, 10, 32)
		if err != nil {
			return mail.Page{}, fmt.Errorf("imap: search: %w", mail.ErrCursorInvalid)
		}
		if pos <= 1 {
			return mail.Page{}, nil
		}
		var set imap.UIDSet
		set.AddRange(1, imap.UID(pos-1))
		crit.UID = append(slices.Clone(crit.UID), set)
	}

	uids, err := uidSearch(c, &crit)
	if err != nil {
		return mail.Page{}, err
	}
	scanned, scanCut := false, false
	if len(uids) == 0 && filt.canScan() {
		uids, scanCut, err = scanEnvelopes(c, scanCriteria(crit), filt.words)
		if err != nil {
			return mail.Page{}, err
		}
		scanned = true
	}
	if len(uids) == 0 {
		if scanCut {
			return mail.Page{Note: scanCutNote, Partial: true}, nil
		}
		return mail.Page{}, nil
	}

	// C28: a search can give 100 000 UIDs. Newest first, then take
	// the highest few and fetch data for those only.
	slices.SortFunc(uids, func(a, b imap.UID) int { return cmp.Compare(b, a) })
	clientMatch := filt.clientSide() || scanned
	if idsOnly && !clientMatch {
		return idsPage(uids, folder, uidValidity, limit, hash), nil
	}
	window := limit
	if filt.clientSide() {
		window = candidateLimit
	}
	// truncated records whether UIDs beyond the window were cut off
	// and never examined at all. DRV.12: with a client-side filter,
	// the window can be full of candidates that do not match, giving
	// a short page with older, unexamined UIDs still below it; the
	// caller must still be told a next page exists.
	truncated := len(uids) > window
	if truncated {
		uids = uids[:window]
	}

	rows, err := fetchRows(c, uids)
	if err != nil {
		return mail.Page{}, err
	}
	byUID := make(map[imap.UID]*imapclient.FetchMessageBuffer, len(rows))
	for _, r := range rows {
		byUID[r.UID] = r
	}

	msgs := make([]mail.Message, 0, limit)
	kept := make([]*imapclient.FetchMessageBuffer, 0, limit)
	// examinedIdx is the last index of uids this loop looked at and
	// decided on, kept or not. It differs from the index of the last
	// kept row whenever the loop stops short of the window: that gap
	// holds UIDs nothing has decided on yet (DRV.12).
	examinedIdx := -1
	for i, uid := range uids {
		examinedIdx = i
		r := byUID[uid]
		if r == nil || !filt.keep(r) {
			continue
		}
		msgs = append(msgs, rowToMessage(r, folder, uidValidity))
		kept = append(kept, r)
		if len(msgs) == limit {
			break
		}
	}

	var missingPreviews int
	if len(msgs) > 0 {
		var err error
		missingPreviews, err = addPreviews(c, msgs, kept)
		if err != nil {
			return mail.Page{}, err
		}
	}

	page := mail.Page{Messages: msgs}
	if truncated && filt.clientSide() {
		// The candidate window itself was cut off before the fetch, so
		// older messages below it were never examined at all. A short
		// page here can read as the whole answer when it is not; say
		// so even when msgs came back full (DRV.12). This note only
		// applies when a client-side filter set the window to
		// candidateLimit (:368); a plain search is truncated at the
		// caller's own Limit, which is not a hidden cut.
		page.Note = fmt.Sprintf("the newest %d matching messages were checked; more could match further back", candidateLimit)
		page.Partial = true
	}
	if scanCut {
		page.Note = joinPageNote(page.Note, scanCutNote)
		page.Partial = true
	}
	if idsOnly && clientMatch {
		page.Note = joinPageNote(page.Note, clientMatchNote)
		page.Partial = true
	}
	if missingPreviews > 0 {
		// A local preview-fetch error (connBroken false) left some
		// rows with no preview; the row itself is still correct, only
		// its preview text is missing (DR1G.5, DR1G.18.3). The count
		// never names a folder, which is server data (I14).
		page.Note = joinPageNote(page.Note, fmt.Sprintf("previews are missing for %d message(s)", missingPreviews))
	}
	// A next page is needed whenever the loop stopped before the end
	// of the window (more to check there) or the window itself was
	// truncated (more to check below it) (DRV.12).
	if examinedIdx < len(uids)-1 || truncated {
		if lowest := uids[examinedIdx]; lowest > 1 {
			page.NextCursor = mail.EncodeCursor(mail.Cursor{
				Position:    strconv.FormatUint(uint64(lowest), 10),
				QueryHash:   hash,
				UIDValidity: uidValidity,
			})
		}
	}
	return page, nil
}

// idsPage builds an ids-only page out of the UIDs of one search,
// newest first, with no FETCH. It pages the way searchIn does for a
// query with no client-side filter: the window is limit, and a cut
// window gives a cursor at the lowest UID of the page. A UID that a
// second client removed after the search still gives a row; the
// caller that acts on it sees the message gone (DS9.4).
//
// arch: DS9.4, C1, C28, §3.9
func idsPage(uids []imap.UID, folder string, uidValidity uint32, limit int, hash string) mail.Page {
	truncated := len(uids) > limit
	if truncated {
		uids = uids[:limit]
	}
	msgs := make([]mail.Message, 0, len(uids))
	for _, uid := range uids {
		msgs = append(msgs, mail.Message{ID: mail.FormatIMAPID(uidValidity, uint32(uid), folder)})
	}
	page := mail.Page{Messages: msgs}
	if lowest := uids[len(uids)-1]; truncated && lowest > 1 {
		page.NextCursor = mail.EncodeCursor(mail.Cursor{
			Position:    strconv.FormatUint(uint64(lowest), 10),
			QueryHash:   hash,
			UIDValidity: uidValidity,
		})
	}
	return page
}

// uidSearch runs one UID SEARCH. C1: only UID commands, never a
// sequence set, because a sequence number moves as soon as another
// client removes a message.
func uidSearch(c *Conn, crit *imap.SearchCriteria) ([]imap.UID, error) {
	var opts *imap.SearchOptions
	if c.Caps().Has(imap.CapESearch) {
		// One range answer instead of a line with every number.
		opts = &imap.SearchOptions{ReturnAll: true}
	}
	data, err := c.UIDSearch(crit, opts).Wait()
	if err != nil {
		return nil, fmt.Errorf("imap: search: %w", err)
	}
	return data.AllUIDs(), nil
}

// fetchRows gets the row data of §3.10 for one page of UIDs.
func fetchRows(c *Conn, uids []imap.UID) ([]*imapclient.FetchMessageBuffer, error) {
	opts := &imap.FetchOptions{
		UID:           true,
		Flags:         true,
		InternalDate:  true,
		RFC822Size:    true,
		Envelope:      true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}
	rows, err := c.Fetch(imap.UIDSetNum(uids...), opts).Collect()
	if err != nil {
		return nil, fmt.Errorf("imap: fetch rows: %w", err)
	}
	return rows, nil
}

// scanEnvelopes is the client scan of §3.9 for trap C7. Many servers
// match a header against its raw RFC 2047 text, so a query with a
// non-ASCII word finds nothing. The scan reads the envelopes of the
// newest scanLimit messages and matches the subject, the sender name
// and the sender address, all in lower case. go-imap gives the
// envelope already decoded, so the words match there. cut is true
// when older messages were left out at scanLimit (S9-GAP1).
//
// arch: T4.3, §3.9, C7
func scanEnvelopes(c *Conn, crit *imap.SearchCriteria, words []string) (uids []imap.UID, cut bool, err error) {
	all, err := uidSearch(c, crit)
	if err != nil {
		return nil, false, err
	}
	if len(all) == 0 {
		return nil, false, nil
	}
	slices.SortFunc(all, func(a, b imap.UID) int { return cmp.Compare(b, a) })
	if len(all) > scanLimit {
		all = all[:scanLimit]
		cut = true
	}
	rows, err := c.Fetch(imap.UIDSetNum(all...), &imap.FetchOptions{UID: true, Envelope: true}).Collect()
	if err != nil {
		return nil, false, fmt.Errorf("imap: scan envelopes: %w", err)
	}
	for _, r := range rows {
		if envelopeHolds(r.Envelope, words) {
			uids = append(uids, r.UID)
		}
	}
	return uids, cut, nil
}

// scanCriteria drops the text the server could not match and keeps
// the rest of the query: the flags, the dates, the size and the
// cursor bound. The scan stands in for the text match only. A scan
// that searched for everything would give back messages that the
// query excludes, and it would ignore the cursor, so every page of a
// non-ASCII search would hold the same rows (C7).
//
// arch: T4.3, §3.9, C7
func scanCriteria(crit imap.SearchCriteria) *imap.SearchCriteria {
	crit.Header, crit.Body, crit.Text = nil, nil, nil
	return &crit
}

// envelopeHolds reports whether the envelope holds every word.
func envelopeHolds(e *imap.Envelope, words []string) bool {
	if e == nil {
		return false
	}
	var b strings.Builder
	b.WriteString(e.Subject)
	for _, a := range e.From {
		b.WriteByte(' ')
		b.WriteString(a.Name)
		b.WriteByte(' ')
		b.WriteString(a.Addr())
	}
	hay := strings.ToLower(b.String())
	for _, w := range words {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// rowToMessage builds one search row.
//
// Date is INTERNALDATE, never the Date header, which a sender writes
// (C22). MessageID and ReplyTo come from the envelope, where they
// cost nothing. References stays empty here: the envelope does not
// carry that header, and the Read path fetches it (§3.14).
func rowToMessage(r *imapclient.FetchMessageBuffer, folder string, uidValidity uint32) mail.Message {
	m := mail.Message{
		ID:     mail.FormatIMAPID(uidValidity, uint32(r.UID), folder),
		Folder: folder,
		Date:   r.InternalDate,
		Size:   r.RFC822Size,
		Flags:  toFlags(r.Flags),
	}
	if e := r.Envelope; e != nil {
		m.Subject = e.Subject
		if len(e.From) > 0 {
			m.From = toAddress(e.From[0])
		}
		m.To = toAddresses(e.To)
		m.Cc = toAddresses(e.Cc)
		m.MessageID = angled(e.MessageID)
		m.ReplyTo = toAddresses(e.ReplyTo)
	}
	return m
}

// angled puts the angle brackets back around a Message-ID. go-imap
// strips them from the envelope; mail.Message keeps them (§3.14).
func angled(id string) string {
	if id == "" || strings.HasPrefix(id, "<") {
		return id
	}
	return "<" + id + ">"
}

func toAddress(a imap.Address) mail.Address {
	return mail.Address{Name: a.Name, Address: a.Addr()}
}

func toAddresses(in []imap.Address) []mail.Address {
	if len(in) == 0 {
		return nil
	}
	out := make([]mail.Address, 0, len(in))
	for _, a := range in {
		out = append(out, toAddress(a))
	}
	return out
}

// toFlags maps the IMAP flags to the common shape. Any other keyword
// becomes a label (§3.10, C18).
func toFlags(in []imap.Flag) mail.Flags {
	var f mail.Flags
	for _, fl := range in {
		switch fl {
		case imap.FlagSeen:
			f.Seen = true
		case imap.FlagFlagged:
			f.Flagged = true
		case imap.FlagAnswered:
			f.Answered = true
		case imap.FlagDraft:
			f.Draft = true
		case imap.FlagDeleted, "\\Recent":
			// State of the folder, not a label.
		default:
			f.Labels = append(f.Labels, string(fl))
		}
	}
	return f
}

// hasAttachment reads the attachment rule of §3.10 off the body
// structure, with no download: a single part is an attachment when
// isAttachment says so (DRV.3).
func hasAttachment(bs imap.BodyStructure) bool {
	found := false
	bs.Walk(func(_ []int, part imap.BodyStructure) bool {
		if found {
			return false
		}
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}
		if isAttachment(sp) {
			found = true
			return false
		}
		return true
	})
	return found
}

// previewPart is the text part a preview comes from, with the fetch
// window §3.10 asks for.
type previewPart struct {
	path        []int
	window      int64
	contentType string
	encoding    string
}

// pickPreviewPart walks the body structure and takes text/plain when
// there is one, text/html when there is not.
//
// The window depends on the media type. A text/plain part starts with
// the text, so 2048 bytes hold the first lines. An HTML part starts
// with the <style> head of the sender's template, which is often
// longer than 2048 bytes on its own; a 2048-byte window then decodes
// to nothing at all. HTML gets 16 KB, which reaches past the head of
// every newsletter we measured.
//
// arch: T4.3, §3.10, C20, DRV.3
func pickPreviewPart(bs imap.BodyStructure) (previewPart, bool) {
	var plain, html *imap.BodyStructureSinglePart
	var plainPath, htmlPath []int
	bs.Walk(func(path []int, part imap.BodyStructure) bool {
		sp, ok := part.(*imap.BodyStructureSinglePart)
		if !ok {
			return true
		}
		// The same rule as Read: a named part with no disposition is
		// an attachment too, not the preview (DRV.3).
		if isAttachment(sp) {
			return true
		}
		switch strings.ToLower(sp.MediaType()) {
		case "text/plain":
			if plain == nil {
				plain, plainPath = sp, slices.Clone(path)
			}
		case "text/html":
			if html == nil {
				html, htmlPath = sp, slices.Clone(path)
			}
		}
		return true
	})
	switch {
	case plain != nil:
		return previewPart{path: plainPath, window: previewPlainBytes,
			contentType: contentTypeOf(plain), encoding: plain.Encoding}, true
	case html != nil:
		return previewPart{path: htmlPath, window: previewHTMLBytes,
			contentType: contentTypeOf(html), encoding: html.Encoding}, true
	}
	return previewPart{}, false
}

// contentTypeOf rebuilds the Content-Type header of a part, with the
// charset, so mime.Preview can decode it (C21).
func contentTypeOf(sp *imap.BodyStructureSinglePart) string {
	ct := sp.MediaType()
	if cs := sp.Params["charset"]; cs != "" {
		ct += "; charset=" + cs
	}
	return ct
}

// addPreviews fills the preview of the newest previewRows rows
// (§3.10). Rows with the same part path and window share one fetch,
// so a normal page costs one or two commands.
//
// A local failure never fails the search: the rows in the failed
// group keep an empty preview, and the count of them comes back as
// the first result, for the caller to put in a note (DR1G.5,
// DR1G.18.3). A dead socket gives its error back, so the pool can
// dial again (DRV.10); the count up to that point is not meaningful
// then, because the whole call is retried.
//
// arch: DR1G.5, DR1G.18.3
func addPreviews(c *Conn, msgs []mail.Message, rows []*imapclient.FetchMessageBuffer) (int, error) {
	n := min(len(msgs), previewRows)
	type group struct {
		part previewPart
		uids []imap.UID
	}
	groups := make(map[string]*group)
	at := make(map[imap.UID]int, n)
	for i := 0; i < n; i++ {
		if rows[i].BodyStructure == nil {
			continue
		}
		p, ok := pickPreviewPart(rows[i].BodyStructure)
		if !ok {
			continue
		}
		// The key holds the whole part description, not the path
		// alone: two rows can share a path and a window and still
		// need a different charset or transfer encoding, and the
		// group decodes every row with the part it holds (C21).
		key := fmt.Sprintf("%v/%d/%s/%s", p.path, p.window, p.contentType, p.encoding)
		g := groups[key]
		if g == nil {
			g = &group{part: p}
			groups[key] = g
		}
		g.uids = append(g.uids, rows[i].UID)
		at[rows[i].UID] = i
	}
	var missing int
	for _, g := range groups {
		opts := &imap.FetchOptions{
			UID:         true,
			BodySection: []*imap.FetchItemBodySection{partialFetch(g.part.path, g.part.window)},
		}
		got, err := c.Fetch(imap.UIDSetNum(g.uids...), opts).Collect()
		if connBroken(c, err) {
			return missing, err
		}
		if err != nil {
			// This one group of rows keeps no preview; every other
			// group still gets its own fetch (DR1G.5).
			missing += len(g.uids)
			continue
		}
		for _, r := range got {
			i, ok := at[r.UID]
			if !ok || len(r.BodySection) == 0 {
				continue
			}
			msgs[i].Preview = mime.Preview(r.BodySection[0].Bytes, g.part.contentType, g.part.encoding)
		}
	}
	return missing, nil
}

// joinPageNote appends add to have, the "; " join DR1G.5 asks for
// when a page already carries a note from another check (DRV.12).
func joinPageNote(have, add string) string {
	if have == "" {
		return add
	}
	return have + "; " + add
}
