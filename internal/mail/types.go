// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// Package mail holds the types every provider (imap, gmail, jmap) builds
// on: message ids, search cursors and the common query grammar (§3.7,
// §3.8, §3.9). The provider contract itself is [tools.Writer]
// (DRV.16a). Nothing in this package talks to a network or a disk;
// that is the job of internal/imap, internal/gmail and internal/jmap.
//
// arch: T3.1, §3.7, §3.8, §3.9, DRV.16a
package mail

import "time"

// Folder is one mailbox folder or, on gmail, one label shown as a
// folder to the search and modify tools.
type Folder struct {
	Name   string
	Role   string // "inbox", "sent", "drafts", "trash", "junk", "archive", "all", or ""
	Total  int
	Unread int
}

// Address is one parsed mail address.
type Address struct {
	Name    string
	Address string
}

// Attachment describes one part of a message that a caller can fetch
// with Provider.Attachment. It carries no content.
type Attachment struct {
	// Ref identifies the part to Provider.Attachment: the part path
	// (imap) or the provider's attachment id (gmail, jmap). C19: a
	// caller may also pass Filename as ref; the provider accepts both.
	Ref         string
	Filename    string
	ContentType string
	Size        int64

	// SMIMEType is the smime-type parameter of the part, as the
	// server gave it. Empty means the part has no such parameter, or
	// the provider did not read it. read gives it with ContentType to
	// SMIMEKindOfValue to name the attachment kind (DR1G.18.2). It is
	// not part of the tool output.
	SMIMEType string `json:"-"`
}

// Flags holds the read/starred/answered state of a message plus any
// labels or keywords beyond those three (§3.10, §3.16 C18).
type Flags struct {
	Seen     bool
	Flagged  bool
	Answered bool
	Draft    bool
	Labels   []string
}

// Message is one email, decoded and ready for the tool layer to fence
// (fencing itself happens in internal/tools, never here; §3.15).
type Message struct {
	ID     string
	Folder string
	From   Address
	To     []Address
	Cc     []Address

	// Date is the server's own time (INTERNALDATE / internalDate),
	// never the sender's Date header, which a sender can set to
	// anything (§3.10, C22).
	Date time.Time

	Subject     string
	Preview     string
	Body        string
	Attachments []Attachment
	Flags       Flags
	Size        int64

	// MessageID is the Message-ID header of this message, with the
	// angle brackets kept. A provider fills it from the headers it
	// already fetches for Read or for the thread rule of §3.10. An
	// empty value means the provider could not read the header, not
	// that the message has none.
	MessageID string

	// References is the References header of this message, oldest
	// first, one id per entry with its angle brackets kept. A reply
	// tool builds the next message's References from this list plus
	// MessageID, so it never has to fetch the raw source for that
	// alone (§3.14). Empty means the provider could not read the
	// header.
	References []string

	// ReplyTo is the Reply-To header, parsed. A reply tool sends to
	// ReplyTo when it is not empty, and to From otherwise (§3.14).
	// Empty means the message has no Reply-To header, or the provider
	// could not read it.
	ReplyTo []Address

	// HiddenRemoved is the count of HTML text runs that the provider
	// removed as hidden when it made Body from an HTML part (D4.1,
	// D4.2). Zero when Body came from a text/plain part.
	HiddenRemoved int

	// PartsDiffer is true when the message has a text/plain and a
	// text/html body part, their words differ, and Body therefore
	// holds the text of the HTML part (D4.2).
	PartsDiffer bool

	// SignedHint says whether the whole source can hold a signature.
	// It has three states, and its zero value is [SignedUnknown]: a
	// provider that never sets it says "I did not look", and read
	// then fetches the source and checks it (D6.2). Only
	// [SignedNo] turns the check off.
	//
	// A provider sets [SignedYes] when it saw a multipart/signed
	// entity or an application/(x-)pkcs7-mime part at any depth of
	// the structure, or [InlinePGPMarker] in the full decoded text of
	// a text part. It reads that text before it cuts the body to
	// Offset and MaxChars, so the hint never depends on a paging
	// argument. It sets [SignedNo] only when it read both the
	// structure and the full text and found neither.
	SignedHint SignedState

	// AuthResults is the Authentication-Results header block of the
	// message, header text only, as the server gave it. The DKIM
	// check of read reads it, so a message with no signed part gives
	// a DKIM verdict from a header fetch and never from the whole
	// source (D6.2). Empty means the message has no such header, or
	// the provider could not read it.
	AuthResults string

	// MediaType is the top-level media type of the message, as
	// type/subtype, from the structure the provider read. read uses
	// it to name an encrypted message with a fixed note (D7.3). Empty
	// means the provider did not read the structure.
	MediaType string

	// SMIMEType is the smime-type parameter of the top-level
	// Content-Type, as the server gave it. Empty means the message
	// has no such parameter, or the provider did not read it (D7.3).
	SMIMEType string

	// Headers holds the values of the headers that ReadOpts.Headers
	// names. The key is the name as the caller wrote it in
	// ReadOpts.Headers; a header matches it without regard to case.
	// Each instance of the header in the message gives one entry, in
	// message order. A value is unfolded and trimmed, but not decoded
	// (no RFC 2047), and it is sender text. A name with no instance
	// has no key. A name that ReadOpts.Headers repeats, in any case,
	// counts once, and its first spelling is the key. Nil when
	// ReadOpts.Headers is empty (DS9.2).
	Headers map[string][]string
}

// SignedState is the three-state answer of a provider to "can the
// whole source hold a signature?" (D6.2). It is a type, and not a
// bool, so that the zero value means "not answered" and not "no": a
// new provider that forgets [Message.SignedHint] costs one fetch per
// read, never a lost signature check.
//
// arch: D6.2
type SignedState int

// The states of [SignedState]. SignedUnknown is the zero value, so it
// is what a provider reports when it sets nothing.
const (
	// SignedUnknown means the provider did not answer. read fetches
	// the whole source and checks it (D6.2).
	SignedUnknown SignedState = iota
	// SignedYes means the structure or the full text holds a
	// signature. read fetches the whole source and checks it.
	SignedYes
	// SignedNo means the provider read the structure and the full
	// text and found no signature. read fetches no source, and only
	// the Authentication-Results header can give a verdict.
	SignedNo
)

// String gives the word of a state, for a test message and a log
// line. It holds no sender text.
func (s SignedState) String() string {
	switch s {
	case SignedYes:
		return "signed"
	case SignedNo:
		return "not signed"
	default:
		return "unknown"
	}
}

// InlinePGPMarker starts an inline clearsigned OpenPGP block. A
// provider looks for it in the full text of a message to set
// [Message.SignedHint]; the tool layer looks for it in the body it
// shows, for the type of a result it could not check. Both need the
// same word, so it lives here, where neither package imports the
// other.
const InlinePGPMarker = "-----BEGIN PGP SIGNED MESSAGE-----"

// ReadOpts controls what Provider.Read returns.
type ReadOpts struct {
	Thread   bool
	Format   string // "text" (default) or "html"
	MaxChars int
	Offset   int
	MarkRead bool

	// Headers names the headers to return in Message.Headers, for
	// example List-Unsubscribe. A provider fetches them on demand, so
	// a read with no names costs nothing more (DS9.2).
	Headers []string
}

// Page is one page of search results.
type Page struct {
	Messages []Message

	// NextCursor is empty when there is no further page. A caller
	// passes it back as Query.Cursor for the next call (§3.9).
	NextCursor string

	// Note is a short line for the caller, set when the page is true
	// but could read as the whole answer when it is not. DRV.12: a
	// client-side filter only checks a bounded window of the newest
	// candidate messages, so a short page can still have unchecked
	// messages below it. A preview fetch error adds to it too
	// (DR1G.5, DR1G.18.3), joined with "; " when both apply. Empty
	// means the provider has nothing to add.
	Note string

	// Partial is true when the match set of the query may be
	// incomplete: a client-side filter or a scan limit cut it. Note
	// then says why. A caller that must act on every match (bulk)
	// refuses a page with Partial set (DS9.4, S9-GAP1).
	Partial bool
}

// ThreadResult is the outcome of Reader.Thread: the conversation plus
// how complete the search was. A folder that gave a local error is
// skipped, not fatal (§3.10), so the caller still gets every message
// the search did find, with a count of what it could not check.
//
// arch: DR1G.4, DR1G.5, DR1G.18.3
type ThreadResult struct {
	Messages []*Message

	// Skipped is the number of folders that gave a local (non-dead-
	// socket) error and were not searched. The conversation may then
	// be incomplete. A dead connection is never counted here: it
	// fails the whole call instead, so the pool can dial again and
	// run the search again (DRV.10).
	Skipped int

	// PreviewsMissing is the number of messages in Messages that a
	// local preview-fetch error left with no preview. A dead
	// connection during a preview fetch is never counted here
	// either; it fails the whole call the same way Skipped does.
	PreviewsMissing int
}

// Query is what a caller passes to Provider.Search. Raw is the exact
// text a person or a model gave (§3.9); a provider with its own syntax
// (gmail) sends Raw to the server unchanged. A provider that needs
// structure (imap, jmap) calls ParseQuery(Raw) itself.
type Query struct {
	Raw    string
	Folder string
	Since  time.Time // zero value: no lower bound
	Limit  int
	Cursor string

	// IDsOnly asks for rows that carry ID only: the provider skips
	// the envelope fetch for the page. A provider honours it only when
	// every term of the query runs on the server; otherwise it gives
	// full rows and sets Page.Partial (DS9.4, S9-GAP1). IDsOnly does
	// not change the result set, so HashQuery leaves it out and a
	// cursor of a full page stays valid for an ids-only page.
	IDsOnly bool
}

// Outgoing is a message a caller wants to send or save as a draft. Its
// fields already passed the guard checks of §3.15 (addresses parsed,
// no CR/LF, attachment paths resolved) before a provider sees it.
type Outgoing struct {
	From        string
	To, Cc, Bcc []string
	Subject     string
	Text        string
	HTML        string
	Attachments []string // resolved file paths, guard.AttachPath already ran

	InReplyTo  string // Message-ID of the message this replies to, or ""
	References []string

	// ReplyToID is the id (folder and UID, §3.8) of the message this
	// replies to, or "". A provider uses it to set \Answered on the
	// exact message, instead of a Message-ID search limited to a few
	// role folders (§3.10).
	ReplyToID string
}

// SendResult is the outcome of Provider.Send.
type SendResult struct {
	ID          string
	Sent        bool
	SavedToSent bool

	// Warning is set when the send worked but a secondary step (the
	// Sent copy, C14) failed. A non-empty Warning never means Sent is
	// false: the mail already left.
	Warning string
}

// Change is what Provider.Modify applies. A nil *bool means "leave
// unchanged"; MoveTo, Archive and Trash are mutually exclusive at the
// tool layer (Appendix B), not enforced here.
type Change struct {
	Read         *bool
	Starred      *bool
	AddLabels    []string
	RemoveLabels []string
	MoveTo       string
	Archive      bool
	Trash        bool

	// RestoreFolders is for undo only. A provider with mailbox lists
	// (JMAP) sets the mailboxes of the message to exactly these. Empty
	// means no change of the mailbox list (DS78.5).
	RestoreFolders []string

	// KeepJunkKeywords is for undo only. The move then does not
	// change the junk keywords, because the labels of the change
	// already give the keywords back exactly (DS8.2d).
	KeepJunkKeywords bool
}

// Applied is one entry of what Provider.Modify actually did, fed to
// the undo journal (§3.18).
type Applied struct {
	ID     string
	NewID  string // set when the id changed (an imap move, C5); equal to ID when an imap message was already in the target (R16-M5)
	Before Flags
	After  Flags

	// FoldersBefore and FoldersAfter are the mailboxes the message
	// was in before and after the change. A provider with mailbox
	// lists (JMAP) fills them on each mailbox change, because a JMAP
	// move keeps the id. They stay empty for IMAP, where the id names
	// the folder, and for Gmail, where a folder is a label (DS78.5).
	FoldersBefore []string
	FoldersAfter  []string

	// ExpungePending is true when a move copied this message and
	// flagged the old copy \Deleted, but the server could not remove
	// that copy: it has no UIDPLUS, and a plain EXPUNGE would remove
	// every \Deleted message in the folder (C12). The message is then
	// in both folders until the server or another client removes the
	// old copy. The tool result says expunge_pending, because a
	// caller that reads a clean success does not know about the
	// second copy (§3.10).
	ExpungePending bool
}

// ModifyResult is what a write provider knows about one modify call:
// the Applied rows, the gone ids, and one ExpungePending answer for
// the whole call.
//
// ExpungePending is true when a move copied the messages and flagged
// the old copies \Deleted, but the server has no UIDPLUS, so no
// UID EXPUNGE could remove those copies. A plain EXPUNGE is not an
// option (C12), so the old copies stay until the server or another
// client removes them. The message is in both folders until then.
// Every row of Applied carries the same answer in
// [Applied.ExpungePending].
//
// Gone lists the ids of the messages that were not there when the
// call acted: another client expunged or moved them. They get no row
// in Applied, so the undo journal never records a change that did not
// happen (D5.4, I16). The ids keep the order of the call.
//
// A call with an empty [Change] changes nothing. It reads the current
// flags of each id into Applied.Before and names each absent id in
// Gone. A provider with mailbox lists (JMAP) also reads the current
// mailboxes of each id into Applied.FoldersAfter. Undo uses this read
// to see if another client changed or moved a message (D5.4, DS78.5).
//
// The type is here and not in internal/imap, so the tool layer can
// name it in its Writer contract with no import of a provider package.
//
// arch: T5.3, §3.10, C12, D5.4, DS78.5
type ModifyResult struct {
	Applied        []Applied
	Gone           []string
	ExpungePending bool
}

// AttachmentInfo describes the attachment Provider.Attachment just
// opened. The tool layer never logs or returns Filename verbatim
// without fencing it first (§3.15): a sender picks the file name.
type AttachmentInfo struct {
	Filename    string
	ContentType string
	Size        int64
}

// ProviderIdentity is one sending identity as the provider stores it:
// a Gmail send-as entry or a JMAP Identity object. The CLI command
// "identities detect" reads it (DI6.2).
//
// TextSignature is the exact text of the signature, or empty when the
// provider text cannot be given back exactly. HTMLSignature is the
// signature as the provider stores it. Source names the origin, for
// example "gmail sendAs" or "jmap Identity".
//
// arch: DI6.2
type ProviderIdentity struct {
	Email, Name   string
	TextSignature string
	HTMLSignature string
	Default       bool
	Source        string
}
