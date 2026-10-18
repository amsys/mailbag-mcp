// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The Gmail drafts and the send (DS7.4, DS78.8 sequence 3). SaveDraft
// builds the RFC 822 source with internal/mime and stores it through
// drafts.create or drafts.update. SendDraft finds the draft by its
// message id and sends it with drafts.send. Both run the send-as check
// of DS7.5 first (IS7.4). The id that the tools see is the message id
// of the draft, so Read and Raw work on it.

package gmail

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	gomail "github.com/emersion/go-message/mail"

	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
)

// The bounds of the draft search of SendDraft and of a replace.
const (
	// draftPageSize is maxResults of one drafts.list call, the most
	// that Gmail gives.
	draftPageSize = 500
	// maxDraftPages stops the draft search when the server gives a
	// next page without end.
	maxDraftPages = 100
)

// draftMeta is the JSON part of the drafts.create and drafts.update
// upload (DS7.4). ID is set on an update only.
type draftMeta struct {
	ID      string `json:"id,omitempty"`
	Message struct {
		ThreadID string `json:"threadId,omitempty"`
	} `json:"message"`
}

// draftResource is a draft of drafts.create, drafts.update and
// drafts.list. The draft id and the message id are not the same, and
// an update gives the draft a new message id.
type draftResource struct {
	ID      string `json:"id"`
	Message struct {
		ID       string `json:"id"`
		ThreadID string `json:"threadId"`
	} `json:"message"`
}

// SaveDraft stores one message as a draft and gives the message id of
// the draft, so Read and Raw work on it (DS7.4). The send-as check of
// DS7.5 runs first, and nothing is built or stored before it passes
// (IS7.4, E6). An empty From means the account address. When m answers
// a message, the draft goes into the thread of that message.
//
// replaceID is the message id of the draft that this one takes the
// place of, or "". It must be a draft. drafts.update replaces the
// draft in place and gives it a new message id.
//
// The draft gets no mime.ReplyIDHeader: drafts.send sends the stored
// source as it is, so the header would reach the recipients. Gmail
// keeps the thread through threadId.
//
// arch: DS7.4, DS7.5, DS78.8, IS7.4, E6
func (p *Provider) SaveDraft(ctx context.Context, m *mail.Outgoing, replaceID string) (string, error) {
	if m == nil {
		return "", errors.New("gmail: save draft: no message")
	}
	from := strings.TrimSpace(m.From)
	if from == "" {
		if p.acct.Email == "" {
			return "", errors.New("gmail: this account has no email address; add one to accounts.toml")
		}
		from = p.acct.Email
	}
	addr, err := gomail.ParseAddress(from)
	if err != nil {
		return "", fmt.Errorf("gmail: from address: %w", err)
	}
	if err := p.fromAllowed(ctx, addr.Address); err != nil {
		return "", err
	}

	var meta draftMeta
	if m.ReplyToID != "" {
		if meta.Message.ThreadID, err = p.threadOf(ctx, m.ReplyToID); err != nil {
			return "", err
		}
	}
	method, path := http.MethodPost, "drafts"
	if replaceID != "" {
		if meta.ID, err = p.findDraft(ctx, replaceID); err != nil {
			return "", err
		}
		method, path = http.MethodPut, "drafts/"+meta.ID
	}

	var raw bytes.Buffer
	in := mime.Input{
		From:        from,
		To:          m.To,
		Cc:          m.Cc,
		Bcc:         m.Bcc,
		Subject:     m.Subject,
		Text:        m.Text,
		HTML:        m.HTML,
		Attachments: m.Attachments,
		InReplyTo:   m.InReplyTo,
		References:  m.References,
	}
	if err := mime.Build(&raw, in, p.now(), rand.Reader); err != nil {
		return "", err
	}

	var d draftResource
	if err := p.api.Upload(ctx, method, path, meta, raw.Bytes(), &d); err != nil {
		return "", err
	}
	if err := checkMsgID(d.Message.ID); err != nil {
		return "", fmt.Errorf("gmail: the server saved the draft, but gave no valid message id for it: %w", err)
	}
	return d.Message.ID, nil
}

// SendDraft sends the draft whose message id is id (DS7.4). drafts.list
// finds the draft id, page by page; a message that is not in the list
// is not a draft. The From header of the draft must pass the send-as
// check of DS7.5 before drafts.send runs (IS7.4). drafts.send is tried
// again on 429 only, because after another failure the message can
// have left already (IS7.3). Gmail files the sent message in SENT
// itself, and SendResult.ID is the id of the sent message.
//
// arch: DS7.4, DS7.5, DS78.8, IS7.3, IS7.4
func (p *Provider) SendDraft(ctx context.Context, id string) (mail.SendResult, error) {
	draftID, err := p.findDraft(ctx, id)
	if err != nil {
		return mail.SendResult{}, err
	}
	var hdr metaMessage
	q := url.Values{"format": {"metadata"}, "metadataHeaders": {"From"}}
	if err := p.api.Get(ctx, "messages/"+id, q, &hdr); err != nil {
		return mail.SendResult{}, err
	}
	from := addressList(hdr.header("From"))
	if len(from) == 0 || from[0].Address == "" {
		return mail.SendResult{}, errors.New("gmail: this draft has no from address")
	}
	if err := p.fromAllowed(ctx, from[0].Address); err != nil {
		return mail.SendResult{}, err
	}

	var sent metaMessage
	if err := p.api.sendOnce(ctx, "drafts/send", map[string]string{"id": draftID}, &sent); err != nil {
		return mail.SendResult{}, err
	}
	// The mail left. Nothing below changes Sent (M3).
	return mail.SendResult{ID: sent.ID, Sent: true, SavedToSent: true}, nil
}

// findDraft gives the draft id of the draft whose message id is msgID.
// It reads drafts.list page by page. A message id that no draft has
// gives the error "is not a draft".
func (p *Provider) findDraft(ctx context.Context, msgID string) (string, error) {
	if err := checkMsgID(msgID); err != nil {
		return "", err
	}
	token := ""
	for range maxDraftPages {
		q := url.Values{"maxResults": {strconv.Itoa(draftPageSize)}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Drafts        []draftResource `json:"drafts"`
			NextPageToken string          `json:"nextPageToken"`
		}
		if err := p.api.Get(ctx, "drafts", q, &page); err != nil {
			return "", err
		}
		for _, d := range page.Drafts {
			if d.Message.ID != msgID {
				continue
			}
			if err := checkMsgID(d.ID); err != nil {
				return "", err
			}
			return d.ID, nil
		}
		if page.NextPageToken == "" {
			return "", fmt.Errorf("gmail: message %s is not a draft", msgID)
		}
		token = page.NextPageToken
	}
	return "", fmt.Errorf("gmail: the draft list has more than %d pages; message %s was not found in it", maxDraftPages, msgID)
}

// threadOf gives the threadId of the message id, from messages.get
// with format=minimal.
func (p *Provider) threadOf(ctx context.Context, id string) (string, error) {
	if err := checkMsgID(id); err != nil {
		return "", err
	}
	var one metaMessage
	if err := p.api.Get(ctx, "messages/"+id, url.Values{"format": {"minimal"}}, &one); err != nil {
		return "", err
	}
	if err := checkMsgID(one.ThreadID); err != nil {
		return "", err
	}
	return one.ThreadID, nil
}
