// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The read of the JMAP identities with their signatures, for the CLI
// command "identities detect" (DI6.2). It is a separate Identity/get.
// It does not use or fill the identity cache, and the send path does
// not call it.

package jmap

import (
	"context"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// ProviderIdentities calls Identity/get with the properties id, name,
// email, textSignature and htmlSignature and gives one entry for each
// identity. A server without the submission capability gets no call,
// because it would refuse the whole batch; the list is then empty
// (DI6.2).
//
// arch: DI6.2
func (p *Provider) ProviderIdentities(ctx context.Context) ([]mail.ProviderIdentity, error) {
	s, err := p.c.Session(ctx)
	if err != nil {
		return nil, p.report(err)
	}
	if _, ok := s.Capabilities[usingSubmission]; !ok {
		return nil, nil
	}
	acc, err := p.accountID(ctx)
	if err != nil {
		return nil, err
	}
	r, err := p.call(ctx, Invocation{Name: "Identity/get", ID: "i", Args: map[string]any{
		"accountId":  acc,
		"ids":        nil,
		"properties": []string{"id", "name", "email", "textSignature", "htmlSignature"},
	}})
	if err != nil {
		return nil, err
	}
	var ans struct {
		List []struct {
			Name          string `json:"name"`
			Email         string `json:"email"`
			TextSignature string `json:"textSignature"`
			HTMLSignature string `json:"htmlSignature"`
		} `json:"list"`
	}
	if err := result(r, "i", "Identity/get", &ans); err != nil {
		return nil, err
	}
	var out []mail.ProviderIdentity
	for _, i := range ans.List {
		out = append(out, mail.ProviderIdentity{
			Email:         i.Email,
			Name:          i.Name,
			TextSignature: i.TextSignature,
			HTMLSignature: i.HTMLSignature,
			Source:        "jmap Identity",
		})
	}
	return out, nil
}
