// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// The send-as check of Gmail (DS7.5). Gmail rewrites a From that is not
// a verified send-as address to the primary address and still reports
// success (E6). So the provider checks the From itself, before a draft
// is stored and before a draft is sent (IS7.4). This file holds the
// cache of 10 minutes of the verified send-as addresses and the check.

package gmail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/amsys/mailbag-mcp/internal/mail"
)

// sendAsTTL is the life of the send-as cache on the wall clock (DS7.5,
// §3.12).
const sendAsTTL = 10 * time.Minute

// sendAsCache holds the verified send-as addresses: the entries of
// settings/sendAs that are primary or have verificationStatus
// "accepted". It lives sendAsTTL on the wall clock (DS7.5). The zero
// value is empty and ready to use. The Factory shares one cache
// between the providers of one account through State (G6).
type sendAsCache struct {
	mu   sync.Mutex
	at   time.Time // wall time of the settings/sendAs answer in list
	list []string  // the allowed addresses, in the order of the answer
	ok   bool      // list holds an answer
}

// get gives the list when it is younger than sendAsTTL at now. A
// negative age means the wall clock stepped back, so the age is not
// known and the list counts as old.
func (c *sendAsCache) get(now time.Time) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ok {
		return nil, false
	}
	if age := now.Sub(c.at); age < 0 || age >= sendAsTTL {
		return nil, false
	}
	return c.list, true
}

// put keeps list as the answer of settings/sendAs at now.
func (c *sendAsCache) put(list []string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = list
	c.at = now
	c.ok = true
}

// listSendAs calls settings/sendAs, keeps the allowed addresses in the
// send-as cache and gives them. An entry is allowed when it is the
// primary address or its verificationStatus is "accepted" (DS7.5).
func (p *Provider) listSendAs(ctx context.Context) ([]string, error) {
	var ans struct {
		SendAs []struct {
			SendAsEmail        string `json:"sendAsEmail"`
			IsPrimary          bool   `json:"isPrimary"`
			VerificationStatus string `json:"verificationStatus"`
		} `json:"sendAs"`
	}
	if err := p.api.Get(ctx, "settings/sendAs", nil, &ans); err != nil {
		return nil, err
	}
	var list []string
	for _, s := range ans.SendAs {
		if s.SendAsEmail != "" && (s.IsPrimary || s.VerificationStatus == "accepted") {
			list = append(list, s.SendAsEmail)
		}
	}
	p.sendAs.put(list, p.now())
	return list, nil
}

// fromAllowed returns nil when from is a verified send-as address, in
// any case, else an error that lists the allowed addresses. Gmail
// would rewrite an unverified From to the primary address and report
// success (E6). The check uses the send-as cache. When the cached list
// has no match, it asks the server once more, because the person can
// have verified the address after the cache was filled.
//
// arch: DS7.5, IS7.4, E6
func (p *Provider) fromAllowed(ctx context.Context, from string) error {
	list, cached := p.sendAs.get(p.now())
	if !cached {
		var err error
		if list, err = p.listSendAs(ctx); err != nil {
			return err
		}
	}
	if containsFold(list, from) {
		return nil
	}
	if cached {
		var err error
		if list, err = p.listSendAs(ctx); err != nil {
			return err
		}
		if containsFold(list, from) {
			return nil
		}
	}
	if len(list) == 0 {
		return errors.New("gmail: the account has no verified send-as address")
	}
	return fmt.Errorf("gmail: %q is not a verified send-as address of this account; the allowed addresses are: %s", from, strings.Join(list, ", "))
}

// containsFold reports whether list holds s, in any case.
func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// ProviderIdentities lists the send-as entries of the account with one
// settings/sendAs call, for "identities detect". It does not use or
// fill the send-as cache. TextSignature holds the text only when the
// stored signature has the exact form that [signatureHTML] writes, so
// a signature that another client wrote as HTML gives an empty text
// and the HTML stays in HTMLSignature (DI6.2).
//
// arch: DI6.2
func (p *Provider) ProviderIdentities(ctx context.Context) ([]mail.ProviderIdentity, error) {
	var ans struct {
		SendAs []struct {
			SendAsEmail string `json:"sendAsEmail"`
			DisplayName string `json:"displayName"`
			Signature   string `json:"signature"`
			IsDefault   bool   `json:"isDefault"`
		} `json:"sendAs"`
	}
	if err := p.api.Get(ctx, "settings/sendAs", nil, &ans); err != nil {
		return nil, err
	}
	var out []mail.ProviderIdentity
	for _, s := range ans.SendAs {
		if s.SendAsEmail == "" {
			continue
		}
		id := mail.ProviderIdentity{
			Email:         s.SendAsEmail,
			Name:          s.DisplayName,
			HTMLSignature: s.Signature,
			Default:       s.IsDefault,
			Source:        "gmail sendAs",
		}
		if text := signatureText(s.Signature); signatureHTML(text) == s.Signature {
			id.TextSignature = text
		}
		out = append(out, id)
	}
	return out, nil
}
