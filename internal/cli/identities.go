// SPDX-FileCopyrightText: 2026 Martin <dev@amsys.cz>
// SPDX-License-Identifier: MIT

// This file holds "mailbag-mcp identities detect <alias>" (DI7). The
// command reads the provider signatures and a sample of the Sent
// folder, finds the signature and the reply layout of each sender
// address, and prints a proposal as TOML. It writes the proposal to
// accounts.toml only after a person types "yes" at a terminal.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	netmail "net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/amsys/mailbag-mcp/internal/config"
	"github.com/amsys/mailbag-mcp/internal/guard"
	"github.com/amsys/mailbag-mcp/internal/mail"
	"github.com/amsys/mailbag-mcp/internal/mime"
	"github.com/amsys/mailbag-mcp/internal/tools"
)

// Limits of the Sent-mail sample and of the vote (DI7.1, DI7.3).
const (
	detectDefaultSample = 50
	detectMaxSample     = 100
	detectReadMaxChars  = 20000
	voteMinMails        = 5
	voteMinPercent      = 60
	voteShownGroups     = 3

	// detectTimeout bounds the whole command: one folder list, one
	// search and up to detectMaxSample reads.
	detectTimeout = 5 * time.Minute
)

// gmailSettingsLabel is the label of every Gmail provider signature
// (DI7.4): a model can set it through the gmail_settings tool.
const gmailSettingsLabel = "may have been set through gmail_settings"

// mailbagMessageID matches the Message-ID that mailbag writes: 32 hex
// digits at a domain (newMessageID in internal/mime). Detect skips such
// a mail, so a copy that a model made never counts in the vote (DI7.2).
var mailbagMessageID = regexp.MustCompile(`^<?[0-9a-fA-F]{32}@[^@<>\s]+>?$`)

// forwardHeaders are the lines that start a forward block (DI7.3).
var forwardHeaders = []string{
	"---------- Forwarded message ---------",
	"-------- Forwarded Message --------",
	"Begin forwarded message:",
}

// detectProvider is the part of [tools.Reader] that detect calls. The
// [tools.IdentitySource] check runs on the concrete value.
type detectProvider interface {
	Folders(ctx context.Context) ([]mail.Folder, error)
	Search(ctx context.Context, q mail.Query) (mail.Page, error)
	Read(ctx context.Context, id string, o mail.ReadOpts) (*mail.Message, error)
}

// openAccount opens alias the same way loginReport does (DI7.1): a
// factory with no logger. The returned function closes the factory.
func openAccount(ctx context.Context, alias string) (tools.Reader, config.Account, func(), error) {
	f := tools.NewFactory(nil)
	p, acct, err := f.Open(ctx, alias)
	if err != nil {
		f.Close()
		return nil, config.Account{}, nil, err
	}
	return p, acct, f.Close, nil
}

// identitiesCmd runs one "identities ..." subcommand.
//
// arch: DI7.1
func identitiesCmd(args []string, env Env) int {
	if len(args) == 0 {
		return usageErrf(env, "identities needs the subcommand detect")
	}
	switch args[0] {
	case "detect":
		return identitiesDetect(args[1:], env)
	default:
		return usageErrf(env, "unknown identities subcommand %q", args[0])
	}
}

// identitiesDetect is "identities detect <alias> [--sample N]". It
// prints the proposal, then asks for "yes" and writes the tables with
// [config.AddIdentityTables]. It writes nothing when the account
// already has identity settings, when stdin is not a terminal, or when
// the answer is not exactly "yes" (DI7.6, I7).
//
// arch: DI7.1, DI7.5, DI7.6, DI8 I7
func identitiesDetect(args []string, env Env) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return usageErrf(env, "identities detect needs an alias as its first argument")
	}
	alias := args[0]

	set := flag.NewFlagSet("identities detect", flag.ContinueOnError)
	set.SetOutput(env.Stderr)
	set.Usage = func() { _, _ = fmt.Fprint(env.Stderr, usageText) }
	sample := set.Int("sample", detectDefaultSample, "the number of Sent mails to read, 1 to 100")
	if err := set.Parse(args[1:]); err != nil {
		return exitUsage
	}
	if set.NArg() > 0 {
		return usageErrf(env, "unexpected argument %q", set.Arg(0))
	}
	if *sample < 1 || *sample > detectMaxSample {
		return usageErrf(env, "--sample must be 1 to %d", detectMaxSample)
	}
	if err := guard.ValidateAlias(alias); err != nil {
		return usageErrf(env, "alias %q: use letters, digits, - and _ only", alias)
	}
	path, err := config.AccountsPath()
	if err != nil {
		return failf(env, "find the config directory: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), detectTimeout)
	defer cancel()
	p, acct, closeFn, err := env.OpenAccount(ctx, alias)
	if err != nil {
		return failf(env, "account %q: %v", alias, err)
	}
	if closeFn != nil {
		defer closeFn()
	}

	prop, err := detect(ctx, p, acct, alias, *sample)
	if err != nil {
		return failf(env, "account %q: %v", alias, err)
	}
	for _, l := range prop.render() {
		printf(env, "%s", l)
	}
	if len(prop.tables) == 0 {
		printf(env, "nothing to propose; nothing written")
		return exitOK
	}
	if acct.IdentityMode() {
		printf(env, "account %q already has identity settings; nothing written. Edit accounts.toml by hand.", alias)
		return exitOK
	}
	answer, err := env.ReadLine(fmt.Sprintf("Write this to %s? Type yes: ", path))
	if errors.Is(err, errNotTerminal) {
		printf(env, "stdin is not a terminal; nothing written")
		return exitOK
	}
	if err != nil {
		return failf(env, "read the answer: %v; nothing written", err)
	}
	if strings.TrimSpace(answer) != "yes" {
		printf(env, "the answer is not \"yes\"; nothing written")
		return exitOK
	}
	if err := config.AddIdentityTables(path, alias, prop.def, prop.tablesText()); err != nil {
		return failf(env, "write %s: %v; nothing written", path, err)
	}
	printf(env, "identity settings of account %q written to %s", alias, path)
	return exitOK
}

// sentMail is what detect keeps of one sampled Sent mail.
type sentMail struct {
	addr  string // From address, bare, lower case
	name  string // From display name
	date  time.Time
	shape mailShape
}

// mailShape is the DI7.3 analysis of one mail body.
type mailShape struct {
	block    string // signature block in DI1.4 normal form; "" = none
	hasQuote bool   // the body has a ">" quote block
	above    bool   // own text before the quote
	below    bool   // own text after the quote
	sigAfter bool   // the signature delimiter is after the quote
}

// analyseBody finds the own region, the signature block and the reply
// layout of one text body (DI7.3 items 1 to 3 and 5).
//
// The own region is the text before the quote start. When the quote
// is a ">" block, the text after the end of that block (up to a
// forward header) is own text too, because a reply can put its text
// or its signature below the quote (DI2.2, DI3.3). A forward block has
// no end, so no text after a forward header is own text.
//
// arch: DI7.3
func analyseBody(body string) mailShape {
	lines := strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n")
	for i, l := range lines {
		if strings.TrimFunc(l, unicode.IsSpace) == "" {
			lines[i] = ""
		}
	}
	qs, qe, quote := quoteSpan(lines)
	before := lines[:qs]
	var after []string
	if quote {
		end := qe
		for end < len(lines) && !isForwardHeader(lines[end]) {
			end++
		}
		after = lines[qe:end]
	}

	var s mailShape
	s.hasQuote = quote
	beforeOwn, afterOwn := before, after
	if i := lastDelimiter(after); i >= 0 {
		afterOwn = after[:i]
		s.block = signatureBlock(after[i+1:])
		s.sigAfter = true
	} else if i := lastDelimiter(before); i >= 0 {
		beforeOwn = before[:i]
		s.block = signatureBlock(before[i+1:])
	}
	s.above = hasText(beforeOwn)
	s.below = quote && hasText(afterOwn)
	return s
}

// quoteSpan finds the quote start qs and, for a ">" quote, the first
// line qe after the quote block. quote is false for a forward header
// or for no quote; then qe equals qs. With no quote start, qs is
// len(lines).
func quoteSpan(lines []string) (qs, qe int, quote bool) {
	for i, l := range lines {
		if isForwardHeader(l) {
			return i, i, false
		}
		if strings.HasPrefix(l, ">") {
			qe = i
			for qe < len(lines) && (lines[qe] == "" || strings.HasPrefix(lines[qe], ">")) {
				qe++
			}
			return attributionStart(lines, i), qe, true
		}
	}
	return len(lines), len(lines), false
}

// attributionStart gives the line of an "On ... wrote:" line above the
// first ">" line at q, with empty lines between them allowed. A mail
// client can wrap that line, so the "On " start can be up to two lines
// above the "wrote:" end. With no such line it gives q.
func attributionStart(lines []string, q int) int {
	j := q - 1
	for j >= 0 && lines[j] == "" {
		j--
	}
	if j < 0 || !strings.HasSuffix(strings.TrimSpace(lines[j]), "wrote:") {
		return q
	}
	for k := j; k >= 0 && k >= j-2; k-- {
		if strings.HasPrefix(strings.TrimSpace(lines[k]), "On ") {
			return k
		}
	}
	return q
}

// isForwardHeader reports whether l starts a forward block (DI7.3).
func isForwardHeader(l string) bool {
	t := strings.TrimSpace(l)
	for _, h := range forwardHeaders {
		if strings.EqualFold(t, h) {
			return true
		}
	}
	return false
}

// isDelimiter reports whether l is a signature delimiter: "-- " or
// "--" once trailing white space is cut.
func isDelimiter(l string) bool {
	return strings.TrimRightFunc(l, unicode.IsSpace) == "--"
}

// lastDelimiter gives the index of the last delimiter line, or -1.
func lastDelimiter(lines []string) int {
	for i := len(lines) - 1; i >= 0; i-- {
		if isDelimiter(lines[i]) {
			return i
		}
	}
	return -1
}

// signatureBlock joins the lines after a delimiter and gives the DI1.4
// normal form.
func signatureBlock(lines []string) string {
	return config.NormalizeSignature(strings.Join(lines, "\n"))
}

// hasText reports whether a line holds more than white space.
func hasText(lines []string) bool {
	for _, l := range lines {
		if l != "" {
			return true
		}
	}
	return false
}

// detect reads the provider identities and the Sent sample and builds
// the proposal (DI7.2 to DI7.5).
//
// arch: DI7.2, DI7.3, DI7.4
func detect(ctx context.Context, p detectProvider, acct config.Account, alias string, sample int) (*proposal, error) {
	var pids []mail.ProviderIdentity
	if src, ok := p.(tools.IdentitySource); ok {
		var err error
		if pids, err = src.ProviderIdentities(ctx); err != nil {
			return nil, fmt.Errorf("read the provider identities: %w", err)
		}
	}

	folders, err := p.Folders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the folders: %w", err)
	}
	sent := ""
	for _, f := range folders {
		if f.Role == "sent" {
			sent = f.Name
			break
		}
	}
	if sent == "" {
		return nil, fmt.Errorf("no folder has the role sent; set folders.sent for account %q in accounts.toml", alias)
	}
	page, err := p.Search(ctx, mail.Query{Folder: sent, Limit: sample})
	if err != nil {
		return nil, fmt.Errorf("search the Sent folder: %w", err)
	}

	var mails []sentMail
	var skipped, failed int
	rows := page.Messages
	if len(rows) > sample {
		rows = rows[:sample]
	}
	for _, row := range rows {
		m, err := p.Read(ctx, row.ID, mail.ReadOpts{
			Format:   "text",
			MaxChars: detectReadMaxChars,
			Headers:  []string{"Message-ID"},
		})
		if err != nil || m == nil {
			failed++
			continue
		}
		if isMailbagMail(m) {
			skipped++
			continue
		}
		addr := strings.ToLower(strings.TrimSpace(m.From.Address))
		if addr == "" {
			failed++
			continue
		}
		mails = append(mails, sentMail{
			addr:  addr,
			name:  strings.TrimSpace(m.From.Name),
			date:  m.Date,
			shape: analyseBody(m.Body),
		})
	}

	prop := buildProposal(acct, alias, pids, mails)
	prop.head = append([]string{
		fmt.Sprintf("Sent folder %s: %d mails read, %d made by mailbag and skipped, %d not readable",
			serverText(strconv.Quote(sent)), len(mails), skipped, failed),
	}, prop.head...)
	return prop, nil
}

// isMailbagMail reports whether the Message-ID of m has the mailbag
// form (DI7.2).
func isMailbagMail(m *mail.Message) bool {
	ids := append([]string{m.MessageID}, m.Headers["Message-ID"]...)
	for _, id := range ids {
		if mailbagMessageID.MatchString(strings.TrimSpace(id)) {
			return true
		}
	}
	return false
}

// proposal is the result of detect for one account.
type proposal struct {
	alias  string
	def    string // default_identity, or ""
	defWhy string
	tables []*idProposal
	head   []string // information lines, already terminal safe
}

// idProposal is the proposed identity table of one address. Each
// "why" text is the evidence comment above its key. No why text holds
// server text, because it goes into accounts.toml as a comment.
type idProposal struct {
	email    string
	emailWhy string
	name     string
	nameWhy  string
	sig      string
	sigWhy   string
	html     string
	htmlWhy  string
	above    *bool
	aboveWhy string
	below    *bool
	belowWhy string
	sent     int      // sent mails of this address
	shown    []string // lines shown before the TOML, terminal safe
}

// group is one set of identical values in a vote.
type group struct {
	value      string
	count      int
	first, end time.Time
}

// vote groups the non-empty values. It gives the groups, largest
// first, and whether the largest one is at least 60 % of total and at
// least 5 mails (DI7.3 item 4).
func vote(values []string, dates []time.Time, total int) ([]group, bool) {
	idx := map[string]int{}
	var gs []group
	for i, v := range values {
		if v == "" {
			continue
		}
		j, ok := idx[v]
		if !ok {
			j = len(gs)
			idx[v] = j
			gs = append(gs, group{value: v})
		}
		gs[j].count++
		gs[j].add(dates[i])
	}
	sort.SliceStable(gs, func(a, b int) bool {
		if gs[a].count != gs[b].count {
			return gs[a].count > gs[b].count
		}
		return gs[a].value < gs[b].value
	})
	ok := len(gs) > 0 && gs[0].count >= voteMinMails && gs[0].count*100 >= total*voteMinPercent
	return gs, ok
}

// add widens the date range of g to d. A zero d changes nothing.
func (g *group) add(d time.Time) {
	if d.IsZero() {
		return
	}
	if g.first.IsZero() || d.Before(g.first) {
		g.first = d
	}
	if d.After(g.end) {
		g.end = d
	}
}

// dateRange gives ", 2026-08-01..2026-10-14" for the evidence of g, or
// "" when the mails have no date.
func (g group) dateRange() string {
	if g.first.IsZero() {
		return ""
	}
	return ", " + g.first.UTC().Format("2006-01-02") + ".." + g.end.UTC().Format("2006-01-02")
}

// buildProposal merges the provider identities and the analysed Sent
// mails into one proposal (DI7.3, DI7.4). An address gets a table when
// the provider reports it or when the account owns it. A Sent address
// that the account does not own gets an information line only, so
// detect never widens the From check on its own (I6).
//
// arch: DI7.3, DI7.4, DI8 I6
func buildProposal(acct config.Account, alias string, pids []mail.ProviderIdentity, mails []sentMail) *proposal {
	prop := &proposal{alias: alias}

	byAddr := map[string][]sentMail{}
	for _, m := range mails {
		byAddr[m.addr] = append(byAddr[m.addr], m)
	}
	provider := map[string]mail.ProviderIdentity{}
	tables := map[string]*idProposal{}
	for _, pi := range pids {
		email := strings.TrimSpace(pi.Email)
		if pa, err := netmail.ParseAddress(email); err != nil || pa.Name != "" || pa.Address != email {
			prop.head = append(prop.head, fmt.Sprintf("provider identity %s: not a bare address; not proposed", serverText(strconv.Quote(email))))
			continue
		}
		key := strings.ToLower(email)
		if _, dup := provider[key]; dup {
			continue
		}
		provider[key] = pi
		tables[key] = &idProposal{email: email, emailWhy: pi.Source}
	}
	for addr, ms := range byAddr {
		t, ok := tables[addr]
		if !ok {
			if !acct.OwnsAddress(addr) {
				prop.head = append(prop.head, fmt.Sprintf("%s: %d sent mails, but it is not an address of account %q; not proposed",
					serverText(strconv.Quote(addr)), len(ms), alias))
				continue
			}
			email := addr
			if strings.EqualFold(addr, acct.Email) {
				email = acct.Email
			}
			t = &idProposal{email: email}
			tables[addr] = t
		}
		t.sent = len(ms)
		var span group
		for _, m := range ms {
			span.add(m.date)
		}
		ev := fmt.Sprintf("%d sent mails%s", len(ms), span.dateRange())
		if t.emailWhy != "" {
			t.emailWhy += "; " + ev
		} else {
			t.emailWhy = ev
		}
	}

	keys := make([]string, 0, len(tables))
	for k := range tables {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t := tables[k]
		var pi *mail.ProviderIdentity
		if v, ok := provider[k]; ok {
			pi = &v
		}
		fillIdentity(t, pi, byAddr[k])
		prop.tables = append(prop.tables, t)
	}

	if len(prop.tables) >= 2 {
		prop.def, prop.defWhy = pickDefault(acct, prop.tables, provider)
	}
	sort.SliceStable(prop.tables, func(a, b int) bool {
		da := strings.EqualFold(prop.tables[a].email, prop.def)
		db := strings.EqualFold(prop.tables[b].email, prop.def)
		if da != db {
			return da
		}
		if prop.tables[a].sent != prop.tables[b].sent {
			return prop.tables[a].sent > prop.tables[b].sent
		}
		return strings.ToLower(prop.tables[a].email) < strings.ToLower(prop.tables[b].email)
	})
	return prop
}

// pickDefault chooses default_identity: the provider default, else the
// account email, else the address with the most sent mails.
func pickDefault(acct config.Account, ts []*idProposal, provider map[string]mail.ProviderIdentity) (string, string) {
	for _, t := range ts {
		if pi, ok := provider[strings.ToLower(t.email)]; ok && pi.Default {
			return t.email, pi.Source + " marks it as the default"
		}
	}
	for _, t := range ts {
		if strings.EqualFold(t.email, acct.Email) {
			return t.email, "the account email"
		}
	}
	best := ts[0]
	for _, t := range ts[1:] {
		if t.sent > best.sent {
			best = t
		}
	}
	return best.email, fmt.Sprintf("the address with the most sent mails (%d)", best.sent)
}

// fillIdentity sets the name, signature and reply layout of one table
// from the provider identity pi (nil when none) and the sent mails ms
// of that address (DI7.3, DI7.4).
func fillIdentity(t *idProposal, pi *mail.ProviderIdentity, ms []sentMail) {
	n := len(ms)
	names := make([]string, n)
	blocks := make([]string, n)
	dates := make([]time.Time, n)
	for i, m := range ms {
		names[i], blocks[i], dates[i] = m.name, m.shape.block, m.date
	}

	// Name: the provider name, else the Sent-mail vote.
	if pi != nil && strings.TrimSpace(pi.Name) != "" {
		t.name, t.nameWhy = pi.Name, pi.Source
	} else if gs, ok := vote(names, dates, n); ok {
		t.name = gs[0].value
		t.nameWhy = fmt.Sprintf("%d of %d sent mails%s", gs[0].count, n, gs[0].dateRange())
	}

	fillSignature(t, pi, blocks, dates, n)
	fillLayout(t, ms)
}

// fillSignature applies the DI7.4 merge of the provider signature and
// the Sent-mail vote, and the DI1.3 checks of signature and
// signature_html.
func fillSignature(t *idProposal, pi *mail.ProviderIdentity, blocks []string, dates []time.Time, n int) {
	gs, voted := vote(blocks, dates, n)
	vb, vWhy := "", ""
	if voted {
		vb = gs[0].value
		vWhy = fmt.Sprintf("%d of %d sent mails%s", gs[0].count, n, gs[0].dateRange())
	}
	pt, pWhy := "", ""
	if pi != nil {
		pt = config.NormalizeSignature(pi.TextSignature)
		pWhy = providerWhy(*pi)
		if pt == "" && strings.TrimSpace(pi.HTMLSignature) != "" {
			t.shown = append(t.shown, fmt.Sprintf("  the %s signature of %s is HTML with no exact text form; it is not used",
				pi.Source, serverText(t.email)))
		}
	}

	switch {
	case pt != "" && vb != "" && pt != vb:
		t.sigWhy = "signature: not proposed: the provider signature and the Sent-mail signature differ (both are shown above)"
		t.shown = append(t.shown, fmt.Sprintf("  provider signature of %s (%s):", serverText(t.email), pWhy))
		t.shown = append(t.shown, showLines(pt)...)
		t.shown = append(t.shown, fmt.Sprintf("  Sent-mail signature of %s (%s):", serverText(t.email), vWhy))
		t.shown = append(t.shown, showLines(vb)...)
		return
	case pt != "" && vb != "":
		t.sig, t.sigWhy = pt, vWhy+"; "+pWhy
	case pt != "":
		t.sig, t.sigWhy = pt, pWhy
	case vb != "":
		t.sig, t.sigWhy = vb, vWhy
	default:
		switch {
		case len(gs) == 0:
			t.sigWhy = fmt.Sprintf("signature: not proposed: no provider signature and no signature in %d sent mails", n)
		default:
			t.sigWhy = fmt.Sprintf("signature: not proposed: the largest group is %d of %d sent mails; %d %% and %d mails are necessary",
				gs[0].count, n, voteMinPercent, voteMinMails)
			for i, g := range gs {
				if i == voteShownGroups {
					break
				}
				t.shown = append(t.shown, fmt.Sprintf("  Sent-mail signature group %d of %s: %d of %d mails%s", i+1, serverText(t.email), g.count, n, g.dateRange()))
				t.shown = append(t.shown, showLines(g.value)...)
			}
		}
		return
	}

	if why := signatureProblem(t.sig); why != "" {
		t.shown = append(t.shown, fmt.Sprintf("  signature of %s:", serverText(t.email)))
		t.shown = append(t.shown, showLines(t.sig)...)
		t.sig, t.sigWhy = "", "signature: not proposed: "+why
		return
	}
	t.shown = append(t.shown, fmt.Sprintf("  signature of %s (%s):", serverText(t.email), t.sigWhy))
	t.shown = append(t.shown, showLines(t.sig)...)

	// signature_html comes only from the provider, only when its text
	// form is the proposed signature, and only when it passes the
	// DI1.3 item 4 checks.
	if pi != nil && pi.HTMLSignature != "" && pt == t.sig {
		if why := signatureHTMLProblem(pi.HTMLSignature); why == "" {
			t.html, t.htmlWhy = pi.HTMLSignature, pWhy
		} else {
			t.htmlWhy = "signature_html: not proposed: the provider HTML " + why
		}
	}
}

// providerWhy names the source of a provider signature. A Gmail one
// always carries the gmail_settings label (DI7.4).
func providerWhy(pi mail.ProviderIdentity) string {
	if strings.HasPrefix(pi.Source, "gmail") {
		return pi.Source + " (" + gmailSettingsLabel + ")"
	}
	return pi.Source
}

// signatureProblem gives the DI1.3 item 3 refusal of sig, or "".
func signatureProblem(sig string) string {
	if strings.ContainsRune(sig, 0) {
		return "it holds a NUL byte"
	}
	if strings.ContainsRune(sig, '\r') {
		return "it holds a lone CR"
	}
	for _, l := range strings.Split(sig, "\n") {
		if strings.HasPrefix(l, ">") {
			return "a line starts with \">\""
		}
	}
	if len([]rune(sig)) > 1000 {
		return "it is longer than 1000 characters"
	}
	return ""
}

// signatureHTMLProblem gives the DI1.3 item 4 refusal of html, or "".
// It applies the same checks as the load of accounts.toml, so a
// proposed signature_html never fails the strict load.
func signatureHTMLProblem(html string) string {
	if len(html) > 4000 {
		return "is longer than 4000 bytes"
	}
	if clean, _ := mime.AllowHTML(html); clean != html {
		return "holds markup that the HTML allowlist removes"
	}
	text, removed := mime.HTMLToTextCount(html)
	if removed > 0 {
		return "holds hidden or too deeply nested text"
	}
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, ">") {
			return "has a text line that starts with \">\""
		}
	}
	return ""
}

// fillLayout votes reply_above_quote and signature_below_quote from
// the mails with a quote (DI7.3 item 5). A key is proposed only when
// one side has the majority and at least 5 mails.
func fillLayout(t *idProposal, ms []sentMail) {
	var above, below, sigAfter, sigBefore int
	for _, m := range ms {
		s := m.shape
		if !s.hasQuote {
			continue
		}
		switch {
		case s.above && !s.below:
			above++
			if s.block != "" {
				if s.sigAfter {
					sigAfter++
				} else {
					sigBefore++
				}
			}
		case s.below && !s.above:
			below++
		}
	}
	if v, ok := majority(above, below); ok {
		t.above = &v
		t.aboveWhy = fmt.Sprintf("%d sent replies have the own text above the quote, %d below it", above, below)
	} else if above+below > 0 {
		t.aboveWhy = fmt.Sprintf("reply_above_quote: not proposed: %d sent replies above the quote, %d below it; a majority of %d is necessary",
			above, below, voteMinMails)
	}
	if t.above != nil && !*t.above {
		return
	}
	if v, ok := majority(sigAfter, sigBefore); ok {
		t.below = &v
		t.belowWhy = fmt.Sprintf("%d sent replies with the own text above the quote have the signature below the quote, %d above it", sigAfter, sigBefore)
	} else if sigAfter+sigBefore > 0 {
		t.belowWhy = fmt.Sprintf("signature_below_quote: not proposed: %d signatures below the quote, %d above it; a majority of %d is necessary",
			sigAfter, sigBefore, voteMinMails)
	}
}

// majority gives yes > no or no > yes, when the larger side has at
// least 5 mails.
func majority(yes, no int) (bool, bool) {
	switch {
	case yes > no && yes >= voteMinMails:
		return true, true
	case no > yes && no >= voteMinMails:
		return false, true
	}
	return false, false
}

// showLines gives the lines of sig for the terminal (DI7.5): each line
// goes through [serverText], an empty line gets a visible mark, and
// trailing white space is counted.
func showLines(sig string) []string {
	var out []string
	for _, l := range strings.Split(sig, "\n") {
		if l == "" {
			out = append(out, "    | (empty line)")
			continue
		}
		t := strings.TrimRightFunc(l, unicode.IsSpace)
		line := "    | " + serverText(t)
		if n := len([]rune(l)) - len([]rune(t)); n > 0 {
			line += fmt.Sprintf("  (+%d trailing white space)", n)
		}
		out = append(out, line)
	}
	return out
}

// render gives every line that detect prints: the information lines,
// the signatures, then the TOML (DI7.5).
func (p *proposal) render() []string {
	out := append([]string(nil), p.head...)
	for _, t := range p.tables {
		out = append(out, t.shown...)
	}
	if len(p.tables) == 0 {
		return out
	}
	out = append(out, "", fmt.Sprintf("# proposal for [accounts.%s] in accounts.toml:", p.alias))
	if p.def != "" {
		out = append(out, "# "+p.defWhy, "default_identity = "+tomlString(p.def), "")
	}
	out = append(out, strings.Split(strings.TrimRight(p.tablesText(), "\n"), "\n")...)
	return out
}

// tablesText gives the "[[accounts.<alias>.identity]]" tables as TOML
// text. Each key has its evidence comment above it. compose_html and
// the signature_on_* keys are left out (DI7.3 item 6).
func (p *proposal) tablesText() string {
	var b strings.Builder
	for i, t := range p.tables {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "[[accounts.%s.identity]]\n", p.alias)
		key(&b, t.emailWhy, "email", tomlString(t.email))
		if t.name != "" {
			key(&b, t.nameWhy, "name", tomlString(t.name))
		}
		if t.sig != "" {
			key(&b, t.sigWhy, "signature", tomlString(t.sig))
		} else if t.sigWhy != "" {
			comment(&b, t.sigWhy)
		}
		if t.html != "" {
			key(&b, t.htmlWhy, "signature_html", tomlString(t.html))
		} else if t.htmlWhy != "" {
			comment(&b, t.htmlWhy)
		}
		if t.above != nil {
			key(&b, t.aboveWhy, "reply_above_quote", strconv.FormatBool(*t.above))
		} else if t.aboveWhy != "" {
			comment(&b, t.aboveWhy)
		}
		if t.below != nil {
			key(&b, t.belowWhy, "signature_below_quote", strconv.FormatBool(*t.below))
		} else if t.belowWhy != "" {
			comment(&b, t.belowWhy)
		}
	}
	return b.String()
}

// key writes one evidence comment and one key line.
func key(b *strings.Builder, why, name, value string) {
	comment(b, why)
	fmt.Fprintf(b, "%s = %s\n", name, value)
}

// comment writes one comment line. why holds no line break.
func comment(b *strings.Builder, why string) {
	if why != "" {
		b.WriteString("# " + strings.ReplaceAll(why, "\n", " ") + "\n")
	}
}

// tomlString writes s as a TOML basic string. A line break is "\n", so
// an editor that cuts line ends cannot change a signature (DI7.5). A
// control character, a format character and each space other than
// U+0020 is a \u escape, so it is visible and no terminal acts on it.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == ' ':
			b.WriteRune(r)
		case unicode.IsSpace(r) || !unicode.IsGraphic(r) || unicode.Is(unicode.Cf, r):
			if r > 0xFFFF {
				fmt.Fprintf(&b, `\U%08X`, r)
			} else {
				fmt.Fprintf(&b, `\u%04X`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
