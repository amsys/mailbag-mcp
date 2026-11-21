<h1 align="center">mailbag-mcp</h1>

<p align="center">
  <a href="https://github.com/amsys/mailbag-mcp/actions/workflows/test.yml"><img src="https://github.com/amsys/mailbag-mcp/actions/workflows/test.yml/badge.svg" alt="test"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/go-1.27.1-00ADD8" alt="Go 1.27.1">
  <img src="https://img.shields.io/badge/status-alpha-orange" alt="Status: alpha">
</p>

Most mail MCP servers serve one mailbox for each server entry. A person
with many mailboxes must add many entries, and each entry puts its full
tool list into the model context.

mailbag-mcp is one MCP server for all your own mailboxes. One entry
reads, files, drafts and sends mail in every account, with a small tool
list. The design started from jgalea/mailbox-mcp.

A `search` with no `account` reads all mailboxes in one call:

```
search {"query": "is:unread from:billing"}

{"_fence": "3fa9c2e17b604d55", "rows": [
  {"id": "1700000001-4211-494e424f58", "account": "work",
   "folder_ref": "=494e424f58", "date": "2026-10-12T08:14:00Z", "flags": "unread",
   "untrusted": {
     "folder": "[UNTRUSTED_3fa9c2e17b604d55]\nINBOX\n[/UNTRUSTED_3fa9c2e17b604d55]",
     "from": "[UNTRUSTED_3fa9c2e17b604d55]\nBilling <billing@shop.example.com>\n[/UNTRUSTED_3fa9c2e17b604d55]",
     "subject": "[UNTRUSTED_3fa9c2e17b604d55]\nInvoice 2026-118\n[/UNTRUSTED_3fa9c2e17b604d55]"}},
  {"id": "1600000002-977-494e424f58", "account": "home",
   "folder_ref": "=494e424f58", "date": "2026-10-11T17:40:00Z", "flags": "unread",
   "untrusted": {
     "folder": "[UNTRUSTED_3fa9c2e17b604d55]\nINBOX\n[/UNTRUSTED_3fa9c2e17b604d55]",
     "from": "[UNTRUSTED_3fa9c2e17b604d55]\nbilling@power.example.org\n[/UNTRUSTED_3fa9c2e17b604d55]",
     "subject": "[UNTRUSTED_3fa9c2e17b604d55]\nYour October bill\n[/UNTRUSTED_3fa9c2e17b604d55]"}}
]}
```

## Features

- One MCP entry for N mailboxes: IMAP/SMTP, Outlook, Gmail and JMAP.
- 6 core tools are always on; 14 tools with every toolset on.
- Secrets in the system keyring, with a file fallback.
- An access level for each account: `read`, `classify`, `draft` or `send`.
  `classify` is for a junk sorter: it reads, and it moves mail only
  between INBOX and the junk folder.
- Two-zone results: a fresh random nonce in `_fence`, a fence marked with
  that nonce around each text that a sender controls (under `untrusted`),
  and a strict check of every other string before the result leaves.
- One static binary, with an optional daemon that shares one sign-in
  between all sessions.

## Install

```
go install github.com/amsys/mailbag-mcp@latest
```

Or download a release binary from
<https://github.com/amsys/mailbag-mcp/releases>. `@latest` does not
select a pre-release. To install one, give its tag, for example
`@v0.2.0-alpha.2`. Then add an account
and connect the client:

```
mailbag-mcp account add work --provider imap --email you@example.com --imap mail.example.com:993 --smtp mail.example.com:465
claude mcp add mailbag -- mailbag-mcp
```

On Linux, `mailbag-mcp service install` writes the systemd user units
of the optional daemon. Gmail and Outlook need your own OAuth client;
see the [user guide](docs/USER-GUIDE.md#oauth-client-disclaimer).

## Usage

The client starts `mailbag-mcp` with no argument. The server talks
JSON-RPC on its stdin and stdout. In Claude Code, add it with:

```
claude mcp add mailbag -- mailbag-mcp
```

Other clients take a command in their configuration. Most use this
shape:

```json
{
  "mcpServers": {
    "mailbag": { "command": "mailbag-mcp" }
  }
}
```

Then the model calls a tool, for example `search` as shown above. The
[user guide](docs/USER-GUIDE.md#client-setup) lists every tool.

## Documentation

- [User guide](docs/USER-GUIDE.md): accounts, clients, tools, troubleshooting.
- [Developer guide](docs/DEVELOPER-GUIDE.md): build, tests, design, release.
- [Documentation index](docs/README.md): all documents in `docs/`.

## License

MIT. See [`LICENSE`](LICENSE).
