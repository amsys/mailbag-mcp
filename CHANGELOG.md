# Changelog

All notable changes to this project are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-20

### Added

- One MCP server for many mailboxes: IMAP/SMTP, Outlook, Gmail (REST
  API) and JMAP.
- Six core tools that are always on: `accounts`, `folders`, `search`,
  `read`, `attachment` and `export`.
- Toolsets that are off by default and that `extras` in `accounts.toml`
  turns on: `decrypt`, `modify`, `send` (`draft` and `send`),
  `unsubscribe`, `bulk`, `templates` and `gmail_settings`.
- An access level for each account: `read`, `draft` or `send`.
- An undo journal for `modify` and `bulk`.
- The CLI: `account add|list|test|remove`, `oauth set`, `doctor`,
  `tools size`, `tools markdown`, `service install|uninstall` and
  `version`.
- A daemon, `mailbag-mcp serve`, on a Unix socket in
  `$XDG_RUNTIME_DIR`. All sessions share one sign-in. systemd socket
  activation is optional. The daemon stops after 15 minutes with no
  session.
- Secrets in the system keyring, with a file store as the fallback.
- `mailbag-setup`, a setup page in the browser for the account, the
  client and the daemon steps. It listens on `127.0.0.1` and needs a
  token.
- `account add --answers-stdin` and `oauth set --answers-stdin`: the
  setup page sends passwords and client secrets through stdin.
- `bulk` has `dry_run`: it counts the matches and lists up to 50 rows,
  and it changes nothing.
- One session holds at most 16 places of the store for pending sends
  and bulk changes. Another session still has room. A repeated call
  reuses its place and does not take a new one.
- Linux packages `.deb`, `.rpm` and `.pkg.tar.zst`, with `mailbag-mcp`
  and `mailbag-setup` in `/usr/bin`.
- A release gate: a tag must have a good SSH signature, and CI reads
  the allowed keys from `main`. The `release` environment needs an
  approval before the release goes public.
- Live tests of the JMAP provider against a Stalwart account. They
  need the build tag `live` and `MAILBAG_LIVE_JMAP`.

### Changed

- Compared with mailbox-mcp, the server that this project replaces: 6
  core tools instead of about 57, secrets in the keyring instead of in
  files, and a write gate for each account.
- The MCP entry connects to the daemon on Linux and macOS. It runs the
  server in its own process on Windows, when `XDG_RUNTIME_DIR` is not
  set, or when the daemon does not answer.

### Security

- The server puts all text that a sender controls between
  `[UNTRUSTED_...]` markers, removes hidden characters from it and
  defangs links in search results.
- `send` and `bulk` ask the person to confirm in the client. A client
  that cannot ask gets a refusal, unless the configuration permits it.
- No tool takes a password or a token. Secrets go in through the CLI
  only, and `oauth set` never prints a client id or a client secret.
- The daemon accepts a connection only from the same user, and its
  socket is never in `/tmp`.
- The JMAP client refuses a private or loopback address. With
  `private_host = true`, it permits a private address for the session
  host of that account only.
