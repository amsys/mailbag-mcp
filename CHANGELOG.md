# Changelog

All notable changes to this project are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
