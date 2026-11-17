# Changelog

All notable changes to this project are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Every tool result has two zones. The first field `_fence` holds a
  nonce of 64 bits that is new for each response. Each string that a
  sender controls sits under the key `untrusted`, in a fence marked
  `[UNTRUSTED_<nonce>]`. A sender cannot guess the nonce, so a forged
  marker no longer matches.
- Every other string in a result must match a closed grammar. A runtime
  gate checks this on each result. A result that breaks a rule is
  refused with the error class `output_refused`.
- Error results start with the line `_fence: <nonce>`. Folder names no
  longer appear in ids or in plain fields.
- `unsubscribe` asks the human one question before it sends a
  one-click POST. The question shows the number of POSTs and the host
  of each. A decline sends no POST and gives each one-click row the
  status `declined` and its link. A client that cannot ask gets a
  refusal, unless the new key `[unsubscribe] allow_without_elicitation`
  is true. The `[bulk]` key does not cover this question.
- The Gmail `delete_filter` asks the human first.

### Changed

- The output shape of every tool changed. Sender text moved under
  `untrusted`. A model that reads a result must read both zones.
- The IMAP and Outlook message id is now
  `<uidvalidity>-<uid>-<hex of the folder name>`. The old form
  `<uidvalidity>.<uid>.<folder>` still works as input.
- A folder shows as `folder_ref` (`=` and hex of the name) plus the
  name under `untrusted.folder`. Input fields that take a folder accept
  a name or a `folder_ref`.
- Some byte budgets are larger, because the new form is longer.

## [0.2.0-alpha.1] - 2026-11-17

This is a pre-release for tests. `go install ...@latest` and the
"Latest" release on GitHub stay at 0.1.0.

Known issue: S/MIME verify needs OpenSSL 3.x. On a system with
OpenSSL 4, the signature status of an S/MIME message is `unsupported`.
Set `openssl_path` to an OpenSSL 3 program.

### Added

- The access level `classify`, between `read` and `draft`. It permits
  the read tools and `modify` changes that sort mail: a move to INBOX
  or to the junk folder, `read`, `starred` and labels. It refuses
  trash, delete, undo, `bulk`, `draft`, `send` and every folder write.

### Security

- At `classify`, a Gmail `add_labels` with a label that the account
  does not have fails, and the error lists the labels. The server
  creates no label at this level.
- A forged fence marker no longer passes the escape. The server folds
  look-alike letters (Cyrillic, Greek and others) and look-alike
  slashes to ASCII on a copy, and it accepts `_`, a space, `-` or no
  separator after UNTRUSTED. The same fold applies to the strip of
  outgoing text, which never rewrites the owner's own characters.
- A character with no glyph inside the marker word (a variation
  selector, a soft hyphen, a combining mark, a Hangul filler) no longer
  hides a forged fence marker from the escape or from the strip of
  outgoing text.
- The strip of outgoing text makes at most 16 passes. A mail body with
  thousands of nested markers made a reply or a forward use tens of
  seconds of processor time. Text with more nested levels than the
  limit loses every square bracket.
- More chat template tokens are escaped: `<tool_call>`,
  `<tool_response>`, `<function_calls>`, `<invoke`,
  `<function_results>`, `[TOOL_RESULTS]`, `<system>` and the
  line-initial `System:`, `### Instruction:` and `### Response:`.
  The line-initial `Human:` and `Assistant:` were escaped before.
- Server text that can quote a stranger goes through `guard.Sanitize`:
  provider error text in a note, folder names, the folder of a search
  row or a message, and label words. A folder name is now shown in its
  NFKC form.
- The outgoing text of `gmail_settings` (vacation subject and body,
  signature, filter criteria and labels) has fence markers stripped.
- `gmail_settings` asks the human to confirm `set_vacation` with
  `enabled` true, every `set_signature`, and a `create_filter` that
  marks mail as read or removes INBOX or UNREAD. The question shows
  the text that goes out. The `[bulk]` key `allow_without_elicitation`
  also covers these questions. The session grant of `bulk` does not.
- A test pins that no message byte reaches the arguments of `gpg` and
  `openssl`: mail data goes in through stdin only.
- A reply whose `Reply-To` address differs from the `From` address of
  the original, with no `to` given, gets a note in the `draft` result.
  The note shows no address.

### Changed

- The size budget of the release binary is 15,600,000 B (was
  15,000,000 B). The two dependency bumps below add about 450 KB.
- Update `github.com/ProtonMail/go-crypto` to v1.5.2. It fixes panics
  on malformed input in the OpenPGP verifier.
- Update `github.com/modelcontextprotocol/go-sdk` to v1.8.0. A session
  whose peer closes during a call now ends with the reason `peer-gone`.
- Update `github.com/emersion/go-smtp` and the `golang.org/x` modules.
  These are separate dependency updates. Neither main bump needs them.
- The `bulk` `dry_run` text warns that on JMAP a `from:` term matches
  whole words of the address.
- A release tag with a pre-release part, such as `v0.2.0-alpha.1`,
  makes a GitHub pre-release.
- The user guide has a section "Autonomous agents", a paragraph on
  `attach_dirs`, the three `gmail_settings` confirmations, the note
  that an empty Gmail label stays after an undo, and the note that the
  server does not open or scan a saved file.

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
