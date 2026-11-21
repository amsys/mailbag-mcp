# Changelog

All notable changes to this project are in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-alpha.2] - 2026-11-21

This is a pre-release for tests. `go install ...@latest` and the
"Latest" release on GitHub stay at 0.1.0. The output of every tool
changed: a client of 0.2.0-alpha.1 that reads a result by its keys
must change with it.

Known issue: S/MIME verify needs OpenSSL 3.x. On a system with
OpenSSL 4, the signature status of an S/MIME message is `unsupported`.
Set `openssl_path` to an OpenSSL 3 program.

### Removed

These changes break a client of 0.2.0-alpha.1 that reads a result by
its keys, or that sends a value that the server now refuses. The input
fields of the tools did not change. Every result has the new first key
`_fence`. Each text that a sender, a mail server or the model controls
is now under a key `untrusted`, in a fence. The Security section gives
the three exceptions.

Output keys that were removed or moved, by tool:

- `search`: each row lost `email` and `folder`. The sender, the
  subject and the preview are `untrusted.from`, `untrusted.subject`
  and `untrusted.preview`. The folder is `folder_ref` and
  `untrusted.folder`. Labels and keywords left `flags` and are in
  `untrusted.labels`. `flags` holds only the words `unread`,
  `starred`, `answered` and `draft`, with a space between them.
  `errors[].error` is a class word, not the error text. The text is in
  `errors[].untrusted.detail`.
- `read`: each message lost `headers`, `body` and `folder`. The
  headers are `untrusted.from`, `untrusted.to`, `untrusted.cc`,
  `untrusted.reply_to` and `untrusted.subject`, and a thread row of a
  message that the call did not name has `untrusted.preview`. The body
  is `untrusted.body`. The folder is `folder_ref` and
  `untrusted.folder`. Labels left `flags` and are in
  `untrusted.labels`. `untrusted.to`, `untrusted.cc`,
  `untrusted.reply_to` and `untrusted.labels` are lists with one fence
  for each entry. Each attachment lost `file`: the file name and
  the media type are `untrusted.name` and `untrusted.type`. An
  attachment `ref` that is not digits and dots is now `=` and the hex
  of the part id.
- `decrypt`: `body` is now `untrusted.body`. Each attachment lost
  `file` and `type`: they are `untrusted.name` and `untrusted.type`.
- `attachment`: `path` is gone. `dir` is the save root only,
  `untrusted.subdir` is the path below the root (absent when the file
  is in the root), and `untrusted.name` is the file name.
- `export`: each item of `files` lost `path`. It has `dir`,
  `untrusted.subdir` and `untrusted.name`, as in `attachment`.
- `folders`: each row lost `name`. The folder is `folder_ref` and
  `untrusted.name`.
- `gmail_settings`: each filter lost `from`, `to`, `subject`,
  `query`, `add_labels` and `remove_labels`. They are under the
  `untrusted` key of the filter. `vacation` lost `subject` and `body`.
  They are under `vacation.untrusted`. `signature` is now
  `untrusted.signature`.
- `bulk`: each `sample` row lost `from` and `subject`. They are under
  the `untrusted` key of the row.
- `modify` and `bulk`, the undo list (`operations` and `records`):
  `summary` is a fixed text with action words and a count. The folder
  and label names of the operation are in `untrusted.detail` of the
  row. A record of an earlier version has no `summary`, and its whole
  line is in `untrusted.detail`.
- `templates`: each row lost `subject`. It is `untrusted.subject`.
- `unsubscribe`: each row lost `url`. It is `untrusted.url`. Each row
  has the new key `index`, the place of its id in `ids`. The words of
  `method` and `status` have `_` in place of `-` and of the space:
  `one_click`, `draft_saved`, `see_link`, `not_authenticated` and
  `no_header`.
- `send`: `id` is present only when the provider gives a Message-ID
  (`<...@...>`). No provider gives one today, so a Gmail or JMAP result
  no longer has `id`.
- `export`: the file name comes from the new form of the message id.
  An IMAP message that was `1700000001.4211.INBOX.eml` is now
  `1700000001-4211-494e424f58.eml`.
- Keys that can now be absent: `date` of a `search` row and of a `read`
  message, `id` of a `read` message, of `decrypt`, of a `bulk` sample
  row and of an `unsubscribe` row, and `ref` of a `read` attachment
  (absent for a part id of more than 256 bytes).
- `draft`: the identity sentence of `note` no longer holds the From
  address. It gives the number of the rule that picked the address,
  and the address is in `untrusted.detail`.
- `read` and `decrypt`: a `signature.fingerprint` of fewer than 8 hex
  digits is left out.
- Every tool: `note` holds only texts from a fixed set, and the parts
  join with `"; "`. A provider text that matches no such text becomes
  `note withheld`. Provider text that a note names by its class word
  is in `untrusted.detail`.
- Every tool: an IMAP or Outlook message id has the new form
  `<uidvalidity>-<uid>-<hex of the folder name>`. The old form still
  works as input.
- Every tool: an error result is no longer the plain error text. Its
  first line is `_fence: <nonce>` and its second line is
  `error: <class>`. The class is one of `timeout`, `canceled`,
  `unknown_account`, `needs_auth`, `invalid_input`, `not_found`,
  `refused`, `limit`, `unavailable`, `output_refused`, `internal` and
  `error`. A fixed text of the server can come next. All other error
  text is in one fence after it. Only when the server cannot make a
  nonce, the error is `error: internal` with no `_fence` line.

Values that the server now refuses:

- A result with a string that breaks its rule: `output_refused`, and
  no part of the result is sent.
- A folder value that starts with `=` and is not a valid `folder_ref`
  (`=` and 2 to 1024 lowercase hex digits), in `folder` of `search`
  and `bulk`, `move_to` of `modify` and `bulk`, and the `name` of a
  `folders` rename or delete: `invalid_input`. Before, the value was a
  folder name.
- A new folder name (the `name` of a `folders` create, `new_name` of a
  rename) that starts with `=`, also after spaces, or that holds fence
  marker text, a hidden character or a control character:
  `invalid_input`.
- `move_to` of `modify` and `bulk`, and a name of `add_labels` of
  `modify`, that would make a folder or label with such a name:
  `invalid_input`, unless a folder or label with that name exists.
- An `attachment` `ref` that starts with `=` and is not `=` and 2 to
  512 lowercase hex digits: `invalid_input`.
- An account alias of more than 64 characters: the server refuses
  `accounts.toml`, and `account add`, `account test` and
  `identities detect` refuse the alias. `account remove` still takes
  it.
- A `templates` save with a name of more than 64 characters:
  `invalid_input`. Delete and draft still take such a name. A list
  leaves it out and says so in `note`.
- An `export` of an id that is not a valid message id:
  `invalid_input`. Take the id from a `search` row.
- A one-click `unsubscribe` in a client that cannot ask the human:
  `refused`, unless `[unsubscribe] allow_without_elicitation` is true.
- A Gmail `delete_filter` in a client that cannot ask the human:
  `refused`, unless `[bulk] allow_without_elicitation` is true. A
  `filter_id` that names no filter: `not_found`.
- A `draft` that the mail server saves with an id in a form that the
  server does not accept: an error with the class `error`. The draft
  is saved.
- An address, identity name, `reply_match` entry or save root from
  your own setup that holds a character that the check refuses:
  `output_refused` on the result that shows it.

### Security

- Every tool result has two zones. The first field `_fence` holds a
  nonce of 64 bits that is new for each response. Each string that a
  sender controls sits under the key `untrusted`, in a fence marked
  `[UNTRUSTED_<nonce>]`. A sender cannot guess the nonce, so a forged
  marker no longer matches.
- Three values are outside this rule. On the newer protocol, a result
  that asks the human a question (`send`, `bulk`, `unsubscribe`,
  `gmail_settings`) has no `_fence`, and its question can show sender
  text with no fence, because the human reads it. A template name is text
  that the model chose at the save, and it shows outside the fence in
  the `templates` list: it has at most 64 letters, digits, `-` and
  `_`. On Gmail and JMAP, an id that the call gave comes back outside
  the fence in a `modify` row with the state `gone` and in an
  `unsubscribe` row: it has at most 256 letters, digits, `-` and `_`.
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
- The Gmail `delete_filter` asks the human first. The question shows
  the filter id and the criteria and actions of the filter. A
  `filter_id` that names no filter gets the class `not_found`, and
  nobody is asked. The `[bulk]` key `allow_without_elicitation` also
  covers this question.
- The `dir` of an `attachment` or `export` result holds only the
  allowed save root. The path below the root that the call chose is in
  `untrusted.subdir`, inside a fence. A mail could ask the model to save
  into a directory whose name is an instruction; that name no longer
  shows outside a fence.
- A new folder name must not start with `=`: `folders` refuses such a
  create `name` or rename `new_name` with the class `invalid_input`.
  These two fields take no `folder_ref`.
- `move_to` of `modify` and `bulk`, and each name of `add_labels` of
  `modify`, must name a folder or label that exists when the name
  starts with `=`, or holds fence marker text, a hidden character or a
  control character. This applies to a plain name, a fenced name and a
  `folder_ref`. Else the call fails with the class `invalid_input`
  before it changes a message. So a move or a label cannot make such a
  Gmail label. On IMAP and JMAP such a keyword in `add_labels` is
  refused unless a folder has the same name.

### Changed

- `modify` removes the spaces at the start and the end of `move_to`,
  as `bulk` does. A `move_to` of ` INBOX` now moves to INBOX, also at
  the `classify` level. A new folder name that starts with `=` after
  spaces is refused.
- The output shape of every tool changed. Sender text moved under
  `untrusted`. A model that reads a result must read both zones.
- The IMAP and Outlook message id is now
  `<uidvalidity>-<uid>-<hex of the folder name>`. The old form
  `<uidvalidity>.<uid>.<folder>` still works as input.
- A folder shows as `folder_ref` (`=` and hex of the name) plus the
  name under `untrusted.folder`. Input fields that name an existing
  folder accept a name or a `folder_ref`.
- An IMAP or Outlook message in a folder whose name is longer than 512
  bytes has no valid id, as a message whose id does not parse.
  `search` leaves such a message out and sets `partial`, and `modify`
  leaves it out of `applied`. In `read`, in a `bulk` sample, in an
  `unsubscribe` row and in `decrypt`, the message stays but has no `id`
  (and in `read` no `folder_ref`). One such message does not make the
  whole result fail.
- The `in:` term of a search query takes a `folder_ref` on every
  provider. A value that starts with `=` is read as a `folder_ref`.
- `templates` save removes fence markers from the subject and the body
  before it writes the file. `modify` removes them from each name of
  `add_labels` and `remove_labels`.
- The fixed refusals of the server (send, idempotency key, Gmail
  settings, templates, unsubscribe, folders, an unknown account) give
  their guidance outside the fence, with a class word: `refused`,
  `invalid_input`, `limit`, `not_found`, `unknown_account` or
  `internal` (a send that stopped before it is known if the mail
  left). Model
  input that a refusal names, such as an alias or a template name, is
  in a fence after the text. Some texts changed: the send limit gives
  the account and the wait in the fenced part.
- Text from your own setup (the addresses, identity names and
  `reply_match` entries of `accounts.toml`, and the save roots) is
  checked free text, not a closed grammar. It must have no control
  character, no line or paragraph separator (U+2028, U+2029), no
  hidden character, no character that shows no glyph (such as a
  variation selector or U+2800), no fence marker and no chat template
  token, and it need not be in NFKC form, so a name such as
  `ACME™ Support` passes. A value that fails gives `output_refused`.
- The byte budgets are larger, because the new form is longer: the
  `tools/list` reply with every toolset on is at most 8704 B (was
  8192 B), the server instructions are at most 1024 B (was 640 B), and
  the stripped release binary is at most 16,000,000 B (was
  15,600,000 B).

### Fixed

- A Gmail settings change that the human accepts no longer ends with
  `error: internal` after Gmail made the change. The fault came with the
  two-zone form and was in no release.
- `attachment` decodes the `ref` that `read` gives as `=` and hex for a
  part id that is not digits and dots, for example a JMAP part id. Such
  an attachment can be saved again. A `ref` that starts with `=` and is
  not `=` and 2 to 512 lowercase hex digits is refused with the class
  `invalid_input`. The fault came with the two-zone form and was in no
  release.
- `folders` create, rename and delete: when the change is done but the
  folder list after it cannot be read, the call is a success. The
  `folders` list is empty, the new `note` says that the change is done
  and gives the error class, and the error text is in
  `untrusted.detail`. Before, the call gave an error, so a retry could
  fail or make a second folder.
- A plain folder or label name with a hidden character (a zero width
  non-joiner in a Persian label, for example) reaches the mail server
  unchanged, in `folder` of `search` and `bulk`, `move_to` of `modify`
  and `bulk`, the `name` of a `folders` rename or delete, and
  `add_labels` and `remove_labels` of `modify`. The server removed
  these characters, so the call acted on another folder or made a new
  Gmail label. The fault came with the two-zone form and was in no
  release.
- The setup page removes an account whose alias has more than 64
  characters, as `account remove` does.

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
