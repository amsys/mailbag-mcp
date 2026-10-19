---
name: mailbag-mcp
description: Rules and traps of mailbag-mcp, each with the test that pins it. Load before editing internal/imap, internal/oauth, internal/gmail, internal/jmap, internal/guard, internal/tools, internal/config, internal/cli, internal/server, internal/shim, cmd/mailbag-setup or the release files of mailbag-mcp (.goreleaser.yaml, .github/workflows, scripts/coverage_gate.sh, scripts/release, size_test.go), and before changing a tool schema or a test bound.
---

# mailbag-mcp rules

Each line gives a rule and the test that holds it. Each rule came from a
real failure or from a verified property of a library. Do not remove a
rule because the code looks simpler without it. The source of each
group is `docs/features/mailbag/03-design.md` section 4, or the later
design file that the group names. A later design file is correct where
two files differ.

## Repo facts

- Run tests with `export TMPDIR=/tmp`. The OS limit of a socket path
  is 104 bytes (macOS) or 108 bytes (Linux). The e2e tests skip when the
  daemon socket path is longer than 100 bytes (`maxSocketPath`), and a
  skip is not a pass. A `TMPDIR` with a hidden component (a dot name)
  makes the attach path tests fail, because trap G7 refuses it.
- Each e2e launch gets its own `XDG_RUNTIME_DIR` (`shortRuntimeDir` in
  `e2e_test.go`). No test dials the live socket of the owner.
- `UPDATE_GOLDEN=1` rewrites `testdata/schema.golden.json`
  (`TestSchema_Golden`) and the tools block in `docs/USER-GUIDE.md`
  (`TestDocs_ToolsReferenceCurrent`). Read the diff before you keep it.
  Each new input field needs a text in `internal/cli/toolsdoc.go`
  (`TestToolsDoc_EveryFieldHasText`).
- `go run . tools size` prints the names bytes and the `tools/list`
  bytes for each toolset, then a total line with the instructions bytes.
  Core tools at most 4096 B, all toolsets at most 8192 B
  (`TestToolsList_Budget`). Raise a budget only with a decision record
  in `PLAN.md`. Never cut a rule, a limit, a unit or a default from a
  description to fit.
- `TestBinarySize_Budget` caps the stripped binary at 15,000,000 B. The
  history and each owner decision are in
  `docs/features/mailbag/size-baseline.md`. The owner puts run-time
  speed first and size second: do not trade speed for bytes without
  asking.
- Live tests: `go test -tags live` with `MAILBAG_LIVE_GMAIL=<alias>`
  (`internal/gmail`) or `MAILBAG_LIVE_JMAP=<alias>` (`internal/jmap`).
  `go test ./...` touches no network.
- Coverage: `go test -race -coverprofile=cover.out ./...`, then
  `scripts/coverage_gate.sh cover.out` (limit 80.0 %). CI runs the same
  script on Linux only.
- A timing bound in a test scales for its instrumentation: `raceFactor`
  for `-race`, and a further factor when `-race` makes coverage atomic
  (`TestHTMLToText_DeepNestingBounded`). Never widen a bound for the
  plain run without a measured cause.
- Release: `.goreleaser.yaml` sets `-trimpath` and `-s -w`, and never
  `-X`. The version comes from the Go build info, so a dirty tree gives
  `+dirty`. Each action in `.github/workflows` is pinned by commit hash.
- Release workflow: verify, test (`test.yml` through `workflow_call`),
  build, publish. verify runs `scripts/release/verify-tag.sh` from
  `origin/main`: the tag must be on main, have a CHANGELOG section and
  carry an SSH signature that `git verify-tag` accepts against
  `.github/allowed_signers` (principal `dev@amsys.cz`, key
  `~/.ssh/id_ed25519_amsys_sign`). Tag with `git tag -s` and
  `gpg.format=ssh`. GoReleaser makes a draft release; publish runs in
  the environment `release` and needs the owner's approval (IS12.5).
- Packages: `nfpms` makes `.deb`, `.rpm` and `.pkg.tar.zst`. They put
  `mailbag-mcp` and `mailbag-setup` in `/usr/bin`, the licence and the
  docs under `/usr/share`, and no systemd units: the user runs
  `mailbag-mcp service install`, which writes the units with the path
  of the running binary (DF.2). Each archive holds both binaries.
- Lint runs locally with `trueup lint`; CI runs only a pinned gitleaks
  (`.github/workflows/secrets.yml`, `.github/gitleaks.toml`).
- The build records (`docs/features/`, `PLAN.md`, `.state/`) are not in
  the public repo. They are in a second git dir over the same paths:
  `git --git-dir=.git-private ...`.
- CI runs staticcheck `v0.8.2` and govulncheck `v1.9.0`, pinned by
  version in `test.yml`; run them before a push. staticcheck refuses a
  raw invisible character in a string literal (ST1018): write U+200B as
  `​`, U+202E as `‮`.
- No published document holds a real client id, secret, token or mail
  address (`TestDocs_NoRealSecrets` scans README.md, SUPPORT.md,
  CHANGELOG.md, docs/*.md and each SKILL.md). Test fixtures use made-up
  ids that end in `test-client.apps.googleusercontent.com`. No test
  scans the fixtures: check them by hand.

## A. Process and transport

- A1 Stdout carries JSON-RPC only. No `fmt.Print*` and no `os.Stdout`
  outside `internal/cli` and the `main.go` functions `printVersion` and
  `stdio`. `TestNoStdoutWrites`,
  `TestE2E_StdoutIsOnlyJSONRPC`.
- A2 Ignore `SIGINT` and `SIGHUP`: the client runs in the terminal's
  process group. `TestE2E_SurvivesSIGINT`, `TestE2E_SurvivesSIGHUP`.
- A3 Exit 0 on `SIGTERM` and on stdin EOF. `TestE2E_SIGTERMExits0`,
  `TestE2E_StdinEOFExits0`.
- A4 A parent watchdog ends a server whose client was killed.
  `TestWatchdog_ParentChange`.
- A5 `signal.Ignore(SIGPIPE)`; a closed stderr never stops the server.
  `TestE2E_ClosedStderrKeepsServing`.
- A7 `recover` in the tool wrapper and in each background goroutine.
  `TestWrapper_RecoversPanic`, `TestPool_ReaperSurvivesPanic`,
  `TestWatchdog_PanicLogged`.
- A8 A deadline for each call and a limit on each fan-out; give a part
  of the result with a note. `TestSearch_DeadlineReturnsPartial`,
  `TestGmail_SearchFanOut10`.
- A9 No network and no keyring before the first tool call. The test
  checks only that the `initialize` reply comes in under 1 s.
  `TestE2E_InitializeUnder1s`.
- A10 One file for each record; temporary file, then rename.
  `TestUndo_ParallelWriters`, `TestFileStore_ParallelSet`.
- A11 Let the SDK select the protocol version; e2e tests send
  `initialize` with `2025-06-18`. The test checks the reply, not the
  version that the SDK selects. `TestE2E_LegacyInitialize`.
- A12 A field with no `omitempty` becomes required, and the SDK then
  refuses a call without it. Required today: `account`, `id`, `ref`,
  `action`, `draft_id`, `idempotency_key`, `ids`; `search` and
  `accounts` have no required field. A change shows as a diff in
  `TestSchema_Golden`.
- A13 Wait on a signal, or poll with a deadline; do not add a fixed
  sleep. The e2e helper waits for the first stdout line and keeps
  reading. Some server tests still sleep (`server_test.go:169`).
- A14 `MAILBAG_DEBUG=1` makes the shim run the in-process server: the
  daemon has no stderr, so its wire debug reaches nobody. Never write
  wire traffic to `server.log`. `TestShim_DebugRunsInProcess`.

## B. Secrets and sign-in

- B1 Store the refresh token only; a value too big for the keyring
  gives an error that names `MAILBAG_SECRETS=file`.
  `TestKeyringStore_TooBig`.
- B2 A locked keyring waits for a desktop dialog. Each keyring call
  stops after 30 s, in the server and in the CLI, and a timeout is never
  `ErrNotFound`. `TestKeyringStore_Timeout`.
- B3 A locked or failed keyring is an error, never a silent change to
  the file store. The test checks the error; nothing checks that the CLI
  records its choice. `TestServer_NoSilentFallback`.
- B4 No tool takes a secret. `TestSchema_NoSecretFields`.
- B5 Secrets come from a terminal, or from one strict JSON document on
  stdin with `account add --answers-stdin` (`{"secret": S,
  "use_file_store": B}`, design DS13.5). The flag replaces
  `Env.ReadSecret` and `Env.Confirm`; there is no line parsing, an
  unknown key, a second document or an oversize input exits 2 before
  any file write, and a prompt the document does not answer is an
  error. A secret never goes in argv or the environment. Without the
  flag a pipe is still refused. Check the alias before each prompt; a
  failed login removes the new account. `TestCLI_AddRefusesPipe`,
  `TestCLI_AliasBeforePrompt`, `TestCLI_LoginFailRollsBack`,
  `TestCLI_AnswersStdin_WritesAccount`,
  `TestCLI_AnswersStdin_BadDocumentRefused`,
  `TestCLI_AnswersStdin_OversizeRefused`,
  `TestCLI_AnswersStdin_PasteUnanswered`, `TestCLI_AnswersStdin_Confirm`.
- B6 The redactor replaces each registered secret.
  `TestCLI_PasswordNeverPrinted`.
- B7 Save a rotated refresh token; keep the old one when none comes
  back; a failed save is a warning. `TestTokenSource_RotationPersists`,
  `TestTokenSource_KeepsOldWhenAbsent`,
  `TestTokenSource_KeepsOldWhenAbsent_FailedSaveWarns`.
- B8 On `invalid_grant` read the store again and retry once, then
  `needs_auth`. `TestTokenSource_InvalidGrantRereads`,
  `TestTokenSource_InvalidGrantTwiceNeedsAuth`.
- B9 A Google project in "Testing" gives 7-day tokens; the `needs_auth`
  text names it. The Gmail token function of the Factory gives
  `oauth.GoogleNeedsAuth`, and doctor adds `GoogleTestingText` to its
  hint. `TestGoogleNeedsAuthTextNamesTesting`, `TestGoogleNeedsAuth_Error`,
  `TestFactory_GmailNeedsAuthNamesTesting`,
  `TestDoctor_GmailNeedsAuthNamesTesting`.
- B10 Google: always `access_type=offline` and `prompt=consent`.
  `TestGoogleConfig_OfflineConsent`.
- B11 Microsoft loopback listens on both `127.0.0.1` and `::1`.
  `TestLoopback_DualBind`.
- B11a The loopback checks `state` before it reads `error=`. A local
  process that does not know the state cannot put its text in the
  sign-in error. `TestLoopback_ErrorNeedsState`.
- B12 Own SASL clients for XOAUTH2 and LOGIN, used by IMAP and SMTP.
  `TestXOAUTH2_InitialResponse`, `TestXOAUTH2_EmptyReplyToChallenge`,
  `TestLOGIN_Steps`.
- B13 SMTP `535 5.7.139` becomes a text that names the tenant setting.
  `TestSMTP_Error57139Text`.
- B14 The pool gets a new token before each dial.
  `TestPool_RedialGetsFreshToken`.
- B15 The IMAP debug writer drops all data until the login is complete.
  `TestDebugWriter_DropsAuth`.
- B16 The secrets file must be 0600 in a 0700 directory. The store
  refuses a key file with any group or other bit, and a directory that
  group or other can write (they could replace a key file). A 0755
  directory passes the store (`t.TempDir()` makes 0755) and `doctor`
  reports it. Write it with a temporary file and a rename (no test holds
  the rename). `doctor` checks the mode of the store's key files only
  (an alias or an `oauth.` name), so a 0644 `signature_file` in the
  same directory passes. `TestFileStore_RefusesWideMode`,
  `TestFileStore_RefusesWritableDir`, `TestFileStore_Modes`,
  `TestDoctor_FileStoreModeOnlyKeys`.
- B17 Alias pattern `^[a-zA-Z0-9_-]+$`, checked in config, CLI and each
  tool. `account add` also refuses an alias that equals an existing
  alias under case folding: on APFS and NTFS `Work` and `work` are one
  secret file. `TestAlias_Pattern`, `TestCLI_AliasBeforePrompt`,
  `TestTools_UnknownAccount`, `TestCLI_AddRefusesAliasCaseFold`.
- B18 Never re-encode `accounts.toml`: append and cut text blocks, then
  parse and compare. `account remove` finds the alias and the store
  kind with the lenient decode (`config.PeekFile`), never the strict
  load, so a broken account can still be removed. The write resolves a
  symlinked `accounts.toml` first, so the link stays a link, and syncs
  the temporary file before the rename (no test holds the sync).
  `TestConfig_AddKeepsComments`, `TestConfig_SpliceKeepsSymlink`,
  `TestConfig_RemoveCutsOnlyBlock`, `TestConfig_SpliceMismatchAborts`,
  `TestCLI_RemoveBrokenAccount`.

## C. IMAP (`internal/imap`)

- C1 UID commands only, never a sequence set.
  `TestIMAP_UsesUIDCommands`.
- C2 Always `BODY.PEEK[...]`. `TestIMAP_ReadKeepsUnseen`.
- C3 `EXAMINE` for reads. `TestIMAP_ReadsUseExamine`.
- C4 The id holds `uidvalidity`; a stale id fails.
  `TestIMAP_StaleIDRefused`.
- C5 A move returns the new id from `COPYUID`.
  `TestIMAP_MoveReturnsNewID`.
- C6 An empty query and `*` parse as empty, so the search lists the
  newest messages. The test checks the parse only.
  `TestQuery_EmptyListsRecent`.
- C7 A non-ASCII query also gets a client scan.
  `TestIMAP_NonASCIIFallback`, `TestIMAP_ASCIIEmptyNoFallback`.
- C8 `SINCE` and `BEFORE` have day precision: filter on `INTERNALDATE`
  in the client. `TestIMAP_SincePrecise`.
- C9 Unread counts are live, never from `SELECT`.
  `TestIMAP_UnreadCountIsLive`.
- C10 Folder role: the config table of the account wins, then the
  special-use flag, then the name table. The name table gives no role
  that a flag gives to a folder of the list, and reads only a top-level
  folder or a folder directly below `INBOX` ("Bin" is not trash when a
  `\Trash` folder exists). Keep no role cache: roles come from `LIST`
  on each call, and each folder write clears the selected folder.
  `TestFolders_RoleDiscovery`, `TestFolders_SpecialUseWinsOverNameTable`,
  `TestFolders_CacheCleared`.
- C11 Use the `LIST` delimiter and the `NAMESPACE` prefix.
  `TestFolders_DelimiterAndPrefix`.
- C12 Never a plain `EXPUNGE`. With no `MOVE`: `UID COPY`,
  `UID STORE \Deleted`, then `UID EXPUNGE` when `UIDPLUS` exists. With
  no `UIDPLUS` the old copy stays and `expunge_pending` is true.
  `TestIMAP_MoveFallbackNoPlainExpunge`.
- C13 `save_sent = auto` with the host list.
  `TestSendDraft_SavedToSentRules`.
- C14 A failed Sent copy still returns `sent: true` with a warning.
  `TestSendDraft_AppendFailureStillSent`.
- C15 A draft id comes from `APPENDUID` or a `Message-ID` search.
  `TestDraft_IDIsUsable`.
- C16 Remove `Bcc:` from the SMTP copy, keep it in the Sent copy.
  `TestSendDraft_StripsBcc`.
- C17 Check `PERMANENTFLAGS` before a keyword. Read it from a
  `SELECT`, also in the capability report: many servers answer
  `EXAMINE` with `PERMANENTFLAGS ()` (RFC 3501), and the memory server
  hides this. `TestIMAP_KeywordNeedsPermission`,
  `TestCaps_KeywordsFromSelect`.
- C18 One mapping in the tool layer for the pseudo labels `UNREAD`,
  `STARRED`, `INBOX` and `TRASH`. A verb with its opposite, or two move
  targets, is refused. `TestModify_PseudoLabels`.
- C19 Attachment by file name or part path; an unknown one lists the
  names. `TestAttachment_ByNameOrPart`, `TestAttachment_UnknownListsNames`.
- C20 Preview rules. `TestPreview_Golden`. A `read` thread row of a
  message that the caller did not name shows the preview of the thread
  search as a `preview:` line in its header fence; the named message
  keeps its full body (R16-M7). `TestRead_ThreadRowsShowPreview`.
- C21 Import the charsets; an unknown charset gives the raw bytes.
  `TestDecode_Latin2`, `TestDecode_UnknownCharsetNoError`.
- C22 A bad address header gives a parse error, and the reader shows
  the raw text (no test holds the raw text); the date comes from
  `INTERNALDATE`. `TestParse_BadAddressList`,
  `TestRead_DateIsInternalDate`.
- C23 `LIST-STATUS`, or `STATUS` in batches of 8.
  `TestFolders_StatusBatches`.
- C24 Pool: reuse within 60 s, probe after, reconnect on a failed or
  slow probe, close after 15 min, one connection per alias, one
  reconnect for callers that come together, never repeat a write.
  `TestPool_ReuseWithin60s`, `TestPool_ProbeAfter60s`,
  `TestPool_ReconnectWhenProbeFails`, `TestPool_ProbeTimeoutReconnects`,
  `TestPool_IdleCloseAfter15Min`, `TestPool_PerAliasConnections`,
  `TestPool_ConcurrentCallersShareOneReconnect`,
  `TestPool_WriteNeverRetries`.
- C24a Idle time uses the wall clock: the monotonic clock stops during
  suspend, so a socket that died in sleep looked fresh (T199).
  `TestNewPool_ClockIsWallOnly`, `TestPool_ProbeWhenClockStepsBack`,
  `TestPool_ReaperClosesOnClockStepBack`.
- C25 go-imap commands cannot be cancelled: `context.AfterFunc` closes
  the socket. When `fn` returns nil and the context ended after it, the
  pool drops the connection but returns nil: an error makes the caller
  send a done write again. `TestPool_ContextCancelClosesConn`,
  `TestPool_SuccessAfterCancelReportsSuccess`.
- C26 Pin go-imap at `v2.0.0-beta.8`. Non-test code imports it only
  in `internal/imap`. The Factory dial and login use the alias
  `imap.Client`. Test files use the go-imap memory server as a fake.
- C27 `tls_ca` for a private CA; never skip verification.
  `TestTLS_CustomCA`, `TestTLS_NoInsecureOption`.
- C28 Take the highest N UIDs; fetch data for the page only.
  `TestSearch_LargeResultBounded`.

## M. SMTP and message building (`internal/imap`, `internal/mime`)

- M1 Port 465 is TLS; other ports need `STARTTLS` or fail.
  `TestSMTP_RequiresSTARTTLS`.
- M2 `PLAIN`, then `LOGIN`. `TestSMTP_AuthFallback`.
- M3 No automatic retry of a send. `TestSend_NoRetry`.
- M4 Always write `Message-ID`, `Date`, `MIME-Version`.
  `TestBuild_AlwaysMessageID`.
- M5 A reply has `In-Reply-To` and `References` (the first id plus the
  last 20). `TestReply_ThreadHeaders`.
- M6 Reply-all removes duplicates and the account itself.
  `TestReplyAll_DedupeAndSelf`.
- M7 A forward attaches the files again. `TestForward_KeepsAttachments`.
- M8 The library encodes headers and file names.
  `TestBuild_NonASCIISubjectAndFilename`.
- M9 Text and HTML together when `html` is given.
  `TestBuild_Alternative`.
- M10 An embedded CR, LF or NUL in a header value is refused, not
  removed. Trailing white space, CR and LF are trimmed.
  `TestValidate_RejectsCRLF`.
- M11 25 MB for a file and a message, and the server `SIZE`.
  `TestAttach_Caps`, `TestSMTP_SizeLimit`.
- M12 10 sends a minute for each account. `TestSend_RateLimit`.
- M13 Outside identity mode (N1), `from` is empty, the account
  address or one of the flat `identities`, and it goes to the provider
  as given. In identity mode the draft tool picks the identity (N6).
  IMAP and Outlook `envelopeFrom` calls `Account.OwnsAddress` in both
  modes; outside identity mode `OwnsAddress` is the raw compare with
  the account email and the flat list. The SMTP envelope sender is
  always the bare address. Gmail (E6) and JMAP
  keep their own provider checks. `TestSend_FromMustBeIdentity`,
  `TestEnvelopeFrom_OwnsAddress`, `TestSaveDraft_IdentityFromHeader`.
- M14 Remove fence markers from the outgoing subject and body.
  `TestSend_StripsFenceMarkers`.
- M15 Parse address lists with the library; anchored reply prefix.
  `TestHeaders_AddressListQuotedComma`, `TestHeaders_RePrefix`.
- M16 Quoted-printable for text, so no line passes 998 characters.
  `TestBuild_LongLines`.

## E. Gmail (`internal/gmail`, design `03-design-S7S8.md`)

- E1 A thin REST client by hand, no Google client library, for load
  time. No test checks the dependency; `go.mod` has none.
  `TestE2E_InitializeUnder1s` times the start only.
- E2 A limit of 10 on each fan-out path. `TestGmail_SearchFanOut10`,
  `TestGmail_FoldersFanOut10`.
- E3 `batchModify` with 1000 ids at most. `TestGmail_BatchModifyChunks1000`.
- E4 Label names become ids first; an unknown name lists the labels; a
  user label named "Trash" is not the system label. A new label of
  `add_labels` or `move_to` is created only just before `batchModify`,
  so a refused change or a change on gone ids leaves no empty label.
  `TestGmail_LabelNameToID`, `TestGmail_UnknownLabelListsLabels`,
  `TestGmail_LabelNamedTrashIsNotSystem`,
  `TestGmail_NoLabelCreatedWithoutWrite`.
- E5 A filter never adds `TRASH` or `SPAM` and never forwards.
  `TestGmailSettings_FilterRefusesTrashSpam`,
  `TestGmailSettings_LabelNamedTrash`, `TestGmailSettings_NoForwardField`.
- E6 The send-as check runs before a draft is stored and before a send;
  the list is kept 10 minutes. `TestGmail_FromNotVerified`,
  `TestGmail_SendAsCached10Min`.
- E7 Unescape the `snippet`. `TestGmail_SnippetUnescaped`.
- E8 Body data is base64url with no padding.
  `TestGmail_Base64URLNoPadding`.
- E9 A large part comes through the attachment call.
  `TestGmail_LargePartViaAttachment`.
- E10 A draft goes up as one `multipart/related` upload: JSON metadata,
  then `message/rfc822`. A send is `drafts.send` with the draft id and
  uploads nothing. `TestAPI_RequestShapes`.
- E11 Backoff on 429, on the rate 403 and on 5xx; `Retry-After` wins;
  `drafts.send` is retried only on 429. `TestAPI_BackoffOn429`,
  `TestAPI_403RateIsRetried`, `TestAPI_5xxRetried4Times`,
  `TestAPI_RetryAfterWins`, `TestAPI_SendRetriesOnlyOn429`.
- E12 The date of a result is the internal date of the server
  (`INTERNALDATE` or Gmail `internalDate`). No result carries the
  sender's `Date` header today; if one ever does, it goes inside the
  fence. `TestRead_DateIsInternalDate`.
- E13 A filter with absent parts lists with no error; the row holds
  only the parts that exist. `TestGmailSettings_FiltersMissingParts`.
- E14 A 401 refreshes once; a second 401 gives `needs_auth`.
  `TestAPI_401ForgetsAndRetriesOnce`, `TestAPI_Second401IsNeedsAuth`.
- E15 No Google server message, project number or client id reaches a
  result, a terminal line or the log. `TestAPI_ErrorTextHasNoServerMessage`,
  `TestFactory_GmailSecretsRedacted`, `TestCLI_OAuthSetGoogleNeverPrintsID`.
- E16 Gmail API off in the project is a fixed error and an `api_off`
  state. `TestAPI_AccessNotConfiguredIsFixedError`,
  `TestFactory_GmailAuthStates`.
- E17 `move_to X` adds X and removes INBOX, TRASH and SPAM (each one
  that is not X). Gmail keeps a label that the change does not remove,
  so without this a move from Trash gives `[TRASH INBOX]`.
  `TestGmail_MoveTakesOutOfTrashAndSpam`.

## F. JMAP (`internal/jmap`, design `03-design-S7S8.md`)

- F0 The client is written by hand on `net/http` (no go-jmap), through
  the guarded HTTP client. `TestFactory_JMAPClientIsGuarded`.
- F0a Stalwart refuses concurrent calls with
  `urn:ietf:params:jmap:error:limit`; `postCapped` retries them and
  counts each retry in the package variable `limitRetries`. Live tests
  in `internal/jmap/live_stalwart_test.go` (tag `live`,
  `MAILBAG_LIVE_JMAP=<alias>`, package `jmap_test`; `export_test.go`
  gives `LimitRetries()`): `TestLive_LimitRetry` (read only) and
  `TestLive_MoveOutOfJunkSetsNotJunk`, which creates its own message
  and destroys it in `t.Cleanup` and touches no other message.
- F1 A submission has `identityId`, and `using` has submission.
  `TestJMAP_SubmissionIdentity`, `TestJMAP_UsingHasSubmission`.
- F2 `onSuccessUpdateEmail` files the sent message.
  `TestJMAP_SentFiling`.
- F3 Plain text comes from the text/plain parts of `textBody`; an
  HTML-only message becomes text with hidden runs removed, never HTML
  source. `TestJMAP_HTMLOnlyBody`.
- F4 Every URL is https and passes the guard; no redirects.
  `TestJMAP_ServerURLGuard`, `TestJMAP_NoRedirects`.
- F4a A private host needs `private_host = true` (JMAP only), and then
  only that host. `TestNewHTTPClientFor_PrivateHostOnlyThatHost`,
  `TestNewHTTPClientFor_PrivateHostStillRefusesLoopback`,
  `TestLoad_PrivateHostJMAPOnly`.
- F5 Bearer token for Fastmail. `TestJMAP_BearerAuth`.
- F6 Upload the blob, then use the `blobId`. `TestJMAP_AttachmentBlob`.
- F7 A folder filter with text uses the AND operator form.
  `TestJMAP_AndFilter`.
- F8 No archive role: fail with a hint. Never remove the last mailbox.
  `TestJMAP_ArchiveMissing`, `TestJMAP_NeverRemovesLastMailbox`.
- F9 A label in `add_labels` and in `remove_labels` (in any case) is
  refused, as Gmail refuses it; a patch with both keys would let one
  side win with no error. `TestJMAP_AddAndRemoveSameLabelRefused`.
- F10 A search span (`newer_than`, `older_than`) or size (`larger`,
  `smaller`) past the int64 bound is refused; it must never wrap to a
  date in the future or a negative size. The size bound is that of
  Gmail `sizeBytes`. imap and jmap share `mail.ParseSpan` and
  `mail.ParseSize`. `TestJMAP_QuerySpanAndSizeBounds`,
  `TestSearch_BadTermFails`.
- F11 A header property can come back in the short form. Stalwart
  answers `header:<Name>:all` to a request for
  `header:<Name>:asRaw:all` (asRaw is the RFC 8621 default form).
  `headerInstances` reads the exact key first, then either form with no
  regard to case. Without it, `List-Unsubscribe` and
  `Authentication-Results` are always empty on Stalwart.
  `TestJMAP_ReadHeadersShortForm`.
- F12 The client caps the API requests in flight at the session's
  `maxConcurrentRequests` (4 when absent or 0), and sends a request
  again only after the `urn:ietf:params:jmap:error:limit` request
  error: at most 4 tries, waits of 100, 200 and 400 ms, and ctx ends
  the wait. Stalwart gives the limit error to about 4 concurrent
  searches. Upload and download are not capped.
  `TestJMAP_ConcurrentCallsCapped`, `TestJMAP_LimitErrorRetried`,
  `TestJMAP_LimitErrorRetryBounded`, `TestJMAP_LimitRetryStopsOnCancel`,
  `TestJMAP_OtherRequestErrorNotRetried`.
- F13 A search with no folder searches INBOX, as IMAP does (only Gmail
  searches all mail). Bulk with no folder follows it.
  `TestJMAP_SearchDefaultsToInbox`.
- F14 A `from:` term matches whole words of the address on Stalwart,
  not a substring: `-from:mailer` does not exclude
  `noreply@mailer.example.com`; `-from:mailer.example.com` does. The NOT filter
  is correct (`TestJMAP_NotFilter`); this is server tokenisation.

## G. Guard (`internal/guard`, `internal/tools`)

- G1 The server `instructions` tell the model the fence rule.
  `TestServer_InstructionsPresent`, `TestInstructions_BudgetR1`.
- G2 Escape copies of the markers with U+27E6, in any case.
  `TestFence_Escape`, `FuzzFence`.
- G3 Each field a sender controls is fenced, in results and errors, on
  every toolset. `TestTools_EveryUntrustedFieldFenced`,
  `TestServer_EveryUntrustedFieldFenced`.
- G4 Remove hidden characters (tag block, bidi, zero width).
  `TestInvisible_Table`, `FuzzInvisible`.
- G4a HTML text hidden by style counts as hidden; a value that cannot
  be read fails closed. `TestHTMLToText_UnparsedColorFailsClosed`,
  `TestHTMLToText_NoLeakAgainstTreeBuilder`.
- G5 Redact each error and each log line. The tests check the redactor
  only (token shapes, registered values, home directory), not each
  caller. `TestRedact_Patterns`, `TestRedact_Values`.
- G6 Save path: the directory must resolve, after links, inside a
  permitted root; a link out of the root fails. The part below the
  root must have no hidden component (`~/.config/autostart` with the
  root `~`); a dot in the root itself passes. Create never follows a
  link at the file name and never overwrites (a taken name gets " (1)").
  A directory swapped for a link after the check fails. A sender file
  name that cleans to nothing (`..`, only invisible characters) saves
  as "attachment". `TestSavePath_Attacks`, `TestSavePath_NoFollowOnCreate`,
  `TestSavePath_ExistingFileNeverOverwritten`,
  `TestSavePath_SwappedDirSymlink`, `TestSaveName_Table`,
  `TestSavePath_HiddenBelowRootRefused`, `TestAttachment_BadNameFallsBack`.
- G7 Attach path: refuse a hidden path component. Refuse a path under
  `config.ConfigDir()` or `config.StateDir()`, after links: the macOS
  config dir has no dot component and holds the secrets file. When
  `attach_dirs` is set, the file must be under one of its entries.
  `TestAttachPath_HiddenRefused`, `TestAttachPath_AllowList`,
  `TestAttachPath_RefusesConfigAndStateDirs`.
- G8 Check the address at dial time and dial the checked IP; no proxy.
  The guarded transport passes `CloseIdleConnections` on to the
  transport below it; `http.Client` drops the call on a transport
  without the method. `TestSSRF_DialGuard`, `TestSSRF_NoProxy`,
  `TestNewHTTPClientFor_DialsCheckedIPOnly`,
  `TestGuardedTransport_ForwardsCloseIdle`.
- G9 Toolsets are for size; the access level is for security.
  `TestAccess_Matrix`, `TestAccess_LevelOrder`.
- G10 Each tool except `accounts` and `search` requires `account`. The
  alias is checked first; an unknown alias fails before any network or
  keyring work. `TestTools_UnknownAccount`.
- G11 A gate that decides whether to verify fails closed: the signed
  hint has unknown as its zero value.
- G12 One part walker for one decision: openssl verifies the bytes
  that Go split, never its own split (DRV.1).
  `TestVerify_PreambleEpilogueIsUnsigned`,
  `TestSMIME_LookalikeBoundaryAppend`. `read` and `decrypt` give the
  part walk the full header of the entity, so a top-level part with
  `Content-Disposition: attachment` is an attachment, as a nested one
  is (R16-L3). `TestDecrypt_TopLevelAttachmentIsNotBody`.
- G13 The S/MIME weak probe is an allow-list of digest names (sha224,
  sha256, sha384, sha512, sha3-224 to sha3-512). Any other name in the
  digestAlgorithms SET is weak: openssl maps `sha1WithRSA` and other
  OIDs to SHA-1. A cut print or a missing list is weak too (DRV.18).
  `TestSMIME_DigestAliasIsWeak`, `TestSMIME_PaddedDigestSetStillWeak`.
- G14 The send summary walks the bytes that leave (`bodyParts`). A
  Content-Type that does not parse refuses the send with
  `errBodyUnreadable`: on a parse error go-message gives the raw header
  value as the type, so the part looks like an attachment or like a
  multipart with no parts. Decide multipart with
  `e.MultipartReader() != nil`, not with the type text. Each summary
  value and body line folds CR, LF, U+2028 and U+2029 to a space
  (`lineBreakFolder`): a web client breaks the line at U+2028 too, and
  a field after it shows with no `> ` prefix.
  `TestSendSummary_ContentTypeUnreadable`,
  `TestSendSummary_UnicodeLineBreaksFolded`.

## H. Bulk and undo (`internal/tools`, `internal/undo`, design `03-design-S9.md`)

- H1 `bulk` asks the human through elicitation before any change; with
  no elicitation it needs the config key. `TestBulk_AsksBeforeChange`,
  `TestBulk_NoElicitationNeedsKey`.
- H2 The change uses exactly the ids shown. `TestBulk_ExactIDSet`.
- H3 Undo runs once; an unknown id is an error. `TestUndo_Once`,
  `TestUndo_UnknownID`.
- H4 A declined answer or no match writes and journals nothing.
  `TestBulk_DeclineWritesNothing`, `TestBulk_NothingMatchesNoCall`.
- H5 One bulk is one journal record, in chunks of 500. A failed chunk
  stops the loop, and the record keeps every row that changed.
  `TestBulk_ChunksOf500OneRecord`,
  `TestBulk_StopAfterChunkKeepsRows`. A failed `Extend` keeps the token
  of the earlier chunks. `TestBulk_ExtendFailKeepsToken`. The record
  summary is written with chunk 1, so it names the matched count as
  matched; `Count` of the undo list gives the changed rows.
  `TestBulk_SummaryNamesMatchedCount`.
- H6 Partial undo: reverse each row still in its recorded state and
  list the rest. `TestUndo_PartialReversesRest`,
  `TestUndo_AllChangedStaysOpen`. The state read runs one folder at a
  time. A folder that the server built again (`imap.ErrStaleID`) or
  that another client deleted (`imap.ErrFolderGone`) skips only its
  own ids. `TestUndo_StaleFolderSkipsOnlyItsIDs`,
  `TestModify_SecondFolderFailsKeepsFirstRows`.
- H7 A move on Gmail or JMAP leaves a record that undo reverses.
  `TestGmail_MoveReversesByLabelDiff`, `TestUndo_RestoresJMAPFolders`.
  Only an IMAP row with no new id blocks the undo token. A row that
  the change left as it was (equal label sets, or an IMAP message in
  the target folder already, which the provider marks with
  NewID = ID) has nothing to reverse and does not block it.
  `TestModify_NothingToReverseKeepsUndo`,
  `TestBulk_ArchiveOfArchivedKeepsUndo`, `TestModify_InboxCaseNoSelfCopy`.
- H8 `modify` and undo never report a change for an absent message.
  `TestModify_GoneMessage`, `TestUndo_ChangedOrGone`.
- H9 Junk rule (DS8.2d, `mail.JunkRule`): a move out of the junk-role
  folder into a folder that is not junk or trash sets not-junk and
  clears junk in the same server step; a move into junk does the
  reverse; trash changes nothing; a call that names `$junk` or
  `$notjunk` itself wins. JMAP patches `keywords/$junk` and
  `keywords/$notjunk` (one extra `Email/get` round trip on such moves);
  IMAP stores `$Junk`/`$NotJunk` in the source folder before the move,
  only when `PERMANENTFLAGS` has `\*`. Undo never applies the rule
  (`Change.KeepJunkKeywords`) and gives back the old keywords exactly.
  Gmail needs nothing: `move_to` removes `SPAM`. `TestJunkRule`,
  `TestJMAP_MoveOutOfJunkMarksNotJunk`,
  `TestIMAP_MoveOutOfJunkMarksNotJunk`,
  `TestIMAP_JunkRuleSkipsFolderWithoutKeywords`,
  `TestUndo_JunkMoveRestoresKeywords`.
- H10 Bulk session grant (DS14.11), the one exception to H1. The bulk
  question has the required boolean `apply` and the optional boolean
  `remember` ("Yes, and do not ask again until reconnect"). Only
  `accept` with `apply` and `remember` both true grants (outcome
  `elicit_accept_session`). `grantStore` (`internal/tools/grant.go`)
  keys the grant on one `*mcp.ServerSession` and one account alias,
  keeps it in memory only, and drops it on `ss.Wait()`. Never persist
  it, never key it on anything that outlives the session, and never
  read it in `send`: send asks each time. A covered call asks nobody,
  keeps no pending record on the MRTR path, keeps the tool deadline and
  puts `bulkGrantUsedNote` in the result. `apply` stays the only field
  that changes mail; read answers only through `bulkOutcome` (both
  `askBulk` and `bulkAnswer`). `TestBulk_SessionGrantSkipsQuestion`,
  `TestBulk_SessionGrantPerAccount`, `TestBulk_SessionGrantPerSession`,
  `TestBulk_SessionGrantDeclineGrantsNothing`,
  `TestBulk_SessionGrantSendStillAsks`, `TestBulk_MRTRSessionGrant`.
- H11 `dry_run` (DS14.14) gives the count and up to `bulkDryRunSample`
  (50) rows with a date and the note "dry run: nothing changed". It
  needs read access only, and it returns before the session, the
  retry state, the grant and `askFirst`, so it reaches no Writer, no
  pending record, no undo record and no question. `collectIDs` takes a
  `Reader`, so the compiler blocks a write there. `dry_run` with
  `undo` is an input error. Before a bulk change by sender, call with
  `dry_run` and keep receipts, invoices and account mail out of the
  query (a by-sender move once took a wanted message with the promo mail).
  `TestBulk_DryRunChangesNothing`, `TestBulk_DryRunReadAccess`,
  `TestBulk_DryRunWithUndoRefused`.
- H12 A repeat bulk first call with the same session, account and
  input reuses the open record through `hold` and gets a NEW request
  state; the old state is stale (DS14.13), as for send.
  `TestBulk_MRTRSameInputReuses`, `TestBulk_MRTRSameInputOtherSession`.

## N. Identities and signatures (`internal/config`, `internal/tools`, `internal/cli`, design `03-design-identities.md`)

The ids in brackets are the invariants of DI8.

- N1 [I2] Each identity path runs only in identity mode: the account
  has an `identity` table or a `default_identity`. The flat
  `identities` list alone never turns it on. Outside identity mode,
  drafts, From values, the read of the original and the send summary
  stay as at `97a33ec`. Never edit an old assertion to make an
  identity change pass. `TestIdentity_ModeOff`,
  `TestSignature_NotIdentityMode`, `TestDraft_IdentityReadsOriginalOnce`,
  `TestDraft_IdentityFromAndNote`,
  `TestSendSummary_SignatureLineOnlyInIdentityMode`.
- N2 [I3] Each identity key is a plain struct field with a toml tag.
  Never add `UnmarshalTOML`: it turns off the unknown-key check. A bad
  identity key or value fails the whole file, and a reload keeps the
  old set. Each new key goes into `docs/accounts.example.toml`.
  `default_identity` may name the account email, a table email or a
  flat `identities` entry; its check runs after the flat merge.
  `TestIdentity_LoadRefuses`, `TestIdentity_RefreshKeepsOldSet`,
  `TestTemplate_HasEveryKey`, `TestIdentity_DefaultIdentityFlatEntry`.
- N3 [I1] The text part of a saved draft holds `"-- \n"` and the
  signature byte for byte on IMAP, Gmail and JMAP. Quoted-printable
  stores the delimiter as `--=20` with CRLF; compare after decoding.
  `TestDraft_SignatureNew`, `TestBuild_FromHeaderAndSignature`,
  `TestSaveDraft_IdentityFromHeader`,
  `TestProviderGmail_SaveDraftKeepsSignature`,
  `TestProviderJMAP_SaveDraftKeepsSignature`,
  `TestSendSummary_SignatureLineBuiltDraft`.
- N4 [I5] One signature. `cleanOwn` cuts an exact copy at the end of
  the own text, also on a `draft_id` replace. It refuses a near copy
  (same words, other white space) and any other `--` line with
  `errSignatureInBody`. HTML from the caller is refused, never cut.
  The forward path and the templates `draft` action share this code
  and refuse a near copy too. When the signature is not added to this
  draft (its flag is off), `prepareOwn` refuses an exact copy and does
  not cut it, so no model text goes with no error. A signature with
  one line of text is a near copy only at the end of the own text
  and at a word start (`HasSuffix` plus offset 0 or a space before),
  so a name in a sentence passes and sig "IT" does not refuse
  "please EDIT"; a signature with two
  or more lines of text is a near copy anywhere (`Contains`), a P.S.
  after it included. Keep the empty line of the owner's multi-line
  signature in every test that uses it.
  `TestCleanOwn`, `TestDraft_SignatureOwnerNearCopy`,
  `TestDraft_SignatureReplaceExactCopy`, `TestDraft_SignatureHTMLOnly`,
  `TestDraft_SignatureNearCopyForwardAndTemplates`,
  `TestDraft_SignatureNotAddedExactCopyRefused`,
  `TestCheckOwn_OneLineSignature`.
- N5 [I10] The signature checks run on the own text only, before the
  quote or the forward block joins it. Never run them on the joined
  text: a forward block has no `>` prefix.
  `TestDraft_SignatureReplyLayout`, `TestDraft_SignatureForward`.
- N6 [I6] The From address is the account email, an identity email,
  or, on a reply or a forward only, an address of the original that a
  `reply_match` pattern matches. An explicit catch-all `from` on a new
  draft is refused. Reply-all drops the picked address. The display
  name of From is always the configured `name` of the identity; a name
  in the caller's `from` is dropped, because the send confirmation
  shows bare addresses only. The account `email` is one bare address:
  `account add` and the load refuse a name form, because it makes
  `OwnsAddress` false and can reach the SMTP envelope.
  `TestPickIdentity_FromNameIsConfigured`,
  `TestPickIdentity_Rules`, `TestDraft_IdentityCatchAllFromRefused`,
  `TestDraft_ReplyAllDropsPicked`, `TestOwnsAddress`, `TestMatchReply`,
  `TestConfig_Load_EmailMustBeBare`, `TestCLI_AddRefusesNameFormEmail`.
- N7 [I8] No MCP tool writes identity settings or returns signature
  text. The `accounts` tool gives `identity_settings` with booleans for
  the signatures, and only in identity mode. `TestAccounts_IdentitySettings`,
  `TestSchema_Golden`.
- N8 [I4] The send summary shows each signature line and, in identity
  mode, one `Signature:` line that never refuses. Its search for a
  `--` line stops at the forward block that `mime.ForwardBody` writes
  (the `From:`, `Date:`, `Subject:`, `To:` lines), so a delimiter of
  the forwarded mail is no `DIFFERS`. A signature line
  that starts with `>` fails the load, because the summary hides such
  lines. An HTML part with the signature must pass `AllowHTML`
  unchanged, or the draft is refused. `TestSendSummary_SignatureLine`,
  `TestSendSummary_SignatureLineAfterHeaders`,
  `TestSendSummary_SignatureLineInConfirmation`,
  `TestDraft_SignatureComposeHTML`, `TestSignature_PlaceRefusesUnclean`.
- N9 [I7] `identities detect` writes only after the exact word `yes`
  on a terminal, and never for an account in identity mode. The splice
  changes only the `identity` tables and `default_identity` of that
  alias, and the result must pass the strict load before the rename.
  Mails with a mailbag Message-ID never vote.
  `TestIdentitiesDetect_YesGate`,
  `TestIdentitiesDetect_ExistingSettingsWriteNothing`,
  `TestAddIdentityTables_Refuses`, `TestConfig_SpliceIdentitiesVerify`,
  `TestIdentitiesDetect_SkipsMailbagMails`.
- N10 [I11] The JMAP draft and send path makes no new `Identity/get`.
  The signature reader of detect is a separate call with no cache.
  `TestJMAP_SubmissionIdentity`, `TestProviderIdentities_JMAP`,
  `TestProviderJMAP_SaveDraftKeepsSignature`.
- N11 [I3] `signature_file` and `signature_html_file` are plain
  fields. A relative path starts at the directory of `accounts.toml`
  (`loadSnapshot` passes it to `validateIn`), `~/` at the
  home directory. Setting a file key and its inline key fails the load;
  so does a file that is missing, not regular, over 64 KiB or not
  UTF-8. `sigLoader.load` opens with `O_NONBLOCK` and checks the open
  file (`f.Stat`), never `os.Stat` then `os.Open`: a plain open of a
  FIFO blocks for ever under `f.mu`. It cuts a leading UTF-8 byte
  order mark, else U+FEFF reaches every draft and the hidden-character
  note shows on every send. An error text never holds the path. The text file goes through
  `NormalizeSignature` and keeps inner empty lines. The snapshot keeps
  each file's modification time, and `Refresh` reloads when only a
  signature file changed. `identities detect` writes inline strings
  only. `TestIdentity_SignatureFile`, `TestIdentity_SignatureHTMLFile`,
  `TestIdentity_SignatureFileRefuses`, `TestIdentity_SignatureFileFIFO`,
  `TestIdentity_RefreshSignatureFile`,
  `TestAddIdentityTables_SignatureFileRelative`.

## Later rules

- R1 byte economy: `tools/list` has no `outputSchema`; a toolset that
  is off gives no tool name. `TestToolsList_NoOutputSchema`,
  `TestToolsets_OffMeansAbsent`, `TestToolsList_Budget` (I3).
- R1 send: no send with no accepted elicitation, unless the config key
  allows it; one idempotency key sends at most one mail.
  `TestSend_NoElicitationRefuses`, `TestSend_IdempotentKey`.
- R1 decrypt exists only when `extras` and both keys agree.
  `TestDecrypt_ThreeKeys`.
- A no-MDC test fixture needs a recipient key with no AEAD preference
  (`--default-preference-list "AES256 SHA256 ZLIB"`). The gpg of
  Debian and Ubuntu (2.4.4) gives each new key an AEAD preference and
  then ignores `--rfc2440`: the packet is OCB AEAD and gpg reports
  GOODMDC, so the text comes back correctly. The fixture checks
  `--list-only --list-packets` for a tag 9 packet.
  `TestDecrypt_RequiresGoodMDC`.
- DRV.10 refused logins: a local error keeps the socket; a refused
  login is not repeated for 10 minutes on any provider; a changed
  secret ends the refusal. `TestPool_NoRedialOnLocalError`,
  `TestFactory_AuthErrorNoRelogin`, `TestFactory_ChangedSecretEndsRefusal`,
  `TestFactory_JMAPRefusalWindow`.
- DR1G.17 capabilities come through the optional `CapsReporter`
  interface, not a new `Reader` method, so the provider fakes stay
  unchanged. `TestFactory_OpenGivesCapsReporter`,
  `TestCLI_LoginNoCapsReporter`.
- DS6 Outlook: hosts are written at `account add`; the tenant comes
  from the email domain (a consumer domain gives `consumers`, and an
  explicit `--tenant` wins). `TestCLI_OutlookPasteWritesHostsAndSecret`,
  `TestCLI_OutlookTenantFromEmail`, `TestMicrosoft_TenantRejectsInjection`.
  The OAuth HTTP client is a plain client, not the SSRF guard
  (`internal/oauth/oauth.go`, no test).
- DS6 OAuth sign-in stays in-house with a client the user supplies.
  The tests check that the CLI stores that client; no test checks that
  the binary carries no client id, so grep non-test code before a
  release. `TestCLI_OAuthSetMicrosoftClientID`,
  `TestCLI_OAuthSetGoogleFile`.
- DS9 one-click unsubscribe: a POST only through the guarded client,
  only to an https URL from the message header, only with `dkim=pass`
  from the configured `authserv_id`; never a GET.
  `TestUnsubscribe_OneClickPostsWhenDKIMPass`, `TestUnsubscribe_NeverGET`,
  `TestUnsubscribe_ProductionClientIsGuarded`.
- DS9 `unsubscribe` and `templates` make drafts; no mail leaves through
  them. `TestUnsubscribe_MailtoMakesDraft`, `TestTemplates_DraftFillsVars`.
- DS9 templates never follow a link out of their directory; files are
  0600. `TestTemplates_LinkOutOfRootRefused`,
  `TestTemplates_SaveDoesNotFollowLink`, `TestTemplates_Mode0600`.
- DS11 no `Server.Run` in non-test code: one session per connection
  with `Connect` plus `Wait`; a normal session end logs no ERROR.
  `TestService_SessionEndNeverLogsError`.
- DS11 one `Service` for all sessions: two sessions share one login.
  `TestService_TwoSessionsOneLogin`, `TestE2E_ShimSecondSessionNoNewStart`.
- DS11 `detach` at the point of no return: a send after the human
  accepted, and a modify once the provider call starts, complete with
  no session. `TestSend_CompletesAfterClientGone`,
  `TestModify_CompletesAfterClientGone`, `TestBulk_Detached`.
- DS11 peer uid check before any byte is read.
  `TestSocket_PeerUIDRefused`.
- DS11 handshake: same config and another build gives RESTART; the
  daemon frees the socket and the lock at once and finishes the calls in
  flight. Any config mismatch gives CONFIG, also with another build; the
  daemon stays and the shim runs in process. A bad reply makes the shim
  fall back.
  `TestSocket_BuildMismatchDrains`, `TestSocket_ConfigMismatchStays`,
  `TestShim_FallbackOnConfig`, `TestShim_FallbackOnBadReply`.
- DS11 two shims never start two daemons. `TestShim_SpawnsOnce`,
  `TestSocket_LockRefusesSecondDaemon`.
- DS11 the CLI commands need no daemon: `internal/cli` never imports
  `internal/shim` or `internal/server` (`go list -deps`).
- DS11 `service install` writes the systemd units and never runs
  `systemctl`.
- DS14 confirmation on protocol 2026-07-28 (design `03-design-S14.md`).
  That protocol forbids a server request during a tool call, so
  `ss.Elicit` fails there however long the connection lives. `send`
  and `bulk` then return an input-required result with one form
  (`inputRequests` key `confirm`) and a single-use `requestState`, and
  act only on the retry. A session on an older protocol keeps
  `ss.Elicit`; `newProtocol(ss)` selects the path. Traps:
  - go-sdk v1.7.0 fills `ss.InitializeParams()` from the `_meta` of
    the first new-protocol request, so a client with no `initialize`
    still reads as 2026-07-28 with its capabilities.
  - The record lives in daemon memory and is bound to the session
    pointer. A transport with one server session per request would
    give `errConfirmStale` on every retry; stdio and the daemon socket
    keep one session.
  - The send record pins the SHA-256 of the source that the summary
    shows; the retry refuses a changed draft (`errDraftChanged`). The
    bulk retry acts on the ids of the first call, never a new search.
  - The first send call spends the limit; the retry does not. The key
    store runs on both calls.
  - Each tool (send, bulk) has its own store of `pendingLimit` (64)
    places, and one session holds at most `pendingPerSession` (16) of
    them; the next place gives `errPendingSessionFull` (DS14.12). The
    check runs in `hold` and `put` before `limit.take`, so a refused
    send spends no send. take, drop, expiry and reuse give the place
    back to its session; a count of 0 deletes the map key.
    `TestPendingStore_SessionShare`, `TestPendingStore_SessionShareReturns`,
    `TestSend_MRTRSessionShareSpendsNoSend`,
    `TestSend_MRTROneSessionFillsStore`, `TestBulk_MRTRStoreFull`.
  - The go-sdk test client speaks 2026-07-28 and answers
    `inputRequests` through its `ElicitationHandler`; tests of forged
    or replayed states turn that off (`MultiRoundTripOptions`).
  `TestSend_MRTRAccept`, `TestSend_MRTRStaleState`,
  `TestSend_MRTRDraftChanged`, `TestBulk_MRTRAccept`,
  `TestBulk_MRTROtherSession`, `TestClaimPending_EachFieldMustMatch`.

## S. Setup page (`cmd/mailbag-setup`, design `03-design-S13.md`)

- S1 `mailbag-setup` is a second binary. It changes state only through
  the `mailbag-mcp` CLI (IS13.1), finds the CLI and refuses a version
  mismatch before any write (DS13.7), and never runs sudo, systemctl
  or launchctl (IS13.5). `TestSetup_FindCLI`,
  `TestSetup_VersionMismatchNoWrites`.
- S2 The server listens on 127.0.0.1 with a one-time token, checks
  Host, sends the security headers on every response, sends no CORS
  headers, takes only JSON posts, runs one job at a time and exits when
  idle (DS13.6). `TestSetup_NoToken403`, `TestSetup_WrongToken403`,
  `TestSetup_HostMismatch403`, `TestSetup_SecurityHeadersOnEveryResponse`,
  `TestSetup_NoCORSHeaders`, `TestSetup_PostNeedsJSON`,
  `TestSetup_OneJobAtATime`, `TestSetup_IdleExit`.
- S3 A secret goes to the CLI on stdin (`--answers-stdin`), never in
  argv, the environment or a log. `TestSetup_SecretNotInArgvOrEnv`.
- S4 The page (`cmd/mailbag-setup/web/`, `go:embed`) writes text with
  `textContent` only; `TestWeb_NoHTMLSinks` refuses `innerHTML`,
  `outerHTML`, `insertAdjacentHTML`, `document.write` and `eval(`.
  Presets are in `web/presets.json`. The token moves from the URL
  fragment to `sessionStorage`. `TestWeb_PageShape`, `TestWeb_Presets`,
  `TestSetup_PageFilesServedWithHeaders`.
- S5 Client config: Claude Desktop JSON is merged with a backup first
  (`...json.bak-<UTC time>`), a temp file and a rename, the key order
  kept, bad JSON refused, and no write while the app runs; Claude Code
  goes through `claude mcp add --scope user`. Tests use temp dirs only.
  `TestClients_DesktopMerge_KeyOrder`, `TestClients_DesktopMerge_BadJSON`,
  `TestClients_DesktopApp_RunningRefused`, `TestClients_ClaudeCode_Args`.
