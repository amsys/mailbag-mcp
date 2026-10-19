---
id: developer-guide
type: how-to
audience: [maintainer, agent]
status: current
last_reviewed: 2026-10-19
---

# mailbag-mcp developer guide

This guide tells you how to build and test mailbag-mcp, where the
design is recorded, and how a release is made. For the use of the
server, read the [user guide](USER-GUIDE.md).

## Build

You need Go 1.27.1 or later. The binary has no C code:

```
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' .
```

- `CGO_ENABLED=0` gives one static binary for each target.
- `-trimpath` removes the local paths from the binary.
- `-s -w` removes the symbol table and the debug data. The release
  build uses the same flags.

The build sets no version with the linker (no `-X`). `mailbag-mcp
version` reads the version from the Go build info
(`debug.ReadBuildInfo` in `main.go`):

- A build from a tagged commit with no local change gives the tag,
  for example `mailbag-mcp v0.1.0`.
- A build from an untagged commit gives a pseudo-version such as
  `v0.0.0-20261013172000-1ec0d90e0ff5`.
- A build from a tree with uncommitted changes adds `+dirty` to the
  version. The release build runs in a clean checkout, so it has no
  `+dirty`. `dist/` is in `.gitignore`, so the output of a snapshot run
  does not make the tree dirty.
- `go run .` and some test builds have no version: the binary prints
  `mailbag-mcp (devel)`.

## Lint

Run `trueup lint` in the repository root before a commit. It runs
golangci-lint, Vale and the reference checker with the settings of
`trueup.toml`. The repository keeps no lint config files. CI does not run
lint. CI scans the git history with gitleaks (`.github/workflows/secrets.yml`,
config in `.github/gitleaks.toml`).

## Tests

Run all tests with the race detector:

```
export TMPDIR=/tmp
go test -race ./...
```

Why `TMPDIR=/tmp`: the e2e tests start a daemon with its socket under a
temporary directory. A Unix socket path has a limit of 104 bytes on
macOS and 108 bytes on Linux. A sandbox or a CI runner can set a long
`TMPDIR`. Then the socket path is too long, and the e2e tests skip with
the text "set a shorter TMPDIR" (`shortRuntimeDir` in `e2e_test.go`).
A skip is not a pass, so set a short `TMPDIR` before a full run.

No test reaches the live daemon socket: each e2e launch gets its own
`XDG_RUNTIME_DIR`.

### Golden files

Two tests compare output with a stored copy. Set `UPDATE_GOLDEN=1` to
write the new copy, then read the diff before you keep it:

| Test | Stored copy | Command |
|---|---|---|
| `TestSchema_Golden` | `testdata/schema.golden.json`, the `tools/list` JSON of every tool | `UPDATE_GOLDEN=1 go test -run TestSchema_Golden ./internal/tools` |
| `TestDocs_ToolsReferenceCurrent` | the tools block between the markers in `docs/USER-GUIDE.md` | `UPDATE_GOLDEN=1 go test -run TestDocs_ToolsReferenceCurrent .` |

The tools block comes from `mailbag-mcp tools markdown`. The text for
each input field is in `internal/cli/toolsdoc.go`.
`TestToolsDoc_EveryFieldHasText` fails when a field has no text.

### Schema budget

The `tools/list` reply goes into the context of the model at each
session start. `go run . tools size` prints its size per tool.
`TestToolsList_Budget` in `internal/tools/schema_test.go` keeps the
core tools at 4096 B or less and all tools at 8192 B or less. Do not
raise these numbers without a decision record in `PLAN.md`.

### Binary size

`TestBinarySize_Budget` (`size_test.go`) builds the stripped binary and
fails above `sizeBudgetBytes` (15,000,000 B). The measured history and
each decision that raised the budget are in
`docs/features/mailbag/size-baseline.md`. Raise the budget only with a
new record in that file.

### Live tests

Two tests run against a real account. They have the build tag `live`
and need an alias in an environment variable. With no alias, they skip.

| Provider | Command |
|---|---|
| Gmail | `MAILBAG_LIVE_GMAIL=<alias> go test -tags live -run TestLive ./internal/gmail -v` |
| JMAP | `MAILBAG_LIVE_JMAP=<alias> go test -tags live -run TestLive ./internal/jmap -v` |

The account must exist in `accounts.toml`. The tests print field names
and counts only, never a message value.

### Coverage gate

```
go test -race -coverprofile=cover.out ./...
scripts/coverage_gate.sh cover.out
```

The script prints `coverage <total> % (limit 80.0 %)` and exits 1 below
the limit. A second argument sets another limit. CI runs the same
script on Linux. The Windows total is lower, because some tests skip
on Windows.

## Design in short

The design is in `docs/features/mailbag/03-design.md`. Each later
stage has its own file, `docs/features/mailbag/03-design-<stage>.md`
(R1, R1G, RV, S6, S7S8, S9, S10, S11). The later file is correct where
two files differ. `PLAN.md` records the stages, the tasks and the owner
decisions. These build records are in a private repository of the
owner (see `docs/README.md`), not in this repository.

- `main.go`: no argument runs the shim (the MCP entry). `serve` runs
  the daemon. The other subcommands go to `internal/cli`.
- `internal/shim`: the MCP entry. It dials the daemon socket, compares
  the build and the configuration in a handshake, and copies bytes in
  both directions. With no socket it starts the daemon. When that
  fails, it runs the server in the same process.
- `internal/server`: the MCP server. One `Service` holds the state of
  all sessions: the connection pool, the token sources and the send
  limits. The daemon listens on a Unix socket in
  `$XDG_RUNTIME_DIR/mailbag/`, checks the user id of the peer, and also
  accepts a socket from systemd. It exits after 15 minutes with no
  client.
- `internal/tools`: the MCP tools, the toolsets, the access levels and
  the provider factory. Each tool puts the text that a sender controls
  between untrusted-content fences.
- `internal/mail`: the provider contract and the types that all
  providers share, with the search query parser.
- `internal/imap`: the IMAP and SMTP provider on go-imap, with the
  connection pool, the folder roles and the capability report.
- `internal/gmail`: the Gmail provider on the Gmail REST API, with the
  label cache and the Gmail settings calls.
- `internal/jmap`: the JMAP provider, written by hand on `net/http`.
- `internal/oauth`: the sign-in with PKCE for Microsoft and Google, and
  the token sources. The user supplies the OAuth client.
- `internal/mime`: builds outgoing messages, decodes incoming parts,
  and turns HTML into text with the hidden-text check.
- `internal/verify`: the signature result that `read` shows (DKIM,
  S/MIME, OpenPGP).
- `internal/guard`: the fences, the redaction of secrets in logs, the
  path checks for save and attach, and the SSRF guard for outgoing HTTP.
- `internal/undo`: the undo journal for `modify` and `bulk`.
- `internal/config`: loads and checks `accounts.toml`.
- `internal/secrets`: the system keyring, with a file fallback.
- `internal/cli`: the terminal commands (`account`, `oauth`, `tools`,
  `doctor`, `service`) and the systemd user units.

## Traps

The project skill `skills/mailbag-mcp/SKILL.md` holds the rules and
traps of the code, each with the test that pins it. Read it before you
change a package that it names.

## Release

A tag `v*` starts `.github/workflows/release.yml`. It has four jobs. A
job starts only when the job before it passes:

1. **verify** runs `scripts/release/verify-tag.sh`. The tag must have a
   good SSH signature from a key in `.github/allowed_signers`, the name
   in the signed tag object must be the tag name, the tag must point to
   the commit that the job checked out, its commit must be on `main`,
   and `CHANGELOG.md` must have a section `## [<version>]` with text in
   it. That section becomes the release notes. The job reads the script
   and `.github/allowed_signers` from `origin/main`, not from the tag,
   because a tag can hold any tree. So a tag that a leaked token pushes
   stops here. The build job runs the same checks again.
2. **test** calls `test.yml` with `workflow_call`.
3. **build** runs GoReleaser with `.goreleaser.yaml` and makes a
   **draft** release (`release.draft: true`) with six archives (Linux,
   macOS and Windows, each on amd64 and arm64), three Linux packages
   (`.deb`, `.rpm` and `.pkg.tar.zst`) and `checksums.txt`. It
   attests each file in `checksums.txt`, and `checksums.txt` itself,
   with `actions/attest-build-provenance`.
4. **publish** runs in the GitHub environment `release`. It waits until
   the owner approves, then makes the draft public with
   `gh release edit <tag> --draft=false`. The first step of the job
   reads the environment and fails unless it has a `required_reviewers`
   rule with at least one reviewer. The environment `release` must
   exist, with the owner as required reviewer. If it does not exist,
   GitHub creates it with no reviewer, and the check stops the publish.
   The job uses `GITHUB_TOKEN` with `actions: read` for this check.
   That is the least permission that can read the environment rules.

Each archive holds the binary, `LICENSE`, `README.md`, `SUPPORT.md`,
`CHANGELOG.md`, the guides in `docs/` and the systemd units in
`contrib/systemd/`.

### Signed tags

`.github/allowed_signers` holds the public key of
`~/.ssh/id_ed25519_amsys_sign` with the principal `dev@amsys.cz`. An
unsigned tag, a lightweight tag or a tag from another key fails the
verify job. Make the tag on `main` with git signing in SSH format:

```
git -c gpg.format=ssh -c user.signingkey="$HOME/.ssh/id_ed25519_amsys_sign.pub" tag -s v1.2.0 -m v1.2.0
sh scripts/release/verify-tag.sh --main main --notes /tmp/dist-notes.md v1.2.0
```

The second command runs the checks of the verify job on your clone and
writes the notes to `/tmp/dist-notes.md`, outside the work tree, so a
snapshot stays clean. `sh scripts/release/verify-tag.sh --selftest` tests the
script with throwaway keys.

To change the signing key, change `.github/allowed_signers` in a commit
on `main` before you push the next tag.

The gate has limits. A token that can push to `main`, or a token with
the `workflow` permission, can change the gate itself. Protect `main`
with a ruleset, so that only the owner can push to it. The owner
approval of the `release` environment is the last stop.

The environment `release`, with the owner as required reviewer, is a
setting of the GitHub repository, not a file. Make it before the first
tag. If it does not exist, GitHub makes it with no reviewer, and the
publish job runs with no approval.

Make a local snapshot before you push a tag:

```
go run github.com/goreleaser/goreleaser/v2@v2.18.2 release --snapshot --clean --skip=publish
```

The archives go to `dist/`. Run it in a clean checkout: in a tree with
local changes the binary version ends in `+dirty`.

Each action in `test.yml` and `release.yml` is pinned by its commit
hash, with the tag in a comment. To update an action, resolve the new
tag with `git ls-remote` and change the hash and the comment together.

## CI

`.github/workflows/test.yml` runs on a push to `main` and on each pull
request, and when `release.yml` calls it for a tag. It runs on
`ubuntu-latest`, `macos-latest` and `windows-latest`:
`go vet`, staticcheck, `go test -race -coverprofile=cover.out ./...`,
`go tool cover -func`, the coverage gate (Linux only) and govulncheck
(not on Windows).

Windows runs a subset (DF.7.4): build, vet, staticcheck and tests for
`./internal/config/...`, `./internal/mime/...`, `./internal/guard/...`,
`./internal/tools/...`, `./internal/undo/...` and `./internal/cli/...`
only. `internal/server` has no daemon on Windows, `internal/verify`
needs OpenSSL 3, and the root e2e tests need the daemon. The steps use
`bash`. `test.yml` says why in a comment.

staticcheck and govulncheck are pinned by version in `test.yml`, so a
new release of a tool cannot fail CI with no code change. Run the same
versions before a push:

```
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

staticcheck refuses a raw invisible character (for example U+200B) in
a string literal (ST1018). Write it as an escape, such as `​`.

CI is not observed yet. The repository has had no push, so no CI run
exists. The first push gives the first result.

## Proof table

Unit tests use fakes. This table shows which path was tested against a
real server, and when.

| Path | Live-tested on |
|---|---|
| IMAP and SMTP | owner mailbox, 2026-09-20 |
| Outlook | open: owner step DS6.6 (redirect URI, `account add --provider outlook`, `account test`) |
| Gmail | open: owner step T7.6 (the live test above) |
| JMAP | open: owner step (`account add --provider jmap`, the live test above) |
| Daemon on systemd | open: owner step (`service install`, then `systemctl --user enable --now mailbag.socket`) |
