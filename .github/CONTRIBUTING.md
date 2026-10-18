# Contributing

Thank you for your interest in mailbag-mcp.

## Before you start

- Read the [README](../README.md) for the purpose of the project.
- Read the [developer guide](../docs/DEVELOPER-GUIDE.md) for the build, the tests and the design.
- Open an issue before a large change, so we agree on the design first.

## Making a change

1. Create a branch for your change.
2. Build the binary with `go build`. The developer guide gives the release flags.
3. Add or change tests. Run all tests with the race detector:

   ```
   export TMPDIR=/tmp
   go test -race ./...
   ```

4. Run `go vet ./...` and staticcheck. CI runs both.
5. Write each commit message as a conventional commit that cites the task id when there is one, for example `fix(calc): sum the last item (T3)`.
6. Sign your commits.
7. Open a pull request that says what changed and why.

## Code style

Follow the style of the file you change. Write docs and comments in ASD-STE100 Simplified Technical English: short sentences and active voice. Do not weaken, skip or delete a test to make it pass.

## Reporting a bug

Open an issue with the steps to reproduce it, the result you expected and the result you got. Add the output of `mailbag-mcp version`. See [SUPPORT.md](../SUPPORT.md).
