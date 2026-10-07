# 05. Tests for fingerprint and notify

## Problem

`internal/fingerprint` and `internal/notify` have no tests. They talk to
D-Bus (fprintd, the notification daemon), so they were left alone during the
refactor. They still contain decision logic that is security-relevant and
easy to break:

- `fingerprint.Verifier.Verify`: maps `VerifyStatus` signals to
  match / no-match / sensor unavailable, keeps waiting on non-final results,
  and wraps every hardware problem in `ErrUnavailable`. The authenticator
  allows or denies based on that distinction.
- `notify.Desktop`: the prompt id is replaced and cleared under a mutex.

`internal/approval` is covered: its backends run against shell scripts in
`t.TempDir()`.

## Proposed approach

- **fingerprint**: extract the signal interpretation into a pure function,
  for example `interpret(result string, done bool) (outcome, error)`, and
  table-test it. Leave the D-Bus calls untested or behind a small interface.
- **notify**: the D-Bus call can sit behind an unexported function variable
  or interface so the prompt-id bookkeeping can be tested; low priority.

## Done when

- Each package has table-driven tests covering the failure paths above.
- `go test -race ./internal/...` passes without D-Bus or a display.
