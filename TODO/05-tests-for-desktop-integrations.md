# 05. Tests for fingerprint, notify and approval

## Problem

`internal/fingerprint`, `internal/notify` and `internal/approval` have no
tests. They talk to D-Bus (fprintd, the notification daemon) and to the
external `omarchy-menu-select` binary, so they were left alone during the
refactor. They still contain decision logic that is security-relevant and
easy to break:

- `approval.Menu.Confirm`: a non-zero exit with empty stderr means the user
  dismissed the prompt (deny), with stderr it means the prompt could not run
  (error). It also strips a tab-separated subtext from the chosen line, and
  turns a context timeout into an error.
- `fingerprint.Verifier.Verify`: maps `VerifyStatus` signals to
  match / no-match / sensor unavailable, keeps waiting on non-final results,
  and wraps every hardware problem in `ErrUnavailable`. The authenticator
  allows or denies based on that distinction.
- `notify.Desktop`: the prompt id is replaced and cleared under a mutex.

## Proposed approach

- **approval**: make the binary path injectable (it already is a field) and
  point it at small shell scripts written to `t.TempDir()` that print a
  choice, exit 1 silently, exit 1 with stderr, or sleep past a short timeout.
  Make the timeout a field for the test. Table-driven.
- **fingerprint**: extract the signal interpretation into a pure function,
  for example `interpret(result string, done bool) (outcome, error)`, and
  table-test it. Leave the D-Bus calls untested or behind a small interface.
- **notify**: the D-Bus call can sit behind an unexported function variable
  or interface so the prompt-id bookkeeping can be tested; low priority.

## Done when

- Each package has table-driven tests covering the failure paths above.
- `go test -race ./internal/...` passes without D-Bus or a display.
