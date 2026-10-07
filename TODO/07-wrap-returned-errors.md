# 07. Wrap returned errors

## Problem

The project standard asks for wrapped errors (`fmt.Errorf("action: %w",
err)`), but many paths return them bare. A count of plain `return err` /
`return nil, err` at the time of writing:

| File | Bare returns |
|------|-------------:|
| `internal/vault/vault.go` | 28 |
| `cmd/llavero/vaultcmd.go` | 14 |
| `cmd/llavero/daemon.go` | 2 |
| `cmd/llavero/passphrase.go` | 2 |
| `internal/tpm/tpm.go` | 2 |

The user then sees, for example, `error: permission denied` without knowing
whether it was the vault file, the sealed blob, the temp file during save or
the backup during rekey. `internal/vault` is the worst case because every
I/O step of `save` and `Create` returns the raw `os` error.

## Proposed approach

- Wrap at each boundary with the action, not the function name:
  `fmt.Errorf("writing vault temp file: %w", err)`,
  `fmt.Errorf("reading sealed blob %s: %w", path, err)`.
- Keep sentinel errors (`vault.ErrBadPassphrase`, `fingerprint.ErrUnavailable`)
  matchable with `errors.Is`; do not wrap them in a way that changes the
  user-facing wording the README documents.
- Where a caller already adds context (for example `runRekey` adding "your
  backup at ... is still good"), wrap below it rather than duplicating text.
- Do it one package per commit, starting with `internal/vault`.

## Done when

- `grep -nE 'return (nil, )?err$'` finds only returns where the callee
  already produced a self-describing error, each with a short comment saying
  so, or none at all.
- Tests that check `errors.Is` on sentinels still pass.
