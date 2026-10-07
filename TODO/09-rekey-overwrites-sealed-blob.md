# 09. Rekey overwrites the sealed blob before the vault is safe

## Problem

`vault.Rekey` into a TPM mode seals a new secret and writes it over
`<vault>.tpm` (`sealNewSecret`) *before* the vault file is rewritten under
the new key. `cmd/llavero/vaultcmd.go` `runRekey` backs up only the vault
file (`<vault>.bak-<time>`), not the sealed blob.

If the vault was already TPM-bound (`tpm` or `tpm+passphrase`) and anything
fails after the blob is replaced (the save in `Rekey`, or the reopen check
in `runRekey`):

- the old vault file on disk is still encrypted under the *old* TPM secret;
- the backup is a copy of that same file;
- the only blob that could unseal the old secret has just been overwritten.

Both the vault and its backup are then unrecoverable, while the error
message says "your backup at ... is still good". Going from `passphrase` to
a TPM mode is not affected (the old vault does not need a blob), nor is
going from a TPM mode to `passphrase` (no new blob is written).

## Proposed approach

1. In `Rekey`, keep the old blob until the new vault is known good:
   - write the new blob to `<vault>.tpm.new`;
   - save the vault under the new key;
   - rename `<vault>.tpm` to `<vault>.tpm.old`, then `<vault>.tpm.new` to
     `<vault>.tpm`;
   - delete `<vault>.tpm.old` only after the caller has reopened the vault.

   At every point either the old vault and old blob or the new vault and new
   blob are on disk, and the old blob is never deleted before the new pair has
   been proven to open.
2. In `runRekey`, back up the blob too (`<vault>.tpm.bak-<time>`) whenever
   the current mode needs the TPM, and name both files in the restore
   messages.
3. Add `*.pkv.tpm.bak-*` and `*.pkv.tpm.new` to `.gitignore`.

## Done when

- A vault test with a fake sealer rekeys `tpm` → `tpm+passphrase` while
  making the save fail (for example by making the directory read-only after
  sealing), and the original vault still opens with the original blob.
- `runRekey` produces a blob backup for TPM-bound vaults and its messages
  name it.
