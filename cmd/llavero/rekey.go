package main

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"llavero/internal/bootstrap"
	"llavero/internal/tpm"
	"llavero/internal/vault"
)

func rekeyCommand() bootstrap.Command {
	return bootstrap.Command{
		Name:        "rekey",
		Description: "re-encrypt the vault under another unlock mode",
		Options:     &rekeyCmd{},
	}
}

type rekeyCmd struct {
	vaultOptions

	NewPassFD int `long:"new-passphrase-fd" value-name:"FD" default:"-1" description:"read the NEW passphrase from this file descriptor"`
	Args      struct {
		Mode string `positional-arg-name:"MODE" description:"passphrase, tpm, or tpm+passphrase"`
	} `positional-args:"yes" required:"yes"`
}

func (c *rekeyCmd) Execute([]string) error {
	return c.withApp(func(a *app) error { return a.rekey(c.Args.Mode, c.NewPassFD) })
}

// rekey re-encrypts the vault under target, reading a new passphrase from
// newPassFD when target needs one.
func (a *app) rekey(target string, newPassFD int) error {
	opts := a.opts
	newMode, err := vault.ParseUnlockMode(target)
	if err != nil {
		return fmt.Errorf("rekey: %w", err)
	}
	if newMode.NeedsTPM() {
		if err := tpm.Available(); err != nil {
			return fmt.Errorf("%s needs the TPM: %w", newMode, err)
		}
	}

	v, err := a.loadVault("")
	if err != nil {
		return err // loadVault's errors already say what failed
	}
	if v.Mode() == newMode {
		a.log.Info("vault is already in this mode, nothing to do", zap.Stringer("unlock", newMode))
		return nil
	}

	// Back up before touching anything. A failed rekey must never be the
	// reason someone loses their passkeys. A TPM-bound vault is useless
	// without its sealed blob, so that is backed up too.
	stamp := time.Now().Format("20060102-150405")
	backup := fmt.Sprintf("%s.bak-%s", opts.VaultPath, stamp)
	if err := copyFile(opts.VaultPath, backup); err != nil {
		return fmt.Errorf("could not back up the vault, refusing to rekey: %w", err)
	}
	backups := backup
	if v.Mode().NeedsTPM() {
		blob := vault.SealedBlobPath(opts.VaultPath)
		blobBackup := fmt.Sprintf("%s.bak-%s", blob, stamp)
		if err := copyFile(blob, blobBackup); err != nil {
			return fmt.Errorf("could not back up the sealed blob, refusing to rekey: %w", err)
		}
		backups = fmt.Sprintf("%s with %s (restore both, as %s and %s)", backup, blobBackup, opts.VaultPath, blob)
	}
	a.log.Info("backed up the existing vault", zap.String("backup", backups))

	var newPass []byte
	if newMode.NeedsPassphrase() {
		p, err := readPassphrase(newPassFD, true, "new ")
		if err != nil {
			return err // readPassphrase's errors already say what failed
		}
		defer zero(p)
		newPass = p
	}

	if err := v.Rekey(newMode, newPass); err != nil {
		return fmt.Errorf("rekey failed (backup: %s): %w", backups, err)
	}
	a.log.Info("rekeyed", zap.Stringer("unlock", newMode), zap.Int("passkeys", v.Count()))

	// Prove the new file actually opens before declaring success.
	// Until it does, the previous sealed blob stays parked beside it.
	check, err := vault.Open(opts.VaultPath, newPass, tpm.Sealer{})
	if err != nil {
		return fmt.Errorf("the rekeyed vault does not reopen (restore from %s): %w", backups, err)
	}
	if check.Count() != v.Count() {
		return fmt.Errorf("credential count changed during rekey (restore from %s)", backups)
	}
	a.log.Info("verified: the rekeyed vault reopens", zap.Int("passkeys", check.Count()))
	if err := v.RemovePreviousBlob(); err != nil {
		a.log.Warn("could not remove the previous sealed blob; it is safe to delete by hand",
			zap.String("path", vault.PreviousBlobPath(opts.VaultPath)), zap.Error(err))
	}
	return nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}
	return nil
}
