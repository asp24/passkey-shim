package main

import (
	"errors"
	"fmt"
	"os"

	"go.uber.org/zap"

	"llavero/internal/tpm"
	"llavero/internal/vault"
)

// loadVault opens an existing vault, asking only for the factors the vault's
// own mode requires. A missing vault is created in createMode, or is an error
// when createMode is empty: only serve makes a vault, so a mistyped --vault
// for anything else does not leave an empty one behind.
func (a *app) loadVault(createMode string) (*vault.Vault, error) {
	opts := a.opts
	_, statErr := os.Stat(opts.VaultPath)
	isNew := errors.Is(statErr, os.ErrNotExist)
	if isNew && createMode == "" {
		return nil, fmt.Errorf("no vault at %s (llavero serve creates one; pass --vault for another path)", opts.VaultPath)
	}

	mode := vault.ModePassphrase
	if isNew {
		m, err := vault.ParseUnlockMode(createMode)
		if err != nil {
			return nil, fmt.Errorf("--unlock: %w", err)
		}
		mode = m
	} else {
		m, err := vault.ReadMode(opts.VaultPath)
		if err != nil {
			return nil, fmt.Errorf("checking the vault's unlock mode: %w", err)
		}
		mode = m
	}

	if mode.NeedsTPM() {
		if err := tpm.Available(); err != nil {
			return nil, fmt.Errorf("this vault needs the TPM: %w", err)
		}
	}

	var passphrase []byte
	if mode.NeedsPassphrase() {
		p, err := readPassphrase(opts.PassFD, isNew, "")
		if err != nil {
			return nil, err // readPassphrase's errors already say what failed
		}
		defer zero(p)
		passphrase = p
	}

	if isNew {
		v, err := vault.Create(opts.VaultPath, mode, passphrase, tpm.Sealer{})
		if err != nil {
			return nil, fmt.Errorf("creating the vault: %w", err)
		}
		a.log.Info("created a new vault", zap.String("path", opts.VaultPath), zap.Stringer("unlock", mode))
		return v, nil
	}

	v, err := vault.Open(opts.VaultPath, passphrase, tpm.Sealer{})
	if err != nil {
		return nil, fmt.Errorf("unlocking the vault: %w", err)
	}
	a.log.Info("unlocked the vault", zap.String("path", opts.VaultPath),
		zap.Stringer("unlock", v.Mode()), zap.Int("passkeys", v.Count()))
	return v, nil
}
