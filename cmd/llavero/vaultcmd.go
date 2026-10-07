package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"llavero/internal/tpm"
	"llavero/internal/vault"
)

// loadVault opens an existing vault or creates one, asking only for the
// factors the vault's own mode requires.
func (a *app) loadVault() (*vault.Vault, error) {
	opts := a.opts
	_, statErr := os.Stat(opts.vaultPath)
	isNew := errors.Is(statErr, os.ErrNotExist)

	mode := vault.ModePassphrase
	if isNew {
		m, err := vault.ParseUnlockMode(opts.unlock)
		if err != nil {
			return nil, fmt.Errorf("-unlock: %w", err)
		}
		mode = m
	} else {
		m, err := vault.ReadMode(opts.vaultPath)
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
		p, err := readPassphrase(opts.passFD, isNew, "")
		if err != nil {
			return nil, err // readPassphrase's errors already say what failed
		}
		defer zero(p)
		passphrase = p
	}

	if isNew {
		v, err := vault.Create(opts.vaultPath, mode, passphrase, tpm.Sealer{})
		if err != nil {
			return nil, fmt.Errorf("creating the vault: %w", err)
		}
		a.log.Info("created a new vault", zap.String("path", opts.vaultPath), zap.Stringer("unlock", mode))
		return v, nil
	}

	v, err := vault.Open(opts.vaultPath, passphrase, tpm.Sealer{})
	if err != nil {
		return nil, fmt.Errorf("unlocking the vault: %w", err)
	}
	a.log.Info("unlocked the vault", zap.String("path", opts.vaultPath),
		zap.Stringer("unlock", v.Mode()), zap.Int("passkeys", v.Count()))
	return v, nil
}

func (a *app) runRekey() error {
	opts := a.opts
	newMode, err := vault.ParseUnlockMode(opts.rekeyTo)
	if err != nil {
		return fmt.Errorf("-rekey: %w", err)
	}
	if newMode.NeedsTPM() {
		if err := tpm.Available(); err != nil {
			return fmt.Errorf("%s needs the TPM: %w", newMode, err)
		}
	}

	v, err := a.loadVault()
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
	backup := fmt.Sprintf("%s.bak-%s", opts.vaultPath, stamp)
	if err := copyFile(opts.vaultPath, backup); err != nil {
		return fmt.Errorf("could not back up the vault, refusing to rekey: %w", err)
	}
	backups := backup
	if v.Mode().NeedsTPM() {
		blob := vault.SealedBlobPath(opts.vaultPath)
		blobBackup := fmt.Sprintf("%s.bak-%s", blob, stamp)
		if err := copyFile(blob, blobBackup); err != nil {
			return fmt.Errorf("could not back up the sealed blob, refusing to rekey: %w", err)
		}
		backups = fmt.Sprintf("%s with %s (restore both, as %s and %s)", backup, blobBackup, opts.vaultPath, blob)
	}
	a.log.Info("backed up the existing vault", zap.String("backup", backups))

	var newPass []byte
	if newMode.NeedsPassphrase() {
		p, err := readPassphrase(opts.newPassFD, true, "new ")
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
	check, err := vault.Open(opts.vaultPath, newPass, tpm.Sealer{})
	if err != nil {
		return fmt.Errorf("the rekeyed vault does not reopen (restore from %s): %w", backups, err)
	}
	if check.Count() != v.Count() {
		return fmt.Errorf("credential count changed during rekey (restore from %s)", backups)
	}
	a.log.Info("verified: the rekeyed vault reopens", zap.Int("passkeys", check.Count()))
	if err := v.RemovePreviousBlob(); err != nil {
		a.log.Warn("could not remove the previous sealed blob; it is safe to delete by hand",
			zap.String("path", vault.PreviousBlobPath(opts.vaultPath)), zap.Error(err))
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

// runList prints what is in the vault. Useful on its own, and the only way to
// find the id of something worth deleting.
func (a *app) runList() error {
	v, err := a.loadVault()
	if err != nil {
		return err // loadVault's errors already say what failed
	}
	creds := v.List()
	if len(creds) == 0 {
		fmt.Println("\nThe vault is empty.")
		return nil
	}
	fmt.Printf("\n%-28s  %-34s  %-16s  %5s  %s\n", "SITE", "ACCOUNT", "CREDENTIAL", "USES", "CREATED")
	for _, c := range creds {
		account := c.UserName
		if account == "" {
			account = c.UserDisplay
		}
		fmt.Printf("%-28s  %-34s  %-16x  %5d  %s\n",
			truncate(c.RPID, 28), truncate(account, 34), c.ID[:8], c.SignCount,
			c.CreatedAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Printf("\n%d passkey(s).\n", len(creds))
	return nil
}

// runForget deletes credentials by site or by credential id prefix. It always
// shows what it is about to remove and asks first: there is no undo, and a
// deleted passkey may be the only way into an account.
func (a *app) runForget() error {
	opts := a.opts
	if serviceHasOpen(opts.vaultPath) {
		return errors.New("the llavero service is running against this vault and holds its own\n" +
			"       copy in memory, so its next write would resurrect anything deleted here.\n" +
			"       Stop it first:  systemctl --user stop llavero.service")
	}

	v, err := a.loadVault()
	if err != nil {
		return err // loadVault's errors already say what failed
	}

	needle := strings.ToLower(opts.forget)
	match := func(c vault.Credential) bool {
		return strings.ToLower(c.RPID) == needle ||
			strings.HasPrefix(strings.ToLower(fmt.Sprintf("%x", c.ID)), needle)
	}

	var doomed []vault.Credential
	for _, c := range v.List() {
		if match(c) {
			doomed = append(doomed, c)
		}
	}
	if len(doomed) == 0 {
		return fmt.Errorf("nothing in the vault matches %q (try -list)", opts.forget)
	}

	fmt.Printf("\nAbout to delete %d passkey(s):\n\n", len(doomed))
	for _, c := range doomed {
		fmt.Printf("  %s  %s  %x  (used %d time(s))\n", c.RPID, c.UserName, c.ID[:8], c.SignCount)
	}
	// Echo the exact string back. Saying "type the site name" invites a near
	// miss on values like ".dummy", where the leading dot is easy to drop.
	fmt.Printf("\nThis cannot be undone. Type %q to confirm: ", opts.forget)

	var typed string
	fmt.Scanln(&typed)
	if strings.ToLower(strings.TrimSpace(typed)) != needle {
		return fmt.Errorf("confirmation did not match (wanted %q, got %q), nothing was deleted",
			opts.forget, strings.TrimSpace(typed))
	}

	gone, err := v.Remove(match)
	if err != nil {
		return fmt.Errorf("deleting passkeys: %w", err)
	}
	a.log.Info("deleted passkeys", zap.Int("deleted", len(gone)), zap.Int("remaining", v.Count()))
	return nil
}

// serviceHasOpen reports whether the running service is using this very vault.
// Editing a different file while the daemon runs is harmless, so the guard is
// scoped to the path rather than refusing whenever the service happens to be up.
func serviceHasOpen(vaultPath string) bool {
	out, err := exec.Command("systemctl", "--user", "is-active", "llavero.service").Output()
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return false
	}

	// The unit passes no -vault, so the service is on the default path. If it
	// ever gains one, prefer what the unit actually says.
	servicePath := vault.DefaultPath()
	if line, err := exec.Command("systemctl", "--user", "show", "-p", "ExecStart",
		"--value", "llavero.service").Output(); err == nil {
		fields := strings.Fields(string(line))
		for i, f := range fields {
			if f == "-vault" && i+1 < len(fields) {
				servicePath = fields[i+1]
			}
		}
	}
	return sameFile(vaultPath, servicePath)
}

// sameFile compares paths after resolving symlinks, falling back to a cleaned
// absolute comparison when a path does not exist yet.
func sameFile(a, b string) bool {
	resolve := func(p string) string {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return real
		}
		return filepath.Clean(p)
	}
	return resolve(a) == resolve(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "\u2026"
}
