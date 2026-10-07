package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var errInjected = errors.New("injected rename failure")

// failRenameTo makes renameFile fail whenever it would create target.
func failRenameTo(t *testing.T, target string) {
	t.Helper()
	renameFile = func(oldpath, newpath string) error {
		if newpath == target {
			return errInjected
		}
		return os.Rename(oldpath, newpath)
	}
	t.Cleanup(func() { renameFile = os.Rename })
}

// factors are what Open needs for a mode.
func factors(mode UnlockMode, pass []byte, sealer Sealer) ([]byte, Sealer) {
	var p []byte
	if mode.NeedsPassphrase() {
		p = pass
	}
	var s Sealer
	if mode.NeedsTPM() {
		s = sealer
	}
	return p, s
}

func newVaultWithCredential(t *testing.T, mode UnlockMode, pass []byte, sealer Sealer) (string, *Vault) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.pkv")
	p, _ := factors(mode, pass, sealer)
	// The daemon always hands the vault a sealer, so a rekey into a TPM mode
	// can use it.
	v, err := Create(path, mode, p, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.AddCredential(Account{RPID: "example.test", UserID: []byte("u1")}); err != nil {
		t.Fatal(err)
	}
	return path, v
}

func mustOpen(t *testing.T, path string, mode UnlockMode, pass []byte, sealer Sealer) *Vault {
	t.Helper()
	p, s := factors(mode, pass, sealer)
	v, err := Open(path, p, s)
	if err != nil {
		t.Fatalf("vault does not open in %s mode: %v", mode, err)
	}
	if v.Count() != 1 {
		t.Fatalf("Count() = %d, want 1", v.Count())
	}
	return v
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// A failed save during rekey must leave the vault and its blob exactly as
// they were, on disk and in memory, for every pair of modes.
func TestRekeySaveFailureChangesNothing(t *testing.T) {
	pass, newPass := []byte("old passphrase"), []byte("new passphrase")
	machine := fakeSealer{pad: 0x5a}
	modes := []UnlockMode{ModePassphrase, ModeTPM, ModeTPMPass}
	for _, from := range modes {
		for _, to := range modes {
			if from == to {
				continue
			}
			t.Run(from.String()+"->"+to.String(), func(t *testing.T) {
				path, v := newVaultWithCredential(t, from, pass, machine)
				blobBefore, _ := os.ReadFile(SealedBlobPath(path))

				failRenameTo(t, path)
				err := v.Rekey(to, newPass)
				if !errors.Is(err, errInjected) {
					t.Fatalf("Rekey() = %v, want the injected failure", err)
				}
				renameFile = os.Rename

				if v.Mode() != from {
					t.Fatalf("Mode() = %v after a failed rekey, want %v", v.Mode(), from)
				}
				if exists(pendingBlobPath(path)) || exists(PreviousBlobPath(path)) {
					t.Fatal("a failed rekey left blob files behind")
				}
				blobAfter, _ := os.ReadFile(SealedBlobPath(path))
				if string(blobAfter) != string(blobBefore) {
					t.Fatal("a failed rekey changed the sealed blob")
				}
				mustOpen(t, path, from, pass, machine)

				// The in-memory vault still writes with the old key.
				if _, _, err := v.AddCredential(Account{RPID: "other.test", UserID: []byte("u2")}); err != nil {
					t.Fatal(err)
				}
				p, s := factors(from, pass, machine)
				if _, err := Open(path, p, s); err != nil {
					t.Fatalf("vault written after a failed rekey does not open: %v", err)
				}
			})
		}
	}
}

// If the blobs cannot be swapped after the vault was saved, nothing is lost:
// the error names the renames that finish the job, and doing them works.
func TestRekeyBlobSwapFailureIsRecoverable(t *testing.T) {
	pass, newPass := []byte("old passphrase"), []byte("new passphrase")
	machine := fakeSealer{pad: 0x5a}
	tests := []struct {
		name   string
		target func(path string) string
	}{
		{"parking the old blob", PreviousBlobPath},
		{"placing the new blob", SealedBlobPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, v := newVaultWithCredential(t, ModeTPM, pass, machine)

			failRenameTo(t, tt.target(path))
			err := v.Rekey(ModeTPMPass, newPass)
			renameFile = os.Rename
			if !errors.Is(err, errInjected) {
				t.Fatalf("Rekey() = %v, want the injected failure", err)
			}
			pending := pendingBlobPath(path)
			if !strings.Contains(err.Error(), pending) {
				t.Fatalf("error %q does not say where the new blob is", err)
			}

			// Finish by hand, as the error says.
			if exists(SealedBlobPath(path)) {
				if err := os.Rename(SealedBlobPath(path), PreviousBlobPath(path)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(pending, SealedBlobPath(path)); err != nil {
				t.Fatal(err)
			}
			mustOpen(t, path, ModeTPMPass, newPass, machine)
		})
	}
}

func TestRekeyParksPreviousBlob(t *testing.T) {
	pass, newPass := []byte("old passphrase"), []byte("new passphrase")
	machine := fakeSealer{pad: 0x5a}
	tests := []struct {
		from, to   UnlockMode
		wantParked bool
	}{
		{ModeTPM, ModeTPMPass, true},
		{ModeTPMPass, ModeTPM, true},
		{ModeTPM, ModePassphrase, true},
		{ModePassphrase, ModeTPM, false},
	}
	for _, tt := range tests {
		t.Run(tt.from.String()+"->"+tt.to.String(), func(t *testing.T) {
			path, v := newVaultWithCredential(t, tt.from, pass, machine)
			if err := v.Rekey(tt.to, newPass); err != nil {
				t.Fatal(err)
			}
			if exists(pendingBlobPath(path)) {
				t.Fatal("pending blob left behind after a successful rekey")
			}
			if got := exists(PreviousBlobPath(path)); got != tt.wantParked {
				t.Fatalf("previous blob parked = %v, want %v", got, tt.wantParked)
			}
			mustOpen(t, path, tt.to, newPass, machine)

			if err := v.RemovePreviousBlob(); err != nil {
				t.Fatal(err)
			}
			if exists(PreviousBlobPath(path)) {
				t.Fatal("RemovePreviousBlob left the file")
			}
			if err := v.RemovePreviousBlob(); err != nil {
				t.Fatalf("second RemovePreviousBlob() = %v, want nil", err)
			}
		})
	}
}
