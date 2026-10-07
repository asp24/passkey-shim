package vault

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

// fakeSealer stands in for the TPM. Its blob is the secret XORed with a
// per-machine pad, so a different fakeSealer cannot unseal it, just as a
// different TPM cannot.
type fakeSealer struct{ pad byte }

func (f fakeSealer) Seal(secret []byte) ([]byte, error) { return f.xor(secret), nil }

func (f fakeSealer) Unseal(blob []byte) ([]byte, error) { return f.xor(blob), nil }

func (f fakeSealer) xor(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b ^ f.pad
	}
	return out
}

type failingSealer struct{}

func (failingSealer) Seal([]byte) ([]byte, error)   { return nil, errors.New("no TPM") }
func (failingSealer) Unseal([]byte) ([]byte, error) { return nil, errors.New("no TPM") }

func TestCreateAndOpenEachMode(t *testing.T) {
	pass := []byte("correct horse battery staple")
	machine := fakeSealer{pad: 0x5a}
	for _, mode := range []UnlockMode{ModePassphrase, ModeTPM, ModeTPMPass} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault.pkv")
			v, err := Create(path, mode, pass, machine)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := v.AddCredential(Account{RPID: "example.test", UserID: []byte("u1")}); err != nil {
				t.Fatal(err)
			}

			got, err := ReadMode(path)
			if err != nil || got != mode {
				t.Fatalf("ReadMode() = %v, %v; want %v", got, err, mode)
			}
			reopened, err := Open(path, pass, machine)
			if err != nil {
				t.Fatalf("Open() = %v", err)
			}
			if reopened.Count() != 1 {
				t.Fatalf("Count() = %d, want 1", reopened.Count())
			}
		})
	}
}

func TestOpenRejectsWrongFactors(t *testing.T) {
	pass := []byte("correct horse battery staple")
	machine := fakeSealer{pad: 0x5a}
	tests := []struct {
		name   string
		mode   UnlockMode
		pass   []byte
		sealer Sealer
	}{
		{"wrong passphrase", ModePassphrase, []byte("wrong"), machine},
		{"other machine", ModeTPM, nil, fakeSealer{pad: 0x33}},
		{"no TPM configured", ModeTPM, nil, nil},
		{"TPM refuses", ModeTPM, nil, failingSealer{}},
		{"right TPM, wrong passphrase", ModeTPMPass, []byte("wrong"), machine},
		{"right passphrase, other machine", ModeTPMPass, pass, fakeSealer{pad: 0x33}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault.pkv")
			if _, err := Create(path, tt.mode, pass, machine); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(path, tt.pass, tt.sealer); err == nil {
				t.Fatal("Open() succeeded with the wrong factors")
			}
		})
	}
}

func TestCreateTPMModeNeedsSealer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pkv")
	if _, err := Create(path, ModeTPM, nil, nil); err == nil {
		t.Fatal("Create() made a TPM vault without a sealer")
	}
}

func TestRekeyPreservesCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pkv")
	pass := []byte("correct horse battery staple")
	machine := fakeSealer{pad: 0x5a}
	v, err := Create(path, ModePassphrase, pass, machine)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.AddCredential(Account{RPID: "example.test", UserID: []byte("u1")}); err != nil {
		t.Fatal(err)
	}
	if err := v.Rekey(ModeTPM, nil); err != nil {
		t.Fatal(err)
	}
	if v.Mode() != ModeTPM {
		t.Fatalf("Mode() = %v after rekey, want tpm", v.Mode())
	}
	if _, err := Open(path, pass, nil); err == nil {
		t.Fatal("old passphrase still opens the rekeyed vault without a TPM")
	}
	reopened, err := Open(path, nil, machine)
	if err != nil {
		t.Fatalf("rekeyed vault does not reopen: %v", err)
	}
	if reopened.Count() != 1 {
		t.Fatalf("Count() = %d after rekey, want 1", reopened.Count())
	}
}

func TestCredentialLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pkv")
	v, err := Create(path, ModePassphrase, []byte("correct horse battery staple"), nil)
	if err != nil {
		t.Fatal(err)
	}
	add := func(rpID, user string) []byte {
		t.Helper()
		c, _, err := v.AddCredential(Account{RPID: rpID, UserID: []byte(user), UserName: user})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	alice := add("example.test", "alice")
	bob := add("example.test", "bob")
	add("other.test", "alice")

	// Re-registering the same account replaces its key instead of piling up.
	alice2 := add("example.test", "alice")
	if v.Count() != 3 {
		t.Fatalf("Count() = %d after re-registration, want 3", v.Count())
	}

	tests := []struct {
		name  string
		rpID  string
		allow [][]byte
		want  [][]byte
	}{
		{"all for site, newest first", "example.test", nil, [][]byte{bob, alice2}},
		{"allow list narrows", "example.test", [][]byte{bob}, [][]byte{bob}},
		{"replaced id is gone", "example.test", [][]byte{alice}, nil},
		{"unknown site", "nowhere.test", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.FindForRP(tt.rpID, tt.allow)
			if len(got) != len(tt.want) {
				t.Fatalf("FindForRP() returned %d credentials, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if !bytes.Equal(got[i].ID, tt.want[i]) {
					t.Fatalf("FindForRP()[%d] = %x, want %x", i, got[i].ID, tt.want[i])
				}
			}
		})
	}

	if !v.HasCredentialFor("example.test", [][]byte{bob}) {
		t.Error("HasCredentialFor() missed a registered credential")
	}
	if v.HasCredentialFor("other.test", [][]byte{bob}) {
		t.Error("HasCredentialFor() matched a credential from another site")
	}
}
