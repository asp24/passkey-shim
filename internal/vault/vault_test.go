package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeLegacyV1Vault reproduces the original on-disk format byte for byte:
// a 33-byte header and the raw PBKDF2 output used directly as the AES key,
// with no HKDF step. This is what shipped before unlock modes existed, and
// real vaults are still in this format.
func writeLegacyV1Vault(t *testing.T, path string, passphrase []byte, contents vaultContents) {
	t.Helper()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, kdfIterations, 32)
	if err != nil {
		t.Fatal(err)
	}

	header := make([]byte, 0, headerLenV1)
	header = append(header, vaultMagic...)
	header = append(header, vaultVersion1)
	header = append(header, salt...)
	header = append(header, nonce...)

	plain, err := json.Marshal(contents)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nil, nonce, plain, header)

	if err := os.WriteFile(path, append(header, ciphertext...), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sampleContents(t *testing.T) vaultContents {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return vaultContents{Credentials: []Credential{{
		ID:         []byte("credential-id-0001"),
		RPID:       "example.test",
		UserID:     []byte("user-0001"),
		UserName:   "alice",
		PrivateKey: pkcs8,
		SignCount:  7,
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}}}
}

// A vault written in the original format must still open. Changing the key
// derivation without this path is how existing passkeys become unrecoverable.
func TestOpensLegacyV1Vault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pkv")
	pass := []byte("correct horse battery staple")
	want := sampleContents(t)

	writeLegacyV1Vault(t, path, pass, want)

	v, err := Open(path, pass, nil)
	if err != nil {
		t.Fatalf("a version 1 vault failed to open: %v", err)
	}
	if v.mode != ModePassphrase {
		t.Errorf("mode = %v, want passphrase", v.mode)
	}
	if !v.upgradedFromV1 {
		t.Error("upgradedFromV1 should be set for a v1 file")
	}
	if got := v.Count(); got != 1 {
		t.Fatalf("credential count = %d, want 1", got)
	}
	if got := v.contents.Credentials[0].UserName; got != "alice" {
		t.Errorf("username = %q, want alice", got)
	}
	if got := v.contents.Credentials[0].SignCount; got != 7 {
		t.Errorf("sign count = %d, want 7", got)
	}
	if !bytes.Equal(v.contents.Credentials[0].PrivateKey, want.Credentials[0].PrivateKey) {
		t.Error("private key did not survive the read")
	}
}

func TestLegacyV1WrongPassphraseStillFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pkv")
	writeLegacyV1Vault(t, path, []byte("the real passphrase"), sampleContents(t))

	if _, err := Open(path, []byte("not the passphrase"), nil); err == nil {
		t.Fatal("a wrong passphrase opened a v1 vault")
	}
}

// Opening a v1 file and then writing must produce a v2 file that reopens with
// the same passphrase, with nothing lost in the format change.
func TestV1UpgradesToV2OnWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.pkv")
	pass := []byte("correct horse battery staple")
	writeLegacyV1Vault(t, path, pass, sampleContents(t))

	v, err := Open(path, pass, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Any mutation triggers a save.
	if _, err := v.BumpSignCount([]byte("credential-id-0001")); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if raw[4] != vaultVersion2 {
		t.Fatalf("file version = %d after write, want %d", raw[4], vaultVersion2)
	}

	reopened, err := Open(path, pass, nil)
	if err != nil {
		t.Fatalf("upgraded vault will not reopen: %v", err)
	}
	if reopened.upgradedFromV1 {
		t.Error("upgradedFromV1 should be clear on a v2 file")
	}
	if got := reopened.Count(); got != 1 {
		t.Fatalf("credential count = %d after upgrade, want 1", got)
	}
	if got := reopened.contents.Credentials[0].SignCount; got != 8 {
		t.Errorf("sign count = %d, want 8", got)
	}
}

// A v2 vault must not be openable with the v1 derivation, and vice versa, or
// the version byte is not actually selecting anything.
func TestV1AndV2DerivationsDiffer(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAB}, saltLen)
	pass := []byte("same passphrase")

	legacy, err := deriveVaultKey(ModePassphrase, salt, pass, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	current, err := deriveVaultKey(ModePassphrase, salt, pass, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(legacy, current) {
		t.Fatal("v1 and v2 derivations produced the same key; the version byte selects nothing")
	}
}

// Each unlock mode must produce a distinct key from identical inputs, so a
// vault cannot be opened by presenting the same factors under another mode.
func TestUnlockModesProduceDistinctKeys(t *testing.T) {
	salt := bytes.Repeat([]byte{0xCD}, saltLen)
	pass := []byte("same passphrase")
	tpmSecret := bytes.Repeat([]byte{0xEF}, tpmSecretLen)

	keys := map[string]string{}
	for _, m := range []UnlockMode{ModePassphrase, ModeTPM, ModeTPMPass} {
		k, err := deriveVaultKey(m, salt, pass, tpmSecret, false)
		if err != nil {
			t.Fatalf("%v: %v", m, err)
		}
		if prev, seen := keys[string(k)]; seen {
			t.Fatalf("modes %s and %s derive the same key", prev, m)
		}
		keys[string(k)] = m.String()
	}
}
