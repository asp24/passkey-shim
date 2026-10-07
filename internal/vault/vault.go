// Package vault is the encrypted credential store.
//
// On-disk layout, version 2:
//
//	"PKV1" | version(1) | mode(1) | kdfSalt(16) | nonce(12) | AES-256-GCM ciphertext
//
// The whole header is passed to GCM as additional authenticated data, so
// neither the salt nor the unlock mode can be altered to force a weaker
// derivation. Version 1 files (no mode byte, passphrase only) still open, so
// existing vaults keep working.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	vaultMagic      = "PKV1"
	vaultVersion1   = 1
	vaultVersion2   = 2
	kdfIterations   = 600_000 // OWASP 2023 floor for PBKDF2-HMAC-SHA256
	saltLen         = 16
	nonceLen        = 12
	headerLenV1     = 4 + 1 + saltLen + nonceLen     // 33
	headerLenV2     = 4 + 1 + 1 + saltLen + nonceLen // 34
	credentialIDLen = 32
	tpmSecretLen    = 32
)

// UnlockMode records which factors are needed to derive the vault key.
type UnlockMode byte

// Unlock modes. The values are stored in the vault header.
const (
	ModePassphrase UnlockMode = 0 // passphrase only
	ModeTPM        UnlockMode = 1 // TPM-sealed secret only, so no typing at boot
	ModeTPMPass    UnlockMode = 2 // both
)

func (m UnlockMode) String() string {
	switch m {
	case ModePassphrase:
		return "passphrase"
	case ModeTPM:
		return "tpm"
	case ModeTPMPass:
		return "tpm+passphrase"
	default:
		return fmt.Sprintf("unknown(%d)", byte(m))
	}
}

// ParseUnlockMode parses a mode as String prints it.
func ParseUnlockMode(s string) (UnlockMode, error) {
	switch s {
	case "passphrase":
		return ModePassphrase, nil
	case "tpm":
		return ModeTPM, nil
	case "tpm+passphrase":
		return ModeTPMPass, nil
	default:
		return 0, fmt.Errorf("unknown unlock mode %q (want passphrase, tpm, or tpm+passphrase)", s)
	}
}

// NeedsPassphrase reports whether the mode asks the user for a passphrase.
func (m UnlockMode) NeedsPassphrase() bool { return m == ModePassphrase || m == ModeTPMPass }

// NeedsTPM reports whether the mode mixes in a TPM-sealed secret.
func (m UnlockMode) NeedsTPM() bool { return m == ModeTPM || m == ModeTPMPass }

// ErrBadPassphrase is returned when a vault does not decrypt.
var ErrBadPassphrase = errors.New("wrong passphrase, or vault file is corrupt")

// Sealer binds a secret to this machine, as a TPM does.
type Sealer interface {
	Seal(secret []byte) ([]byte, error)
	Unseal(blob []byte) ([]byte, error)
}

// Credential is one stored passkey. The JSON tags are the on-disk format.
type Credential struct {
	ID          []byte    `json:"id"`
	RPID        string    `json:"rp_id"`
	RPName      string    `json:"rp_name,omitempty"`
	UserID      []byte    `json:"user_id"`
	UserName    string    `json:"user_name,omitempty"`
	UserDisplay string    `json:"user_display,omitempty"`
	PrivateKey  []byte    `json:"private_key"` // PKCS#8
	SignCount   uint32    `json:"sign_count"`
	CreatedAt   time.Time `json:"created_at"`
}

type vaultContents struct {
	Credentials []Credential `json:"credentials"`
}

// Vault is an unlocked vault. All methods are safe for concurrent use.
type Vault struct {
	mu     sync.Mutex
	path   string
	sealer Sealer
	key    []byte
	salt   []byte
	mode   UnlockMode
	// upgradedFromV1 means the file on disk is still the old format and will
	// be rewritten as v2 on the next save.
	upgradedFromV1 bool
	contents       vaultContents
}

// DefaultPath is $XDG_DATA_HOME/llavero/vault.pkv.
func DefaultPath() string {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "llavero", "vault.pkv")
}

// tpmBlobPath keeps the sealed secret beside the vault. Both are needed, and
// neither is useful without this machine's TPM.
func tpmBlobPath(vaultPath string) string { return vaultPath + ".tpm" }

// deriveVaultKey combines whichever factors the mode calls for. HKDF is the
// combiner so that adding a factor cannot weaken the result.
//
// legacyV1 selects the original derivation, which used the PBKDF2 output
// directly as the AES key with no HKDF step. Version 1 vaults were written
// that way and must keep opening, so this is not optional and not removable
// while any v1 file might still exist.
func deriveVaultKey(mode UnlockMode, salt, passphrase, tpmSecret []byte, legacyV1 bool) ([]byte, error) {
	if legacyV1 {
		if mode != ModePassphrase {
			return nil, errors.New("version 1 vaults are passphrase-only")
		}
		key, err := pbkdf2.Key(sha256.New, string(passphrase), salt, kdfIterations, 32)
		if err != nil {
			return nil, fmt.Errorf("stretching passphrase: %w", err)
		}
		return key, nil
	}

	var ikm []byte

	if mode.NeedsPassphrase() {
		stretched, err := pbkdf2.Key(sha256.New, string(passphrase), salt, kdfIterations, 32)
		if err != nil {
			return nil, fmt.Errorf("stretching passphrase: %w", err)
		}
		ikm = append(ikm, stretched...)
	}
	if mode.NeedsTPM() {
		if len(tpmSecret) != tpmSecretLen {
			return nil, errors.New("TPM secret missing or wrong size")
		}
		ikm = append(ikm, tpmSecret...)
	}
	if len(ikm) == 0 {
		return nil, errors.New("no unlock factors available")
	}

	// The info string pins the derivation to a mode, so the same factors in a
	// different mode produce a different key.
	//
	// DO NOT change this literal. It is an input to the key derivation, not a
	// label: every existing v2 vault was encrypted under it, and editing it
	// (for instance while renaming the project) makes them all undecryptable
	// with no error message that would point at the cause.
	info := "passkey-vault/v2/" + mode.String()
	return hkdf.Key(sha256.New, ikm, salt, info, 32)
}

// ReadMode reports the mode a vault file was written in, without
// needing any credentials. Callers use it to know what to ask the user for.
func ReadMode(path string) (UnlockMode, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading vault: %w", err)
	}
	if len(raw) < headerLenV1 || string(raw[0:4]) != vaultMagic {
		return 0, errors.New("not a llavero vault file")
	}
	switch raw[4] {
	case vaultVersion1:
		return ModePassphrase, nil
	case vaultVersion2:
		if len(raw) < headerLenV2 {
			return 0, errors.New("vault file is truncated")
		}
		return UnlockMode(raw[5]), nil
	default:
		return 0, fmt.Errorf("unsupported vault version %d", raw[4])
	}
}

// Open decrypts an existing vault. It does not create one; use Create. sealer
// may be nil for a vault that does not use the TPM.
func Open(path string, passphrase []byte, sealer Sealer) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}
	if len(raw) < headerLenV1 || string(raw[0:4]) != vaultMagic {
		return nil, errors.New("not a llavero vault file")
	}

	var (
		mode      UnlockMode
		headerLen int
		legacyV1  bool
	)
	switch raw[4] {
	case vaultVersion1:
		mode, headerLen, legacyV1 = ModePassphrase, headerLenV1, true
	case vaultVersion2:
		if len(raw) < headerLenV2 {
			return nil, errors.New("vault file is truncated")
		}
		mode, headerLen = UnlockMode(raw[5]), headerLenV2
	default:
		return nil, fmt.Errorf("unsupported vault version %d", raw[4])
	}

	saltOff := headerLen - nonceLen - saltLen
	salt := raw[saltOff : saltOff+saltLen]
	nonce := raw[saltOff+saltLen : headerLen]
	ciphertext := raw[headerLen:]

	var tpmSecret []byte
	if mode.NeedsTPM() {
		if sealer == nil {
			return nil, errors.New("this vault is TPM-bound but no TPM is configured")
		}
		blob, err := os.ReadFile(tpmBlobPath(path))
		if err != nil {
			return nil, fmt.Errorf("this vault is TPM-bound but its sealed blob is unreadable: %w", err)
		}
		tpmSecret, err = sealer.Unseal(blob)
		if err != nil {
			return nil, fmt.Errorf("unsealing the vault's TPM secret: %w", err)
		}
	}

	key, err := deriveVaultKey(mode, salt, passphrase, tpmSecret, legacyV1)
	if err != nil {
		return nil, fmt.Errorf("deriving vault key: %w", err)
	}
	plain, err := decrypt(key, nonce, raw[:headerLen], ciphertext)
	if err != nil {
		if mode.NeedsTPM() && !mode.NeedsPassphrase() {
			return nil, errors.New("vault will not decrypt; the sealed blob and the vault file may be from different installs")
		}
		return nil, ErrBadPassphrase
	}

	// The file opened under the old derivation. Switch the in-memory key to
	// the current one so the next write lands as a consistent v2 file. Until
	// that write happens the file on disk stays v1 and stays readable, so an
	// interrupted upgrade loses nothing.
	if legacyV1 {
		upgraded, err := deriveVaultKey(mode, salt, passphrase, nil, false)
		if err != nil {
			return nil, fmt.Errorf("deriving upgraded vault key: %w", err)
		}
		key = upgraded
	}

	v := &Vault{path: path, sealer: sealer, key: key, salt: salt, mode: mode, upgradedFromV1: legacyV1}
	if err := json.Unmarshal(plain, &v.contents); err != nil {
		return nil, fmt.Errorf("vault contents are malformed: %w", err)
	}
	return v, nil
}

// Create writes a brand new empty vault in the requested mode, sealing a
// fresh TPM secret with sealer if the mode needs one.
func Create(path string, mode UnlockMode, passphrase []byte, sealer Sealer) (*Vault, error) {
	salt, err := randomBytes(saltLen, "salt")
	if err != nil {
		return nil, err
	}

	var tpmSecret []byte
	if mode.NeedsTPM() {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("creating vault directory: %w", err)
		}
		if tpmSecret, err = sealNewSecret(sealer, path); err != nil {
			return nil, err
		}
	}

	key, err := deriveVaultKey(mode, salt, passphrase, tpmSecret, false)
	if err != nil {
		return nil, fmt.Errorf("deriving vault key: %w", err)
	}
	v := &Vault{path: path, sealer: sealer, key: key, salt: salt, mode: mode}
	if err := v.save(); err != nil {
		return nil, fmt.Errorf("writing new vault: %w", err)
	}
	return v, nil
}

// sealNewSecret generates a TPM secret, seals it with sealer and writes the
// blob beside the vault at path. Its errors name the failed step, so callers
// return them as they are.
func sealNewSecret(sealer Sealer, path string) ([]byte, error) {
	if sealer == nil {
		return nil, errors.New("this unlock mode needs a TPM but none is configured")
	}
	secret, err := randomBytes(tpmSecretLen, "TPM secret")
	if err != nil {
		return nil, err
	}
	blob, err := sealer.Seal(secret)
	if err != nil {
		return nil, fmt.Errorf("sealing the vault's TPM secret: %w", err)
	}
	if err := os.WriteFile(tpmBlobPath(path), blob, 0o600); err != nil {
		return nil, fmt.Errorf("writing sealed blob: %w", err)
	}
	return secret, nil
}

// randomBytes returns n bytes from the system CSPRNG. Its error names what
// was being generated, so callers return it as it is.
func randomBytes(n int, what string) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating %s: %w", what, err)
	}
	return b, nil
}

// Rekey rewrites an already-open vault under a new mode, preserving every
// credential. The caller is responsible for having backed up the old file.
func (v *Vault) Rekey(mode UnlockMode, passphrase []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	salt, err := randomBytes(saltLen, "salt")
	if err != nil {
		return err
	}

	var tpmSecret []byte
	if mode.NeedsTPM() {
		if tpmSecret, err = sealNewSecret(v.sealer, v.path); err != nil {
			return err
		}
	}

	key, err := deriveVaultKey(mode, salt, passphrase, tpmSecret, false)
	if err != nil {
		return fmt.Errorf("deriving vault key: %w", err)
	}
	v.key, v.salt, v.mode, v.upgradedFromV1 = key, salt, mode, false
	if err := v.save(); err != nil {
		return fmt.Errorf("writing rekeyed vault: %w", err)
	}
	return nil
}

// newGCM returns AES-256-GCM under key. Its errors name the failed step, so
// callers return them as they are.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialising AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialising GCM: %w", err)
	}
	return gcm, nil
}

// decrypt opens ciphertext. An authentication failure comes back as the bare
// gcm.Open error, which callers turn into ErrBadPassphrase.
func decrypt(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// save rewrites the whole vault. Callers must hold v.mu, except on the
// creation path where no other goroutine can see v yet.
func (v *Vault) save() error {
	plain, err := json.Marshal(v.contents)
	if err != nil {
		return fmt.Errorf("encoding vault contents: %w", err)
	}

	// A fresh nonce on every write. Reusing one under the same key would leak
	// plaintext, and we rewrite the file on every registration and sign-in.
	nonce, err := randomBytes(nonceLen, "nonce")
	if err != nil {
		return err
	}

	header := make([]byte, 0, headerLenV2)
	header = append(header, vaultMagic...)
	header = append(header, vaultVersion2)
	header = append(header, byte(v.mode))
	header = append(header, v.salt...)
	header = append(header, nonce...)

	gcm, err := newGCM(v.key)
	if err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, header)

	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}
	// Write-then-rename so a crash mid-write cannot leave half a vault. The
	// temp file shares the directory so the rename stays on one filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(v.path), ".vault-*.tmp")
	if err != nil {
		return fmt.Errorf("creating vault temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("restricting vault temp file: %w", err)
	}
	if _, err := tmp.Write(append(header, ciphertext...)); err != nil {
		tmp.Close()
		return fmt.Errorf("writing vault temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing vault temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing vault temp file: %w", err)
	}
	if err := os.Rename(tmp.Name(), v.path); err != nil {
		return fmt.Errorf("replacing vault: %w", err)
	}
	return nil
}

// Account names the relying party and user a new credential is minted for.
type Account struct {
	RPID        string
	RPName      string
	UserID      []byte
	UserName    string
	UserDisplay string
}

// Mode reports how the vault is unlocked.
func (v *Vault) Mode() UnlockMode {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.mode
}

// AddCredential mints a keypair for a new registration and persists it.
func (v *Vault) AddCredential(acct Account) (*Credential, *ecdsa.PrivateKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating key pair: %w", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding private key: %w", err)
	}
	id, err := randomBytes(credentialIDLen, "credential id")
	if err != nil {
		return nil, nil, err
	}

	cred := Credential{
		ID:          id,
		RPID:        acct.RPID,
		RPName:      acct.RPName,
		UserID:      acct.UserID,
		UserName:    acct.UserName,
		UserDisplay: acct.UserDisplay,
		PrivateKey:  pkcs8,
		SignCount:   0,
		CreatedAt:   time.Now().UTC(),
	}

	// One passkey per (rpId, userId). Re-registering the same account replaces
	// the old key rather than accumulating credentials the RP will never ask
	// for again.
	replaced := false
	for i := range v.contents.Credentials {
		c := &v.contents.Credentials[i]
		if c.RPID == acct.RPID && string(c.UserID) == string(acct.UserID) {
			v.contents.Credentials[i] = cred
			replaced = true
			break
		}
	}
	if !replaced {
		v.contents.Credentials = append(v.contents.Credentials, cred)
	}

	if err := v.save(); err != nil {
		return nil, nil, fmt.Errorf("saving new credential: %w", err)
	}
	return &cred, priv, nil
}

// FindForRP returns every credential registered to an RP, newest first. A
// non-empty allow list restricts the result to those credential IDs.
func (v *Vault) FindForRP(rpID string, allow [][]byte) []Credential {
	v.mu.Lock()
	defer v.mu.Unlock()

	var out []Credential
	for _, c := range v.contents.Credentials {
		if c.RPID != rpID {
			continue
		}
		if len(allow) > 0 && !matchesAllowList(c.ID, allow) {
			continue
		}
		out = append(out, c)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func matchesAllowList(id []byte, allow [][]byte) bool {
	for _, a := range allow {
		if string(a) == string(id) {
			return true
		}
	}
	return false
}

// HasCredentialFor reports whether any of the excluded credential IDs is
// registered to rpID.
func (v *Vault) HasCredentialFor(rpID string, exclude [][]byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.contents.Credentials {
		if c.RPID == rpID && matchesAllowList(c.ID, exclude) {
			return true
		}
	}
	return false
}

// BumpSignCount increments and persists the per-credential counter.
func (v *Vault) BumpSignCount(id []byte) (uint32, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.contents.Credentials {
		if string(v.contents.Credentials[i].ID) == string(id) {
			v.contents.Credentials[i].SignCount++
			n := v.contents.Credentials[i].SignCount
			if err := v.save(); err != nil {
				return 0, fmt.Errorf("saving sign count: %w", err)
			}
			return n, nil
		}
	}
	return 0, errors.New("credential not found")
}

// List returns a copy of every stored credential, oldest first.
func (v *Vault) List() []Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Credential, len(v.contents.Credentials))
	copy(out, v.contents.Credentials)
	return out
}

// Remove deletes every credential matching pred and persists the result.
// It returns what was removed so the caller can report it.
func (v *Vault) Remove(pred func(Credential) bool) ([]Credential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	var kept, gone []Credential
	for _, c := range v.contents.Credentials {
		if pred(c) {
			gone = append(gone, c)
		} else {
			kept = append(kept, c)
		}
	}
	if len(gone) == 0 {
		return nil, nil
	}
	v.contents.Credentials = kept
	if err := v.save(); err != nil {
		return nil, fmt.Errorf("saving after removal: %w", err)
	}
	return gone, nil
}

// Count returns the number of stored credentials.
func (v *Vault) Count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.contents.Credentials)
}
