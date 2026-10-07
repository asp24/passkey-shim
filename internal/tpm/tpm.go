// Package tpm seals small secrets to this machine's TPM.
//
// A 32-byte secret is sealed to this machine's TPM and mixed into the vault
// key. The sealed blob is useless on any other machine, so a copied vault file
// plus a copied blob still decrypts to nothing elsewhere.
//
// Deliberately NOT bound to PCR values. PCR policies break on firmware and
// kernel updates, and a passkey vault that locks you out after a routine
// update is worse than one that does not resist an attacker who already has
// code execution on the running machine. Machine binding is the goal here;
// defending the live system is the approval prompt's job.
package tpm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/user"
	"slices"
	"syscall"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

const tpmDevice = "/dev/tpmrm0"

// sealedObjectTemplate describes a keyedHash object holding opaque data.
// FixedTPM and FixedParent are what make the blob non-duplicable: the TPM
// refuses to export it, so it cannot be migrated to another machine.
var sealedObjectTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgKeyedHash,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:     true,
		FixedParent:  true,
		UserWithAuth: true,
		NoDA:         true, // never contributes to dictionary-attack lockout
	},
}

// Available checks that the TPM resource manager can be opened, and explains
// the fix when it cannot.
func Available() error {
	f, err := os.OpenFile(tpmDevice, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("no access to %s.\n       %s", tpmDevice, tssGroupAdvice())
		}
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is missing; this machine has no usable TPM 2.0", tpmDevice)
		}
		return fmt.Errorf("opening %s: %w", tpmDevice, err)
	}
	f.Close()
	return nil
}

// withPrimary runs fn against a freshly derived storage root key. The SRK is
// regenerated from the fixed TCG template every time rather than persisted to
// an NV handle, so the same key comes back on every run without us occupying
// a handle the rest of the system might want.
func withPrimary(fn func(tpm transport.TPM, srk tpm2.AuthHandle) error) error {
	tpm, err := linuxtpm.Open(tpmDevice)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer tpm.Close()

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}
	rsp, err := createPrimary.Execute(tpm)
	if err != nil {
		return fmt.Errorf("creating storage root key: %w", err)
	}
	defer func() {
		flush := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		_, _ = flush.Execute(tpm)
	}()

	return fn(tpm, tpm2.AuthHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	})
}

// Sealer seals secrets to this machine's TPM. The zero value is ready to use.
type Sealer struct{}

// Seal seals secret and returns a blob to store on disk.
func (Sealer) Seal(secret []byte) ([]byte, error) {
	var blob []byte
	err := withPrimary(func(tpm transport.TPM, srk tpm2.AuthHandle) error {
		create := tpm2.Create{
			ParentHandle: srk,
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{
					Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
						Buffer: secret,
					}),
				},
			},
			InPublic: tpm2.New2B(sealedObjectTemplate),
		}
		rsp, err := create.Execute(tpm)
		if err != nil {
			return fmt.Errorf("sealing to TPM: %w", err)
		}
		blob = encodeBlob(tpm2.Marshal(rsp.OutPublic), tpm2.Marshal(rsp.OutPrivate))
		return nil
	})
	return blob, err
}

// Unseal recovers the secret from a blob produced by Seal on this same
// machine.
func (Sealer) Unseal(blob []byte) ([]byte, error) {
	pubBytes, privBytes, err := decodeBlob(blob)
	if err != nil {
		return nil, err // decodeBlob says which part is truncated
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("sealed blob is corrupt (public area): %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return nil, fmt.Errorf("sealed blob is corrupt (private area): %w", err)
	}

	var secret []byte
	err = withPrimary(func(tpm transport.TPM, srk tpm2.AuthHandle) error {
		load := tpm2.Load{
			ParentHandle: srk,
			InPrivate:    *priv,
			InPublic:     *pub,
		}
		loaded, err := load.Execute(tpm)
		if err != nil {
			return fmt.Errorf("the TPM refused this sealed blob, which means it was "+
				"sealed on a different machine or the TPM has been cleared: %w", err)
		}
		defer func() {
			flush := tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}
			_, _ = flush.Execute(tpm)
		}()

		unseal := tpm2.Unseal{
			ItemHandle: tpm2.NamedHandle{
				Handle: loaded.ObjectHandle,
				Name:   loaded.Name,
			},
		}
		rsp, err := unseal.Execute(tpm)
		if err != nil {
			return fmt.Errorf("unsealing: %w", err)
		}
		secret = append([]byte{}, rsp.OutData.Buffer...)
		return nil
	})
	if err != nil {
		return nil, err // every step inside withPrimary names itself
	}
	return secret, nil
}

// encodeBlob frames the two TPM areas with explicit lengths, so the file stays
// parseable even though both halves are already self-describing.
func encodeBlob(pub, priv []byte) []byte {
	out := make([]byte, 0, 8+len(pub)+len(priv))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(pub)))
	out = append(out, l[:]...)
	out = append(out, pub...)
	binary.BigEndian.PutUint32(l[:], uint32(len(priv)))
	out = append(out, l[:]...)
	out = append(out, priv...)
	return out
}

func decodeBlob(b []byte) (pub, priv []byte, err error) {
	if len(b) < 8 {
		return nil, nil, errors.New("sealed blob is truncated")
	}
	n := binary.BigEndian.Uint32(b[0:4])
	if uint64(len(b)) < 4+uint64(n)+4 {
		return nil, nil, errors.New("sealed blob is truncated (public area)")
	}
	pub = b[4 : 4+n]
	rest := b[4+n:]
	m := binary.BigEndian.Uint32(rest[0:4])
	if uint64(len(rest)) < 4+uint64(m) {
		return nil, nil, errors.New("sealed blob is truncated (private area)")
	}
	priv = rest[4 : 4+m]
	return pub, priv, nil
}

// tssGroupAdvice distinguishes the two reasons the TPM is unreachable, because
// the fix is completely different and the wrong hint sends people in circles.
//
// A process inherits its supplementary groups at login. Running usermod does
// not change any process that already exists, including the systemd --user
// manager, so "add yourself to the group" is useless advice to someone who
// already did exactly that ten minutes ago.
func tssGroupAdvice() string {
	grp, err := user.LookupGroup("tss")
	if err != nil {
		return "This system has no tss group, so the TPM device is not delegated to users."
	}

	inDatabase := false
	if u, err := user.Current(); err == nil {
		if ids, err := u.GroupIds(); err == nil {
			inDatabase = slices.Contains(ids, grp.Gid)
		}
	}

	inProcess := false
	if gids, err := syscall.Getgroups(); err == nil {
		for _, g := range gids {
			if fmt.Sprint(g) == grp.Gid {
				inProcess = true
				break
			}
		}
	}

	switch {
	case inDatabase && !inProcess:
		return "You ARE in the tss group, but this process is not: supplementary groups\n" +
			"       are fixed at login, so anything started before `usermod` still has the\n" +
			"       old set. Log out and back in (a full session restart, not just a new\n" +
			"       terminal), then start this again.\n" +
			"       To check without logging out:  sudo -u $USER -g tss " + os.Args[0]
	case !inDatabase:
		return "Add yourself to the tss group, then log out and back in:\n" +
			"         sudo usermod -aG tss $USER"
	default:
		return "You are in the tss group and so is this process, so the device permissions\n" +
			"       themselves are wrong. Check:  ls -l " + tpmDevice
	}
}
