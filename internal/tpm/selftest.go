package tpm

import (
	"bytes"
	"errors"
)

// SelfTest proves the TPM path works on this machine: seal a known secret,
// unseal it, and confirm the bytes survive.
func SelfTest(logf func(string, ...any)) error {
	if err := Available(); err != nil {
		return err
	}
	logf("TPM device is reachable")

	var sealer Sealer
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i * 7)
	}

	blob, err := sealer.Seal(secret)
	if err != nil {
		return err
	}
	logf("sealed a %d-byte secret into a %d-byte blob", len(secret), len(blob))

	got, err := sealer.Unseal(blob)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, secret) {
		return errors.New("unsealed bytes do not match what was sealed")
	}
	logf("unsealed and matched")

	// Two seals of the same secret must differ, or the TPM is not adding its
	// own entropy to the wrapping and something is very wrong.
	blob2, err := sealer.Seal(secret)
	if err != nil {
		return err
	}
	if bytes.Equal(blob, blob2) {
		return errors.New("two seals of the same secret produced identical blobs")
	}
	logf("re-sealing produced a distinct blob, as it should")

	bad := append([]byte{}, blob...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := sealer.Unseal(bad); err == nil {
		return errors.New("a corrupted blob unsealed successfully, which must not happen")
	}
	logf("a corrupted blob was correctly rejected")

	logf("TPM selftest passed")
	return nil
}
