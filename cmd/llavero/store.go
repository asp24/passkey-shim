package main

import (
	"crypto/ecdsa"

	"llavero/internal/ctap"
	"llavero/internal/vault"
)

// vaultStore adapts the vault to the authenticator's Store port, so neither
// package has to know about the other.
type vaultStore struct{ v *vault.Vault }

var _ ctap.Store = vaultStore{}

func (s vaultStore) HasCredentialFor(rpID string, exclude [][]byte) bool {
	return s.v.HasCredentialFor(rpID, exclude)
}

func (s vaultStore) AddCredential(rp ctap.RPEntity, user ctap.UserEntity) ([]byte, *ecdsa.PrivateKey, error) {
	cred, priv, err := s.v.AddCredential(vault.Account{
		RPID:        rp.ID,
		RPName:      rp.Name,
		UserID:      user.ID,
		UserName:    user.Name,
		UserDisplay: user.DisplayName,
	})
	if err != nil {
		return nil, nil, err
	}
	return cred.ID, priv, nil
}

func (s vaultStore) FindForRP(rpID string, allow [][]byte) []ctap.Credential {
	stored := s.v.FindForRP(rpID, allow)
	out := make([]ctap.Credential, 0, len(stored))
	for _, c := range stored {
		out = append(out, ctap.Credential{
			ID:          c.ID,
			UserID:      c.UserID,
			UserName:    c.UserName,
			UserDisplay: c.UserDisplay,
			PrivateKey:  c.PrivateKey,
		})
	}
	return out
}

func (s vaultStore) BumpSignCount(id []byte) (uint32, error) {
	return s.v.BumpSignCount(id)
}
