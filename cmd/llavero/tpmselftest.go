package main

import (
	"llavero/internal/bootstrap"
	"llavero/internal/logging"
	"llavero/internal/tpm"
)

func tpmSelftestCommand() bootstrap.Command {
	return bootstrap.Command{
		Name:        "tpm-selftest",
		Description: "seal and unseal a test secret",
		Options:     &tpmSelftestCmd{},
	}
}

// tpmSelftestCmd never opens the vault, so it takes no vault options and
// skips the hardening that guards decrypted keys.
type tpmSelftestCmd struct {
	logOptions
}

func (c *tpmSelftestCmd) Execute([]string) error {
	log := logging.New(c.Verbose)
	defer func() { _ = log.Sync() }()
	return tpm.SelfTest(log.Named("tpm"))
}
