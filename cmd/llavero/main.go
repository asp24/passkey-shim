// Command llavero is a software FIDO2 authenticator for Linux.
//
// It registers a virtual FIDO HID device with the kernel, so browsers discover
// it the same way they discover a hardware security key: no extension, no
// native messaging host, no browser configuration.
package main

import (
	"go.uber.org/zap"

	"llavero/internal/bootstrap"
	"llavero/internal/hardening"
	"llavero/internal/logging"
	"llavero/internal/notify"
	"llavero/internal/vault"
)

// aaguid identifies the authenticator model, not the user or the installation.
// It is public and intentionally fixed across installs.
var aaguid = [16]byte{
	0x9d, 0x3a, 0x5b, 0x71, 0x2c, 0x84, 0x4e, 0x1f,
	0xa7, 0x60, 0xc3, 0x18, 0xe5, 0x02, 0xbb, 0x46,
}

func main() {
	bootstrap.MustRunCommand(
		serveCommand(),
		listCommand(),
		forgetCommand(),
		rekeyCommand(),
		tpmSelftestCommand(),
	)
}

// app carries the vault options and the dependencies every vault command shares.
type app struct {
	opts *vaultOptions
	log  *zap.Logger
	// desktop is shared by every component that talks to the user, so a
	// sticky prompt raised by one can be replaced or dismissed by another.
	desktop *notify.Desktop
}

type logOptions struct {
	Verbose bool `short:"v" long:"verbose" description:"log debug detail, including every CTAPHID frame under serve"`
}

// vaultOptions are embedded by every command that opens the vault.
type vaultOptions struct {
	logOptions

	VaultPath string `long:"vault" value-name:"PATH" description:"path to the encrypted vault file (default: the per-user data directory)"`
	PassFD    int    `long:"passphrase-fd" value-name:"FD" default:"-1" description:"read the vault passphrase from this file descriptor"`
	NoMlock   bool   `long:"no-mlock" description:"do not lock memory, letting keys be written to swap"`
}

// Finalize fills in the defaults that are computed rather than constant.
func (o *vaultOptions) Finalize() error {
	if o.VaultPath == "" {
		o.VaultPath = vault.DefaultPath()
	}
	return nil
}

// withApp builds the shared dependencies and runs fn with them. Core dumps
// and ptrace are shut off first, before anything is decrypted.
func (o *vaultOptions) withApp(fn func(a *app) error) error {
	log := logging.New(o.Verbose)
	defer func() { _ = log.Sync() }()
	hardening.Apply(!o.NoMlock, log.Named("hardening"))
	return fn(&app{opts: o, log: log, desktop: &notify.Desktop{}})
}
