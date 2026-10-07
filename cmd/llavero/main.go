// Command llavero is a software FIDO2 authenticator for Linux.
//
// It registers a virtual FIDO HID device with the kernel, so browsers discover
// it the same way they discover a hardware security key: no extension, no
// native messaging host, no browser configuration.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"

	"llavero/internal/approval"
	"llavero/internal/logging"
	"llavero/internal/notify"
	"llavero/internal/tpm"
	"llavero/internal/vault"
)

// aaguid identifies the authenticator model, not the user or the installation.
// It is public and intentionally fixed across installs.
var aaguid = [16]byte{
	0x9d, 0x3a, 0x5b, 0x71, 0x2c, 0x84, 0x4e, 0x1f,
	0xa7, 0x60, 0xc3, 0x18, 0xe5, 0x02, 0xbb, 0x46,
}

// app carries the parsed options and the dependencies every command shares.
type app struct {
	opts options
	log  *zap.Logger
	// desktop is shared by every component that talks to the user, so a
	// sticky prompt raised by one can be replaced or dismissed by another.
	desktop *notify.Desktop
}

type options struct {
	vaultPath   string
	unlock      string
	rekeyTo     string
	uv          string
	uvStrict    bool
	consent     string
	uvGrace     time.Duration
	list        bool
	forget      string
	mlock       bool
	autoApprove bool
	approval    string
	passFD      int
	newPassFD   int
}

func main() {
	var (
		opts        options
		tpmSelftest = flag.Bool("tpm-selftest", false, "seal and unseal a test secret, then exit")
		verboseFlag = flag.Bool("v", false, "log every CTAPHID frame")
	)
	flag.StringVar(&opts.vaultPath, "vault", vault.DefaultPath(), "path to the encrypted vault file")
	flag.StringVar(&opts.unlock, "unlock", "passphrase", "unlock mode for a NEW vault: passphrase, tpm, or tpm+passphrase")
	flag.StringVar(&opts.rekeyTo, "rekey", "", "re-encrypt an existing vault under this unlock mode, then exit")
	flag.StringVar(&opts.uv, "uv", "fingerprint", "user verification: fingerprint or prompt")
	flag.BoolVar(&opts.uvStrict, "uv-strict", false, "deny when the fingerprint sensor is unusable instead of falling back to the prompt")
	flag.StringVar(&opts.consent, "consent", "prompt", "how to take consent: prompt (click to approve, then touch) or fingerprint (touch only)")
	flag.DurationVar(&opts.uvGrace, "uv-grace", 5*time.Second, "reuse a just-completed fingerprint scan for repeat requests from the SAME site (0 disables)")
	flag.BoolVar(&opts.mlock, "mlock", true, "lock memory so keys cannot be written to swap")
	flag.BoolVar(&opts.list, "list", false, "list stored passkeys, then exit")
	flag.StringVar(&opts.forget, "forget", "", "delete passkeys matching a site or a credential id prefix, then exit")
	flag.StringVar(&opts.approval, "approval", approval.BackendAuto, "approval prompt: auto, omarchy or zenity")
	flag.BoolVar(&opts.autoApprove, "auto-approve", false, "approve every request without prompting (testing only)")
	flag.IntVar(&opts.passFD, "passphrase-fd", -1, "read the vault passphrase from this file descriptor")
	flag.IntVar(&opts.newPassFD, "new-passphrase-fd", -1, "read the NEW passphrase for -rekey from this file descriptor")
	flag.Parse()

	log := logging.New(*verboseFlag)
	a := &app{opts: opts, log: log, desktop: &notify.Desktop{}}

	var err error
	if *tpmSelftest {
		err = tpm.SelfTest(log.Named("tpm"))
	} else {
		err = a.run()
	}
	_ = log.Sync()
	if err != nil {
		// The final error is addressed to the person at the terminal and may
		// span several lines of advice, so it is printed rather than logged.
		fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		os.Exit(1)
	}
}
