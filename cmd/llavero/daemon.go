package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"llavero/internal/approval"
	"llavero/internal/ctap"
	"llavero/internal/ctaphid"
	"llavero/internal/fingerprint"
	"llavero/internal/hardening"
	"llavero/internal/hidbridge"
)

func run(opts options) error {
	// Before anything touches a key. Core dumps and ptrace are shut off first
	// so there is no window in which a decrypted vault could escape.
	hardening.Apply(opts.mlock, logf)

	if opts.rekeyTo != "" {
		return runRekey(opts)
	}
	if opts.list {
		return runList(opts)
	}
	if opts.forget != "" {
		return runForget(opts)
	}

	// Connect to the broker before asking for a passphrase, so a missing
	// system service does not cost the user a typed secret first.
	dev, err := hidbridge.Dial(hidbridge.SocketPath(os.Getuid()), 0)
	if err != nil {
		return fmt.Errorf("UHID service: %w (enable llavero-uhid@%d.service)", err, os.Getuid())
	}
	defer dev.Close()

	v, err := loadVault(opts)
	if err != nil {
		return err
	}

	var ap ctap.Approver
	if opts.autoApprove {
		logf("WARNING: -auto-approve is set. Every request will be granted without asking.")
		ap = approval.Auto{}
	} else {
		ap, err = approval.NewMenu()
		if err != nil {
			return fmt.Errorf("no approval UI available: %w\n"+
				"       (omarchy-menu-select is required, or run with -auto-approve for testing)", err)
		}
	}

	// Keep this an interface and assign it only on success: a nil
	// *fingerprint.Verifier stored here would compare non-nil.
	var verifier ctap.UserVerifier
	switch opts.uv {
	case "fingerprint":
		if opts.autoApprove {
			break // testing mode skips biometrics too
		}
		fv, err := fingerprint.New(desktop, logf)
		if err != nil {
			logf("fingerprint verification unavailable (%v)", err)
			logf("continuing with the desktop prompt as the only check; pass -uv prompt to silence this")
			break
		}
		verifier = fv
	case "prompt":
		logf("user verification is the desktop prompt alone")
	default:
		return fmt.Errorf("unknown -uv value %q (want fingerprint or prompt)", opts.uv)
	}

	fingerprintConsent := false
	switch opts.consent {
	case "prompt":
	case "fingerprint":
		if verifier == nil {
			// Without a sensor this would leave no user interaction at all, so
			// fall back rather than let a page mint passkeys in silence.
			logf("-consent fingerprint needs a working sensor; falling back to the approval prompt")
		} else {
			fingerprintConsent = true
			logf("consent is the fingerprint touch alone; no approval click")
		}
	default:
		return fmt.Errorf("unknown -consent value %q (want prompt or fingerprint)", opts.consent)
	}

	if opts.uvGrace > 0 && verifier != nil {
		logf("repeat requests from the same site within %s reuse the previous scan", opts.uvGrace)
	}

	auth := ctap.New(ctap.Config{
		Store:              vaultStore{v},
		Approver:           ap,
		Verifier:           verifier,
		Notifier:           desktop,
		StrictUV:           opts.uvStrict,
		FingerprintConsent: fingerprintConsent,
		UVGrace:            opts.uvGrace,
		AAGUID:             aaguid,
		Logf:               logf,
	})

	// Only now does the device appear, so browsers never see a key that
	// cannot answer yet.
	if err := dev.Create(); err != nil {
		return err
	}
	shutdown := func() { _ = dev.Close() }

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		logf("shutting down")
		shutdown()
		os.Exit(0)
	}()

	go reportNode()

	stack := ctaphid.New(dev, auth.Handle, vlogf)

	for {
		ev, err := dev.Read()
		if err != nil {
			return fmt.Errorf("UHID service: %w", err)
		}
		switch ev.Kind {
		case hidbridge.EventStart:
			logf("authenticator is live, waiting for a browser")
		case hidbridge.EventOpen:
			vlogf("device opened by a client")
		case hidbridge.EventClose:
			vlogf("device closed by a client")
		case hidbridge.EventStop:
			vlogf("UHID_STOP")
		case hidbridge.EventOutput:
			stack.HandlePacket(ev.Data)
		default:
			vlogf("uhid event type %d", ev.Kind)
		}
	}
}

// reportNode tells the user which hidraw node we became, and whether they can
// actually reach it, which is the first thing to check if a browser cannot see
// the key.
func reportNode() {
	uniq := hidbridge.DeviceUniq(os.Getuid())
	time.Sleep(400 * time.Millisecond)
	matches, _ := filepath.Glob("/sys/class/hidraw/hidraw*")
	for _, m := range matches {
		data, err := os.ReadFile(filepath.Join(m, "device", "uevent"))
		if err != nil || !strings.Contains("\n"+string(data), "\nHID_UNIQ="+uniq+"\n") {
			continue
		}
		node := "/dev/" + filepath.Base(m)
		if f, err := os.OpenFile(node, os.O_RDWR, 0); err == nil {
			f.Close()
			logf("presenting as %s, readable by this user", node)
		} else {
			logf("presenting as %s, but THIS USER CANNOT OPEN IT: %v", node, err)
			logf("browsers will not see the key until that is fixed")
		}
		return
	}
	logf("warning: could not locate our hidraw node")
}
