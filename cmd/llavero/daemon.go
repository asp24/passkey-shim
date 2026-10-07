package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"

	"llavero/internal/approval"
	"llavero/internal/ctap"
	"llavero/internal/ctaphid"
	"llavero/internal/fingerprint"
	"llavero/internal/hardening"
	"llavero/internal/hidbridge"
)

func (a *app) run() error {
	opts := a.opts
	// Before anything touches a key. Core dumps and ptrace are shut off first
	// so there is no window in which a decrypted vault could escape.
	hardening.Apply(opts.mlock, a.log.Named("hardening"))

	if opts.rekeyTo != "" {
		return a.runRekey()
	}
	if opts.list {
		return a.runList()
	}
	if opts.forget != "" {
		return a.runForget()
	}

	// Connect to the broker before asking for a passphrase, so a missing
	// system service does not cost the user a typed secret first.
	dev, err := hidbridge.Dial(hidbridge.SocketPath(os.Getuid()), 0)
	if errors.Is(err, hidbridge.ErrUnavailable) {
		return fmt.Errorf("UHID service: %w; load the uhid kernel module (sudo modprobe uhid), "+
			"details in: journalctl -u llavero-uhid@%d", err, os.Getuid())
	}
	if err != nil {
		return fmt.Errorf("UHID service: %w (is llavero-uhid@%d.service enabled? check: systemctl status llavero-uhid@%d)",
			err, os.Getuid(), os.Getuid())
	}
	defer dev.Close()

	v, err := a.loadVault()
	if err != nil {
		return err // loadVault's errors already say what failed
	}

	var ap ctap.Approver
	if opts.autoApprove {
		a.log.Warn("-auto-approve is set: every request will be granted without asking")
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
		fv, err := fingerprint.New(a.desktop, a.log.Named("fingerprint"))
		if err != nil {
			a.log.Warn("fingerprint verification unavailable; the desktop prompt is the only check "+
				"(pass -uv prompt to silence this)", zap.Error(err))
			break
		}
		verifier = fv
	case "prompt":
		a.log.Info("user verification is the desktop prompt alone")
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
			a.log.Warn("-consent fingerprint needs a working sensor; falling back to the approval prompt")
		} else {
			fingerprintConsent = true
			a.log.Info("consent is the fingerprint touch alone; no approval click")
		}
	default:
		return fmt.Errorf("unknown -consent value %q (want prompt or fingerprint)", opts.consent)
	}

	if opts.uvGrace > 0 && verifier != nil {
		a.log.Info("repeat requests from the same site reuse the previous scan", zap.Duration("grace", opts.uvGrace))
	}

	auth := ctap.New(ctap.Config{
		Store:              vaultStore{v},
		Approver:           ap,
		Verifier:           verifier,
		Notifier:           a.desktop,
		StrictUV:           opts.uvStrict,
		FingerprintConsent: fingerprintConsent,
		UVGrace:            opts.uvGrace,
		AAGUID:             aaguid,
		Logger:             a.log.Named("ctap"),
	})

	// Signals are caught only from here on. Before this point Ctrl+C must
	// still kill a passphrase prompt the default way.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Only now does the device appear, so browsers never see a key that
	// cannot answer yet.
	if err := dev.Create(); err != nil {
		return fmt.Errorf("UHID service: %w", err)
	}

	// Closing the broker connection is what wakes dev.Read on shutdown.
	stopClosing := context.AfterFunc(ctx, func() { _ = dev.Close() })
	defer stopClosing()

	var background sync.WaitGroup
	defer background.Wait()
	background.Go(func() { a.reportNode(ctx) })

	// Requests get their own context so that leaving the loop for any reason
	// closes an open prompt before stack.Wait waits for it.
	reqCtx, cancelRequests := context.WithCancel(ctx)
	stack := ctaphid.New(dev, auth.Handle, a.log.Named("ctaphid"))
	defer stack.Wait()
	defer cancelRequests()

	for {
		ev, err := dev.Read()
		if err != nil {
			if ctx.Err() != nil {
				a.log.Info("shutting down")
				return nil
			}
			return fmt.Errorf("UHID service: %w", err)
		}
		switch ev.Kind {
		case hidbridge.EventStart:
			a.log.Info("authenticator is live, waiting for a browser")
		case hidbridge.EventOpen:
			a.log.Debug("device opened by a client")
		case hidbridge.EventClose:
			a.log.Debug("device closed by a client")
		case hidbridge.EventStop:
			a.log.Debug("device stopped")
		case hidbridge.EventOutput:
			stack.HandlePacket(reqCtx, ev.Data)
		default:
			a.log.Debug("unhandled device event", zap.Uint8("kind", ev.Kind))
		}
	}
}

// reportNode tells the user which hidraw node we became, and whether they can
// actually reach it, which is the first thing to check if a browser cannot see
// the key.
func (a *app) reportNode(ctx context.Context) {
	uniq := hidbridge.DeviceUniq(os.Getuid())
	// Give udev a moment to create the node.
	select {
	case <-ctx.Done():
		return
	case <-time.After(400 * time.Millisecond):
	}
	matches, _ := filepath.Glob("/sys/class/hidraw/hidraw*")
	for _, m := range matches {
		data, err := os.ReadFile(filepath.Join(m, "device", "uevent"))
		if err != nil || !strings.Contains("\n"+string(data), "\nHID_UNIQ="+uniq+"\n") {
			continue
		}
		node := "/dev/" + filepath.Base(m)
		if f, err := os.OpenFile(node, os.O_RDWR, 0); err == nil {
			f.Close()
			a.log.Info("presenting as a hidraw node readable by this user", zap.String("node", node))
		} else {
			a.log.Error("this user cannot open our hidraw node; browsers will not see the key "+
				"until that is fixed", zap.String("node", node), zap.Error(err))
		}
		return
	}
	a.log.Warn("could not locate our hidraw node")
}
