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
	"llavero/internal/bootstrap"
	"llavero/internal/ctap"
	"llavero/internal/ctaphid"
	"llavero/internal/fingerprint"
	"llavero/internal/hidbridge"
)

func serveCommand() bootstrap.Command {
	return bootstrap.Command{
		Name:        "serve",
		Description: "run the authenticator, creating the vault on first start",
		Options:     &serveCmd{},
	}
}

type serveCmd struct {
	vaultOptions

	Unlock      string        `long:"unlock" value-name:"MODE" default:"passphrase" description:"unlock mode if the vault does not exist yet: passphrase, tpm, or tpm+passphrase"`
	UV          string        `long:"uv" default:"fingerprint" choice:"fingerprint" choice:"prompt" description:"user verification method"`
	UVStrict    bool          `long:"uv-strict" description:"deny when the fingerprint sensor is unusable instead of falling back to the prompt"`
	Consent     string        `long:"consent" default:"prompt" choice:"prompt" choice:"fingerprint" description:"how to take consent: prompt (click to approve, then touch) or fingerprint (touch only)"`
	UVGrace     time.Duration `long:"uv-grace" value-name:"DURATION" default:"5s" description:"reuse a just-completed fingerprint scan for repeat requests from the SAME site (0 disables)"`
	Approval    string        `long:"approval" default:"auto" choice:"auto" choice:"omarchy" choice:"zenity" description:"approval prompt"`
	AutoApprove bool          `long:"auto-approve" description:"approve every request without prompting (testing only)"`
}

func (c *serveCmd) Execute([]string) error {
	return c.withApp(func(a *app) error { return a.serve(c) })
}

// serve runs the authenticator until it is told to stop.
func (a *app) serve(opts *serveCmd) error {
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

	v, err := a.loadVault(opts.Unlock)
	if err != nil {
		return err // loadVault's errors already say what failed
	}

	var ap ctap.Approver
	if opts.AutoApprove {
		a.log.Warn("--auto-approve is set: every request will be granted without asking")
		ap = approval.Auto{}
	} else {
		ap, err = approval.New(opts.Approval)
		if err != nil {
			return fmt.Errorf("no approval UI available: %w\n"+
				"       (install zenity or omarchy-menu-select, or run with --auto-approve for testing)", err)
		}
		a.log.Info("approval prompt", zap.String("backend", fmt.Sprintf("%T", ap)))
	}

	// Keep this an interface and assign it only on success: a nil
	// *fingerprint.Verifier stored here would compare non-nil.
	var verifier ctap.UserVerifier
	switch opts.UV {
	case "fingerprint":
		if opts.AutoApprove {
			break // testing mode skips biometrics too
		}
		fv, err := fingerprint.New(a.log.Named("fingerprint"), a.desktop)
		if err != nil {
			a.log.Warn("fingerprint verification unavailable; the desktop prompt is the only check "+
				"(pass --uv prompt to silence this)", zap.Error(err))
			break
		}
		verifier = fv
	case "prompt":
		a.log.Info("user verification is the desktop prompt alone")
	default:
		return fmt.Errorf("unknown --uv value %q (want fingerprint or prompt)", opts.UV)
	}

	fingerprintConsent := false
	switch opts.Consent {
	case "prompt":
	case "fingerprint":
		if verifier == nil {
			// Without a sensor this would leave no user interaction at all, so
			// fall back rather than let a page mint passkeys in silence.
			a.log.Warn("--consent fingerprint needs a working sensor; falling back to the approval prompt")
		} else {
			fingerprintConsent = true
			a.log.Info("consent is the fingerprint touch alone; no approval click")
		}
	default:
		return fmt.Errorf("unknown --consent value %q (want prompt or fingerprint)", opts.Consent)
	}

	if opts.UVGrace > 0 && verifier != nil {
		a.log.Info("repeat requests from the same site reuse the previous scan", zap.Duration("grace", opts.UVGrace))
	}

	auth := ctap.New(a.log.Named("ctap"), ctap.Config{
		Store:              vaultStore{v},
		Approver:           ap,
		Verifier:           verifier,
		Notifier:           a.desktop,
		StrictUV:           opts.UVStrict,
		FingerprintConsent: fingerprintConsent,
		UVGrace:            opts.UVGrace,
		AAGUID:             aaguid,
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
	stack := ctaphid.New(a.log.Named("ctaphid"), dev, auth.Handle)
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
