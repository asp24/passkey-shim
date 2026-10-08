// llavero-uhid owns a fixed FIDO device. Its client can only send 64-byte
// reports; the UHID descriptor and kernel event types never cross the socket.
//
// This binary only wires hidbridge.Server to the kernel device; the protocol
// lives in internal/hidbridge and the /dev/uhid adapter in its kernel package.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"llavero/internal/bootstrap"
	"llavero/internal/hidbridge"
	"llavero/internal/hidbridge/kernel"
	"llavero/internal/logging"
)

type options struct {
	UID uint32 `long:"uid" required:"yes" description:"numeric UID allowed to connect"`
}

// Finalize rejects root: the broker exists to hand the device to a user.
func (o *options) Finalize() error {
	if o.UID == 0 {
		return errors.New("--uid must name a non-root numeric UID")
	}
	return nil
}

func main() {
	opts := bootstrap.MustParseConfig[options]()
	uid := opts.UID
	if os.Geteuid() != 0 {
		fatal("must run as root")
	}
	log := logging.New(false).Named("broker").With(zap.Uint32("uid", uid))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := serve(ctx, int(uid), log, kernel.Check)
	stop()
	if err != nil {
		log.Error("broker stopped", zap.Error(err))
		_ = log.Sync()
		os.Exit(1)
	}
	log.Info("broker stopped")
	_ = log.Sync()
}

// serve runs until ctx is cancelled; the deferred Close unlinks the socket.
// checkDevice runs before the socket exists: a broker that cannot open
// /dev/uhid fails its unit instead of accepting clients it cannot serve.
func serve(ctx context.Context, uid int, log *zap.Logger, checkDevice func() error) error {
	if err := checkDevice(); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	// systemd creates the root-owned runtime directory.
	listener, err := hidbridge.Listen(hidbridge.SocketPath(uid), uid)
	if err != nil {
		return err // Listen names the socket and the failed step
	}
	defer listener.Close()
	log.Info("listening", zap.String("socket", hidbridge.SocketPath(uid)))
	srv := hidbridge.NewServer(log, uid, func() (hidbridge.Device, error) {
		return kernel.Open(hidbridge.DeviceUniq(uid))
	})
	return srv.Serve(ctx, listener)
}

func fatal(v any) { fmt.Fprintln(os.Stderr, v); os.Exit(1) }
