// llavero-uhid owns a fixed FIDO device. Its client can only send 64-byte
// reports; the UHID descriptor and kernel event types never cross the socket.
//
// This binary only wires hidbridge.Server to the kernel device; the protocol
// lives in internal/hidbridge and the /dev/uhid adapter in its kernel package.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"llavero/internal/hidbridge"
	"llavero/internal/hidbridge/kernel"
)

func main() {
	uidFlag := flag.String("uid", "", "numeric UID allowed to connect (required)")
	flag.Parse()
	uid, err := strconv.ParseUint(*uidFlag, 10, 32)
	if err != nil || uid == 0 {
		fatal("-uid must name a non-root numeric UID")
	}
	if os.Geteuid() != 0 {
		fatal("must run as root")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, int(uid)); err != nil {
		fatal(err)
	}
}

// serve runs until ctx is cancelled; the deferred Close unlinks the socket.
func serve(ctx context.Context, uid int) error {
	// systemd creates the root-owned runtime directory.
	listener, err := hidbridge.Listen(hidbridge.SocketPath(uid), uid)
	if err != nil {
		return err
	}
	defer listener.Close()
	srv := &hidbridge.Server{
		UID:       uid,
		NewDevice: func() (hidbridge.Device, error) { return kernel.Open(hidbridge.DeviceUniq(uid)) },
		Logf:      log.New(os.Stdout, "", 0).Printf,
	}
	return srv.Serve(ctx, listener)
}

func fatal(v any) { fmt.Fprintln(os.Stderr, v); os.Exit(1) }
