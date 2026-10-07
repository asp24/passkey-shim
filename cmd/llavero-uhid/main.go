// llavero-uhid owns a fixed FIDO device. Its client can only send 64-byte
// reports; the UHID descriptor and kernel event types never cross the socket.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"llavero/internal/hidbridge"
	"llavero/internal/uhid"
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
	if err := serve(int(uid)); err != nil {
		fatal(err)
	}
}

func serve(uid int) error {
	// systemd creates the root-owned runtime directory.
	listener, err := hidbridge.Listen(hidbridge.SocketPath(uid), uid)
	if err != nil {
		return err
	}
	defer listener.Close()
	srv := &hidbridge.Server{
		UID:       uid,
		NewDevice: func() (hidbridge.Device, error) { return newKernelDevice(hidbridge.DeviceUniq(uid)) },
		Logf:      log.New(os.Stdout, "", 0).Printf,
	}
	return srv.Serve(listener)
}

// kernelDevice adapts a /dev/uhid device to the broker protocol, so kernel
// event numbers stay inside this binary.
type kernelDevice struct{ dev *uhid.Device }

func newKernelDevice(uniq string) (*kernelDevice, error) {
	dev, err := uhid.Open()
	if err != nil {
		return nil, err
	}
	if err := dev.Create(uniq); err != nil {
		dev.Close()
		return nil, err
	}
	return &kernelDevice{dev: dev}, nil
}

func (d *kernelDevice) SendInput(report []byte) error { return d.dev.SendInput(report) }

func (d *kernelDevice) Close() error { return d.dev.Close() }

// Read returns the next kernel event the client cares about, skipping the
// rest (feature and report requests a FIDO device never answers).
func (d *kernelDevice) Read() (hidbridge.Event, error) {
	for {
		ev, err := d.dev.Read()
		if err != nil {
			return hidbridge.Event{}, err
		}
		switch ev.Kind {
		case uhid.EventStart:
			return hidbridge.Event{Kind: hidbridge.EventStart}, nil
		case uhid.EventStop:
			return hidbridge.Event{Kind: hidbridge.EventStop}, nil
		case uhid.EventOpen:
			return hidbridge.Event{Kind: hidbridge.EventOpen}, nil
		case uhid.EventClose:
			return hidbridge.Event{Kind: hidbridge.EventClose}, nil
		case uhid.EventOutput:
			return hidbridge.Event{Kind: hidbridge.EventOutput, Data: ev.Data}, nil
		}
	}
}

func fatal(v any) { fmt.Fprintln(os.Stderr, v); os.Exit(1) }
