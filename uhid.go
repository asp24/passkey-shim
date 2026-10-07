package main

import (
	"fmt"
	"llavero/internal/hidbridge"
	"net"
	"os"
	"time"
)

const (
	uhidStart  = hidbridge.EventStart
	uhidStop   = hidbridge.EventStop
	uhidOpen   = hidbridge.EventOpen
	uhidClose  = hidbridge.EventClose
	uhidOutput = hidbridge.EventOutput
)

// uhidDevice is the client end of the llavero-uhid broker socket. The broker
// owns /dev/uhid; this side only exchanges FIDO reports with it.
type uhidDevice struct{ conn *net.UnixConn }

type uhidEvent struct {
	kind byte
	data []byte // populated for uhidOutput
}

func openUHID() (*uhidDevice, error) {
	path := hidbridge.SocketPath(os.Getuid())
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("connect to UHID service at %s: %w (enable llavero-uhid@%d.service)", path, err, os.Getuid())
	}
	uid, err := hidbridge.PeerUID(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("checking UHID service credentials: %w", err)
	}
	if uid != 0 {
		conn.Close()
		return nil, fmt.Errorf("UHID service at %s runs as uid %d, not root; refusing to talk to it", path, uid)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ready := make([]byte, 2)
	n, err := conn.Read(ready)
	if err != nil || n != 1 || ready[0] != hidbridge.Ready {
		conn.Close()
		return nil, fmt.Errorf("UHID service did not create a device (check its system journal): %v", err)
	}
	conn.SetReadDeadline(time.Time{})
	return &uhidDevice{conn: conn}, nil
}

// sendInput pushes one report from device to host.
func (d *uhidDevice) sendInput(report []byte) error {
	if len(report) != hidbridge.ReportSize {
		return fmt.Errorf("FIDO report must be %d bytes, got %d", hidbridge.ReportSize, len(report))
	}
	_, err := d.conn.Write(report)
	return err
}

func (d *uhidDevice) read() (uhidEvent, error) {
	buf := make([]byte, hidbridge.MaxEventSize+1)
	n, err := d.conn.Read(buf)
	if err != nil {
		return uhidEvent{}, err
	}
	if n == 0 {
		return uhidEvent{}, fmt.Errorf("empty UHID service message")
	}
	kind := buf[0]
	switch kind {
	case uhidOutput:
		if n != 1+hidbridge.ReportSize {
			return uhidEvent{}, fmt.Errorf("invalid FIDO output length %d", n-1)
		}
	case uhidStart, uhidStop, uhidOpen, uhidClose:
		if n != 1 {
			return uhidEvent{}, fmt.Errorf("invalid lifecycle message length %d", n)
		}
	default:
		return uhidEvent{}, fmt.Errorf("invalid UHID service event %d", kind)
	}
	return uhidEvent{kind: kind, data: buf[1:n]}, nil
}
