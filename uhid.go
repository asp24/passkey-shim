package main

import (
	"fmt"
	"llavero/internal/hidbridge"
	"net"
	"os"
	"time"
)

const (
	uhidStart  = 2
	uhidStop   = 3
	uhidOpen   = 4
	uhidClose  = 5
	uhidOutput = 6
)

type uhidDevice struct{ conn *net.UnixConn }
type uhidEvent struct {
	kind uint32
	data []byte
}

func openUHID() (*uhidDevice, error) {
	path := hidbridge.SocketPath(os.Getuid())
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("connect to UHID service at %s: %w (enable llavero-uhid@%d.service)", path, err, os.Getuid())
	}
	uid, err := hidbridge.PeerUID(conn)
	if err != nil || uid != 0 {
		conn.Close()
		return nil, fmt.Errorf("UHID service must be owned by root (uid %d, error %v)", uid, err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	ready := make([]byte, 2)
	n, err := conn.Read(ready)
	if err != nil || n != 1 || ready[0] != 0 {
		conn.Close()
		return nil, fmt.Errorf("UHID service did not create a device (check its system journal): %v", err)
	}
	conn.SetReadDeadline(time.Time{})
	return &uhidDevice{conn: conn}, nil
}
func (d *uhidDevice) sendInput(report []byte) error {
	if len(report) != 64 {
		return fmt.Errorf("FIDO report must be 64 bytes")
	}
	_, err := d.conn.Write(report)
	return err
}
func (d *uhidDevice) read() (uhidEvent, error) {
	buf := make([]byte, 66)
	n, err := d.conn.Read(buf)
	if err != nil {
		return uhidEvent{}, err
	}
	if n != 1 && n != 65 {
		return uhidEvent{}, fmt.Errorf("invalid UHID service message length %d", n)
	}
	kind := uint32(buf[0])
	switch kind {
	case uhidOutput:
		if n != 65 {
			return uhidEvent{}, fmt.Errorf("invalid FIDO output")
		}
	case uhidStart, uhidStop, uhidOpen, uhidClose:
		if n != 1 {
			return uhidEvent{}, fmt.Errorf("invalid lifecycle message")
		}
	default:
		return uhidEvent{}, fmt.Errorf("invalid UHID service event %d", kind)
	}
	return uhidEvent{kind: kind, data: buf[1:n]}, nil
}
