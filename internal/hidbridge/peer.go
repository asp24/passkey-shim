package hidbridge

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
)

// Wire protocol between llavero and llavero-uhid over a SOCK_SEQPACKET socket.
// Each message is one packet:
//
//	broker -> client: Ready once the device exists, then one lifecycle byte
//	                  (EventStart..EventClose) or EventOutput followed by a
//	                  ReportSize-byte report from the host.
//	client -> broker: exactly ReportSize bytes, one input report for the host.
const (
	ReportSize = 64

	Ready       byte = 0
	EventStart  byte = 2
	EventStop   byte = 3
	EventOpen   byte = 4
	EventClose  byte = 5
	EventOutput byte = 6

	// Receive buffers are one byte larger than the largest valid packet, so a
	// SEQPACKET message that would be truncated shows up as too long instead.
	MaxEventSize = 1 + ReportSize
)

// DeviceUniq is the HID_UNIQ of the device the broker creates for uid, which
// lets the client find its own hidraw node among other users' devices.
func DeviceUniq(uid int) string { return fmt.Sprintf("llavero-%d", uid) }

func SocketPath(uid int) string { return fmt.Sprintf("/run/llavero-uhid-%d/device.sock", uid) }

func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) { cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return 0, err
	}
	if sockErr != nil {
		return 0, sockErr
	}
	return cred.Uid, nil
}
