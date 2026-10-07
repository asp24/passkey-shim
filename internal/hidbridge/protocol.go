// Package hidbridge connects the llavero daemon to the llavero-uhid broker,
// which owns /dev/uhid on its behalf.
package hidbridge

import "fmt"

// Wire protocol between llavero and llavero-uhid over a SOCK_SEQPACKET socket.
// Each message is one packet:
//
//	broker -> client: Accepted once the broker has taken this client and
//	                  opened /dev/uhid, or Unavailable if it could not open
//	                  it. A second client is disconnected instead. Either way
//	                  the client learns before it asks for a passphrase.
//	client -> broker: CmdCreate once, when the client is ready to serve. Until
//	                  then no HID device exists, so browsers see nothing while
//	                  the vault is still locked.
//	broker -> client: Ready once the device exists, then one lifecycle byte
//	                  (EventStart..EventClose) or EventOutput followed by a
//	                  ReportSize-byte report from the host.
//	client -> broker: exactly ReportSize bytes, one input report for the host.
const (
	ReportSize = 64

	CmdCreate byte = 1

	Ready       byte = 0
	Accepted    byte = 7
	Unavailable byte = 8
	EventStart  byte = 2
	EventStop   byte = 3
	EventOpen   byte = 4
	EventClose  byte = 5
	EventOutput byte = 6

	// Receive buffers are one byte larger than the largest valid packet, so a
	// SEQPACKET message that would be truncated shows up as too long instead.
	MaxEventSize = 1 + ReportSize
)

// Event is one device lifecycle change or host output report.
type Event struct {
	Kind byte
	Data []byte // ReportSize bytes for EventOutput, empty otherwise
}

// encodeEvent builds the packet for ev, rejecting anything the protocol does
// not allow so a malformed event never reaches the client.
func encodeEvent(ev Event) ([]byte, error) {
	switch ev.Kind {
	case EventStart, EventStop, EventOpen, EventClose:
		if len(ev.Data) != 0 {
			return nil, fmt.Errorf("lifecycle event %d carries %d bytes", ev.Kind, len(ev.Data))
		}
		return []byte{ev.Kind}, nil
	case EventOutput:
		if len(ev.Data) != ReportSize {
			return nil, fmt.Errorf("invalid FIDO output length %d", len(ev.Data))
		}
		return append([]byte{EventOutput}, ev.Data...), nil
	default:
		return nil, fmt.Errorf("unknown event %d", ev.Kind)
	}
}

// decodeEvent parses one broker packet. The returned Data aliases packet.
func decodeEvent(packet []byte) (Event, error) {
	if len(packet) == 0 {
		return Event{}, fmt.Errorf("empty broker message")
	}
	ev := Event{Kind: packet[0], Data: packet[1:]}
	switch ev.Kind {
	case EventStart, EventStop, EventOpen, EventClose:
		if len(ev.Data) != 0 {
			return Event{}, fmt.Errorf("invalid lifecycle message length %d", len(packet))
		}
		ev.Data = nil
	case EventOutput:
		if len(ev.Data) != ReportSize {
			return Event{}, fmt.Errorf("invalid FIDO output length %d", len(ev.Data))
		}
	default:
		return Event{}, fmt.Errorf("unknown broker event %d", ev.Kind)
	}
	return ev, nil
}

// DeviceUniq is the HID_UNIQ of the device the broker creates for uid, which
// lets the client find its own hidraw node among other users' devices.
func DeviceUniq(uid int) string { return fmt.Sprintf("llavero-%d", uid) }

// SocketPath is where the broker for uid listens.
func SocketPath(uid int) string { return fmt.Sprintf("/run/llavero-uhid-%d/device.sock", uid) }
