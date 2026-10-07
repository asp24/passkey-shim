// Package kernel implements hidbridge.Device on top of /dev/uhid, keeping
// kernel UHID event numbers out of the broker protocol.
package kernel

import (
	"fmt"

	"llavero/internal/hidbridge"
	"llavero/internal/uhid"
)

// Device is a FIDO HID device registered with the kernel through /dev/uhid.
type Device struct{ dev *uhid.Device }

var _ hidbridge.Device = (*Device)(nil)

// Open creates the FIDO device with the given HID_UNIQ. It needs root.
func Open(uniq string) (*Device, error) {
	dev, err := uhid.Open()
	if err != nil {
		return nil, err
	}
	if err := dev.Create(uniq); err != nil {
		dev.Close()
		return nil, fmt.Errorf("creating FIDO device: %w", err)
	}
	return &Device{dev: dev}, nil
}

// SendInput pushes one report from device to host.
func (d *Device) SendInput(report []byte) error { return d.dev.SendInput(report) }

// Close destroys the device; the kernel removes it with the last fd.
func (d *Device) Close() error { return d.dev.Close() }

// Read returns the next kernel event the client cares about, skipping the
// rest (feature and report requests a FIDO device never answers).
func (d *Device) Read() (hidbridge.Event, error) {
	for {
		ev, err := d.dev.Read()
		if err != nil {
			return hidbridge.Event{}, fmt.Errorf("reading /dev/uhid: %w", err)
		}
		if out, ok := translate(ev); ok {
			return out, nil
		}
	}
}

// translate maps a kernel UHID event to the broker protocol. ok is false for
// events the broker does not forward.
func translate(ev uhid.Event) (out hidbridge.Event, ok bool) {
	switch ev.Kind {
	case uhid.EventStart:
		return hidbridge.Event{Kind: hidbridge.EventStart}, true
	case uhid.EventStop:
		return hidbridge.Event{Kind: hidbridge.EventStop}, true
	case uhid.EventOpen:
		return hidbridge.Event{Kind: hidbridge.EventOpen}, true
	case uhid.EventClose:
		return hidbridge.Event{Kind: hidbridge.EventClose}, true
	case uhid.EventOutput:
		return hidbridge.Event{Kind: hidbridge.EventOutput, Data: ev.Data}, true
	default:
		return hidbridge.Event{}, false
	}
}
