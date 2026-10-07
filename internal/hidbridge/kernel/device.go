// Package kernel implements hidbridge.Device on top of /dev/uhid, keeping
// kernel UHID event numbers out of the broker protocol.
package kernel

import (
	"fmt"

	"llavero/internal/hidbridge"
	"llavero/internal/uhid"
)

// Device is a FIDO HID device backed by /dev/uhid. It is invisible to the
// host until Create.
type Device struct {
	dev  *uhid.Device
	uniq string
}

var _ hidbridge.Device = (*Device)(nil)

// Open opens /dev/uhid for a FIDO device with the given HID_UNIQ, without
// creating it yet. It needs root.
func Open(uniq string) (*Device, error) {
	dev, err := uhid.Open()
	if err != nil {
		return nil, err // names /dev/uhid and, if missing, the module to load
	}
	return &Device{dev: dev, uniq: uniq}, nil
}

// Check reports whether /dev/uhid can be opened at all, so the broker can
// refuse to start on a machine where no session could ever succeed.
func Check() error {
	dev, err := uhid.Open()
	if err != nil {
		return err // names /dev/uhid and, if missing, the module to load
	}
	return dev.Close()
}

// Create registers the device with the kernel, which makes it visible to
// browsers.
func (d *Device) Create() error {
	if err := d.dev.Create(d.uniq); err != nil {
		return fmt.Errorf("creating FIDO device: %w", err)
	}
	return nil
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
