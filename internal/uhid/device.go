package uhid

// Minimal binding for the kernel's /dev/uhid character device.
//
// The kernel ABI is a single packed C struct (struct uhid_event) whose body is
// a union of every request type, so every read and write is against fixed byte
// offsets into one oversized buffer. Offsets below come from linux/uhid.h.

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Kernel event kinds from linux/uhid.h.
const (
	uhidDestroy = 1
	EventStart  = 2
	EventStop   = 3
	EventOpen   = 4
	EventClose  = 5
	EventOutput = 6
	uhidCreate2 = 11
	uhidInput2  = 12

	// 4-byte type tag plus the largest union member (create2, 4372 bytes).
	EventSize = 4376

	busUSB = 0x03

	// Both FIDO reports in fidoReportDescriptor are this long.
	ReportSize = 64
)

// create2 field offsets, measured from the start of the event.
const (
	offName    = 4   // [128]u8
	offPhys    = 132 // [64]u8
	offUniq    = 196 // [64]u8
	offRDSize  = 260 // u16
	offBus     = 262 // u16
	offVendor  = 264 // u32
	offProduct = 268 // u32
	offVersion = 272 // u32
	offCountry = 276 // u32
	offRDData  = 280 // [4096]u8
)

// The FIDO HID report descriptor: usage page 0xF1D0, 64-byte in and out
// reports. udev's 60-fido-id.rules looks for exactly this to tag the resulting
// hidraw node as a security token, which is what makes browsers pick it up.
var fidoReportDescriptor = []byte{
	0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
	0x09, 0x01, //       Usage (U2F HID Authenticator Device)
	0xA1, 0x01, //       Collection (Application)
	0x09, 0x20, //         Usage (Input Report Data)
	0x15, 0x00, //         Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //         Report Size (8)
	0x95, 0x40, //         Report Count (64)
	0x81, 0x02, //         Input (Data,Var,Abs)
	0x09, 0x21, //         Usage (Output Report Data)
	0x15, 0x00, //         Logical Minimum (0)
	0x26, 0xFF, 0x00, //   Logical Maximum (255)
	0x75, 0x08, //         Report Size (8)
	0x95, 0x40, //         Report Count (64)
	0x91, 0x02, //         Output (Data,Var,Abs)
	0xC0, //             End Collection
}

type Device struct {
	f *os.File
}

func Open() (*Device, error) {
	fd, err := unix.Open("/dev/uhid", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/uhid (needs root): %w", err)
	}
	return &Device{f: os.NewFile(uintptr(fd), "/dev/uhid")}, nil
}

// Create registers the virtual device with the kernel, which materialises a
// /dev/hidraw* node for it. uniq becomes HID_UNIQ in the device's uevent and
// must tell apart the devices of different users.
func (d *Device) Create(uniq string) error {
	ev := make([]byte, EventSize)
	binary.LittleEndian.PutUint32(ev[0:], uhidCreate2)
	copy(ev[offName:offName+127], "Llavero (virtual FIDO2)")
	copy(ev[offPhys:offPhys+63], "llavero")
	copy(ev[offUniq:offUniq+63], uniq)
	binary.LittleEndian.PutUint16(ev[offRDSize:], uint16(len(fidoReportDescriptor)))
	binary.LittleEndian.PutUint16(ev[offBus:], busUSB)
	binary.LittleEndian.PutUint32(ev[offVendor:], 0x1209)  // pid.codes, open-source VID
	binary.LittleEndian.PutUint32(ev[offProduct:], 0x000C) // arbitrary within that space
	binary.LittleEndian.PutUint32(ev[offVersion:], 1)
	binary.LittleEndian.PutUint32(ev[offCountry:], 0)
	copy(ev[offRDData:], fidoReportDescriptor)

	if _, err := d.f.Write(ev); err != nil {
		return fmt.Errorf("UHID_CREATE2: %w", err)
	}
	return nil
}

func (d *Device) Destroy() error {
	ev := make([]byte, 4)
	binary.LittleEndian.PutUint32(ev[0:], uhidDestroy)
	_, err := d.f.Write(ev)
	return err
}

// sendInput pushes one 64-byte report from device to host.
func (d *Device) SendInput(report []byte) error {
	if len(report) != ReportSize {
		return fmt.Errorf("FIDO report must be 64 bytes")
	}
	ev := make([]byte, 6+len(report))
	binary.LittleEndian.PutUint32(ev[0:], uhidInput2)
	binary.LittleEndian.PutUint16(ev[4:], uint16(len(report)))
	copy(ev[6:], report)
	_, err := d.f.Write(ev)
	return err
}

type Event struct {
	Kind uint32
	Data []byte // populated for EventOutput
}

func (d *Device) Read() (Event, error) {
	buf := make([]byte, EventSize)
	n, err := d.f.Read(buf)
	if err != nil {
		return Event{}, err
	}
	if n < 4 {
		return Event{}, fmt.Errorf("short uhid event: %d bytes", n)
	}
	ev := Event{Kind: binary.LittleEndian.Uint32(buf[0:])}

	// uhid_output_req lays out data BEFORE size, unlike input2. Getting this
	// backwards is the classic way to lose an afternoon here.
	if ev.Kind == EventOutput {
		const (
			outOffData  = 4
			outOffSize  = 4100
			outOffRtype = 4102
		)
		if n < outOffRtype+1 {
			return Event{}, fmt.Errorf("truncated UHID_OUTPUT: %d bytes", n)
		}
		size := int(binary.LittleEndian.Uint16(buf[outOffSize:]))
		if size > outOffSize-outOffData {
			return Event{}, fmt.Errorf("implausible output size %d", size)
		}
		data := make([]byte, size)
		copy(data, buf[outOffData:outOffData+size])
		// hidraw strips a leading report number of 0, but tolerate it anyway.
		if len(data) == 65 && data[0] == 0 {
			data = data[1:]
		}
		ev.Data = data
	}
	return ev, nil
}

func (d *Device) Close() error { return d.f.Close() }
