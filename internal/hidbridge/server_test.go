package hidbridge

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"
)

const testTimeout = 2 * time.Second

// fakeDevice stands in for /dev/uhid: the test feeds it host events and
// inspects the reports the client sent.
type fakeDevice struct {
	createErr error
	created   chan struct{}
	events    chan Event
	inputs    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{
		created: make(chan struct{}, 1),
		events:  make(chan Event),
		inputs:  make(chan []byte, 8),
		closed:  make(chan struct{}),
	}
}

func (d *fakeDevice) Create() error {
	if d.createErr != nil {
		return d.createErr
	}
	d.created <- struct{}{}
	return nil
}

func (d *fakeDevice) SendInput(report []byte) error {
	d.inputs <- append([]byte(nil), report...)
	return nil
}

func (d *fakeDevice) Read() (Event, error) {
	select {
	case ev := <-d.events:
		return ev, nil
	case <-d.closed:
		return Event{}, errors.New("device closed")
	}
}

func (d *fakeDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

// startServer runs a broker for the current user on a temporary socket.
func startServer(t *testing.T, openDevice func() (Device, error)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "device.sock")
	listener, err := Listen(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(zaptest.NewLogger(t), os.Getuid(), openDevice)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, listener) }()
	// Serve waits for its sessions, so nothing logs after the test ends.
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("Serve() = %v after cancel, want nil", err)
		}
	})
	return path
}

func dialSelf(t *testing.T, path string) *Client {
	t.Helper()
	client, err := Dial(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func waitClosed(t *testing.T, dev *fakeDevice) {
	t.Helper()
	select {
	case <-dev.closed:
	case <-time.After(testTimeout):
		t.Fatal("device was not closed")
	}
}

func TestSessionRelaysBothDirections(t *testing.T) {
	dev := newFakeDevice()
	path := startServer(t, func() (Device, error) { return dev, nil })
	client := dialSelf(t, path)
	if err := client.Create(); err != nil {
		t.Fatal(err)
	}

	report := bytes.Repeat([]byte{0x11}, ReportSize)
	if err := client.SendInput(report); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-dev.inputs:
		if !bytes.Equal(got, report) {
			t.Fatalf("device got %x, want %x", got, report)
		}
	case <-time.After(testTimeout):
		t.Fatal("report did not reach the device")
	}

	output := bytes.Repeat([]byte{0x22}, ReportSize)
	for _, want := range []Event{{Kind: EventStart}, {Kind: EventOutput, Data: output}} {
		dev.events <- want
		got, err := client.Read()
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind != want.Kind || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("client read %+v, want %+v", got, want)
		}
	}

	client.Close()
	waitClosed(t, dev)
}

func TestCancelEndsActiveSession(t *testing.T) {
	dev := newFakeDevice()
	path := filepath.Join(t.TempDir(), "device.sock")
	listener, err := Listen(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(nil, os.Getuid(), func() (Device, error) { return dev, nil })
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, listener) }()

	client := dialSelf(t, path)
	if err := client.Create(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve() = %v, want nil", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Serve did not return after cancel")
	}
	waitClosed(t, dev)
	if _, err := client.Read(); err == nil {
		t.Fatal("client still connected after shutdown")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket left behind: %v", err)
	}
}

func TestNoDeviceBeforeCreate(t *testing.T) {
	dev := newFakeDevice()
	opened := make(chan struct{}, 1)
	path := startServer(t, func() (Device, error) {
		opened <- struct{}{}
		return dev, nil
	})
	client := dialSelf(t, path)
	select {
	case <-opened:
	default:
		t.Fatal("device was not opened before the client was accepted")
	}
	select {
	case <-dev.created:
		t.Fatal("device created before the client asked")
	case <-time.After(100 * time.Millisecond):
	}
	if err := client.Create(); err != nil {
		t.Fatal(err)
	}
	<-dev.created
}

// A broker that cannot open the device must say so at connect time, before
// the client would ask for a passphrase.
func TestUnavailableDeviceReportedAtDial(t *testing.T) {
	path := startServer(t, func() (Device, error) { return nil, errors.New("no uhid module") })
	c, err := Dial(path, uint32(os.Getuid()))
	if err == nil {
		c.Close()
		t.Fatal("Dial succeeded although the broker cannot open the device")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Dial() = %v, want ErrUnavailable", err)
	}
}

func TestSecondClientRefused(t *testing.T) {
	path := startServer(t, func() (Device, error) { return newFakeDevice(), nil })
	dialSelf(t, path)
	if c, err := Dial(path, uint32(os.Getuid())); err == nil {
		c.Close()
		t.Fatal("second client was accepted")
	}
}

func TestClientRejectsUnexpectedBrokerUID(t *testing.T) {
	path := startServer(t, func() (Device, error) { return newFakeDevice(), nil })
	if c, err := Dial(path, uint32(os.Getuid())+1); err == nil {
		c.Close()
		t.Fatal("client trusted a broker running as the wrong uid")
	}
}

func TestCreateFailureReachesClient(t *testing.T) {
	dev := newFakeDevice()
	dev.createErr = errors.New("kernel refused UHID_CREATE2")
	path := startServer(t, func() (Device, error) { return dev, nil })
	client := dialSelf(t, path)
	if err := client.Create(); err == nil {
		t.Fatal("Create succeeded although the broker had no device")
	}
}

func TestInvalidReportEndsSession(t *testing.T) {
	dev := newFakeDevice()
	path := startServer(t, func() (Device, error) { return dev, nil })
	client := dialSelf(t, path)
	if err := client.Create(); err != nil {
		t.Fatal(err)
	}
	// Bypass SendInput's own length check to see what the broker does.
	if _, err := client.conn.Write(make([]byte, ReportSize-1)); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, dev)
	if len(dev.inputs) != 0 {
		t.Fatal("invalid report reached the device")
	}
}

// socketPair returns connected client and server ends of a SEQPACKET socket.
func socketPair(t *testing.T) (client, server *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "socket")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err = net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err = listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	server.SetDeadline(time.Now().Add(testTimeout))
	return client, server
}

func TestAwaitCreate(t *testing.T) {
	tests := []struct {
		name    string
		msg     []byte
		wantErr bool
	}{
		{"create", []byte{CmdCreate}, false},
		{"wrong command", []byte{Ready}, true},
		{"report before create", bytes.Repeat([]byte{CmdCreate}, ReportSize), true},
		{"two bytes", []byte{CmdCreate, 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := socketPair(t)
			if _, err := client.Write(tt.msg); err != nil {
				t.Fatal(err)
			}
			if err := awaitCreate(server); (err != nil) != tt.wantErr {
				t.Fatalf("awaitCreate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAwaitCreateDisconnect(t *testing.T) {
	client, server := socketPair(t)
	client.Close()
	if err := awaitCreate(server); err == nil {
		t.Fatal("awaitCreate succeeded on a closed connection")
	}
}

type reportSink struct{ got []byte }

var errReceived = errors.New("received")

func (s *reportSink) SendInput(b []byte) error { s.got = append([]byte(nil), b...); return errReceived }

func TestForwardReportsBoundary(t *testing.T) {
	for _, size := range []int{0, 1, 63, 64, 65, 4096} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			client, server := socketPair(t)
			payload := bytes.Repeat([]byte{0x0b}, size) // even UHID-like data is just a report
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			sink := &reportSink{}
			err := forwardReports(server, sink)
			if size == ReportSize {
				if !errors.Is(err, errReceived) || !bytes.Equal(sink.got, payload) {
					t.Fatalf("valid report: %v, %x", err, sink.got)
				}
			} else if err == nil || sink.got != nil {
				t.Fatalf("invalid report reached device: %v", err)
			}
		})
	}
}

// brokenDevice fails its first read, as a device the kernel tore down would.
type brokenDevice struct{ *fakeDevice }

var errDeviceGone = errors.New("device gone")

func (brokenDevice) Read() (Event, error) { return Event{}, errDeviceGone }

// When the device fails, the log must name the device error rather than the
// closed socket it causes on the other side of the relay.
func TestSessionReportsDeviceFailure(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	path := filepath.Join(t.TempDir(), "device.sock")
	listener, err := Listen(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	dev := brokenDevice{newFakeDevice()}
	srv := NewServer(zap.New(core), os.Getuid(), func() (Device, error) { return dev, nil })
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, listener) }()

	client := dialSelf(t, path)
	if err := client.Create(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(); err == nil {
		t.Fatal("client still connected after the device failed")
	}
	waitClosed(t, dev.fakeDevice)
	// The session logs after it returns; cancelling first would relabel it as
	// a shutdown.
	deadline := time.Now().Add(testTimeout)
	for logs.FilterMessage("session ended abnormally").Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-served

	ended := logs.FilterMessage("session ended abnormally").All()
	if len(ended) != 1 {
		t.Fatalf("got %d abnormal-session logs, want 1: %v", len(ended), logs.All())
	}
	if got, _ := ended[0].ContextMap()["error"].(string); !strings.Contains(got, errDeviceGone.Error()) {
		t.Fatalf("logged error %q, want it to name %q", got, errDeviceGone)
	}
}
