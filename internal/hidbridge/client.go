package hidbridge

import (
	"fmt"
	"net"
	"time"
)

// replyTimeout bounds how long the client waits for a broker control byte.
const replyTimeout = 5 * time.Second

// Client is the daemon's end of the broker socket. It exchanges FIDO reports
// with the broker and never touches /dev/uhid itself.
type Client struct{ conn *net.UnixConn }

// Dial connects to the broker at path and checks that it runs as brokerUID
// (root in production) and has accepted this client.
func Dial(path string, brokerUID uint32) (*Client, error) {
	conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", path, err)
	}
	uid, err := PeerUID(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("checking broker credentials: %w", err)
	}
	if uid != brokerUID {
		conn.Close()
		return nil, fmt.Errorf("broker at %s runs as uid %d, not %d; refusing to talk to it", path, uid, brokerUID)
	}
	c := &Client{conn: conn}
	if err := c.expect(Accepted); err != nil {
		conn.Close()
		return nil, fmt.Errorf("broker refused the connection (is another llavero running?): %w", err)
	}
	return c, nil
}

// Create asks the broker to register the HID device and waits until it has.
// Browsers can see the authenticator from this point on.
func (c *Client) Create() error {
	if _, err := c.conn.Write([]byte{CmdCreate}); err != nil {
		return fmt.Errorf("asking broker to create the device: %w", err)
	}
	if err := c.expect(Ready); err != nil {
		return fmt.Errorf("broker did not create a device (check its system journal): %w", err)
	}
	return nil
}

// SendInput pushes one report from device to host.
func (c *Client) SendInput(report []byte) error {
	if len(report) != ReportSize {
		return fmt.Errorf("FIDO report must be %d bytes, got %d", ReportSize, len(report))
	}
	if _, err := c.conn.Write(report); err != nil {
		return fmt.Errorf("sending report: %w", err)
	}
	return nil
}

// Read blocks until the broker forwards the next device event.
func (c *Client) Read() (Event, error) {
	buf := make([]byte, MaxEventSize+1)
	n, err := c.conn.Read(buf)
	if err != nil {
		return Event{}, fmt.Errorf("reading from broker: %w", err)
	}
	return decodeEvent(buf[:n])
}

// Close disconnects, which makes the broker destroy the device.
func (c *Client) Close() error { return c.conn.Close() }

// expect reads one control byte from the broker, waiting at most replyTimeout.
func (c *Client) expect(want byte) error {
	if err := c.conn.SetReadDeadline(time.Now().Add(replyTimeout)); err != nil {
		return fmt.Errorf("setting deadline: %w", err)
	}
	buf := make([]byte, 2)
	n, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("reading reply: %w", err)
	}
	if n != 1 || buf[0] != want {
		return fmt.Errorf("unexpected %d-byte reply starting with %d", n, buf[0])
	}
	if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clearing deadline: %w", err)
	}
	return nil
}
