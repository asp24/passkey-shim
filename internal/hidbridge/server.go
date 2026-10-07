package hidbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// Device is the HID device a broker session drives. Read must return an error
// once Close has been called, so a session can always be torn down.
type Device interface {
	SendInput(report []byte) error
	Read() (Event, error)
	Close() error
}

// Server relays FIDO reports between one client and one Device at a time.
type Server struct {
	// UID is the only user allowed to connect.
	UID int
	// NewDevice creates the HID device once the client asks for it.
	NewDevice func() (Device, error)
	// Logf reports sessions that end abnormally. Nil discards them.
	Logf func(format string, args ...any)
}

// Listen creates the broker socket at path, reachable only by uid. It never
// removes an existing socket, so a second broker cannot take over a running
// broker's endpoint.
func Listen(path string, uid int) (*net.UnixListener, error) {
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chown(path, uid, -1); err != nil {
		listener.Close()
		return nil, fmt.Errorf("handing %s to uid %d: %w", path, uid, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("restricting %s: %w", path, err)
	}
	return listener, nil
}

// Serve accepts clients until ctx is done or the listener fails. Connections
// from other users, and any connection while a session is active, are
// dropped. On return the listener is closed and no session is left running.
func (s *Server) Serve(ctx context.Context, listener *net.UnixListener) error {
	ctx, cancel := context.WithCancel(ctx)
	var sessions sync.WaitGroup
	defer sessions.Wait()
	defer cancel()
	stopListener := context.AfterFunc(ctx, func() { listener.Close() })
	defer stopListener()

	var active sync.Mutex
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accepting client: %w", err)
		}
		peer, err := PeerUID(conn)
		if err != nil || peer != uint32(s.UID) {
			conn.Close()
			continue
		}
		if !active.TryLock() {
			conn.Close()
			continue
		}
		sessions.Go(func() {
			defer active.Unlock()
			defer conn.Close()
			stopConn := context.AfterFunc(ctx, func() { conn.Close() })
			defer stopConn()
			// A client closing its socket is the normal way a session ends.
			if err := s.relay(conn); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.logf("client disconnected: %v", err)
			}
		})
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

func (s *Server) relay(conn *net.UnixConn) error {
	if _, err := conn.Write([]byte{Accepted}); err != nil {
		return fmt.Errorf("accepting client: %w", err)
	}
	// The client connects before unlocking its vault but asks for the device
	// only afterwards, so a locked authenticator never shows up in browsers.
	if err := awaitCreate(conn); err != nil {
		return err
	}
	dev, err := s.NewDevice()
	if err != nil {
		return fmt.Errorf("creating device: %w", err)
	}
	defer dev.Close()
	// A ready byte confirms device creation, so the client fails loudly if the
	// kernel refused it.
	if _, err := conn.Write([]byte{Ready}); err != nil {
		return fmt.Errorf("confirming device: %w", err)
	}
	// Closing the socket on either direction's failure wakes the other
	// direction, and closing the device wakes its reader.
	done := make(chan error, 1)
	go func() {
		err := forwardEvents(conn, dev)
		conn.Close()
		done <- err
	}()
	err = forwardReports(conn, dev)
	conn.Close()
	dev.Close()
	readerErr := <-done
	if err != nil {
		return err
	}
	return readerErr
}

func awaitCreate(conn *net.UnixConn) error {
	buf := make([]byte, 2)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("waiting for create request: %w", err)
	}
	if n != 1 || buf[0] != CmdCreate {
		return fmt.Errorf("expected create request, got %d-byte message", n)
	}
	return nil
}

func forwardReports(conn *net.UnixConn, dev interface{ SendInput([]byte) error }) error {
	buf := make([]byte, ReportSize+1)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("reading report: %w", err)
		}
		if n != ReportSize {
			return fmt.Errorf("invalid report length %d", n)
		}
		if err := dev.SendInput(buf[:n]); err != nil {
			return fmt.Errorf("sending report to device: %w", err)
		}
	}
}

func forwardEvents(conn *net.UnixConn, dev Device) error {
	for {
		ev, err := dev.Read()
		if err != nil {
			return fmt.Errorf("reading device: %w", err)
		}
		packet, err := encodeEvent(ev)
		if err != nil {
			return err
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("forwarding event: %w", err)
		}
	}
}
