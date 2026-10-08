package hidbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"go.uber.org/zap"
)

// Device is the HID device a broker session drives. It is opened when a client
// connects but stays invisible to the host until Create. Read must return an
// error once Close has been called, so a session can always be torn down.
type Device interface {
	Create() error
	SendInput(report []byte) error
	Read() (Event, error)
	Close() error
}

// Server relays FIDO reports between one client and one Device at a time.
type Server struct {
	uid        int
	openDevice func() (Device, error)
	log        *zap.Logger
}

// NewServer returns a Server that accepts only uid. openDevice prepares the
// HID device when a client connects, so a missing device is reported before
// the client asks for a passphrase; it must not make anything visible to the
// host, Create does that. log records rejected clients and sessions that end
// abnormally; nil discards them.
func NewServer(log *zap.Logger, uid int, openDevice func() (Device, error)) *Server {
	if log == nil {
		log = zap.NewNop()
	}
	return &Server{uid: uid, openDevice: openDevice, log: log}
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
	log := s.log
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
		if err != nil {
			log.Warn("rejected client: unknown credentials", zap.Error(err))
			conn.Close()
			continue
		}
		if peer != uint32(s.uid) {
			log.Warn("rejected client from another user", zap.Uint32("uid", peer))
			conn.Close()
			continue
		}
		if !active.TryLock() {
			log.Info("rejected second client while a session is active")
			conn.Close()
			continue
		}
		sessions.Go(func() {
			defer active.Unlock()
			defer conn.Close()
			stopConn := context.AfterFunc(ctx, func() { conn.Close() })
			defer stopConn()
			// A client closing its socket is the normal way a session ends.
			log.Info("client connected")
			err := s.relay(conn)
			switch {
			case ctx.Err() != nil:
				log.Info("session closed for shutdown")
			case err == nil || errors.Is(err, io.EOF):
				log.Info("client disconnected")
			default:
				log.Warn("session ended abnormally", zap.Error(err))
			}
		})
	}
}

func (s *Server) relay(conn *net.UnixConn) error {
	// Open the device up front, so a client on a machine where it cannot
	// work hears so before it asks the user for a passphrase.
	dev, err := s.openDevice()
	if err != nil {
		_, _ = conn.Write([]byte{Unavailable})
		return fmt.Errorf("opening device: %w", err)
	}
	defer dev.Close()
	if _, err := conn.Write([]byte{Accepted}); err != nil {
		return fmt.Errorf("accepting client: %w", err)
	}
	// The client connects before unlocking its vault but asks for the device
	// only afterwards, so a locked authenticator never shows up in browsers.
	if err := awaitCreate(conn); err != nil {
		return err // awaitCreate names the failed step
	}
	if err := dev.Create(); err != nil {
		return fmt.Errorf("creating device: %w", err)
	}
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
	// forwardReports only returns once the session is over, always with a
	// reason. If the event reader failed first, that reason is just the socket
	// the reader closed, and the reader's error is the one worth reporting.
	err = forwardReports(conn, dev)
	conn.Close()
	dev.Close()
	readerErr := <-done
	if errors.Is(err, net.ErrClosed) {
		return readerErr
	}
	return err
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
			return fmt.Errorf("encoding device event: %w", err)
		}
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("forwarding event: %w", err)
		}
	}
}
