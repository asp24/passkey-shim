// llavero-uhid owns a fixed FIDO device. Its client can only send 64-byte
// reports; the UHID descriptor and kernel event types never cross the socket.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"llavero/internal/hidbridge"
	"llavero/internal/uhid"
	"net"
	"os"
	"strconv"
	"sync"
)

func main() {
	uidFlag := flag.String("uid", "", "numeric UID allowed to connect (required)")
	flag.Parse()
	uid, err := strconv.ParseUint(*uidFlag, 10, 32)
	if err != nil || uid == 0 {
		fatal("-uid must name a non-root numeric UID")
	}
	if os.Geteuid() != 0 {
		fatal("must run as root")
	}
	if err := serve(int(uid)); err != nil {
		fatal(err)
	}
}

func serve(uid int) error {
	path := hidbridge.SocketPath(uid)
	// systemd creates the root-owned runtime directory. Never remove an existing
	// socket: a second broker must not take over a running broker's endpoint.
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chown(path, uid, -1); err != nil {
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	var active sync.Mutex
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		peer, err := hidbridge.PeerUID(conn)
		if err != nil || peer != uint32(uid) {
			conn.Close()
			continue
		}
		if !active.TryLock() {
			conn.Close()
			continue
		}
		go func() {
			defer active.Unlock()
			defer conn.Close()
			// A client closing its socket is the normal way a session ends.
			if err := relay(conn, uid); err != nil && !errors.Is(err, io.EOF) {
				fmt.Printf("client disconnected: %v\n", err)
			}
		}()
	}
}

func relay(conn *net.UnixConn, uid int) error {
	if _, err := conn.Write([]byte{hidbridge.Accepted}); err != nil {
		return err
	}
	// The client connects before unlocking its vault but asks for the device
	// only afterwards, so a locked authenticator never shows up in browsers.
	if err := awaitCreate(conn); err != nil {
		return err
	}
	dev, err := uhid.Open()
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := dev.Create(hidbridge.DeviceUniq(uid)); err != nil {
		return err
	}
	// A ready byte confirms device creation, so the client fails loudly if the
	// kernel refused it.
	if _, err := conn.Write([]byte{hidbridge.Ready}); err != nil {
		return err
	}
	// Closing the socket on either direction's failure wakes the other direction.
	// The kernel reader is nonblocking through os.File's poller, so Close wakes it.
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
		return err
	}
	if n != 1 || buf[0] != hidbridge.CmdCreate {
		return fmt.Errorf("expected create request, got %d-byte message", n)
	}
	return nil
}

func forwardReports(conn *net.UnixConn, dev interface{ SendInput([]byte) error }) error {
	buf := make([]byte, hidbridge.ReportSize+1)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		if n != hidbridge.ReportSize {
			return fmt.Errorf("invalid report length %d", n)
		}
		if err := dev.SendInput(buf[:n]); err != nil {
			return err
		}
	}
}

func forwardEvents(conn *net.UnixConn, dev *uhid.Device) error {
	for {
		ev, err := dev.Read()
		if err != nil {
			return err
		}
		var packet []byte
		switch ev.Kind {
		case uhid.EventStart:
			packet = []byte{hidbridge.EventStart}
		case uhid.EventStop:
			packet = []byte{hidbridge.EventStop}
		case uhid.EventOpen:
			packet = []byte{hidbridge.EventOpen}
		case uhid.EventClose:
			packet = []byte{hidbridge.EventClose}
		case uhid.EventOutput:
			if len(ev.Data) != hidbridge.ReportSize {
				return fmt.Errorf("invalid kernel FIDO report length %d", len(ev.Data))
			}
			packet = append([]byte{hidbridge.EventOutput}, ev.Data...)
		default:
			continue
		}
		if _, err := conn.Write(packet); err != nil {
			return err
		}
	}
}

func fatal(v any) { fmt.Fprintln(os.Stderr, v); os.Exit(1) }
