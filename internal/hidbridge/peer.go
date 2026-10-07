package hidbridge

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// PeerUID returns the UID of the process on the other end of conn, as the
// kernel recorded it at connect time (SO_PEERCRED).
func PeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("accessing socket: %w", err)
	}
	var cred *unix.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) { cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return 0, fmt.Errorf("accessing socket: %w", err)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("reading SO_PEERCRED: %w", sockErr)
	}
	return cred.Uid, nil
}
