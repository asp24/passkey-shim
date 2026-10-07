package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"go.uber.org/zap/zaptest"

	"llavero/internal/hidbridge"
)

// A broker that cannot open /dev/uhid must fail before it creates a socket,
// so systemd marks the unit failed and clients fail at connect time.
func TestServeRefusesWithoutDevice(t *testing.T) {
	errNoModule := errors.New("no uhid module")
	uid := os.Getuid() + 1000000 // a socket path no other test or broker uses
	err := serve(context.Background(), uid, zaptest.NewLogger(t), func() error { return errNoModule })
	if !errors.Is(err, errNoModule) {
		t.Fatalf("serve() = %v, want the device check's error", err)
	}
	if _, err := os.Stat(hidbridge.SocketPath(uid)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket exists after a failed start: %v", err)
	}
}
