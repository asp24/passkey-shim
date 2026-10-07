package main

import (
	"bytes"
	"errors"
	"llavero/internal/hidbridge"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type reportSink struct{ got []byte }

var errReceived = errors.New("received")

func (s *reportSink) SendInput(b []byte) error { s.got = append([]byte(nil), b...); return errReceived }

func TestReportBoundary(t *testing.T) {
	for _, size := range []int{0, 1, 63, 64, 65, 4096} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "socket")
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			uid, err := hidbridge.PeerUID(server)
			if err != nil || uid != uint32(os.Getuid()) {
				t.Fatalf("peer uid: %d, %v", uid, err)
			}
			payload := bytes.Repeat([]byte{0x0b}, size) // even UHID-like data is just a report
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			sink := &reportSink{}
			err = forwardReports(server, sink)
			if size == 64 {
				if !errors.Is(err, errReceived) || !bytes.Equal(sink.got, payload) {
					t.Fatalf("valid report: %v, %x", err, sink.got)
				}
			} else if err == nil || sink.got != nil {
				t.Fatalf("invalid report reached device: %v", err)
			}
		})
	}
}
