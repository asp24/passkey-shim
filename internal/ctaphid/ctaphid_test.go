package ctaphid

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// recorder captures every report the transport sends to the host.
type recorder struct {
	mu      sync.Mutex
	packets [][]byte
}

func (r *recorder) SendInput(report []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.packets = append(r.packets, append([]byte(nil), report...))
	return nil
}

// message reassembles the recorded packets into (cid, cmd, payload), skipping
// keepalives the way a browser does.
func (r *recorder) message(t *testing.T) (uint32, byte, []byte) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range r.packets {
		if p[4]&0x7f == cmdKeepalive {
			continue
		}
		cid := binary.BigEndian.Uint32(p[0:4])
		cmd := p[4] & 0x7f
		total := int(binary.BigEndian.Uint16(p[5:7]))
		out := append([]byte{}, p[7:7+min(total, initDataLen)]...)
		for seq, cont := range r.packets[i+1:] {
			if len(out) >= total {
				break
			}
			if cont[4] != byte(seq) {
				t.Fatalf("continuation %d has sequence %d", seq, cont[4])
			}
			out = append(out, cont[5:5+min(total-len(out), contDataLen)]...)
		}
		return cid, cmd, out
	}
	t.Fatal("no message was sent")
	return 0, 0, nil
}

// packets frames a host-to-device message the way a browser would.
func packets(cid uint32, cmd byte, payload []byte) [][]byte {
	first := make([]byte, packetSize)
	binary.BigEndian.PutUint32(first[0:4], cid)
	first[4] = cmd | 0x80
	binary.BigEndian.PutUint16(first[5:7], uint16(len(payload)))
	n := copy(first[7:], payload)
	out := [][]byte{first}
	for seq := byte(0); n < len(payload); seq++ {
		cont := make([]byte, packetSize)
		binary.BigEndian.PutUint32(cont[0:4], cid)
		cont[4] = seq
		n += copy(cont[5:], payload[n:])
		out = append(out, cont)
	}
	return out
}

func newTestTransport(onCBOR func(context.Context, []byte) []byte) (*Transport, *recorder) {
	rec := &recorder{}
	if onCBOR == nil {
		onCBOR = func(context.Context, []byte) []byte { return nil }
	}
	return New(rec, onCBOR, zap.NewNop()), rec
}

func TestInitAllocatesChannel(t *testing.T) {
	tr, rec := newTestTransport(nil)
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	tr.HandlePacket(context.Background(), packets(broadcastCID, cmdInit, nonce)[0])

	cid, cmd, resp := rec.message(t)
	if cid != broadcastCID || cmd != cmdInit {
		t.Fatalf("reply on %08x cmd 0x%02x, want broadcast INIT", cid, cmd)
	}
	if !bytes.Equal(resp[:8], nonce) {
		t.Fatal("nonce not echoed")
	}
	got := binary.BigEndian.Uint32(resp[8:12])
	if got == 0 || got == broadcastCID {
		t.Fatalf("allocated reserved channel %08x", got)
	}
	if resp[16]&capNMSG == 0 || resp[16]&capCBOR == 0 {
		t.Fatalf("capabilities 0x%02x, want CBOR and NMSG", resp[16])
	}
}

// Payloads that span several packets in both directions must come back intact.
func TestPingRoundTripsFragmentedPayloads(t *testing.T) {
	for _, size := range []int{0, 1, initDataLen, initDataLen + 1, initDataLen + contDataLen + 1, 1000} {
		tr, rec := newTestTransport(nil)
		payload := bytes.Repeat([]byte{0xa5}, size)
		for _, p := range packets(7, cmdPing, payload) {
			tr.HandlePacket(context.Background(), p)
		}
		cid, cmd, resp := rec.message(t)
		if cid != 7 || cmd != cmdPing || !bytes.Equal(resp, payload) {
			t.Fatalf("size %d: got cid %d cmd 0x%02x, %d bytes", size, cid, cmd, len(resp))
		}
	}
}

func TestCBORReachesHandler(t *testing.T) {
	var got []byte
	tr, rec := newTestTransport(func(_ context.Context, p []byte) []byte {
		got = append([]byte(nil), p...)
		return []byte{0x00, 0xaa}
	})
	request := append([]byte{0x04}, bytes.Repeat([]byte{0x11}, 100)...)
	for _, p := range packets(9, cmdCBOR, request) {
		tr.HandlePacket(context.Background(), p)
	}
	if !bytes.Equal(got, request) {
		t.Fatalf("handler got %d bytes, want %d", len(got), len(request))
	}
	if _, cmd, resp := rec.message(t); cmd != cmdCBOR || !bytes.Equal(resp, []byte{0x00, 0xaa}) {
		t.Fatalf("response cmd 0x%02x %x", cmd, resp)
	}
}

func TestErrors(t *testing.T) {
	tooLong := packets(3, cmdPing, nil)[0]
	binary.BigEndian.PutUint16(tooLong[5:7], 7610)

	skipped := packets(3, cmdPing, bytes.Repeat([]byte{1}, 200))
	skipped[1][4] = 1 // first continuation claims sequence 1

	tests := []struct {
		name    string
		packets [][]byte
		want    byte
	}{
		{"message over spec maximum", [][]byte{tooLong}, errInvalidLen},
		{"out-of-order continuation", skipped[:2], errInvalidSeq},
		{"legacy U2F message", packets(3, cmdMsg, []byte{1}), errInvalidCmd},
		{"unknown command", packets(3, 0x2a, nil), errInvalidCmd},
		{"empty CBOR message", packets(3, cmdCBOR, nil), errInvalidLen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, rec := newTestTransport(nil)
			for _, p := range tt.packets {
				tr.HandlePacket(context.Background(), p)
			}
			_, cmd, resp := rec.message(t)
			if cmd != cmdError || len(resp) != 1 || resp[0] != tt.want {
				t.Fatalf("got cmd 0x%02x %x, want ERROR 0x%02x", cmd, resp, tt.want)
			}
		})
	}
}

func TestRuntAndStrayPacketsAreIgnored(t *testing.T) {
	tr, rec := newTestTransport(nil)
	tr.HandlePacket(context.Background(), []byte{1, 2, 3})
	stray := make([]byte, packetSize)
	binary.BigEndian.PutUint32(stray[0:4], 5)
	stray[4] = 0 // continuation on an idle channel
	tr.HandlePacket(context.Background(), stray)
	if len(rec.packets) != 0 {
		t.Fatalf("sent %d packets in reply to garbage", len(rec.packets))
	}
}
