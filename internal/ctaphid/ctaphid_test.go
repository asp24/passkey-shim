package ctaphid

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
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

// newTestTransport returns a transport that waits for its background request
// when the test ends, so no handler outlives the test.
func newTestTransport(t *testing.T, onCBOR func(context.Context, []byte) []byte) (*Transport, *recorder) {
	t.Helper()
	rec := &recorder{}
	if onCBOR == nil {
		onCBOR = func(context.Context, []byte) []byte { return nil }
	}
	tr := New(rec, onCBOR, zaptest.NewLogger(t))
	t.Cleanup(tr.Wait)
	return tr, rec
}

func TestInitAllocatesChannel(t *testing.T) {
	tr, rec := newTestTransport(t, nil)
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
		tr, rec := newTestTransport(t, nil)
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
	tr, rec := newTestTransport(t, func(_ context.Context, p []byte) []byte {
		got = append([]byte(nil), p...)
		return []byte{0x00, 0xaa}
	})
	request := append([]byte{0x04}, bytes.Repeat([]byte{0x11}, 100)...)
	for _, p := range packets(9, cmdCBOR, request) {
		tr.HandlePacket(context.Background(), p)
	}
	tr.Wait()
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
			tr, rec := newTestTransport(t, nil)
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
	tr, rec := newTestTransport(t, nil)
	tr.HandlePacket(context.Background(), []byte{1, 2, 3})
	stray := make([]byte, packetSize)
	binary.BigEndian.PutUint32(stray[0:4], 5)
	stray[4] = 0 // continuation on an idle channel
	tr.HandlePacket(context.Background(), stray)
	if len(rec.packets) != 0 {
		t.Fatalf("sent %d packets in reply to garbage", len(rec.packets))
	}
}

// blockingHandler stands in for a request waiting on the user. It reports
// that it started, then answers KEEPALIVE_CANCEL once its context is done, or
// OK once released.
type blockingHandler struct {
	started  chan struct{}
	release  chan struct{}
	canceled chan struct{}
}

func newBlockingHandler() *blockingHandler {
	return &blockingHandler{
		started:  make(chan struct{}, 4),
		release:  make(chan struct{}),
		canceled: make(chan struct{}, 4),
	}
}

func (h *blockingHandler) handle(ctx context.Context, _ []byte) []byte {
	h.started <- struct{}{}
	select {
	case <-ctx.Done():
		h.canceled <- struct{}{}
		return []byte{0x2d}
	case <-h.release:
		return []byte{0x00}
	}
}

const waitTimeout = 2 * time.Second

func startCBOR(t *testing.T, tr *Transport, ctx context.Context, cid uint32, h *blockingHandler) {
	t.Helper()
	for _, p := range packets(cid, cmdCBOR, []byte{0x02, 0xa0}) {
		tr.HandlePacket(ctx, p)
	}
	select {
	case <-h.started:
	case <-time.After(waitTimeout):
		t.Fatal("handler did not start")
	}
}

func waitDone(t *testing.T, tr *Transport) {
	t.Helper()
	done := make(chan struct{})
	go func() { tr.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("request did not finish")
	}
}

// cborResponse returns the payload of the CTAPHID_CBOR response sent on cid.
func cborResponse(t *testing.T, rec *recorder, cid uint32) []byte {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, p := range rec.packets {
		if binary.BigEndian.Uint32(p[0:4]) == cid && p[4] == cmdCBOR|0x80 {
			n := int(binary.BigEndian.Uint16(p[5:7]))
			return append([]byte(nil), p[7:7+n]...)
		}
	}
	t.Fatalf("no CBOR response on channel %08x", cid)
	return nil
}

// errorOn returns the CTAPHID_ERROR code sent on cid, or -1.
func errorOn(rec *recorder, cid uint32) int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, p := range rec.packets {
		if binary.BigEndian.Uint32(p[0:4]) == cid && p[4] == cmdError|0x80 {
			return int(p[7])
		}
	}
	return -1
}

// CANCEL or INIT on the request's own channel must stop it promptly and send
// the handler's answer as the response.
func TestAbortStopsRequest(t *testing.T) {
	tests := []struct {
		name  string
		abort []byte
	}{
		{"CTAPHID_CANCEL", packets(9, cmdCancel, nil)[0]},
		{"CTAPHID_INIT resync", packets(9, cmdInit, bytes.Repeat([]byte{7}, 8))[0]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newBlockingHandler()
			tr, rec := newTestTransport(t, h.handle)
			startCBOR(t, tr, context.Background(), 9, h)

			tr.HandlePacket(context.Background(), tt.abort)
			waitDone(t, tr)
			select {
			case <-h.canceled:
			default:
				t.Fatal("handler context was not cancelled")
			}
			if got := cborResponse(t, rec, 9); !bytes.Equal(got, []byte{0x2d}) {
				t.Fatalf("response %x, want KEEPALIVE_CANCEL", got)
			}
		})
	}
}

// Another channel cannot cancel a request it does not own.
func TestCancelOnOtherChannelIsIgnored(t *testing.T) {
	h := newBlockingHandler()
	tr, rec := newTestTransport(t, h.handle)
	startCBOR(t, tr, context.Background(), 9, h)

	tr.HandlePacket(context.Background(), packets(10, cmdCancel, nil)[0])
	select {
	case <-h.canceled:
		t.Fatal("CANCEL from another channel stopped the request")
	case <-time.After(50 * time.Millisecond):
	}
	close(h.release)
	waitDone(t, tr)
	if got := cborResponse(t, rec, 9); !bytes.Equal(got, []byte{0x00}) {
		t.Fatalf("response %x, want the handler's OK", got)
	}
}

// While one request waits for the user, any other CTAP2 request is refused
// rather than queued behind a prompt.
func TestBusyWhileRequestRuns(t *testing.T) {
	for _, cid := range []uint32{9, 10} {
		h := newBlockingHandler()
		tr, rec := newTestTransport(t, h.handle)
		startCBOR(t, tr, context.Background(), 9, h)

		for _, p := range packets(cid, cmdCBOR, []byte{0x02, 0xa0}) {
			tr.HandlePacket(context.Background(), p)
		}
		if got := errorOn(rec, cid); got != errChannelBusy {
			t.Fatalf("second request on %08x got error %d, want ERR_CHANNEL_BUSY", cid, got)
		}
		close(h.release)
		waitDone(t, tr)
	}
}

// Once a response is out, the next request must be accepted.
func TestNotBusyAfterResponse(t *testing.T) {
	h := newBlockingHandler()
	close(h.release)
	tr, rec := newTestTransport(t, h.handle)
	for range 3 {
		startCBOR(t, tr, context.Background(), 9, h)
		waitDone(t, tr)
	}
	if got := errorOn(rec, 9); got != -1 {
		t.Fatalf("sequential requests got error %d", got)
	}
}

// Cancelling the transport's parent context ends the running request, which
// is how the daemon shuts down with a prompt open.
func TestParentContextCancelsRequest(t *testing.T) {
	h := newBlockingHandler()
	tr, rec := newTestTransport(t, h.handle)
	ctx, cancel := context.WithCancel(context.Background())
	startCBOR(t, tr, ctx, 9, h)

	cancel()
	waitDone(t, tr)
	if got := cborResponse(t, rec, 9); !bytes.Equal(got, []byte{0x2d}) {
		t.Fatalf("response %x, want KEEPALIVE_CANCEL", got)
	}
}
