// Package ctaphid implements CTAPHID transport framing, per CTAP 2.1 section
// 11.2.
//
// Everything travels in 64-byte packets. A message opens with an "init" packet
// carrying the command and total payload length, and spills into "continuation"
// packets numbered 0,1,2... The sequence numbers are the only thing keeping
// reassembly honest, so they are checked strictly.
package ctaphid

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"go.uber.org/zap"
)

const (
	packetSize  = 64
	initDataLen = packetSize - 7 // 57
	contDataLen = packetSize - 5 // 59

	broadcastCID = 0xFFFFFFFF

	cmdPing      = 0x01
	cmdMsg       = 0x03
	cmdInit      = 0x06
	cmdWink      = 0x08
	cmdCBOR      = 0x10
	cmdCancel    = 0x11
	cmdKeepalive = 0x3B
	cmdError     = 0x3F

	// Capability flags advertised in the INIT response.
	capCBOR = 0x04 // speaks CTAP2
	capNMSG = 0x08 // does NOT speak legacy U2F (CTAPHID_MSG)

	errInvalidCmd = 0x01
	errInvalidLen = 0x03
	errInvalidSeq = 0x04
	errOther      = 0x7F

	// KEEPALIVE status bytes.
	statusProcessing = 0x01
	statusUPNeeded   = 0x02

	// How often to reassure the host while a prompt is on screen. The spec
	// suggests 100ms; browsers give up after a second or so of silence.
	keepaliveInterval = 100 * time.Millisecond
)

// assembly tracks a partially received message on one channel.
type assembly struct {
	cmd     byte
	total   int
	payload []byte
	nextSeq byte
}

// ReportSender delivers one 64-byte input report to the host.
type ReportSender interface {
	SendInput(report []byte) error
}

// Transport reassembles host packets into CTAPHID messages, answers the
// transport-level commands itself and hands CTAP2 payloads to a handler.
// HandlePacket must be called from one goroutine.
type Transport struct {
	dev     ReportSender
	pending map[uint32]*assembly
	nextCID uint32
	onCBOR  func(payload []byte) []byte
	log     *zap.Logger
}

// New returns a Transport that answers through dev and passes each CTAP2
// message to onCBOR, whose return value is sent back as the response. Frames
// are logged at debug level, transport faults at warn.
func New(dev ReportSender, onCBOR func([]byte) []byte, log *zap.Logger) *Transport {
	return &Transport{
		dev:     dev,
		pending: make(map[uint32]*assembly),
		nextCID: rand.Uint32() | 1,
		onCBOR:  onCBOR,
		log:     log,
	}
}

// HandlePacket consumes one 64-byte host-to-device packet.
func (c *Transport) HandlePacket(p []byte) {
	if len(p) < 5 {
		c.log.Debug("ignoring runt packet", zap.Int("bytes", len(p)))
		return
	}
	if len(p) < packetSize {
		// Pad; the host is allowed to send a short final packet.
		padded := make([]byte, packetSize)
		copy(padded, p)
		p = padded
	}

	cid := binary.BigEndian.Uint32(p[0:4])

	if p[4]&0x80 != 0 { // init packet
		cmd := p[4] & 0x7F
		bcnt := int(binary.BigEndian.Uint16(p[5:7]))

		if cmd == cmdInit {
			delete(c.pending, cid) // INIT aborts any transaction on this channel
			c.handleInit(cid, p[7:7+8])
			return
		}
		if cmd == cmdCancel {
			delete(c.pending, cid)
			return
		}
		if bcnt > 7609 { // spec maximum message size
			c.sendError(cid, errInvalidLen)
			return
		}

		a := &assembly{cmd: cmd, total: bcnt}
		n := bcnt
		if n > initDataLen {
			n = initDataLen
		}
		a.payload = append(a.payload, p[7:7+n]...)
		if len(a.payload) >= bcnt {
			c.dispatch(cid, a)
			return
		}
		c.pending[cid] = a
		return
	}

	// continuation packet
	a, ok := c.pending[cid]
	if !ok {
		c.log.Debug("ignoring continuation for idle channel", cidField(cid))
		return
	}
	seq := p[4]
	if seq != a.nextSeq {
		c.log.Warn("bad continuation sequence", cidField(cid), zap.Uint8("got", seq), zap.Uint8("want", a.nextSeq))
		delete(c.pending, cid)
		c.sendError(cid, errInvalidSeq)
		return
	}
	a.nextSeq++
	remaining := a.total - len(a.payload)
	n := contDataLen
	if n > remaining {
		n = remaining
	}
	a.payload = append(a.payload, p[5:5+n]...)
	if len(a.payload) >= a.total {
		delete(c.pending, cid)
		c.dispatch(cid, a)
	}
}

func (c *Transport) handleInit(cid uint32, nonce []byte) {
	newCID := cid
	if cid == broadcastCID {
		c.nextCID++
		if c.nextCID == 0 || c.nextCID == broadcastCID {
			c.nextCID = 1
		}
		newCID = c.nextCID
	}
	c.log.Debug("CTAPHID_INIT", cidField(cid), zap.String("allocated", fmt.Sprintf("%08x", newCID)))

	resp := make([]byte, 17)
	copy(resp[0:8], nonce)
	binary.BigEndian.PutUint32(resp[8:12], newCID)
	resp[12] = 2 // CTAPHID protocol version
	resp[13] = 0 // device major
	resp[14] = 1 // device minor
	resp[15] = 0 // device build
	resp[16] = capCBOR | capNMSG
	c.sendMessage(cid, cmdInit, resp)
}

func (c *Transport) dispatch(cid uint32, a *assembly) {
	switch a.cmd {
	case cmdPing:
		c.log.Debug("CTAPHID_PING", cidField(cid), zap.Int("bytes", len(a.payload)))
		c.sendMessage(cid, cmdPing, a.payload)
	case cmdCBOR:
		if len(a.payload) == 0 {
			c.sendError(cid, errInvalidLen)
			return
		}
		c.log.Debug("CTAPHID_CBOR", cidField(cid),
			zap.String("command", describeCBORCommand(a.payload[0])), zap.Int("bytes", len(a.payload)))
		c.runWithKeepalive(cid, a.payload)
	case cmdWink:
		c.log.Debug("CTAPHID_WINK", cidField(cid))
		c.sendMessage(cid, cmdWink, nil)
	case cmdMsg:
		// We advertise NMSG, so a well-behaved host never sends this.
		c.log.Debug("refusing legacy U2F CTAPHID_MSG", cidField(cid))
		c.sendError(cid, errInvalidCmd)
	default:
		c.log.Debug("unhandled CTAPHID command", cidField(cid), zap.Uint8("command", a.cmd))
		c.sendError(cid, errInvalidCmd)
	}
}

// runWithKeepalive executes a CTAP2 command while trickling KEEPALIVE frames
// back to the host. Commands here block on a desktop approval dialog for as
// long as the user takes, and without these frames the browser abandons the
// request after about a second.
//
// Note this blocks the read loop, so CTAPHID_CANCEL is not honoured mid-prompt;
// the host times out instead. Acceptable while there is one dialog at a time.
func (c *Transport) runWithKeepalive(cid uint32, payload []byte) {
	done := make(chan []byte, 1)
	go func() { done <- c.onCBOR(payload) }()

	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case resp := <-done:
			c.sendMessage(cid, cmdCBOR, resp)
			return
		case <-ticker.C:
			c.sendKeepalive(cid, statusUPNeeded)
		}
	}
}

func (c *Transport) sendKeepalive(cid uint32, status byte) {
	pkt := make([]byte, packetSize)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmdKeepalive | 0x80
	binary.BigEndian.PutUint16(pkt[5:7], 1)
	pkt[7] = status
	if err := c.dev.SendInput(pkt); err != nil {
		c.log.Warn("keepalive send failed", cidField(cid), zap.Error(err))
	}
}

func (c *Transport) sendError(cid uint32, code byte) {
	c.sendMessage(cid, cmdError, []byte{code})
}

// sendMessage fragments a payload back to the host across as many packets as
// it takes.
func (c *Transport) sendMessage(cid uint32, cmd byte, payload []byte) {
	pkt := make([]byte, packetSize)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmd | 0x80
	binary.BigEndian.PutUint16(pkt[5:7], uint16(len(payload)))

	n := len(payload)
	if n > initDataLen {
		n = initDataLen
	}
	copy(pkt[7:], payload[:n])
	if err := c.dev.SendInput(pkt); err != nil {
		c.log.Warn("send failed", cidField(cid), zap.Error(err))
		return
	}
	sent := n

	var seq byte
	for sent < len(payload) {
		cont := make([]byte, packetSize)
		binary.BigEndian.PutUint32(cont[0:4], cid)
		cont[4] = seq
		n := len(payload) - sent
		if n > contDataLen {
			n = contDataLen
		}
		copy(cont[5:], payload[sent:sent+n])
		if err := c.dev.SendInput(cont); err != nil {
			c.log.Warn("send failed", cidField(cid), zap.Error(err))
			return
		}
		sent += n
		seq++
		if seq > 0x7F {
			c.log.Error("message too long to fragment", cidField(cid), zap.Int("bytes", len(payload)))
			return
		}
	}
}

// cidField renders a channel id the way the CTAP spec writes them.
func cidField(cid uint32) zap.Field { return zap.String("cid", fmt.Sprintf("%08x", cid)) }

func describeCBORCommand(b byte) string {
	switch b {
	case 0x01:
		return "authenticatorMakeCredential"
	case 0x02:
		return "authenticatorGetAssertion"
	case 0x04:
		return "authenticatorGetInfo"
	case 0x06:
		return "authenticatorClientPIN"
	case 0x08:
		return "authenticatorGetNextAssertion"
	case 0x0A:
		return "authenticatorCredentialManagement"
	case 0x0B:
		return "authenticatorSelection"
	default:
		return fmt.Sprintf("unknown(0x%02x)", b)
	}
}
