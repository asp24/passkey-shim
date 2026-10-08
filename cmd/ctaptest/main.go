package main

// An independent CTAP2 client that exercises the authenticator the way a
// browser does: register a credential, then authenticate with it, then verify
// the resulting signature against the public key the registration handed back.
//
// The structs here are defined separately from the daemon's on purpose. If both
// sides shared one definition, a mistake in the encoding would cancel itself
// out and the test would pass on a credential no real relying party accepts.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"

	"llavero/internal/bootstrap"
)

// savedRegistration lets a later run verify against a credential registered by
// an earlier one, which is how the across-restart check works.
type savedRegistration struct {
	CredID []byte `json:"cred_id"`
	X      []byte `json:"x"`
	Y      []byte `json:"y"`
}

const packetSize = 64

var (
	enc      cbor.EncMode
	dec      cbor.DecMode
	failures int
)

func init() {
	enc, _ = cbor.CTAP2EncOptions().EncMode()
	dec, _ = cbor.DecOptions{}.DecMode()
}

func pass(format string, a ...any) { fmt.Printf("PASS  "+format+"\n", a...) }
func fail(format string, a ...any) { fmt.Printf("FAIL  "+format+"\n", a...); failures++ }

type rpEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}
type userEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}
type pubKeyCredParam struct {
	Type string `cbor:"type"`
	Alg  int    `cbor:"alg"`
}
type credentialDescriptor struct {
	Type string `cbor:"type"`
	ID   []byte `cbor:"id"`
}
type makeCredentialRequest struct {
	ClientDataHash   []byte            `cbor:"1,keyasint"`
	RP               rpEntity          `cbor:"2,keyasint"`
	User             userEntity        `cbor:"3,keyasint"`
	PubKeyCredParams []pubKeyCredParam `cbor:"4,keyasint"`
	Options          map[string]bool   `cbor:"7,keyasint,omitempty"`
}
type makeCredentialResponse struct {
	Fmt      string         `cbor:"1,keyasint"`
	AuthData []byte         `cbor:"2,keyasint"`
	AttStmt  map[string]any `cbor:"3,keyasint"`
}
type getAssertionRequest struct {
	RPID           string                 `cbor:"1,keyasint"`
	ClientDataHash []byte                 `cbor:"2,keyasint"`
	AllowList      []credentialDescriptor `cbor:"3,keyasint,omitempty"`
	Options        map[string]bool        `cbor:"5,keyasint,omitempty"`
}
type getAssertionResponse struct {
	Credential credentialDescriptor `cbor:"1,keyasint"`
	AuthData   []byte               `cbor:"2,keyasint"`
	Signature  []byte               `cbor:"3,keyasint"`
	User       *userEntity          `cbor:"4,keyasint,omitempty"`
}
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}
type authenticatorInfo struct {
	Versions   []string        `cbor:"1,keyasint"`
	AAGUID     []byte          `cbor:"3,keyasint"`
	Options    map[string]bool `cbor:"4,keyasint"`
	MaxMsgSize uint            `cbor:"5,keyasint"`
}

type conn struct {
	f   *os.File
	cid uint32
}

func (c *conn) writePacket(pkt []byte) error {
	_, err := c.f.Write(append([]byte{0x00}, pkt...))
	return err
}

func (c *conn) readPacket() ([]byte, error) {
	buf := make([]byte, packetSize)
	n, err := c.f.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *conn) transact(cid uint32, cmd byte, payload []byte) ([]byte, error) {
	pkt := make([]byte, packetSize)
	binary.BigEndian.PutUint32(pkt[0:4], cid)
	pkt[4] = cmd | 0x80
	binary.BigEndian.PutUint16(pkt[5:7], uint16(len(payload)))
	n := min(len(payload), 57)
	copy(pkt[7:], payload[:n])
	if err := c.writePacket(pkt); err != nil {
		return nil, err
	}
	sent, seq := n, byte(0)
	for sent < len(payload) {
		cont := make([]byte, packetSize)
		binary.BigEndian.PutUint32(cont[0:4], cid)
		cont[4] = seq
		n := min(len(payload)-sent, 59)
		copy(cont[5:], payload[sent:sent+n])
		if err := c.writePacket(cont); err != nil {
			return nil, err
		}
		sent += n
		seq++
	}

	for {
		p, err := c.readPacket()
		if err != nil {
			return nil, err
		}
		respCmd := p[4] & 0x7F
		total := int(binary.BigEndian.Uint16(p[5:7]))
		// Swallow KEEPALIVE frames; they arrive while a prompt is on screen.
		if respCmd == 0x3B {
			continue
		}
		out := append([]byte{}, p[7:]...)
		if len(out) > total {
			out = out[:total]
		}
		for len(out) < total {
			p, err := c.readPacket()
			if err != nil {
				return nil, err
			}
			chunk := p[5:]
			if len(chunk) > total-len(out) {
				chunk = chunk[:total-len(out)]
			}
			out = append(out, chunk...)
		}
		return out, nil
	}
}

// cbor sends a CTAP2 command and splits the status byte off the response.
func (c *conn) cbor(cmd byte, body []byte) (byte, []byte, error) {
	resp, err := c.transact(c.cid, 0x10, append([]byte{cmd}, body...))
	if err != nil {
		return 0, nil, err
	}
	if len(resp) == 0 {
		return 0, nil, fmt.Errorf("empty response")
	}
	return resp[0], resp[1:], nil
}

// parsedAuthData is the registration authData broken into its fields.
type parsedAuthData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
	CredID    []byte
	PubKey    *ecdsa.PublicKey
}

func parseAuthData(b []byte, attested bool) (*parsedAuthData, error) {
	if len(b) < 37 {
		return nil, fmt.Errorf("authData too short: %d bytes", len(b))
	}
	p := &parsedAuthData{
		RPIDHash:  b[0:32],
		Flags:     b[32],
		SignCount: binary.BigEndian.Uint32(b[33:37]),
	}
	if !attested {
		return p, nil
	}
	if len(b) < 55 {
		return nil, fmt.Errorf("authData missing attested credential data")
	}
	credLen := int(binary.BigEndian.Uint16(b[53:55]))
	if len(b) < 55+credLen {
		return nil, fmt.Errorf("credential id runs past end of authData")
	}
	p.CredID = b[55 : 55+credLen]

	var ck coseKey
	if err := dec.Unmarshal(b[55+credLen:], &ck); err != nil {
		return nil, fmt.Errorf("decoding COSE key: %w", err)
	}
	if ck.Kty != 2 || ck.Alg != -7 || ck.Crv != 1 {
		return nil, fmt.Errorf("unexpected COSE key: kty=%d alg=%d crv=%d", ck.Kty, ck.Alg, ck.Crv)
	}
	if len(ck.X) != 32 || len(ck.Y) != 32 {
		return nil, fmt.Errorf("coordinates must be 32 bytes, got x=%d y=%d", len(ck.X), len(ck.Y))
	}
	pub, err := p256Key(ck.X, ck.Y)
	if err != nil {
		return nil, fmt.Errorf("public key is not a valid P-256 point: %w", err)
	}
	p.PubKey = pub
	return p, nil
}

// p256Key builds a public key from fixed-size coordinates. Parsing rejects a
// point that is not on the curve.
func p256Key(x, y []byte) (*ecdsa.PublicKey, error) {
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, x...), y...))
}

type options struct {
	StatePath string `long:"state" value-name:"FILE" description:"persist the registration here, and reuse it if the file already exists"`
	Args      struct {
		Device string `positional-arg-name:"/dev/hidrawN"`
	} `positional-args:"yes" required:"yes"`
}

func main() {
	opts := bootstrap.MustParseConfig[options]()
	f, err := os.OpenFile(opts.Args.Device, os.O_RDWR, 0)
	if err != nil {
		fmt.Printf("FAIL  cannot open %s: %v\n", opts.Args.Device, err)
		os.Exit(1)
	}
	defer f.Close()
	c := &conn{f: f}

	const rpID = "example.test"
	userID := []byte("user-0001")

	// --- INIT -------------------------------------------------------------
	nonce := make([]byte, 8)
	rand.Read(nonce)
	resp, err := c.transact(0xFFFFFFFF, 0x06, nonce)
	if err != nil {
		fail("CTAPHID_INIT: %v", err)
		os.Exit(1)
	}
	if !bytes.Equal(resp[0:8], nonce) {
		fail("CTAPHID_INIT nonce mismatch")
		os.Exit(1)
	}
	c.cid = binary.BigEndian.Uint32(resp[8:12])
	pass("CTAPHID_INIT        channel %08x, caps 0x%02x", c.cid, resp[16])

	// --- getInfo ----------------------------------------------------------
	st, body, err := c.cbor(0x04, nil)
	if err != nil || st != 0 {
		fail("getInfo: status 0x%02x err %v", st, err)
		os.Exit(1)
	}
	var info authenticatorInfo
	if err := dec.Unmarshal(body, &info); err != nil {
		fail("getInfo: cannot decode: %v", err)
		os.Exit(1)
	}
	if !info.Options["rk"] {
		fail("getInfo: rk option is false, discoverable credentials are required for passkeys")
	} else {
		pass("getInfo             %v, rk=%v uv=%v", info.Versions, info.Options["rk"], info.Options["uv"])
	}

	wantHash := sha256.Sum256([]byte(rpID))

	// --- reuse a prior registration, if asked to --------------------------
	var reg *parsedAuthData
	reusing := false
	if opts.StatePath != "" {
		if raw, err := os.ReadFile(opts.StatePath); err == nil {
			var saved savedRegistration
			if json.Unmarshal(raw, &saved) == nil {
				pub, err := p256Key(saved.X, saved.Y)
				if err != nil {
					fail("saved registration in %s holds an invalid key: %v", opts.StatePath, err)
					os.Exit(1)
				}
				reg = &parsedAuthData{CredID: saved.CredID, PubKey: pub}
				reusing = true
				pass("reusing credential  %x… registered before the restart", saved.CredID[:6])
			}
		}
	}

	// --- makeCredential ---------------------------------------------------
	regClientData := sha256.Sum256([]byte(`{"type":"webauthn.create","challenge":"test"}`))
	if !reusing {
		mcReq := makeCredentialRequest{
			ClientDataHash: regClientData[:],
			RP:             rpEntity{ID: rpID, Name: "Example Test"},
			User:           userEntity{ID: userID, Name: "alice", DisplayName: "Alice Example"},
			PubKeyCredParams: []pubKeyCredParam{
				{Type: "public-key", Alg: -7},
			},
			Options: map[string]bool{"rk": true},
		}
		mcBody, _ := enc.Marshal(mcReq)
		st, body, err = c.cbor(0x01, mcBody)
		if err != nil {
			fail("makeCredential: %v", err)
			os.Exit(1)
		}
		if st != 0 {
			fail("makeCredential: CTAP status 0x%02x", st)
			os.Exit(1)
		}
		var mcResp makeCredentialResponse
		if err := dec.Unmarshal(body, &mcResp); err != nil {
			fail("makeCredential: cannot decode response: %v", err)
			os.Exit(1)
		}
		reg, err = parseAuthData(mcResp.AuthData, true)
		if err != nil {
			fail("makeCredential: %v", err)
			os.Exit(1)
		}

		wantHash := sha256.Sum256([]byte(rpID))
		if !bytes.Equal(reg.RPIDHash, wantHash[:]) {
			fail("makeCredential: rpIdHash does not match SHA-256(%q)", rpID)
		}
		if reg.Flags&0x40 == 0 {
			fail("makeCredential: AT flag not set, attested credential data is missing")
		}
		if reg.Flags&0x01 == 0 {
			fail("makeCredential: UP flag not set")
		}
		if mcResp.Fmt != "none" {
			fail("makeCredential: unexpected attestation format %q", mcResp.Fmt)
		}
		pass("makeCredential      fmt=%s flags=0x%02x credId=%x…", mcResp.Fmt, reg.Flags, reg.CredID[:6])
		pass("  public key        P-256, on curve, 32-byte coordinates")

		if opts.StatePath != "" {
			point, err := reg.PubKey.Bytes()
			if err != nil {
				fail("could not encode the public key for saving: %v", err)
				os.Exit(1)
			}
			saved := savedRegistration{CredID: reg.CredID, X: point[1:33], Y: point[33:65]}
			raw, _ := json.Marshal(saved)
			if err := os.WriteFile(opts.StatePath, raw, 0o600); err != nil {
				fail("could not save registration state: %v", err)
			}
		}
	}

	// --- getAssertion -----------------------------------------------------
	authClientData := sha256.Sum256([]byte(`{"type":"webauthn.get","challenge":"test2"}`))
	gaReq := getAssertionRequest{
		RPID:           rpID,
		ClientDataHash: authClientData[:],
		AllowList:      []credentialDescriptor{{Type: "public-key", ID: reg.CredID}},
		Options:        map[string]bool{"up": true},
	}
	gaBody, _ := enc.Marshal(gaReq)
	st, body, err = c.cbor(0x02, gaBody)
	if err != nil {
		fail("getAssertion: %v", err)
		os.Exit(1)
	}
	if st != 0 {
		fail("getAssertion: CTAP status 0x%02x", st)
		os.Exit(1)
	}
	var gaResp getAssertionResponse
	if err := dec.Unmarshal(body, &gaResp); err != nil {
		fail("getAssertion: cannot decode response: %v", err)
		os.Exit(1)
	}
	if !bytes.Equal(gaResp.Credential.ID, reg.CredID) {
		fail("getAssertion: returned a different credential than requested")
	}
	assert, err := parseAuthData(gaResp.AuthData, false)
	if err != nil {
		fail("getAssertion: %v", err)
		os.Exit(1)
	}
	if !bytes.Equal(assert.RPIDHash, wantHash[:]) {
		fail("getAssertion: rpIdHash mismatch")
	}
	// The user entity is optional in a getAssertion response.
	userName := "(omitted)"
	if gaResp.User != nil {
		userName = gaResp.User.Name
	}
	pass("getAssertion        credential matched, counter=%d, user=%q",
		assert.SignCount, userName)

	// --- the test that decides everything ---------------------------------
	// A relying party verifies exactly this: ECDSA over SHA-256 of authData
	// concatenated with the client data hash.
	signed := append(append([]byte{}, gaResp.AuthData...), authClientData[:]...)
	digest := sha256.Sum256(signed)
	if ecdsa.VerifyASN1(reg.PubKey, digest[:], gaResp.Signature) {
		pass("SIGNATURE VERIFIES  against the public key from registration")
	} else {
		fail("SIGNATURE DOES NOT VERIFY, no relying party would accept this assertion")
	}

	// A wrong challenge must not verify, or the check above proves nothing.
	badDigest := sha256.Sum256(append(append([]byte{}, gaResp.AuthData...), make([]byte, 32)...))
	if ecdsa.VerifyASN1(reg.PubKey, badDigest[:], gaResp.Signature) {
		fail("signature verified against the WRONG challenge, the check is meaningless")
	} else {
		pass("negative control    wrong challenge correctly rejected")
	}

	// --- counter must advance --------------------------------------------
	st, body, err = c.cbor(0x02, gaBody)
	if err == nil && st == 0 {
		var second getAssertionResponse
		if dec.Unmarshal(body, &second) == nil {
			s2, err := parseAuthData(second.AuthData, false)
			if err == nil {
				if s2.SignCount > assert.SignCount {
					pass("sign counter        advanced %d -> %d", assert.SignCount, s2.SignCount)
				} else {
					fail("sign counter did not advance (%d -> %d)", assert.SignCount, s2.SignCount)
				}
			}
		}
	}

	// --- unknown RP must not yield a credential ---------------------------
	gaReq.RPID = "not-registered.test"
	gaReq.AllowList = nil
	otherBody, _ := enc.Marshal(gaReq)
	st, _, err = c.cbor(0x02, otherBody)
	switch {
	case err != nil:
		fail("unknown RP: %v", err)
	case st == 0x2E:
		pass("unknown RP          correctly returned NO_CREDENTIALS (0x2e)")
	default:
		fail("unknown RP returned status 0x%02x, expected 0x2e", st)
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("%d check(s) FAILED\n", failures)
		os.Exit(1)
	}
	fmt.Println("all checks passed")
}
