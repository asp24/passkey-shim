package ctap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// memStore is an in-memory Store.
type memStore struct {
	creds []storedCred
}

type storedCred struct {
	rpID string
	Credential
	signCount uint32
}

func (s *memStore) HasCredentialFor(rpID string, exclude [][]byte) bool {
	for _, c := range s.creds {
		for _, id := range exclude {
			if c.rpID == rpID && bytes.Equal(c.ID, id) {
				return true
			}
		}
	}
	return false
}

func (s *memStore) AddCredential(rp RPEntity, user UserEntity) ([]byte, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	id := make([]byte, 32)
	rand.Read(id)
	s.creds = append(s.creds, storedCred{rpID: rp.ID, Credential: Credential{
		ID: id, UserID: user.ID, UserName: user.Name, UserDisplay: user.DisplayName, PrivateKey: pkcs8,
	}})
	return id, priv, nil
}

func (s *memStore) FindForRP(rpID string, allow [][]byte) []Credential {
	var out []Credential
	for i := len(s.creds) - 1; i >= 0; i-- {
		c := s.creds[i]
		if c.rpID != rpID {
			continue
		}
		if len(allow) > 0 && !containsID(allow, c.ID) {
			continue
		}
		out = append(out, c.Credential)
	}
	return out
}

func (s *memStore) BumpSignCount(id []byte) (uint32, error) {
	for i := range s.creds {
		if bytes.Equal(s.creds[i].ID, id) {
			s.creds[i].signCount++
			return s.creds[i].signCount, nil
		}
	}
	return 0, errors.New("not found")
}

func containsID(ids [][]byte, id []byte) bool {
	for _, x := range ids {
		if bytes.Equal(x, id) {
			return true
		}
	}
	return false
}

// fakeApprover approves by picking the first choice, or declines.
type fakeApprover struct {
	decline bool
	err     error
}

func (f fakeApprover) Confirm(_ context.Context, _ string, choices []string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if f.decline {
		return "", nil
	}
	return choices[0], nil
}

type fakeVerifier struct {
	match bool
	err   error
	calls int
}

func (f *fakeVerifier) Verify(context.Context, string) (bool, error) {
	f.calls++
	return f.match, f.err
}

type nopNotifier struct{}

func (nopNotifier) Notify(string, string) {}

func newTestAuthenticator(t *testing.T, store Store, ap Approver, uv UserVerifier, mutate ...func(*Config)) *Authenticator {
	cfg := Config{Store: store, Approver: ap, Notifier: nopNotifier{}, AAGUID: [16]byte{1, 2, 3}, Logger: zaptest.NewLogger(t)}
	if uv != nil {
		cfg.Verifier = uv
	}
	for _, m := range mutate {
		m(&cfg)
	}
	return New(cfg)
}

func clientDataHash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func command(t *testing.T, cmd byte, req any) []byte {
	t.Helper()
	body, err := ctapEncMode.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{cmd}, body...)
}

func registerRequest(rpID string, algs ...int) makeCredentialRequest {
	if len(algs) == 0 {
		algs = []int{algES256}
	}
	params := make([]pubKeyCredParam, 0, len(algs))
	for _, a := range algs {
		params = append(params, pubKeyCredParam{Type: "public-key", Alg: a})
	}
	return makeCredentialRequest{
		ClientDataHash:   clientDataHash("create"),
		RP:               RPEntity{ID: rpID, Name: "Example"},
		User:             UserEntity{ID: []byte("user-1"), Name: "alice"},
		PubKeyCredParams: params,
		Options:          map[string]bool{"rk": true},
	}
}

func signRequest(rpID string) getAssertionRequest {
	return getAssertionRequest{RPID: rpID, ClientDataHash: clientDataHash("get")}
}

// register runs makeCredential and returns the credential ID and public key
// parsed out of the attested authData.
func register(t *testing.T, a *Authenticator, rpID string) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	resp := a.Handle(context.Background(), command(t, ctapMakeCredential, registerRequest(rpID)))
	if resp[0] != statusOK {
		t.Fatalf("makeCredential status 0x%02x", resp[0])
	}
	var mc makeCredentialResponse
	if err := ctapDecMode.Unmarshal(resp[1:], &mc); err != nil {
		t.Fatal(err)
	}
	ad := mc.AuthData
	wantHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(ad[:32], wantHash[:]) {
		t.Fatal("rpIdHash mismatch")
	}
	if ad[32]&flagAttestedData == 0 {
		t.Fatal("AT flag missing")
	}
	credLen := int(binary.BigEndian.Uint16(ad[53:55]))
	credID := ad[55 : 55+credLen]
	var key coseKey
	if err := ctapDecMode.Unmarshal(ad[55+credLen:], &key); err != nil {
		t.Fatal(err)
	}
	if len(key.X) != 32 || len(key.Y) != 32 {
		t.Fatalf("coordinates are %d and %d bytes, want 32", len(key.X), len(key.Y))
	}
	point := append(append([]byte{0x04}, key.X...), key.Y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		t.Fatalf("registered public key is invalid: %v", err)
	}
	return credID, pub
}

func TestRegisterThenSignVerifies(t *testing.T) {
	a := newTestAuthenticator(t, &memStore{}, fakeApprover{}, nil)
	credID, pub := register(t, a, "example.test")

	for wantCount := uint32(1); wantCount <= 2; wantCount++ {
		req := signRequest("example.test")
		resp := a.Handle(context.Background(), command(t, ctapGetAssertion, req))
		if resp[0] != statusOK {
			t.Fatalf("getAssertion status 0x%02x", resp[0])
		}
		var ga getAssertionResponse
		if err := ctapDecMode.Unmarshal(resp[1:], &ga); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ga.Credential.ID, credID) {
			t.Fatal("assertion names a different credential")
		}
		if got := binary.BigEndian.Uint32(ga.AuthData[33:37]); got != wantCount {
			t.Fatalf("sign count = %d, want %d", got, wantCount)
		}
		if ga.AuthData[32]&(flagUserPresent|flagUserVerified) != flagUserPresent|flagUserVerified {
			t.Fatalf("flags 0x%02x lack UP|UV", ga.AuthData[32])
		}
		digest := sha256.Sum256(append(append([]byte{}, ga.AuthData...), req.ClientDataHash...))
		if !ecdsa.VerifyASN1(pub, digest[:], ga.Signature) {
			t.Fatal("signature does not verify against the registered public key")
		}
	}
}

func TestMakeCredentialRefusals(t *testing.T) {
	tests := []struct {
		name     string
		approver Approver
		existing bool // register example.test first and exclude it
		req      func() makeCredentialRequest
		want     byte
	}{
		{"chrome dummy registration", fakeApprover{}, false,
			func() makeCredentialRequest { return registerRequest(".dummy") }, statusUnsupportedAlgo},
		{"no ES256 offered", fakeApprover{}, false,
			func() makeCredentialRequest { return registerRequest("example.test", -257) }, statusUnsupportedAlgo},
		{"short client data hash", fakeApprover{}, false,
			func() makeCredentialRequest {
				r := registerRequest("example.test")
				r.ClientDataHash = r.ClientDataHash[:16]
				return r
			}, statusInvalidParameter},
		{"user declines", fakeApprover{decline: true}, false,
			func() makeCredentialRequest { return registerRequest("example.test") }, statusOperationDenied},
		{"prompt cannot be shown", fakeApprover{err: errors.New("no display")}, false,
			func() makeCredentialRequest { return registerRequest("example.test") }, statusOperationDenied},
		{"already registered", fakeApprover{}, true,
			func() makeCredentialRequest { return registerRequest("example.test") }, statusCredentialExcluded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &memStore{}
			req := tt.req()
			if tt.existing {
				id, _ := register(t, newTestAuthenticator(t, store, fakeApprover{}, nil), "example.test")
				req.ExcludeList = []credentialDescriptor{{Type: "public-key", ID: id}}
			}
			before := len(store.creds)
			a := newTestAuthenticator(t, store, tt.approver, nil)
			resp := a.Handle(context.Background(), command(t, ctapMakeCredential, req))
			if resp[0] != tt.want {
				t.Fatalf("status 0x%02x, want 0x%02x", resp[0], tt.want)
			}
			if len(store.creds) != before {
				t.Fatal("a refused registration was stored")
			}
		})
	}
}

func TestGetAssertionRefusals(t *testing.T) {
	tests := []struct {
		name     string
		approver Approver
		rpID     string
		want     byte
	}{
		{"unknown site", fakeApprover{}, "other.test", statusNoCredentials},
		{"user declines", fakeApprover{decline: true}, "example.test", statusOperationDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &memStore{}
			register(t, newTestAuthenticator(t, store, fakeApprover{}, nil), "example.test")
			a := newTestAuthenticator(t, store, tt.approver, nil)
			resp := a.Handle(context.Background(), command(t, ctapGetAssertion, signRequest(tt.rpID)))
			if resp[0] != tt.want {
				t.Fatalf("status 0x%02x, want 0x%02x", resp[0], tt.want)
			}
			if store.creds[0].signCount != 0 {
				t.Fatal("a refused assertion advanced the sign counter")
			}
		})
	}
}

func TestMalformedRequests(t *testing.T) {
	a := newTestAuthenticator(t, &memStore{}, fakeApprover{}, nil)
	tests := []struct {
		name    string
		payload []byte
		want    byte
	}{
		{"empty", nil, statusInvalidLength},
		{"makeCredential garbage", []byte{ctapMakeCredential, 0xff, 0x00}, statusInvalidParameter},
		{"getAssertion garbage", []byte{ctapGetAssertion, 0xa1}, statusInvalidParameter},
		{"reset is refused", []byte{ctapReset}, statusOperationDenied},
		{"clientPIN unsupported", []byte{ctapClientPIN}, statusNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if resp := a.Handle(context.Background(), tt.payload); resp[0] != tt.want {
				t.Fatalf("status 0x%02x, want 0x%02x", resp[0], tt.want)
			}
		})
	}
}

func TestUserVerificationOutcomes(t *testing.T) {
	unavailable := errors.New("sensor wedged")
	tests := []struct {
		name   string
		match  bool
		err    error
		strict bool
		want   byte
	}{
		{"finger matches", true, nil, false, statusOK},
		{"finger does not match", false, nil, false, statusOperationDenied},
		{"sensor broken, lenient", false, unavailable, false, statusOK},
		{"sensor broken, strict", false, unavailable, true, statusOperationDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uv := &fakeVerifier{match: tt.match, err: tt.err}
			a := newTestAuthenticator(t, &memStore{}, fakeApprover{}, uv, func(c *Config) { c.StrictUV = tt.strict })
			resp := a.Handle(context.Background(), command(t, ctapMakeCredential, registerRequest("example.test")))
			if resp[0] != tt.want {
				t.Fatalf("status 0x%02x, want 0x%02x", resp[0], tt.want)
			}
		})
	}
}

// A scan may be reused for the same site inside the grace window, and never
// for a different one.
func TestGraceWindowIsPerSite(t *testing.T) {
	store := &memStore{}
	setup := newTestAuthenticator(t, store, fakeApprover{}, nil)
	register(t, setup, "example.test")
	register(t, setup, "other.test")

	uv := &fakeVerifier{match: true}
	a := newTestAuthenticator(t, store, fakeApprover{}, uv, func(c *Config) { c.UVGrace = 1 << 40 })
	for _, rpID := range []string{"example.test", "example.test", "other.test"} {
		if resp := a.Handle(context.Background(), command(t, ctapGetAssertion, signRequest(rpID))); resp[0] != statusOK {
			t.Fatalf("%s: status 0x%02x", rpID, resp[0])
		}
	}
	if uv.calls != 2 {
		t.Fatalf("verifier ran %d times, want 2 (one per site)", uv.calls)
	}
}

// Fingerprint consent must not silently approve when no sensor exists.
func TestFingerprintConsentNeedsVerifier(t *testing.T) {
	a := newTestAuthenticator(t, &memStore{}, fakeApprover{decline: true}, nil, func(c *Config) { c.FingerprintConsent = true })
	resp := a.Handle(context.Background(), command(t, ctapMakeCredential, registerRequest("example.test")))
	if resp[0] != statusOperationDenied {
		t.Fatalf("status 0x%02x; consent was skipped without a sensor", resp[0])
	}
}

func TestGetInfoAdvertisesPasskeys(t *testing.T) {
	a := newTestAuthenticator(t, &memStore{}, fakeApprover{}, nil)
	resp := a.Handle(context.Background(), []byte{ctapGetInfo})
	if resp[0] != statusOK {
		t.Fatalf("status 0x%02x", resp[0])
	}
	var info authenticatorInfo
	if err := ctapDecMode.Unmarshal(resp[1:], &info); err != nil {
		t.Fatal(err)
	}
	if !info.Options["rk"] || !bytes.Equal(info.AAGUID, []byte{1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("getInfo = %+v", info)
	}
}

// A coordinate that starts with a zero byte must still encode as 32 bytes, or
// relying parties reject the key. About one key in 256 has one, so search for
// such a key instead of hoping a random one hits it.
func TestCOSEKeyKeepsLeadingZeros(t *testing.T) {
	a := newTestAuthenticator(t, &memStore{}, fakeApprover{}, nil)
	for range 10000 {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		point, err := priv.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if point[1] != 0 && point[33] != 0 {
			continue
		}
		credID := []byte("cred")
		attested, err := a.attestedCredentialData(credID, priv)
		if err != nil {
			t.Fatal(err)
		}
		var key coseKey
		if err := ctapDecMode.Unmarshal(attested[16+2+len(credID):], &key); err != nil {
			t.Fatal(err)
		}
		if len(key.X) != 32 || len(key.Y) != 32 {
			t.Fatalf("coordinates encoded as %d and %d bytes, want 32", len(key.X), len(key.Y))
		}
		if !bytes.Equal(append(append([]byte{0x04}, key.X...), key.Y...), point) {
			t.Fatal("COSE coordinates do not match the public key")
		}
		return
	}
	t.Fatal("no key with a leading zero coordinate in 10000 tries")
}

// waitingApprover blocks until the request is cancelled, like a prompt the
// user never answers.
type waitingApprover struct{}

func (waitingApprover) Confirm(ctx context.Context, _ string, _ []string) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// lateApprover approves, but only after the host has already cancelled.
type lateApprover struct{ cancel context.CancelFunc }

func (l lateApprover) Confirm(_ context.Context, _ string, choices []string) (string, error) {
	l.cancel()
	return choices[0], nil
}

// waitingVerifier blocks until the request is cancelled, like a sensor
// nobody touches, and reports the cancellation as its error.
type waitingVerifier struct{}

func (waitingVerifier) Verify(ctx context.Context, _ string) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

// A request the host cancels must end with KEEPALIVE_CANCEL and change
// nothing, wherever it was waiting.
func TestHostCancellation(t *testing.T) {
	tests := []struct {
		name     string
		cmd      byte
		approver func(cancel context.CancelFunc) Approver
		verifier UserVerifier
		strictUV bool
	}{
		{"register: approval prompt open", ctapMakeCredential,
			func(context.CancelFunc) Approver { return waitingApprover{} }, nil, false},
		{"register: approved after the host gave up", ctapMakeCredential,
			func(c context.CancelFunc) Approver { return lateApprover{c} }, nil, false},
		// The lenient fallback treats a broken sensor as approval; a cancelled
		// scan must not be mistaken for one.
		{"register: fingerprint scan, lenient", ctapMakeCredential,
			func(context.CancelFunc) Approver { return fakeApprover{} }, waitingVerifier{}, false},
		{"register: fingerprint scan, strict", ctapMakeCredential,
			func(context.CancelFunc) Approver { return fakeApprover{} }, waitingVerifier{}, true},
		{"sign in: approval prompt open", ctapGetAssertion,
			func(context.CancelFunc) Approver { return waitingApprover{} }, nil, false},
		{"sign in: fingerprint scan, lenient", ctapGetAssertion,
			func(context.CancelFunc) Approver { return fakeApprover{} }, waitingVerifier{}, false},
		{"selection prompt open", ctapSelection,
			func(context.CancelFunc) Approver { return waitingApprover{} }, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &memStore{}
			register(t, newTestAuthenticator(t, store, fakeApprover{}, nil), "example.test")
			before := len(store.creds)

			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			var uv UserVerifier
			if tt.verifier != nil {
				uv = tt.verifier
			}
			a := newTestAuthenticator(t, store, tt.approver(cancel), uv, func(c *Config) { c.StrictUV = tt.strictUV })

			var payload []byte
			switch tt.cmd {
			case ctapMakeCredential:
				req := registerRequest("example.test")
				req.User.ID = []byte("user-2") // a new account, so nothing is excluded
				payload = command(t, ctapMakeCredential, req)
			case ctapGetAssertion:
				payload = command(t, ctapGetAssertion, signRequest("example.test"))
			default:
				payload = []byte{tt.cmd}
			}

			resp := a.Handle(ctx, payload)
			if resp[0] != statusKeepaliveCancel {
				t.Fatalf("status 0x%02x, want KEEPALIVE_CANCEL", resp[0])
			}
			if len(store.creds) != before {
				t.Fatal("a cancelled registration was stored")
			}
			if store.creds[0].signCount != 0 {
				t.Fatal("a cancelled assertion advanced the sign counter")
			}
		})
	}
}

// A user who declines is still reported as a denial, not a cancellation.
func TestDeclineIsNotCancel(t *testing.T) {
	a := newTestAuthenticator(t, &memStore{}, fakeApprover{decline: true}, nil)
	if resp := a.Handle(context.Background(), command(t, ctapMakeCredential, registerRequest("example.test"))); resp[0] != statusOperationDenied {
		t.Fatalf("status 0x%02x, want OPERATION_DENIED", resp[0])
	}
}
