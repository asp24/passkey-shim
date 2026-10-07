package ctap

// CTAP2 request and response shapes. CTAP2 uses integer map keys throughout,
// hence keyasint on every field. Nested entity maps (rp, user, credential
// descriptors) use string keys instead, which is why they look different.

import "github.com/fxamacker/cbor/v2"

const (
	ctapMakeCredential = 0x01
	ctapGetAssertion   = 0x02
	ctapGetInfo        = 0x04
	ctapClientPIN      = 0x06
	ctapReset          = 0x07
	ctapGetNextAssert  = 0x08
	ctapSelection      = 0x0B

	// Status codes we actually return.
	statusOK                 = 0x00
	statusInvalidParameter   = 0x02
	statusInvalidLength      = 0x03
	statusCredentialExcluded = 0x19
	statusUnsupportedAlgo    = 0x26
	statusOperationDenied    = 0x27
	statusNoCredentials      = 0x2E
	statusUserActionTimeout  = 0x2F
	statusNotAllowed         = 0x30
	statusUnsupportedOption  = 0x2B
	statusOther              = 0x7F

	// authData flag bits.
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttestedData = 0x40

	algES256 = -7
)

// RPEntity is the relying party a credential belongs to.
type RPEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

// UserEntity is the account a credential belongs to. ID is an opaque handle.
type UserEntity struct {
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
	ClientDataHash   []byte                 `cbor:"1,keyasint"`
	RP               RPEntity               `cbor:"2,keyasint"`
	User             UserEntity             `cbor:"3,keyasint"`
	PubKeyCredParams []pubKeyCredParam      `cbor:"4,keyasint"`
	ExcludeList      []credentialDescriptor `cbor:"5,keyasint,omitempty"`
	Extensions       map[string]any         `cbor:"6,keyasint,omitempty"`
	Options          map[string]bool        `cbor:"7,keyasint,omitempty"`
	PinUvAuthParam   []byte                 `cbor:"8,keyasint,omitempty"`
	PinUvAuthProto   uint                   `cbor:"9,keyasint,omitempty"`
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
	Extensions     map[string]any         `cbor:"4,keyasint,omitempty"`
	Options        map[string]bool        `cbor:"5,keyasint,omitempty"`
	PinUvAuthParam []byte                 `cbor:"6,keyasint,omitempty"`
	PinUvAuthProto uint                   `cbor:"7,keyasint,omitempty"`
}

type getAssertionResponse struct {
	Credential          credentialDescriptor `cbor:"1,keyasint"`
	AuthData            []byte               `cbor:"2,keyasint"`
	Signature           []byte               `cbor:"3,keyasint"`
	User                *UserEntity          `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials int                  `cbor:"5,keyasint,omitempty"`
}

// coseKey is an ES256 public key in COSE_Key form. Under CTAP2 canonical
// ordering the encoded keys sort 0x01,0x03,0x20,0x21,0x22, which is the
// 1,3,-1,-2,-3 order relying parties expect.
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

// ctapEncMode is the canonical CTAP2 encoder. Relying parties verify
// signatures over bytes we produce here, so the ordering rules are not
// cosmetic: a non-canonical map breaks signature verification.
var ctapEncMode cbor.EncMode

// ctapDecMode is deliberately strict about duplicate map keys, which are a
// classic way to smuggle a second value past a parser.
var ctapDecMode cbor.DecMode

func init() {
	var err error
	ctapEncMode, err = cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	opts := cbor.DecOptions{
		DupMapKey:       cbor.DupMapKeyEnforcedAPF,
		IndefLength:     cbor.IndefLengthForbidden,
		MaxNestedLevels: 16,
		UTF8:            cbor.UTF8RejectInvalid,
	}
	ctapDecMode, err = opts.DecMode()
	if err != nil {
		panic(err)
	}
}
