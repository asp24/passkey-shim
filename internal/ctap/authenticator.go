// Package ctap implements the CTAP2 authenticator: the command handlers that
// turn a decoded request into a signed credential or assertion, and the
// consent and user verification that guard them.
package ctap

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"go.uber.org/zap"
)

// Credential is a stored passkey as the authenticator needs it.
type Credential struct {
	ID          []byte
	UserID      []byte
	UserName    string
	UserDisplay string
	PrivateKey  []byte // PKCS#8
}

// Store holds the passkeys. Every mutating method persists before returning.
type Store interface {
	// HasCredentialFor reports whether any of the excluded IDs belongs to rpID.
	HasCredentialFor(rpID string, exclude [][]byte) bool
	// AddCredential mints and stores a P-256 key for the account, replacing
	// any earlier credential for the same rp and user.
	AddCredential(rp RPEntity, user UserEntity) (id []byte, priv *ecdsa.PrivateKey, err error)
	// FindForRP returns the credentials for rpID, newest first, restricted to
	// allow when it is not empty.
	FindForRP(rpID string, allow [][]byte) []Credential
	// BumpSignCount increments and returns the credential's counter.
	BumpSignCount(id []byte) (uint32, error)
}

// Approver asks the user to pick one of several choices.
type Approver interface {
	// Confirm blocks until the user decides or ctx is done. An empty choice
	// denies the operation; an error means we could not ask at all, which
	// also denies. The prompt must be gone from the screen when it returns.
	Confirm(ctx context.Context, title string, choices []string) (string, error)
}

// UserVerifier is the biometric check. Verify returns false on a genuine
// non-match and an error when the check could not run at all, including when
// ctx was cancelled first.
type UserVerifier interface {
	Verify(ctx context.Context, reason string) (bool, error)
}

// Notifier tells the user what just happened.
type Notifier interface {
	Notify(summary, body string)
}

// Config wires an Authenticator to its dependencies.
type Config struct {
	Store    Store
	Approver Approver
	// Verifier is nil when biometric user verification is off.
	Verifier UserVerifier
	Notifier Notifier
	// StrictUV denies when the sensor is unusable instead of falling back to
	// the approval the user already gave.
	StrictUV bool
	// FingerprintConsent drops the click-to-approve menu and treats the
	// fingerprint touch as both consent and verification, the way Touch ID
	// and Windows Hello do. The notification names the site before the scan,
	// so the user still sees what they are approving.
	FingerprintConsent bool
	// UVGrace lets a second request for the SAME site reuse a scan that just
	// succeeded. Clients routinely fire two getAssertion calls milliseconds
	// apart, and asking for two touches to sign in once reads as a bug.
	UVGrace time.Duration
	// AAGUID identifies the authenticator model.
	AAGUID [16]byte
}

// Authenticator handles CTAP2 commands. Handle is safe to call from several
// goroutines.
type Authenticator struct {
	store              Store
	approver           Approver
	verifier           UserVerifier
	notifier           Notifier
	strictUV           bool
	fingerprintConsent bool
	uvGrace            time.Duration
	aaguid             [16]byte
	log                *zap.Logger

	graceMu   sync.Mutex
	graceRP   string
	graceTime time.Time
}

// New builds an Authenticator from cfg. Store, Approver and Notifier are
// required. log records every decision; nil discards it.
func New(log *zap.Logger, cfg Config) *Authenticator {
	if log == nil {
		log = zap.NewNop()
	}
	return &Authenticator{
		store:              cfg.Store,
		approver:           cfg.Approver,
		verifier:           cfg.Verifier,
		notifier:           cfg.Notifier,
		strictUV:           cfg.StrictUV,
		fingerprintConsent: cfg.FingerprintConsent,
		uvGrace:            cfg.UVGrace,
		aaguid:             cfg.AAGUID,
		log:                log,
	}
}

// recentlyVerified reports whether a successful scan for this exact site is
// still inside the grace window. Scoping it to one site matters: a scan for
// one login must never authorise a different one.
func (a *Authenticator) recentlyVerified(rpID string) bool {
	if a.uvGrace <= 0 {
		return false
	}
	a.graceMu.Lock()
	defer a.graceMu.Unlock()
	return a.graceRP == rpID && time.Since(a.graceTime) < a.uvGrace
}

func (a *Authenticator) markVerified(rpID string) {
	a.graceMu.Lock()
	defer a.graceMu.Unlock()
	a.graceRP, a.graceTime = rpID, time.Now()
}

// consentIsFingerprint reports whether the touch alone stands in for the menu.
// It is only safe when a sensor is actually available: with no verifier there
// would be no user interaction at all, and a page could mint passkeys in
// silence.
func (a *Authenticator) consentIsFingerprint() bool {
	return a.fingerprintConsent && a.verifier != nil
}

// denied is the status for a refused operation: KEEPALIVE_CANCEL when the
// host cancelled the request while we waited, OPERATION_DENIED otherwise.
func denied(ctx context.Context) []byte {
	if ctx.Err() != nil {
		return []byte{statusKeepaliveCancel}
	}
	return []byte{statusOperationDenied}
}

// requestConsent asks the user to approve an operation, returning false if they
// declined, could not be asked, or the host cancelled. With fingerprint
// consent the touch is the whole interaction; otherwise the menu runs first
// and the touch confirms it.
func (a *Authenticator) requestConsent(ctx context.Context, rpID, title, affirmative, reason string) bool {
	if a.consentIsFingerprint() {
		return a.verifyUserFor(ctx, rpID, reason)
	}
	choice, err := a.approver.Confirm(ctx, title, []string{affirmative, "Cancel"})
	if ctx.Err() != nil {
		a.log.Info("cancelled by the host while asking for approval", zap.String("reason", reason))
		return false
	}
	if err != nil {
		a.log.Warn("could not ask for approval", zap.String("reason", reason), zap.Error(err))
		return false
	}
	if choice != affirmative {
		a.log.Info("declined by user", zap.String("reason", reason))
		return false
	}
	return a.verifyUserFor(ctx, rpID, reason)
}

// verifyUserFor is the biometric half of user verification. Consent (the
// menu) has already happened by the time this runs. Naming a site lets a scan
// for it be reused within the grace window.
//
// A sensor that cannot be used is treated differently from a finger that does
// not match. A non-match denies, always. A hardware failure falls back to the
// approval the user just gave, because this laptop's fingerprint reader is
// known to wedge after suspend, and a vault that locks you out of every
// account until you reboot is a worse outcome than one that leans on the
// prompt you already answered. Run with --uv-strict to invert that.
//
// A cancelled request is never mistaken for a broken sensor: the lenient
// fallback would otherwise approve a request the host already abandoned.
func (a *Authenticator) verifyUserFor(ctx context.Context, rpID, reason string) bool {
	if ctx.Err() != nil {
		return false
	}
	if a.verifier == nil {
		return true
	}
	if rpID != "" && a.recentlyVerified(rpID) {
		a.log.Info("reusing the scan from moments ago", zap.String("rp", rpID))
		return true
	}
	ok, err := a.verifier.Verify(ctx, reason)
	if ctx.Err() != nil {
		a.log.Info("cancelled by the host during the fingerprint scan", zap.String("reason", reason))
		return false
	}
	if err != nil {
		if a.strictUV {
			a.log.Warn("fingerprint unavailable; denying because strict verification is on", zap.Error(err))
			a.notifier.Notify("Fingerprint unavailable", "Request denied")
			return false
		}
		a.log.Warn("fingerprint unavailable; accepting the desktop approval alone", zap.Error(err))
		a.notifier.Notify("Fingerprint unavailable", "Approved on the desktop prompt alone")
		return true
	}
	if !ok {
		a.log.Info("fingerprint did not match", zap.String("reason", reason))
		a.notifier.Notify("Fingerprint did not match", reason)
		return false
	}
	if rpID != "" {
		a.markVerified(rpID)
	}
	return true
}

// Handle decodes one CTAP2 message and returns the raw response, status byte
// first. Every error path returns a CTAP status rather than a Go error,
// because the transport has no other way to report failure. Cancelling ctx
// closes any prompt and answers KEEPALIVE_CANCEL.
func (a *Authenticator) Handle(ctx context.Context, payload []byte) []byte {
	if len(payload) == 0 {
		return []byte{statusInvalidLength}
	}
	cmd, body := payload[0], payload[1:]

	switch cmd {
	case ctapGetInfo:
		return a.getInfo()
	case ctapMakeCredential:
		return a.makeCredential(ctx, body)
	case ctapGetAssertion:
		return a.getAssertion(ctx, body)
	case ctapSelection:
		// Used by browsers to ask "is this the key the user wants to use?".
		return a.selection(ctx)
	case ctapReset:
		// Wiping every passkey on an unauthenticated USB command is not a
		// trade we want, so this stays refused.
		a.log.Warn("refusing authenticatorReset")
		return []byte{statusOperationDenied}
	default:
		a.log.Info("unimplemented CTAP2 command", zap.Uint8("command", cmd))
		return []byte{statusNotAllowed}
	}
}

func (a *Authenticator) getInfo() []byte {
	info := authenticatorInfo{
		Versions: []string{"FIDO_2_0"},
		AAGUID:   a.aaguid[:],
		Options: map[string]bool{
			"rk":   true,  // discoverable credentials, which is what a passkey is
			"up":   true,  // we can test user presence
			"uv":   true,  // and user verification, via the desktop prompt
			"plat": false, // we present as a removable key, not a platform one
		},
		MaxMsgSize: 1200,
	}
	body, err := ctapEncMode.Marshal(info)
	if err != nil {
		a.log.Error("getInfo: encode failed", zap.Error(err))
		return []byte{statusOther}
	}
	return append([]byte{statusOK}, body...)
}

func (a *Authenticator) selection(ctx context.Context) []byte {
	choice, err := a.approver.Confirm(ctx, "Use Llavero for this site?", []string{"Use it", "Cancel"})
	if err != nil || choice != "Use it" {
		return denied(ctx)
	}
	return []byte{statusOK}
}

func (a *Authenticator) makeCredential(ctx context.Context, body []byte) []byte {
	var req makeCredentialRequest
	if err := ctapDecMode.Unmarshal(body, &req); err != nil {
		a.log.Info("makeCredential: malformed request", zap.Error(err))
		return []byte{statusInvalidParameter}
	}
	if req.RP.ID == "" || len(req.ClientDataHash) != 32 {
		return []byte{statusInvalidParameter}
	}

	// Chrome sends a throwaway registration for the RP ID ".dummy" to force a
	// user gesture without disclosing which credentials we hold. A real
	// authenticator is expected to fail it. Storing it would leave junk in the
	// vault and, worse, cost a fingerprint scan every time a site triggers one.
	// An RP ID is a domain, so a leading or trailing dot can never be a real
	// origin and is safe to refuse outright.
	if !isPlausibleRPID(req.RP.ID) {
		a.log.Info("makeCredential: refusing throwaway registration", zap.String("rp", req.RP.ID))
		return []byte{statusUnsupportedAlgo}
	}

	// We only speak ES256. Refusing early gives the browser a clean error
	// instead of a credential it cannot verify.
	if !supportsES256(req.PubKeyCredParams) {
		a.log.Info("makeCredential: relying party did not offer ES256", zap.String("rp", req.RP.ID))
		return []byte{statusUnsupportedAlgo}
	}

	// excludeList is how an RP says "this user already has a key here". The
	// spec wants user presence before we admit it, but a desktop prompt for a
	// duplicate registration is noise, so we answer directly.
	if a.store.HasCredentialFor(req.RP.ID, descriptorIDs(req.ExcludeList)) {
		a.log.Info("makeCredential: a credential in the exclude list already exists", zap.String("rp", req.RP.ID))
		return []byte{statusCredentialExcluded}
	}

	label := displayName(req.User)
	title := fmt.Sprintf("Create a passkey for %s?", req.RP.ID)
	if label != "" {
		title = fmt.Sprintf("Create a passkey for %s as %s?", req.RP.ID, label)
	}
	reason := fmt.Sprintf("Create a passkey for %s", req.RP.ID)
	if label != "" {
		reason = fmt.Sprintf("Create a passkey for %s as %s", req.RP.ID, label)
	}
	if !a.requestConsent(ctx, req.RP.ID, title, "Create passkey", reason) {
		return denied(ctx)
	}
	// The host may have given up while the user was approving. Storing the
	// key then would leave a passkey the relying party never received.
	if ctx.Err() != nil {
		return denied(ctx)
	}

	credID, priv, err := a.store.AddCredential(req.RP, req.User)
	if err != nil {
		a.log.Error("makeCredential: storing the credential failed", zap.String("rp", req.RP.ID), zap.Error(err))
		return []byte{statusOther}
	}

	attested, err := a.attestedCredentialData(credID, priv)
	if err != nil {
		a.log.Error("makeCredential: encoding the public key failed", zap.Error(err))
		return []byte{statusOther}
	}

	// UV is set because the user just approved interactively against a vault
	// they unlocked with a passphrase at startup.
	flags := byte(flagUserPresent | flagUserVerified | flagAttestedData)
	authData := buildAuthData(req.RP.ID, flags, 0, attested)

	resp := makeCredentialResponse{
		Fmt:      "none", // self-attestation buys nothing for a software key
		AuthData: authData,
		AttStmt:  map[string]any{},
	}
	out, err := ctapEncMode.Marshal(resp)
	if err != nil {
		a.log.Error("makeCredential: encode failed", zap.Error(err))
		return []byte{statusOther}
	}

	a.log.Info("registered passkey", zap.String("rp", req.RP.ID), zap.String("account", label),
		zap.String("credential", hex.EncodeToString(credID[:8])))
	a.notifier.Notify("Passkey created", fmt.Sprintf("%s (%s)", req.RP.ID, label))
	return append([]byte{statusOK}, out...)
}

func (a *Authenticator) getAssertion(ctx context.Context, body []byte) []byte {
	var req getAssertionRequest
	if err := ctapDecMode.Unmarshal(body, &req); err != nil {
		a.log.Info("getAssertion: malformed request", zap.Error(err))
		return []byte{statusInvalidParameter}
	}
	if req.RPID == "" || len(req.ClientDataHash) != 32 {
		return []byte{statusInvalidParameter}
	}

	matches := a.store.FindForRP(req.RPID, descriptorIDs(req.AllowList))
	if len(matches) == 0 {
		a.log.Info("getAssertion: no credential for this site", zap.String("rp", req.RPID))
		return []byte{statusNoCredentials}
	}

	// With several accounts at one site, let the user pick rather than
	// silently choosing for them.
	chosen := matches[0]
	if len(matches) > 1 {
		labels := make([]string, 0, len(matches))
		for _, c := range matches {
			labels = append(labels, displayName(UserEntity{
				Name: c.UserName, DisplayName: c.UserDisplay,
			}))
		}
		choice, err := a.approver.Confirm(ctx,
			fmt.Sprintf("Sign in to %s as:", req.RPID), labels)
		if err != nil || choice == "" {
			a.log.Info("getAssertion: account choice declined or timed out", zap.String("rp", req.RPID), zap.Error(err))
			return denied(ctx)
		}
		idx := indexOf(labels, choice)
		if idx < 0 {
			return denied(ctx)
		}
		chosen = matches[idx]
		// Choosing an account is itself the consent, so only verification is
		// left to do.
		if !a.verifyUserFor(ctx, req.RPID, fmt.Sprintf("Sign in to %s as %s", req.RPID, labels[idx])) {
			return denied(ctx)
		}
	} else {
		label := displayName(UserEntity{Name: chosen.UserName, DisplayName: chosen.UserDisplay})
		title := fmt.Sprintf("Sign in to %s?", req.RPID)
		if label != "" {
			title = fmt.Sprintf("Sign in to %s as %s?", req.RPID, label)
		}
		reason := fmt.Sprintf("Sign in to %s", req.RPID)
		if label != "" {
			reason = fmt.Sprintf("Sign in to %s as %s", req.RPID, label)
		}
		if !a.requestConsent(ctx, req.RPID, title, "Sign in", reason) {
			return denied(ctx)
		}
	}

	priv, err := parsePrivateKey(chosen.PrivateKey)
	if err != nil {
		a.log.Error("getAssertion: stored key unusable", zap.String("rp", req.RPID), zap.Error(err))
		return []byte{statusOther}
	}

	count, err := a.store.BumpSignCount(chosen.ID)
	if err != nil {
		a.log.Error("getAssertion: could not persist the sign count", zap.String("rp", req.RPID), zap.Error(err))
		return []byte{statusOther}
	}

	authData := buildAuthData(req.RPID, flagUserPresent|flagUserVerified, count, nil)

	// The signature covers authData concatenated with the client data hash.
	// Getting this concatenation wrong is the single most common way an
	// authenticator produces assertions no RP will accept.
	signed := append(append([]byte{}, authData...), req.ClientDataHash...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		a.log.Error("getAssertion: signing failed", zap.Error(err))
		return []byte{statusOther}
	}

	resp := getAssertionResponse{
		Credential: credentialDescriptor{Type: "public-key", ID: chosen.ID},
		AuthData:   authData,
		Signature:  sig,
		User: &UserEntity{
			ID:          chosen.UserID,
			Name:        chosen.UserName,
			DisplayName: chosen.UserDisplay,
		},
	}
	out, err := ctapEncMode.Marshal(resp)
	if err != nil {
		a.log.Error("getAssertion: encode failed", zap.Error(err))
		return []byte{statusOther}
	}

	a.log.Info("signed assertion", zap.String("rp", req.RPID), zap.String("account", chosen.UserName),
		zap.Uint32("sign_count", count))
	return append([]byte{statusOK}, out...)
}

// attestedCredentialData builds the attestation block embedded in authData at
// registration: aaguid, credential id, then the COSE public key.
func (a *Authenticator) attestedCredentialData(credID []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	// The uncompressed SEC 1 point is 0x04 || X || Y with each coordinate
	// fixed at 32 bytes, which is exactly what COSE wants. A coordinate with
	// leading zero bytes must not encode short, or the RP rejects the key.
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	key := coseKey{
		Kty: 2, // EC2
		Alg: algES256,
		Crv: 1, // P-256
		X:   point[1:33],
		Y:   point[33:65],
	}
	coseBytes, err := ctapEncMode.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("encoding COSE key: %w", err)
	}

	out := make([]byte, 0, 16+2+len(credID)+len(coseBytes))
	out = append(out, a.aaguid[:]...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(credID)))
	out = append(out, l[:]...)
	out = append(out, credID...)
	out = append(out, coseBytes...)
	return out, nil
}

func buildAuthData(rpID string, flags byte, signCount uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37+len(attested))
	out = append(out, h[:]...)
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], signCount)
	out = append(out, c[:]...)
	out = append(out, attested...)
	return out
}

// isPlausibleRPID rejects RP IDs that cannot correspond to a real origin.
// This is not a validation of the RP ID against the caller's origin, which is
// the browser's job; it only screens out client sentinels like ".dummy".
func isPlausibleRPID(id string) bool {
	if id == "" || strings.HasPrefix(id, ".") || strings.HasSuffix(id, ".") {
		return false
	}
	if strings.Contains(id, "..") || strings.ContainsAny(id, " /\\:") {
		return false
	}
	return true
}

func supportsES256(params []pubKeyCredParam) bool {
	for _, p := range params {
		if p.Type == "public-key" && p.Alg == algES256 {
			return true
		}
	}
	return false
}

// displayName picks the friendliest label for an account. The user handle is
// opaque binary per spec, so it is only used as a last resort and only when it
// happens to be printable, rather than spraying control bytes into a menu.
func displayName(u UserEntity) string {
	if u.Name != "" {
		return u.Name
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if s := strings.TrimSpace(string(u.ID)); s != "" && isPrintable(s) {
		return s
	}
	return "this account"
}

func isPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// descriptorIDs extracts the credential IDs from an allow or exclude list.
func descriptorIDs(list []credentialDescriptor) [][]byte {
	ids := make([][]byte, 0, len(list))
	for _, d := range list {
		ids = append(ids, d.ID)
	}
	return ids
}

func parsePrivateKey(pkcs8 []byte) (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#8 key: %w", err)
	}
	priv, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("stored key is not ECDSA")
	}
	return priv, nil
}

func indexOf(hay []string, needle string) int {
	for i, s := range hay {
		if s == needle {
			return i
		}
	}
	return -1
}
