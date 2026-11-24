// Package passkeytest is a software WebAuthn authenticator for tests (spec 7.5,
// "tested with a virtual authenticator at panel.localhost"). It builds the
// same JSON a browser sends after navigator.credentials.create and .get, from
// the options the server returned, with the knobs a test needs to break a
// ceremony on purpose: user verification off, another RP ID or origin, a counter
// that does not advance.
//
// It is imported from test files only. It uses ES256 and the "none"
// attestation format, which is what the server asks for.
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// Authenticator is one virtual passkey.
type Authenticator struct {
	Key        *ecdsa.PrivateKey
	CredID     []byte
	UserHandle []byte

	// Origin and RPID are what the authenticator signs for. A test changes one to
	// simulate a phishing page or another relying party.
	Origin, RPID string

	// Flags written into authenticator data. UV is on by default, as it is for
	// every real platform authenticator the server accepts.
	UV, BackupEligible, BackupState bool

	// SignCount is the counter of the last assertion. A test sets Frozen to keep
	// it where it is (a synced passkey reports 0 forever, a clone does not
	// advance).
	SignCount uint32
	Frozen    bool

	// Transports is what Create reports; nil means ["internal"]. The list is not
	// part of the signed attestation, so a client can send anything (tenant-r3-6).
	Transports []string
}

// New makes an authenticator for an origin and RP ID.
func New(origin, rpID string) *Authenticator {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("passkeytest: " + err.Error())
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &Authenticator{Key: k, CredID: id, Origin: origin, RPID: rpID, UV: true}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}

// options is the part of the server's options the authenticator reads.
type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func parse(optionsJSON []byte) (options, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil || o.PublicKey.Challenge == "" {
		return o, errors.New("passkeytest: unreadable options")
	}
	return o, nil
}

func (a *Authenticator) flags(attested bool) byte {
	f := byte(0x01) // user present
	if a.UV {
		f |= 0x04
	}
	if a.BackupEligible {
		f |= 0x08
	}
	if a.BackupState {
		f |= 0x10
	}
	if attested {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.Origin, "crossOrigin": false})
	return b
}

type coseKey struct {
	Kty int64  `cbor:"1,keyasint"`
	Alg int64  `cbor:"3,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

// Create answers a registration ceremony: the JSON body of POST
// /account/passkeys/finish.
func (a *Authenticator) Create(optionsJSON []byte) ([]byte, error) {
	o, err := parse(optionsJSON)
	if err != nil {
		return nil, err
	}
	a.UserHandle = unb64(o.PublicKey.User.ID)
	pub, err := a.Key.PublicKey.ECDH()
	if err != nil {
		return nil, err
	}
	raw := pub.Bytes() // 0x04 || X || Y
	key, err := cbor.Marshal(coseKey{Kty: 2, Alg: -7, Crv: 1, X: raw[1:33], Y: raw[33:65]})
	if err != nil {
		return nil, err
	}
	rp := sha256.Sum256([]byte(a.RPID))
	auth := append([]byte{}, rp[:]...)
	auth = append(auth, a.flags(true))
	auth = binary.BigEndian.AppendUint32(auth, 0)
	auth = append(auth, make([]byte, 16)...) // AAGUID, zero: no attestation
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(a.CredID)))
	auth = append(auth, a.CredID...)
	auth = append(auth, key...)
	obj, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		return nil, err
	}
	transports := a.Transports
	if transports == nil {
		transports = []string{"internal"}
	}
	return json.Marshal(map[string]any{
		"id": b64(a.CredID), "rawId": b64(a.CredID), "type": "public-key", "authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON": b64(a.clientData("webauthn.create", o.PublicKey.Challenge)), "attestationObject": b64(obj),
			"transports": transports,
		},
		"clientExtensionResults": map[string]any{},
	})
}

// Get answers an assertion ceremony: the JSON body of the finish routes. The
// user handle is always included, as a discoverable credential does.
func (a *Authenticator) Get(optionsJSON []byte) ([]byte, error) {
	o, err := parse(optionsJSON)
	if err != nil {
		return nil, err
	}
	if !a.Frozen {
		a.SignCount++
	}
	rp := sha256.Sum256([]byte(a.RPID))
	auth := append([]byte{}, rp[:]...)
	auth = append(auth, a.flags(false))
	auth = binary.BigEndian.AppendUint32(auth, a.SignCount)
	cd := a.clientData("webauthn.get", o.PublicKey.Challenge)
	cdh := sha256.Sum256(cd)
	sum := sha256.Sum256(append(append([]byte{}, auth...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, sum[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64(a.CredID), "rawId": b64(a.CredID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON": b64(cd), "authenticatorData": b64(auth), "signature": b64(sig), "userHandle": b64(a.UserHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
}
