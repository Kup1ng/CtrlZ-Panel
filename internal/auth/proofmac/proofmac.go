// Package proofmac tags the bearer values that a person holds between two steps of a sign-in: a ticket (mfa, reset,
// passkey), an OTP challenge id and a refresh token (P1 auth review round 19, tenant-r19-1; D64 nat-proof-tag).
//
// Why a tag. Only a database read can tell a real ticket from junk, so these requests used to be charged to the
// client's /24, the same bucket strangers use. In Iran thousands of subscribers share one /24: one noisy neighbour
// made every honest user holding a ticket answer 429, across tenants. A value with a keyed tag that the server can
// check in process (one HMAC, no I/O) is a proof of something the server issued, so the request is charged to the
// account the value names and not to the network, exactly as the session cookie is (internal/auth/session/tag.go).
//
// The layout is the session token's: a body of the subject (16 bytes), 20 bytes of reference and the expiry (4
// bytes, Unix seconds), and an 8 byte tag, 48 bytes, 64 base64url characters with no spare bits, so a value has one
// spelling, one hash and one budget. The tag covers a kind byte as well as the body, so a ticket is no refresh token
// and no challenge id, under one label of auth_mac (keyring.LabelProof).
//
// The tag is a filter and never the credential. A forged value still has to be a stored 160 bit value (a ticket, a
// refresh token) or a live challenge row, and the database stays the authority: the subject and the expiry are only
// read to charge sooner or to refuse sooner, never to accept. Because the tag names the subject and the expiry, a
// holder cannot collect dead values to buy database reads with no network charge: every use is charged to the
// subject's own bucket, and a value past its expiry is refused here for the price of one MAC.
package proofmac

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Kind is what a value is for. It is part of what the tag covers.
type Kind byte

// The kinds.
const (
	Ticket    Kind = 't'
	Refresh   Kind = 'r'
	Challenge Kind = 'c'
)

const (
	subjectLen = 16
	// RefLen is the reference part: 20 random bytes for a ticket and a refresh token, a challenge id and four zero
	// bytes for an OTP challenge.
	RefLen  = 20
	expLen  = 4
	bodyLen = subjectLen + RefLen + expLen
	tagLen  = 8
	// Len is the length of a tagged value in characters.
	Len = (bodyLen + tagLen) * 4 / 3
)

// ErrNoKeys is returned by New for a ring that cannot tag under the proof label.
var ErrNoKeys = errors.New("proofmac: the key ring lacks auth_mac or the proof label")

// ErrNoSubject is returned when a value is asked for with no subject: the tag would then name nobody.
var ErrNoSubject = errors.New("proofmac: a tagged value needs a subject")

// ErrBadRef is a reference that is not RefLen bytes.
var ErrBadRef = errors.New("proofmac: a reference is RefLen bytes")

// Signer makes and opens tagged values.
type Signer struct {
	ring *keyring.Ring
	now  func() time.Time
}

// New returns a Signer over the ring. The ring must hold auth_mac with the proof label listed.
func New(ring *keyring.Ring, now func() time.Time) (*Signer, error) {
	if ring == nil || !ring.Has(keyring.DomainAuthMAC) || !keyring.PairListed(keyring.DomainAuthMAC, keyring.LabelProof) {
		return nil, ErrNoKeys
	}
	if now == nil {
		now = appclock.Now
	}
	return &Signer{ring: ring, now: now}, nil
}

// Body is what a tagged value says once its tag and expiry check.
type Body struct {
	Subject uuid.UUID
	Ref     []byte // RefLen bytes; a slice, because a crash prints the words of an array passed by value (internal/lint TestNoFunctionTakesAnArrayByValue)
	Expires time.Time
}

// ProofID is the id the `p` bucket of a rate class charges the value to: the value itself, never the account it names.
// A ticket and a refresh token are bearer values, and a stranger who holds one (a password-only login holds a ticket
// for the owner's account; a leaked cookie is a refresh token) must spend only what his own value is worth. With one
// bucket for the account he could send twenty requests a minute with a value he holds and refuse every other ticket and
// the refresh cookie of the owner from any network (P1 auth review round 19, tenant-r19-6; rule budget-keying). The id
// is a hash of the reference, so the key, which lives in Valkey, holds no part of the credential. What a holder who
// gathers many values can spend is the proof-network bucket (SubjectKey), which is per network and account. A challenge
// is charged to its own id, and its subject is a phone's hash, which anybody can ask a challenge for.
func (b *Body) ProofID(k Kind) string {
	if k == Challenge {
		id, _ := uuid.FromBytes(b.Ref[:16])
		return "c:" + id.String()
	}
	h := sha256.Sum256(append([]byte{byte(k)}, b.Ref...))
	return string(rune(k)) + ":" + hex.EncodeToString(h[:16])
}

// SubjectKey is the account (or, for a challenge, the phone's hash) the proof-network bucket is keyed with: a source
// that rotates values of ONE subject meets its ceiling, and the other accounts of its address group keep theirs.
// A user id and a phone's hash can never meet, whatever the bytes are.
func (b *Body) SubjectKey(k Kind) string {
	if k == Challenge {
		return "s:" + b.Subject.String()
	}
	return "u:" + b.Subject.String()
}

// RandomRef returns 20 random bytes for a ticket or a refresh token.
func RandomRef() ([]byte, error) {
	ref := make([]byte, RefLen)
	_, err := rand.Read(ref)
	return ref, err
}

// Mint makes a tagged value. The expiry is saturated to what four bytes can say.
func (s *Signer) Mint(k Kind, subject uuid.UUID, ref []byte, expires time.Time) (secret.String, error) {
	if subject == uuid.Nil {
		return secret.String{}, ErrNoSubject
	}
	if len(ref) != RefLen {
		return secret.String{}, ErrBadRef
	}
	var raw [bodyLen + tagLen]byte
	copy(raw[:subjectLen], subject[:])
	copy(raw[subjectLen:subjectLen+RefLen], ref)
	binary.BigEndian.PutUint32(raw[subjectLen+RefLen:bodyLen], expiryOf(expires))
	copy(raw[bodyLen:], s.ring.MAC(keyring.DomainAuthMAC, keyring.LabelProof, []byte{byte(k)}, raw[:bodyLen])[:tagLen])
	return secret.New(base64.RawURLEncoding.EncodeToString(raw[:])), nil
}

func expiryOf(t time.Time) uint32 {
	u := t.Unix()
	switch {
	case u < 0:
		return 0
	case u > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(u)
}

// Open checks the shape, the tag and the expiry of a value of kind k, with no I/O. ok is false for anything that is
// not a value this service issued under that kind, or one past its expiry.
func (s *Signer) Open(k Kind, text string) (Body, bool) {
	if len(text) != Len {
		return Body{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) != bodyLen+tagLen ||
		!s.ring.VerifyMAC(keyring.DomainAuthMAC, keyring.LabelProof, raw[bodyLen:], []byte{byte(k)}, raw[:bodyLen]) {
		return Body{}, false
	}
	exp := binary.BigEndian.Uint32(raw[subjectLen+RefLen : bodyLen])
	if s.now().Unix() > int64(exp) {
		return Body{}, false
	}
	var b Body
	copy(b.Subject[:], raw[:subjectLen])
	if b.Subject == uuid.Nil {
		return Body{}, false
	}
	b.Ref = append([]byte(nil), raw[subjectLen:subjectLen+RefLen]...)
	b.Expires = time.Unix(int64(exp), 0)
	return b, true
}

// PhoneSubject is the subject of an OTP challenge: a keyed hash of the phone, so a decoy challenge (a phone with no
// account) carries one exactly like a real one and the tag tells a stranger nothing about the account. It is not a
// user id and is namespaced apart from one by Body.Key.
func (s *Signer) PhoneSubject(phone string) uuid.UUID {
	var u uuid.UUID
	copy(u[:], s.ring.MAC(keyring.DomainAuthMAC, keyring.LabelProof, []byte{'p'}, []byte(phone)))
	return u
}
