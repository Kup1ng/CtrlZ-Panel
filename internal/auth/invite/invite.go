// Package invite makes and opens invite links (spec 11.3, D67).
//
// An invite is never sent by SMS: the admin copies the link and gives it to whomever they choose. That
// removed the 25 character limit that kept the old code short, so the token is signed with Ed25519 (D64's
// tag for invites). The private key lives in the admin process only. The api holds the public key, and
// Open decides in process, before any throttle row or database read, whether a token is one the admin made.
// Fake and expired tokens therefore cost the database nothing.
//
// Layout of the 105 bytes, written as 140 base64url characters with no spare bit, so a token has exactly
// one spelling:
//
//	version 1 | key number 2 | invite id 16 | expiry 4 (Unix seconds) | random 18 | signature 64
//
// The signature covers "ctrlz/invite-link/v1" 0x00 and the first 41 bytes. The database stores only SHA-256
// of the 140 characters, so a stolen backup holds no usable link, and a leaked key without the database opens
// nothing because the row is still the final authority (used, revoked, expired, or missing is the same 404).
package invite

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

const (
	version   = 0x01
	randBytes = 18
	bodyLen   = 1 + 2 + 16 + 4 + randBytes // 41
	sigLen    = 64
	rawLen    = bodyLen + sigLen // 105
	// TokenChars is the length of a token: 105 bytes is exactly 140 base64url characters.
	TokenChars = 140
	// maxRawBytes is the schema's 200 characters at four bytes each. The fold (NFKC) can expand one code point
	// into eighteen, so the bound is applied to the raw text before it, and a longer text is refused and never cut.
	maxRawBytes = 4 * 200
	domainTag   = "ctrlz/invite-link/v1"
)

// Errors never repeat the input.
var (
	ErrMint = errors.New("invite: cannot make a link")
)

// Ref is what a token that opened names. It is a claim of the signer, not the state of the invite: the row
// decides whether the invite is still usable.
type Ref struct {
	ID      uuid.UUID
	Expires time.Time
	// Hash is SHA-256 of the 140 characters, the value of invites.token_hash.
	Hash []byte
}

func message(body []byte) []byte {
	m := make([]byte, 0, len(domainTag)+1+len(body))
	m = append(m, domainTag...)
	m = append(m, 0)
	return append(m, body...)
}

// Mint makes a token for the invite id that stops opening at expires, and the hash to store. The token is
// shown once, in the response that creates the invite.
func Mint(ring *keyring.Ring, id uuid.UUID, expires time.Time) (token secret.String, hash []byte, err error) {
	if ring == nil || id == uuid.Nil {
		return secret.String{}, nil, ErrMint
	}
	exp := expires.Unix()
	if exp <= 0 || exp > int64(^uint32(0)) {
		return secret.String{}, nil, ErrMint
	}
	var raw [rawLen]byte
	body := raw[:bodyLen]
	body[0] = version
	copy(body[3:19], id[:])
	binary.BigEndian.PutUint32(body[19:23], uint32(exp))
	if _, err := rand.Read(body[23:]); err != nil {
		return secret.String{}, nil, ErrMint
	}
	// The key number is part of what is signed, so it is read first; Sign signs under the newest key too and
	// the two must agree, which they do because a Ring is immutable.
	n, ok := ring.Newest(keyring.DomainInviteSign)
	if !ok {
		return secret.String{}, nil, ErrMint
	}
	binary.BigEndian.PutUint16(body[1:3], n)
	signedN, sig, err := ring.Sign(keyring.DomainInviteSign, keyring.LabelInviteLink, message(body))
	if err != nil || signedN != n || len(sig) != sigLen {
		return secret.String{}, nil, ErrMint
	}
	copy(raw[bodyLen:], sig)
	text := base64.RawURLEncoding.EncodeToString(raw[:])
	clear(raw[:])
	return secret.New(text), digest(text), nil
}

// fold is what a person pasted, reduced to the token text: the paste marks dropped and the keyboard's digits
// read as ASCII (digits.Typed, the one fold every typed or pasted code takes) and spaces removed. Case is
// kept, because base64url is case sensitive, and hyphens are kept, because they are base64url characters. A
// link copied out of a chat or a right-to-left message brings the same marks a typed code does.
func fold(s string) (string, bool) {
	if len(s) > maxRawBytes {
		return "", false
	}
	var b strings.Builder
	for _, r := range digits.Typed(s) {
		if r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String(), true
}

// Open reports what a token names if it was signed by a key of the public ring and has not expired at now.
// It does no I/O and returns one answer for every failure.
func Open(public *keyring.PublicRing, now time.Time, text string) (Ref, bool) {
	folded, ok := fold(text)
	if !ok || len(folded) != TokenChars {
		return Ref{}, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(folded)
	if err != nil || len(raw) != rawLen || raw[0] != version {
		return Ref{}, false
	}
	var id uuid.UUID
	copy(id[:], raw[3:19])
	if id == uuid.Nil {
		return Ref{}, false
	}
	exp := int64(binary.BigEndian.Uint32(raw[19:23]))
	if now.Unix() >= exp {
		return Ref{}, false
	}
	if !public.Verify(keyring.LabelInviteLink, binary.BigEndian.Uint16(raw[1:3]), message(raw[:bodyLen]), raw[bodyLen:]) {
		return Ref{}, false
	}
	return Ref{ID: id, Expires: time.Unix(exp, 0).UTC(), Hash: digest(folded)}, true
}

func digest(text string) []byte {
	h := sha256.Sum256([]byte(text))
	return h[:]
}
