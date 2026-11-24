// Package token makes and hashes the opaque bearer values of P1: session,
// refresh and ticket tokens (spec 3.1). They are 32 random bytes in base64url,
// so an unkeyed SHA-256 is the right thing to store: there is no low-entropy
// input for a dictionary to attack, unlike a phone number.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

const (
	rawLen = 32
	// EncodedLen is the length of a valid token: 32 bytes in base64url without
	// padding.
	EncodedLen = 43
)

// New returns a fresh token from crypto/rand.
func New() (secret.String, error) { return NewFrom(rand.Reader) }

// NewFrom is New with a chosen source of randomness, for tests.
func NewFrom(r io.Reader) (secret.String, error) {
	var b [rawLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return secret.String{}, err
	}
	return secret.New(base64.RawURLEncoding.EncodeToString(b[:])), nil
}

// Hash is the value stored for a token: SHA-256 of the text the client holds.
func Hash(t secret.String) []byte { return HashString(t.Reveal()) }

// HashString is Hash for a value read from a cookie or header.
func HashString(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// Valid reports whether s has the shape of a token. A cookie that does not is
// refused before any database call, so junk cannot cost a lookup. The shape is
// public, so this reveals nothing.
//
// The shape is canonical: 43 characters carry 258 bits for 256, and a decoder that does
// not look at the 2 spare bits of the last character reads four spellings as one token.
// Each spelling would hash to a lookup key and a stored-hash key of its own, so one
// cookie would get four budgets (primitives-r5-9). Only the spelling that New writes is
// valid, so one token has one text and one key.
func Valid(s string) bool {
	if len(s) != EncodedLen || spareBits(s[len(s)-1]) != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// spareBits is the value of the 2 low bits of the last base64url character of a 32 byte
// value, which a canonical encoding leaves zero. A character outside the alphabet reports
// a non-zero value so that the caller refuses it.
func spareBits(c byte) byte {
	var v byte
	switch {
	case c >= 'A' && c <= 'Z':
		v = c - 'A'
	case c >= 'a' && c <= 'z':
		v = c - 'a' + 26
	case c >= '0' && c <= '9':
		v = c - '0' + 52
	case c == '-':
		v = 62
	case c == '_':
		v = 63
	default:
		return 1
	}
	return v & 3
}
