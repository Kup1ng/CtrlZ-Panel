// Package hubtoken is the enrolment token (p4-nodes 4.2 step 1): 32 random bytes, shown once as
// base64url without padding, stored only as the SHA-256 of the 32 raw bytes.
//
// One definition for both ends. The admin route that creates an enrolment calls New; the hub calls
// Parse on whatever arrives (the Enroll message and the bearer header of a bundle download), so a
// text that is not exactly a token never reaches a database query. The node's install script accepts
// the characters A-Z a-z 0-9 _ - up to 256, which both forms here stay inside.
package hubtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
)

// Bytes is the size of a token before encoding.
const Bytes = 32

// New makes a token and the hash the database stores. r is crypto/rand.Reader outside tests.
func New(r io.Reader) (token string, hash []byte, err error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, Bytes)
	if _, err = io.ReadFull(r, b); err != nil {
		return "", nil, err
	}
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(b), h[:], nil
}

// Parse decodes a token text (43 base64url characters, or 64 hexadecimal digits for a token typed by
// hand) and returns the hash to look up. Anything else, padding and whitespace included, is not a
// token.
func Parse(s string) (hash []byte, ok bool) {
	var raw []byte
	var err error
	switch len(s) {
	case base64.RawURLEncoding.EncodedLen(Bytes):
		raw, err = base64.RawURLEncoding.Strict().DecodeString(s)
	case 2 * Bytes:
		raw, err = hex.DecodeString(s)
	default:
		return nil, false
	}
	if err != nil || len(raw) != Bytes {
		return nil, false
	}
	h := sha256.Sum256(raw)
	return h[:], true
}
