// Package recovery makes and checks TOTP recovery codes (spec 6.5).
//
// Ten codes of 80 bits each, in Crockford base32, shown as XXXX-XXXX-XXXX-XXXX.
// They are random and high-entropy, so a plain SHA-256 of the canonical text is
// enough to store (PS section 1): there is nothing to brute force. They are
// hashes in the database, which is also why losing the TOTP key domain does not
// lose them (8.5).
package recovery

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Count is how many codes a set holds.
const Count = 10

const (
	codeBytes = 10 // 80 bits
	codeChars = 16 // 80 bits / 5 bits per character
	groupSize = 4
	// alphabet is Crockford's: no I, L, O or U, so a code read aloud or copied by
	// hand is not mistaken.
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// ErrFormat means the text is not a recovery code. It is a fixed string that
// never repeats the input.
var ErrFormat = errors.New("recovery: not a recovery code")

// Set is a fresh batch: the codes to show the user once, and the hashes to
// store. Codes are secret.String so a stray log line prints the marker.
type Set struct {
	Codes  []secret.String
	Hashes [][]byte
}

// NewSet makes Count codes.
func NewSet() (Set, error) {
	s := Set{Codes: make([]secret.String, 0, Count), Hashes: make([][]byte, 0, Count)}
	seen := make(map[string]bool, Count)
	for len(s.Codes) < Count {
		c, err := generate()
		if err != nil {
			return Set{}, err
		}
		// A repeat among ten 80-bit values means the random source is broken.
		// Refuse it rather than store two rows with one hash.
		if seen[c] {
			return Set{}, errors.New("recovery: random source repeated a value")
		}
		seen[c] = true
		canon, ok := Canonical(c)
		if !ok {
			return Set{}, errors.New("recovery: generated a malformed code")
		}
		s.Codes = append(s.Codes, secret.New(c))
		s.Hashes = append(s.Hashes, hash(canon))
	}
	return s, nil
}

// generate draws 10 random bytes and writes them as 16 base32 characters in
// four groups of four. 80 bits is exactly 16 characters, so nothing is wasted
// and nothing is biased.
func generate() (string, error) {
	var b [codeBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("recovery: no randomness")
	}
	s := encode(b[:])
	clear(b[:])
	return s, nil
}

// encode is the deterministic half of generate, split out so a test can pin the
// bit packing with known bytes. It takes a slice and not the array: the runtime prints the words of an
// array argument into the container log when it dies of a throw, whatever GOTRACEBACK says, and these are
// the ten bytes of a code (round 18, primitives-r18-9, internal/lint TestNoFunctionTakesAnArrayByValue).
// A slice is printed as an address, a length and a capacity. Anything but ten bytes is no code.
func encode(b []byte) string {
	if len(b) != codeBytes {
		return ""
	}
	var out [codeChars + 3]byte
	var acc uint16
	bits, n := 0, 0
	for _, by := range b {
		acc = acc<<8 | uint16(by)
		bits += 8
		for bits >= 5 {
			bits -= 5
			if n > 0 && n%groupSize == 0 {
				out[n+n/groupSize-1] = '-'
			}
			out[n+n/groupSize] = alphabet[(acc>>uint(bits))&31]
			n++
		}
	}
	return string(out[:])
}

// Canonical folds what a person typed to the text that is hashed: hyphens and
// spaces removed, upper case, and Crockford's look-alikes read as the digits
// they stand for (O as 0, I and L as 1), Persian and Arabic digits as ASCII. It reports false if the result is not
// 16 characters of the alphabet.
func Canonical(s string) (string, bool) {
	// The bound is the one every typed code shares (digits.MaxTypedBytes); it
	// exists because NFKC runs next.
	if len(s) > digits.MaxTypedBytes {
		return "", false
	}
	var b strings.Builder
	// digits.Typed is the fold every typed code shares (primitives-r13-1): a
	// Persian or Arabic keyboard types its own digits, a paste brings direction
	// marks and no-break spaces. They map one to one or vanish, so this adds no
	// guessing space, and a refusal would cost the user one of the five
	// attempts for nothing.
	for _, r := range digits.Typed(s) {
		switch {
		case r == '-' || r == ' ':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}
		switch r {
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if r > 0x7f || strings.IndexByte(alphabet, byte(r)) < 0 {
			return "", false
		}
		b.WriteByte(byte(r))
	}
	if b.Len() != codeChars {
		return "", false
	}
	return b.String(), true
}

// Hash is the value stored and compared: SHA-256 of the canonical text. A text
// that is not a code gives ErrFormat, which the caller treats like a wrong code
// (and spends the same throttle attempt on).
func Hash(code secret.String) ([]byte, error) {
	canon, ok := Canonical(code.Reveal())
	if !ok {
		return nil, ErrFormat
	}
	return hash(canon), nil
}

func hash(canon string) []byte {
	h := sha256.Sum256([]byte(canon))
	return h[:]
}

// Equal compares two stored hashes in constant time.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
