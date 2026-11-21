// Package invite makes and reads invite codes (spec 11.3).
//
// A code is 20 Crockford base32 characters, 100 bits, from crypto/rand. It is
// not a link: sms.ir limits a template parameter to 25 characters and
// Melipayamak refuses a link in a variable, so the SMS carries the code and the
// invite page takes it typed or from a URL fragment. The database stores only
// SHA-256 of the canonical text, as with every other high-entropy token (PS
// section 1), so a stolen backup holds no usable invite.
//
// The admin route that creates invites and the tenant routes that look them up
// both use this package, so the canonical form cannot drift between them.
package invite

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/digits"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

const (
	codeBytes = 13 // 104 bits drawn, 100 used
	codeChars = 20 // 100 bits / 5 bits per character
	groupSize = 5
	// alphabet is Crockford's: no I, L, O or U.
	alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// ErrFormat means the text is not an invite code. It never repeats the input.
var ErrFormat = errors.New("invite: not an invite code")

// New returns a fresh code in display form (XXXXX-XXXXX-XXXXX-XXXXX) and the
// hash to store. The code is shown once, in the response that creates the invite.
func New() (code secret.String, hash []byte, err error) {
	var b [codeBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return secret.String{}, nil, errors.New("invite: no randomness")
	}
	var raw [codeChars]byte
	var acc uint32
	bits, n := 0, 0
	for _, by := range b {
		acc = acc<<8 | uint32(by)
		bits += 8
		for bits >= 5 && n < codeChars {
			bits -= 5
			raw[n] = alphabet[(acc>>uint(bits))&31]
			n++
		}
		acc &= 1<<uint(bits) - 1
	}
	clear(b[:])
	var out strings.Builder
	for i, c := range raw {
		if i > 0 && i%groupSize == 0 {
			out.WriteByte('-')
		}
		out.WriteByte(c)
	}
	return secret.New(out.String()), digest(string(raw[:])), nil
}

// Canonical folds what a person typed to the text that is hashed: the paste marks
// dropped and the keyboard's digits read as ASCII (digits.Typed, the one fold every
// typed code takes), hyphens and spaces removed, upper case, and Crockford's
// look-alikes read as the digits they stand for. It reports false if the result is
// not 20 characters of the alphabet.
//
// The invite code is a typed code like the SMS code and the recovery code: it comes
// in a Persian SMS and is copied into the invite page, and a copy out of a
// right-to-left message carries direction marks. It was the one typed code outside
// the fold, so a paste was a bare 400 at the schema and Persian digits were an
// unknown invite that spent the network's junk-token budget (round 15, tenant-r15-1
// and -5). Every fold here maps one to one or vanishes, so it adds no guessing space.
func Canonical(s string) (string, bool) {
	// The bound every typed code shares, applied before the fold because NFKC can
	// expand one code point into eighteen; a longer text is refused, never cut.
	if len(s) > digits.MaxTypedBytes {
		return "", false
	}
	var b strings.Builder
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

// Hash is the stored form of what a person typed. A text that is not a code is
// ErrFormat, which the caller answers like an unknown invite.
func Hash(typed string) ([]byte, error) {
	canon, ok := Canonical(typed)
	if !ok {
		return nil, ErrFormat
	}
	return digest(canon), nil
}

func digest(canon string) []byte {
	h := sha256.Sum256([]byte(canon))
	return h[:]
}
