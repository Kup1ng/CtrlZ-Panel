// Package identity is the resolver grammar: how a hostname, an SNI or a DoH
// path names an Endpoint and a client, and the hashes that keep those names off
// disk.
//
// A resolver_id is a routing label, not a secret (R7). The DoH token is the
// only secret in this package, and it only ever appears inside TLS.
package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const (
	ResolverIDLen = 26
	DoHTokenLen   = 32
	VerifyLen     = names.VerifyLen
	ClientMax     = names.ClientMax
	ProofLen      = 10
)

// b32 is RFC 4648 base32 in lowercase without padding. The alphabet has no
// hyphen, so a resolver_id can never be confused with "<id>-<client>".
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func isB32(c byte) bool { return c >= 'a' && c <= 'z' || c >= '2' && c <= '7' }

func allB32(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isB32(s[i]) {
			return false
		}
	}
	return true
}

// ValidResolverID reports whether s matches [a-z2-7]{26}.
func ValidResolverID(s string) bool { return allB32(s, ResolverIDLen) }

// ValidDoHToken reports whether s matches [a-z2-7]{32}.
func ValidDoHToken(s string) bool { return allB32(s, DoHTokenLen) }

// ValidVerifyLabel reports whether s matches [a-z2-7]{26}.
func ValidVerifyLabel(s string) bool { return names.ValidVerifyLabel(s) }

// ValidClient reports whether s matches
// [a-z0-9](?:[a-z0-9-]{0,34}[a-z0-9])?  (1 to 36 bytes, no edge hyphen). The
// 36-byte cap leaves room for "<26 id>-<client>" inside one 63-byte label.
func ValidClient(s string) bool { return names.ValidClientLabel(s) }

func randomB32(nChars int) (string, error) {
	// 5 bits per character: ask for enough bytes, then cut.
	buf := make([]byte, (nChars*5+7)/8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.ToLower(b32.EncodeToString(buf))[:nChars], nil
}

// NewResolverID returns 130 random bits as 26 base32 characters.
func NewResolverID() (string, error) { return randomB32(ResolverIDLen) }

// NewDoHToken returns 160 random bits as 32 base32 characters. Its length
// differs from a resolver_id so path parsing is unambiguous (3.4).
func NewDoHToken() (string, error) { return randomB32(DoHTokenLen) }

// NewVerifyLabel returns a random label for one browser attempt or proof.
func NewVerifyLabel() (string, error) { return randomB32(VerifyLen) }

// SlugClient is the one normalizer behind DoH, DoT, DoQ and the wizard:
// NFKC, ASCII lowercase, keep [a-z0-9], map every other run to one '-', trim
// '-', cut to 36, trim again. It returns false when nothing remains; the
// wizard then asks for an explicit label. Persian text lives only in the
// Unicode alias, never on the network.
func SlugClient(alias string) (string, bool) {
	s := norm.NFKC.String(alias)
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			r += 'a' - 'A'
			fallthrough
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		default:
			dash = true
		}
	}
	out := b.String()
	if len(out) > ClientMax {
		out = out[:ClientMax]
	}
	out = strings.Trim(out, "-")
	if out == "" {
		return "", false
	}
	return out, true
}

// Domain-separated hashes. The prefix stops a hash computed for one purpose
// from being replayed as another.

// RIDHash is the Endpoint lookup key: no plain resolver_id is stored on a node
// (R16).
func RIDHash(rid string) [16]byte {
	h := sha256.Sum256([]byte("ctrlz-rid-v1\x00" + rid))
	var out [16]byte
	copy(out[:], h[:16])
	return out
}

// AccountHash is the one-way label of a tenant that every EndpointRecord of that
// tenant carries (EndpointRecord.account_hash, p4b-proxy 3.4): the first 16 bytes of
// the SHA-256 of "ctrlz-account-v1\x00" and the 16 bytes of the tenant's id. The
// node learns from it which Endpoints share an account, and never the id itself
// (R18). It returns nil for an id that is not 16 bytes, so a caller that passes
// the wrong thing gets a value that fails every later length check instead of a
// hash of something else. A slice and not an array, so no frame holds the bytes
// by value.
func AccountHash(tenantID []byte) []byte {
	if len(tenantID) != 16 {
		return nil
	}
	h := sha256.Sum256(append([]byte("ctrlz-account-v1\x00"), tenantID...))
	return append([]byte(nil), h[:16]...)
}

// TokenHash is what the node compares a DoH path token against.
func TokenHash(token string) [32]byte {
	return sha256.Sum256([]byte("ctrlz-doh-v1\x00" + token))
}

// ClientHash is the client record key, so client labels are not on disk (R16).
func ClientHash(label string) [16]byte {
	h := sha256.Sum256([]byte("ctrlz-client-v1\x00" + label))
	var out [16]byte
	copy(out[:], h[:16])
	return out
}

// ProofCode is the TXT answer for a UDP verify proof: the first 10 characters
// of lowercase base32 of HMAC-SHA256(proof_key, "ctrlz-proof-v1\0" label "\0"
// source IP text). The panel recomputes it from the same inputs, so no node to
// panel call is needed.
//
// The source IP text is one form only: netip.Addr.Unmap().String(), so
// 192.0.2.1 and ::ffff:192.0.2.1 give the same code and an IPv6 address is the
// lower-case compressed form of RFC 5952. Taking an Addr and not text keeps the
// node and the hub from formatting the same source two ways.
func ProofCode(proofKey []byte, label string, src netip.Addr) string {
	m := hmac.New(sha256.New, proofKey)
	m.Write([]byte("ctrlz-proof-v1\x00" + label + "\x00" + src.Unmap().String()))
	return strings.ToLower(b32.EncodeToString(m.Sum(nil)))[:ProofLen]
}

// ErrBadPath is the single error for every DoH path failure. The caller maps
// it to HTTP 404 and must not say which part was wrong, so an unknown id and a
// wrong token look the same.
var ErrBadPath = errors.New("identity: unrecognized path")

// TokenMatches compares a DoH path token against the stored hash. The compare
// is constant-time so a wrong token cannot be refined one byte at a time, and
// it hashes first, so an input of any shape (wrong length, uppercase, empty)
// is simply a mismatch.
func TokenMatches(token string, want [32]byte) bool {
	got := TokenHash(token)
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}
