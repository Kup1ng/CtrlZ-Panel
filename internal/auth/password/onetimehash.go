package password

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// oneTimeParams is the cost of hashing a one-time password (a function and not a
// variable, to keep the package free of mutable state): the smallest Argon2id
// allows. A password with 120 bits of entropy gains nothing from a slow hash (the
// work needed to guess it is 2^120 whatever the cost), while a slow hash makes
// the first login of an account depend on the Argon2 gate, which strangers can
// keep full (review round 3, admin-r3-11). The parameters are exact and not "at
// most", and NewHasher refuses them (the test environment lets a setting reach
// them, primitives-r8-1), so a hash made with the hasher's normal parameters
// never takes the ungated path.
func oneTimeParams() Params { return Params{MemoryKiB: 8, Time: 1, Threads: 1} }

// isOneTimeHash says a parsed hash was made by HashOneTime.
func isOneTimeHash(p Params) bool { return p == oneTimeParams() }

// ErrNotOneTime is returned by HashOneTime for a password that cannot be the output of
// NewOneTime: not exactly OneTimeLength characters of the base32 alphabet, or too few
// different ones. The cheap hash is only safe for NewOneTime's
// output, and a caller that passes a chosen password by mistake must fail rather
// than store it under a hash anyone can guess against.
var ErrNotOneTime = errors.New("password: not a generated one-time password")

// HashOneTime hashes a password made by NewOneTime. It takes no slot of the
// gate: the work is a few microseconds and 8 KiB, and the gate's derive sees that
// the memory is tiny and lets the run through without one. Verify recognises the
// result by its parameters and, for the one caller that asks for it
// (VerifyGateFree), takes no slot for it either.
func (h *Hasher) HashOneTime(pw secret.String) (secret.String, error) {
	n, err := Normalize(pw)
	if err != nil {
		return secret.String{}, err
	}
	if !looksGenerated(n.Reveal()) {
		return secret.String{}, ErrNotOneTime
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return secret.String{}, errors.New("password: no randomness")
	}
	sum, err := h.derive(context.Background(), n, salt, oneTimeParams(), hashLen, tinyFree)
	if err != nil {
		return secret.String{}, err
	}
	return secret.New(encode(oneTimeParams(), salt, sum)), nil
}

// ErrOneTimeOnly is returned by a hasher from NewOneTimeHasher when asked to do
// anything but HashOneTime: it was built without the memory the other paths need.
var ErrOneTimeOnly = errors.New("password: this hasher only makes one-time hashes")

// NewOneTimeHasher is the hasher of the console tools. They only call
// HashOneTime (8 KiB). `docker compose exec admin ctrlz-admin ...` runs in the cgroup
// of the live admin service, whose Argon2 gate is not the tool's gate, so a tool
// must never be able to allocate what the service's hasher does (review round 4,
// admin-r4-2). Its gate has a budget of 8 KiB in one slot, so every path that
// would need the full cost (Hash, Verify against a chosen password) is refused,
// by ErrOneTimeOnly here and, were that check ever dropped, by the gate's
// ErrOverBudget, instead of storing a weak hash of a chosen password. Building it
// computes nothing, as for any hasher.
func NewOneTimeHasher() (*Hasher, error) {
	h, err := newHasher(oneTimeParams(), newGate(1, 0, tinyMemKiB))
	if err != nil {
		return nil, err
	}
	h.oneTimeOnly = true
	return h, nil
}

// minDistinct is how many different characters a generated one-time password has at least.
// 24 draws from 32 symbols give 17 on average, and fewer than 8 has a probability far below
// one in a hundred million, so a real one is never refused; "AAAAAAAAAAAAAAAAAAAAAAAA" and a
// short phrase repeated to length are.
const minDistinct = 8

// looksGenerated says s has the shape NewOneTime writes: exactly OneTimeLength characters
// of RFC 4648 base32, with enough different ones. The cheap hash (8 KiB, one pass) is safe
// only for 120 bits of entropy, and the verify of the admin login trusts those parameters
// without a gate slot, so a chosen password must not be able to reach it. A length check
// alone passed any 24 characters, "aaaaaaaaaaaaaaaaaaaaaaaa" among them (primitives-r5-6).
// The shape cannot prove randomness; it closes the way a typed or weak value gets in, and
// both callers pass NewOneTime's output straight through.
func looksGenerated(s string) bool {
	if len(s) != OneTimeLength {
		return false
	}
	var seen [256]bool
	distinct := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
			return false
		}
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	return distinct >= minDistinct
}

// MayBeOneTime says pw can be a console one-time password: after the same NFKC step every verify
// makes, it has the shape NewOneTime writes. It is a pure function of the typed text and reads
// nothing about any account, so a handler may use it to refuse a request before it touches the
// database or the floor without adding an oracle: the answer is the same for a known and an
// unknown username, and the caller already knows what it typed (round 8, admin-r8-1, -4). The
// admin login uses it for the one request the deferred class admin-login lets through its spent
// bucket (rule budget-keying): anything that cannot be a console password is turned away at once.
//
// The length is bounded before the normalisation so a 16 KiB body costs a length check. Every
// source character gives at least one character of the NFKC result (a full-width letter gives
// one, a ligature several), so a result of 24 comes from at most 24 source characters of at
// most 4 bytes each.
func MayBeOneTime(pw secret.String) bool {
	if len(pw.Reveal()) > OneTimeLength*4 {
		return false
	}
	n, err := Normalize(pw)
	if err != nil {
		return false
	}
	return looksGenerated(n.Reveal())
}
