package keyring

import (
	"encoding/hex"
	"strings"

	"github.com/google/uuid"
)

// Context is what a sealed value is bound to: the AAD tail of spec 8.2. A ciphertext made under one
// Context does not open under another, so a ciphertext copied into a different row is refused.
//
// It is a type, and not the bytes it holds, so that the wrong context cannot be written (round 18,
// primitives-r18-13). Rounds 12 to 17 guarded []byte: an empty context, then the zero row id, then
// its NUL spelling, each by a search for one more spelling of "nothing" in the bytes, and a hex
// spelling of the same zero id still passed. Now the field is unexported and only RowContext and
// DigestContext make a non-zero Context. Each refuses the zero row id, an empty part and any part
// that carries no information, and each owns the one encoding, so a caller can neither spell the
// row's identity another way nor leave it out. The zero Context binds nothing, and Seal and Open
// refuse it, so `Context{}`, a variable never filled and a refused construction are all the same
// closed door.
//
// The encoding is the bytes the ciphertexts already in a database were sealed under, so no stored
// value changes (TestContextEncodingIsFrozen): the text form of each id, then each part, joined by one
// NUL byte.
type Context struct{ b []byte }

// maxContext bounds a context: the ids and parts of every row of the product are a few dozen bytes.
const maxContext = 512

// RowContext binds a seal to the row that holds it, named by the ids it is read under (a tenant and a
// user, an admin, a gateway) and, after them, parts that tell uses of one row apart (a phone, a
// provider, a version tag of a kind). At least one id is needed. It returns the zero Context, which
// Seal and Open refuse, when an id is uuid.Nil (what a value is when it was never read from a row), when
// there is no id, or when a part is not usable (see usablePart). The zero id has no clause of its own:
// every id is judged as the text it is encoded as, and the text of the zero id is made of '0' and '-'
// only, which usablePart refuses (primitives-r18-16: a separate check was dead code).
func RowContext(ids []uuid.UUID, parts ...string) Context {
	if len(ids) == 0 {
		return Context{}
	}
	segs := make([]string, 0, len(ids)+len(parts))
	for _, id := range ids {
		segs = append(segs, id.String())
	}
	return join(segs, parts)
}

// DigestContext binds a seal to a row whose own id does not exist yet when the value is sealed, by a
// random value the row will hold: the keyed hash of the code of an OTP challenge, which the caller
// computed before the insert and the sender reads back with the row (spec 5.2). The digest is rendered
// in hex after the parts, and at least one part is needed to tell uses apart. It returns the zero
// Context for a digest of fewer than 16 bytes and for an unusable part. A digest of zero bytes needs no
// clause of its own: its hex is all '0', which usablePart refuses (primitives-r18-16: a separate check
// was dead code that no mutant could kill).
func DigestContext(digest []byte, parts ...string) Context {
	if len(parts) == 0 || len(digest) < 16 {
		return Context{}
	}
	return join(append([]string(nil), parts...), []string{hex.EncodeToString(digest)})
}

// join checks the parts and encodes. head and tail are joined in that order; both are judged, so the
// callers cannot send an unusable segment through either.
func join(head, tail []string) Context {
	n := len(head) + len(tail)
	if n == 0 {
		return Context{}
	}
	all := make([]string, 0, n)
	all = append(all, head...)
	all = append(all, tail...)
	total := n - 1
	for _, p := range all {
		if !usablePart(p) {
			return Context{}
		}
		total += len(p)
	}
	if total > maxContext {
		return Context{}
	}
	return Context{b: []byte(strings.Join(all, "\x00"))}
}

// usablePart says whether a segment can tell one row from another. It is not empty, holds no NUL (the
// separator: a part that held one could be cut elsewhere, so two lists of parts would give one
// context), and holds some character other than '0' and '-' (what the text of the zero id and of any
// run of zeros is made of, in whatever grouping). The rule is the complement of "carries
// something", and not a list of spellings of nothing.
func usablePart(p string) bool {
	return p != "" && !strings.ContainsRune(p, 0) && strings.Trim(p, "0-") != ""
}

// zero reports that the context binds nothing.
func (c Context) zero() bool { return len(c.b) == 0 }

// Bytes is the encoded context, for golden tests of the stored format and for the key tool's status
// output. Nothing takes bytes back: Seal and Open accept a Context only, so a caller cannot rebuild one
// from this.
func (c Context) Bytes() []byte { return append([]byte(nil), c.b...) }
