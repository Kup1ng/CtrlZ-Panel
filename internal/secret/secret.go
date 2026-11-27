// Package secret holds the one type that carries a credential through the
// program. Anything else that prints, marshals or logs a secret is a bug, so
// the type makes the safe thing the only thing: every formatting path yields
// a fixed marker, and the plain text is reachable only through Reveal, which
// is easy to grep for in review.
package secret

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Redacted is what every formatting path prints in place of the value.
const Redacted = "[REDACTED]"

// String is a credential. The zero value is the empty secret.
//
// The value sits behind a pointer on purpose. fmt prints unexported struct
// fields by reflection and cannot call methods on them, so a String embedded
// as an unexported field of another struct (a config with a private
// `password` field, say) would print its contents if it held the text inline.
// Behind a pointer, reflection prints an address instead. The canary test
// pins this case.
type String struct {
	p *string
}

// New wraps s. The caller should drop its own copy of s as soon as it can.
func New(s string) String {
	if s == "" {
		return String{}
	}
	return String{p: &s}
}

// FromFile reads a secret from a file such as a Docker secret under
// /run/secrets. One trailing newline is trimmed, because editors and
// `echo` add one and no generated secret ends in whitespace. Errors name the
// path but never the content.
func FromFile(path string) (String, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return String{}, fmt.Errorf("secret: read %s: %w", path, pathErrOnly(err))
	}
	s := strings.TrimSuffix(string(b), "\n")
	s = strings.TrimSuffix(s, "\r")
	return New(s), nil
}

// pathErrOnly strips everything but the operation's underlying cause, so a
// wrapped *PathError does not repeat the path a second time.
func pathErrOnly(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

// Reveal returns the plain text. Call it at the last moment, at the call that
// hands the value to a driver or a signer, and never store the result.
func (s String) Reveal() string {
	if s.p == nil {
		return ""
	}
	return *s.p
}

// IsZero reports whether the secret is empty.
func (s String) IsZero() bool { return s.p == nil || *s.p == "" }

// Equal compares two secrets in constant time for equal lengths.
func (s String) Equal(o String) bool {
	return subtle.ConstantTimeCompare([]byte(s.Reveal()), []byte(o.Reveal())) == 1
}

// String implements fmt.Stringer.
func (String) String() string { return Redacted }

// GoString implements fmt.GoStringer, which %#v uses.
func (String) GoString() string { return "secret.String(" + Redacted + ")" }

// Format implements fmt.Formatter so that no verb (%s, %v, %+v, %q, %x, %d)
// can reach the content, even a verb nobody has thought of yet.
func (String) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", Redacted)
	default:
		_, _ = f.Write([]byte(Redacted))
	}
}

// LogValue implements slog.LogValuer, so slog never sees the content even
// through a handler that inspects attribute values by kind.
func (String) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalText implements encoding.TextMarshaler. encoding/json uses it for
// both values and map keys, and the YAML and TOML encoders use it as well.
func (String) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalJSON implements json.Marshaler.
func (String) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// UnmarshalText lets configuration decoders fill a String from text. This is
// the one way in from outside besides New and FromFile.
func (s *String) UnmarshalText(b []byte) error {
	*s = New(string(b))
	return nil
}

// Bytes is String's twin for binary credentials: a key, a TOTP seed, a raw
// token. It follows the same rules, on purpose, so that no call site has to
// remember which of the two it is holding.
//
// Like String it keeps the content behind a pointer, so fmt's reflection over
// an unexported field prints an address and not the bytes. A []byte inline
// would print as a list of numbers on %v and as hex on %x.
//
// The zero value is the empty secret.
type Bytes struct {
	p *[]byte
}

// NewBytes copies b into a Bytes. It copies so that the caller can wipe its own
// slice at once (clear(b)) without touching the secret, and so that a later
// write to b cannot change a key that is already in use.
func NewBytes(b []byte) Bytes {
	if len(b) == 0 {
		return Bytes{}
	}
	c := make([]byte, len(b))
	copy(c, b)
	return Bytes{p: &c}
}

// BytesFromFile reads a binary secret, such as a key file, exactly as it is on
// disk: no trimming, since a random key may end in any byte. Errors name the
// path but never the content.
func BytesFromFile(path string) (Bytes, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Bytes{}, fmt.Errorf("secret: read %s: %w", path, pathErrOnly(err))
	}
	s := NewBytes(b)
	clear(b)
	return s, nil
}

// Reveal returns the bytes themselves, not a copy. Read them, do not keep the
// slice and do not write to it. Call it at the last moment, at the call that
// hands the value to a cipher or a MAC, so a grep for Reveal finds every place
// a secret leaves its wrapper.
func (b Bytes) Reveal() []byte {
	if b.p == nil {
		return nil
	}
	return *b.p
}

// Len is the length of the content. A length is not a secret here: the
// callers that hold a Bytes already know it (a key is 32 bytes).
func (b Bytes) Len() int {
	if b.p == nil {
		return 0
	}
	return len(*b.p)
}

// IsZero reports whether the secret is empty.
func (b Bytes) IsZero() bool { return b.Len() == 0 }

// Equal compares two secrets in constant time for equal lengths.
func (b Bytes) Equal(o Bytes) bool {
	return subtle.ConstantTimeCompare(b.Reveal(), o.Reveal()) == 1
}

// Wipe overwrites the content in place. Go gives no promise about copies the
// runtime made earlier, so this narrows the window; it does not close it. Every
// copy that shares this Bytes is wiped too, which is the point when a key is
// retired.
func (b Bytes) Wipe() {
	if b.p != nil {
		clear(*b.p)
	}
}

// String implements fmt.Stringer.
func (Bytes) String() string { return Redacted }

// GoString implements fmt.GoStringer, which %#v uses.
func (Bytes) GoString() string { return "secret.Bytes(" + Redacted + ")" }

// Format implements fmt.Formatter so that no verb can reach the content.
func (Bytes) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", Redacted)
	default:
		_, _ = f.Write([]byte(Redacted))
	}
}

// LogValue implements slog.LogValuer.
func (Bytes) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalText implements encoding.TextMarshaler, for JSON, YAML and TOML.
func (Bytes) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// MarshalJSON implements json.Marshaler.
func (Bytes) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }

// MarshalBinary implements encoding.BinaryMarshaler, which gob and some RPC
// codecs prefer over text. A byte secret is the type most likely to meet one.
func (Bytes) MarshalBinary() ([]byte, error) { return []byte(Redacted), nil }

// UnmarshalText fills a Bytes from text as it is, without decoding. It is a way
// in for configuration, like String's.
func (b *Bytes) UnmarshalText(t []byte) error {
	*b = NewBytes(t)
	return nil
}
