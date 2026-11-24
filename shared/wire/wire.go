// Package wire decodes and validates the protobuf messages that cross a trust
// boundary, and defines the hash chain over stored entries.
//
// Protobuf parsing only guarantees that bytes are well-formed protobuf. It says
// nothing about whether a field that must be 32 bytes is, whether an enum is
// one we know, or whether a prefix has stray host bits. Every receiver calls
// the matching Validate function before it uses a message (contract 12), so a
// hostile or buggy peer is stopped in one place.
package wire

import (
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
)

// Re-exported so callers can say wire.ReasonBadMagic; the definitions live in
// package reason so blob and gtable can use them without importing this one.
type Reason = reason.Code

const (
	ReasonBadMagic           = reason.BadMagic
	ReasonUnsupportedMajor   = reason.UnsupportedMajor
	ReasonLengthMismatch     = reason.LengthMismatch
	ReasonBadDirectory       = reason.BadDirectory
	ReasonMissingSection     = reason.MissingSection
	ReasonBadSection         = reason.BadSection
	ReasonIndexRange         = reason.IndexRange
	ReasonUnsorted           = reason.Unsorted
	ReasonBadEnum            = reason.BadEnum
	ReasonBadName            = reason.BadName
	ReasonHashMismatch       = reason.HashMismatch
	ReasonSizeCap            = reason.SizeCap
	ReasonPanic              = reason.Panic
	ReasonUnsupportedSection = reason.UnsupportedSection
)

// Size caps of the contract (9.1).
const (
	MaxEntrySize     = 16 << 20
	MaxProfileBlob   = 64 << 20
	MaxBlockPageBlob = 2 << 20
	MaxEnvelope      = 4 << 20
)

// ZeroHash returns the prev_hash of the first entry: 32 zero bytes. A function,
// not a variable, so no importer can change it.
func ZeroHash() [32]byte { return [32]byte{} }

// EntryHash is SHA-256(prev_hash + stored_bytes). It runs over the exact bytes
// that were stored, never over a re-marshalled message: two correct protobuf
// encoders can produce different bytes for the same message, and a chain that
// depended on re-encoding would break the first time the encoder changed.
func EntryHash(prev [32]byte, stored []byte) [32]byte {
	h := sha256.New()
	h.Write(prev[:])
	h.Write(stored)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// MarshalEntry encodes an entry deterministically. The panel calls it once and
// stores the result; from then on those bytes are the entry.
func MarshalEntry(e *policyv1.ConfigEntry) ([]byte, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(e)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxEntrySize {
		return nil, reason.New(reason.SizeCap, "entry", 0, "%d bytes", len(b))
	}
	return b, nil
}

// DecodeEntry parses and validates one stored entry. It never panics: a panic
// in the protobuf decoder or a validator becomes reason.Panic, because an
// entry arrives from the network and must not stop the node (9.7).
func DecodeEntry(b []byte) (e *policyv1.ConfigEntry, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, err = nil, reason.New(reason.Panic, "entry", 0, "decoder panic")
		}
	}()
	if len(b) > MaxEntrySize {
		return nil, reason.New(reason.SizeCap, "entry", 0, "%d bytes exceeds %d", len(b), MaxEntrySize)
	}
	e = &policyv1.ConfigEntry{}
	if err := proto.Unmarshal(b, e); err != nil {
		return nil, reason.New(reason.BadSection, "entry", 0, "not a ConfigEntry: %v", err)
	}
	if err := ValidateEntry(e); err != nil {
		return nil, err
	}
	return e, nil
}

// bad builds a validation failure.
func bad(c reason.Code, where, format string, args ...any) error {
	return reason.New(c, where, 0, "%s", fmt.Sprintf(format, args...))
}

func lenIs(where, field string, b []byte, n int) error {
	if len(b) != n {
		return bad(reason.BadSection, where, "%s is %d bytes, want %d", field, len(b), n)
	}
	return nil
}
