// Package reason holds the failure vocabulary shared by every decoder
// (contract 9.7). It is a leaf so that blob, gtable and wire report the same
// codes without importing each other, and so a QuarantineReport can carry the
// code, the section and the byte offset that failed.
package reason

import (
	"errors"
	"fmt"
)

// Code is a stable, machine-readable failure reason. The strings are part of
// the node to hub protocol (QuarantineReport.reason); never rename one.
type Code string

const (
	BadMagic           Code = "bad_magic"
	UnsupportedMajor   Code = "unsupported_major"
	LengthMismatch     Code = "length_mismatch"
	BadDirectory       Code = "bad_directory"
	MissingSection     Code = "missing_section"
	BadSection         Code = "bad_section"
	IndexRange         Code = "index_range"
	Unsorted           Code = "unsorted"
	BadEnum            Code = "bad_enum"
	BadName            Code = "bad_name"
	HashMismatch       Code = "hash_mismatch"
	SizeCap            Code = "size_cap"
	Panic              Code = "panic"
	UnsupportedSection Code = "unsupported_section"
)

// All lists every code, for tests that check coverage.
func All() []Code {
	return []Code{BadMagic, UnsupportedMajor, LengthMismatch, BadDirectory, MissingSection, BadSection,
		IndexRange, Unsorted, BadEnum, BadName, HashMismatch, SizeCap, Panic, UnsupportedSection}
}

// Error is a decoder failure with enough detail to find the bad byte.
type Error struct {
	Code    Code
	Section string // section name, or "" for the header
	Offset  uint64 // byte offset inside the object, 0 if not meaningful
	Detail  string
}

func (e *Error) Error() string {
	s := string(e.Code)
	if e.Section != "" {
		s += " in " + e.Section
	}
	if e.Offset != 0 {
		s += fmt.Sprintf(" at %d", e.Offset)
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// New builds an *Error.
func New(c Code, section string, off uint64, format string, args ...any) *Error {
	return &Error{Code: c, Section: section, Offset: off, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf extracts the code from an error, or "" if it is not an *Error.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
