package compiler

import (
	"errors"
	"net/netip"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
)

// The functions of this file are the compiler's only places that take an address apart into bytes: a record on the
// wire holds the bytes of a prefix, a node address or a block address, and the database hands them over as text or
// as a netip value. They key no bucket and keep nothing, which is what the network-cut lint is told about each of
// them (internal/lint/netcut_test.go). Returning slices and never arrays keeps the by-value lint quiet too.

var errAddr = errors.New("compiler: bad address")

// ipBytes is the 4 or 16 bytes of an address in text form.
func ipBytes(text string) ([]byte, error) {
	a, err := netip.ParseAddr(text)
	if err != nil {
		return nil, errAddr
	}
	return a.AsSlice(), nil
}

// prefixWire is the wire form of a prefix the database holds in canonical form (a cidr value has no host bits).
func prefixWire(p netip.Prefix) (*commonv1.Prefix, error) {
	if !p.IsValid() {
		return nil, errAddr
	}
	return &commonv1.Prefix{Addr: p.Addr().AsSlice(), Bits: uint32(p.Bits())}, nil
}

// cidrWire is prefixWire for a cidr in text form.
func cidrWire(text string) (*commonv1.Prefix, error) {
	p, err := netip.ParsePrefix(text)
	if err != nil {
		return nil, errAddr
	}
	return prefixWire(p)
}
