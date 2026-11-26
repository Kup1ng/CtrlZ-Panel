package policy

import (
	"encoding/binary"
	"net/netip"
)

// SvcParam keys that carry addresses (RFC 9460, section 7.3).
const (
	paramIPv4Hint = 4
	paramIPv6Hint = 6
)

// svcHints returns the addresses in the ipv4hint and ipv6hint SvcParams of an
// HTTPS or SVCB record's RDATA: priority, the target name (a compression
// pointer ends it), then key/length/value triples.
//
// It reads what is well formed and stops at what is not, like RR.Addr, which
// reads nothing from a record of the wrong length. A hint whose length is not
// a whole number of addresses is skipped entirely, never read in part, and a
// parameter that runs past the end of the record ends the scan, so a damaged
// record neither panics nor turns leftover bytes into an address. Hints read
// before the damage still count: Rebind is a blocking check, and a private
// address that was fully there is not an accident.
func svcHints(rdata []byte) []netip.Addr {
	if len(rdata) < 3 {
		return nil
	}
	i := 2 // priority
nameLoop:
	for { // TargetName
		if i >= len(rdata) {
			return nil
		}
		l := int(rdata[i])
		switch {
		case l == 0:
			i++
			break nameLoop
		case l&0xC0 == 0xC0:
			// RFC 9460 forbids compression here, but a client whose parser follows
			// pointers would still read the hints behind one. A pointer ends the
			// name and is two bytes long, so skip it and go on to the params; if
			// the scan stopped instead, a hostile zone could hide a private hint
			// behind a pointer.
			if i+2 > len(rdata) {
				return nil
			}
			i += 2
			break nameLoop
		case l&0xC0 != 0:
			// The reserved 0x40 and 0x80 label types have no length we can trust.
			return nil
		}
		i++
		if i+l > len(rdata) {
			return nil
		}
		i += l
	}
	var out []netip.Addr
	for i+4 <= len(rdata) {
		param := binary.BigEndian.Uint16(rdata[i:])
		n := int(binary.BigEndian.Uint16(rdata[i+2:]))
		i += 4
		if i+n > len(rdata) {
			return out
		}
		v := rdata[i : i+n]
		i += n
		switch {
		case param == paramIPv4Hint && n%4 == 0:
			for ; len(v) >= 4; v = v[4:] {
				out = append(out, netip.AddrFrom4([4]byte(v)))
			}
		case param == paramIPv6Hint && n%16 == 0:
			for ; len(v) >= 16; v = v[16:] {
				out = append(out, netip.AddrFrom16([16]byte(v)))
			}
		}
	}
	return out
}
