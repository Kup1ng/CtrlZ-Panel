package setup

import (
	"encoding/base64"
	"fmt"
	"net/netip"
)

// DNS Stamps (https://dnscrypt.info/stamps-specifications) for DoH, DoT and DoQ.
//
//	DoH: 0x02 | props(8, LE) | LP(addr) | VLP(hashes) | LP(host) | LP(path) | VLP(bootstrap_ipi)
//	DoT: 0x03 | props(8, LE) | LP(addr) | VLP(hashes) | LP(host) | VLP(bootstrap_ipi)
//	DoQ: 0x04 as DoT
//
// LP is one length byte and the bytes; VLP is a list whose every element but the
// last has 0x80 set in its length byte, and an empty list is one 0x00. The text
// is "sdns://" and the bytes in unpadded base64url.
//
// Ours have every property clear (we claim no DNSSEC, no-log or no-filter, and a
// stamp is read by apps that act on those claims) and no hashes, so a
// certificate renewal does not break a stamp (SC 8a.8).
const (
	stampDoH byte = 0x02
	stampDoT byte = 0x03
	stampDoQ byte = 0x04
)

// stamp is one stamp before encoding. addr is "" for a hostname stamp.
type stamp struct {
	kind      byte
	props     uint64
	addr      string
	host      string
	path      string // DoH only
	bootstrap []string
}

// stampAddr is how a stamp writes an address: IPv4 as is, IPv6 in square
// brackets, no port (the default of the protocol).
func stampAddr(a netip.Addr) string {
	if a.Is6() {
		return "[" + a.String() + "]"
	}
	return a.String()
}

func appendLP(b []byte, s string) ([]byte, error) {
	if len(s) > 255 {
		return nil, bad("stamp field length")
	}
	return append(append(b, byte(len(s))), s...), nil
}

// appendVLP writes a list of strings. Each element must be shorter than 128
// bytes because the high bit of its length byte marks "more follows".
func appendVLP(b []byte, items []string) ([]byte, error) {
	if len(items) == 0 {
		return append(b, 0), nil
	}
	for i, it := range items {
		if len(it) > 127 {
			return nil, bad("stamp list element length")
		}
		n := byte(len(it))
		if i != len(items)-1 {
			n |= 0x80
		}
		b = append(append(b, n), it...)
	}
	return b, nil
}

func (s stamp) encode() (string, error) {
	b := make([]byte, 9, 96)
	b[0] = s.kind
	for i := 0; i < 8; i++ {
		b[1+i] = byte(s.props >> (8 * i))
	}
	var err error
	if b, err = appendLP(b, s.addr); err != nil {
		return "", err
	}
	if b, err = appendVLP(b, nil); err != nil { // no hashes
		return "", err
	}
	if b, err = appendLP(b, s.host); err != nil {
		return "", err
	}
	if s.kind == stampDoH {
		if b, err = appendLP(b, s.path); err != nil {
			return "", err
		}
	}
	// The list is optional at the end; it is written only when it has members.
	if len(s.bootstrap) > 0 {
		if b, err = appendVLP(b, s.bootstrap); err != nil {
			return "", err
		}
	}
	return "sdns://" + base64.RawURLEncoding.EncodeToString(b), nil
}

// protocolStamps makes the hostname stamp and the two address stamps of one
// protocol. The hostname stamp comes first: an app that takes one stamp must get
// the one that resolves the hostname through the nodes and follows the failover
// of SC 8a.3. An address stamp alone would pin it to one node for good. The
// address stamps keep the hostname and the bootstrap list ("otherwise the
// same", SC 8a.8), so the TLS name check is the same on every one.
func protocolStamps(kind byte, host, path string, primary, fallback netip.Addr) (ProtocolStamps, error) {
	boot := []string{stampAddr(primary), stampAddr(fallback)}
	base := stamp{kind: kind, host: host, path: path, bootstrap: boot}
	var out ProtocolStamps
	var err error
	if out.HostnameStamp, err = base.encode(); err != nil {
		return ProtocolStamps{}, err
	}
	for _, ip := range []netip.Addr{primary, fallback} {
		s := base
		s.addr = stampAddr(ip)
		text, err := s.encode()
		if err != nil {
			return ProtocolStamps{}, err
		}
		out.AddressStamps = append(out.AddressStamps, AddressStamp{IP: ip, Stamp: text})
	}
	return out, nil
}

func buildStamps(host, dohPath string, primary, fallback netip.Addr) (*Stamps, error) {
	var st Stamps
	var err error
	if st.DoH, err = protocolStamps(stampDoH, host, dohPath, primary, fallback); err != nil {
		return nil, fmt.Errorf("doh stamp: %w", err)
	}
	if st.DoT, err = protocolStamps(stampDoT, host, "", primary, fallback); err != nil {
		return nil, fmt.Errorf("dot stamp: %w", err)
	}
	if st.DoQ, err = protocolStamps(stampDoQ, host, "", primary, fallback); err != nil {
		return nil, fmt.Errorf("doq stamp: %w", err)
	}
	return &st, nil
}
