// Package netclass classifies IP addresses for Rebind protection, the Sanity
// Gate and grant safety. It is table driven and has no I/O.
package netclass

import "net/netip"

// Class is the address class.
type Class uint8

const (
	Public Class = iota
	Private
	Loopback
	LinkLocal
	CGNAT
	Multicast
	Reserved
	// Injected is 10.10.34.0/24, the block-page answer some Iranian networks
	// inject for filtered names. It is listed apart from Private so the Sanity
	// Gate can name it in reports, and it wins over Private because it sits
	// inside 10/8.
	Injected
)

func (c Class) String() string {
	names := [...]string{"public", "private", "loopback", "linklocal", "cgnat", "multicast", "reserved", "injected"}
	if int(c) >= len(names) {
		return "unknown"
	}
	return names[c]
}

type entry struct {
	p netip.Prefix
	c Class
}

// table is ordered most specific first; the first match wins. It is built per
// call from literals because the module forbids package-level mutable state.
func table() []entry {
	m := netip.MustParsePrefix
	return []entry{
		{m("10.10.34.0/24"), Injected},
		{m("10.0.0.0/8"), Private},
		{m("172.16.0.0/12"), Private},
		{m("192.168.0.0/16"), Private},
		{m("127.0.0.0/8"), Loopback},
		{m("169.254.0.0/16"), LinkLocal},
		{m("100.64.0.0/10"), CGNAT},
		{m("224.0.0.0/4"), Multicast},
		{m("0.0.0.0/8"), Reserved},
		{m("192.0.0.0/24"), Reserved},
		{m("192.0.2.0/24"), Reserved},
		// 6to4 relay anycast (RFC 7526, deprecated): no one should answer from it.
		{m("192.88.99.0/24"), Reserved},
		{m("198.18.0.0/15"), Reserved},
		{m("198.51.100.0/24"), Reserved},
		{m("203.0.113.0/24"), Reserved},
		{m("240.0.0.0/4"), Reserved},

		{m("::1/128"), Loopback},
		{m("::/128"), Reserved},
		{m("fe80::/10"), LinkLocal},
		{m("fc00::/7"), Private},
		// Deprecated site-local (RFC 3879); some stacks still route it inside a site.
		{m("fec0::/10"), Private},
		{m("ff00::/8"), Multicast},
		{m("2001:db8::/32"), Reserved},
		{m("100::/64"), Reserved},
	}
}

// ClassOf returns the class of addr. An IPv4-mapped IPv6 address is classified
// by its IPv4 part, because that is what the client would connect to. The same
// goes for the other IPv6 forms that carry an IPv4 destination (NAT64
// 64:ff9b::/96, IPv4-compatible ::/96, 6to4 2002::/16, Teredo 2001::/32): a
// public-looking IPv6 prefix in front of 192.168.1.1 still reaches 192.168.1.1
// on a network that translates it, which is exactly what Rebind exists to
// stop. An invalid address is Reserved. Everything that matches no row is
// public.
func ClassOf(addr netip.Addr) Class {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return Reserved
	}
	for _, e := range table() {
		if e.p.Contains(addr) {
			return e.c
		}
	}
	for _, v4 := range embeddedV4(addr) {
		if c := ClassOf(v4); c != Public {
			return c
		}
	}
	return Public
}

// embeddedV4 returns the IPv4 addresses an IPv6 address stands for, or nil.
// Teredo carries two: the server (in the clear) and the client (bit-flipped).
func embeddedV4(addr netip.Addr) []netip.Addr {
	if !addr.Is6() {
		return nil
	}
	b := addr.As16()
	m := netip.MustParsePrefix
	switch {
	case m("64:ff9b::/96").Contains(addr), m("::/96").Contains(addr):
		return []netip.Addr{netip.AddrFrom4([4]byte(b[12:16]))}
	case m("2002::/16").Contains(addr):
		return []netip.Addr{netip.AddrFrom4([4]byte(b[2:6]))}
	case m("2001::/32").Contains(addr):
		return []netip.Addr{
			netip.AddrFrom4([4]byte(b[4:8])),
			netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}),
		}
	}
	return nil
}

// IsPublic is the check for grant safety (R9): only public passes.
func IsPublic(addr netip.Addr) bool { return ClassOf(addr) == Public }

// RebindPrivate is Rebind's rule: everything except public counts as private,
// because a public name answering with loopback or CGNAT space is just as
// useful to an attacker as one answering with 192.168.x.x.
func RebindPrivate(addr netip.Addr) bool { return ClassOf(addr) != Public }
