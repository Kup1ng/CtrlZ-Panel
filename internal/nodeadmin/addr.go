// Package nodeadmin is what the admin routes of nodes need and no route should write twice (p4-nodes 4.2,
// 9.2): the checks of a node's addresses, the PairTable a change of membership would produce and its
// validity, and the install command shown once when an enrolment is made.
//
// None of it touches the database or the clock: the store hands rows in and the route hands the time in,
// so every rule here can be tested with plain values.
package nodeadmin

import (
	"errors"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// ErrAddress is the one refusal of an address. Its text names the rule, never the value: the answer to the
// admin is the code address_refused with the field that failed.
var ErrAddress = errors.New("nodeadmin: address refused")

// ParseAddr reads an address typed by the admin or sent by a host. A zone, a prefix length and any text
// netip does not read as a plain address are refused; so is every form that embeds an IPv4 address in an
// IPv6 one (SC 11), because the database CHECKs of nodes refuse them and a node judged by its embedded
// address would be judged by an address nobody typed.
func ParseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || embedsIPv4(a) {
		return netip.Addr{}, ErrAddress
	}
	return a, nil
}

// embedsIPv4 says whether an IPv6 address is one of the five forms that carry an IPv4 address: IPv4-mapped
// (::ffff:0:0/96), NAT64 (64:ff9b::/96), IPv4-compatible (::/96), 6to4 (2002::/16) and Teredo (2001::/32).
// It looks at the bytes of an operator's node address, never a client's, which is why it is the one function
// of this package the network-cut lint lists.
func embedsIPv4(a netip.Addr) bool {
	if a.Is4In6() {
		return true
	}
	if !a.Is6() {
		return false
	}
	b := a.As16()
	zero := func(from, to int) bool {
		for _, x := range b[from:to] {
			if x != 0 {
				return false
			}
		}
		return true
	}
	switch {
	case zero(0, 12): // ::/96
		return true
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && zero(4, 12): // 64:ff9b::/96
		return true
	case b[0] == 0x20 && b[1] == 0x02: // 2002::/16
		return true
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0: // 2001::/32
		return true
	}
	return false
}

// CheckBind judges an address a node binds its listeners to. It may be private (1:1 NAT, 4.2 step 4) but
// must be an address a socket can be bound to.
func CheckBind(a netip.Addr) error {
	if !a.IsValid() || a.Zone() != "" || embedsIPv4(a) || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return ErrAddress
	}
	return nil
}

// CheckAdvertised judges an address the node is reached on from outside: public, except in a lab build
// (SC 8a.7), the same rule zone.Build applies to the table, so the refusal comes at the form and not at the
// table.
func CheckAdvertised(a netip.Addr) error {
	if err := CheckBind(a); err != nil {
		return err
	}
	if netclass.ClassOf(a) == netclass.Public || (netclass.AllowPrivatePairAddrs && netclass.ClassOf(a) == netclass.Private) {
		return nil
	}
	return ErrAddress
}

// AddrText is the text of an operator's node address for the admin API and the install command. It is one
// function so that the string form of an address, which the network-cut lint treats as a way to cut a
// client's network, is made in one place that handles infrastructure addresses only.
func AddrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.Unmap().String()
}

// PrefixText is the text of a claimed prefix for the report of a node, for the same reason as AddrText: one place
// renders addresses and prefixes of this package's callers.
func PrefixText(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}
