// Package netkey names the "source network" of a client address, the unit that
// rate limits and login throttles count on (spec 4.5, 14.1). One mobile carrier
// NAT can put many users on one IPv4 address, and one IPv6 subscriber holds a
// whole /64, so single addresses are the wrong thing to count.
package netkey

import "net/netip"

// Net is the source network: the /24 of an IPv4 address and the /64 of an IPv6
// one. It is the same key auth_otp_issue uses for the ip scope, so one client
// has one network everywhere.
func Net(a netip.Addr) string {
	a = a.Unmap()
	if !a.IsValid() {
		return ""
	}
	if a.Is4() {
		return netip.PrefixFrom(a, 24).Masked().String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

// Wide is the IPv6 /48 that holds the client's /64, and false for IPv4. One /48
// holds 65,536 /64s, so an attacker with one allocation can rotate through them;
// the second bucket on the /48 is what stops that (spec 14.1).
func Wide(a netip.Addr) (string, bool) {
	a = a.Unmap()
	if !a.IsValid() || a.Is4() {
		return "", false
	}
	return netip.PrefixFrom(a, 48).Masked().String(), true
}
