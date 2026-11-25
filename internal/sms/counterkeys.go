package sms

import "net/netip"

// CounterKey names one row of sms_counters. It lives here, and not in the store, on
// purpose: the store has no method that takes one. The only counter an unsent OTP gives
// back is the world-wide one (store.GlobalTx.CountersRefund), so a key list has no use anywhere but in
// the test that compares this file with auth_otp_issue, and a refund of any other row has
// no type to travel in (rule known-unknown-oracle, review round 6, sms-r6-1).
type CounterKey struct {
	Scope string
	Key   string
}

// OTPCounterKeys returns the rows of sms_counters that auth_otp_issue bumped for
// one challenge. Nothing in production reads it: the refund of an unsent code is the
// global key alone and the store knows that key by itself. It stays as the second
// statement of what the function writes, because the catalog test runs the function and
// compares its rows with this list for each case, so a change to either side fails there.
//
// ip is the address of the request (already unmapped from ::ffff:). trusted says the
// request came from a known device: it counts on its own phone key and leaves the shared
// ones alone. A decoy is listed too, without the global key: the function probes and
// locks one shard of the global count (one of sixteen, chosen at random, since 0055 db-r18-2) for a decoy
// as well and may create it at count zero (0052, tenant-r16-11), but it counts nothing there, so the list
// names the rows that moved a count and the catalog test leaves a zero global shard out when it compares.
func OTPCounterKeys(phone string, ip netip.Addr, trusted, decoy bool) []CounterKey {
	ip = ip.Unmap()
	var keys []CounterKey
	var net string
	if ip.Is4() {
		net = netPrefix(ip, 24)
		keys = append(keys, CounterKey{Scope: "ip", Key: ip.String()}, CounterKey{Scope: "ip", Key: net})
	} else {
		net = netPrefix(ip, 64)
		keys = append(keys, CounterKey{Scope: "ip", Key: net}, CounterKey{Scope: "ip", Key: netPrefix(ip, 48)})
	}
	if trusted {
		keys = append(keys, CounterKey{Scope: "phone", Key: phone + "|trusted"})
	} else {
		keys = append(keys, CounterKey{Scope: "phone_net", Key: phone + "|" + net}, CounterKey{Scope: "phone", Key: phone})
	}
	if !decoy {
		keys = append(keys, CounterKey{Scope: "global", Key: "all"})
	}
	return keys
}

// netPrefix is Postgres's network(set_masklen(ip, bits))::text: the masked
// address, a slash and the length.
func netPrefix(ip netip.Addr, bits int) string {
	return netip.PrefixFrom(ip, bits).Masked().String()
}
