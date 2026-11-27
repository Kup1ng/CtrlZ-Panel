package netclass

import (
	"net/netip"
	"testing"
)

func TestClassOf(t *testing.T) {
	cases := map[string]Class{
		"93.184.216.34": Public, "8.8.8.8": Public, "2606:2800:220:1::1": Public, "64:ff9b::808:808": Public,
		// Embedded IPv4 decides the class: NAT64, IPv4-compatible, 6to4, Teredo.
		"64:ff9b::c0a8:101": Private, "64:ff9b::a00:1": Private, "64:ff9b::7f00:1": Loopback, "64:ff9b::6440:1": CGNAT,
		"::192.168.1.1": Private, "::8.8.8.8": Public, "2002:c0a8:101::1": Private, "2002:808:808::1": Public,
		"2001:0:c0a8:101::1": Private, "2001:0:808:808:0:0:3f57:fefe": Private, "2001:0:808:808:0:0:f7f7:f7f7": Public,
		"10.1.2.3": Private, "172.16.0.1": Private, "172.31.255.255": Private, "172.32.0.1": Public, "192.168.1.1": Private, "fd00::1": Private,
		"10.10.34.5": Injected, "10.10.35.5": Private,
		"127.0.0.1": Loopback, "::1": Loopback, "169.254.1.1": LinkLocal, "fe80::1": LinkLocal,
		"100.64.0.1": CGNAT, "100.127.255.255": CGNAT, "100.128.0.1": Public,
		"224.0.0.1": Multicast, "ff02::1": Multicast,
		"0.0.0.0": Reserved, "240.0.0.1": Reserved, "255.255.255.255": Reserved, "192.0.2.1": Reserved, "2001:db8::1": Reserved, "::": Reserved,
		"::ffff:10.0.0.1": Private, "::ffff:8.8.8.8": Public,
		// L1-F13: the rest of ::/96, site-local and the 6to4 relay block.
		"::7f00:1": Loopback, "::a00:1": Private, "::c0a8:101": Private, "::a9fe:1": LinkLocal, "::808:808": Public, "::2": Reserved,
		"fec0::1": Private, "feff::1": Private, "febf::1": LinkLocal,
		"192.88.99.1": Reserved, "192.88.99.255": Reserved, "192.88.98.255": Public, "192.88.100.0": Public,
	}
	for in, want := range cases {
		if got := ClassOf(netip.MustParseAddr(in)); got != want {
			t.Errorf("%s: got %v want %v", in, got, want)
		}
	}
	if ClassOf(netip.Addr{}) != Reserved {
		t.Error("invalid address")
	}
}
