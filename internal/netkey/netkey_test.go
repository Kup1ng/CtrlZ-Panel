package netkey_test

import (
	"net/netip"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/netkey"
)

func TestNetAndWide(t *testing.T) {
	cases := []struct {
		ip, net, wide string
	}{
		{"203.0.113.77", "203.0.113.0/24", ""},
		{"::ffff:203.0.113.77", "203.0.113.0/24", ""},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64", "2001:db8:1::/48"},
		{"2001:db8:1:ffff::1", "2001:db8:1:ffff::/64", "2001:db8:1::/48"},
	}
	for _, c := range cases {
		a := netip.MustParseAddr(c.ip)
		if got := netkey.Net(a); got != c.net {
			t.Errorf("Net(%s) = %s, want %s", c.ip, got, c.net)
		}
		w, ok := netkey.Wide(a)
		if (c.wide != "") != ok || w != c.wide {
			t.Errorf("Wide(%s) = %q,%v, want %q", c.ip, w, ok, c.wide)
		}
	}
	if netkey.Net(netip.Addr{}) != "" {
		t.Error("the zero address has no network")
	}
}
