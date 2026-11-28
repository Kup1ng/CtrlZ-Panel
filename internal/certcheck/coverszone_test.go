package certcheck_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/certcheck"
)

func TestCoversZone(t *testing.T) {
	const zone = "dns.example.org"
	full := []string{"dns.example.org", "*.dns.example.org", "*.verify.dns.example.org"}
	cases := []struct {
		name string
		sans []string
		zone string
		want bool
	}{
		{"all three names", full, zone, true},
		{"a parent wildcard covers the zone only, not its wildcard names", []string{"*.example.org"}, zone, false},
		{"the parent wildcard with the two others", []string{"*.example.org", "*.dns.example.org", "*.verify.dns.example.org"}, zone, true},
		{"one name missing", []string{"dns.example.org", "*.dns.example.org"}, zone, false},
		{"a wildcard stands for one label", []string{"dns.example.org", "*.dns.example.org"}, "a.dns.example.org", false},
		{"another zone", full, "dns.example.net", false},
		{"no zone", full, "", false},
		{"a bare wildcard", []string{"*."}, zone, false},
		{"a suffix is not a label", []string{"*.ample.org", "*.dns.example.org", "*.verify.dns.example.org"}, zone, false},
	}
	for _, c := range cases {
		if got := certcheck.CoversZone(c.sans, c.zone); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}
