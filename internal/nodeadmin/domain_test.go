package nodeadmin_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
)

func TestValidZone(t *testing.T) {
	for zone, want := range map[string]bool{
		"dns.example.ir":         true,
		"dns.sub.example.com":    true,
		"dns.example.co.ir":      true,  // example.co.ir is a name someone owns under the public suffix co.ir
		"dns.ir":                 false, // one label after dns.
		"dns.co.ir":              false, // a public suffix
		"dns.blogspot.com":       false, // a private-section public suffix
		"example.ir":             false, // no dns. prefix
		"dnsx.example.ir":        false,
		"DNS.example.ir":         false, // the route lowers first; a capital here is refused
		"dns.example.ir.":        false,
		"dns..example.ir":        false,
		"dns.-example.ir":        false,
		"dns.exa_mple.ir":        false,
		"dns.":                   false,
		"":                       false,
		"dns.example.ir/path":    false,
		"dns.example.ir:8443":    false,
		"dns.xn--mgba3a4f16a.ir": false, // the IDN suffix of .ir that the list holds, in punycode
	} {
		if got := nodeadmin.ValidZone(zone); got != want {
			t.Errorf("ValidZone(%q) = %v, want %v", zone, got, want)
		}
	}
	// A label of 64 characters is one too long.
	long := "dns."
	for i := 0; i < 64; i++ {
		long += "a"
	}
	if nodeadmin.ValidZone(long + ".ir") {
		t.Error("a 64-character label was accepted")
	}
}

func TestCheckDomain(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	later, earlier := now.Add(24*time.Hour), now.Add(-24*time.Hour)
	set := nodeadmin.DomainState{DNSZone: "dns.example.ir"}
	phasing := nodeadmin.DomainState{DNSZone: "dns.example.ir", PrevDNSZone: "dns.old.ir", TransitionUntil: &later}
	phased := nodeadmin.DomainState{DNSZone: "dns.example.ir", PrevDNSZone: "dns.old.ir", TransitionUntil: &earlier}
	cases := []struct {
		name string
		in   nodeadmin.DomainInput
		cur  nodeadmin.DomainState
		want error
	}{
		{"first set", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "panel.example.ir", AdminHost: "admin.example.ir"}, nodeadmin.DomainState{}, nil},
		{"hosts cleared", nodeadmin.DomainInput{DNSZone: "dns.example.ir"}, set, nil},
		{"a host edit only", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "p.example.ir"}, phasing, nil},
		{"a zone change after the last one ended", nodeadmin.DomainInput{DNSZone: "dns.new.ir"}, phased, nil},
		{"a zone change", nodeadmin.DomainInput{DNSZone: "dns.new.ir"}, set, nil},
		{"a zone change during a transition", nodeadmin.DomainInput{DNSZone: "dns.new.ir"}, phasing, nodeadmin.ErrTransition},
		{"a bad zone", nodeadmin.DomainInput{DNSZone: "dns.co.ir"}, set, nodeadmin.ErrDomain},
		{"a panel under the zone", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "panel.dns.example.ir"}, set, nodeadmin.ErrDomain},
		{"a panel equal to the zone", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "dns.example.ir"}, set, nodeadmin.ErrDomain},
		{"a panel under the new zone", nodeadmin.DomainInput{DNSZone: "dns.new.ir", PanelHost: "a.dns.new.ir"}, set, nodeadmin.ErrDomain},
		{"a panel under the old zone during a transition", nodeadmin.DomainInput{DNSZone: "dns.example.ir", AdminHost: "a.dns.old.ir"}, phasing, nodeadmin.ErrDomain},
		{"a panel under the old zone after it ended", nodeadmin.DomainInput{DNSZone: "dns.example.ir", AdminHost: "a.dns.old.ir"}, phased, nil},
		{"a host that only ends like the zone", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "xdns.example.ir"}, set, nil},
		{"a host with a capital", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "Panel.example.ir"}, set, nodeadmin.ErrDomain},
		{"a host with a port", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "panel.example.ir:443"}, set, nodeadmin.ErrDomain},
		{"one name for both", nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: "x.example.ir", AdminHost: "x.example.ir"}, set, nodeadmin.ErrDomain},
	}
	for _, tc := range cases {
		err := nodeadmin.CheckDomain(tc.in, tc.cur, now)
		if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// A request that names no host leaves the host that serves now in force, and a zone must not swallow it (R34-r1-10); a
// host too long for the name of its Caddy snippet is refused where the admin can still change it (R34-r1-12).
func TestCheckDomainJudgesTheHostThatServes(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	served := nodeadmin.DomainState{DNSZone: "dns.old.ir", ServedPanel: "panel.dns.example.ir", ServedAdmin: "admin.example.ir"}
	in := nodeadmin.DomainInput{DNSZone: "dns.example.ir"}
	if err := nodeadmin.CheckDomain(in, served, now); !errors.Is(err, nodeadmin.ErrDomain) {
		t.Errorf("a zone over the served panel host: %v", err)
	}
	if f := nodeadmin.FailedDomainField(in, served, now); f != "panel_host" {
		t.Errorf("the failing field is %q", f)
	}
	// A request that names its own panel host is judged on that one, and the admin host that serves is outside the zone.
	in.PanelHost = "panel.example.ir"
	if err := nodeadmin.CheckDomain(in, served, now); err != nil {
		t.Errorf("a moved panel host is refused: %v", err)
	}
	// The served hosts are not judged by the grammar: a refusal for text the install chose would lock the admin out.
	odd := nodeadmin.DomainState{ServedPanel: "Panel_Odd", ServedAdmin: "admin.example.ir"}
	if err := nodeadmin.CheckDomain(nodeadmin.DomainInput{DNSZone: "dns.example.ir"}, odd, now); err != nil {
		t.Errorf("a served host of odd text blocks the zone: %v", err)
	}
	// The served hosts equal: one name for both dashboards.
	same := nodeadmin.DomainState{ServedPanel: "x.example.ir", ServedAdmin: "x.example.ir"}
	if err := nodeadmin.CheckDomain(nodeadmin.DomainInput{DNSZone: "dns.example.ir"}, same, now); !errors.Is(err, nodeadmin.ErrDomain) {
		t.Errorf("one served name for both: %v", err)
	}

	long := strings.Repeat(strings.Repeat("a", 61)+".", 4) + "bb" // 250 bytes
	if len(long) <= nodeadmin.MaxServedHost || !nodeadmin.ValidHost(long) {
		t.Fatalf("the test host is %d bytes", len(long))
	}
	if err := nodeadmin.CheckDomain(nodeadmin.DomainInput{DNSZone: "dns.example.ir", PanelHost: long}, nodeadmin.DomainState{}, now); !errors.Is(err, nodeadmin.ErrDomain) {
		t.Errorf("a host over the length of a snippet name: %v", err)
	}
}
