package hubctl

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/route"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// geoSet answers membership for one tag, the way the node's catalog does.
type geoSet map[string]map[string]bool

func (g geoSet) Has(tag string, n *names.Name) bool { return g[tag][n.String()] }

func configRead(mode string) store.HubConfigRead {
	u := func(kind, group string, pos int, addr string, boot string) store.HubUpstream {
		h := store.HubUpstream{ID: uuid.New(), Group: group, Position: pos, Kind: kind, Address: addr, TimeoutMS: 2000, HealthSec: 30}
		if boot != "" {
			h.Bootstrap = netip.MustParseAddr(boot)
			h.TLSName = "dns.example.net"
		}
		return h
	}
	return store.HubConfigRead{
		Found: true, Status: "active",
		DNSBind: netip.MustParseAddr("198.51.100.10"), DNSAdv: netip.MustParseAddr("198.51.100.10"),
		ResolveMode: mode, DNSZone: "ctrlz.example",
		PanelHost: "Panel.Example", AdminHost: "admin.example",
		Upstreams: []store.HubUpstream{
			u("udp", "ir", 0, "192.0.2.53:53", ""),
			u("doh", "world", 0, "https://dns.example.net/dns-query", "192.0.2.80"),
			u("dot", "world", 1, "dns.example.net:853", "192.0.2.81"),
			u("doq", "world", 2, "dns.example.net:853", "192.0.2.82"),
		},
		Rules: []store.HubRule{
			{Position: 1, MatchType: "domain", Value: "exact.example.com", Group: "ir"},
			{Position: 2, MatchType: "suffix", Value: "example.ir", Group: "ir"},
			{Position: 3, MatchType: "geosite", Value: "geosite:ir", Group: "ir"},
			{Position: 4, MatchType: "qtype", Value: "MX", Group: "world"},
			{Position: 5, MatchType: "tld", Value: "ir", Group: "ir"},
			// The table keeps a match_type on a final row too; the value is empty.
			{Position: 9, MatchType: "domain", Group: "world", Final: true},
		},
	}
}

func testBuilder() *ConfigBuilder {
	return &ConfigBuilder{ProofKey: make([]byte, 32), Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
}

// T-028: a row of every mode, upstream kind and rule type becomes a NodeConfig the node's own validator accepts, and the
// rules parse and route the way the node's router will route them (the node builds its router from the same route.ParseRule).
func TestBuildHybridConfigOverEveryModeKindAndRuleType(t *testing.T) {
	for mode, want := range map[string]commonv1.ResolveMode{
		"recursive": commonv1.ResolveMode_RESOLVE_MODE_RECURSIVE,
		"upstream":  commonv1.ResolveMode_RESOLVE_MODE_UPSTREAM,
		"hybrid":    commonv1.ResolveMode_RESOLVE_MODE_HYBRID,
	} {
		c, err := testBuilder().Build(configRead(mode))
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if c.Mode != want {
			t.Errorf("%s: mode %v, want %v", mode, c.Mode, want)
		}
		if err := wire.ValidateNodeConfig(c); err != nil {
			t.Errorf("%s: validator: %v", mode, err)
		}
	}

	c, err := testBuilder().Build(configRead("hybrid"))
	if err != nil {
		t.Fatal(err)
	}
	wantKinds := []commonv1.UpstreamKind{commonv1.UpstreamKind_UPSTREAM_KIND_UDP, commonv1.UpstreamKind_UPSTREAM_KIND_DOH,
		commonv1.UpstreamKind_UPSTREAM_KIND_DOT, commonv1.UpstreamKind_UPSTREAM_KIND_DOQ}
	if len(c.Upstreams) != len(wantKinds) {
		t.Fatalf("%d upstreams", len(c.Upstreams))
	}
	for i, k := range wantKinds {
		if c.Upstreams[i].Kind != k {
			t.Errorf("upstream %d kind %v, want %v", i, c.Upstreams[i].Kind, k)
		}
	}
	if len(c.Groups) != 2 || c.Groups[0].Name != "ir" || len(c.Groups[1].UpstreamIds) != 3 {
		t.Fatalf("groups %v", c.Groups)
	}
	if len(c.PanelHostnames) != 2 || c.PanelHostnames[0] != "panel.example" {
		t.Errorf("panel hostnames %v (lower case, both hosts)", c.PanelHostnames)
	}

	var rules []route.Rule
	for _, r := range c.Rules {
		pr, err := route.ParseRule(r.Order, r.MatchType, r.MatchValue, r.Group, r.FinalDefault)
		if err != nil {
			t.Fatalf("rule %d: %v", r.Order, err)
		}
		rules = append(rules, pr)
	}
	geo := geoSet{"geosite:ir": {"digikala.example": true}}
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"exact.example.com", 1, "ir"},        // domain
		{"a.b.example.ir", 1, "ir"},           // suffix
		{"digikala.example", 1, "ir"},         // geosite
		{"mail.other.example", 15, "world"},   // qtype MX
		{"foo.ir", 1, "ir"},                   // tld
		{"anything.example.org", 1, "world"},  // final default
		{"sub.exact.example.com", 1, "world"}, // domain is exact only
	} {
		n, err := names.ParseUser(tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := route.Match(rules, &n, tc.qtype, geo); got != tc.want {
			t.Errorf("%s/%d routes to %q, want %q", tc.name, tc.qtype, got, tc.want)
		}
	}
}

// The word the schema and the contract use for the third mode is hybrid. A row saying anything else would reach the node as
// mode 0, so the build refuses it and the node stays on its last config.
func TestBuildRefusesAModeTheSchemaDoesNotKnow(t *testing.T) {
	for _, mode := range []string{"mixed", ""} {
		if _, err := testBuilder().Build(configRead(mode)); err == nil {
			t.Errorf("mode %q built", mode)
		}
	}
}

// A geosite value must carry the prefix the route package requires; a row without it is refused whole, never half sent.
func TestBuildRefusesAGeositeRuleWithoutItsPrefix(t *testing.T) {
	r := configRead("hybrid")
	r.Rules[2].Value = "ir"
	if _, err := testBuilder().Build(r); err == nil {
		t.Fatal("geosite rule without the geosite: prefix built")
	}
}
