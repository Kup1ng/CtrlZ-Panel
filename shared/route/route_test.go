package route

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

type geo map[string]map[string]bool

func (g geo) Has(tag string, n *names.Name) bool { return g[tag][n.String()] }

func mustRule(t *testing.T, order uint32, mt, mv, group string, final bool) Rule {
	t.Helper()
	r, err := ParseRule(order, mt, mv, group, final)
	if err != nil {
		t.Fatalf("%s %s: %v", mt, mv, err)
	}
	return r
}

func TestMatchEachCondition(t *testing.T) {
	rs := []Rule{
		mustRule(t, 1, "domain", "exact.example.com", "g-domain", false),
		mustRule(t, 2, "suffix", "example.ir", "g-suffix", false),
		mustRule(t, 3, "geosite", "geosite:ir", "g-geo", false),
		mustRule(t, 4, "qtype", "MX", "g-mx", false),
		mustRule(t, 5, "tld", "ir", "g-tld", false),
		mustRule(t, 9, "", "", "g-default", true),
	}
	gs := geo{"geosite:ir": {"digikala.example": true}}
	cases := []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"exact.example.com", 1, "g-domain"},
		{"sub.exact.example.com", 1, "g-default"},
		{"example.ir", 1, "g-suffix"},
		{"a.b.example.ir", 1, "g-suffix"},
		{"digikala.example", 1, "g-geo"},
		{"mail.other.com", 15, "g-mx"},
		{"other.ir", 1, "g-tld"},
		{"other.com", 1, "g-default"},
	}
	for _, c := range cases {
		n := names.MustString(c.name)
		got, ok := Match(rs, &n, c.qtype, gs)
		if !ok || got != c.want {
			t.Errorf("%s/%d: got %q %v want %q", c.name, c.qtype, got, ok, c.want)
		}
	}
	n := names.MustString("other.com")
	if _, ok := Match(rs[:5], &n, 1, gs); ok {
		t.Error("no final default: expected no match")
	}
}

func TestOrderWinsOverListPosition(t *testing.T) {
	rs := []Rule{
		mustRule(t, 20, "suffix", "example.com", "late", false),
		mustRule(t, 10, "suffix", "example.com", "early", false),
	}
	n := names.MustString("a.example.com")
	if g, _ := Match(rs, &n, 1, nil); g != "early" {
		t.Fatal(g)
	}
}

func TestParseRuleRejects(t *testing.T) {
	bad := [][4]string{
		{"domain", "1.2.3.4", "g", ""}, {"suffix", "", "g", ""}, {"geosite", "ir", "g", ""}, {"geosite", "geosite:", "g", ""},
		{"geosite", "geosite:IR", "g", ""}, {"qtype", "0", "g", ""}, {"qtype", "NOPE", "g", ""}, {"tld", "a.b", "g", ""},
		{"regex", "x", "g", ""}, {"domain", "a.com", "", ""},
	}
	for _, b := range bad {
		if _, err := ParseRule(1, b[0], b[1], b[2], false); err == nil {
			t.Errorf("%v accepted", b)
		}
	}
}
