package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const (
	tRID   = "abcdefghijklmnopqrstuvwxy2"
	tToken = "abcdefghijklmnopqrstuvwxyz234567"
)

// goldenCase is one entry of testdata/views.json. The file was produced by an
// encoder written separately from the Go one (a Node script from the stamp
// specification), so the stamps are not the code's own output checked against
// itself.
type goldenCase struct {
	Name     string                  `json:"name"`
	RID      string                  `json:"rid"`
	Token    string                  `json:"token"`
	Client   string                  `json:"client"`
	Zone     string                  `json:"zone"`
	Primary  string                  `json:"primary"`
	Fallback string                  `json:"fallback"`
	Host     string                  `json:"host"`
	DoHURL   string                  `json:"doh_url"`
	Raw      map[string]goldenStamps `json:"stamps"`
}

type goldenStamps struct {
	Hostname string `json:"hostname_stamp"`
	Address  []struct {
		IP    string `json:"ip"`
		Stamp string `json:"stamp"`
	} `json:"address_stamps"`
}

func loadGolden(t *testing.T) []goldenCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/views.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 3 {
		t.Fatalf("golden file holds %d cases", len(cases))
	}
	return cases
}

func (c goldenCase) input() Input {
	return Input{
		ResolverID: c.RID, DoHToken: c.Token, Client: c.Client, Zone: c.Zone,
		Primary: netip.MustParseAddr(c.Primary), Fallback: netip.MustParseAddr(c.Fallback),
	}
}

func readyView(t *testing.T) ResolverView {
	t.Helper()
	v, err := View(Input{
		ResolverID: tRID, DoHToken: tToken, Zone: "dns.example.com",
		Primary: netip.MustParseAddr("203.0.113.10"), Fallback: netip.MustParseAddr("203.0.113.20"),
	})
	if err != nil || !v.Ready {
		t.Fatalf("view: ready=%v err=%v", v.Ready, err)
	}
	return v
}

func TestViewGolden(t *testing.T) {
	for _, c := range loadGolden(t) {
		t.Run(c.Name, func(t *testing.T) {
			v, err := View(c.input())
			if err != nil {
				t.Fatal(err)
			}
			if !v.Ready || v.Reason != "" {
				t.Fatalf("ready=%v reason=%q", v.Ready, v.Reason)
			}
			if v.Host != c.Host || v.DoHURL != c.DoHURL {
				t.Fatalf("host or URL differs: %q %q", v.Host, v.DoHURL)
			}
			if v.Legacy.DNS1.String() != c.Primary || v.Legacy.DNS2.String() != c.Fallback {
				t.Fatal("legacy addresses are not primary then fallback")
			}
			if got := v.Bootstrap; len(got) != 2 || got[0].String() != c.Primary || got[1].String() != c.Fallback {
				t.Fatalf("bootstrap order: %v", got)
			}
			for name, got := range map[string]ProtocolStamps{"doh": v.Stamps.DoH, "dot": v.Stamps.DoT, "doq": v.Stamps.DoQ} {
				want := c.Raw[name]
				if got.HostnameStamp != want.Hostname {
					t.Errorf("%s hostname stamp:\n got %s\nwant %s", name, got.HostnameStamp, want.Hostname)
				}
				if len(got.AddressStamps) != 2 || len(want.Address) != 2 {
					t.Fatalf("%s: %d address stamps", name, len(got.AddressStamps))
				}
				for i, a := range got.AddressStamps {
					if a.IP.String() != want.Address[i].IP || a.Stamp != want.Address[i].Stamp {
						t.Errorf("%s address stamp %d:\n got %s %s\nwant %s %s", name, i, a.IP, a.Stamp, want.Address[i].IP, want.Address[i].Stamp)
					}
				}
			}
		})
	}
}

// Every host and URL of a view reads back to the Endpoint and client it was made
// for, through the grammar the node uses (SC 3.2, 3.4).
func TestViewParsesBack(t *testing.T) {
	for _, c := range loadGolden(t) {
		v, err := View(c.input())
		if err != nil {
			t.Fatal(err)
		}
		zone := []names.Name{names.MustString(c.Zone)}
		h := identity.ParseHost(v.Host, zone)
		if h.Kind != identity.HostResolver || h.RID != c.RID || h.Client != c.Client {
			t.Errorf("%s: host %+v", c.Name, h)
		}
		const prefix = "https://"
		rest := strings.TrimPrefix(v.DoHURL, prefix)
		host, path, ok := strings.Cut(rest, "/")
		if !ok || host != v.Host {
			t.Fatalf("%s: DoH URL shape", c.Name)
		}
		p, err := identity.ParseDoHPath("/" + path)
		if err != nil || p.Form != 'A' || p.Token != c.Token || p.Client != "" {
			t.Errorf("%s: DoH path %+v %v", c.Name, p, err)
		}
		target, err := identity.ResolveDoH("/"+path, v.Host, zone)
		if err != nil || target.RID != c.RID || target.Token != c.Token || target.Client != c.Client {
			t.Errorf("%s: ResolveDoH %+v %v", c.Name, target, err)
		}
	}
}

func TestProtocolsAreExactlyD24AndD51(t *testing.T) {
	want := []Protocol{"plain", "doh", "doh3", "dot", "doq"}
	if got := Protocols(); !slices.Equal(got, want) {
		t.Fatalf("protocols %v", got)
	}
	// A caller that changes its copy changes nobody else's.
	p := Protocols()
	p[0] = "dnscrypt"
	if Protocols()[0] != PlainDNS {
		t.Fatal("Protocols shares its slice")
	}
	v := readyView(t)
	if !slices.Equal(v.Protocols, want) {
		t.Fatalf("view protocols %v", v.Protocols)
	}
	for _, p := range want {
		if len(v.Values(p)) == 0 {
			t.Errorf("no values for %s", p)
		}
	}
	if v.Values("dnscrypt") != nil {
		t.Fatal("values for a protocol that is not served")
	}
	// DoH3 is the DoH URL (D51), and the view has no stamp for it.
	if !slices.Equal(v.Values(DoH3), v.Values(DoH)) {
		t.Fatal("DoH3 is not the DoH URL")
	}
	if got := v.Values(PlainDNS); got[0] != "203.0.113.10" || got[1] != "203.0.113.20" {
		t.Fatalf("plain values %v", got)
	}
	if v.Values(DoT)[0] != v.Host || v.Values(DoQ)[0] != v.Host {
		t.Fatal("DoT and DoQ take the hostname")
	}
}

func TestViewNotReady(t *testing.T) {
	pair := func() (netip.Addr, netip.Addr) {
		return netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.20")
	}
	p, f := pair()
	cases := map[string]struct {
		in     Input
		reason Reason
	}{
		"no zone":                {Input{Zone: "", Primary: p, Fallback: f}, ReasonZoneMissing},
		"no zone and no pair":    {Input{}, ReasonZoneMissing},
		"no pair":                {Input{Zone: "dns.example.com"}, ReasonPairMissing},
		"no fallback":            {Input{Zone: "dns.example.com", Primary: p}, ReasonPairMissing},
		"no primary":             {Input{Zone: "dns.example.com", Fallback: f}, ReasonPairMissing},
		"unspecified":            {Input{Zone: "dns.example.com", Primary: p, Fallback: netip.IPv4Unspecified()}, ReasonPairMissing},
		"loopback":               {Input{Zone: "dns.example.com", Primary: netip.MustParseAddr("127.0.0.1"), Fallback: f}, ReasonPairMissing},
		"multicast":              {Input{Zone: "dns.example.com", Primary: netip.MustParseAddr("224.0.0.1"), Fallback: f}, ReasonPairMissing},
		"mapped":                 {Input{Zone: "dns.example.com", Primary: netip.MustParseAddr("::ffff:203.0.113.10"), Fallback: f}, ReasonPairMissing},
		"zoned":                  {Input{Zone: "dns.example.com", Primary: netip.MustParseAddr("fe80::1%eth0"), Fallback: f}, ReasonPairMissing},
		"link-local is not used": {Input{Zone: "dns.example.com", Primary: netip.MustParseAddr("fe80::1%eth0"), Fallback: netip.MustParseAddr("fe80::2%eth0")}, ReasonPairMissing},
		"link-local unicast":     {Input{Zone: "dns.example.com", Primary: netip.MustParseAddr("fe80::1"), Fallback: netip.MustParseAddr("fe80::2")}, ReasonPairMissing},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			c.in.ResolverID, c.in.DoHToken = tRID, tToken
			v, err := View(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if v.Ready || v.Reason != c.reason {
				t.Fatalf("ready=%v reason=%q", v.Ready, v.Reason)
			}
			// Nothing to generate from: no host, URL, address or stamp.
			if v.Host != "" || v.DoHURL != "" || v.Legacy != nil || v.Bootstrap != nil || v.Stamps != nil {
				t.Fatal("a not-ready view holds values")
			}
			if len(v.Protocols) != 5 || v.ResolverID != tRID {
				t.Fatal("the protocol list and the id are given even when not ready")
			}
			for _, g := range Generators() {
				if out, err := g.Run(v); !errors.Is(err, ErrNotReady) || out != "" {
					t.Errorf("%s generated from a view that is not ready", g.ID)
				}
			}
			if v.Values(DoH) != nil {
				t.Fatal("values from a view that is not ready")
			}
		})
	}
}

func TestViewRefusesBadInput(t *testing.T) {
	p, f := netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.20")
	ok := Input{ResolverID: tRID, DoHToken: tToken, Zone: "dns.example.com", Primary: p, Fallback: f}
	mut := func(fn func(*Input)) Input { in := ok; fn(&in); return in }
	cases := map[string]Input{
		"short id":            mut(func(i *Input) { i.ResolverID = tRID[:25] }),
		"upper id":            mut(func(i *Input) { i.ResolverID = strings.ToUpper(tRID) }),
		"hyphen in id":        mut(func(i *Input) { i.ResolverID = tRID[:25] + "-" }),
		"empty token":         mut(func(i *Input) { i.DoHToken = "" }),
		"short token":         mut(func(i *Input) { i.DoHToken = tToken[:31] }),
		"token with slash":    mut(func(i *Input) { i.DoHToken = tToken[:31] + "/" }),
		"upper client":        mut(func(i *Input) { i.Client = "Kid" }),
		"edge hyphen":         mut(func(i *Input) { i.Client = "-kid" }),
		"long client":         mut(func(i *Input) { i.Client = strings.Repeat("a", 37) }),
		"dot in client":       mut(func(i *Input) { i.Client = "a.b" }),
		"zone not under dns.": mut(func(i *Input) { i.Zone = "example.com" }),
		"zone upper":          mut(func(i *Input) { i.Zone = "DNS.Example.com" }),
		"zone trailing dot":   mut(func(i *Input) { i.Zone = "dns.example.com." }),
		"zone ip":             mut(func(i *Input) { i.Zone = "10.0.0.1" }),
		"zone has space":      mut(func(i *Input) { i.Zone = "dns example.com" }),
		"equal pair":          mut(func(i *Input) { i.Fallback = p }),
		"host too long":       mut(func(i *Input) { i.Zone = strings.Repeat("a.", 110) + "example.com" }),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := View(in)
			if !errors.Is(err, ErrInput) {
				t.Fatalf("err = %v, ready=%v", err, v.Ready)
			}
			// The token is a secret and never rides an error.
			if strings.Contains(err.Error(), tToken) {
				t.Fatal("the error holds the token")
			}
			if v.Ready || v.Host != "" || v.DoHURL != "" {
				t.Fatal("a refused input gave a view")
			}
		})
	}
	// The longest client label still fits: 26 + 1 + 36 + the zone.
	in := ok
	in.Client = strings.Repeat("a", 36)
	if _, err := View(in); err != nil {
		t.Fatalf("longest client: %v", err)
	}
}

func TestViewIsASecret(t *testing.T) {
	v := readyView(t)
	for _, s := range []string{
		fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v),
		fmt.Sprintf("%v", &v), fmt.Sprintf("%+v", []ResolverView{v}),
	} {
		if strings.Contains(s, tToken) || strings.Contains(s, "203.0.113") {
			t.Fatalf("a formatted view leaks: %s", s)
		}
	}
}

// The JSON of a view is the P3 9.3 schema.
func TestViewJSONShape(t *testing.T) {
	v := readyView(t)
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ready", "resolver_id", "host", "doh_url", "legacy", "bootstrap", "stamps", "protocols"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if _, ok := m["reason"]; ok {
		t.Error("a ready view has a reason")
	}
	if _, ok := m["client"]; ok {
		t.Error("a view with no client has a client key")
	}
	legacy := m["legacy"].(map[string]any)
	if legacy["dns1"] != "203.0.113.10" || legacy["dns2"] != "203.0.113.20" {
		t.Errorf("legacy %v", legacy)
	}
	stamps := m["stamps"].(map[string]any)
	if len(stamps) != 3 {
		t.Errorf("stamps keys %v", stamps)
	}
	for _, p := range []string{"doh", "dot", "doq"} {
		ps := stamps[p].(map[string]any)
		as := ps["address_stamps"].([]any)
		if len(as) != 2 || as[0].(map[string]any)["ip"] != "203.0.113.10" {
			t.Errorf("%s address stamps %v", p, as)
		}
	}

	nr, _ := View(Input{ResolverID: tRID, DoHToken: tToken})
	raw, _ = json.Marshal(nr)
	if !strings.Contains(string(raw), `"ready":false`) || !strings.Contains(string(raw), `"reason":"zone_missing"`) {
		t.Errorf("not-ready json %s", raw)
	}
	if strings.Contains(string(raw), "doh_url") || strings.Contains(string(raw), tToken) {
		t.Errorf("not-ready json holds values: %s", raw)
	}
}
