package setup

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

var (
	urlRE  = regexp.MustCompile(`https://[^\s'"]+`)
	addrRE = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
)

// forbidden is the "Never" column of SC 8a.8 and the certificate rule, read
// against the generated text: a mode that falls back to plaintext, and a switch
// that turns the certificate check off.
var forbidden = []string{
	`"automatic"`, "automatic", "opportunistic", "AllowFallbackToUdp $True", `"Fallback": true`,
	"trr.mode 2", "network.trr.bootstrapAddr", "bootstrapAddr",
	"SkipCertificate", "-k ", "insecure", "VerifyCertificate", "tls-skip-verify", "InsecureSkipVerify", "validation=off",
}

// Check E7 (P3 11.2) over the registry, for each golden view: the primary comes
// first where the order is listed, the strict setting of the client is present
// and none of the forbidden ones is, and every host and URL in the output reads
// back to the Endpoint, token and client of the view.
func TestGeneratorsE7(t *testing.T) {
	gens := Generators()
	if len(gens) != 5 {
		t.Fatalf("registry holds %d generators", len(gens))
	}
	for _, c := range loadGolden(t) {
		v, err := View(c.input())
		if err != nil {
			t.Fatal(err)
		}
		zone := []names.Name{names.MustString(c.Zone)}
		for _, g := range gens {
			out, err := g.Run(v)
			if err != nil || out == "" {
				t.Fatalf("%s/%s: %q, %v", c.Name, g.ID, out, err)
			}
			for _, bad := range forbidden {
				if strings.Contains(out, bad) {
					t.Errorf("%s/%s holds %q", c.Name, g.ID, bad)
				}
			}
			for _, u := range urlRE.FindAllString(out, -1) {
				u = strings.TrimRight(u, ",")
				host, path, _ := strings.Cut(strings.TrimPrefix(u, "https://"), "/")
				h := identity.ParseHost(host, zone)
				p, err := identity.ParseDoHPath("/" + path)
				if h.Kind != identity.HostResolver || h.RID != c.RID || h.Client != c.Client || err != nil || p.Token != c.Token {
					t.Errorf("%s/%s: URL does not read back (%v)", c.Name, g.ID, err)
				}
			}
			// Every address in the output is the primary or the fallback, and the
			// primary is the first to appear.
			if first := firstAddr(out); first != "" && first != c.Primary {
				t.Errorf("%s/%s: first address is %s, not the primary", c.Name, g.ID, first)
			}
			for _, a := range addrRE.FindAllString(out, -1) {
				if a != c.Primary && a != c.Fallback {
					t.Errorf("%s/%s: address %s is not in the view", c.Name, g.ID, a)
				}
			}
		}
	}
}

func firstAddr(s string) string {
	best, at := "", len(s)+1
	for _, re := range []*regexp.Regexp{addrRE, regexp.MustCompile(`2001:db8::[0-9a-f]+`)} {
		if loc := re.FindStringIndex(s); loc != nil && loc[0] < at {
			best, at = s[loc[0]:loc[1]], loc[0]
		}
	}
	return best
}

func TestGeneratorsOutputs(t *testing.T) {
	v := readyView(t)
	run := func(id string) string {
		for _, g := range Generators() {
			if g.ID == id {
				out, err := g.Run(v)
				if err != nil {
					t.Fatal(err)
				}
				return out
			}
		}
		t.Fatalf("no generator %s", id)
		return ""
	}

	win := run("windows-doh")
	if strings.Count(win, "Add-DnsClientDohServerAddress") != 2 || strings.Count(win, "-AllowFallbackToUdp $False -AutoUpgrade $True") != 2 {
		t.Errorf("windows needs one strict DoH template per address:\n%s", win)
	}
	if !strings.Contains(win, "-ServerAddresses ('203.0.113.10','203.0.113.20')") ||
		strings.Index(win, "-ServerAddress '203.0.113.10'") > strings.Index(win, "-ServerAddress '203.0.113.20'") {
		t.Errorf("windows order:\n%s", win)
	}
	if strings.Count(win, v.DoHURL) != 2 {
		t.Error("each address needs the same DoH template")
	}

	ff := run("firefox-policy")
	for _, want := range []string{`"Enabled": true`, `"Locked": true`, `"Fallback": false`, `"ProviderURL": "` + v.DoHURL + `"`} {
		if !strings.Contains(ff, want) {
			t.Errorf("firefox policy lacks %s:\n%s", want, ff)
		}
	}

	ch := run("chromium-policy")
	if !strings.Contains(ch, `"DnsOverHttpsMode": "secure"`) || !strings.Contains(ch, `"DnsOverHttpsTemplates": "`+v.DoHURL+`"`) {
		t.Errorf("chromium policy:\n%s", ch)
	}

	if got := run("android-private-dns"); got != v.Host+"\n" {
		t.Errorf("android %q", got)
	}
	if got := run("address-list"); got != "DNS1 203.0.113.10\nDNS2 203.0.113.20\n" {
		t.Errorf("address list %q", got)
	}
}

// IPv6 pairs keep the order in every generator.
func TestGeneratorsIPv6Pair(t *testing.T) {
	v, err := View(Input{
		ResolverID: tRID, DoHToken: tToken, Zone: "dns.example.org",
		Primary: netip.MustParseAddr("2001:db8::10"), Fallback: netip.MustParseAddr("2001:db8::20"),
	})
	if err != nil || !v.Ready {
		t.Fatal(err)
	}
	out, _ := AddressList(v)
	if out != "DNS1 2001:db8::10\nDNS2 2001:db8::20\n" {
		t.Errorf("%q", out)
	}
	win, _ := WindowsCommands(v)
	if strings.Index(win, "2001:db8::10") > strings.Index(win, "2001:db8::20") {
		t.Error("windows order")
	}
}

// The registry is built fresh, so a caller cannot reorder what others walk.
func TestGeneratorsFreshRegistry(t *testing.T) {
	a := Generators()
	a[0], a[1] = a[1], a[0]
	if Generators()[0].ID != "windows-doh" {
		t.Fatal("registry shared")
	}
}
