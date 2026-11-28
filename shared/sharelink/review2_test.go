package sharelink

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

// Tests for the findings of review round 2 of B1.

// B1-r2-1 and B1-r2-7, now 7.3: ech is not on the list, so a link that carries it is an
// error of its line, named and without its value, and the exit is pasted as JSON. A DoH,
// h2c or UDP address, and a name or an address with a server, would make Xray query a
// server of its own, which the checker refuses for good.
func TestEchOfALinkIsAnErrorOfItsLine(t *testing.T) {
	link := func(scheme, ech string) string {
		return scheme + "://" + uuid + "@203.0.113.7:443?security=tls&sni=a.example&ech=" + url.QueryEscape(ech)
	}
	for _, scheme := range []string{"vless", "vmess", "trojan"} {
		l := link(scheme, "AEX+DQBBAAAgACD7bQ==")
		if scheme == "trojan" {
			l = strings.Replace(l, uuid, "pw", 1)
		}
		for name, ech := range map[string]string{
			"base64":         "AEX+DQBBAAAgACD7bQ==",
			"udp":            "udp://attacker.example:53",
			"https":          "https://1.1.1.1/dns-query",
			"name and https": "example.com+https://1.1.1.1/dns-query",
			"address":        "1.1.1.1",
			"name":           "example.com",
		} {
			l := link(scheme, ech)
			if scheme == "trojan" {
				l = strings.Replace(l, uuid, "pw", 1)
			}
			_, _, _, err := Convert(l)
			if err == nil {
				t.Errorf("%s %s: converted", scheme, name)
			} else if !strings.Contains(err.Error(), `"ech"`) || strings.Contains(err.Error(), "attacker") {
				t.Errorf("%s %s: the error must name the parameter and not the value: %v", scheme, name, err)
			}
		}
	}
	// The checker stands behind the converter: the fragment of a JSON import is not the
	// converter's, and Check refuses the same text.
	frag := `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"` + uuid + `","encryption":"none"},"streamSettings":{"security":"tls","tlsSettings":{"echConfigList":"example.com+https://1.1.1.1/dns-query"}}}]}`
	if r := xrayschema.Newest().Check([]byte(frag), nil); r.OK() {
		t.Error("the checker accepts an ech URL")
	}
}

// B1-r2-6: the query part of spx is the crawler settings of the REALITY fallback.
func TestSpxHasNoQueryPart(t *testing.T) {
	reality := func(spx string) string {
		return "vless://" + uuid + "@203.0.113.7:443?security=reality&sni=a.example&pbk=" + realityKey + "&spx=" + url.QueryEscape(spx)
	}
	if _, _, _, err := Convert(reality("/")); err != nil {
		t.Errorf("spx /: %v", err)
	}
	for _, spx := range []string{"/?p=9000000000000000000", "/?c=10000000&t=1000000000", "?r=1"} {
		_, _, _, err := Convert(reality(spx))
		if err == nil {
			t.Errorf("spx %q converted", spx)
		} else if !strings.Contains(err.Error(), `"spx"`) || strings.Contains(err.Error(), "9000") {
			t.Errorf("the error must name the parameter and not the value: %v", err)
		}
	}
}

// B1-r2-4: the port of a hysteria2 URI is optional and 443.
func TestHysteria2PortDefaultsTo443(t *testing.T) {
	for _, link := range []string{
		"hy2://made-up-auth@a.example/?sni=a.example",
		"hysteria2://made-up-auth@a.example?sni=a.example",
		"hysteria2://made-up-auth@[2001:db8::1]/?sni=a.example",
	} {
		frag, _, _, err := Convert(link)
		if err != nil {
			t.Errorf("%s: %v", link, err)
			continue
		}
		if !strings.Contains(string(frag), `"port":443`) {
			t.Errorf("%s: port 443 is not in %s", link, frag)
		}
		if r := xrayschema.Newest().Check(frag, nil); !r.OK() {
			t.Errorf("%s: %v %v", link, r.Rejected, r.Warnings)
		}
	}
	// Other links keep needing a port, and a list of ports is still refused.
	for _, link := range []string{
		"vless://" + uuid + "@a.example?security=none",
		"hysteria2://made-up-auth@a.example:1000-2000/?sni=a.example",
		"hysteria2://made-up-auth@a.example:443,5000/?sni=a.example",
		"hysteria2://made-up-auth@a.example:0/?sni=a.example",
	} {
		if _, _, _, err := Convert(link); err == nil {
			t.Errorf("%s converted", link)
		}
	}
}
