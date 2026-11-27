package xrayschema

import (
	"sort"
	"strings"
	"testing"
)

// G4 (p4b-proxy 7.2, 15.4): every leaf of the table has a closed kind with a bound. The
// test walks the whole table of each release, so a key that joins it with no bound
// fails here, not in a review.
func TestEveryLeafOfTheTableHasAClosedKindWithABound(t *testing.T) {
	for _, tag := range Releases() {
		tb, _ := For(tag)
		leaves := 0
		var walk func(n *node, where string, depth int)
		walk = func(n *node, where string, depth int) {
			if depth > 12 {
				t.Fatalf("%s: the table is nested deeper than 12 at %s (it must not hold itself)", tag, where)
			}
			if why := n.problem(); why != "" {
				t.Errorf("%s: %s: %s", tag, where, why)
			}
			if n.k != kObj && n.k != kArr {
				leaves++
			}
			keys := make([]string, 0, len(n.fields))
			for k := range n.fields {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(n.fields[k], where+"."+k, depth+1)
			}
			if n.elem != nil {
				walk(n.elem, where+"[]", depth+1)
			}
			variants := make([]string, 0, len(n.sel))
			for k := range n.sel {
				variants = append(variants, k)
			}
			sort.Strings(variants)
			for _, k := range variants {
				walk(n.sel[k], where+"<"+k+">", depth+1)
			}
			for i, a := range n.alts {
				walk(a, where+"|"+string(rune('a'+i)), depth+1)
			}
		}
		walk(tb.build(), "outbound", 0)
		if leaves < 60 {
			t.Errorf("%s: only %d leaves were walked: is the walk complete?", tag, leaves)
		}
	}
	// The check itself must see an unbounded node.
	for name, n := range map[string]*node{
		"no kind":       {},
		"number":        {k: kInt},
		"range":         {k: kRange},
		"array":         {k: kArr, elem: boolean()},
		"empty enum":    {k: kEnum},
		"empty choice":  {k: kOneOf},
		"choice of obj": oneOf(obj()),
	} {
		if n.problem() == "" {
			t.Errorf("%s: not found", name)
		}
	}
}

// freedomHop is a vless exit that dials through a freedom hop with the given settings.
func freedomHop(settings string) string {
	return `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"tag":"f","protocol":"freedom","settings":{` + settings + `}}]}`
}

func replaceV(s, v string) string {
	return strings.Replace(s, "VALUE", v, 1)
}

// Each listed key judged by its kind: the values on the edge of the bound pass, the ones
// beside them are a warning at the path of the key (never a rejection), and the reason
// names the bound and never the value.
func TestKindsOfListedKeys(t *testing.T) {
	stream := func(inner string) func(string) string {
		return func(v string) string { return outboundWith(`,"streamSettings":{` + replaceV(inner, v) + `}`) }
	}
	hopOf := func(inner string) func(string) string {
		return func(v string) string { return freedomHop(replaceV(inner, v)) }
	}
	settings := func(proto, inner string) func(string) string {
		return func(v string) string {
			return `{"outbounds":[{"protocol":"` + proto + `","settings":{` + replaceV(inner, v) + `}}]}`
		}
	}
	str := func(s string) string { return `"` + s + `"` }
	cases := []struct {
		name  string
		build func(v string) string
		good  []string
		bad   []string
	}{
		{"port", settings("vless", `"port":VALUE`), []string{`1`, `65535`}, []string{`0`, `65536`, `-1`, `"443"`, `443.0`, `4e2`, `true`}},
		{"address", settings("vless", `"address":VALUE`),
			[]string{str("203.0.113.7"), str("a.example"), str("2001:db8::1"), str("a-b_c.example.com")},
			[]string{str("fromMitm"), str("a b.example"), str("fe80::1%eth0"), str("-a.example"), str("a..example"), str("a.example."), str(strings.Repeat("a", 64) + ".example"), str(strings.Repeat("a.", 130)), `5`, `["a.example"]`}},
		{"id", settings("vless", `"id":VALUE`),
			[]string{str("5783a3e7-e373-51cd-8642-c83782b807c5"), str(strings.Repeat("a", 30)), str("my id")},
			[]string{str(strings.Repeat("a", 31)), str("5783a3e7-e373-51cd-8642-c83782b807cz"), str("a\\nb")}},
		{"flow", settings("vless", `"flow":VALUE`), []string{str("xtls-rprx-vision"), str("XTLS-RPRX-VISION-UDP443")}, []string{str("xtls-rprx-direct"), `1`}},
		{"vmess security", settings("vmess", `"security":VALUE`), []string{str("auto"), str("ZERO"), str("chacha20-poly1305")}, []string{str("aes-256-gcm"), `1`}},
		{"vnext users", settings("vless", `"vnext":[{"address":"a.example","port":1,"users":VALUE}]`), []string{`[{}]`}, []string{`[]`, `[{},{}]`, `{}`}},
		{"servers", settings("trojan", `"servers":VALUE`), []string{`[{}]`}, []string{`[]`, `[{},{}]`}},
		{"password", settings("trojan", `"password":VALUE`), []string{str("p"), str(strings.Repeat("p", 255))}, []string{str(strings.Repeat("p", 256)), str("a\\u0007b"), `7`}},
		{"socks user", settings("socks", `"user":VALUE`), []string{str(strings.Repeat("u", 255))}, []string{str(strings.Repeat("u", 256)), str(strings.Repeat("u", 9000))}},
		{"socks pass of a server", settings("socks", `"servers":[{"address":"a.example","port":1,"users":[{"pass":VALUE}]}]`), []string{str(strings.Repeat("p", 255))}, []string{str(strings.Repeat("p", 256))}},
		{"hysteria version", settings("hysteria", `"version":VALUE`), []string{`2`}, []string{`1`, `3`, str("2")}},
		{"mux concurrency", func(v string) string { return outboundWith(`,"mux":{"enabled":true,"concurrency":` + v + `}`) }, []string{`-1`, `0`, `128`}, []string{`-2`, `129`, `"8"`}},
		{"wireguard mtu", func(v string) string { return strings.Replace(wireguard(``), `"mtu":1280`, `"mtu":`+v, 1) }, []string{`1280`, `1420`}, []string{`1279`, `1421`, `0`, `9000`}},
		{"wireguard keepAlive", func(v string) string { return strings.Replace(wireguard(``), `"keepAlive":25`, `"keepAlive":`+v, 1) }, []string{`0`, `600`}, []string{`-1`, `601`}},
		{"wireguard reserved", func(v string) string { return strings.Replace(wireguard(``), `"reserved":[1,2,3]`, `"reserved":`+v, 1) }, []string{`[0,255,7]`}, []string{`[1,2]`, `[1,2,3,4]`, `[1,2,256]`, `[1,2,-1]`}},
		{"wireguard endpoint", func(v string) string { return strings.Replace(wireguard(``), `"203.0.113.9:51820"`, v, 1) },
			[]string{str("203.0.113.9:51820"), str("a.example:1"), str("[2001:db8::1]:51820")}, []string{str("a.example"), str("a.example:0"), str("a.example:65536"), str("fromMitm:1"), str("203.0.113.9:x")}},
		{"wireguard key", func(v string) string {
			return strings.Replace(wireguard(``), `"secretKey":"`+wgKey+`"`, `"secretKey":`+v, 1)
		},
			[]string{str(wgKey), str(strings.Repeat("ab", 32)), str(strings.Repeat("A", 42) + "-="), str(strings.TrimSuffix(wgKey, "=")), str(realityKey)}, []string{str("K"), str(strings.Repeat("ab", 31)), str(realityKey + "=="), str(strings.Repeat("A", 46))}},
		{"wireguard addresses", func(v string) string {
			return strings.Replace(wireguard(``), `"address":["10.0.0.2/32"]`, `"address":`+v, 1)
		},
			[]string{`["10.0.0.2/32","fd00::2/128"]`, `["10.0.0.2"]`}, []string{`[]`, `["10.0.0.2/33"]`, `["a.example"]`, `["1.1.1.1","1.1.1.2","1.1.1.3","1.1.1.4","1.1.1.5","1.1.1.6","1.1.1.7","1.1.1.8","1.1.1.9"]`}},
		{"freedom packets", hopOf(`"fragment":{"packets":VALUE}`), []string{str("tlshello"), str("1-10"), str("3"), str("TLSHELLO")}, []string{str("0"), `11`, str("1-11"), str("tlshello2"), `5`, `1`}},
		{"freedom length", hopOf(`"fragment":{"length":VALUE}`), []string{`1`, `1500`, str("100-200")}, []string{`0`, `1501`, str("200-100"), str("-1"), str("1-70000"), str("a"), str("1,2"), str("1-"), str(" 1")}},
		{"freedom interval", hopOf(`"fragment":{"interval":VALUE}`), []string{`0`, `100`, str("10-20")}, []string{`-1`, `101`, str("1-99999")}},
		{"tls serverName", stream(`"security":"tls","tlsSettings":{"serverName":VALUE}`), []string{str("a.example"), str("203.0.113.7")}, []string{str("localhost"), `1`}},
		{"tls alpn", stream(`"security":"tls","tlsSettings":{"alpn":VALUE}`), []string{`["h2"]`, `["h3","h2","http/1.1"]`, `["H2"]`}, []string{`[]`, `["spdy"]`, `["h2","h2","h2","h2"]`, str("h2"), `[1]`}},
		{"tls fingerprint", stream(`"security":"tls","tlsSettings":{"fingerprint":VALUE}`), []string{str("chrome"), str("Randomized")}, []string{str("unsafe"), str("hellochrome_auto")}},
		{"tls pin", stream(`"security":"tls","tlsSettings":{"pinnedPeerCertSha256":VALUE}`),
			[]string{str(strings.Repeat("ab", 32)), str(strings.Repeat("AB", 32)), str(strings.Repeat("ab", 32) + "," + strings.Repeat("cd", 32))},
			// B1n-r1-1 and 7: the loader splits on "," alone, so "~" joins nothing.
			[]string{str(strings.Repeat("ab", 31)), str(strings.Repeat("ab", 32) + ","), str(strings.Repeat(strings.Repeat("ab", 32)+",", 4) + strings.Repeat("ab", 32)), str("zz"), `1`,
				str(strings.Repeat("ab", 32) + "~" + strings.Repeat("cd", 32)), str(strings.Repeat("ab", 32) + " , " + strings.Repeat("cd", 32))}},
		{"reality publicKey", stream(`"security":"reality","realitySettings":{"publicKey":VALUE}`), []string{str(realityKey)}, []string{str("PUB"), str(realityKey + "="), str(realityKey + "A"), str(strings.Repeat("+", 43))}},
		{"reality shortId", stream(`"security":"reality","realitySettings":{"shortId":VALUE}`), []string{str("ab"), str("0123456789abcdef")}, []string{str("0123456789abcdef0"), str("xy"), `12`}},
		{"reality serverName", stream(`"security":"reality","realitySettings":{"serverName":VALUE}`), []string{str("www.example.com")}, []string{str("example")}},
		{"ws path", stream(`"method":"ws","wsSettings":{"path":VALUE}`), []string{str("/a"), str("/" + strings.Repeat("a", 254))}, []string{str("/a b"), str("/" + strings.Repeat("a", 255)), str("/\\u00e9")}},
		{"ws host", stream(`"method":"ws","wsSettings":{"host":VALUE}`), []string{str("a.example"), str("a.example:8443"), str("203.0.113.7")},
			// B1n-r1-5: a byte above 0x7f in a Host makes Request.Write fail, and the xhttp upload panics on it.
			[]string{str("anything goes, it is text"), str("xn--\u00fc.com"), str("a.example:0"), str(strings.Repeat("h", 256)), `1`}},
		{"xhttp host", stream(`"method":"xhttp","xhttpSettings":{"host":VALUE}`), []string{str("a.example"), str("a.example:8443")}, []string{str("xn--\u00fc.com"), str("a\ufffd.example"), str("a b.example"), `1`}},
		{"wireguard allowedIPs", func(v string) string {
			return strings.Replace(wireguard(``), `"allowedIPs":["0.0.0.0/0"]`, `"allowedIPs":`+v, 1)
		},
			[]string{`["0.0.0.0/0","::/0"]`, `["10.0.0.1/32"]`}, []string{`["10.0.0.1"]`, `["10.0.0.1/33"]`, `["a.example/32"]`, `[]`}},
		{"ws headers", stream(`"method":"ws","wsSettings":{"headers":VALUE}`), []string{`{"A":"b"}`, `{"X-A_1":"` + strings.Repeat("v", 255) + `"}`},
			[]string{`{"A":"` + strings.Repeat("v", 256) + `"}`, `{"A B":"c"}`, `{"A":"\u0007"}`, `{"A":1}`, `{"A":["b"]}`, `{"":"c"}`, `{"` + strings.Repeat("a", 65) + `":"c"}`, `[]`}},
		{"raw headers", stream(`"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"headers":VALUE}}}`), []string{`{"Host":["a.example"]}`, `{"Host":"a.example"}`},
			[]string{`{"Host":[]}`, `{"Host":["1","2","3","4","5","6","7","8","9"]}`, `{"Host":[1]}`}},
		{"raw path list", stream(`"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"path":VALUE}}}`), []string{`["/"]`}, []string{`[]`, str("/"), `["/ a"]`}},
		{"raw header type", stream(`"network":"tcp","tcpSettings":{"header":{"type":VALUE}}`), []string{str("http"), str("none")}, []string{str("srtp")}},
		{"grpc idle_timeout", stream(`"method":"grpc","grpcSettings":{"idle_timeout":VALUE}`), []string{`0`, `3600`}, []string{`-1`, `3601`}},
		{"grpc window", stream(`"method":"grpc","grpcSettings":{"initial_windows_size":VALUE}`), []string{`0`}, []string{`1`, `2147483647`, `33554432`}},
		{"xhttp xPaddingBytes", stream(`"method":"xhttp","xhttpSettings":{"xPaddingBytes":VALUE}`), []string{`1`, `2000`, str("100-1000")}, []string{`0`, `2001`, `2000000000`, str("100-2000000"), str("1000-100")}},
		{"xhttp scMaxEachPostBytes", stream(`"method":"xhttp","xhttpSettings":{"scMaxEachPostBytes":VALUE}`), []string{`16384`, `1000000`, str("20000-30000")}, []string{`16383`, `1000001`, `2000000000`, str("1-2000000000")}},
		{"xhttp extra", stream(`"method":"xhttp","xhttpSettings":{"extra":{"scMaxEachPostBytes":VALUE}}`), []string{`1000000`}, []string{`2000000000`}},
		{"xhttp mode", stream(`"method":"xhttp","xhttpSettings":{"mode":VALUE}`), []string{str("auto"), str("Stream-One"), str("packet-up"), str("stream-up")}, []string{str("other")}},
		{"xhttp noGRPCHeader", stream(`"method":"xhttp","xhttpSettings":{"noGRPCHeader":VALUE}`), []string{`true`}, []string{`1`, str("true")}},
		{"hysteria auth", stream(`"method":"hysteria","hysteriaSettings":{"auth":VALUE}`), []string{str("a")}, []string{str(strings.Repeat("a", 256))}},
		{"udphop interval", stream(`"finalmask":{"udp":[{"type":"udphop","settings":{"interval":VALUE}}]}`), []string{`5`, `600`, str("5-10")}, []string{`4`, `601`, `-5`, `0`}},
		{"udphop ports", stream(`"finalmask":{"udp":[{"type":"udphop","settings":{"remotePorts":VALUE}}]}`), []string{`443`, str("443"), str("20000-30000")}, []string{`0`, str("0-20"), str("20000-70000"), str("1000,0"), str("20000-30000,443"), str("30000-20000")}},
		{"salamander password", stream(`"finalmask":{"udp":[{"type":"salamander","settings":{"password":VALUE}}]}`), []string{str("p")}, []string{str(strings.Repeat("p", 256))}},
		{"mask settings of an unlisted key", stream(`"finalmask":{"udp":[{"type":"salamander","settings":{"packetSize":VALUE}}]}`), nil, []string{`1200`}},
	}
	for _, c := range cases {
		for _, good := range c.good {
			if r := check(t, c.build(good)); !r.OK() {
				t.Errorf("%s %s: not accepted: warnings=%v rejected=%v", c.name, good, r.Warnings, r.Rejected)
			}
		}
		for _, bad := range c.bad {
			frag := c.build(bad)
			r := check(t, frag)
			if len(r.Rejected) != 0 || len(r.Warnings) == 0 || r.Normalized != nil {
				t.Errorf("%s %s: want a warning and no rejection: warnings=%v rejected=%v", c.name, bad, r.Warnings, r.Rejected)
				continue
			}
			// The reason names the bound and never the value the admin wrote.
			for _, w := range r.Warnings {
				if len(bad) > 8 && strings.Contains(w.Msg, strings.Trim(bad, `"`)) {
					t.Errorf("%s: the reason echoes the value %s", c.name, bad)
				}
			}
			// Its path passes it, and the normal form is then stored as pasted.
			if got := check(t, frag, r.Warnings[0].Path); len(got.Rejected) != 0 {
				t.Errorf("%s %s: refused after accept: %v", c.name, bad, got.Rejected)
			}
		}
	}
}
