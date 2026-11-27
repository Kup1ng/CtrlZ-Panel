package xrayschema

import (
	"sort"
	"strings"
	"testing"
)

// Tests for the findings of review round 2 of B1 (p4b-proxy 7.2) that still name a key
// the table accepts or a rule it keeps.

func tlsWith(tls string) string {
	return outboundWith(`,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"` + tls + `}}`)
}

// B1-r2-1 and B1-r2-7: an echConfigList with :// (or any value that is not a base64
// list) makes Xray ask a DoH, h2c or UDP server for the ECH record with socket options
// of its own and resolve its name by the host resolver. The key is unknown: a base64
// list passes with its path, and a value that is not one is refused at any depth, in
// any case, whatever was accepted.
func TestEchConfigListIsOnlyABase64List(t *testing.T) {
	for name, v := range map[string]string{
		"https":          "https://1.1.1.1/dns-query",
		"udp":            "udp://attacker.example:53",
		"name and https": "example.com+https://1.1.1.1/dns-query",
		"name and udp":   "secret.example+udp://attacker.example:53",
		"an address":     "1.1.1.1",
		"a name":         "example.com",
		"h2c":            "h2c://1.1.1.1/dns-query",
	} {
		mustReject(t, name, tlsWith(`,"echConfigList":"`+v+`"`), "outbounds[0].streamSettings.tlsSettings.echConfigList")
		// Any case of the key, and a path the admin names as accepted, change nothing.
		mustReject(t, name+" (case)", tlsWith(`,"ECHCONFIGLIST":"`+v+`"`), "outbounds[0].streamSettings.tlsSettings.ECHCONFIGLIST")
		mustReject(t, name+" (raw subtree)", outboundWith(`,"streamSettings":{"xhttpSettings":{"h2Params":{"echConfigList":"`+v+`"}}}`),
			"outbounds[0].streamSettings.xhttpSettings.h2Params")
		mustReject(t, name+" (unknown key)", tlsWith(`,"newThing":{"echConfigList":"`+v+`"}`), "outbounds[0].streamSettings.tlsSettings.newThing")
	}
	mustReject(t, "ech key beside a table", outboundWith(`,"streamSettings":{"echConfigList":"https://1.1.1.1/dns-query"}`),
		"outbounds[0].streamSettings.echConfigList")
	// A base64 list is unknown, so it needs the path; an empty one is the default.
	mustWarn(t, "base64 list", tlsWith(`,"echConfigList":"AEX+DQBBAAAgACD7bQ=="`), "outbounds[0].streamSettings.tlsSettings.echConfigList")
	mustOK(t, tlsWith(`,"echConfigList":"AEX+DQBBAAAgACD7bQ=="`), "outbounds[0].streamSettings.tlsSettings.echConfigList")
	mustOK(t, tlsWith(`,"echConfigList":""`))
}

// The reality kinds: a spiderX is a path with no query and no escape. Xray reads p, c,
// t, i and r of a query as crawler settings; a value that is not a plain path is unknown
// and the admin decides, and inside an accepted subtree nothing is judged.
func TestSpiderXIsAPlainPath(t *testing.T) {
	reality := func(spx string) string {
		return outboundWith(`,"streamSettings":{"security":"reality","realitySettings":{"serverName":"a.example","publicKey":"` + realityKey + `","spiderX":"` + spx + `"}}`)
	}
	mustOK(t, reality("/"))
	mustOK(t, reality("/some/path_a-b.c~d"))
	for name, spx := range map[string]string{
		"p":          "/?p=9000000000000000000",
		"c and t":    "/?c=10000000&t=1000000000",
		"bare query": "?r=1",
		"after path": "/x?i=1",
		"escape":     "/a%3Fb",
		"no slash":   "a",
		"a space":    "/a b",
		"too long":   "/" + strings.Repeat("a", 255),
	} {
		mustWarn(t, name, reality(spx), "outbounds[0].streamSettings.realitySettings.spiderX")
	}
	mustOK(t, reality("/"+strings.Repeat("a", 254)))
	// No bound is judged inside an accepted unknown subtree.
	mustOK(t, outboundWith(`,"streamSettings":{"xhttpSettings":{"h2Params":{"spiderX":"/?p=1"}}}`), "outbounds[0].streamSettings.xhttpSettings.h2Params")
}

const (
	hyOutbound  = `{"protocol":"hysteria","settings":{"version":2,"address":"203.0.113.7","port":443}}`
	vlessPrefix = `{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"}`
)

// B1-r2-2 and B1-r2-8: Stateful is what 7.5 step 5 acts on.
func TestStatefulConfigs(t *testing.T) {
	tb := Newest()
	xhttp := func(tls string, extra string) string {
		return `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"xhttp","security":"tls","tlsSettings":{"serverName":"a.example"` + tls + `}` + extra + `}}]}`
	}
	for name, frag := range map[string]string{
		"wireguard":              wireguard(``),
		"hysteria protocol":      `{"outbounds":[` + hyOutbound + `]}`,
		"hysteria transport":     `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"hysteria"}}]}`,
		"transport, old name":    `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"network":"Hysteria"}}]}`,
		"grpc transport":         `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"grpc"}}]}`,
		"grpc, old case":         `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"network":"GRPC"}}]}`,
		"wireguard as a hop":     `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"w"}}},` + strings.Replace(wgFull, `"protocol"`, `"tag":"w","protocol"`, 1) + `]}`,
		"protocol in any case":   `{"outbounds":[{"PROTOCOL":"WireGuard"}]}`,
		"xhttp h3 array":         xhttp(`,"alpn":["h3"]`, ""),
		"xhttp old name":         strings.Replace(xhttp(`,"alpn":["h3"]`, ""), `"xhttp"`, `"splithttp"`, 1),
		"xhttp h3 in download":   xhttp(``, `,"xhttpSettings":{"downloadSettings":{"security":"tls","tlsSettings":{"alpn":["h3"]}}}`),
		"xhttp h3 in raw extras": xhttp(``, `,"xhttpSettings":{"h2Params":{"alpn":["h3"]}}`),
		// A fragment the table does not pass as it stands is stateful: nobody read what its
		// handler keeps (7.2).
		"unknown key":        `{"outbounds":[` + vlessPrefix + `,"surprise":1}]}`,
		"a value off kind":   `{"outbounds":[{"protocol":"vless","settings":{"port":"443"}}]}`,
		"kcp":                `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"kcp"}}]}`,
		"alpn off the list":  xhttp(`,"alpn":["h30"]`, ""),
		"rejected fragment":  `{"outbounds":[{"protocol":"loopback"}]}`,
		"not a fragment":     `[]`,
		"alpn as one string": xhttp(`,"alpn":"h2, H3"`, ""),
	} {
		if !tb.Stateful([]byte(frag)) {
			t.Errorf("%s: not stateful", name)
		}
	}
	for name, frag := range map[string]string{
		"vless reality": vlessReality,
		"xhttp over h2": xhttp(`,"alpn":["h2","http/1.1"]`, ""),
		"xhttp no alpn": xhttp(``, ""),
		"ws with h3":    `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"method":"ws","security":"tls","tlsSettings":{"serverName":"a.example","alpn":["h3"]}}}]}`,
		"freedom hop":   `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"tag":"f","protocol":"freedom"}]}`,
	} {
		if tb.Stateful([]byte(frag)) {
			t.Errorf("%s: stateful", name)
		}
	}
	// A fragment that cannot be read, and a table with no rules, are called stateful.
	if !tb.Stateful([]byte(`{`)) || !(Table{}).Stateful([]byte(vlessReality)) {
		t.Error("an unreadable fragment or a table with no rules is not stateful")
	}
	// The normal form says the same as the fragment, and an accepted unknown is stateful.
	r := mustOK(t, xhttp(`,"alpn":["h3"]`, ""))
	if !tb.Stateful(r.Normalized) {
		t.Error("the normal form of an xhttp h3 config is not stateful")
	}
	r = mustOK(t, outboundWith(`,"surprise":1`), "outbounds[0].surprise")
	if !tb.Stateful(r.Normalized) {
		t.Error("the normal form with an accepted unknown key is not stateful")
	}
}

// G4: a protocol or a transport the table accepts but nobody classified would be
// missed by Stateful, and rmo would leave its device or session up.
func TestEveryProtocolAndTransportIsClassified(t *testing.T) {
	for _, tag := range Releases() {
		tb, _ := For(tag)
		rules := tb.rules()
		var protocols, classified []string
		for p := range tb.build().sel {
			protocols = append(protocols, p)
		}
		for p := range rules.protocols {
			classified = append(classified, p)
		}
		sort.Strings(protocols)
		sort.Strings(classified)
		if strings.Join(protocols, ",") != strings.Join(classified, ",") {
			t.Errorf("%s: protocols of the table %v, classified %v", tag, protocols, classified)
		}
		seen := map[string]bool{}
		var transports, ctransports []string
		for _, canon := range transportEnum().enum {
			if !seen[canon] {
				seen[canon] = true
				transports = append(transports, canon)
			}
		}
		for tr := range rules.transports {
			ctransports = append(ctransports, tr)
		}
		sort.Strings(transports)
		sort.Strings(ctransports)
		if strings.Join(transports, ",") != strings.Join(ctransports, ",") {
			t.Errorf("%s: transports of the table %v, classified %v", tag, transports, ctransports)
		}
	}
}
