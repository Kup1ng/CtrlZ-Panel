package xrayschema

import (
	"bytes"
	"strings"
	"testing"
)

// realityKey is 32 bytes in base64url, the kind of a REALITY key.
const realityKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// wgKey is 32 bytes in base64, the kind of a WireGuard key.
const wgKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

const (
	vlessReality = `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none","flow":"xtls-rprx-vision"},
		"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"ab12"}}}]}`
)

func newest(t *testing.T) Table {
	t.Helper()
	return Newest()
}

func check(t *testing.T, frag string, accept ...string) Result {
	t.Helper()
	return newest(t).Check([]byte(frag), accept)
}

func mustOK(t *testing.T, frag string, accept ...string) Result {
	t.Helper()
	r := check(t, frag, accept...)
	if !r.OK() {
		t.Fatalf("not accepted: rejected=%v warnings=%v", r.Rejected, r.Warnings)
	}
	return r
}

func mustReject(t *testing.T, what, frag string, accept ...string) Result {
	t.Helper()
	r := check(t, frag, accept...)
	if len(r.Rejected) == 0 {
		t.Errorf("%s: not rejected (warnings=%v)", what, r.Warnings)
	}
	if r.Normalized != nil {
		t.Errorf("%s: a rejected fragment has a normal form", what)
	}
	return r
}

// outboundWith builds a one-outbound fragment of a vless exit with the given extra
// text spliced into the outbound object.
func outboundWith(extra string) string {
	return `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"}` + extra + `}]}`
}

func TestAGoodFragmentPassesAndIsStable(t *testing.T) {
	r := mustOK(t, vlessReality)
	again := newest(t).Check(r.Normalized, nil)
	if !again.OK() || !bytes.Equal(again.Normalized, r.Normalized) {
		t.Fatalf("the normal form is not a fixed point:\n%s\n%s", r.Normalized, again.Normalized)
	}
	if len(again.Diff) != 0 {
		t.Errorf("the normal form changes again: %v", again.Diff)
	}
	// The user's old spelling was written as the new one, and the tag was assigned.
	s := string(r.Normalized)
	for _, want := range []string{`"method":"raw"`, `"tag":"0"`} {
		if !strings.Contains(s, want) {
			t.Errorf("normal form lacks %s: %s", want, s)
		}
	}
	if strings.Contains(s, `"network"`) {
		t.Errorf("old spelling kept: %s", s)
	}
}

func TestKeysAndValuesAreFoldedLikeTheLoader(t *testing.T) {
	r := mustOK(t, `{"OUTBOUNDS":[{"Protocol":"VLESS","SETTINGS":{"Address":"203.0.113.7","PORT":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},"streamsettings":{"Network":"WS","wsSettings":{"PATH":"/p"}}}]}`)
	s := string(r.Normalized)
	for _, want := range []string{`"protocol":"vless"`, `"settings":{`, `"address":"203.0.113.7"`, `"method":"ws"`, `"wsSettings":{"path":"/p"}`, `"streamSettings"`} {
		if !strings.Contains(s, want) {
			t.Errorf("normal form lacks %s: %s", want, s)
		}
	}
	// Unicode simple folding, as in Go's decoder: the Kelvin sign is a "k".
	r = check(t, outboundWith(`,"streamSettings":{"security":"reality","realitySettings":{"public`+"\u212A"+`ey":"`+realityKey+`"}}`))
	if !r.OK() || !strings.Contains(string(r.Normalized), `"publicKey"`) {
		t.Errorf("a key spelled with the Kelvin sign is not the key: %v %v", r.Warnings, r.Rejected)
	}
}

func TestRepeatedKeysAreRefusedInAnyCase(t *testing.T) {
	for name, frag := range map[string]string{
		"same spelling":      outboundWith(`,"tag":"a","tag":"b"`),
		"two cases":          outboundWith(`,"tag":"a","TAG":"b"`),
		"in the settings":    `{"outbounds":[{"protocol":"vless","settings":{"port":1,"Port":2}}]}`,
		"two new spellings":  outboundWith(`,"streamSettings":{"method":"raw","Method":"raw"}`),
		"two old spellings":  outboundWith(`,"streamSettings":{"network":"raw","NETWORK":"raw"}`),
		"top level":          `{"outbounds":[],"Outbounds":[]}`,
		"in a free-form map": outboundWith(`,"streamSettings":{"wsSettings":{"headers":{"A":"1","A":"2"}}}`),
	} {
		r := check(t, frag)
		if len(r.Rejected) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBothSpellingsMustAgree(t *testing.T) {
	mustOK(t, outboundWith(`,"streamSettings":{"network":"tcp","method":"raw"}`))
	mustOK(t, outboundWith(`,"streamSettings":{"tcpSettings":{"header":{"type":"none"}},"rawSettings":{"header":{"type":"none"}}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"network":"splithttp","xhttpSettings":{"path":"/a"},"splithttpSettings":{"path":"/a"}}`))
	mustReject(t, "network and method differ", outboundWith(`,"streamSettings":{"network":"ws","method":"raw"}`))
	mustReject(t, "raw and tcp settings differ", outboundWith(`,"streamSettings":{"tcpSettings":{"header":{"type":"http"}},"rawSettings":{"header":{"type":"none"}}}`))
	mustReject(t, "xhttp and splithttp differ", outboundWith(`,"streamSettings":{"xhttpSettings":{"path":"/a"},"splithttpSettings":{"path":"/b"}}`))
	r := mustOK(t, outboundWith(`,"streamSettings":{"tcpSettings":{"header":{"type":"none"}},"rawSettings":{"header":{"type":"none"}}}`))
	if n := strings.Count(string(r.Normalized), `"header"`); n != 1 {
		t.Errorf("the merged spelling is written %d times: %s", n, r.Normalized)
	}
}

// Each key of the always-rejected list is refused at the depth where the loader
// would read it, in three case forms, and also inside a subtree the table does not know.
func TestAlwaysRejectedKeys(t *testing.T) {
	spots := map[string]string{
		"outbound":     `{"outbounds":[{"protocol":"vless","settings":{"port":1},%s}]}`,
		"settings":     `{"outbounds":[{"protocol":"vless","settings":{%s}}]}`,
		"stream":       `{"outbounds":[{"protocol":"vless","streamSettings":{%s}}]}`,
		"sockopt":      `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{%s}}}]}`,
		"tls":          `{"outbounds":[{"protocol":"vless","streamSettings":{"security":"tls","tlsSettings":{%s}}}]}`,
		"download":     `{"outbounds":[{"protocol":"vless","streamSettings":{"xhttpSettings":{"downloadSettings":{"sockopt":{%s}}}}}]}`,
		"extra":        `{"outbounds":[{"protocol":"vless","streamSettings":{"xhttpSettings":{"extra":{%s}}}}]}`,
		"finalmask":    `{"outbounds":[{"protocol":"vless","streamSettings":{"finalmask":{"udp":[{"type":"noise","settings":{%s}}]}}}]}`,
		"unknown tree": `{"outbounds":[{"protocol":"vless","streamSettings":{"somethingNew":{"a":[{%s}]}}}]}`,
	}
	keys := []string{"xdriveSettings", "script", "webhook", "env", "metrics", "geodata", "process", "redirect", "reverse",
		"masterKeyLog", "certificateFile", "keyFile", "dir", "sendThrough", "mark", "interface", "tproxy", "customSockopt",
		"acceptProxyProtocol", "proxySettings", "isClient", "finalRules", "ipsBlocked", "masqueSettings", "portMapping", "debug"}
	for _, key := range keys {
		for _, form := range []string{key, strings.ToLower(key), strings.ToUpper(key)} {
			for spot, tmpl := range spots {
				frag := strings.Replace(tmpl, "%s", `"`+form+`":1`, 1)
				// With every unknown path accepted a key of this list still stops it.
				r := mustReject(t, spot+" "+form, frag, "outbounds[0].streamSettings.somethingNew", "outbounds[0]."+form)
				if len(r.Rejected) > 0 && !strings.Contains(r.Rejected[0].Msg, "never allowed") {
					t.Errorf("%s %s: refused for another reason: %v", spot, form, r.Rejected)
				}
			}
		}
	}
	// dialerProxy on freedom, and nowhere else.
	mustReject(t, "freedom dialerProxy", `{"outbounds":[{"protocol":"vless"},{"protocol":"freedom","tag":"f","streamSettings":{"sockopt":{"dialerProxy":"x"}}}]}`)
	// A key of a free-form map is a value.
	mustOK(t, outboundWith(`,"streamSettings":{"network":"ws","wsSettings":{"headers":{"Env":"x","Script":"y","dir":"z"}}}`))
}

func TestNoOtherTopLevelKey(t *testing.T) {
	for _, k := range []string{"inbounds", "routing", "dns", "log", "policy", "api", "stats", "observatory", "x"} {
		mustReject(t, k, `{"outbounds":[{"protocol":"vless"}],"`+k+`":{}}`)
	}
	mustReject(t, "no outbounds", `{}`)
	mustReject(t, "empty list", `{"outbounds":[]}`)
	mustReject(t, "nine outbounds", `{"outbounds":[`+strings.TrimSuffix(strings.Repeat(`{"protocol":"vless"},`, 9), ",")+`]}`)
	mustReject(t, "not an object", `[]`)
}

func TestProtocolNetworkSecurityAndMethodOutsideTheTableAreNeverAccepted(t *testing.T) {
	cases := map[string]string{
		"loopback":   `{"outbounds":[{"protocol":"%s"}]}`,
		"blackhole":  `{"outbounds":[{"protocol":"%s"}]}`,
		"dns":        `{"outbounds":[{"protocol":"%s"}]}`,
		"tun":        `{"outbounds":[{"protocol":"%s"}]}`,
		"xdrive":     `{"outbounds":[{"protocol":"%s"}]}`,
		"masque":     `{"outbounds":[{"protocol":"%s"}]}`,
		"direct":     `{"outbounds":[{"protocol":"%s"}]}`,
		"dokodemo":   `{"outbounds":[{"protocol":"%s"}]}`,
		"newproto":   `{"outbounds":[{"protocol":"%s"}]}`,
		"quic":       `{"outbounds":[{"protocol":"vless","streamSettings":{"network":"%s"}}]}`,
		"h2":         `{"outbounds":[{"protocol":"vless","streamSettings":{"method":"%s"}}]}`,
		"xdrive ":    `{"outbounds":[{"protocol":"vless","streamSettings":{"method":"%s"}}]}`,
		"masque ":    `{"outbounds":[{"protocol":"vless","streamSettings":{"network":"%s"}}]}`,
		"xtls":       `{"outbounds":[{"protocol":"vless","streamSettings":{"security":"%s"}}]}`,
		"unknownsec": `{"outbounds":[{"protocol":"vless","streamSettings":{"security":"%s"}}]}`,
		"rc4":        `{"outbounds":[{"protocol":"shadowsocks","settings":{"method":"%s"}}]}`,
		"none":       `{"outbounds":[{"protocol":"shadowsocks","settings":{"method":"%s"}}]}`,
	}
	for val, tmpl := range cases {
		val = strings.TrimSpace(val)
		for _, form := range []string{val, strings.ToUpper(val), strings.ToTitle(val)} {
			frag := strings.Replace(tmpl, "%s", form, 1)
			// Not even a decision of the admin passes it.
			var accept []string
			for _, p := range []string{"protocol", "settings.method", "streamSettings.method", "streamSettings.network", "streamSettings.security"} {
				accept = append(accept, "outbounds[0]."+p)
			}
			r := mustReject(t, val+" as "+form, frag, accept...)
			if len(r.Warnings) != 0 && len(r.Rejected) == 0 {
				t.Errorf("%s: only a warning", form)
			}
		}
	}
	// The table's own values pass, in any case.
	for _, p := range []string{"VLESS", "Vmess", "trojan", "SHADOWSOCKS", "socks", "HTTP", "hysteria", "wireguard"} {
		r := check(t, `{"outbounds":[{"protocol":"`+p+`"}]}`)
		if len(r.Rejected) != 0 {
			t.Errorf("protocol %s refused: %v", p, r.Rejected)
		}
	}
	mustReject(t, "freedom first", `{"outbounds":[{"protocol":"freedom"}]}`)
}

func TestUnknownKeyIsABlockingWarningUntilItsPathIsAccepted(t *testing.T) {
	frag := outboundWith(`,"streamSettings":{"newThing":{"a":1}}`)
	r := check(t, frag)
	if r.OK() || len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].streamSettings.newThing" || len(r.Rejected) != 0 {
		t.Fatalf("warnings=%v rejected=%v", r.Warnings, r.Rejected)
	}
	if r.Preview == nil || r.Normalized != nil {
		t.Error("a fragment with a warning has a preview and no normal form to store")
	}
	// Another path accepts nothing, and the path must be exact (no prefix, no suffix).
	for _, p := range []string{"outbounds[0].streamSettings", "outbounds[0].streamSettings.newThing.a", "outbounds[1].streamSettings.newThing", "outbounds[0].streamSettings.newthing"} {
		if r := check(t, frag, p); r.OK() {
			t.Errorf("path %s accepted the key", p)
		}
	}
	r = check(t, frag, "outbounds[0].streamSettings.newThing")
	if !r.OK() {
		t.Fatalf("accepted path not accepted: %v %v", r.Warnings, r.Rejected)
	}
	found := false
	for _, d := range r.Diff {
		if d.Path == "outbounds[0].streamSettings.newThing" {
			found = true
		}
	}
	if !found {
		t.Errorf("an accepted unknown is not in the diff: %v", r.Diff)
	}
	// A path of a wrong form is itself refused.
	for _, p := range []string{"", "routing.rules", "outbounds[0]", "outbounds[9].a", "outbounds[0].", "outbounds[0].a b", "outbounds[0]..a", "outbounds[0].a[x]"} {
		if r := check(t, frag, p); len(r.Rejected) == 0 {
			t.Errorf("accept_unknown %q not refused", p)
		}
	}
	// Unknown keys at the top of an outbound and an unknown mask type are warnings too.
	if r := check(t, outboundWith(`,"surprise":1`)); len(r.Warnings) != 1 {
		t.Errorf("outbound key: %v", r.Warnings)
	}
	r = check(t, outboundWith(`,"streamSettings":{"finalmask":{"udp":[{"type":"noise","settings":{"reset":1}}]}}`))
	// The settings of the unknown type have a warning of their own (B1n-r2-5).
	if len(r.Warnings) != 2 || r.Warnings[0].Path != "outbounds[0].streamSettings.finalmask.udp[0].type" ||
		r.Warnings[1].Path != "outbounds[0].streamSettings.finalmask.udp[0].settings" {
		t.Errorf("unknown mask type: %v %v", r.Warnings, r.Rejected)
	}
	// The text of a warning says what accepting it is worth.
	if !strings.Contains(r.Warnings[0].Msg, "does not judge") || !strings.Contains(r.Warnings[0].Msg, "Xray process") {
		t.Errorf("the warning does not say what it means: %s", r.Warnings[0].Msg)
	}
}

func TestValuesThatReachTheHostAreRefused(t *testing.T) {
	for name, extra := range map[string]string{
		"address env":      `,"streamSettings":{"address":"env:SECRET"}`,
		"address env case": `,"streamSettings":{"address":"ENV:SECRET"}`,
		"ext in alpn":      `,"streamSettings":{"security":"tls","tlsSettings":{"alpn":"h2,ext:file.dat:tag"}}`,
		"geoip in filter":  `,"streamSettings":{"finalmask":{"tcp":[{"type":"filter","settings":{"blockedSourceIPs":["geoip:ir"]}}]}}`,
		"geosite negated":  `,"streamSettings":{"finalmask":{"tcp":[{"type":"filter","settings":{"blockedSourceIPs":["!geosite:x"]}}]}}`,
		"port list env":    `,"streamSettings":{"finalmask":{"udp":[{"type":"udphop","settings":{"remotePorts":"80, env:P"}}]}}`,
		"header value":     `,"streamSettings":{"network":"ws","wsSettings":{"headers":{"X":"ext:a"}}}`,
		"in unknown tree":  `,"streamSettings":{"newThing":["env:HOME"]}`,
	} {
		mustReject(t, name, outboundWith(extra), "outbounds[0].streamSettings.newThing")
	}
	// A password that merely contains the letters is fine.
	mustOK(t, `{"outbounds":[{"protocol":"trojan","settings":{"address":"203.0.113.7","port":443,"password":"next:env:ext"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"}}}]}`)
}

const wgFull = `{"protocol":"wireguard","settings":{"secretKey":"` + wgKey + `","address":["10.0.0.2/32"],"peers":[{"publicKey":"` + wgKey + `","endpoint":"203.0.113.9:51820","allowedIPs":["0.0.0.0/0"],"keepAlive":25}],"mtu":1280,"reserved":[1,2,3]%s}}`

func wireguard(extra string) string {
	return `{"outbounds":[` + strings.Replace(wgFull, "%s", extra, 1) + `]}`
}

func TestWireguardAndFreedomRules(t *testing.T) {
	r := mustOK(t, wireguard(`,"noKernelTun":false`))
	if !strings.Contains(string(r.Normalized), `"noKernelTun":true`) || len(r.Diff) == 0 {
		t.Errorf("noKernelTun not forced: %s %v", r.Normalized, r.Diff)
	}
	r = mustOK(t, wireguard(``))
	if !strings.Contains(string(r.Normalized), `"noKernelTun":true`) {
		t.Errorf("noKernelTun not added: %s", r.Normalized)
	}
	// The client reads Peers[0] with no check: none, or two, is a warning, and so is a
	// missing list.
	for name, peers := range map[string]string{"none": `"peers":[]`, "two": `"peers":[{"publicKey":"` + wgKey + `"},{"publicKey":"` + wgKey + `"}]`} {
		frag := `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"` + wgKey + `",` + peers + `}}]}`
		if r := check(t, frag); r.OK() || len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].settings.peers" {
			t.Errorf("%s: %v %v", name, r.Warnings, r.Rejected)
		}
	}
	if r := check(t, `{"outbounds":[{"protocol":"wireguard","settings":{"secretKey":"`+wgKey+`"}}]}`); r.OK() || len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].settings.peers" {
		t.Errorf("missing peers: %v %v", r.Warnings, r.Rejected)
	}
	mustReject(t, "isClient", `{"outbounds":[{"protocol":"wireguard","settings":{"isClient":false,"secretKey":"K"}}]}`)
	mustReject(t, "IsClient", `{"outbounds":[{"protocol":"wireguard","settings":{"IsClient":false}}]}`)
	// A freedom hop may fragment, and may not bring rules of its own.
	mustOK(t, `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"frag"}}},{"protocol":"freedom","tag":"frag","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"}}}]}`)
	mustOK(t, freedomHop(`"fragment":{"packets":"1-3","length":100,"interval":0}`))
	mustReject(t, "finalRules", `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"protocol":"freedom","tag":"f","settings":{"finalRules":[{"action":"allow"}]}}]}`)
	mustReject(t, "ipsBlocked", `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"f"}}},{"protocol":"freedom","tag":"f","settings":{"ipsBlocked":["geoip:private"]}}]}`)
}

func hop(tag, dialer string) string {
	s := `{"protocol":"vless","tag":"` + tag + `","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"}`
	if dialer != "" {
		s += `,"streamSettings":{"sockopt":{"dialerProxy":"` + dialer + `"}}`
	}
	return s + `}`
}

func frag(hops ...string) string { return `{"outbounds":[` + strings.Join(hops, ",") + `]}` }

func TestChains(t *testing.T) {
	r := mustOK(t, frag(hop("exit", "hop_2"), hop("hop_2", "")))
	s := string(r.Normalized)
	if strings.Contains(s, "exit") || strings.Contains(s, "hop_2") || !strings.Contains(s, `"dialerProxy":"1"`) || !strings.Contains(s, `"tag":"0"`) || !strings.Contains(s, `"tag":"1"`) {
		t.Errorf("tags of the user survive: %s", s)
	}
	long := strings.Repeat("a", 200)
	mustOK(t, frag(hop(long, "ایران"), hop("ایران", "")))
	mustOK(t, frag(hop("a", "b"), hop("b", "c"), hop("c", "")))
	mustReject(t, "self", frag(hop("a", "a")))
	mustReject(t, "A to A through B", frag(hop("a", "b"), hop("b", "a")))
	mustReject(t, "A to B to A to C", frag(hop("a", "b"), hop("b", "a"), hop("c", "")))
	mustReject(t, "missing target", frag(hop("a", "nope")))
	mustReject(t, "ambiguous target", frag(hop("a", "b"), hop("b", ""), hop("b", "")))
	mustReject(t, "an outbound nothing reaches", frag(hop("a", ""), hop("b", "")))
	mustReject(t, "freedom first", `{"outbounds":[{"protocol":"freedom","tag":"x"}]}`)
	// A link inside a subtree the table does not list (downloadSettings, echSockopt) cannot
	// join the chain check, so it is refused even when the subtree is accepted.
	nested := `{"protocol":"vless","tag":"a","streamSettings":{"xhttpSettings":{"downloadSettings":{"address":"203.0.113.9","method":"xhttp","sockopt":{"dialerProxy":"b"}}}}}`
	mustReject(t, "downloadSettings link", frag(nested, hop("b", "")), "outbounds[0].streamSettings.xhttpSettings.downloadSettings")
	ech := `{"protocol":"vless","tag":"a","streamSettings":{"security":"tls","tlsSettings":{"echSockopt":{"dialerProxy":"b"}}}}`
	mustReject(t, "echSockopt link", frag(ech, hop("b", "")), "outbounds[0].streamSettings.tlsSettings.echSockopt")
	// An empty dialerProxy is no link.
	mustOK(t, frag(hop("a", "")))
}

func TestNoValueIsEverEchoed(t *testing.T) {
	const canary = "CANARY-pw-9f3a"
	frags := []string{
		`{"outbounds":[{"protocol":"trojan","settings":{"password":"` + canary + `"},"surprise":"` + canary + `","streamSettings":{"network":"` + canary + `"}}]}`,
		`{"outbounds":[{"protocol":"vless","settings":{"id":"` + canary + `","env":"` + canary + `"},"` + canary + `":1}]}`,
		`{"` + canary + `":1}`,
		`{"outbounds":[{"protocol":"shadowsocks","settings":{"method":"` + canary + `","password":"` + canary + `","address":"env:` + canary + `"}}]}`,
		`{"outbounds":[{"protocol":"vless","tag":"` + canary + `","streamSettings":{"sockopt":{"dialerProxy":"` + canary + `x"}}}]}`,
	}
	for _, f := range frags {
		r := check(t, f, "outbounds[0].surprise")
		var all []string
		for _, i := range r.Rejected {
			all = append(all, i.Path+" "+i.Msg)
		}
		for _, i := range r.Warnings {
			all = append(all, i.Path+" "+i.Msg)
		}
		for _, i := range r.Diff {
			all = append(all, i.Path+" "+i.Msg)
		}
		// A key the user wrote may show in a path (that is how it is named), a value never.
		for _, a := range all {
			if strings.Contains(a, canary) && !strings.Contains(f, `"`+canary+`":`) {
				t.Errorf("a value is echoed: %s", a)
			}
		}
	}
}

func TestShapeLimits(t *testing.T) {
	deep := outboundWith(`,"streamSettings":{"newThing":` + strings.Repeat(`[`, 40) + strings.Repeat(`]`, 40) + `}`)
	mustReject(t, "depth 40", deep)
	mustOK(t, `{"outbounds":[{"protocol":"vless","streamSettings":{"newThing":`+strings.Repeat(`[`, 20)+strings.Repeat(`]`, 20)+`}}]}`, "outbounds[0].streamSettings.newThing")
	mustReject(t, "trailing data", vlessReality+` {}`)
	mustReject(t, "trailing garbage", vlessReality+`x`)
	mustReject(t, "truncated", vlessReality[:40])
	mustReject(t, "invalid UTF-8", strings.Replace(vlessReality, "chrome", "\xff\xfe", 1))
	mustReject(t, "over 32 KiB", outboundWith(`,"surprise":"`+strings.Repeat("a", MaxFragmentBytes)+`"`), "outbounds[0].surprise")
	mustReject(t, "an outbound that is a string", `{"outbounds":["vless"]}`)
	mustReject(t, "an outbound that is null", `{"outbounds":[null]}`)
	mustReject(t, "outbounds that is null", `{"outbounds":null}`)
	// A value that is not of its kind is a warning at its path, a wrong JSON type included,
	// and that path passes it.
	for path, frag := range map[string]string{
		"outbounds[0].settings.port":         `{"outbounds":[{"protocol":"vless","settings":{"port":"443"}}]}`,
		"outbounds[0].tag":                   `{"outbounds":[{"protocol":"vless","tag":5}]}`,
		"outbounds[0].settings":              `{"outbounds":[{"protocol":"vless","settings":[]}]}`,
		"outbounds[0].settings.address":      `{"outbounds":[{"protocol":"vless","settings":{"address":"fromMitm"}}]}`,
		"outbounds[0].settings.vnext":        `{"outbounds":[{"protocol":"vless","settings":{"vnext":[]}}]}`,
		"outbounds[0].mux.concurrency":       `{"outbounds":[{"protocol":"vless","mux":{"concurrency":129}}]}`,
		"outbounds[0].settings.encryption":   `{"outbounds":[{"protocol":"vless","settings":{"encryption":"mlkem768x25519plus.native.0rtt.` + realityKey + `"}}]}`,
		"outbounds[0].settings.flow":         `{"outbounds":[{"protocol":"vless","settings":{"flow":"xtls-rprx-direct"}}]}`,
		"outbounds[0].streamSettings.method": `{"outbounds":[{"protocol":"vless","streamSettings":{"network":"kcp"}}]}`,
	} {
		r := check(t, frag)
		found := false
		for _, w := range r.Warnings {
			if w.Path == path {
				found = true
			}
		}
		if len(r.Rejected) != 0 || !found {
			t.Errorf("%s: warnings=%v rejected=%v", path, r.Warnings, r.Rejected)
		}
		if r.Normalized != nil {
			t.Errorf("%s: a fragment with a warning has a normal form", path)
		}
		if got := check(t, frag, path); !got.OK() {
			t.Errorf("%s: not accepted by its path: %v %v", path, got.Warnings, got.Rejected)
		}
	}
	// Two elements of vnext warn at the array, and each element is judged too.
	if r := check(t, `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{},{}]}}]}`); len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].settings.vnext" {
		t.Errorf("two vnext: %v %v", r.Warnings, r.Rejected)
	}
	// null, false and empty values are the loader's defaults: dropped with a line in Diff,
	// for a listed key and for an unlisted one.
	r := mustOK(t, outboundWith(`,"tag":null,"surprise":null,"other":false,"third":"","streamSettings":{"security":"","sockopt":{"dialerProxy":""}}`))
	for _, key := range []string{`"tag":null`, `"surprise"`, `"other"`, `"third"`, `"security"`, `"dialerProxy"`} {
		if strings.Contains(string(r.Normalized), key) {
			t.Errorf("%s was kept: %s", key, r.Normalized)
		}
	}
	if len(r.Diff) < 6 {
		t.Errorf("a dropped key has no line in Diff: %v", r.Diff)
	}
	// The same null is kept as pasted inside a subtree the admin accepted.
	r = mustOK(t, outboundWith(`,"surprise":{"a":null,"b":false}`), "outbounds[0].surprise")
	if !strings.Contains(string(r.Normalized), `"surprise":{"a":null,"b":false}`) {
		t.Errorf("an accepted subtree is not stored as pasted: %s", r.Normalized)
	}
	// An unlisted key with true or 0 is not a default.
	if r := check(t, outboundWith(`,"surprise":true,"other":0`)); len(r.Warnings) != 2 {
		t.Errorf("true and 0 are values: %v", r.Warnings)
	}
	// The always-rejected list is judged before the rule: a null does not drop one.
	mustReject(t, "null env", outboundWith(`,"env":null`))
	mustReject(t, "empty script", outboundWith(`,"script":""`))
	// The limit is on bytes in: exactly the limit is judged.
	pad := strings.Repeat("a", MaxFragmentBytes-len(outboundWith(`,"surprise":""`)))
	mustOK(t, outboundWith(`,"surprise":"`+pad+`"`), "outbounds[0].surprise")
}

func TestReleases(t *testing.T) {
	if _, err := For("v0.0.1"); err == nil {
		t.Error("an unknown release has a table")
	}
	if _, err := For(""); err == nil {
		t.Error("the empty tag has a table")
	}
	rs := Releases()
	if len(rs) == 0 {
		t.Fatal("no release")
	}
	for _, tag := range rs {
		tb, err := For(tag)
		if err != nil || tb.Release() != tag || !ValidReleaseTag(tag) {
			t.Errorf("release %s: %v", tag, err)
		}
	}
	if Newest().Release() != rs[len(rs)-1] {
		t.Error("Newest is not the last release")
	}
}

func TestValidReleaseTagAndPath(t *testing.T) {
	for _, s := range []string{"v26.11.9", "v1.0.0", "v100.200.300"} {
		if !ValidReleaseTag(s) {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{"", "26.11.9", "v26.11", "v26.11.9.1", "v26.11.", "v.1.2", "v1..2", "v1.2.3-rc1", "V1.2.3", "v1.2.3\n", "v1.2.x", "v1.2.3/../x"} {
		if ValidReleaseTag(s) {
			t.Errorf("%q accepted", s)
		}
	}
	for _, p := range []string{"outbounds[0].a", "outbounds[7].a.b[3].c", "outbounds[2].streamSettings.tlsSettings.alpn[0]", "outbounds[0].a_b-c"} {
		if !ValidPath(p) {
			t.Errorf("path %s refused", p)
		}
	}
	for _, p := range []string{"", "outbounds", "outbounds[0]", "outbounds[8].a", "outbounds[10].a", "outbounds[0][1]", "outbounds[0].a[]", "outbounds[0].a[1", "outbounds[0].a.", "outbounds[0].a.b c", "Outbounds[0].a", "outbounds[0].a" + strings.Repeat("a", 300)} {
		if ValidPath(p) {
			t.Errorf("path %q accepted", p)
		}
	}
}

func TestListedKeysPass(t *testing.T) {
	tls := `"security":"tls","tlsSettings":{"serverName":"a.example","alpn":["h2","http/1.1"],"fingerprint":"chrome","pinnedPeerCertSha256":"` + strings.Repeat("ab", 32) + `"}`
	mustOK(t, outboundWith(`,"streamSettings":{"network":"xhttp",`+tls+`,
		"xhttpSettings":{"host":"a.example","path":"/x","mode":"auto","headers":{"A":"b"},"noGRPCHeader":true,"xPaddingBytes":"100-1000","scMaxEachPostBytes":1000000,
		"extra":{"xPaddingBytes":"100-1000","headers":{"A":"b"},"noGRPCHeader":false,"scMaxEachPostBytes":"20000-30000"}}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"s","authority":"a.example","multiMode":false,"permit_without_stream":false,"idle_timeout":60,"health_check_timeout":20,"initial_windows_size":0}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"version":"1.1","method":"GET","path":["/a","/b"],"headers":{"Host":["a.example","b.example"],"X":"y"}}}}}`))
	mustOK(t, outboundWith(`,"streamSettings":{"security":"reality","realitySettings":{"serverName":"a.example","fingerprint":"firefox","publicKey":"`+realityKey+`","shortId":"ab12","spiderX":"/a/b_c-d.e~f"}}`))
	mustOK(t, `{"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"203.0.113.7","port":443},"streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"a"},"tlsSettings":{"serverName":"h.example","alpn":["h3"]},
		"finalmask":{"udp":[{"type":"salamander","settings":{"password":"p"}},{"type":"udphop","settings":{"mode":"intervalRemote","interval":"5-600","remotePorts":"20000-30000"}}]}}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"shadowsocks","settings":{"address":"203.0.113.7","port":8388,"method":"2022-BLAKE3-AES-128-GCM","password":"x","ota":true,"level":3}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"203.0.113.7","port":1080,"users":[{"user":"u","pass":"p","level":1}]}]}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"203.0.113.7","port":443,"users":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","security":"auto","alterId":0}]}]},"mux":{"enabled":true,"concurrency":8,"xudpConcurrency":16}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"http","settings":{"address":"203.0.113.7","port":3128,"user":"u","pass":"p"}}]}`)
	mustOK(t, `{"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"a.example","port":443,"password":"p"}]}}]}`)
	mustReject(t, "noise script", outboundWith(`,"streamSettings":{"finalmask":{"udp":[{"type":"noise","settings":{"script":"os.execute('x')"}}]}}`), "outbounds[0].streamSettings.finalmask.udp[0].type")
	// Dropped with a line in Diff: keys that have no effect on this node.
	r := mustOK(t, outboundWith(`,"mux":{"xudpProxyUDP443":"reject"},"streamSettings":{"sockopt":{"domainStrategy":"UseIP","tcpNoDelay":true}}`))
	for _, key := range []string{"xudpProxyUDP443", "domainStrategy", "tcpNoDelay"} {
		if strings.Contains(string(r.Normalized), key) {
			t.Errorf("%s was kept: %s", key, r.Normalized)
		}
	}
	// A legacy alterId that is not 0 is not dropped: it is unknown.
	if r := check(t, `{"outbounds":[{"protocol":"vmess","settings":{"alterId":4}}]}`); len(r.Warnings) != 1 {
		t.Errorf("alterId 4: %v", r.Warnings)
	}
}

// kcp is the one transport that is an unknown value; any other unlisted transport is
// refused for good.
func TestKcpIsUnknownAndOtherTransportsAreRefused(t *testing.T) {
	for _, n := range []string{"kcp", "mkcp", "KCP"} {
		r := check(t, outboundWith(`,"streamSettings":{"network":"`+n+`"}`))
		if len(r.Rejected) != 0 || len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].streamSettings.method" {
			t.Errorf("%s: %v %v", n, r.Warnings, r.Rejected)
		}
		r = check(t, outboundWith(`,"streamSettings":{"network":"`+n+`","kcpSettings":{"mtu":1350}}`), "outbounds[0].streamSettings.method")
		if len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].streamSettings.kcpSettings" {
			t.Errorf("%s with settings: %v", n, r.Warnings)
		}
		mustOK(t, outboundWith(`,"streamSettings":{"network":"`+n+`","kcpSettings":{"mtu":1350}}`), "outbounds[0].streamSettings.method", "outbounds[0].streamSettings.kcpSettings")
	}
	// B1n-r1-3: the dialer of httpupgrade panics on bytes after the 101 header, so it is an
	// unknown value like kcp, and its settings are unknown keys.
	for _, n := range []string{"httpupgrade", "HttpUpgrade"} {
		r := check(t, outboundWith(`,"streamSettings":{"network":"`+n+`","httpupgradeSettings":{"host":"a.example"}}`))
		if len(r.Rejected) != 0 || len(r.Warnings) != 2 || r.OK() {
			t.Errorf("%s: %v %v", n, r.Warnings, r.Rejected)
		}
		mustOK(t, outboundWith(`,"streamSettings":{"network":"`+n+`","httpupgradeSettings":{"host":"a.example"}}`), "outbounds[0].streamSettings.method", "outbounds[0].streamSettings.httpupgradeSettings")
	}
	mustReject(t, "quic", outboundWith(`,"streamSettings":{"network":"quic"}`), "outbounds[0].streamSettings.method")
}

// A mask other than the one salamander and the one udphop, in that order, is not on the
// list: another type, a third mask, a repeat and the wrong order each warn.
func TestMaskOrder(t *testing.T) {
	sal := `{"type":"salamander","settings":{"password":"p"}}`
	hop := `{"type":"udphop","settings":{"mode":"intervalRemote","interval":30,"remotePorts":"1000-2000"}}`
	udp := func(masks ...string) string {
		return outboundWith(`,"streamSettings":{"finalmask":{"udp":[` + strings.Join(masks, ",") + `]}}`)
	}
	mustOK(t, udp())
	mustOK(t, udp(sal))
	mustOK(t, udp(hop))
	mustOK(t, udp(sal, hop))
	for name, frag := range map[string]string{"hop first": udp(hop, sal), "two salamanders": udp(sal, sal), "three": udp(sal, hop, hop)} {
		if r := check(t, frag); r.OK() || len(r.Rejected) != 0 {
			t.Errorf("%s: %v %v", name, r.Warnings, r.Rejected)
		}
	}
	if r := check(t, outboundWith(`,"streamSettings":{"finalmask":{"tcp":[{"type":"fragment","settings":{}}]}}`)); len(r.Warnings) != 1 || r.Warnings[0].Path != "outbounds[0].streamSettings.finalmask.tcp" {
		t.Errorf("tcp masks: %v", r.Warnings)
	}
	// The order is one more thing a warning can pass.
	mustOK(t, udp(hop, sal), "outbounds[0].streamSettings.finalmask.udp")
}

// quicParams.debug makes the release call os.Setenv in the Xray process: refused at any
// depth. The other quic parameters are unknown.
func TestQuicDebugSetsTheEnvironmentAndIsRefused(t *testing.T) {
	mustReject(t, "quic debug", outboundWith(`,"streamSettings":{"finalmask":{"quicParams":{"debug":true}}}`), "outbounds[0].streamSettings.finalmask.quicParams")
	if r := check(t, outboundWith(`,"streamSettings":{"finalmask":{"quicParams":{"congestion":"bbr"}}}`)); len(r.Warnings) != 1 {
		t.Errorf("quicParams: %v", r.Warnings)
	}
}

// FuzzCheck: whatever bytes arrive, Check never panics, the normal form of an accepted
// fragment is a fixed point of Check, and a fragment is never accepted that holds a
// key of the always-rejected list at any depth.
func FuzzCheck(f *testing.F) {
	f.Add([]byte(vlessReality), "")
	f.Add([]byte(outboundWith(`,"streamSettings":{"sockopt":{"dialerProxy":"x"}}`)), "outbounds[0].a")
	f.Add([]byte(`{"outbounds":[{"protocol":"vless","tag":"a","streamSettings":{"sockopt":{"dialerProxy":"b"}}},{"protocol":"freedom","tag":"b"}]}`), "")
	f.Add([]byte(`{"outbounds":[{"protocol":"wireguard","settings":{"isClient":true}}]}`), "")
	f.Add([]byte(tlsWith(`,"echConfigList":"https://1.1.1.1/dns-query"`)), "")
	f.Add([]byte(outboundWith(`,"streamSettings":{"security":"reality","realitySettings":{"spiderX":"/?p=1"}}`)), "")
	f.Add([]byte(`{`), "")
	f.Fuzz(func(t *testing.T, data []byte, accept string) {
		r := Newest().Check(data, strings.Split(accept, ","))
		if len(r.Rejected) != 0 {
			if r.Normalized != nil {
				t.Fatal("a rejected fragment has a normal form")
			}
			return
		}
		// A fragment with a warning keeps its normal form in Preview only.
		form := r.Normalized
		if len(r.Warnings) != 0 {
			if r.Normalized != nil {
				t.Fatal("a fragment with a warning has a normal form to store")
			}
			form = r.Preview
		}
		again := Newest().Check(form, strings.Split(accept, ","))
		againForm := again.Normalized
		if len(again.Warnings) != 0 {
			againForm = again.Preview
		}
		if len(again.Rejected) != 0 || !bytes.Equal(againForm, form) {
			t.Fatalf("the normal form is not a fixed point:\n%s\n%s\n%v", form, againForm, again.Rejected)
		}
		for k := range globalRejected() {
			if bytes.Contains(bytes.ToLower(form), []byte(`"`+k+`":`)) {
				t.Fatalf("an accepted fragment holds the key %s: %s", k, form)
			}
		}
		if root, err := parse(form); err == nil {
			if key := keyedViolation(root); key != "" {
				t.Fatalf("an accepted fragment holds a bad %s: %s", key, form)
			}
		}
	})
}

// keyedViolation finds a member of the tree that keyedChecks refuse, at any depth.
func keyedViolation(v *val) string {
	for _, m := range v.members {
		if _, bad := keyedCheck(m.key, m.v); bad {
			return m.key
		}
		if k := keyedViolation(m.v); k != "" {
			return k
		}
	}
	for _, it := range v.items {
		if k := keyedViolation(it); k != "" {
			return k
		}
	}
	return ""
}
