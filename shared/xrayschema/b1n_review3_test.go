package xrayschema

import (
	"strings"
	"testing"
)

const (
	r3Hysteria = `"protocol":"hysteria","settings":{"version":2,"address":"203.0.113.8","port":443}`
	r3HysTail  = `"security":"tls","hysteriaSettings":{"version":2,"auth":"a"},"tlsSettings":{"serverName":"h.example","alpn":["h3"]}`
)

// hysteriaHop is a hysteria outbound tagged "h" that the outbound before it dials through.
func r3HysteriaHop(tag string) string {
	return `{` + r3Hysteria + `,"tag":"` + tag + `","streamSettings":{"method":"hysteria",` + r3HysTail + `}}`
}

// B1n-r3-2: a hysteria hop is handed the UDP of the outbound before it and sends it as
// datagrams cut to the size the exit announces, and FragUDPMessage counts the fragments
// in a uint8: a small size indexes past its slice and ends the process every location
// shares. A hysteria outbound anywhere but first is an unknown thing.
func TestHysteriaHopIsUnknown(t *testing.T) {
	const path = "outbounds[1].settings"
	wg := wgThrough("h")
	mains := map[string]string{
		"hysteria main":  `{` + r3Hysteria + `,"streamSettings":{"method":"hysteria",` + r3HysTail + `,"sockopt":{"dialerProxy":"h"}}}`,
		"wireguard main": wg,
		"xhttp h3 main": `{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},` +
			`"streamSettings":{"method":"xhttp","security":"tls","tlsSettings":{"serverName":"a.example","alpn":["h3"]},"sockopt":{"dialerProxy":"h"}}}`,
		"tcp main": `{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},"streamSettings":{"sockopt":{"dialerProxy":"h"}}}`,
	}
	for name, main := range mains {
		frag := `{"outbounds":[` + main + `,` + r3HysteriaHop("h") + `]}`
		mustWarn(t, name, frag, path)
		// The admin may accept it, at exactly that path.
		mustOK(t, frag, path)
	}
	// A socks hop between a UDP main and the hysteria hop passes the UDP on.
	socks := `{"protocol":"socks","tag":"s","settings":{"address":"203.0.113.9","port":1080},"streamSettings":{"sockopt":{"dialerProxy":"h"}}}`
	main := wgThrough("s")
	frag := `{"outbounds":[` + main + `,` + socks + `,` + r3HysteriaHop("h") + `]}`
	mustWarn(t, "socks between", frag, "outbounds[2].settings")
	// A hysteria exit that is the first outbound gets no UDP at the node.
	mustOK(t, `{"outbounds":[`+strings.Replace(mains["hysteria main"], `,"sockopt":{"dialerProxy":"h"}`, "", 1)+`]}`)
	// Other hops are not judged by this rule.
	mustOK(t, `{"outbounds":[`+mains["tcp main"]+`,{"protocol":"socks","tag":"h","settings":{"address":"203.0.113.9","port":1080}}]}`)
}

// B1n-r3-3: a hop can be dialed with the UDP of its main outbound, and then the two xudp
// keys of its mux decide whether that UDP passes (udp443 "reject" is the loader's
// default). They are idle on the first outbound only.
func TestXudpKeysOfAMuxHopAreUnknown(t *testing.T) {
	hop := func(mux string) string {
		return `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},"streamSettings":{"sockopt":{"dialerProxy":"h"}}},` +
			`{"protocol":"vless","tag":"h","settings":{"address":"203.0.113.9","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"},"mux":` + mux + `}]}`
	}
	for _, key := range []string{"xudpProxyUDP443", "xudpConcurrency"} {
		val := `"skip"`
		if key == "xudpConcurrency" {
			val = `-1`
		}
		mux := `{"enabled":true,"concurrency":8,"` + key + `":` + val + `}`
		mustWarn(t, key+" on a hop", hop(mux), "outbounds[1].mux."+key)
		mustOK(t, hop(mux), "outbounds[1].mux."+key)
		// On the first outbound it is still dropped with a line in Diff.
		r := mustOK(t, outboundWith(`,"mux":`+mux))
		if strings.Contains(string(r.Normalized), key) {
			t.Errorf("%s kept on the first outbound: %s", key, r.Normalized)
		}
	}
	// A hop with no xudp key is as before.
	mustOK(t, hop(`{"enabled":true,"concurrency":8}`))
}

// B1n-r3-1: three kinds were narrower than the loader.
func TestKindsAsWideAsTheLoader(t *testing.T) {
	// uuid.ParseString reads 32 hex digits with no dash.
	for _, id := range []string{"5783a3e7e37351cd8642c83782b807c5", "5783A3E7E37351CD8642C83782B807C5"} {
		mustOK(t, strings.Replace(outboundWith(``), "5783a3e7-e373-51cd-8642-c83782b807c5", id, 1))
	}
	// Still narrower than the loader where it is not a UUID: 31 or 33 characters, a dash
	// in the wrong place, and non-hex digits are text of more than 30 bytes.
	for _, id := range []string{"5783a3e7e37351cd8642c83782b807c", "5783a3e7e37351cd8642c83782b807c5a", "5783a3e7-e37351cd-8642c83782b807c5", "5783a3e7e37351cd8642c83782b807cz"} {
		if r := check(t, strings.Replace(outboundWith(``), "5783a3e7-e373-51cd-8642-c83782b807c5", id, 1)); r.OK() {
			t.Errorf("id %q passed", id)
		}
	}
	// ParseWireGuardKey trims one "=" and decodes with the Raw encodings.
	if !key32OK(wgKey) || !key32OK(strings.TrimSuffix(wgKey, "=")) {
		t.Errorf("padded or unpadded key refused: %q", wgKey)
	}
	for _, k := range []string{strings.TrimSuffix(wgKey, "=") + "==", strings.TrimSuffix(wgKey, "=")[:42], ""} {
		if key32OK(k) {
			t.Errorf("key %q passed", k)
		}
	}
	mustOK(t, wireguard(``))
	unpadded := strings.ReplaceAll(wireguard(``), wgKey, strings.TrimSuffix(wgKey, "="))
	mustOK(t, unpadded)
	// The loader lower-cases fragment.packets: TLSHello is written as tlshello.
	frag := `{"outbounds":[{"protocol":"vless","streamSettings":{"sockopt":{"dialerProxy":"frag"}}},{"protocol":"freedom","tag":"frag","settings":{"fragment":{"packets":"TLSHello","length":"100-200","interval":"10-20"}}}]}`
	r := mustOK(t, frag)
	if !strings.Contains(string(r.Normalized), `"packets":"tlshello"`) || len(r.Diff) == 0 {
		t.Errorf("packets not written in canonical form: %s %v", r.Normalized, r.Diff)
	}
	if r := check(t, strings.Replace(frag, "TLSHello", "tlshello2", 1)); r.OK() {
		t.Error("an unknown packets value passed")
	}
}

// wgThrough is a wireguard outbound that dials its endpoint through the hop of that tag.
func wgThrough(tag string) string {
	return strings.TrimSuffix(strings.Replace(wgFull, "%s", "", 1), "}") + `,"streamSettings":{"sockopt":{"dialerProxy":"` + tag + `"}}}`
}
