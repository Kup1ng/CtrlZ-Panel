package xrayschema

import (
	"strings"
	"testing"
)

// Tests for the findings of review round 4 of B1 (p4b-proxy 7.2) that still name a key
// the table accepts or a rule it keeps. What a number, a string or a mask combination of
// an unlisted key can make the one Xray process do is not judged here any more: the key
// is unknown, and 7.5 step 4 contains the harm.

// refuse is mustReject that also fails when the fragment is not JSON, so a typo in a
// test fragment cannot make a test pass by accident.
func refuse(t *testing.T, what, frag string, accept ...string) Result {
	t.Helper()
	r := mustReject(t, what, frag, accept...)
	for _, rj := range r.Rejected {
		if rj.Path == "" {
			t.Errorf("%s: the fragment is not read at all: %s", what, rj.Msg)
		}
	}
	return r
}

func stream4(inner string) string {
	return outboundWith(`,"streamSettings":{` + inner + `}`)
}

// B1-r4-1 and B1-r4-7: happyEyeballs races up to maxConcurrentTry ports for one dial,
// which the dial limits of 5.5 are not sized for. It is refused wherever it sits, in
// any case, and a path in accept_unknown changes nothing.
func TestHappyEyeballsIsRefusedEverywhere(t *testing.T) {
	he := `{"tryDelayMs":1,"maxConcurrentTry":16}`
	for name, frag := range map[string]string{
		"outbound sockopt": stream4(`"sockopt":{"happyEyeballs":` + he + `}`),
		"lower case":       stream4(`"sockopt":{"happyeyeballs":` + he + `}`),
		"upper case":       stream4(`"sockopt":{"HAPPYEYEBALLS":` + he + `}`),
		"echSockopt":       tlsWith(`,"echSockopt":{"happyEyeballs":` + he + `}`),
		"downloadSettings": stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{"sockopt":{"happyEyeballs":` + he + `}}}`),
		"extra":            stream4(`"method":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"sockopt":{"happyEyeballs":` + he + `}}}}`),
		"raw subtree":      stream4(`"xhttpSettings":{"h2Params":{"happyEyeballs":` + he + `}}`),
		"unknown key":      stream4(`"newThing":{"happyEyeballs":` + he + `}`),
	} {
		refuse(t, name, frag)
		refuse(t, name+" (accepted path)", frag, "outbounds[0].streamSettings.newThing.happyEyeballs", "outbounds[0].streamSettings.sockopt.happyEyeballs")
	}
}

// Everything of a sockopt but dialerProxy is unknown, including the TCP tuning of the
// old table (fast open, keepalive, congestion, window clamp): the admin who wants it
// accepts it by path.
func TestSockoptTuningIsUnknown(t *testing.T) {
	for _, k := range []string{"tcpFastOpen", "tcpKeepAliveIdle", "tcpCongestion", "tcpWindowClamp", "tcpMptcp", "penetrate", "v6only", "tcpUserTimeout"} {
		mustWarn(t, k, stream4(`"sockopt":{"`+k+`":1}`), "outbounds[0].streamSettings.sockopt."+k)
		mustOK(t, stream4(`"sockopt":{"`+k+`":1}`), "outbounds[0].streamSettings.sockopt."+k)
	}
}

// The noises of a freedom hop, the protocol options and the mkcp masks are unknown: the
// old bounds on them are gone with their keys.
func TestKeysTheListDoesNotHoldAreUnknown(t *testing.T) {
	for name, tc := range map[string]struct{ frag, path string }{
		"freedom noises":   {freedomHop(`"noises":[{"type":"rand","packet":"1-9999999999999"}]`), "outbounds[1].settings.noises"},
		"freedom noise":    {freedomHop(`"noise":{"type":"rand","packet":"1-9999999999999"}`), "outbounds[1].settings.noise"},
		"freedom maxSplit": {freedomHop(`"fragment":{"maxSplit":99999}`), "outbounds[1].settings.fragment.maxSplit"},
		"proxyProtocol":    {freedomHop(`"proxyProtocol":2`), "outbounds[1].settings.proxyProtocol"},
		"xmux":             {stream4(`"method":"xhttp","xhttpSettings":{"xmux":{"maxConnections":99999}}`), "outbounds[0].streamSettings.xhttpSettings.xmux"},
		"scMinPostsIntervalMs": {stream4(`"method":"xhttp","xhttpSettings":{"scMinPostsIntervalMs":2000000000}`),
			"outbounds[0].streamSettings.xhttpSettings.scMinPostsIntervalMs"},
		"downloadSettings":  {stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{"method":"raw"}}`), "outbounds[0].streamSettings.xhttpSettings.downloadSettings"},
		"kcp settings":      {stream4(`"method":"kcp","kcpSettings":{"mtu":21}`), "outbounds[0].streamSettings.kcpSettings"},
		"ws heartbeat":      {stream4(`"method":"ws","wsSettings":{"heartbeatPeriod":-1}`), "outbounds[0].streamSettings.wsSettings.heartbeatPeriod"},
		"grpc user_agent":   {stream4(`"method":"grpc","grpcSettings":{"user_agent":"x"}`), "outbounds[0].streamSettings.grpcSettings.user_agent"},
		"hysteria idle":     {stream4(`"method":"hysteria","hysteriaSettings":{"udpIdleTimeout":5}`), "outbounds[0].streamSettings.hysteriaSettings.udpIdleTimeout"},
		"outbound strategy": {outboundWith(`,"targetStrategy":"UseIP"`), "outbounds[0].targetStrategy"},
		"stream address":    {stream4(`"address":"a.example"`), "outbounds[0].streamSettings.address"},
		"tls min version":   {tlsWith(`,"minVersion":"1.3"`), "outbounds[0].streamSettings.tlsSettings.minVersion"},
		"tls certificates":  {tlsWith(`,"certificates":[]`), "outbounds[0].streamSettings.tlsSettings.certificates"},
		"reality show":      {stream4(`"security":"reality","realitySettings":{"show":true}`), "outbounds[0].streamSettings.realitySettings.show"},
		"reality mldsa":     {stream4(`"security":"reality","realitySettings":{"mldsa65Verify":"x"}`), "outbounds[0].streamSettings.realitySettings.mldsa65Verify"},
		"vless seed":        {`{"outbounds":[{"protocol":"vless","settings":{"seed":"x"}}]}`, "outbounds[0].settings.seed"},
		"vmess experiments": {`{"outbounds":[{"protocol":"vmess","settings":{"experiments":"x"}}]}`, "outbounds[0].settings.experiments"},
		"trojan flow":       {`{"outbounds":[{"protocol":"trojan","settings":{"flow":"x"}}]}`, "outbounds[0].settings.flow"},
		"wireguard dns":     {strings.Replace(wireguard(``), `"mtu":1280`, `"remoteDNS":["1.1.1.1"]`, 1), "outbounds[0].settings.remoteDNS"},
		"http headers":      {`{"outbounds":[{"protocol":"http","settings":{"headers":{"X":"{{ .Source }}"}}}]}`, "outbounds[0].settings.headers"},
	} {
		r := mustWarn(t, name, tc.frag, tc.path)
		// The warning says that nothing was judged.
		for _, w := range r.Warnings {
			if w.Path == tc.path && !strings.Contains(w.Msg, "does not judge") {
				t.Errorf("%s: %s", name, w.Msg)
			}
		}
		// The path passes it, as pasted.
		mustOK(t, tc.frag, tc.path, "outbounds[0].streamSettings.method")
	}
}
