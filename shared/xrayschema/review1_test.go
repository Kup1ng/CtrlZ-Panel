package xrayschema

import (
	"strings"
	"testing"
)

// Tests for the findings of review round 1 of B1 (p4b-proxy 7.2) that still name a key
// the table accepts or a rule it keeps. They are kept in their own file so each names
// the finding it closes.

// mustWarn is a check that must end in warnings and no rejection, with a warning at
// path. A path of "" asks for any.
func mustWarn(t *testing.T, what, frag, path string, accept ...string) Result {
	t.Helper()
	r := check(t, frag, accept...)
	if len(r.Rejected) != 0 {
		t.Errorf("%s: rejected %v", what, r.Rejected)
	}
	found := path == "" && len(r.Warnings) > 0
	for _, w := range r.Warnings {
		if w.Path == path {
			found = true
		}
	}
	if !found {
		t.Errorf("%s: no warning at %q: %v", what, path, r.Warnings)
	}
	if r.Normalized != nil {
		t.Errorf("%s: a fragment with a warning has a normal form", what)
	}
	return r
}

// B1-r1-3 and B1-r1-12: a key repeated in any case is refused wherever it sits, in a
// table object, among unknown keys and inside an accepted subtree, and one name twice in
// a free-form map too (its first value would be dropped without a word).
func TestRepeatsAreRefusedAmongUnknownKeysAndInRawSubtrees(t *testing.T) {
	accept := []string{
		"outbounds[0].streamSettings.foo", "outbounds[0].streamSettings.newThing",
		"outbounds[0].streamSettings.newThing.a[0].b", "outbounds[0].streamSettings.xhttpSettings.h2Params",
	}
	for name, extra := range map[string]string{
		"unknown key twice":     `,"streamSettings":{"foo":1,"foo":2}`,
		"unknown key two cases": `,"streamSettings":{"foo":1,"FOO":3}`,
		"raw h2Params":          `,"streamSettings":{"xhttpSettings":{"h2Params":{"a":1,"A":2}}}`,
		"raw in unknown tree":   `,"streamSettings":{"newThing":{"a":[{"b":1,"B":2}]}}`,
		"free-form map":         `,"streamSettings":{"wsSettings":{"headers":{"A":"1","A":"2"}}}`,
		"null and a value":      `,"tag":"a","TAG":null`,
	} {
		mustReject(t, name, outboundWith(extra), accept...)
	}
	// Header names that differ in case are two keys of a Go map and stay allowed.
	mustOK(t, outboundWith(`,"streamSettings":{"network":"ws","wsSettings":{"headers":{"A":"1","a":"2"}}}`))
	// With the same key once, the accepted path passes.
	mustOK(t, outboundWith(`,"streamSettings":{"foo":1}`), "outbounds[0].streamSettings.foo")
}

// B1-r1-4: Normalized is what a caller stores, so it is empty while a warning stands;
// Preview is the display copy of the panel's parse (7.3).
func TestOnlyAFragmentWithNoWarningHasANormalForm(t *testing.T) {
	frag := outboundWith(`,"streamSettings":{"newThing":{"a":1}}`)
	r := check(t, frag)
	if r.OK() || len(r.Warnings) != 1 {
		t.Fatalf("warnings=%v rejected=%v", r.Warnings, r.Rejected)
	}
	if r.Normalized != nil {
		t.Errorf("a fragment with a warning has a normal form to store: %s", r.Normalized)
	}
	if !strings.Contains(string(r.Preview), "newThing") {
		t.Errorf("the preview lacks the unknown key: %s", r.Preview)
	}
	r = check(t, frag, "outbounds[0].streamSettings.newThing")
	if !r.OK() || r.Normalized == nil || r.Preview != nil {
		t.Errorf("an accepted fragment: ok=%v normalized=%q preview=%q", r.OK(), r.Normalized, r.Preview)
	}
	if r := mustReject(t, "rejected", `{"outbounds":[]}`); r.Preview != nil {
		t.Errorf("a rejected fragment has a preview")
	}
}

// B1-r1-7: Xray strips every leading "!" before it reads the prefix, and maps geoip:
// and geosite: to ext:, which opens a file of the asset directory. ext-site: is one of
// the prefixes the loader takes too. The mask is unknown, and what is never allowed is
// refused inside it all the same.
func TestEveryLeadingBangIsStrippedBeforeThePrefixIsRead(t *testing.T) {
	filter := func(list string) string {
		return outboundWith(`,"streamSettings":{"finalmask":{"tcp":[{"type":"filter","settings":{"blockedSourceIPs":` + list + `}}]}}`)
	}
	for name, list := range map[string]string{
		"one bang":         `["!geoip:cn"]`,
		"two bangs ext":    `["!!ext:xray:cn"]`,
		"two bangs geoip":  `["!!geoip:cn"]`,
		"three bangs":      `["!!!geosite:cn"]`,
		"bang and space":   `["! !ext:a:b"]`,
		"ext-site":         `["!ext-site:a:b"]`,
		"second part":      `["198.51.100.0/24, !!ext-ip:a:b"]`,
		"upper case, bang": `["!!GeoIP:CN"]`,
	} {
		mustReject(t, name, filter(list), "outbounds[0].streamSettings.finalmask.tcp")
	}
	mustOK(t, filter(`["198.51.100.0/24"]`), "outbounds[0].streamSettings.finalmask.tcp")
}

// B1-r1-8: a subtree that the table has no node for (the settings of an accepted mask
// type) is still judged for what is never allowed: a dialerProxy escapes the chain
// check, and quicConfig.debug of an xdns resolver calls os.Setenv.
func TestAnAcceptedMaskCannotCarryWhatTheTableRefuses(t *testing.T) {
	// The type and its settings are two paths, and the admin accepts both (B1n-r2-5).
	accept := []string{"outbounds[0].streamSettings.finalmask.udp[0].type", "outbounds[0].streamSettings.finalmask.udp[0].settings"}
	mask := func(settings string) string {
		return outboundWith(`,"streamSettings":{"finalmask":{"udp":[{"type":"xdns","settings":` + settings + `}]}}`)
	}
	mustOK(t, mask(`{"resolvers":[{"addr":"a.example"}]}`), accept...)
	for name, settings := range map[string]string{
		"dialerProxy of an ech sockopt": `{"resolvers":[{"tlsConfig":{"echSockopt":{"dialerProxy":"L00000000000000000000000000000001.1.0"}}}]}`,
		"dialerProxy in any case":       `{"resolvers":[{"tlsConfig":{"echSockopt":{"DIALERPROXY":"direct"}}}]}`,
		"quicConfig debug":              `{"resolvers":[{"quicConfig":{"debug":true}}]}`,
		"portMapping of realm":          `{"portMapping":true}`,
		"isClient":                      `{"isClient":false}`,
		"masqueSettings":                `{"masqueSettings":{}}`,
	} {
		mustReject(t, name, mask(settings), accept...)
	}
	// The same key as an unknown key of a table object, where the admin could accept it.
	mustReject(t, "unknown dialerProxy key", outboundWith(`,"streamSettings":{"tlsSettings":{"dialerProxy":"x"}}`),
		"outbounds[0].streamSettings.tlsSettings.dialerProxy")
}

// B1-r1-9, redone in B1-r2-3 and B1-r2-9: testpre starts that many endless pre-dial
// goroutines in the Xray process that every location of the node shares. A warning is
// not enough (an exact path in accept_unknown passes it), so it is refused for good, at
// the settings, in a user of vnext and in any subtree.
func TestVlessTestpreIsRefusedForGood(t *testing.T) {
	frag := `{"outbounds":[{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none","testpre":100000}}]}`
	mustReject(t, "testpre", frag, "outbounds[0].settings.testpre")
	mustReject(t, "TESTPRE", strings.Replace(frag, "testpre", "TESTPRE", 1), "outbounds[0].settings.TESTPRE")
	userPre := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.7","port":443,"users":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","testpre":5}]}]}}]}`
	mustReject(t, "testpre of a user", userPre, "outbounds[0].settings.vnext[0].users[0].testpre")
	mustReject(t, "testpre in a raw subtree", outboundWith(`,"streamSettings":{"xhttpSettings":{"h2Params":{"testpre":1}}}`), "outbounds[0].streamSettings.xhttpSettings.h2Params")
	// testseed is unknown like any key the list does not hold.
	user := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.7","port":443,"users":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","testseed":[1,2]}]}]}}]}`
	mustWarn(t, "testseed of a user", user, "outbounds[0].settings.vnext[0].users[0].testseed")
}

// B1-r1-10: the release always refuses allowInsecure true, so it is refused here at any
// depth and never reaches a node's -test. false is the loader's default and is dropped.
func TestAllowInsecureTrueIsRefused(t *testing.T) {
	tls := func(v string) string {
		return outboundWith(`,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example","allowInsecure":` + v + `}}`)
	}
	mustReject(t, "allowInsecure true", tls("true"))
	mustReject(t, "allowInsecure true, path accepted", tls("true"), "outbounds[0].streamSettings.tlsSettings.allowInsecure")
	mustOK(t, tls("false"))
	mustReject(t, "in a subtree", outboundWith(`,"streamSettings":{"newThing":{"allowInsecure":true}}`), "outbounds[0].streamSettings.newThing")
}

// B1-r1-13: the selector of a variant is required. An outbound with no protocol and a
// mask with no type have settings that no table node judges.
func TestTheSelectorOfAVariantIsRequired(t *testing.T) {
	mustReject(t, "no protocol", `{"outbounds":[{"settings":{"a":1}}]}`)
	mustReject(t, "empty protocol", `{"outbounds":[{"protocol":"","settings":{"a":1}}]}`)
	mustReject(t, "no mask type", outboundWith(`,"streamSettings":{"finalmask":{"udp":[{"settings":{"password":"p"}}]}}`))
}

// The always-rejected list of 7.2 holds portMapping and addressPortStrategy at any depth.
func TestPortMappingAndAddressPortStrategyAreRefused(t *testing.T) {
	mustReject(t, "addressPortStrategy", outboundWith(`,"streamSettings":{"sockopt":{"addressPortStrategy":"SrvPortOnly"}}`))
	mustReject(t, "portMapping", outboundWith(`,"streamSettings":{"newThing":{"portMapping":[]}}`), "outbounds[0].streamSettings.newThing")
}
