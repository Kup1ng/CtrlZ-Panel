package xrayschema

import (
	"strings"
	"testing"
)

// B1n-r2-3: in multi mode the client of the release takes one 8192-byte buffer for every
// element of a MultiHunk, bounded only by the 4 MiB message limit of gRPC, so one message
// of one-byte elements makes Xray allocate gigabytes. multiMode true is an unknown key.
func TestGrpcMultiModeIsUnknown(t *testing.T) {
	grpc := func(g string) string {
		return outboundWith(`,"streamSettings":{"method":"grpc","grpcSettings":{` + g + `}}`)
	}
	const path = "outbounds[0].streamSettings.grpcSettings.multiMode"
	mustWarn(t, "multiMode true", grpc(`"serviceName":"s","multiMode":true`), path)
	mustOK(t, grpc(`"serviceName":"s","multiMode":true`), path)
	// false is the default of Xray: it is dropped and nothing is stored for it.
	r := mustOK(t, grpc(`"serviceName":"s","multiMode":false`))
	if string(r.Normalized) == "" || strings.Contains(string(r.Normalized), "multiMode") {
		t.Errorf("multiMode false kept: %s", r.Normalized)
	}
	mustOK(t, grpc(`"serviceName":"s"`))
}

// B1n-r2-5: the settings of a mask whose type is not on the list were judged by no table,
// and the acceptance of the type alone let them into the stored fragment with no path of
// their own in the warnings.
func TestSettingsOfAnUnlistedMaskTypeHaveAPathOfTheirOwn(t *testing.T) {
	mask := func(m string) string {
		return `{"outbounds":[{"protocol":"hysteria","settings":{"version":2,"address":"203.0.113.7","port":443},"streamSettings":{"network":"hysteria","security":"tls","hysteriaSettings":{"version":2,"auth":"a"},"tlsSettings":{"serverName":"h.example","alpn":["h3"]},"finalmask":{"udp":[` + m + `]}}}]}`
	}
	const typ = "outbounds[0].streamSettings.finalmask.udp[0].type"
	const set = "outbounds[0].streamSettings.finalmask.udp[0].settings"
	for name, m := range map[string]string{
		"unlisted type":  `{"type":"realm","settings":{"url":"x.example"}}`,
		"type not text":  `{"type":5,"settings":{"url":"x.example"}}`,
		"type in case":   `{"type":"Realm","settings":{"stunServers":["a.example:3478"]}}`,
		"other settings": `{"type":"realm","settings":{"a":1}}`,
	} {
		mustWarn(t, name, mask(m), set)
		mustWarn(t, name, mask(m), typ)
		// Accepting the type alone leaves the settings a warning.
		r := check(t, mask(m), typ)
		if r.OK() {
			t.Errorf("%s: the acceptance of the type passed the settings: %v", name, r.Warnings)
		}
		// Both accepted: the fragment passes.
		if r = check(t, mask(m), typ, set); !r.OK() {
			t.Errorf("%s: both paths accepted, still %v %v", name, r.Rejected, r.Warnings)
		}
	}
	// A listed type has its table and no extra warning.
	mustOK(t, mask(`{"type":"salamander","settings":{"password":"p"}}`))
}
