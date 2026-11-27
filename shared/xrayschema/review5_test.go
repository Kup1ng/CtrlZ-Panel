package xrayschema

import (
	"strings"
	"testing"
)

// Tests for the findings of review round 5 of B1 (p4b-proxy 7.2) that still name a key
// the table accepts or a rule it keeps.

func httpExit(settings string) string {
	return `{"outbounds":[{"protocol":"http","settings":{"address":"203.0.113.7","port":3128` + settings + `}}]}`
}

// B1-r5-2: the header values of an http outbound are Go templates that Xray runs on every
// connection. The key is not listed, so a header passes only with its path, and then
// the template is the admin's decision with the TOTP; what is never allowed is still
// refused inside it.
func TestHTTPHeadersAreUnknown(t *testing.T) {
	prog := `{{if eq .Target.Address.String \"evil.example\"}}{{range 9000000000}}{{printf \"%1000000d\" 0}}{{end}}{{end}}`
	r := mustWarn(t, "template", httpExit(`,"headers":{"X":"`+prog+`"}`), "outbounds[0].settings.headers")
	for _, w := range r.Warnings {
		if strings.Contains(w.Msg, "evil") {
			t.Errorf("the reason echoes the value: %s", w.Msg)
		}
	}
	mustOK(t, httpExit(`,"headers":{"X":"`+prog+`"}`), "outbounds[0].settings.headers")
	refuse(t, "env in a header", httpExit(`,"headers":{"X":"env:HOME"}`), "outbounds[0].settings.headers")
	// The transports whose headers are listed keep braces in values: they are no templates.
	mustOK(t, stream4(`"method":"ws","wsSettings":{"headers":{"X":"{{ literal }}"}}`))
	mustOK(t, stream4(`"method":"xhttp","xhttpSettings":{"headers":{"X":"{{ literal }}"}}`))
}

// B1-r5-3: SOCKS5 carries the length of the user and the password in one byte, and the
// client panics when they do not fit its buffer once the exit answers method 02.
func TestSocksCredentialsAreAtMost255Bytes(t *testing.T) {
	long := strings.Repeat("p", 256)
	ok := strings.Repeat("p", 255)
	sock := func(inner string) string {
		return `{"outbounds":[{"protocol":"socks","settings":{` + inner + `}}]}`
	}
	top := func(k, v string) string { return sock(`"address":"203.0.113.7","port":1080,"` + k + `":"` + v + `"`) }
	srv := func(k, v string) string {
		other := map[string]string{"user": "pass", "pass": "user"}[k]
		return sock(`"servers":[{"address":"203.0.113.7","port":1080,"users":[{"` + other + `":"x","` + k + `":"` + v + `"}]}]`)
	}
	for _, k := range []string{"user", "pass"} {
		r := mustWarn(t, "top "+k, top(k, long), "outbounds[0].settings."+k)
		for _, w := range r.Warnings {
			if strings.Contains(w.Msg, long[:20]) {
				t.Errorf("the reason echoes the value")
			}
		}
		mustWarn(t, "9000 bytes", top(k, strings.Repeat("p", 9000)), "outbounds[0].settings."+k)
		mustOK(t, top(k, ok))
		mustOK(t, srv(k, ok))
	}
	mustWarn(t, "servers pass", srv("pass", long), "outbounds[0].settings.servers[0].users[0].pass")
}

// B1-r5-6: the http client keeps its HTTP/2 connections in a map of the process that
// nothing closes, keyed by destination alone.
func TestHTTPExitIsStateful(t *testing.T) {
	tb := Newest()
	for name, frag := range map[string]string{
		"plain":    httpExit(``),
		"in tls":   `{"outbounds":[{"protocol":"http","settings":{"address":"203.0.113.7","port":443},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"}}}]}`,
		"any case": `{"outbounds":[{"PROTOCOL":"HTTP"}]}`,
		"as a hop": `{"outbounds":[` + vlessPrefix + `,"streamSettings":{"sockopt":{"dialerProxy":"h"}}},{"tag":"h","protocol":"http","settings":{"address":"203.0.113.8","port":3128}}]}`,
	} {
		if !tb.Stateful([]byte(frag)) {
			t.Errorf("%s: not stateful", name)
		}
	}
}

// B1-r5-7, now an unknown key: downloadSettings of xhttp is not listed, so a download
// half with no address or with the wrong method passes only by the admin's path, as
// pasted, and what is never allowed (a dialerProxy, an env: address) is refused inside it.
func TestXhttpDownloadSettingsAreUnknown(t *testing.T) {
	dl := func(inner string) string {
		return stream4(`"method":"xhttp","xhttpSettings":{"downloadSettings":{` + inner + `}}`)
	}
	const p = "outbounds[0].streamSettings.xhttpSettings.downloadSettings"
	mustWarn(t, "complete", dl(`"address":"203.0.113.9","port":443,"method":"xhttp"`), p)
	mustOK(t, dl(`"address":"203.0.113.9","port":443,"method":"xhttp"`), p)
	mustOK(t, dl(`"port":443`), p)
	refuse(t, "dialerProxy", dl(`"address":"203.0.113.9","sockopt":{"dialerProxy":"x"}`), p)
	refuse(t, "env address", dl(`"address":"env:HOME"`), p)
	// No downloadSettings at all is the common case.
	mustOK(t, stream4(`"method":"xhttp","xhttpSettings":{"host":"a.example"}`))
}

// B1-r5-8, now a kind: remotePorts of udphop is one port or one a-b. A list, which Xray
// expands into one slice, is not of the kind.
func TestUDPHopRemotePortsIsOneRange(t *testing.T) {
	hop := func(ports string) string {
		return stream4(`"method":"hysteria","finalmask":{"udp":[{"type":"udphop","settings":{"interval":30,"remotePorts":"` + ports + `"}}]}`)
	}
	mustOK(t, hop("1-65535"))
	mustOK(t, hop("443"))
	for name, ports := range map[string]string{
		"a list":           "20000-30000,40000,50000-50100",
		"700 whole ranges": strings.TrimSuffix(strings.Repeat("1-65535,", 700), ","),
		"two ranges":       "1-65535,1-65535",
		"out of range":     "0-10",
		"reversed":         "30000-20000",
	} {
		mustWarn(t, name, hop(ports), "outbounds[0].streamSettings.finalmask.udp[0].settings.remotePorts")
	}
}
