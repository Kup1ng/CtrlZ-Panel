package xrayschema

import "testing"

// B1n-r1-4: a socks exit over ws with a query in the path gets early data, so its first
// connection is a delayDialConn with a nil conn, and the socks client calls SetDeadline
// on it before the first write. Nothing else of the list touches the conn first.
func TestSocksOverWsWithAQueryIsWarned(t *testing.T) {
	socks := func(ss string) string {
		return `{"outbounds":[{"protocol":"socks","settings":{"address":"203.0.113.7","port":443},"streamSettings":{` + ss + `}}]}`
	}
	const path = "outbounds[0].streamSettings.wsSettings.path"
	for name, ss := range map[string]string{
		"ed":          `"method":"ws","security":"tls","wsSettings":{"path":"/?ed=2048"}`,
		"old spelled": `"network":"websocket","wsSettings":{"path":"/p?ed=1"}`,
		"escaped key": `"method":"ws","wsSettings":{"path":"/?e%64=1"}`,
		"any query":   `"method":"ws","wsSettings":{"path":"/a?x"}`,
	} {
		mustWarn(t, name, socks(ss), path)
		mustOK(t, socks(ss), path)
	}
	for _, frag := range map[string]string{
		"no query":      socks(`"method":"ws","wsSettings":{"path":"/p"}`),
		"escaped mark":  socks(`"method":"ws","wsSettings":{"path":"/p%3Fed=1"}`),
		"over raw":      socks(`"method":"raw"`),
		"query, not ws": socks(`"method":"xhttp","xhttpSettings":{"path":"/p?x=1"}`),
		"vless over ws": outboundWith(`,"streamSettings":{"method":"ws","wsSettings":{"path":"/?ed=2048"}}`),
	} {
		mustOK(t, frag)
	}
}
