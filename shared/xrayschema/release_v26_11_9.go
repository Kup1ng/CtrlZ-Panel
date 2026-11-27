package xrayschema

import "strings"

// The allow-list of Xray v26.11.9 (2026-11-09), written from the structs of
// infra/conf at that tag (p4b-proxy 7.2, rewritten 2026-11-25). It is a short, closed
// list of the keys that ordinary exits need, each with a kind that has a bound. Every
// other key of Xray's configuration language is unknown and passes only by D11
// (accept_unknown with the TOTP), because one value can end the process that all
// locations of a node share long after the trial, and a table of every key did not end:
// 7.5 step 4 bounds the harm instead. A key joins this list only when ordinary exits
// need it; a finding on a listed key narrows its kind or takes it off the list.
//
// Reading guide for the next release: copy this file, change the keys that moved,
// register it in tables.go, keep this one. A node may stay on any release that was
// ever shipped (7.2), so no table is ever deleted.

func outbound() *node {
	protocols := map[string]*node{
		"vless":       vlessSettings(),
		"vmess":       vmessSettings(),
		"trojan":      trojanSettings(),
		"shadowsocks": shadowsocksSettings(),
		"socks":       socksSettings(),
		"http":        httpSettings(),
		"hysteria":    hysteriaSettings(),
		"wireguard":   wireguardSettings(),
		"freedom":     freedomSettings(),
	}
	return obj(
		f("protocol", enumOf(false, "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "hysteria", "wireguard", "freedom")),
		f("tag", text()),
		f("settings", obj()),
		f("streamSettings", streamSettings()),
		f("mux", obj(
			f("enabled", boolean()), f("concurrency", bnum(-1, 128)),
			// No UDP comes in at the node, so on the first outbound neither xudp key has an
			// effect. A hop can be dialed with the UDP of the outbound before it (wireguard,
			// hysteria, xhttp over h3), and then both keys decide whether that UDP passes the
			// mux, so on a hop they are unknown keys.
			f("xudpConcurrency", droppedFirst()), f("xudpProxyUDP443", droppedFirst()),
		)),
	).withVariant("protocol", "settings", protocols).postChecked(socksOverEarlyData)
}

// socksOverEarlyData: the path of a ws exit may carry ?ed=N, which the loader turns into
// early data, and the ws dialer then returns a delayDialConn whose embedded conn is nil
// until the first Write. Upstream overrides LocalAddr and RemoteAddr for that, but not
// SetDeadline, and the socks client calls conn.SetDeadline before it writes: a nil
// interface call that ends the process, and no -test dials. Any "?" is refused rather
// than "ed=", because the loader decodes escapes of the query keys. No other listed
// protocol touches the conn before its first write.
func socksOverEarlyData(v *val) (string, string) {
	proto := memberOf(v, "protocol")
	ss := memberOf(v, "streamSettings")
	if proto == nil || proto.k != 's' || !strings.EqualFold(proto.s, "socks") {
		return "", ""
	}
	m := memberOf(ss, "method")
	if m == nil || m.k != 's' || m.s != "ws" {
		return "", ""
	}
	p := memberOf(memberOf(ss, "wsSettings"), "path")
	if p != nil && p.k == 's' && strings.Contains(p.s, "?") {
		return ".streamSettings.wsSettings.path", "a socks exit over ws cannot have a query in the path: ?ed= makes the connection panic before its first write"
	}
	return "", ""
}

// ---- protocols ------------------------------------------------------------------

// One element of vnext or servers, and one user in it, is the form the table accepts: a
// link and ordinary exits have exactly one, and the client of the release reads the
// first. level and email only label a user in Xray's own statistics, which the node does
// not run.
func vlessSettings() *node {
	user := obj(f("id", uuidText()), f("flow", flow()), f("encryption", vlessEncryption()), f("level", dropped()), f("email", dropped()))
	return obj(
		f("address", host()), f("port", port()), f("level", dropped()), f("email", dropped()), f("id", uuidText()),
		f("flow", flow()), f("encryption", vlessEncryption()),
		f("vnext", arrN(1, 1, obj(f("address", host()), f("port", port()), f("users", arrN(1, 1, user))))),
	)
}

// flow lists the two values of the Vision flow. Any other (the xtls-rprx-direct family
// is removed from the release) is unknown.
func flow() *node { return enumOf(true, "xtls-rprx-vision", "xtls-rprx-vision-udp443") }

// vlessEncryption lists "none" alone. The post-quantum form (mlkem768x25519plus) is
// unknown: its handshake text carries sleeps that nothing cancels.
func vlessEncryption() *node { return enumOf(true, "none") }

func vmessSettings() *node {
	sec := enumOf(true, "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero")
	user := obj(f("id", uuidText()), f("security", sec), f("level", dropped()), f("email", dropped()), f("alterId", droppedZero()))
	return obj(
		f("address", host()), f("port", port()), f("level", dropped()), f("email", dropped()), f("id", uuidText()),
		f("security", sec), f("alterId", droppedZero()),
		f("vnext", arrN(1, 1, obj(f("address", host()), f("port", port()), f("users", arrN(1, 1, user))))),
	)
}

func trojanSettings() *node {
	server := obj(f("address", host()), f("port", port()), f("level", dropped()), f("email", dropped()), f("password", text()))
	return obj(
		f("address", host()), f("port", port()), f("level", dropped()), f("email", dropped()), f("password", text()),
		f("servers", arrN(1, 1, server)),
	)
}

// shadowsocksMethods are the ciphers of the release: the four AEAD ciphers with their
// aliases (proxy/shadowsocks) and the three of Shadowsocks 2022 (shadowsocks_2022).
// The loader folds them with strings.ToLower, and a value outside this list can
// never be accepted.
func shadowsocksMethods() *node {
	return enumOf(false,
		"aes-128-gcm", "aead_aes_128_gcm=aead_aes_128_gcm", "aes-256-gcm", "aead_aes_256_gcm=aead_aes_256_gcm",
		"chacha20-poly1305", "aead_chacha20_poly1305=aead_chacha20_poly1305", "chacha20-ietf-poly1305",
		"xchacha20-poly1305", "aead_xchacha20_poly1305=aead_xchacha20_poly1305", "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	)
}

func shadowsocksSettings() *node {
	server := obj(f("address", host()), f("port", port()), f("level", dropped()), f("email", dropped()),
		f("method", shadowsocksMethods()), f("password", text()), f("ota", dropped()))
	return obj(
		f("address", host()), f("port", port()), f("level", dropped()), f("email", dropped()),
		f("method", shadowsocksMethods()), f("password", text()), f("ota", dropped()),
		f("servers", arrN(1, 1, server)),
	)
}

// socks and http: user and pass are text of at most 255 bytes, which is the bound that
// SOCKS5 carries in one byte. The headers of an http outbound are Go templates that Xray
// runs on every connection, so they are not listed.
func socksSettings() *node {
	user := obj(f("user", text()), f("pass", text()), f("level", dropped()), f("email", dropped()))
	return obj(
		f("address", host()), f("port", port()), f("level", dropped()), f("email", dropped()),
		f("user", text()), f("pass", text()),
		f("servers", arrN(1, 1, obj(f("address", host()), f("port", port()), f("users", arrN(1, 1, user))))),
	)
}

func httpSettings() *node { return socksSettings() }

func hysteriaSettings() *node {
	return obj(f("version", bnum(2, 2)), f("address", host()), f("port", port()))
}

// wireguardSettings: the client of the release reads Peers[0] with no check, so exactly
// one peer is listed and a missing list is a warning. noKernelTun is always true: the
// node has no capability to open a kernel interface. isClient is on the global list of
// always-rejected keys: with it the outbound would be a server.
func wireguardSettings() *node {
	peer := obj(f("publicKey", key32()), f("preSharedKey", key32()), f("endpoint", hostPort()), f("keepAlive", bnum(0, 600)),
		f("allowedIPs", arrN(1, 8, prefixOnly())))
	return obj(
		f("noKernelTun", boolean()), f("secretKey", key32()), f("address", arrN(1, 8, ipOrPrefix())),
		f("peers", arrN(1, 1, peer)), f("mtu", bnum(1280, 1420)), f("reserved", arrN(3, 3, bnum(0, 255))),
	).forcing("noKernelTun").needing("peers")
}

// freedomSettings holds what a freedom hop may carry: a fragment of the TLS hello. The
// node renders the rules of the hop itself (7.4), so the strategies and the user level
// of the paste have no effect and are dropped.
func freedomSettings() *node {
	return obj(
		f("fragment", obj(
			f("packets", oneOf(enumOf(false, "tlshello"), brange(1, 10))),
			f("length", brange(1, 1500)), f("interval", brange(0, 100)),
		)),
		f("domainStrategy", dropped()), f("targetStrategy", dropped()), f("userLevel", dropped()),
	)
}

// ---- stream settings --------------------------------------------------------------

func streamSettings() *node {
	return obj(
		f("method", transportEnum()),
		f("security", enumOf(false, "none=none", "tls", "reality")),
		f("finalmask", finalmask()),
		f("tlsSettings", tlsSettings()),
		f("realitySettings", realitySettings()),
		f("rawSettings", rawSettings()),
		f("xhttpSettings", xhttpSettings()),
		f("grpcSettings", grpcSettings()),
		f("wsSettings", obj(f("host", httpHost()), f("path", path()), f("headers", headers()))),
		f("hysteriaSettings", obj(f("version", bnum(2, 2)), f("auth", text()))),
		f("sockopt", obj(f("dialerProxy", dialerTag()), f("domainStrategy", dropped()), f("tcpNoDelay", dropped()))),
	).aliased("method", "network").
		aliased("rawSettings", "tcpSettings").
		aliased("xhttpSettings", "splithttpSettings")
}

// transportEnum is the value of "method" (formerly "network"). The loader folds it
// with strings.ToLower and names the old spellings; the new ones are written. kcp and
// httpupgrade are the transports that are an unknown value, passed by accept_unknown;
// any other transport is refused for good (h2, h3, http and quic are removed from the
// release, and masque and xdrive are never allowed), so they are not here. httpupgrade
// is not listed because its dialer reads the answer with connRF.Read([]byte{}), and a
// byte that the exit sends after the 101 header in the same segment makes that read
// slice a buffer of capacity 0: a panic the exit triggers at a time of its choice.
func transportEnum() *node {
	return enumOf(false,
		"raw=raw", "tcp=raw", "xhttp=xhttp", "splithttp=xhttp", "kcp=kcp", "mkcp=kcp",
		"grpc", "ws=ws", "websocket=ws", "httpupgrade", "hysteria",
	).softening("kcp", "httpupgrade")
}

func tlsSettings() *node {
	return obj(
		f("serverName", host()),
		f("alpn", arrN(1, 3, enumOf(true, "h2", "http/1.1", "h3"))),
		f("fingerprint", enumOf(true, "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn")),
		f("pinnedPeerCertSha256", pins()),
	)
}

func realitySettings() *node {
	return obj(
		f("serverName", host()),
		f("fingerprint", enumOf(true, "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn")),
		f("publicKey", key32URL()), f("password", key32URL()), f("shortId", shortID()), f("spiderX", spiderX()),
	)
}

func rawSettings() *node {
	req := obj(
		f("version", enumOf(true, "1.0", "1.1")), f("method", enumOf(true, "GET", "POST")),
		f("path", arrN(1, 8, path())), f("headers", headersMulti()),
	)
	// A client never sends the response of the http header.
	return obj(f("header", obj(f("type", enumOf(true, "none", "http")), f("request", req), f("response", dropped()))))
}

func xhttpSettings() *node {
	// extra is read again by the loader as xhttp settings; only the members that
	// ordinary exits carry in it are listed, the last four of the object.
	extra := obj(f("headers", headers()), f("noGRPCHeader", boolean()), f("xPaddingBytes", brange(1, 2000)),
		f("scMaxEachPostBytes", brange(16384, 1000000)))
	return obj(
		f("host", httpHost()), f("path", path()), f("mode", enumOf(true, "auto", "packet-up", "stream-up", "stream-one")),
		f("headers", headers()), f("noGRPCHeader", boolean()), f("xPaddingBytes", brange(1, 2000)),
		f("scMaxEachPostBytes", brange(16384, 1000000)), f("extra", extra),
	)
}

// grpcSettings leaves multiMode off the list on purpose (B1n-r2-3). In multi mode the
// client takes one 8192-byte buffer for every element of a MultiHunk, and the only bound
// is the 4 MiB message limit of gRPC, so one message of one-byte elements makes Xray
// allocate gigabytes. multiMode true is an unknown key, and false is the default that
// the check drops.
func grpcSettings() *node {
	return obj(
		f("authority", text()), f("serviceName", text()), f("permit_without_stream", boolean()),
		f("idle_timeout", bnum(0, 3600)), f("health_check_timeout", bnum(0, 3600)), f("initial_windows_size", bnum(0, 0)),
	)
}

// finalmask lists the UDP masks that the Hysteria 2 links need: one salamander, then one
// udphop. The release writes its list in reverse, and the hop must dial, so the order is
// part of the kind (maskOrder). Everything else of finalmask is unknown.
func finalmask() *node {
	item := obj(f("type", enumOf(true, "salamander", "udphop")), f("settings", obj())).withVariant("type", "settings", map[string]*node{
		"salamander": obj(f("password", text())),
		"udphop": obj(
			f("mode", enumOf(true, "intervalRemote")), f("interval", brange(5, 600)), f("remotePorts", brange(1, 65535)),
		),
	})
	return obj(f("udp", arrN(0, 2, item))).postChecked(maskOrder)
}

// maskOrder: at most one salamander and then at most one udphop. A mask of another type
// is warned at its own type.
func maskOrder(v *val) (string, string) {
	udp := memberOf(v, "udp")
	if udp == nil || udp.k != 'a' {
		return "", ""
	}
	last := -1
	for _, it := range udp.items {
		t := memberOf(it, "type")
		if t == nil || t.k != 's' {
			continue
		}
		rank := map[string]int{"salamander": 0, "udphop": 1}
		r, ok := rank[strings.ToLower(t.s)]
		if !ok {
			continue
		}
		if r <= last {
			return ".udp", "the masks must be one salamander and then one udphop, in that order: the release writes the list in reverse, and the hop must dial"
		}
		last = r
	}
	return "", ""
}

// ---- state that rmo leaves behind ------------------------------------------------

// statefulRules classifies every protocol and every transport of the table (7.2,
// finding 4): rmo only drops the tag of an outbound and never closes its handler, so
// a wireguard device with its UDP socket, a hysteria session, a grpc ClientConn (the
// process-wide globalDialerMap of transport/internet/grpc keeps it up to 30 min after
// its last call, with keepalive pings, and redials a dead exit; read, not run) and an
// xhttp session over h3 stay up until the process ends. The http protocol is stateful
// too: its client keeps every HTTP/2 connection in the package-level cachedH2Conns,
// keyed by destination alone and never closed, so a removed exit stays up and an edit (a
// pin, a dialerProxy hop) is answered over the old connection. A change to such a config
// therefore rebuilds in the idle slot (7.5 step 5). Each protocol and transport of the
// table is named here, so a release that adds one fails TestEveryProtocolAndTransportIsClassified
// until someone has read its handler for the same property (G4).
func statefulRules() statefulSet {
	return statefulSet{
		protocols: map[string]bool{
			"vless": false, "vmess": false, "trojan": false, "shadowsocks": false, "socks": false,
			"http": true, "freedom": false, "hysteria": true, "wireguard": true,
		},
		transports: map[string]transportState{
			"raw": never, "kcp": never, "ws": never, "httpupgrade": never, "grpc": always,
			"hysteria": always, "xhttp": withH3,
		},
	}
}
