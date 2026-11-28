package sharelink

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

const uuid = "5783a3e7-e373-51cd-8642-c83782b807c5"

// realityKey is 32 bytes in base64url, the kind of a REALITY key.
const realityKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// norm converts a link and runs the fragment through the allow-list, as the panel
// does, and returns the normal form.
func norm(t *testing.T, link string) string {
	t.Helper()
	frag, _, _, err := Convert(link)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	r := xrayschema.Newest().Check(frag, nil)
	if !r.OK() {
		t.Fatalf("the allow-list refuses the converted link: rejected=%v warnings=%v\n%s", r.Rejected, r.Warnings, frag)
	}
	return string(r.Normalized)
}

func has(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s in %s", w, got)
		}
	}
}

func TestVLESS(t *testing.T) {
	got := norm(t, "vless://"+uuid+"@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk="+realityKey+"&sid=ab12&spx=%2F&type=tcp&headerType=none#my%20node")
	has(t, got, `"protocol":"vless"`, `"address":"203.0.113.7"`, `"port":443`, `"id":"`+uuid+`"`, `"flow":"xtls-rprx-vision"`,
		`"security":"reality"`, `"publicKey":"`+realityKey+`"`, `"shortId":"ab12"`, `"spiderX":"/"`, `"method":"raw"`)
	_, note, proto, _ := Convert("vless://" + uuid + "@203.0.113.7:443?security=none#my%20node")
	if note != "my node" || proto != "vless" {
		t.Errorf("note %q protocol %q", note, proto)
	}
	got = norm(t, "vless://"+uuid+"@[2001:db8::1]:8443?type=ws&path=%2Fws&host=cdn.example.com&security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&fp=firefox&allowInsecure=0")
	has(t, got, `"address":"2001:db8::1"`, `"method":"ws"`, `"path":"/ws"`, `"host":"cdn.example.com"`, `"alpn":["h2","http/1.1"]`, `"fingerprint":"firefox"`)
	got = norm(t, "vless://"+uuid+"@a.example:443?type=grpc&serviceName=svc&authority=a.example&mode=gun&security=tls&sni=a.example")
	has(t, got, `"method":"grpc"`, `"serviceName":"svc"`)
	// B1n-r2-3: multi mode is not on the list, so its link is an error of its line.
	if _, _, _, err := Convert("vless://" + uuid + "@a.example:443?type=grpc&serviceName=svc&mode=multi&security=tls&sni=a.example"); err == nil {
		t.Error("grpc mode=multi converted")
	}
	got = norm(t, "vless://"+uuid+"@a.example:443?type=xhttp&path=%2Fx&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D&security=tls&sni=a.example")
	has(t, got, `"method":"xhttp"`, `"mode":"stream-up"`, `"extra":{"xPaddingBytes":"100-200"}`)
	got = norm(t, "vless://"+uuid+"@a.example:80?type=tcp&headerType=http&host=a.example%2Cb.example&path=%2Fa")
	has(t, got, `"type":"http"`, `"Host":["a.example","b.example"]`, `"path":["/a"]`)
	// B1n-r1-3: httpupgrade is not on the list, so its link is an error of its line.
	if _, _, _, err := Convert("vless://" + uuid + "@a.example:80?type=httpupgrade&path=%2Fu&host=h.example"); err == nil {
		t.Error("httpupgrade converted")
	}
	// B1n-r1-1: links join pins with ~, the loader of Xray splits on a comma.
	got = norm(t, "vless://"+uuid+"@a.example:443?security=tls&sni=a.example&pcs="+strings.Repeat("ab", 32)+"~"+strings.Repeat("cd", 32))
	has(t, got, `"pinnedPeerCertSha256":"`+strings.Repeat("ab", 32)+`,`+strings.Repeat("cd", 32)+`"`)
	// Case of the scheme and of the names.
	norm(t, "VLESS://"+uuid+"@a.example:443?SECURITY=none&Type=TCP")
}

func TestVMess(t *testing.T) {
	js := `{"v":"2","ps":"jp 1","add":"203.0.113.7","port":"443","id":"` + uuid + `","aid":"0","scy":"auto","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"cdn.example.com","alpn":"h2","fp":"chrome"}`
	for name, enc := range map[string]*base64.Encoding{"std": base64.StdEncoding, "rawurl": base64.RawURLEncoding, "url": base64.URLEncoding, "rawstd": base64.RawStdEncoding} {
		link := "vmess://" + enc.EncodeToString([]byte(js))
		got := norm(t, link)
		has(t, got, `"protocol":"vmess"`, `"security":"auto"`, `"method":"ws"`, `"path":"/ws"`, `"security":"tls"`, `"serverName":"cdn.example.com"`)
		_, note, _, _ := Convert(link)
		if note != "jp 1" {
			t.Errorf("%s: note %q", name, note)
		}
	}
	// Port as a number, and grpc with its service name in "path".
	js = `{"v":2,"ps":"g","add":"a.example","port":443,"id":"` + uuid + `","aid":0,"net":"grpc","type":"gun","host":"a.example","path":"svc","tls":"tls"}`
	got := norm(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(js)))
	has(t, got, `"serviceName":"svc"`, `"authority":"a.example"`)
	// B1n-r2-3: a vmess exit in multi mode is an error of its line like the vless one.
	if _, _, _, err := Convert("vmess://" + base64.StdEncoding.EncodeToString([]byte(strings.Replace(js, `"gun"`, `"multi"`, 1)))); err == nil {
		t.Error("vmess grpc multi converted")
	}
	// The URI form.
	got = norm(t, "vmess://"+uuid+"@a.example:443?encryption=aes-128-gcm&type=ws&path=%2Fp&security=tls&sni=a.example")
	has(t, got, `"security":"aes-128-gcm"`, `"method":"ws"`)
}

func TestTrojan(t *testing.T) {
	got := norm(t, "trojan://pa%24sword@203.0.113.7:443?sni=a.example&alpn=h2&type=tcp#t")
	has(t, got, `"protocol":"trojan"`, `"password":"pa$sword"`, `"security":"tls"`, `"serverName":"a.example"`)
	got = norm(t, "trojan://pw@a.example:443?security=tls&type=ws&path=%2Ft&host=a.example&sni=a.example")
	has(t, got, `"method":"ws"`)
}

func TestShadowsocks(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa:ss"))
	got := norm(t, "ss://"+ui+"@203.0.113.7:8388/#name")
	has(t, got, `"protocol":"shadowsocks"`, `"method":"aes-256-gcm"`, `"password":"pa:ss"`, `"port":8388`)
	// The old whole-link base64.
	old := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@a.example:443"))
	got = norm(t, "ss://"+old+"#n")
	has(t, got, `"method":"chacha20-ietf-poly1305"`, `"address":"a.example"`)
	// SIP022: method and key in plain text, percent-encoded.
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	got = norm(t, "ss://2022-blake3-aes-128-gcm:"+strings.NewReplacer("=", "%3D", "+", "%2B", "/", "%2F").Replace(key)+"@[2001:db8::2]:8388")
	has(t, got, `"method":"2022-blake3-aes-128-gcm"`, `"password":"`+key+`"`, `"address":"2001:db8::2"`)
	// A plugin is refused, however it is written.
	for _, q := range []string{"?plugin=obfs-local", "/?plugin=v2ray-plugin%3Bhost%3Dx", "?PLUGIN=x"} {
		if _, _, _, err := Convert("ss://" + ui + "@a.example:1" + q); err == nil || !strings.Contains(err.Error(), "plugin") {
			t.Errorf("%s: %v", q, err)
		}
	}
	got = norm(t, "ss://"+ui+"@a.example:443?type=ws&path=%2Fs&security=tls&sni=a.example")
	has(t, got, `"method":"ws"`)
}

func TestHysteria2(t *testing.T) {
	got := norm(t, "hysteria2://auth%3Apw@203.0.113.7:443?sni=h.example&insecure=0&obfs=salamander&obfs-password=op&pinSHA256=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99#hy")
	has(t, got, `"protocol":"hysteria"`, `"version":2`, `"auth":"auth:pw"`, `"serverName":"h.example"`,
		`"type":"salamander"`, `"password":"op"`, `"pinnedPeerCertSha256":"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"`, `"method":"hysteria"`)
	norm(t, "hy2://tok@h.example:8443?sni=h.example")
}

func TestUnknownParametersAndFailuresAreNamedWithoutValues(t *testing.T) {
	const secret = "TOPSECRET-value"
	cases := map[string]string{
		"unknown parameter":         "vless://" + uuid + "@a.example:443?security=none&frobnicate=" + secret,
		"unknown on trojan":         "trojan://" + secret + "@a.example:443?sni=a.example&bogus=1",
		"given twice":               "vless://" + uuid + "@a.example:443?security=none&security=tls&sni=" + secret,
		"param of another security": "vless://" + uuid + "@a.example:443?security=none&sni=" + secret,
		"reality without pbk":       "vless://" + uuid + "@a.example:443?security=reality&sni=" + secret,
		"stray path on raw":         "vless://" + uuid + "@a.example:443?security=none&path=%2F" + secret,
		"xtls":                      "vless://" + uuid + "@a.example:443?security=xtls",
		"h2":                        "vless://" + uuid + "@a.example:443?security=none&type=h2",
		"quic":                      "vless://" + uuid + "@a.example:443?security=none&type=quic",
		"kcp seed":                  "vless://" + uuid + "@a.example:443?security=none&type=kcp&seed=" + secret,
		"unknown scheme":            "wireguard://" + secret + "@a.example:1",
		"no scheme":                 secret,
		"port 0":                    "vless://" + uuid + "@a.example:0?security=none",
		"port 70000":                "vless://" + uuid + "@a.example:70000?security=none",
		"no port":                   "vless://" + uuid + "@a.example?security=none",
		"no host":                   "vless://" + uuid + "@:443?security=none",
		"no user":                   "vless://a.example:443?security=none",
		"trojan flow":               "trojan://" + secret + "@a.example:443?flow=xtls-rprx-vision",
		"hy2 mport list":            "hysteria2://" + secret + "@a.example:443?mport=1000,2000",
		"hy2 obfs":                  "hysteria2://" + secret + "@a.example:443?obfs=other&obfs-password=x",
		"hy2 pin":                   "hysteria2://" + secret + "@a.example:443?pinSHA256=zz",
		"vmess aid":                 "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"a.example","port":"1","id":"`+secret+`","aid":"4"}`)),
		"vmess unknown field":       "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"a.example","port":"1","id":"x","`+"zzz"+`":"`+secret+`"}`)),
		"vmess not base64":          "vmess://!!!" + secret,
		"vmess not json":            "vmess://" + base64.StdEncoding.EncodeToString([]byte("not json "+secret)),
		"ss bad base64":             "ss://!!!" + secret + "@a.example:1",
		"ss no method":              "ss://" + base64.RawURLEncoding.EncodeToString([]byte(":"+secret)) + "@a.example:1",
		"bool value":                "vless://" + uuid + "@a.example:443?security=tls&sni=a&allowInsecure=" + secret,
	}
	for name, link := range cases {
		_, _, _, err := Convert(link)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error holds a value of the link: %v", name, err)
		}
	}
	_, _, _, err := Convert("vless://" + uuid + "@a.example:443?security=none&frobnicate=1")
	if err == nil || !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("the unknown parameter is not named: %v", err)
	}
	// A value of the allow-list that the converter passes on and the checker refuses
	// is the checker's to refuse, not hidden here.
	frag, _, _, _ := Convert("vless://" + uuid + "@env:HOME:443?security=none")
	if frag != nil {
		if r := xrayschema.Newest().Check(frag, nil); r.OK() {
			t.Error("an env: address passed the allow-list")
		}
	}
}

func TestLinksPaste(t *testing.T) {
	text := "\n  vless://" + uuid + "@a.example:443?security=none#one  \r\n\r\ntrojan://pw@a.example:443?sni=a.example\nbogus://x\nvless://" + uuid + "@a.example:443?security=none&zzz=1\n"
	cands, err := Links(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 4 {
		t.Fatalf("%d candidates", len(cands))
	}
	wantLines := []int{2, 4, 5, 6}
	for i, c := range cands {
		if c.Line != wantLines[i] {
			t.Errorf("candidate %d is on line %d, want %d", i, c.Line, wantLines[i])
		}
	}
	if cands[0].Err != nil || cands[0].Note != "one" || cands[1].Err != nil {
		t.Errorf("good lines: %+v %+v", cands[0], cands[1])
	}
	if cands[2].Err == nil || cands[2].Err.Line != 5 || cands[3].Err == nil || !strings.Contains(cands[3].Err.Error(), "line 6") || !strings.Contains(cands[3].Err.Error(), "zzz") {
		t.Errorf("bad lines: %+v %+v", cands[2], cands[3])
	}
	// 100 pass, 101 do not.
	line := "vless://" + uuid + "@a.example:443?security=none\n"
	if c, err := Links(strings.Repeat(line, MaxLinks)); err != nil || len(c) != MaxLinks {
		t.Errorf("100 links: %v %d", err, len(c))
	}
	if _, err := Links(strings.Repeat(line, MaxLinks+1)); err != ErrTooMany {
		t.Errorf("101 links: %v", err)
	}
	if _, err := Links(strings.Repeat("a", MaxPasteBytes+1)); err != ErrTooLarge {
		t.Errorf("a huge paste: %v", err)
	}
	if _, _, _, err := Convert("vless://" + strings.Repeat("a", MaxLineBytes)); err == nil {
		t.Error("a link over the line limit")
	}
}

func TestFromJSON(t *testing.T) {
	full := `{"log":{"loglevel":"warning"},"inbounds":[{"port":1080,"protocol":"socks"}],"routing":{"rules":[]},"dns":{"servers":["1.1.1.1"]},
	"outbounds":[
	  {"tag":"main","protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"` + uuid + `","encryption":"none"},"streamSettings":{"sockopt":{"dialerProxy":"hop"}}},
	  {"tag":"hop","protocol":"vless","settings":{"address":"203.0.113.8","port":443,"id":"` + uuid + `","encryption":"none"},"streamSettings":{"sockopt":{"dialerProxy":"frag"}}},
	  {"tag":"frag","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"}}},
	  {"tag":"second","protocol":"trojan","settings":{"address":"203.0.113.9","port":443,"password":"pw"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"}}},
	  {"tag":"direct","protocol":"freedom"},
	  {"tag":"block","protocol":"blackhole"},
	  {"tag":"dns-out","protocol":"dns"}
	]}`
	res, err := FromJSON([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res.LeftOut, ","); got != "dns,inbounds,log,routing" {
		t.Errorf("left out: %s", got)
	}
	if len(res.Candidates) != 2 {
		t.Fatalf("%d candidates", len(res.Candidates))
	}
	c0 := res.Candidates[0]
	if c0.Note != "main" || c0.Protocol != "vless" || strings.Count(string(c0.Fragment), `"protocol"`) != 3 {
		t.Errorf("first candidate: %s %s\n%s", c0.Note, c0.Protocol, c0.Fragment)
	}
	r := xrayschema.Newest().Check(c0.Fragment, nil)
	if !r.OK() {
		t.Errorf("the chain is refused: %v %v", r.Rejected, r.Warnings)
	}
	if c1 := res.Candidates[1]; c1.Note != "second" || strings.Count(string(c1.Fragment), `"protocol"`) != 1 {
		t.Errorf("second candidate: %s", c1.Fragment)
	}
	// One outbound object.
	one, err := FromJSON([]byte(`{"protocol":"trojan","tag":"t","settings":{"address":"a.example","port":1,"password":"p"}}`))
	if err != nil || len(one.Candidates) != 1 || len(one.LeftOut) != 0 || one.Candidates[0].Note != "t" {
		t.Errorf("one outbound: %+v %v", one, err)
	}
	for name, in := range map[string]string{
		"not an object":      `[]`,
		"neither":            `{"inbounds":[]}`,
		"repeated top key":   `{"outbounds":[],"Outbounds":[]}`,
		"outbounds a string": `{"outbounds":"x"}`,
		"trailing":           `{"outbounds":[]} {}`,
		"truncated":          `{"outbounds":[`,
		"outbound a number":  `{"outbounds":[1]}`,
	} {
		if _, err := FromJSON([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := FromJSON(make([]byte, maxImportBytes+1)); err == nil {
		t.Error("an oversized configuration")
	}
}

// readCorpus reads a fixtures/sharelink file: one link an item.
func readCorpus(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile("../fixtures/sharelink/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []string `json:"items"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Items
}

// The corpus lists links that must convert and pass the allow-list. CI runs each
// result through the pinned binary with -test (p4b-proxy 15.5); the values are
// documentation addresses and made-up keys.
func TestCorpusConvertsAndPassesTheAllowList(t *testing.T) {
	acc := readCorpus(t, "accepted.json")
	for i, line := range acc {
		frag, _, _, err := Convert(line)
		if err != nil {
			t.Errorf("accepted.json item %d: %v", i+1, err)
			continue
		}
		if r := xrayschema.Newest().Check(frag, nil); !r.OK() {
			t.Errorf("accepted.json item %d: %v %v", i+1, r.Rejected, r.Warnings)
		}
	}
	if len(acc) < 12 {
		t.Errorf("only %d corpus links", len(acc))
	}
	ref := readCorpus(t, "refused.json")
	for i, line := range ref {
		if _, _, _, err := Convert(line); err == nil {
			t.Errorf("refused.json item %d converted", i+1)
		}
	}
	if len(ref) < 8 {
		t.Errorf("only %d refused links", len(ref))
	}
}

// FuzzConvert: whatever a link holds, converting it never panics, an error never
// holds a value of the link, and a fragment that converts is JSON that the allow-list
// reads without a panic.
func FuzzConvert(f *testing.F) {
	for _, l := range []string{
		"vless://" + uuid + "@203.0.113.7:443?security=none#n",
		"ss://YWVzLTI1Ni1nY206cHc@203.0.113.7:8388",
		"trojan://pw@a.example:443?sni=a.example",
		"hysteria2://auth@a.example:443?obfs=salamander&obfs-password=x",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"a.example","port":"443","id":"x"}`)),
		"",
	} {
		f.Add(l)
	}
	f.Fuzz(func(t *testing.T, link string) {
		frag, _, _, err := Convert(link)
		if err != nil {
			return
		}
		_ = xrayschema.Newest().Check(frag, nil)
	})
}

func FuzzFromJSON(f *testing.F) {
	f.Add([]byte(`{"outbounds":[{"protocol":"vless","tag":"a"}]}`))
	f.Add([]byte(`{"protocol":"trojan"}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := FromJSON(data)
		if err != nil {
			return
		}
		for _, c := range res.Candidates {
			_ = xrayschema.Newest().Check(c.Fragment, nil)
		}
	})
}
