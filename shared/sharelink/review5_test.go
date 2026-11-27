package sharelink

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

// Tests for 7.3 as rewritten on 2026-11-25: a link gives keys of the allow-list alone, so
// its candidate never carries a warning.

func xhttpLink(extra string) string {
	return "vless://" + uuid + "@203.0.113.7:443?type=xhttp&security=none&extra=" + url.QueryEscape(extra)
}

// The members of extra that the exit works without are left out with a line in the
// candidate; the listed ones are kept; any other is an error of the line.
func TestExtraOfAnXhttpLink(t *testing.T) {
	cands, err := Links(xhttpLink(`{"xPaddingBytes":"100-1000","headers":{"A":"b"},"xmux":{"maxConcurrency":"16-32"},"scMinPostsIntervalMs":30,"noSSEHeader":true,"serverMaxHeaderBytes":8192,"scMaxBufferedPosts":30,"scStreamUpServerSecs":"20-80"}`))
	if err != nil || len(cands) != 1 || cands[0].Err != nil {
		t.Fatalf("%v %+v", err, cands)
	}
	got := strings.Join(cands[0].Omitted, ",")
	want := "extra.noSSEHeader,extra.scMaxBufferedPosts,extra.scMinPostsIntervalMs,extra.scStreamUpServerSecs,extra.serverMaxHeaderBytes,extra.xmux"
	if got != want {
		t.Errorf("omitted %s, want %s", got, want)
	}
	frag := string(cands[0].Fragment)
	if !strings.Contains(frag, `"xPaddingBytes":"100-1000"`) || strings.Contains(frag, "xmux") || strings.Contains(frag, "scMin") {
		t.Errorf("the fragment keeps what it should leave out, or the reverse: %s", frag)
	}
	if r := xrayschema.Newest().Check(cands[0].Fragment, nil); !r.OK() {
		t.Errorf("the candidate is not clean: %v %v", r.Warnings, r.Rejected)
	}
	// An extra that holds nothing but left-out members gives no extra at all.
	cands, _ = Links(xhttpLink(`{"xmux":{}}`))
	if cands[0].Err != nil || strings.Contains(string(cands[0].Fragment), "extra") {
		t.Errorf("%+v", cands[0])
	}
	for _, e := range []string{`{"downloadSettings":{"address":"a.example"}}`, `{"xPaddingObfsMode":true}`, `{"sessionPlacement":"path"}`, `{"seqKey":"x"}`, `{"unknownThing":1}`} {
		cands, _ := Links(xhttpLink(e))
		if cands[0].Err == nil {
			t.Errorf("%s: converted", e)
			continue
		}
		if cands[0].Err.Line != 1 || strings.Contains(cands[0].Err.Msg, "address") {
			t.Errorf("%s: %+v", e, cands[0].Err)
		}
	}
	// A value that is not of the kind of its key is an error of the line.
	if cands, _ := Links(xhttpLink(`{"xPaddingBytes":"1-99999"}`)); cands[0].Err == nil || !strings.Contains(cands[0].Err.Msg, "xPaddingBytes") {
		t.Errorf("%+v", cands[0])
	}
}

func TestPqvIsLeftOutAndKcpIsAnError(t *testing.T) {
	cands, _ := Links("vless://" + uuid + "@203.0.113.7:443?security=reality&sni=a.example&pbk=" + realityKey + "&pqv=abcdef")
	if cands[0].Err != nil || strings.Join(cands[0].Omitted, ",") != "pqv" || strings.Contains(string(cands[0].Fragment), "mldsa65Verify") {
		t.Errorf("%+v", cands[0])
	}
	for _, l := range []string{
		"vless://" + uuid + "@203.0.113.7:443?security=none&type=kcp",
		"vless://" + uuid + "@203.0.113.7:443?security=none&type=mkcp",
		"vless://" + uuid + "@203.0.113.7:443?security=none&type=kcp&seed=x",
	} {
		if _, _, _, err := Convert(l); err == nil || !strings.Contains(err.Error(), `"type"`) && !strings.Contains(err.Error(), `"seed"`) {
			t.Errorf("%s: %v", l, err)
		}
	}
}

// mport of one port or one a-b gives the udphop form, after the salamander mask.
func TestHysteria2PortHopping(t *testing.T) {
	got := norm(t, "hysteria2://made-up-auth@203.0.113.7:443?sni=a.example&mport=20000-30000&obfs=salamander&obfs-password=op")
	i, j := strings.Index(got, `"type":"salamander"`), strings.Index(got, `"type":"udphop"`)
	if i < 0 || j < 0 || i > j || !strings.Contains(got, `"remotePorts":"20000-30000"`) || !strings.Contains(got, `"mode":"intervalRemote"`) {
		t.Errorf("%s", got)
	}
	got = norm(t, "hysteria2://made-up-auth@203.0.113.7:443?sni=a.example&mport=5000")
	if !strings.Contains(got, `"type":"udphop"`) || strings.Contains(got, "salamander") {
		t.Errorf("%s", got)
	}
	for _, m := range []string{"1000,2000", "1000-2000,3000", "0-10", "10-70000", "20000-10000", "a-b", "-5", "1-"} {
		_, _, _, err := Convert("hysteria2://made-up-auth@203.0.113.7:443?sni=a.example&mport=" + url.QueryEscape(m))
		if err == nil {
			t.Errorf("mport %s converted", m)
		}
	}
}

// A link never carries a warning: a value that is not of the kind of its key is an error
// of its line, named by its path and never with the value.
func TestAValueOffKindIsAnErrorOfTheLine(t *testing.T) {
	const secret = "TOPSECRET-value"
	for name, l := range map[string]string{
		"sni without a dot": "vless://" + uuid + "@203.0.113.7:443?security=tls&sni=localhost",
		"fingerprint":       "vless://" + uuid + "@203.0.113.7:443?security=tls&sni=a.example&fp=unsafe" + secret,
		"alpn":              "vless://" + uuid + "@203.0.113.7:443?security=tls&sni=a.example&alpn=spdy" + secret,
		"id too long":       "vless://" + strings.Repeat("a", 40) + "@203.0.113.7:443?security=none",
		"short id":          "vless://" + uuid + "@203.0.113.7:443?security=reality&sni=a.example&pbk=" + realityKey + "&sid=zz" + secret,
		"public key":        "vless://" + uuid + "@203.0.113.7:443?security=reality&sni=a.example&pbk=short" + secret,
		"ws path":           "vless://" + uuid + "@203.0.113.7:443?security=none&type=ws&path=%2Fa%20b" + secret,
		"flow":              "vless://" + uuid + "@203.0.113.7:443?security=none&flow=xtls-rprx-direct" + secret,
		"ss method":         "ss://" + "YWVzLTEyOC1jZmI6cHc" + "@203.0.113.7:8388",
	} {
		cands, _ := Links(l)
		if len(cands) != 1 || cands[0].Err == nil {
			t.Errorf("%s: %+v", name, cands)
			continue
		}
		if strings.Contains(cands[0].Err.Msg, secret) || !strings.Contains(cands[0].Err.Msg, "outbounds[0]") && !strings.Contains(cands[0].Err.Msg, "parameter") {
			t.Errorf("%s: %s", name, cands[0].Err.Msg)
		}
	}
}
