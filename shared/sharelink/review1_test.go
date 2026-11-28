package sharelink

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/xrayschema"
)

// Tests for the findings of review round 1 of B1.

// The copies of a limit must not drift apart from the checker's.
func TestLimitsEqualTheCheckers(t *testing.T) {
	if maxChain != xrayschema.MaxOutbounds || maxFragmentBytes != xrayschema.MaxFragmentBytes {
		t.Errorf("maxChain %d, maxFragmentBytes %d against the checker's %d and %d", maxChain, maxFragmentBytes,
			xrayschema.MaxOutbounds, xrayschema.MaxFragmentBytes)
	}
}

// B1-r1-5: nothing of the user info is dropped silently.
func TestAPasswordPartOfAnIdIsRefused(t *testing.T) {
	for name, link := range map[string]string{
		"vless": "vless://" + uuid + ":extra@a.example:443?security=none",
		"vmess": "vmess://" + uuid + ":extra@a.example:443?security=none",
		// An empty password part is still a password part.
		"vless empty": "vless://" + uuid + ":@a.example:443?security=none",
	} {
		_, _, _, err := Convert(link)
		if err == nil {
			t.Errorf("%s: converted with a password part", name)
		} else if strings.Contains(err.Error(), "extra") {
			t.Errorf("%s: the error holds the value: %v", name, err)
		}
	}
}

// B1-r1-10: the release refuses allowInsecure true, so no link converts to it.
func TestInsecureTlsIsRefusedByName(t *testing.T) {
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	vm := base64.StdEncoding.EncodeToString([]byte(`{"add":"a.example","port":"443","id":"x","tls":"tls","allowInsecure":"1"}`))
	for name, link := range map[string]string{
		"vless allowInsecure":      "vless://" + uuid + "@a.example:443?security=tls&sni=a.example&allowInsecure=1",
		"vless allowInsecure true": "vless://" + uuid + "@a.example:443?security=tls&sni=a.example&allowInsecure=true",
		"trojan allowInsecure":     "trojan://pw@a.example:443?sni=a.example&allowInsecure=1",
		"ss allowInsecure":         "ss://" + ss + "@a.example:443?security=tls&sni=a.example&allowInsecure=1",
		"hysteria2 insecure":       "hy2://pw@203.0.113.7:443?sni=a.example&insecure=1",
		"vmess json":               "vmess://" + vm,
	} {
		_, _, _, err := Convert(link)
		if err == nil {
			t.Errorf("%s: converted", name)
			continue
		}
		if !strings.Contains(err.Error(), "insecure") || !strings.Contains(err.Error(), "pin") {
			t.Errorf("%s: the error does not name the parameter and its replacement: %v", name, err)
		}
	}
	norm(t, "hy2://pw@203.0.113.7:443?sni=a.example&insecure=0")
}

// B1-r1-12: a key given twice in the JSON of a link is refused, not dropped.
func TestRepeatedKeysInTheJSONOfALinkAreRefused(t *testing.T) {
	vm := func(j string) string { return "vmess://" + base64.StdEncoding.EncodeToString([]byte(j)) }
	if _, _, _, err := Convert(vm(`{"add":"a.example","port":"443","id":"x","id":"y"}`)); err == nil {
		t.Error("vmess JSON with id twice")
	}
	if _, _, _, err := Convert(vm(`{"add":"a.example","port":"443","id":"x"}`)); err != nil {
		t.Errorf("a plain vmess JSON: %v", err)
	}
	extra := func(e string) string {
		return "vless://" + uuid + "@a.example:443?type=xhttp&security=none&extra=" +
			strings.NewReplacer("{", "%7B", "}", "%7D", `"`, "%22", ":", "%3A", ",", "%2C").Replace(e)
	}
	if _, _, _, err := Convert(extra(`{"xPaddingBytes":"1-2","xPaddingBytes":"3-4"}`)); err == nil {
		t.Error("extra with a key twice")
	}
	// The same key in another case is a key twice for Go's decoder, and the converter refuses it.
	if _, _, _, err := Convert(extra(`{"xPaddingBytes":"1-2","XPADDINGBYTES":"3-4"}`)); err == nil {
		t.Error("two cases of one key in extra convert")
	}
}

// B1-r1-14: a small paste cannot make many megabytes of fragments.
func TestFromJSONBoundsCandidatesAndChains(t *testing.T) {
	big := `{"tag":"x","protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"` + uuid +
		`","encryption":"none"},"streamSettings":{"sockopt":{"dialerProxy":"y"}},"pad":"` + strings.Repeat("a", 20<<10) + `"}`
	hop := `{"tag":"y","protocol":"vless","settings":{"address":"203.0.113.8","port":443,"id":"` + uuid + `","encryption":"none"}}`
	outs := []string{big, hop}
	for i := 0; i < 400; i++ {
		outs = append(outs, fmt.Sprintf(`{"protocol":"vless","settings":{"address":"203.0.113.9","port":443,"id":"%s","encryption":"none"},"streamSettings":{"sockopt":{"dialerProxy":"x"}}}`, uuid))
	}
	if _, err := FromJSON([]byte(`{"outbounds":[` + strings.Join(outs, ",") + `]}`)); err != ErrTooMany {
		t.Errorf("hundreds of candidates: %v", err)
	}

	// A chain longer than a config may be is a candidate that carries the reason and no
	// text, and the rest of the paste stays usable.
	var long []string
	for i := 0; i < 10; i++ {
		d := ""
		if i < 9 {
			d = fmt.Sprintf(`,"streamSettings":{"sockopt":{"dialerProxy":"h%d"}}`, i+1)
		}
		long = append(long, fmt.Sprintf(`{"tag":"h%d","protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"%s","encryption":"none"}%s}`, i, uuid, d))
	}
	long = append(long, `{"tag":"ok","protocol":"trojan","settings":{"address":"a.example","port":1,"password":"p"},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"a.example"}}}`)
	res, err := FromJSON([]byte(`{"outbounds":[` + strings.Join(long, ",") + `]}`))
	if err != nil || len(res.Candidates) != 2 {
		t.Fatalf("%v %d candidates", err, len(res.Candidates))
	}
	if c := res.Candidates[0]; c.Err == nil || c.Fragment != nil {
		t.Errorf("a chain of ten has a fragment: %+v", c)
	}
	if c := res.Candidates[1]; c.Err != nil || c.Note != "ok" {
		t.Errorf("the other outbound of the paste: %+v", c)
	}

	// Two big outbounds in one chain are over the fragment limit: no text is built.
	res, err = FromJSON([]byte(`{"outbounds":[` + big + `,` + strings.Replace(hop, `"encryption":"none"`, `"encryption":"none","pad":"`+strings.Repeat("b", 20<<10)+`"`, 1) + `]}`))
	if err != nil || len(res.Candidates) != 1 {
		t.Fatalf("%v %d candidates", err, len(res.Candidates))
	}
	if c := res.Candidates[0]; c.Err == nil || len(c.Fragment) != 0 {
		t.Errorf("a chain over the fragment limit has a fragment of %d bytes", len(c.Fragment))
	}
}
