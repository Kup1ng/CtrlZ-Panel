package sharelink

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// Tests for the findings of review round 3 of B1.

func vmessLink(j string) string { return "vmess://" + base64.StdEncoding.EncodeToString([]byte(j)) }

// B1-r3-8: a field of the vmess JSON that no transport reads is an error, as it is for
// a URI link (R14), and the "type" of v2rayN is the mode of xhttp.
func TestVMessJSONDropsNothing(t *testing.T) {
	base := func(extra string) string {
		return `{"add":"203.0.113.7","port":"443","id":"` + uuid + `","aid":"0","tls":"","scy":"auto"` + extra + `}`
	}
	got := norm(t, vmessLink(base(`,"net":"xhttp","type":"stream-one","path":"/p","host":"a.example"`)))
	has(t, got, `"mode":"stream-one"`)
	norm(t, vmessLink(base(`,"net":"xhttp","type":"none"`)))
	norm(t, vmessLink(base(`,"net":"ws","type":"none","path":"/p"`)))
	for name, j := range map[string]string{
		"ws with a type":          base(`,"net":"ws","type":"http"`),
		"httpupgrade":             base(`,"net":"httpupgrade","type":"","path":"/p"`),
		"httpupgrade with a type": base(`,"net":"httpupgrade","type":"http"`),
		"kcp with a host":         base(`,"net":"kcp","host":"a.example"`),
		"kcp":                     base(`,"net":"kcp","type":"none"`),
		"text after the object":   base(`,"net":"ws"`) + `{"add":"x"}`,
		"a word after the object": base(`,"net":"ws"`) + ` junk`,
	} {
		if _, _, _, err := Convert(vmessLink(j)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A newline after the object is not text.
	norm(t, vmessLink(base(`,"net":"ws"`)+"\n"))
}

// B1-r3-7: the paste of B1-r3-7 (14,000 outbounds of one tag and one outbound with
// 9,800 links to it) took 7 s of CPU; the work is now the number of outbounds plus the
// number of links. The bound is loose so a loaded runner does not trip it.
func TestFromJSONManyLinksToOneTag(t *testing.T) {
	var outs []string
	for i := 0; i < 14000; i++ {
		outs = append(outs, `{"tag":"a"}`)
	}
	outs = append(outs, `{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"`+uuid+`","encryption":"none"},"x":[`+
		strings.TrimSuffix(strings.Repeat(`{"dialerProxy":"a"},`, 9800), ",")+`]}`)
	body := `{"outbounds":[` + strings.Join(outs, ",") + `]}`
	if len(body) > maxImportBytes {
		t.Fatalf("the paste is %d bytes, more than the import accepts", len(body))
	}
	start := time.Now()
	if _, err := FromJSON([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the import took %v", d)
	}
}

// The tags that name another outbound still take it out of the candidates, and an
// outbound that names its own tag does not name itself.
func TestFromJSONNamedOutbounds(t *testing.T) {
	ob := func(tag, hop string) string {
		s := `{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"` + uuid + `","encryption":"none"}`
		if tag != "" {
			s += `,"tag":"` + tag + `"`
		}
		if hop != "" {
			s += `,"streamSettings":{"sockopt":{"dialerProxy":"` + hop + `"}}`
		}
		return s + `}`
	}
	count := func(outs ...string) int {
		res, err := FromJSON([]byte(`{"outbounds":[` + strings.Join(outs, ",") + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		return len(res.Candidates)
	}
	if n := count(ob("m", "h"), ob("h", "")); n != 1 {
		t.Errorf("a main and its hop: %d candidates", n)
	}
	if n := count(ob("s", "s")); n != 1 {
		t.Errorf("an outbound that names its own tag: %d candidates", n)
	}
	// Two outbounds of one tag, both named by a third: both are hops.
	if n := count(ob("m", "h"), ob("h", ""), ob("h", "")); n != 1 {
		t.Errorf("two outbounds of one tag: %d candidates", n)
	}
	// Two naming each other have no main.
	if n := count(ob("a", "b"), ob("b", "a")); n != 0 {
		t.Errorf("a ring: %d candidates", n)
	}
	// The same link twice from one outbound counts once and changes nothing.
	if n := count(`{"protocol":"vless","settings":{"address":"203.0.113.7","port":443,"id":"`+uuid+`","encryption":"none"},"tag":"m","streamSettings":{"sockopt":{"dialerProxy":"h"}},"x":{"dialerProxy":"h"}}`, ob("h", "")); n != 1 {
		t.Errorf("a hop named twice: %d candidates", n)
	}
}
