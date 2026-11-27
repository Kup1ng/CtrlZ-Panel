package identity

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

const (
	rid   = "abcdefghijklmnopqrstuvwxy2"       // 26 chars
	token = "abcdefghijklmnopqrstuvwxyz234567" // 32 chars
)

func zones() []names.Name { return []names.Name{names.MustString("dns.example.com")} }

func TestLengths(t *testing.T) {
	if len(rid) != 26 || len(token) != 32 {
		t.Fatal("test constants")
	}
}

func TestParseHost(t *testing.T) {
	z := zones()
	cases := []struct {
		in   string
		want Host
	}{
		{"dns.example.com", Host{Kind: HostApex}},
		{"DNS.Example.COM.", Host{Kind: HostApex}},
		{"example.org", Host{Kind: HostOutOfZone}},
		{"evildns.example.com", Host{Kind: HostOutOfZone}},
		{rid + ".dns.example.com", Host{Kind: HostResolver, RID: rid}},
		{rid + "-kid.dns.example.com", Host{Kind: HostResolver, RID: rid, Client: "kid"}},
		{rid + "-kid.dns.example.com:443", Host{Kind: HostResolver, RID: rid, Client: "kid"}},
		// L1-F11: a fully qualified host keeps its meaning with a port.
		{rid + "-kid.dns.example.com.:443", Host{Kind: HostResolver, RID: rid, Client: "kid"}},
		{"dns.example.com.:443", Host{Kind: HostApex}},
		{"dns.example.com.:443.", Host{Kind: HostOutOfZone}},
		{"dns.example.com:443.", Host{Kind: HostOutOfZone}},
		{"dns.example.com..", Host{Kind: HostOutOfZone}},
		{rid + "-" + strings.Repeat("a", 36) + ".dns.example.com", Host{Kind: HostResolver, RID: rid, Client: strings.Repeat("a", 36)}},
		{rid + "-" + strings.Repeat("a", 37) + ".dns.example.com", Host{Kind: HostMalformed}},
		{rid[:25] + ".dns.example.com", Host{Kind: HostMalformed}},
		{rid + "x.dns.example.com", Host{Kind: HostMalformed}},
		{rid + "-.dns.example.com", Host{Kind: HostMalformed}},
		{rid + "--a.dns.example.com", Host{Kind: HostMalformed}},
		{"a." + rid + ".dns.example.com", Host{Kind: HostMalformed}},
		{"1" + rid[1:] + ".dns.example.com", Host{Kind: HostMalformed}}, // '1' is not base32
		{rid + ".verify.dns.example.com", Host{Kind: HostVerify, Label: rid}},
		{"verify.dns.example.com", Host{Kind: HostReserved, Name: "verify"}},
		{"myip.dns.example.com", Host{Kind: HostReserved, Name: "myip"}},
		{"_acme-challenge.dns.example.com", Host{Kind: HostReserved, Name: "_acme-challenge"}},
		{"_acme-challenge.verify.dns.example.com", Host{Kind: HostReserved, Name: "_acme-challenge.verify"}},
		{"_acme-challenge.verify.dns.example.com.:443", Host{Kind: HostReserved, Name: "_acme-challenge.verify"}},
		{"_acme-challenge.other.dns.example.com", Host{Kind: HostMalformed}},
		{"ns4.dns.example.com", Host{Kind: HostReserved, Name: "ns4"}},
		{"ns5.dns.example.com", Host{Kind: HostMalformed}},
		{"short.verify.dns.example.com", Host{Kind: HostMalformed}},
	}
	for _, c := range cases {
		if got := ParseHost(c.in, z); got != c.want {
			t.Errorf("%q: got %+v want %+v", c.in, got, c.want)
		}
	}
}

func TestParseHostTwoZones(t *testing.T) {
	z := []names.Name{names.MustString("dns.old.example"), names.MustString("dns.new.example")}
	if h := ParseHost(rid+".dns.new.example", z); h.Kind != HostResolver {
		t.Fatalf("%+v", h)
	}
	if h := ParseHost(rid+".dns.old.example", z); h.Kind != HostResolver {
		t.Fatalf("%+v", h)
	}
}

func TestParseDoHPath(t *testing.T) {
	good := map[string]DoHPath{
		"/" + token:                        {Form: 'A', Token: token},
		"/" + token + "/kid":               {Form: 'A', Token: token, Client: "kid"},
		"/" + token + "?dns=AAAA":          {Form: 'A', Token: token},
		"/" + strings.ToUpper(token):       {Form: 'A', Token: token},
		"/" + rid + "/" + token:            {Form: 'B', RID: rid, Token: token},
		"/" + rid + "/" + token + "/kid-1": {Form: 'B', RID: rid, Token: token, Client: "kid-1"},
	}
	for in, want := range good {
		got, err := ParseDoHPath(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	bad := []string{"", "/", token, "/dns-query", "/" + token + "/", "/" + token + "/a/b", "/" + rid, "/" + rid + "/short",
		"/" + rid + "/" + token + "/a/b", "/" + token[:31] + "1", "/" + token + "/-bad"}
	for _, in := range bad {
		if _, err := ParseDoHPath(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestResolveDoH(t *testing.T) {
	z := zones()
	// Form A needs a resolver authority.
	if _, err := ResolveDoH("/"+token, "dns.example.com", z); err == nil {
		t.Error("form A with apex authority accepted")
	}
	got, err := ResolveDoH("/"+token, rid+"-dev.dns.example.com:443", z)
	if err != nil || got != (DoHTarget{RID: rid, Token: token, Client: "dev"}) {
		t.Errorf("%+v %v", got, err)
	}
	// Form B with apex authority.
	got, err = ResolveDoH("/"+rid+"/"+token, "dns.example.com", z)
	if err != nil || got.RID != rid || got.Client != "" {
		t.Errorf("%+v %v", got, err)
	}
	// Path client beats authority client.
	got, _ = ResolveDoH("/"+token+"/pathc", rid+"-authc.dns.example.com", z)
	if got.Client != "pathc" {
		t.Errorf("client %q", got.Client)
	}
	// Path id beats a different authority id, and that authority's client is ignored.
	other := "zyxwvutsrqponmlkjihgfedcba"
	got, _ = ResolveDoH("/"+rid+"/"+token, other+"-evil.dns.example.com", z)
	if got.RID != rid || got.Client != "" {
		t.Errorf("%+v", got)
	}
}

func TestSlugClient(t *testing.T) {
	cases := map[string]string{
		"My Phone":                     "my-phone",
		"  --Kid's iPad":               "kid-s-ipad",
		"ＡＢＣ１２３":                       "abc123", // NFKC folds full-width forms
		strings.Repeat("a", 40):        strings.Repeat("a", 36),
		strings.Repeat("a", 35) + " b": strings.Repeat("a", 35),
	}
	for in, want := range cases {
		got, ok := SlugClient(in)
		if !ok || got != want {
			t.Errorf("%q: %q %v want %q", in, got, ok, want)
		}
		if !ValidClient(got) {
			t.Errorf("%q: slug %q is not a valid client", in, got)
		}
	}
	for _, in := range []string{"", "   ", "گوشی من", "---"} {
		if s, ok := SlugClient(in); ok {
			t.Errorf("%q gave %q", in, s)
		}
	}
}

func TestGenerators(t *testing.T) {
	a, err := NewResolverID()
	if err != nil || !ValidResolverID(a) {
		t.Fatalf("%q %v", a, err)
	}
	b, _ := NewDoHToken()
	if !ValidDoHToken(b) {
		t.Fatal(b)
	}
	c, _ := NewVerifyLabel()
	if !ValidVerifyLabel(c) {
		t.Fatal(c)
	}
	if a == c {
		t.Fatal("two random ids equal")
	}
}

func TestHashesDomainSeparated(t *testing.T) {
	// The same ASCII string must hash differently for each purpose.
	r := RIDHash("x")
	c := ClientHash("x")
	if r == c {
		t.Fatal("rid and client hash collide")
	}
	tk := TokenHash("x")
	if string(tk[:16]) == string(r[:]) {
		t.Fatal("token and rid hash collide")
	}
}

func TestProofCodeStable(t *testing.T) {
	ip := netip.MustParseAddr
	a := ProofCode([]byte("k"), "lbl", ip("192.0.2.1"))
	b := ProofCode([]byte("k"), "lbl", ip("192.0.2.1"))
	if a != b || len(a) != ProofLen || strings.ToLower(a) != a {
		t.Fatal(a)
	}
	if a == ProofCode([]byte("k"), "lbl", ip("192.0.2.2")) || a == ProofCode([]byte("k2"), "lbl", ip("192.0.2.1")) {
		t.Fatal("proof ignores an input")
	}
}

// One source, one code: an IPv4-mapped address is the same source as its IPv4
// form, and an IPv6 address has one text form whatever its spelling.
func TestProofCodeHasOneTextForm(t *testing.T) {
	ip := netip.MustParseAddr
	k := []byte("k")
	if ProofCode(k, "lbl", ip("::ffff:192.0.2.1")) != ProofCode(k, "lbl", ip("192.0.2.1")) {
		t.Error("the mapped form gives another code")
	}
	if ProofCode(k, "lbl", ip("2001:DB8:0:0:0:0:0:1")) != ProofCode(k, "lbl", ip("2001:db8::1")) {
		t.Error("two spellings of one IPv6 address give two codes")
	}
	if ProofCode(k, "lbl", ip("2001:db8::1")) == ProofCode(k, "lbl", ip("2001:db8::2")) {
		t.Error("different addresses give one code")
	}
}

func FuzzParseHost(f *testing.F) {
	f.Add(rid+"-kid.dns.example.com", "x")
	f.Add("verify.dns.example.com", "x")
	f.Add("_acme-challenge.verify.dns.example.com", "x")
	f.Add("DNS.EXAMPLE.COM.:53", "x")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, host, _ string) {
		h := ParseHost(host, zones())
		if h.Kind == HostResolver {
			if !ValidResolverID(h.RID) || (h.Client != "" && !ValidClient(h.Client)) {
				t.Fatalf("invalid resolver host accepted: %+v", h)
			}
		}
		if h.Kind == HostVerify && !ValidVerifyLabel(h.Label) {
			t.Fatalf("%+v", h)
		}
	})
}

func FuzzParseDoHPath(f *testing.F) {
	f.Add("/" + token)
	f.Add("/" + rid + "/" + token + "/kid")
	f.Add("/%2e%2e/" + token)
	f.Add("//")
	f.Fuzz(func(t *testing.T, p string) {
		d, err := ParseDoHPath(p)
		if err != nil {
			return
		}
		if !ValidDoHToken(d.Token) || (d.Client != "" && !ValidClient(d.Client)) {
			t.Fatalf("%+v", d)
		}
		if (d.Form == 'B') != (d.RID != "") {
			t.Fatalf("%+v", d)
		}
		if d.Form == 'B' && !ValidResolverID(d.RID) {
			t.Fatalf("%+v", d)
		}
	})
}

func FuzzSlugClient(f *testing.F) {
	f.Add("My Phone")
	f.Add("گوشی")
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := SlugClient(s)
		if ok && !ValidClient(out) {
			t.Fatalf("slug %q of %q is not a valid client", out, s)
		}
	})
}

func TestTokenMatches(t *testing.T) {
	const tok = "abcdefghijklmnopqrstuvwxyz234567"
	want := TokenHash(tok)
	if !TokenMatches(tok, want) {
		t.Error("the right token does not match")
	}
	for _, wrong := range []string{"", "abcdefghijklmnopqrstuvwxyz234568", "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", tok + "a", tok[:31]} {
		if TokenMatches(wrong, want) {
			t.Errorf("%q matched", wrong)
		}
	}
}

func TestAccountHash(t *testing.T) {
	id := []byte("0123456789abcdef")
	a := AccountHash(id)
	if len(a) != 16 {
		t.Fatalf("length %d", len(a))
	}
	// Pinned: the node and the panel must agree for ever, and a vector in another
	// language would be wrong by one byte of the prefix. SHA-256 of
	// "ctrlz-account-v1\x00" + "0123456789abcdef", first 16 bytes.
	want := sha256.Sum256([]byte("ctrlz-account-v1\x000123456789abcdef"))
	if !bytes.Equal(a, want[:16]) {
		t.Errorf("hash %x want %x", a, want[:16])
	}
	if bytes.Equal(a, AccountHash([]byte("0123456789abcdeg"))) {
		t.Error("two ids, one hash")
	}
	// Domain separation: it is not the client hash or the rid hash of the same text.
	rid := RIDHash(string(id))
	if bytes.Equal(a, rid[:]) {
		t.Error("the account hash equals the rid hash")
	}
	// The caller's slice is not kept, so a later write to it cannot change the label.
	a[0] ^= 0xff
	if bytes.Equal(a, AccountHash(id)) {
		t.Error("the result aliases a shared buffer")
	}
	for _, n := range []int{0, 15, 17, 32} {
		if AccountHash(make([]byte, n)) != nil {
			t.Errorf("an id of %d bytes got a hash", n)
		}
	}
}
