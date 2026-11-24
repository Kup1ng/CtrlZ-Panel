package appleprofile

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

const ep = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"

func wantErr(t *testing.T, err error, pointer, code string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want *Error %s %s", err, pointer, code)
	}
	if e.Pointer != pointer || e.Code != code {
		t.Fatalf("got %s %s (%s), want %s %s", e.Pointer, e.Code, e.Reason, pointer, code)
	}
}

func TestUUIDv5MatchesRFC9562(t *testing.T) {
	// The DNS namespace and "www.example.com" are the example of RFC 4122
	// errata and of every UUIDv5 implementation: 2ed6657d-e927-568b-95e1-2665a8aea6a2.
	dns := [16]byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	got := uuidV5(dns, "www.example.com")
	if want := strings.ToUpper("2ed6657d-e927-568b-95e1-2665a8aea6a2"); got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestIdentifyIsStableAndDistinct(t *testing.T) {
	a, err := Identify(ep, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Identify(ep, "")
	if a != b {
		t.Fatal("identity is not deterministic")
	}
	c, err := Identify(ep, "kid")
	if err != nil {
		t.Fatal(err)
	}
	if c.PayloadIdentifier != "com.ctrlz.dns."+ep+".c.kid" || a.PayloadIdentifier != "com.ctrlz.dns."+ep {
		t.Fatalf("identifiers %q %q", a.PayloadIdentifier, c.PayloadIdentifier)
	}
	seen := map[string]bool{}
	for _, s := range []string{a.PayloadUUID, a.ContentUUID, a.RootUUID, c.PayloadUUID, c.ContentUUID, c.RootUUID} {
		if seen[s] {
			t.Fatalf("two payloads share the UUID %s", s)
		}
		seen[s] = true
		if len(s) != 36 || s[14] != '5' {
			t.Fatalf("%q is not a UUIDv5", s)
		}
	}
	other, _ := Identify("0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c", "")
	if other.PayloadUUID == a.PayloadUUID {
		t.Fatal("two Endpoints share a profile identity")
	}
}

// A client label may be "dns" or "root", the names of the payload suffixes. No
// identifier and no UUID of one profile may equal one of another profile of the
// same Endpoint, whatever the client is.
func TestIdentifiersOfAllProfilesOfAnEndpointAreDistinct(t *testing.T) {
	seenID := map[string]string{}
	seenUUID := map[string]string{}
	for _, c := range []string{"", "kid", "dns", "root", "c", "a-dns", "dns-root"} {
		id, err := Identify(ep, c)
		if err != nil {
			t.Fatal(err)
		}
		for part, v := range map[string][2]string{
			"payload": {id.PayloadIdentifier, id.PayloadUUID},
			"content": {id.ContentIdentifier, id.ContentUUID},
			"root":    {id.RootIdentifier, id.RootUUID},
		} {
			who := "client " + c + " " + part
			if prev, dup := seenID[v[0]]; dup {
				t.Errorf("identifier %s of %s is also that of %s", v[0], who, prev)
			}
			if prev, dup := seenUUID[v[1]]; dup {
				t.Errorf("UUID %s of %s is also that of %s", v[1], who, prev)
			}
			seenID[v[0]], seenUUID[v[1]] = who, who
		}
	}
	if len(seenID) != 21 {
		t.Fatalf("%d identifiers", len(seenID))
	}
}

func TestSSIDRefusesInvisibleAndBidiCharacters(t *testing.T) {
	for _, r := range []rune{0x200B, 0x200D, 0x200E, 0x202E, 0x2066, 0x2069, 0xFEFF, 0x2028, 0x2029, 0x85, 0x00} {
		req := Request{Protocol: "doh", ExcludedSSIDs: []string{"Home" + string(r)}}
		if err := Validate(req); err == nil {
			t.Errorf("U+%04X accepted", r)
		}
	}
	// The half-space of Persian network names stays.
	if err := Validate(Request{Protocol: "doh", ExcludedSSIDs: []string{"می‌خواهم"}}); err != nil {
		t.Errorf("ZWNJ refused: %v", err)
	}
}

func TestStoredParamsHaveOneSpelling(t *testing.T) {
	base := Params{Protocol: "doh", ExcludedSSIDs: []string{}}
	base.ExcludedDomains = []string{"b.example", "a.example"}
	if err := base.Validate(); err == nil {
		t.Error("unsorted stored domains accepted")
	}
	if _, err := base.Canonical(); err == nil {
		t.Error("Canonical of unsorted domains returned a form")
	}
	for name, in := range map[string]string{
		"repeated key":      `{"client":"","protocol":"dot","protocol":"doh","excluded_ssids":[],"excluded_domains":[],"prohibit_disablement":false}`,
		"key in other case": `{"client":"","Protocol":"doh","excluded_ssids":[],"excluded_domains":[],"prohibit_disablement":false}`,
		"all caps key":      `{"CLIENT":"","protocol":"doh","excluded_ssids":[],"excluded_domains":[],"prohibit_disablement":false}`,
		"not an object":     `[]`,
	} {
		if _, err := ParseParams([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	ok := `{"client":"","protocol":"doh","excluded_ssids":[],"excluded_domains":["a.example","b.example"],"prohibit_disablement":false}`
	if _, err := ParseParams([]byte(ok)); err != nil {
		t.Errorf("a canonical form refused: %v", err)
	}
}

func TestIdentifyRefusesWhatItCannotName(t *testing.T) {
	for _, id := range []string{"", ep[:35], strings.ToUpper(ep), strings.Replace(ep, "-", "", 1) + "-", "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5g"} {
		if _, err := Identify(id, ""); err == nil {
			t.Errorf("endpoint id %q accepted", id)
		}
	}
	for _, c := range []string{"Kid", "-kid", "kid-", "a b", strings.Repeat("a", 37)} {
		if _, err := Identify(ep, c); err == nil {
			t.Errorf("client %q accepted", c)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Request{Protocol: "doh", Client: "kid", ExcludedSSIDs: []string{"Home <&> ]]>"}, ExcludedDomains: []string{"Example.COM."}}
	if err := Validate(ok); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		mutate  func(r *Request)
		pointer string
		code    string
	}{
		{"protocol empty", func(r *Request) { r.Protocol = "" }, "/protocol", CodeInvalid},
		{"protocol doq", func(r *Request) { r.Protocol = "doq" }, "/protocol", CodeInvalid},
		{"client upper", func(r *Request) { r.Client = "Kid" }, "/client", CodeInvalid},
		{"ssid empty", func(r *Request) { r.ExcludedSSIDs = []string{""} }, "/excluded_ssids/0", CodeInvalid},
		{"ssid 33 bytes", func(r *Request) { r.ExcludedSSIDs = []string{"a", strings.Repeat("a", 33)} }, "/excluded_ssids/1", CodeInvalid},
		{"ssid not utf8", func(r *Request) { r.ExcludedSSIDs = []string{"\xff\xfe"} }, "/excluded_ssids/0", CodeInvalid},
		{"ssid newline", func(r *Request) { r.ExcludedSSIDs = []string{"a\nb"} }, "/excluded_ssids/0", CodeInvalid},
		{"ssid nul", func(r *Request) { r.ExcludedSSIDs = []string{"a\x00"} }, "/excluded_ssids/0", CodeInvalid},
		{"ssid noncharacter", func(r *Request) { r.ExcludedSSIDs = []string{"a￿"} }, "/excluded_ssids/0", CodeInvalid},
		{"domain ip", func(r *Request) { r.ExcludedDomains = []string{"example.com", "10.0.0.1"} }, "/excluded_domains/1", CodeInvalid},
		{"domain empty label", func(r *Request) { r.ExcludedDomains = []string{"a..b"} }, "/excluded_domains/0", CodeInvalid},
		{"domain wildcard", func(r *Request) { r.ExcludedDomains = []string{"*.example.com"} }, "/excluded_domains/0", CodeInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ok
			c.mutate(&r)
			wantErr(t, Validate(r), c.pointer, c.code)
		})
	}
}

func TestValidateBounds(t *testing.T) {
	var ssids []string
	for i := 0; i < MaxSSIDs; i++ {
		ssids = append(ssids, "net"+strconv.Itoa(i))
	}
	if err := Validate(Request{Protocol: "dot", ExcludedSSIDs: ssids}); err != nil {
		t.Fatalf("50 networks: %v", err)
	}
	wantErr(t, Validate(Request{Protocol: "dot", ExcludedSSIDs: append(ssids, "one-too-many")}), "/excluded_ssids", CodeExceeded)
	// A repeated network is one network, so repeats never reach the bound.
	if err := Validate(Request{Protocol: "dot", ExcludedSSIDs: append(append([]string{}, ssids...), ssids...)}); err != nil {
		t.Fatalf("repeats: %v", err)
	}
	if err := Validate(Request{Protocol: "dot", ExcludedSSIDs: []string{strings.Repeat("é", 16)}}); err != nil {
		t.Fatalf("32 bytes of 16 runes: %v", err)
	}
	wantErr(t, Validate(Request{Protocol: "dot", ExcludedSSIDs: []string{strings.Repeat("é", 17)}}), "/excluded_ssids/0", CodeInvalid)

	var doms []string
	for i := 0; i < MaxUserDomains; i++ {
		doms = append(doms, "d"+strconv.Itoa(i)+".example.com")
	}
	if err := Validate(Request{Protocol: "doh", ExcludedDomains: doms}); err != nil {
		t.Fatalf("100 domains: %v", err)
	}
	// The same names spelled twice are 100 domains, not 200: a folder and a
	// typed list overlap in practice.
	dup := append(append([]string{}, doms...), "D0.Example.com.")
	if err := Validate(Request{Protocol: "doh", ExcludedDomains: dup}); err != nil {
		t.Fatalf("a repeat: %v", err)
	}
	wantErr(t, Validate(Request{Protocol: "doh", ExcludedDomains: append(doms, "extra.example.com")}), "/excluded_domains", CodeExceeded)
}

func TestExpand(t *testing.T) {
	req := Request{
		Protocol: "doh", Client: "kid",
		ExcludedSSIDs:       []string{"Home", "Office", "Home"},
		ExcludedDomains:     []string{"B.example.com", "a.example.com", "b.example.com."},
		ExcludeCommon:       true,
		ProhibitDisablement: true,
	}
	p, err := Expand(req, []string{"local", "Captive.Apple.com", "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.example.com", "captive.apple.com", "local"}
	if strings.Join(p.ExcludedDomains, ",") != strings.Join(want, ",") {
		t.Fatalf("domains %v want %v", p.ExcludedDomains, want)
	}
	if strings.Join(p.ExcludedSSIDs, ",") != "Home,Office" || !p.ProhibitDisablement || p.Client != "kid" || p.Protocol != "doh" {
		t.Fatalf("params %+v", p)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expanded params do not validate: %v", err)
	}

	// Without the flag the common list is not read at all, even a bad one.
	req.ExcludeCommon = false
	p, err = Expand(req, []string{"not a name"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ExcludedDomains) != 2 {
		t.Fatalf("domains %v", p.ExcludedDomains)
	}
	req.ExcludeCommon = true
	_, err = Expand(req, []string{"not a name"})
	wantErr(t, err, "/exclude_common", CodeInvalid)
}

func TestExpandBound(t *testing.T) {
	var typed, common []string
	for i := 0; i < MaxUserDomains; i++ {
		typed = append(typed, "t"+strconv.Itoa(i)+".example.com")
	}
	for i := 0; i < MaxExpandedDomains-MaxUserDomains; i++ {
		common = append(common, "c"+strconv.Itoa(i)+".example.net")
	}
	req := Request{Protocol: "dot", ExcludedDomains: typed, ExcludeCommon: true}
	p, err := Expand(req, common)
	if err != nil {
		t.Fatalf("exactly 200: %v", err)
	}
	if len(p.ExcludedDomains) != MaxExpandedDomains {
		t.Fatalf("got %d", len(p.ExcludedDomains))
	}
	_, err = Expand(req, append(common, "one-more.example.net"))
	wantErr(t, err, "/exclude_common", CodeExceeded)
	// A list longer than the bound is refused before any entry is parsed.
	long := make([]string, MaxExpandedDomains+1)
	for i := range long {
		long[i] = "not a name"
	}
	_, err = Expand(req, long)
	wantErr(t, err, "/exclude_common", CodeExceeded)
}

func TestCanonicalRoundTrip(t *testing.T) {
	p, err := Expand(Request{Protocol: "doh", ExcludedSSIDs: []string{`<a href="x">&amp;`, "]]>"}, ExcludedDomains: []string{"example.com"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"client":"","protocol":"doh","excluded_ssids":["<a href=\"x\">&amp;","]]>"],"excluded_domains":["example.com"],"prohibit_disablement":false}`
	if string(b) != want {
		t.Fatalf("got  %s\nwant %s", b, want)
	}
	back, err := ParseParams(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := back.Canonical()
	if string(b2) != string(b) {
		t.Fatal("round trip changed the bytes")
	}
	h1, err := p.Hash()
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := back.Hash()
	if h1 != h2 {
		t.Fatal("hash differs after a round trip")
	}
	p.Client = "kid"
	h3, _ := p.Hash()
	if h3 == h1 {
		t.Fatal("hash does not cover the client")
	}
	// Nil lists and empty lists are one form.
	e1, _ := Params{Protocol: "dot"}.Canonical()
	e2, _ := Params{Protocol: "dot", ExcludedSSIDs: []string{}, ExcludedDomains: []string{}}.Canonical()
	if string(e1) != string(e2) || !strings.Contains(string(e1), `"excluded_ssids":[]`) {
		t.Fatalf("empty forms %s %s", e1, e2)
	}
}

func TestParseParamsRefuses(t *testing.T) {
	good := `{"client":"","protocol":"doh","excluded_ssids":[],"excluded_domains":["example.com"],"prohibit_disablement":false}`
	if _, err := ParseParams([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"unknown field":      `{"client":"","protocol":"doh","excluded_ssids":[],"excluded_domains":[],"prohibit_disablement":false,"from_folder_id":"x"}`,
		"trailing data":      good + `{}`,
		"not canonical name": `{"client":"","protocol":"doh","excluded_ssids":[],"excluded_domains":["Example.com"],"prohibit_disablement":false}`,
		"repeated domain":    `{"client":"","protocol":"doh","excluded_ssids":[],"excluded_domains":["example.com","example.com"],"prohibit_disablement":false}`,
		"repeated ssid":      `{"client":"","protocol":"doh","excluded_ssids":["a","a"],"excluded_domains":[],"prohibit_disablement":false}`,
		"bad protocol":       `{"client":"","protocol":"doq","excluded_ssids":[],"excluded_domains":[],"prohibit_disablement":false}`,
		"not json":           `nope`,
		"empty":              ``,
		"wrong type":         `{"client":1}`,
	}
	for name, in := range bad {
		if _, err := ParseParams([]byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseParams([]byte(strings.Repeat(" ", MaxParamsBytes+1))); err == nil {
		t.Error("oversized params accepted")
	}
}

// The stored form must fit the CHECK of profile_download_tokens at its worst:
// 200 domains of 253 bytes, 50 networks of 32 bytes that all need escaping.
func TestWorstCaseFitsTheStoredBound(t *testing.T) {
	var doms []string
	for i := 0; i < MaxExpandedDomains; i++ {
		// 253 bytes: three labels of 63 and one of 61, the first one unique.
		l1 := strconv.Itoa(1000+i) + strings.Repeat("a", 59)
		doms = append(doms, l1+"."+strings.Repeat("b", 63)+"."+strings.Repeat("c", 63)+"."+strings.Repeat("d", 61))
	}
	var ssids []string
	for i := 0; i < MaxSSIDs; i++ {
		ssids = append(ssids, strings.Repeat(`"`, 31)+string(rune('a'+i%26)))
	}
	p, err := Expand(Request{Protocol: "doh", ExcludedSSIDs: ssids, ExcludedDomains: doms[:MaxUserDomains], ExcludeCommon: true}, doms[MaxUserDomains:])
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxParamsBytes {
		t.Fatalf("%d bytes", len(b))
	}
	t.Logf("worst case %d of %d bytes", len(b), MaxParamsBytes)
}
