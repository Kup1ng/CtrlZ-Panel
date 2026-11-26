package wire

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	peerv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/peer/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
)

func b(n int, v byte) []byte { return bytes.Repeat([]byte{v}, n) }

func goodEndpoint() *policyv1.EndpointRecord {
	return &policyv1.EndpointRecord{
		EndpointId: b(16, 1), RidHash: b(16, 2), DohTokenHash: b(32, 3), PairId: b(16, 4),
		AdminState: commonv1.AdminState_ADMIN_STATE_ENABLED, AnalyticsLevel: commonv1.AnalyticsLevel_ANALYTICS_LEVEL_FULL,
		Base:       &policyv1.StackRecord{Profile1Hash: b(32, 5)},
		Authorized: []*commonv1.Prefix{{Addr: []byte{5, 160, 0, 0}, Bits: 16}},
	}
}

func goodEntry() *policyv1.ConfigEntry {
	return &policyv1.ConfigEntry{
		Seq: 1, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, PrevHash: make([]byte, 32), CreatedAt: 1_700_000_000,
		PutBlobs:     []*policyv1.BlobRef{{Hash: b(32, 5), Size: 1000, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}},
		PutEndpoints: []*policyv1.EndpointRecord{goodEndpoint()},
		PutClaims:    []*policyv1.ClaimRecord{{ClaimId: b(16, 7), EndpointId: b(16, 1), Prefix: &commonv1.Prefix{Addr: []byte{5, 160, 1, 0}, Bits: 24}}},
	}
}

func TestDecodeEntryRoundTrip(t *testing.T) {
	raw, err := MarshalEntry(goodEntry())
	if err != nil {
		t.Fatal(err)
	}
	e, err := DecodeEntry(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 1 || len(e.PutEndpoints) != 1 {
		t.Fatalf("%+v", e)
	}
	// Deterministic marshaling: same message, same bytes.
	raw2, _ := MarshalEntry(goodEntry())
	if !bytes.Equal(raw, raw2) {
		t.Fatal("marshal is not deterministic")
	}
}

func TestEntryHashChain(t *testing.T) {
	raw, _ := MarshalEntry(goodEntry())
	h1 := EntryHash(ZeroHash(), raw)
	if h1 == ZeroHash() || h1 != EntryHash(ZeroHash(), raw) {
		t.Fatal("hash")
	}
	if h1 == EntryHash(h1, raw) {
		t.Fatal("prev hash must matter")
	}
	flipped := append([]byte(nil), raw...)
	flipped[len(flipped)-1] ^= 1
	if EntryHash(ZeroHash(), flipped) == h1 {
		t.Fatal("content must matter")
	}
}

func TestValidateEntryRejects(t *testing.T) {
	mut := func(f func(e *policyv1.ConfigEntry)) *policyv1.ConfigEntry {
		e := goodEntry()
		f(e)
		return e
	}
	cases := map[string]*policyv1.ConfigEntry{
		"seq 0":         mut(func(e *policyv1.ConfigEntry) { e.Seq = 0 }),
		"class":         mut(func(e *policyv1.ConfigEntry) { e.Class = 0 }),
		"prev_hash":     mut(func(e *policyv1.ConfigEntry) { e.PrevHash = b(31, 0) }),
		"negative time": mut(func(e *policyv1.ConfigEntry) { e.CreatedAt = -1 }),
		"blob hash":     mut(func(e *policyv1.ConfigEntry) { e.PutBlobs[0].Hash = b(31, 1) }),
		"blob kind":     mut(func(e *policyv1.ConfigEntry) { e.PutBlobs[0].Kind = 0 }),
		"blob size":     mut(func(e *policyv1.ConfigEntry) { e.PutBlobs[0].Size = MaxProfileBlob + 1 }),
		"page blob size": mut(func(e *policyv1.ConfigEntry) {
			e.PutBlobs[0].Kind = policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE
			e.PutBlobs[0].Size = MaxBlockPageBlob + 1
		}),
		"duplicate blob":     mut(func(e *policyv1.ConfigEntry) { e.PutBlobs = append(e.PutBlobs, e.PutBlobs[0]) }),
		"endpoint id":        mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].EndpointId = b(15, 1) }),
		"admin state":        mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].AdminState = 9 }),
		"analytics":          mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].AnalyticsLevel = 0 }),
		"no base":            mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].Base = nil }),
		"merged options":     mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].Base.MergedOptions = b(96, 0xff) }),
		"prefix host bits":   mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].Authorized[0].Addr = []byte{5, 160, 1, 0} }),
		"prefix bits":        mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].Authorized[0].Bits = 33 }),
		"prefix len":         mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints[0].Authorized[0].Addr = []byte{1, 2, 3} }),
		"duplicate endpoint": mut(func(e *policyv1.ConfigEntry) { e.PutEndpoints = append(e.PutEndpoints, goodEndpoint()) }),
		"claim prefix":       mut(func(e *policyv1.ConfigEntry) { e.PutClaims[0].Prefix = nil }),
		"del endpoint":       mut(func(e *policyv1.ConfigEntry) { e.DelEndpoints = [][]byte{b(3, 1)} }),
		"bad schedule grid": mut(func(e *policyv1.ConfigEntry) {
			e.PutEndpoints[0].Schedule = &policyv1.ScheduleRecord{Grid: b(10, 0)}
		}),
		"schedule window out of range": mut(func(e *policyv1.ConfigEntry) {
			g := b(336, 0)
			g[5] = 2
			e.PutEndpoints[0].Schedule = &policyv1.ScheduleRecord{Grid: g, Windows: []*policyv1.WindowRecord{{WindowId: b(16, 9), Stack: &policyv1.StackRecord{Profile1Hash: b(32, 5)}}}}
		}),
		"pair names unknown node": mut(func(e *policyv1.ConfigEntry) {
			e.PairTable = &policyv1.PairTable{GlobalPairId: b(16, 1), Pairs: []*policyv1.Pair{{PairId: b(16, 1), Primary: b(16, 9)}}}
		}),
		"catalog key": mut(func(e *policyv1.ConfigEntry) { e.Catalog = &policyv1.CatalogRef{Key: b(15, 1)} }),
	}
	for name, e := range cases {
		if err := ValidateEntry(e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDecodeEntryRejectsGarbage(t *testing.T) {
	for name, in := range map[string][]byte{
		"truncated": {0x08},
		"bad tag":   {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		"empty":     {},
	} {
		if _, err := DecodeEntry(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodeEntry(make([]byte, MaxEntrySize+1)); reason.CodeOf(err) != reason.SizeCap {
		t.Errorf("oversize: %v", err)
	}
}

func TestReasonCodesMirror(t *testing.T) {
	pairs := map[Reason]string{
		ReasonBadMagic: "bad_magic", ReasonUnsupportedMajor: "unsupported_major", ReasonLengthMismatch: "length_mismatch",
		ReasonBadDirectory: "bad_directory", ReasonMissingSection: "missing_section", ReasonBadSection: "bad_section",
		ReasonIndexRange: "index_range", ReasonUnsorted: "unsorted", ReasonBadEnum: "bad_enum", ReasonBadName: "bad_name",
		ReasonHashMismatch: "hash_mismatch", ReasonSizeCap: "size_cap", ReasonPanic: "panic", ReasonUnsupportedSection: "unsupported_section",
	}
	if len(pairs) != len(reason.All()) {
		t.Fatal("reason list and contract list differ in length")
	}
	for c, s := range pairs {
		if string(c) != s {
			t.Errorf("%q != %q", c, s)
		}
	}
}

func FuzzDecodeEntry(f *testing.F) {
	raw, _ := MarshalEntry(goodEntry())
	f.Add(raw)
	f.Add([]byte{})
	f.Add(raw[:len(raw)/2])
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := DecodeEntry(data)
		if err != nil {
			if reason.CodeOf(err) == reason.Panic {
				t.Fatalf("decoder panicked: %v", err)
			}
			return
		}
		// An entry that decodes must validate again after a re-marshal.
		re, err := proto.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeEntry(re); err != nil {
			t.Fatalf("accepted entry fails after re-marshal: %v", err)
		}
	})
}

func TestWriteCorpus(t *testing.T) {
	if os.Getenv("CTRLZ_WRITE_CORPUS") == "" {
		t.Skip("set CTRLZ_WRITE_CORPUS=1 to regenerate seed corpus")
	}
	raw, _ := MarshalEntry(goodEntry())
	dir := filepath.Join("testdata", "fuzz", "FuzzDecodeEntry")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"valid": raw, "truncated": raw[:len(raw)/2]} {
		body := "go test fuzz v1\n[]byte(" + strconv.Quote(string(data)) + ")\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// FuzzValidateNodeConfig: any bytes that parse as a NodeConfig either validate
// or are refused, and validation never panics (it runs on a message from the network).
func FuzzValidateNodeConfig(f *testing.F) {
	ok := &hubv1.NodeConfig{
		DnsBindIp: []byte{198, 51, 100, 1}, DnsAdvertisedIp: []byte{198, 51, 100, 1}, ProxyBindIp: []byte{198, 51, 100, 2}, ProxyAdvertisedIp: []byte{198, 51, 100, 2},
		Zones: []string{"dns.example.com"}, Mode: commonv1.ResolveMode_RESOLVE_MODE_HYBRID, ProofKey: b(32, 1),
		Upstreams: []*hubv1.Upstream{{Id: b(16, 1), Kind: commonv1.UpstreamKind_UPSTREAM_KIND_DOH, Address: "dns.example.net", BootstrapIp: []byte{192, 0, 2, 1}, TimeoutMs: 2000}},
		Groups:    []*hubv1.UpstreamGroup{{Name: "g", UpstreamIds: [][]byte{b(16, 1)}}},
		Rules:     []*hubv1.ResolverRule{{Order: 1, MatchType: "suffix", MatchValue: "example.ir", Group: "g"}},
	}
	raw, _ := proto.Marshal(ok)
	if err := ValidateNodeConfig(ok); err != nil {
		f.Fatalf("seed config invalid: %v", err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var c hubv1.NodeConfig
		if proto.Unmarshal(data, &c) != nil {
			return
		}
		_ = ValidateNodeConfig(&c)
	})
}

func validGrant(now int64) *peerv1.GrantForward {
	n := names.MustString("example.com")
	return &peerv1.GrantForward{
		GrantId: bytes.Repeat([]byte{1}, 16), EndpointId: bytes.Repeat([]byte{2}, 16),
		SourcePrefix: []byte{1, 2, 3, 0, 24}, NameWire: n.Wire(), GrantKind: 1, ExpiresAt: now + 3600,
	}
}

// TestValidateGrantForwardSource: a peer is untrusted input. Before the
// prefix was decoded, 1.2.3.4/0 and a 255-bit prefix both passed, so one stolen
// pair node could forward a grant that lets every source use the proxy.
func TestValidateGrantForwardSource(t *testing.T) {
	const now = 1_000_000
	if err := ValidateGrantForward(validGrant(now), now); err != nil {
		t.Fatalf("a valid grant: %v", err)
	}
	mutate := func(f func(g *peerv1.GrantForward)) error {
		g := validGrant(now)
		f(g)
		return ValidateGrantForward(g, now)
	}
	v6 := append(netip.MustParseAddr("2001:db8::").AsSlice(), 48)
	for name, f := range map[string]func(g *peerv1.GrantForward){
		"/0 on a real address":   func(g *peerv1.GrantForward) { g.SourcePrefix = []byte{1, 2, 3, 4, 0} },
		"/8 below the floor":     func(g *peerv1.GrantForward) { g.SourcePrefix = []byte{1, 0, 0, 0, 8} },
		"bits beyond the family": func(g *peerv1.GrantForward) { g.SourcePrefix = []byte{1, 2, 3, 0, 255} },
		"33 bits on IPv4":        func(g *peerv1.GrantForward) { g.SourcePrefix = []byte{1, 2, 3, 4, 33} },
		"host bits set":          func(g *peerv1.GrantForward) { g.SourcePrefix = []byte{1, 2, 3, 4, 24} },
		"IPv4-mapped IPv6": func(g *peerv1.GrantForward) {
			g.SourcePrefix = append(netip.MustParseAddr("::ffff:1.2.3.0").AsSlice(), 120)
		},
		"IPv6 below the floor":       func(g *peerv1.GrantForward) { g.SourcePrefix = append(netip.MustParseAddr("2000::").AsSlice(), 16) },
		"root name":                  func(g *peerv1.GrantForward) { g.NameWire = []byte{0} },
		"uppercase name":             func(g *peerv1.GrantForward) { g.NameWire = []byte("\x07EXAMPLE\x03com\x00") },
		"uppercase dial host":        func(g *peerv1.GrantForward) { g.DialHostWire = []byte("\x03WWW\x03com\x00") },
		"prefix of the wrong length": func(g *peerv1.GrantForward) { g.SourcePrefix = []byte{1, 2, 3} },
	} {
		if err := mutate(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := mutate(func(g *peerv1.GrantForward) { g.SourcePrefix = v6 }); err != nil {
		t.Errorf("a /48 IPv6 source: %v", err)
	}
	if err := mutate(func(g *peerv1.GrantForward) { g.SourcePrefix = []byte{1, 2, 3, 4, 32} }); err != nil {
		t.Errorf("a /32 source: %v", err)
	}
	// A node with a measured policy may set its own floor.
	g := validGrant(now)
	g.SourcePrefix = []byte{1, 2, 0, 0, 16}
	if err := ValidateGrantForwardWidth(g, now, 24, 48); err == nil {
		t.Error("a /16 passed a /24 floor")
	}
}
