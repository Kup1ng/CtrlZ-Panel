package blob

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

func pat(t testing.TB, s string) rules.Pattern {
	t.Helper()
	p, err := rules.Parse(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return p
}

func rid(n byte) [16]byte { return [16]byte{n} }

// sample exercises every section and every target kind.
func sample(t testing.TB) *Spec {
	host := names.MustString("safe.example.net")
	return &Spec{
		DisabledUntil: 0,
		Options: Options{
			Present:       OptExfiltration | OptRebind | OptBlockResponse | OptECS | OptBlockTTL | OptBypassTTL,
			Bools:         uint8(OptExfiltration | OptRebind),
			BlockResponse: BlockCustom,
			BlockV4:       [4]byte{192, 0, 2, 1},
			ECSMode:       ECSAuto,
			ECSV4Prefix:   24,
			ECSV6Prefix:   56,
			BlockTTL:      30,
			BypassTTL:     120,
		},
		Default:       ActRedirect,
		DefaultTarget: &TargetSpec{Kind: TargetAuto, Set: []uint16{9, 3, 5}},
		Rules: []RuleSpec{
			{ID: rid(1), Pattern: pat(t, "ads.example.com"), Action: ActBlock},
			{ID: rid(2), Pattern: pat(t, "example.com"), Action: ActBypass, ExpiresAt: 2_000_000_000},
			{ID: rid(3), Pattern: pat(t, "*.example.com"), Action: ActRedirect, Target: &TargetSpec{Kind: TargetLocation, Location: 7}},
			{ID: rid(4), Pattern: pat(t, "server-*.example.com"), Action: ActBlock, DoNotLog: true},
			{ID: rid(5), Pattern: pat(t, "a.*.example.com"), Action: ActRedirect, Target: &TargetSpec{Kind: TargetHost, Host: host.Wire()}},
			{ID: rid(6), Pattern: pat(t, "@IR"), Action: ActBlock},
			{ID: rid(7), Pattern: pat(t, "!@IR"), Action: ActBypass},
			{ID: rid(8), Pattern: pat(t, "@AS13335"), Action: ActRedirect, Target: &TargetSpec{Kind: TargetRandom, Set: []uint16{1, 2}}, LocationUnavailable: true},
			{ID: rid(9), Pattern: pat(t, "#IR"), Action: ActBlock},
			{ID: rid(10), Pattern: pat(t, "!#US"), Action: ActBlock},
			{ID: rid(11), Pattern: pat(t, "ip.example.org"), Action: ActRedirect, Target: &TargetSpec{Kind: TargetIP, V4: netip.MustParseAddr("203.0.113.9"), V6: netip.MustParseAddr("2001:db8::9")}},
		},
		Services: []ServiceSpec{
			{Wire: 20, Action: ActBlock},
			{Wire: 10, Action: ActBypass, DoNotLog: true},
		},
		Filters: []FilterSpec{{FilterID: 1002, ModeWire: 1}, {FilterID: 1, ModeWire: 12}},
	}
}

func TestBuildOpenRoundTrip(t *testing.T) {
	data, err := Build(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	h := p.Header()
	if h.RuleCount != 11 || h.WildCount != 3 || !h.HasDestGeo() || !h.Explicit() || h.MaxLabels != 3 {
		t.Fatalf("header %+v", h)
	}
	if p.ServiceCount() != 2 || p.FilterCount() != 2 || p.GeoCount() != 5 {
		t.Fatalf("counts %d %d %d", p.ServiceCount(), p.FilterCount(), p.GeoCount())
	}
	if id, mode := p.Filter(0); id != 1 || mode != 12 {
		t.Fatalf("filters must be sorted by id: %d %d", id, mode)
	}
	if s, ok := p.Service(20); !ok || s.Action != ActBlock {
		t.Fatalf("service 20 %+v", s)
	}
	if _, ok := p.Service(15); ok {
		t.Fatal("service 15 should be absent")
	}
	if a, tg := p.Default(); a != ActRedirect || tg == NoTarget {
		t.Fatalf("default %v %v", a, tg)
	} else if set := p.LocSet(p.Target(tg).SetOff); len(set) != 3 || set[0] != 3 || set[2] != 9 {
		t.Fatalf("auto set must be sorted: %v", set)
	}
	// Geo order: dest_as, then dest_cc positive before negated, then src_cc.
	var order []string
	for i := 0; i < p.GeoCount(); i++ {
		g := p.Geo(i)
		r := p.Rule(int(g.Rule))
		order = append(order, rules.Kind(r.Kind).String())
		_ = g
	}
	want := []string{"dest_as", "dest_cc", "dest_cc", "src_cc", "src_cc"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("geo order %v", order)
		}
	}
	// Wildcard bucket for example.com: both "*.example.com"... literal bytes descending.
	first, count, ok := p.WildBucket(names.Hash64(names.ProfileKey(), []byte("\x07example\x03com\x00")))
	if !ok || count != 3 {
		t.Fatalf("bucket %d %d %v", first, count, ok)
	}
	prev := 1 << 30
	for i := 0; i < count; i++ {
		w := p.Wild(first + i)
		if int(w.LitBytes) > prev {
			t.Fatal("bucket not in descending literal bytes")
		}
		prev = int(w.LitBytes)
	}
	// The opened options decode back.
	e := p.Options().Effective()
	if !e.Exfiltration || !e.Rebind || e.BlockResponse != BlockCustom || e.BlockTTL != 30 || e.RedirectTTL != 60 || !e.HasBypassTTL || e.BypassTTL != 120 {
		t.Fatalf("effective %+v", e)
	}
}

func TestDeterministicAndOrderIndependent(t *testing.T) {
	a, err := Build(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	s := sample(t)
	for i, j := 0, len(s.Rules)-1; i < j; i, j = i+1, j-1 {
		s.Rules[i], s.Rules[j] = s.Rules[j], s.Rules[i]
	}
	s.Services[0], s.Services[1] = s.Services[1], s.Services[0]
	b, err := Build(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same profile built in a different input order gave different bytes")
	}
	c, _ := Build(sample(t))
	if !bytes.Equal(a, c) {
		t.Fatal("two builds differ")
	}
}

func TestEmptyProfile(t *testing.T) {
	data, err := Build(&Spec{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	if p.Header().Explicit() || p.RuleCount() != 0 {
		t.Fatal("empty profile claims content")
	}
	if a, _ := p.Default(); a != ActNone {
		t.Fatal("default must be null")
	}
}

func TestBuildRejects(t *testing.T) {
	s := sample(t)
	s.Rules = append(s.Rules, RuleSpec{ID: rid(99), Pattern: pat(t, "EXAMPLE.com"), Action: ActBlock})
	if _, err := Build(s); err == nil {
		t.Error("duplicate rule_key accepted")
	}
	s = sample(t)
	s.Rules[0].Target = &TargetSpec{Kind: TargetLocation, Location: 1}
	if _, err := Build(s); err == nil {
		t.Error("target on a Block rule accepted")
	}
	s = sample(t)
	s.Rules[2].Target = nil
	if _, err := Build(s); err == nil {
		t.Error("Redirect without a target accepted")
	}
}

func put32(b []byte, off int, v uint32) { le.PutUint32(b[off:], v) }

// secOff returns the file offset of section id's data.
func secOff(t *testing.T, data []byte, id int) int {
	t.Helper()
	n := int(le.Uint32(data[12:]))
	for i := 0; i < n; i++ {
		o := HeaderLen + 16*i
		if int(le.Uint32(data[o:])) == id {
			return int(le.Uint32(data[o+8:]))
		}
	}
	t.Fatalf("no section %d", id)
	return 0
}

// TestCorruptionPerReason has one corrupt blob for every reason code (the
// panic code is exercised separately by FuzzOpen and TestPanicGuard).
func TestCorruptionPerReason(t *testing.T) {
	good, err := Build(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	mut := func(f func(b []byte) []byte) []byte {
		return f(append([]byte(nil), good...))
	}
	cases := []struct {
		name string
		data []byte
		want reason.Code
	}{
		{"bad magic", mut(func(b []byte) []byte { b[0] = 'X'; return b }), reason.BadMagic},
		{"higher major", mut(func(b []byte) []byte { b[4] = 2; return b }), reason.UnsupportedMajor},
		{"total_len wrong", mut(func(b []byte) []byte { b[16]++; return b }), reason.LengthMismatch},
		{"trailing byte", mut(func(b []byte) []byte { b = append(b, 0); b[16]++; return b }), reason.LengthMismatch},
		{"too short", good[:20], reason.LengthMismatch},
		{"header reserved", mut(func(b []byte) []byte { b[36] = 1; return b }), reason.BadDirectory},
		{"section count 0", mut(func(b []byte) []byte { b[12] = 0; return b }), reason.BadDirectory},
		{"unaligned section", mut(func(b []byte) []byte { b[HeaderLen+8]++; return b }), reason.BadDirectory},
		{"ids not ascending", mut(func(b []byte) []byte { b[HeaderLen+16] = 1; return b }), reason.BadDirectory},
		{"section past end", mut(func(b []byte) []byte { put32(b, HeaderLen+12, 0x7fffff00); return b }), reason.BadDirectory},
		{"missing section", mut(func(b []byte) []byte { b[HeaderLen+16*11] = 99; return b }), reason.UnsupportedSection},
		{"unknown flags", mut(func(b []byte) []byte { b[33] |= 0x80; return b }), reason.BadEnum},
		{"opts bad block_response", mut(func(b []byte) []byte { b[secOff(t, b, SecOPTS)+5] = 9; return b }), reason.BadEnum},
		{"filter record size", mut(func(b []byte) []byte {
			// FLTS is the last section. Shorten it and the file by one byte so
			// only the record-size rule (multiple of 4) can object.
			o := HeaderLen + 16*(SecFLTS-1) + 12
			put32(b, o, le.Uint32(b[o:])-1)
			b = b[:len(b)-1]
			le.PutUint64(b[16:], uint64(len(b)))
			return b
		}), reason.BadSection},
		{"rule target range", mut(func(b []byte) []byte {
			o := secOff(t, b, SecRULE)
			for i := 0; i < 11; i++ {
				if b[o+i*40+31] == byte(ActRedirect) {
					put32(b, o+i*40+36, 9999)
					return b
				}
			}
			t.Fatal("no redirect rule")
			return b
		}), reason.IndexRange},
		{"rule name range", mut(func(b []byte) []byte { put32(b, secOff(t, b, SecRULE)+24, 0xffff0000); return b }), reason.IndexRange},
		{"rule action enum", mut(func(b []byte) []byte { b[secOff(t, b, SecRULE)+31] = 7; return b }), reason.BadEnum},
		{"rule name not wire", mut(func(b []byte) []byte { b[secOff(t, b, SecSTRS)] = 0xff; return b }), reason.BadName},
		{"plix unsorted", mut(func(b []byte) []byte {
			o := secOff(t, b, SecPLIX)
			x := append([]byte(nil), b[o:o+16]...)
			copy(b[o:o+16], b[o+16:o+32])
			copy(b[o+16:o+32], x)
			return b
		}), reason.Unsorted},
		{"plix hash", mut(func(b []byte) []byte { b[secOff(t, b, SecPLIX)+1] ^= 1; return b }), reason.HashMismatch},
		{"wbkt hash", mut(func(b []byte) []byte { b[secOff(t, b, SecWBKT)+1] ^= 1; return b }), reason.HashMismatch},
		{"wbkt too big", mut(func(b []byte) []byte { put32(b, secOff(t, b, SecWBKT)+12, 65); return b }), reason.BadEnum},
		{"geor unsorted", mut(func(b []byte) []byte {
			o := secOff(t, b, SecGEOR)
			x := append([]byte(nil), b[o:o+16]...)
			copy(b[o:o+16], b[o+16:o+32])
			copy(b[o+16:o+32], x)
			return b
		}), reason.Unsorted},
		{"svcs unsorted", mut(func(b []byte) []byte {
			o := secOff(t, b, SecSVCS)
			x := append([]byte(nil), b[o:o+16]...)
			copy(b[o:o+16], b[o+16:o+32])
			copy(b[o+16:o+32], x)
			return b
		}), reason.Unsorted},
		{"flts unsorted", mut(func(b []byte) []byte {
			o := secOff(t, b, SecFLTS)
			x := append([]byte(nil), b[o:o+4]...)
			copy(b[o:o+4], b[o+4:o+8])
			copy(b[o+4:o+8], x)
			return b
		}), reason.Unsorted},
		{"lset unsorted", mut(func(b []byte) []byte {
			o := secOff(t, b, SecLSET)
			// First set in the pool (sorted by encoding) holds ids; swap two to break order.
			n := int(le.Uint16(b[o:]))
			if n < 2 {
				o += 2 + 2*n
				n = int(le.Uint16(b[o:]))
			}
			b[o+2], b[o+4] = b[o+4], b[o+2]
			b[o+3], b[o+5] = b[o+5], b[o+3]
			return b
		}), reason.Unsorted},
		{"target set_off", mut(func(b []byte) []byte {
			o := secOff(t, b, SecTARG)
			for i := 0; i < 8; i++ {
				if k := b[o+i*40]; k == byte(TargetAuto) || k == byte(TargetRandom) {
					put32(b, o+i*40+4, 3)
					return b
				}
			}
			t.Fatal("no set target")
			return b
		}), reason.IndexRange},
		{"target kind", mut(func(b []byte) []byte { b[secOff(t, b, SecTARG)] = 9; return b }), reason.BadEnum},
		{"pad not zero", mut(func(b []byte) []byte { b[secOff(t, b, SecRULE)+34] = 1; return b }), reason.BadSection},
		{"header flag lies", mut(func(b []byte) []byte { b[33] &^= FlagHasDestGeo; return b }), reason.BadSection},
		{"gap padding not zero", mut(func(b []byte) []byte {
			// OPTS ends at a multiple of 8 here; use the gap after a section that does not.
			for id := 1; id < numSecs; id++ {
				o := HeaderLen + 16*(id-1)
				end := int(le.Uint32(b[o+8:])) + int(le.Uint32(b[o+12:]))
				if end%8 != 0 {
					b[end] = 1
					return b
				}
			}
			t.Fatal("no unaligned section end")
			return b
		}), reason.BadDirectory},
		{"too big", make([]byte, MaxSize+1), reason.SizeCap},
	}
	covered := map[reason.Code]bool{}
	for _, c := range cases {
		_, err := Open(c.data)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if got := reason.CodeOf(err); got != c.want {
			t.Errorf("%s: got %q (%v) want %q", c.name, got, err, c.want)
		}
		covered[c.want] = true
	}
	for _, c := range reason.All() {
		if c == reason.Panic || c == reason.HashMismatch && covered[c] || covered[c] {
			continue
		}
		switch c {
		case reason.MissingSection, reason.Panic:
			// MissingSection needs a directory with a hole; covered below.
		default:
			t.Errorf("reason %q has no corrupt case", c)
		}
	}
}

func TestMissingSection(t *testing.T) {
	good, _ := Build(sample(t))
	// Drop the last directory entry by lowering section_count; its bytes then
	// become trailing data, so rebuild the length to isolate the missing check.
	b := append([]byte(nil), good...)
	n := int(le.Uint32(b[12:]))
	last := HeaderLen + 16*(n-1)
	// Turn FLTS (id 12) into an unknown optional id 40: now FLTS is missing.
	le.PutUint32(b[last:], 40)
	le.PutUint32(b[last+4:], 0)
	_, err := Open(b)
	if reason.CodeOf(err) != reason.MissingSection {
		t.Fatalf("got %v", err)
	}
}

func TestHigherMinorWithOptionalSectionIsSkipped(t *testing.T) {
	good, _ := Build(sample(t))
	// Append an optional unknown section id 40 with 8 bytes, minor 1.
	n := int(le.Uint32(good[12:]))
	dirEnd := HeaderLen + 16*n
	// Rebuild: header + (dir + 16 bytes) + sections shifted by 16.
	out := append([]byte(nil), good[:dirEnd]...)
	entry := make([]byte, 16)
	out = append(out, entry...)
	out = append(out, good[dirEnd:]...)
	for i := 0; i < n; i++ {
		o := HeaderLen + 16*i
		le.PutUint32(out[o+8:], le.Uint32(out[o+8:])+16)
	}
	le.PutUint32(out[HeaderLen+16*n:], 40)
	le.PutUint32(out[HeaderLen+16*n+4:], 0) // optional
	le.PutUint32(out[HeaderLen+16*n+8:], uint32(len(out)+(8-len(out)%8)%8))
	le.PutUint32(out[HeaderLen+16*n+12:], 8)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	out = append(out, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22)
	le.PutUint32(out[12:], uint32(n+1))
	le.PutUint64(out[16:], uint64(len(out)))
	le.PutUint16(out[6:], 1) // minor 1
	// The unknown id 40 sorts after 12, so the directory stays ascending.
	p, err := Open(out)
	if err != nil {
		t.Fatalf("higher minor with an optional section: %v", err)
	}
	if p.RuleCount() != 11 {
		t.Fatal("content lost")
	}
	// The same section marked required must be refused.
	le.PutUint32(out[HeaderLen+16*n+4:], 1)
	if _, err := Open(out); reason.CodeOf(err) != reason.UnsupportedSection {
		t.Fatalf("required unknown section: %v", err)
	}
}

// TestTruncationEverywhere cuts the file at every section boundary and at
// every byte of the first kilobyte: each must fail cleanly, never panic.
func TestTruncationEverywhere(t *testing.T) {
	good, _ := Build(sample(t))
	cuts := map[int]bool{}
	for i := 0; i < len(good) && i < 1024; i++ {
		cuts[i] = true
	}
	n := int(le.Uint32(good[12:]))
	for i := 0; i < n; i++ {
		o := HeaderLen + 16*i
		cuts[int(le.Uint32(good[o+8:]))] = true
		cuts[int(le.Uint32(good[o+8:]))+int(le.Uint32(good[o+12:]))-1] = true
	}
	cuts[len(good)-1] = true
	for c := range cuts {
		if c >= len(good) {
			continue
		}
		if _, err := Open(good[:c]); err == nil {
			t.Errorf("truncation to %d bytes accepted", c)
		} else if reason.CodeOf(err) == reason.Panic {
			t.Errorf("truncation to %d bytes panicked", c)
		}
	}
}

func TestWildMatches(t *testing.T) {
	n := names.MustString
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "x.y.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.example.org", false},
		{"server-*.example.com", "server-01.example.com", true},
		{"server-*.example.com", "server-.example.com", true},
		{"server-*.example.com", "server.example.com", false},
		{"server-*.example.com", "a.server-1.example.com", false},
		{"a.*.example.com", "a.b.example.com", true},
		{"a.*.example.com", "a.b.c.example.com", false},
		{"a.*.example.com", "x.b.example.com", false},
		{"*-x.example.com", "a-x.example.com", true},
		{"*-x.example.com", "-x.example.com", true},
	}
	for _, c := range cases {
		p := pat(t, c.pattern)
		name := n(c.name)
		if got := WildMatches(p.Kind, p.Wire, &name); got != c.want {
			t.Errorf("%s vs %s: got %v", c.pattern, c.name, got)
		}
	}
}

func FuzzOpen(f *testing.F) {
	good, err := Build(sample(f))
	if err != nil {
		f.Fatal(err)
	}
	empty, _ := Build(&Spec{})
	f.Add(good)
	f.Add(empty)
	f.Add(good[:48])
	f.Add([]byte("CZPB"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Open(data)
		if err != nil {
			if reason.CodeOf(err) == reason.Panic {
				t.Fatalf("decoder panicked: %v", err)
			}
			return
		}
		// Whatever Open accepted must be fully readable without panicking.
		for i := 0; i < p.RuleCount(); i++ {
			r := p.Rule(i)
			if r.Kind.IsName() {
				_ = p.RuleName(&r)
				if r.Kind.IsWildcard() {
					_ = p.LiteralSuffixOf(&r)
				}
			}
			if r.Target != NoTarget {
				tg := p.Target(r.Target)
				if tg.Kind == TargetAuto || tg.Kind == TargetRandom {
					_ = p.LocSet(tg.SetOff)
				}
				if tg.Kind == TargetHost {
					_ = p.Str(tg.HostOff, tg.HostLen)
				}
			}
		}
		for i := 0; i < p.GeoCount(); i++ {
			_ = p.Geo(i)
		}
		for i := 0; i < p.FilterCount(); i++ {
			_, _ = p.Filter(i)
		}
		_ = p.Options().Effective()
		// A blob that opens is its own canonical form only when rebuilt from its
		// content, but its hash must be stable.
		if p.Hash() != contentHash(data) {
			t.Fatal("hash")
		}
	})
}

func FuzzParseOptions(f *testing.F) {
	o := Options{Present: OptRebind | OptECS, Bools: uint8(OptRebind), ECSMode: ECSAuto, ECSV4Prefix: 24}
	m := o.Marshal()
	f.Add(m[:])
	f.Add(make([]byte, OptsSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := ParseOptions(b)
		if err != nil {
			return
		}
		// Accepted options must re-encode to the identical bytes (one encoding per logical value).
		m := o.Marshal()
		if !bytes.Equal(m[:], b) {
			t.Fatalf("not canonical: %x vs %x", m, b)
		}
		_ = o.Effective()
	})
}

// TestWriteCorpus refreshes testdata/fuzz seed files. It is off by default so
// a normal test run never writes into the source tree.
func TestWriteCorpus(t *testing.T) {
	if os.Getenv("CTRLZ_WRITE_CORPUS") == "" {
		t.Skip("set CTRLZ_WRITE_CORPUS=1 to regenerate seed corpus")
	}
	good, _ := Build(sample(t))
	empty, _ := Build(&Spec{})
	dir := filepath.Join("testdata", "fuzz", "FuzzOpen")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"valid-full": good, "valid-empty": empty, "truncated-header": good[:48], "truncated-mid": good[:len(good)/2]} {
		body := "go test fuzz v1\n[]byte(" + strconv.Quote(string(data)) + ")\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// plainRules returns the indices of the plain domain rules of a blob.
func plainRules(t *testing.T, data []byte) []int {
	t.Helper()
	p, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	var out []int
	for i := 0; i < p.RuleCount(); i++ {
		if p.Rule(i).Kind == rules.KindDomain {
			out = append(out, i)
		}
	}
	return out
}

// rewritePLIX replaces the plain index with the given (hash, rule) pairs,
// sorted the way Open requires, keeping the section length.
func rewritePLIX(t *testing.T, b []byte, entries [][2]uint64) {
	t.Helper()
	o := secOff(t, b, SecPLIX)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i][0] != entries[j][0] {
			return entries[i][0] < entries[j][0]
		}
		return entries[i][1] < entries[j][1]
	})
	for i, e := range entries {
		le.PutUint64(b[o+i*sizePLIX:], e[0])
		le.PutUint32(b[o+i*sizePLIX+8:], uint32(e[1]))
	}
}

// TestOpenRejectsRepeatedPlainNames (review L2-F17): Build refuses two rules
// with one name, but a hostile or buggy compiler can write them, and every
// query on that name would walk all of them. 800,000 expired rules on one name
// cost 30 ms a query.
func TestOpenRejectsRepeatedPlainNames(t *testing.T) {
	good, err := Build(sample(t))
	if err != nil {
		t.Fatal(err)
	}
	plain := plainRules(t, good)
	if len(plain) < 3 {
		t.Fatalf("the sample has %d plain rules", len(plain))
	}
	key := names.ProfileKey()
	b := append([]byte(nil), good...)
	p, _ := Open(good)
	a, c := p.Rule(plain[0]), p.Rule(plain[1])
	ruleOff := secOff(t, b, SecRULE)
	// Rule c now carries the name of rule a.
	put32(b, ruleOff+plain[1]*sizeRULE+24, a.NameOff)
	le.PutUint16(b[ruleOff+plain[1]*sizeRULE+28:], a.NameLen)
	h := names.Hash64(key, p.RuleName(&a))
	var entries [][2]uint64
	for _, i := range plain {
		eh := names.Hash64(key, p.RuleName(ptr(p.Rule(i))))
		if i == plain[1] {
			eh = h
		}
		entries = append(entries, [2]uint64{eh, uint64(i)})
	}
	rewritePLIX(t, b, entries)
	_ = c
	_, err = Open(b)
	if err == nil {
		t.Fatal("a blob with two rules of one name was opened")
	}
	if got := reason.CodeOf(err); got != reason.BadSection {
		t.Errorf("reason %v (%v), want bad_section", got, err)
	}
}

func ptr[T any](v T) *T { return &v }

// TestOpenRejectsALongHashRun: more plain rules on one hash than any compiled
// profile has is refused, whatever their names. The profile key is public, so a
// hostile compiler can pick names that collide.
func TestOpenRejectsALongHashRun(t *testing.T) {
	spec := &Spec{Default: ActBypass}
	for i := 0; i < MaxPlainRun+2; i++ {
		spec.Rules = append(spec.Rules, RuleSpec{ID: rid(byte(i + 1)), Pattern: pat(t, "host"+strconv.Itoa(i)+".example.com"), Action: ActBlock})
	}
	good, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	b := append([]byte(nil), good...)
	plain := plainRules(t, good)
	var entries [][2]uint64
	for _, i := range plain {
		entries = append(entries, [2]uint64{42, uint64(i)}) // one hash for all; the run cap is checked before the hash itself
	}
	rewritePLIX(t, b, entries)
	_, err = Open(b)
	if err == nil {
		t.Fatal("a run of colliding hashes was opened")
	}
	if got := reason.CodeOf(err); got != reason.SizeCap {
		t.Errorf("reason %v (%v), want size_cap", got, err)
	}
	if len(plain) <= MaxPlainRun {
		t.Fatal("test needs more rules than the run cap")
	}
}
