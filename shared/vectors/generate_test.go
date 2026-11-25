package vectors

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/gtable"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

// The blob and gtable groups carry raw bytes, which nobody can review by eye.
// This generator builds them from named, commented mutations of known-good
// files, so a reviewer reads the mutation list here and the JSON is output.
// It is off by default: CTRLZ_WRITE_VECTORS=1 go test ./vectors -run TestGenerate

func mustPattern(t *testing.T, s string) rules.Pattern {
	t.Helper()
	p, err := rules.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleBlob(t *testing.T) []byte {
	t.Helper()
	host := names.MustString("safe.example.net")
	spec := &blob.Spec{
		Options: blob.Options{Present: blob.OptRebind | blob.OptBlockTTL | blob.OptBlockResponse, Bools: uint8(blob.OptRebind), BlockTTL: 30, BlockResponse: blob.BlockCustom, BlockV4: [4]byte{192, 0, 2, 1}},
		Default: blob.ActRedirect, DefaultTarget: &blob.TargetSpec{Kind: blob.TargetAuto, Set: []uint16{3, 5, 9}},
		Rules: []blob.RuleSpec{
			{ID: [16]byte{1}, Pattern: mustPattern(t, "ads.example.com"), Action: blob.ActBlock},
			{ID: [16]byte{2}, Pattern: mustPattern(t, "example.com"), Action: blob.ActBypass, ExpiresAt: 2_000_000_000},
			{ID: [16]byte{3}, Pattern: mustPattern(t, "*.example.com"), Action: blob.ActRedirect, Target: &blob.TargetSpec{Kind: blob.TargetLocation, Location: 7}},
			{ID: [16]byte{4}, Pattern: mustPattern(t, "server-*.example.com"), Action: blob.ActBlock, DoNotLog: true},
			{ID: [16]byte{5}, Pattern: mustPattern(t, "a.*.example.com"), Action: blob.ActRedirect, Target: &blob.TargetSpec{Kind: blob.TargetHost, Host: host.Wire()}},
			{ID: [16]byte{6}, Pattern: mustPattern(t, "@IR"), Action: blob.ActBlock},
			{ID: [16]byte{7}, Pattern: mustPattern(t, "!@IR"), Action: blob.ActBypass},
			{ID: [16]byte{8}, Pattern: mustPattern(t, "@AS13335"), Action: blob.ActRedirect, Target: &blob.TargetSpec{Kind: blob.TargetRandom, Set: []uint16{1, 2}}},
			{ID: [16]byte{9}, Pattern: mustPattern(t, "#IR"), Action: blob.ActBlock},
			{ID: [16]byte{10}, Pattern: mustPattern(t, "ip.example.org"), Action: blob.ActRedirect, Target: &blob.TargetSpec{Kind: blob.TargetIP, V4: netip.MustParseAddr("203.0.113.9"), V6: netip.MustParseAddr("2001:db8::9")}},
		},
		Services: []blob.ServiceSpec{{Wire: 20, Action: blob.ActBlock}, {Wire: 10, Action: blob.ActBypass}},
		Filters:  []blob.FilterSpec{{FilterID: 1002, ModeWire: 1}, {FilterID: 1, ModeWire: 12}},
	}
	b, err := blob.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type genCase struct {
	ID          string `json:"id"`
	Why         string `json:"why"`
	Hex         string `json:"hex"`
	ExpectError string `json:"expect_error"`
}

func writeGroup(t *testing.T, name string, cases []genCase) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "{\n  \"format\": 1,\n  \"group\": %q,\n  \"cases\": [\n", name)
	for i, c := range cases {
		line, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("    " + string(line))
		if i < len(cases)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("  ]\n}\n")
	if err := os.WriteFile(name+".json", []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func u32(b []byte, off int) int      { return int(binary.LittleEndian.Uint32(b[off:])) }
func put32(b []byte, off int, v int) { binary.LittleEndian.PutUint32(b[off:], uint32(v)) }

func secOffset(b []byte, id int) int {
	n := u32(b, 12)
	for i := 0; i < n; i++ {
		o := blob.HeaderLen + 16*i
		if u32(b, o) == id {
			return u32(b, o+8)
		}
	}
	panic("no section")
}

func TestGenerate(t *testing.T) {
	if os.Getenv("CTRLZ_WRITE_VECTORS") == "" {
		t.Skip("set CTRLZ_WRITE_VECTORS=1 to regenerate blob.json and gtable.json")
	}
	good := sampleBlob(t)
	empty, _ := blob.Build(&blob.Spec{})
	cp := func() []byte { return append([]byte(nil), good...) }
	var cs []genCase
	add := func(id, why string, b []byte, want reason.Code) {
		cs = append(cs, genCase{ID: id, Why: why, Hex: hex.EncodeToString(b), ExpectError: string(want)})
	}

	add("blob-valid-full", "A profile using every section and every target kind", good, "")
	add("blob-valid-empty", "A profile with no rules, services or filters", empty, "")
	// Same bytes built twice must be identical: deterministic output.
	again := sampleBlob(t)
	if string(again) != string(good) {
		t.Fatal("builder is not deterministic")
	}

	b := cp()
	b[0] = 'X'
	add("blob-bad-magic", "First four bytes are not CZPB", b, reason.BadMagic)
	b = cp()
	b[4] = 2
	add("blob-higher-major", "Major version 2 is breaking: refuse", b, reason.UnsupportedMajor)
	b = cp()
	b[16]++
	add("blob-total-len", "total_len disagrees with the data length", b, reason.LengthMismatch)
	b = cp()
	b[36] = 1
	add("blob-header-reserved", "Reserved header byte set", b, reason.BadDirectory)
	b = cp()
	b[blob.HeaderLen+8]++
	add("blob-unaligned", "A section offset that is not a multiple of 8", b, reason.BadDirectory)
	b = cp()
	b[blob.HeaderLen+16] = 1
	add("blob-ids-not-ascending", "Directory ids out of order", b, reason.BadDirectory)
	b = cp()
	put32(b, blob.HeaderLen+12, 0x7fffff00)
	add("blob-section-past-end", "A section length that runs beyond the file", b, reason.BadDirectory)
	b = cp()
	b[33] |= 0x80
	add("blob-unknown-flags", "Unknown header flag bit", b, reason.BadEnum)
	b = cp()
	last := blob.HeaderLen + 16*(u32(b, 12)-1)
	put32(b, last, 99) // required flag stays set
	add("blob-unknown-required-section", "A section id this reader does not know, marked required", b, reason.UnsupportedSection)
	b = cp()
	put32(b, last, 40)
	put32(b, last+4, 0)
	add("blob-missing-section", "FLTS replaced by an optional unknown section: a required section is absent", b, reason.MissingSection)
	b = cp()
	b[secOffset(b, blob.SecOPTS)+5] = 9
	add("blob-bad-block-response", "OPTS block_response is not a known value", b, reason.BadEnum)
	b = cp()
	ro := secOffset(b, blob.SecRULE)
	for i := 0; i < 10; i++ {
		if b[ro+i*40+31] == byte(blob.ActRedirect) {
			put32(b, ro+i*40+36, 9999)
			break
		}
	}
	add("blob-target-range", "A redirect rule pointing at a target that does not exist", b, reason.IndexRange)
	b = cp()
	put32(b, ro+24, 0xffff0000)
	add("blob-name-range", "A rule name offset outside the string pool", b, reason.IndexRange)
	b = cp()
	b[secOffset(b, blob.SecSTRS)] = 0xff
	add("blob-name-not-wire", "A rule name that is not a valid wire name", b, reason.BadName)
	b = cp()
	po := secOffset(b, blob.SecPLIX)
	x := append([]byte(nil), b[po:po+16]...)
	copy(b[po:po+16], b[po+16:po+32])
	copy(b[po+16:po+32], x)
	add("blob-plix-unsorted", "Two plain-rule index entries swapped", b, reason.Unsorted)
	b = cp()
	b[po+1] ^= 1
	add("blob-plix-hash", "A plain-rule index hash that does not match its name", b, reason.HashMismatch)
	b = cp()
	b[ro+34] = 1
	add("blob-pad-not-zero", "A pad byte inside a RULE record", b, reason.BadSection)
	b = cp()
	b[33] &^= blob.FlagHasDestGeo
	add("blob-flag-lies", "has_dest_geo cleared although destination-geo rules exist", b, reason.BadSection)
	b = cp()
	put32(b, secOffset(b, blob.SecWBKT)+12, 65)
	add("blob-bucket-too-big", "A wildcard bucket over the 64-entry limit", b, reason.BadEnum)

	// Higher minor with an optional unknown section is valid.
	n := u32(good, 12)
	dirEnd := blob.HeaderLen + 16*n
	hm := append([]byte(nil), good[:dirEnd]...)
	hm = append(hm, make([]byte, 16)...)
	hm = append(hm, good[dirEnd:]...)
	for i := 0; i < n; i++ {
		o := blob.HeaderLen + 16*i
		put32(hm, o+8, u32(hm, o+8)+16)
	}
	for len(hm)%8 != 0 {
		hm = append(hm, 0)
	}
	e := blob.HeaderLen + 16*n
	put32(hm, e, 40)
	put32(hm, e+4, 0)
	put32(hm, e+8, len(hm))
	put32(hm, e+12, 8)
	hm = append(hm, 1, 2, 3, 4, 5, 6, 7, 8)
	put32(hm, 12, n+1)
	binary.LittleEndian.PutUint64(hm[16:], uint64(len(hm)))
	binary.LittleEndian.PutUint16(hm[6:], 1)
	add("blob-higher-minor-optional", "Minor 1 with an optional unknown section is read and the section skipped", hm, "")
	hr := append([]byte(nil), hm...)
	put32(hr, e+4, 1)
	add("blob-higher-minor-required", "The same section marked required cannot be understood", hr, reason.UnsupportedSection)

	// Truncation at every section boundary.
	for i := 0; i < n; i++ {
		o := blob.HeaderLen + 16*i
		start := u32(good, o+8)
		add(fmt.Sprintf("blob-truncated-at-section-%d", u32(good, o)), "File cut where this section begins", good[:start], reason.LengthMismatch)
	}
	add("blob-truncated-last-byte", "File missing its last byte", good[:len(good)-1], reason.LengthMismatch)
	add("blob-truncated-header", "File shorter than the 48-byte header", good[:20], reason.LengthMismatch)
	writeGroup(t, "blob", cs)

	// gtable.
	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	w := func(s string) []byte { x := names.MustString(s); return append([]byte(nil), x.Wire()...) }
	mk := func(k gtable.Kind) []byte {
		var es []gtable.Entry
		for i := 0; i < 40; i++ {
			es = append(es, gtable.Entry{Name: w(fmt.Sprintf("h%d.example.com", i)), Exact: i%4 == 0, Wire: uint32(i), Mask: 1 << (i % 20), SvcCat: uint8(101 + i%12)})
		}
		d, err := (&gtable.Builder{Kind: k, CatalogVersion: 3, Key: key, Entries: es}).Build()
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	var gs []genCase
	gadd := func(id, why string, d []byte, want reason.Code) {
		gs = append(gs, genCase{ID: id, Why: why, Hex: hex.EncodeToString(d), ExpectError: string(want)})
	}
	gf, gsv, gc := mk(gtable.KindFilter), mk(gtable.KindService), mk(gtable.KindCategory)
	gadd("gt-valid-filter", "A filter table mixing suffix and exact entries", gf, "")
	gadd("gt-valid-service", "A service table", gsv, "")
	gadd("gt-valid-category", "A category table", gc, "")
	emptyT, _ := (&gtable.Builder{Kind: gtable.KindFilter, Key: key}).Build()
	gadd("gt-valid-empty", "A table with no entries", emptyT, "")
	g := func(base []byte) []byte { return append([]byte(nil), base...) }
	bits := int(gsv[10])
	body := (gtable.HeaderLen + 4*((1<<bits)+1) + 7) &^ 7
	d := g(gsv)
	d[0] = 'X'
	gadd("gt-bad-magic", "Not CZGT", d, reason.BadMagic)
	d = g(gsv)
	d[4] = 2
	gadd("gt-higher-major", "Major 2", d, reason.UnsupportedMajor)
	d = g(gsv)
	d[8] = 9
	gadd("gt-bad-kind", "Unknown table kind", d, reason.BadEnum)
	d = g(gsv)
	d[10] = 25
	gadd("gt-bucket-bits", "bucket_bits above 24", d, reason.BadEnum)
	d = g(gsv)
	d[60] = 1
	gadd("gt-reserved", "Reserved header byte set", d, reason.BadDirectory)
	d = g(gsv)
	d[16]++
	gadd("gt-total-len", "total_len wrong", d, reason.LengthMismatch)
	d = g(gsv)
	d[12]++
	gadd("gt-entry-count", "entry_count does not fit the data", d, reason.LengthMismatch)
	d = g(gsv)
	put32(d, gtable.HeaderLen+4, 39)
	gadd("gt-offsets-not-monotone", "A bucket offset above the next one", d, reason.IndexRange)
	d = g(gsv)
	put32(d, gtable.HeaderLen+4*(1<<bits), 3)
	gadd("gt-last-offset", "Last offset is not entry_count", d, reason.IndexRange)
	d = g(gsv)
	d[body+7] ^= 0x80
	gadd("gt-key-outside-bucket", "An entry whose key hashes to a different bucket", d, reason.IndexRange)
	d = g(gsv)
	d[body+12] = 1
	gadd("gt-pad-not-zero", "Pad byte set in a service entry", d, reason.BadSection)
	d = g(gsv)
	copy(d[body+16:body+32], d[body:body+16])
	gadd("gt-duplicate-entry", "Two identical service entries", d, reason.Unsorted)
	d = g(gc)
	cb := (gtable.HeaderLen + 4*((1<<int(gc[10]))+1) + 7) &^ 7
	d[cb+12] = 7
	gadd("gt-bad-service-category", "A service category outside 101 to 112", d, reason.BadEnum)
	for _, cut := range []int{0, 10, gtable.HeaderLen - 1, gtable.HeaderLen, body, len(gsv) - 1} {
		gadd(fmt.Sprintf("gt-truncated-%d", cut), "File cut at this byte", gsv[:cut], reason.LengthMismatch)
	}
	writeGroup(t, "gtable", gs)
}
