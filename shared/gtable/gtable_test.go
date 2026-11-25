package gtable

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
)

var testKey = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func w(s string) []byte {
	n := names.MustString(s)
	return append([]byte(nil), n.Wire()...)
}

func key(s string, exact bool) uint64 {
	h := names.Hash64(testKey, w(s))
	if exact {
		return names.ExactKey(h)
	}
	return names.SuffixKey(h)
}

func TestFilterSuffixAgainstExact(t *testing.T) {
	b := &Builder{Kind: KindFilter, CatalogVersion: 7, Key: testKey, Entries: []Entry{
		{Name: w("ads.example.com")},                  // domain: ads.example.com
		{Name: w("tracker.example.net"), Exact: true}, // full: tracker.example.net
	}}
	data, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	tb, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	if tb.Count() != 2 || tb.MaxLabels() != 3 || tb.CatalogVersion() != 7 || tb.Key() != testKey {
		t.Fatalf("header: %d %d", tb.Count(), tb.MaxLabels())
	}
	if !tb.Contains(key("ads.example.com", false)) {
		t.Error("suffix entry not found at its own name")
	}
	if tb.Contains(key("ads.example.com", true)) {
		t.Error("suffix entry answered an exact probe")
	}
	if !tb.Contains(key("tracker.example.net", true)) {
		t.Error("exact entry not found")
	}
	if tb.Contains(key("tracker.example.net", false)) {
		t.Error("exact entry answered a suffix probe (it must not match subdomains)")
	}
	if tb.Contains(key("example.com", false)) {
		t.Error("parent matched")
	}
}

func TestServiceMultipleWiresSameKey(t *testing.T) {
	b := &Builder{Kind: KindService, Key: testKey, Entries: []Entry{
		{Name: w("cdn.example.com"), Wire: 30},
		{Name: w("cdn.example.com"), Wire: 10},
		{Name: w("cdn.example.com"), Wire: 10}, // duplicate is dropped
		{Name: w("other.example.org"), Wire: 5},
	}}
	data, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	tb, err := Open(data)
	if err != nil {
		t.Fatal(err)
	}
	var got []uint32
	tb.Services(key("cdn.example.com", false), func(wire uint32) bool { got = append(got, wire); return true })
	if len(got) != 2 || got[0] != 10 || got[1] != 30 {
		t.Fatalf("wires %v", got)
	}
}

func TestCategoryMerge(t *testing.T) {
	b := &Builder{Kind: KindCategory, Key: testKey, Entries: []Entry{
		{Name: w("x.example.com"), Mask: 1 << 3},
		{Name: w("x.example.com"), Mask: 1 << 0, SvcCat: 105},
		{Name: w("x.example.com"), SvcCat: 102},
	}}
	data, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := Open(data)
	mask, svc, ok := tb.Category(key("x.example.com", false))
	if !ok || mask != 1<<3|1 || svc != 102 {
		t.Fatalf("%b %d %v", mask, svc, ok)
	}
	if _, _, ok := tb.Category(key("y.example.com", false)); ok {
		t.Fatal("absent key found")
	}
}

func TestEmptyAndLarge(t *testing.T) {
	for _, n := range []int{0, 1, 5, 1000, 20000} {
		b := &Builder{Kind: KindFilter, Key: testKey}
		for i := 0; i < n; i++ {
			b.Entries = append(b.Entries, Entry{Name: w("h" + strconv.Itoa(i) + ".example.com")})
		}
		data, err := b.Build()
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		tb, err := Open(data)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if tb.Count() != n {
			t.Fatalf("n=%d: count %d", n, tb.Count())
		}
		for i := 0; i < n; i += 97 {
			if !tb.Contains(key("h"+strconv.Itoa(i)+".example.com", false)) {
				t.Fatalf("n=%d: missing %d", n, i)
			}
		}
	}
}

func TestDeterministic(t *testing.T) {
	mk := func(seed int64) []byte {
		r := rand.New(rand.NewSource(seed))
		var es []Entry
		for i := 0; i < 200; i++ {
			es = append(es, Entry{Name: w("n" + strconv.Itoa(i) + ".example.com"), Exact: i%3 == 0})
		}
		r.Shuffle(len(es), func(i, j int) { es[i], es[j] = es[j], es[i] })
		d, err := (&Builder{Kind: KindFilter, Key: testKey, Entries: es}).Build()
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if !bytes.Equal(mk(1), mk(2)) {
		t.Fatal("entry order changed the bytes")
	}
}

func TestCorruption(t *testing.T) {
	var es []Entry
	for i := 0; i < 50; i++ {
		es = append(es, Entry{Name: w("h" + strconv.Itoa(i) + ".example.com"), Wire: uint32(i)})
	}
	good, err := (&Builder{Kind: KindService, Key: testKey, Entries: es}).Build()
	if err != nil {
		t.Fatal(err)
	}
	bits := int(good[10])
	body := (HeaderLen + 4*((1<<bits)+1) + 7) &^ 7
	mut := func(f func(b []byte)) []byte { b := append([]byte(nil), good...); f(b); return b }
	cases := []struct {
		name string
		data []byte
		want reason.Code
	}{
		{"magic", mut(func(b []byte) { b[0] = 'X' }), reason.BadMagic},
		{"major", mut(func(b []byte) { b[4] = 2 }), reason.UnsupportedMajor},
		{"kind", mut(func(b []byte) { b[8] = 9 }), reason.BadEnum},
		{"bucket bits", mut(func(b []byte) { b[10] = 25 }), reason.BadEnum},
		{"reserved", mut(func(b []byte) { b[60] = 1 }), reason.BadDirectory},
		{"total_len", mut(func(b []byte) { b[16]++ }), reason.LengthMismatch},
		{"entry_count", mut(func(b []byte) { b[12]++ }), reason.LengthMismatch},
		{"short", good[:10], reason.LengthMismatch},
		{"offsets not monotone", mut(func(b []byte) { le.PutUint32(b[HeaderLen+4:], 49) }), reason.IndexRange},
		{"last offset", mut(func(b []byte) { le.PutUint32(b[HeaderLen+4*(1<<bits):], 3) }), reason.IndexRange},
		{"key out of bucket", mut(func(b []byte) { b[body+7] ^= 0x80 }), reason.IndexRange},
		{"service pad", mut(func(b []byte) { b[body+12] = 1 }), reason.BadSection},
		{"duplicate wire", mut(func(b []byte) {
			// Make entry 1 identical to entry 0 (same key, same wire).
			copy(b[body+16:body+32], b[body:body+16])
		}), reason.Unsorted},
	}
	for _, c := range cases {
		_, err := Open(c.data)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if got := reason.CodeOf(err); got != c.want {
			t.Errorf("%s: got %q (%v) want %q", c.name, got, err, c.want)
		}
	}
	for cut := 0; cut < len(good); cut += 7 {
		if _, err := Open(good[:cut]); err == nil {
			t.Errorf("truncation to %d accepted", cut)
		}
	}
}

func FuzzOpen(f *testing.F) {
	for _, k := range []Kind{KindFilter, KindService, KindCategory} {
		d, _ := (&Builder{Kind: k, Key: testKey, Entries: []Entry{
			{Name: w("a.example.com"), Wire: 1, Mask: 4, SvcCat: 101},
			{Name: w("b.example.com"), Exact: true, Wire: 2},
		}}).Build()
		f.Add(d)
	}
	f.Add([]byte("CZGT"))
	f.Fuzz(func(t *testing.T, data []byte) {
		tb, err := Open(data)
		if err != nil {
			if reason.CodeOf(err) == reason.Panic {
				t.Fatalf("decoder panicked: %v", err)
			}
			return
		}
		// Probe a few keys: reading an accepted table must not panic.
		for _, k := range []uint64{0, 1, 1 << 63, ^uint64(0), 0xdeadbeef} {
			_ = tb.Contains(k)
			tb.Services(k, func(uint32) bool { return true })
			_, _, _ = tb.Category(k)
		}
	})
}

func TestWriteCorpus(t *testing.T) {
	if os.Getenv("CTRLZ_WRITE_CORPUS") == "" {
		t.Skip("set CTRLZ_WRITE_CORPUS=1 to regenerate seed corpus")
	}
	dir := filepath.Join("testdata", "fuzz", "FuzzOpen")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]Kind{"filter": KindFilter, "service": KindService, "category": KindCategory} {
		d, _ := (&Builder{Kind: k, Key: testKey, Entries: []Entry{
			{Name: w("a.example.com"), Wire: 1, Mask: 4, SvcCat: 101},
			{Name: w("b.example.com"), Exact: true, Wire: 2},
		}}).Build()
		body := "go test fuzz v1\n[]byte(" + strconv.Quote(string(d)) + ")\n"
		if err := os.WriteFile(filepath.Join(dir, "valid-"+name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
