package locations

import (
	"reflect"
	"testing"
)

func set(ks ...Key) map[Key]struct{} {
	m := map[Key]struct{}{}
	for _, k := range ks {
		m[k] = struct{}{}
	}
	return m
}

var (
	n1, n2, n3, n4 = NodeID{1}, NodeID{2}, NodeID{3}, NodeID{4}
	de             = Key{Country: "DE", City: "Frankfurt"}
	nl             = Key{Country: "NL", City: "Amsterdam"}
	us             = Key{Country: "US"}
	lab            = Key{Label: "gateway-x"}
)

func TestAllowedLocationsTwoPairs(t *testing.T) {
	nodes := NodeSet{
		n1: set(de, nl, us, lab),
		n2: set(de, nl, Key{Label: "gateway-x"}),
		n3: set(de, us),
		n4: set(de, us, Key{Country: "DE", City: "Frankfurt", Label: "renamed"}),
	}
	// Pair 1 shares DE, NL and the label; pair 2 shares DE and US.
	p1, p2 := PairRef{n1, n2}, PairRef{n3, n4}
	if got := AllowedLocations([]PairRef{p1}, PairRef{}, nodes); !reflect.DeepEqual(got, []Key{{Label: "gateway-x"}, de, nl}) {
		t.Errorf("one pair: %v", got)
	}
	// With both pairs, only DE survives. The label differs on n4, which must not matter.
	if got := AllowedLocations([]PairRef{p1, p2}, PairRef{}, nodes); !reflect.DeepEqual(got, []Key{de}) {
		t.Errorf("two pairs: %v", got)
	}
	// No pairs falls back to the global pair.
	if got := AllowedLocations(nil, p2, nodes); !reflect.DeepEqual(got, []Key{de, us}) {
		t.Errorf("global: %v", got)
	}
}

func TestLabelOnlyIsSharedOnlyBySameLabel(t *testing.T) {
	nodes := NodeSet{n1: set(Key{Label: "a"}), n2: set(Key{Label: "b"})}
	if got := AllowedLocations([]PairRef{{n1, n2}}, PairRef{}, nodes); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

func TestEffectiveService(t *testing.T) {
	allowed := []Key{de, nl, us, {Label: "gateway-x"}}
	if got := EffectiveService(allowed, nil); len(got) != 4 {
		t.Errorf("no limit: %v", got)
	}
	if got := EffectiveService(allowed, []string{"de"}); !reflect.DeepEqual(got, []Key{de}) {
		t.Errorf("country: %v", got)
	}
	if got := EffectiveService(allowed, []string{"NL-Amsterdam", "US-Boston"}); !reflect.DeepEqual(got, []Key{nl}) {
		t.Errorf("city: %v", got)
	}
	if got := EffectiveService(allowed, []string{}); len(got) != 0 {
		t.Errorf("empty (not nil) regions allow nothing: %v", got)
	}
}

func TestEffectiveSelection(t *testing.T) {
	a := []Key{de, nl}
	b := []Key{nl, us}
	if got := EffectiveSelection(a, b); !reflect.DeepEqual(got, []Key{nl}) {
		t.Errorf("%v", got)
	}
	if got := EffectiveSelection(a, []Key{us}); len(got) != 0 {
		t.Errorf("%v", got)
	}
	if got := EffectiveSelection(); len(got) != 0 {
		t.Errorf("%v", got)
	}
}

func TestCandidatesAndBitmap(t *testing.T) {
	bm := BitmapFromBytes([]byte{0b0000_0110, 0, 0b0000_0001}) // ids 1, 2, 16
	for id, want := range map[uint16]bool{0: false, 1: true, 2: true, 3: false, 16: true, 17: false, 500: false} {
		if BitmapHas(bm, id) != want {
			t.Errorf("id %d", id)
		}
	}
	healthy := func(id uint16) bool { return id != 2 }
	got := Candidates([]uint16{16, 2, 1, 1, 9}, bm, healthy)
	if !reflect.DeepEqual(got, []uint16{1, 16}) {
		t.Errorf("%v", got)
	}
}

func TestRandomPickStableAndVaries(t *testing.T) {
	c := []uint16{1, 5, 9, 12}
	var ep [16]byte
	ep[0] = 7
	q := []byte("\x03www\x07example\x03com\x00")
	day := int64(20_000) * 86400
	a := RandomPick(c, ep, q, day)
	if a != RandomPick(c, ep, q, day+86399) {
		t.Error("pick changed within a day")
	}
	seen := map[uint16]bool{}
	for d := int64(0); d < 60; d++ {
		seen[RandomPick(c, ep, q, day+d*86400)] = true
	}
	if len(seen) < 3 {
		t.Errorf("pick barely varies across days: %v", seen)
	}
}

// L1-F15: "Tehran" on one node and "tehran " on the other is one location, and
// the same fold decides a service's region. The shown spelling is the smaller
// of the two, so the order of the nodes does not change the answer.
func TestCityFoldsInIdentityAndInRegions(t *testing.T) {
	a := Key{Country: "ir", City: "Tehran"}
	b := Key{Country: "IR", City: " tehran "}
	nodes := NodeSet{n1: set(a), n2: set(b), n3: set(b), n4: set(a)}
	want := []Key{{Country: "IR", City: "Tehran"}}
	if got := AllowedLocations([]PairRef{{n1, n2}}, PairRef{}, nodes); !reflect.DeepEqual(got, want) {
		t.Errorf("one pair: %v, want %v", got, want)
	}
	if got := AllowedLocations([]PairRef{{n2, n1}}, PairRef{}, nodes); !reflect.DeepEqual(got, want) {
		t.Errorf("swapped: %v", got)
	}
	if got := AllowedLocations([]PairRef{{n1, n2}, {n3, n4}}, PairRef{}, nodes); !reflect.DeepEqual(got, want) {
		t.Errorf("two pairs: %v", got)
	}
	for _, region := range []string{"IR-Tehran", "ir-tehran", "IR- TEHRAN "} {
		if got := EffectiveService(want, []string{region}); len(got) != 1 {
			t.Errorf("region %q: %v", region, got)
		}
	}
	if got := EffectiveService(want, []string{"IR-Isfahan"}); len(got) != 0 {
		t.Errorf("another city: %v", got)
	}
	if got := EffectiveSelection([]Key{a}, []Key{b}); !reflect.DeepEqual(got, want) {
		t.Errorf("selection: %v", got)
	}
}

func TestShouldPublish(t *testing.T) {
	for _, c := range []struct {
		last, now uint32
		want      bool
	}{
		{0, 50, true}, // nothing published yet
		{100, 100, false},
		{100, 119, false}, // 19 percent
		{100, 121, true},  // more than 20 percent and than 10 ms
		{100, 80, false},  // exactly 20 percent is not more
		{100, 79, true},
		{30, 38, false}, // 8 ms is more than 20 percent of 30 but not more than 10 ms
		{30, 41, true},  // 11 ms and 36 percent
		{200, 210, false},
		{200, 241, true},
		{1000, 1199, false},
		{1000, 1201, true},
	} {
		if got := ShouldPublish(c.last, c.now); got != c.want {
			t.Errorf("ShouldPublish(%d, %d) = %v, want %v", c.last, c.now, got, c.want)
		}
	}
}
