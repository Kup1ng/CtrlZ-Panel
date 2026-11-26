package zone

import "testing"

func id(b byte) NodeID { return NodeID{b, b, b, b, b, b, b, b, b, b, b, b, b, b, b, b} }

// 8a.4 Node apply, step 3.
func TestFlagMapTake(t *testing.T) {
	member := []NodeID{id(1), id(2)}
	// A node the push names takes its flag; one it does not name keeps its own; a
	// node no push has named is not withdrawn.
	f := FlagMap{id(1): true}
	got := f.Take(map[NodeID]bool{id(2): true}, member)
	if !got[id(1)] || !got[id(2)] {
		t.Errorf("flags %v", got)
	}
	got = got.Take(map[NodeID]bool{id(1): false}, member)
	if got[id(1)] || !got[id(2)] {
		t.Errorf("a named node must take the push's flag and the other keep its own: %v", got)
	}
	if (FlagMap{}).Take(nil, member)[id(1)] {
		t.Error("a node no push has named was withdrawn")
	}

	// A lagging node: the push names A withdrawn, the next holds a membership without
	// A. The node's own membership still has A, so A stays withdrawn.
	lag := FlagMap{}.Take(map[NodeID]bool{id(1): true}, member)
	lag = lag.Take(map[NodeID]bool{id(2): false}, member)
	if !lag[id(1)] {
		t.Error("a lagging node lost the withdrawal of a node its own membership still has")
	}

	// A flag is dropped only for a node in neither the membership nor the push: a
	// push naming a node the log has not added yet keeps its flag until that entry.
	ahead := FlagMap{}.Take(map[NodeID]bool{id(9): true}, member)
	if !ahead[id(9)] {
		t.Error("the flag of a node outside the membership, named by the push, was dropped")
	}
	again := ahead.Take(map[NodeID]bool{id(1): false}, member)
	if _, ok := again[id(9)]; ok {
		t.Error("a flag in neither the membership nor the push was kept")
	}
	if _, ok := (FlagMap{id(7): true}).Take(nil, member)[id(7)]; ok {
		t.Error("an old flag of a removed node was kept")
	}

	// Take returns a new map.
	orig := FlagMap{id(1): true}
	_ = orig.Take(map[NodeID]bool{id(1): false}, member)
	if !orig[id(1)] {
		t.Error("Take changed its receiver")
	}
}

func TestFlagMapRedelivery(t *testing.T) {
	f := FlagMap{id(1): true, id(2): false}
	for name, c := range map[string]struct {
		push map[NodeID]bool
		want bool
	}{
		"same flags":              {map[NodeID]bool{id(1): true, id(2): false}, true},
		"a node only in the map":  {map[NodeID]bool{id(1): true}, true},
		"a node only in the push": {map[NodeID]bool{id(1): true, id(3): true}, true},
		"a different flag":        {map[NodeID]bool{id(1): false}, false},
	} {
		if got := f.Redelivery(c.push); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

func TestWithFlagsKeepsTheLogMembership(t *testing.T) {
	in := BuildInput{
		Nodes: []BuildNode{
			{ID: ids(1), DNSIP: []byte{5, 160, 0, 1}, Slot: 1},
			{ID: ids(2), DNSIP: []byte{5, 160, 1, 1}, Slot: 2, Revoked: true},
		},
		Pairs:  []BuildPair{{ID: ids(0xA), Primary: ids(1), Fallback: ids(2)}},
		Global: ids(0xA),
	}
	out := WithFlags(in, 7, FlagMap{id(1): true, id(2): true, id(9): true})
	if out.Version != 7 || !out.Nodes[0].Withdrawn || !out.Nodes[1].Withdrawn || !out.Nodes[1].Revoked || out.Nodes[1].Slot != 2 {
		t.Errorf("%+v", out.Nodes)
	}
	if in.Version != 0 || in.Nodes[0].Withdrawn {
		t.Error("WithFlags changed its input")
	}
	tbl, err := Build(out)
	if err != nil || tbl.Version != 7 || len(tbl.Nodes) != 2 {
		t.Fatalf("build: %v", err)
	}
}

func ids(b byte) []byte { i := id(b); return i[:] }
