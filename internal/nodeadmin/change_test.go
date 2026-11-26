package nodeadmin

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func ids(n int) []uuid.UUID {
	out := make([]uuid.UUID, n)
	for i := range out {
		out[i] = uuid.MustParse("00000000-0000-7000-8000-00000000000" + string(rune('1'+i)))
	}
	return out
}

// TestSecondPeer is the rule of the constraint trigger: (A, B) beside (B, A) is accepted, (A, B) beside (A, C) is not,
// and the pair being changed does not count against itself.
func TestSecondPeer(t *testing.T) {
	n := ids(4)
	a, b, c, d := n[0], n[1], n[2], n[3]
	p1 := uuid.MustParse("00000000-0000-7000-8000-0000000000a1")
	p2 := uuid.MustParse("00000000-0000-7000-8000-0000000000a2")
	rows := []store.MemberPair{{ID: p1, Primary: a, Fallback: b}}
	for _, tc := range []struct {
		name              string
		pairs             []store.MemberPair
		self, prim, fallb uuid.UUID
		want              bool
	}{
		{"no pairs", nil, uuid.Nil, a, b, false},
		{"the same pair again", rows, uuid.Nil, a, b, false},
		{"the pair reversed", rows, uuid.Nil, b, a, false},
		{"a second peer for the primary", rows, uuid.Nil, a, c, true},
		{"a second peer for the fallback", rows, uuid.Nil, c, b, true},
		{"a second peer when the new fallback is held", rows, uuid.Nil, c, a, true},
		{"two nodes of no pair", rows, uuid.Nil, c, d, false},
		{"the pair itself moves to another peer", rows, p1, a, c, false},
		{"the pair itself moves onto a pair of two others", []store.MemberPair{{ID: p1, Primary: a, Fallback: b}, {ID: p2, Primary: c, Fallback: d}}, p1, a, c, true},
	} {
		if got := SecondPeer(tc.pairs, tc.self, tc.prim, tc.fallb); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func tableOf(pairs ...[2]uuid.UUID) *policyv1.PairTable {
	pt := &policyv1.PairTable{}
	for _, p := range pairs {
		pt.Pairs = append(pt.Pairs, &policyv1.Pair{Primary: p[0][:], Fallback: p[1][:]})
	}
	return pt
}

// TestInSomeTable: a node is in a table when a pair of the newest log entry or of the hub's last event holds it, and
// a table nobody can read is an error and never "not in the table".
func TestInSomeTable(t *testing.T) {
	n := ids(3)
	a, b, c := n[0], n[1], n[2]
	entry, err := proto.Marshal(tableOf([2]uuid.UUID{a, b}))
	if err != nil {
		t.Fatal(err)
	}
	last, err := proto.Marshal(tableOf([2]uuid.UUID{b, c}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		entry, last []byte
		node        uuid.UUID
		want        bool
	}{
		{"nothing yet", nil, nil, a, false},
		{"the log's pair holds it", entry, nil, a, true},
		{"the hub's last event holds it", nil, last, c, true},
		{"the log's pair holds it as the fallback", entry, last, b, true},
		{"neither holds it", entry, nil, c, false},
	} {
		got, err := InSomeTable(tc.entry, tc.last, tc.node)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v, want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := InSomeTable([]byte{0xff, 0xff, 0xff}, nil, a); err != ErrTableDecode {
		t.Errorf("a log entry that does not parse: %v", err)
	}
	if _, err := InSomeTable(nil, []byte{0xff, 0xff, 0xff}, a); err != ErrTableDecode {
		t.Errorf("a last table that does not parse: %v", err)
	}
}

// TestRevokedJobParams: this node plus the node_ids of the jobs it supersedes, sorted and without repeats, and a
// params document of another shape adds nothing.
func TestRevokedJobParams(t *testing.T) {
	n := ids(3)
	old, _ := json.Marshal(map[string]any{"node_ids": []string{n[1].String(), n[0].String()}})
	got, dropped, err := RevokedJobParams(n[0], [][]byte{old, []byte(`{"node_ids":["not a uuid"]}`), []byte(`not json`), []byte(`{}`)})
	if err != nil || len(dropped) != 0 {
		t.Fatal(dropped, err)
	}
	var p struct {
		NodeIDs []string `json:"node_ids"`
	}
	if err := json.Unmarshal(got, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.NodeIDs) != 2 || p.NodeIDs[0] != n[0].String() || p.NodeIDs[1] != n[1].String() {
		t.Fatalf("node_ids %v", p.NodeIDs)
	}
	alone, _, err := RevokedJobParams(n[2], nil)
	if err != nil || string(alone) != `{"node_ids":["`+n[2].String()+`"]}` {
		t.Fatalf("alone: %s %v", alone, err)
	}
}

// TestRevokedJobParamsNeverRefusesARevocation: past MaxRevokedNodeIDs the carried list is cut, this node stays in it, the
// others are kept in id order, and the count of the dropped is returned (I-r3-5). The old behaviour was an error, which
// made a revocation fail while the clean-up of earlier ones was stuck.
func TestRevokedJobParamsNeverRefusesARevocation(t *testing.T) {
	many := make([]uuid.UUID, MaxRevokedNodeIDs+10)
	for i := range many {
		many[i] = uuid.New()
	}
	var strs []string
	for _, id := range many[1:] {
		strs = append(strs, id.String())
	}
	old, _ := json.Marshal(map[string]any{"node_ids": strs})
	got, dropped, err := RevokedJobParams(many[0], [][]byte{old})
	if err != nil {
		t.Fatalf("a long carried list refused the revocation: %v", err)
	}
	var p struct {
		NodeIDs []string `json:"node_ids"`
	}
	if err := json.Unmarshal(got, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.NodeIDs) != MaxRevokedNodeIDs || len(dropped) != 10 || !slices.Contains(p.NodeIDs, many[0].String()) {
		t.Fatalf("%d ids, %d dropped, self kept %v", len(p.NodeIDs), len(dropped), slices.Contains(p.NodeIDs, many[0].String()))
	}
	// Every id is either kept or named as dropped, so none loses its clean-up without a trace (I-r4-2, I-r4-3).
	for _, id := range many[1:] {
		if !slices.Contains(p.NodeIDs, id.String()) && !slices.Contains(dropped, id) {
			t.Fatalf("%s is neither kept nor reported as dropped", id)
		}
	}
}

// TestEntryPairTable: an entry of a tenant-only change carries no table, so the table the log last carried is
// found below it and not in it, and the bytes come back without the entry being decoded.
func TestEntryPairTable(t *testing.T) {
	n := ids(2)
	want, err := proto.Marshal(tableOf([2]uuid.UUID{n[0], n[1]}))
	if err != nil {
		t.Fatal(err)
	}
	with, err := proto.Marshal(&policyv1.ConfigEntry{Seq: 7, PairTable: tableOf([2]uuid.UUID{n[0], n[1]})})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := EntryPairTable(with); err != nil || !ok || string(got) != string(want) {
		t.Errorf("an entry with a table: %x, %v, %v", got, ok, err)
	}
	if _, ok, err := EntryPairTable(nil); err != nil || ok {
		t.Errorf("an entry with none: %v, %v", ok, err)
	}
	other, err := proto.Marshal(&policyv1.ConfigEntry{Seq: 9})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := EntryPairTable(other); err != nil || ok {
		t.Errorf("a tenant-only entry: %v, %v", ok, err)
	}
	if _, _, err := EntryPairTable([]byte{0xff, 0xff, 0xff}); err != ErrTableDecode {
		t.Errorf("an entry that does not parse: %v", err)
	}
}
