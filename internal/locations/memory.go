package locations

import (
	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Memory is the in-memory LocationCatalog the vector cases and the tests build from a description. It
// reads no transaction, so the cases of locations-sets.json and the route tests drive the same code the
// production catalog feeds, with no database behind it.
type Memory struct {
	// Locations are all the locations that have a row, in wire-id order (1, 2, ...). A location a node has
	// must be among them.
	Locations []shared.Key
	// Nodes maps a node name to the locations it has with an enabled config.
	Nodes map[string][]shared.Key
	// GlobalA and GlobalB name the nodes of the global pair; empty means none is set.
	GlobalA, GlobalB string
}

// space makes the ids of the in-memory rows stable: one name is one id in every run.
func space() uuid.UUID { return uuid.MustParse("6f0c1a4e-5d0b-4b53-9a0e-2f6d3c8f7a11") }

// NodeUUID is the id the in-memory catalog gives a node name.
func NodeUUID(name string) uuid.UUID { return uuid.NewSHA1(space(), []byte("node:"+name)) }

// LocationUUID is the id the in-memory catalog gives a location.
func LocationUUID(k shared.Key) uuid.UUID {
	k = fold(k)
	return uuid.NewSHA1(space(), []byte("loc:"+k.Country+"/"+k.City+"/"+k.Label))
}

// Snapshot implements LocationCatalog.
func (m Memory) Snapshot(store.Tx) (Snapshot, error) {
	s := Snapshot{Nodes: shared.NodeSet{}}
	for i, k := range m.Locations {
		s.Rows = append(s.Rows, Row{ID: LocationUUID(k), WireID: i + 1, Key: k})
	}
	for name, ks := range m.Nodes {
		n := shared.NodeID(NodeUUID(name))
		s.Nodes[n] = map[shared.Key]struct{}{}
		for _, k := range ks {
			s.Nodes[n][k] = struct{}{}
		}
	}
	if m.GlobalA != "" && m.GlobalB != "" {
		s.HasGlobal = true
		s.Global = shared.PairRef{A: shared.NodeID(NodeUUID(m.GlobalA)), B: shared.NodeID(NodeUUID(m.GlobalB))}
	}
	return s.Index(), nil
}
