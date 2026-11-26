package zone

// FlagMap holds one withdrawal flag per node_id: the state a node keeps between
// pushes (8a.4 Node apply, step 3). Pushes carry flags and a version only, so the
// map is the one place a flag lives between them; the table in use is the node's
// own membership from the log with these flags laid on it (WithFlags).
//
// A FlagMap is a value to replace, not to edit: Take returns a new one, so the
// node can build a table from it under recover and swap both in together, and a
// failed build leaves the old map in use (step 4).
type FlagMap map[NodeID]bool

// Take is step 3 for a push of a higher version than the node has used. A node
// the push names takes the push's flag. A node the push does not name keeps the
// flag it had, and a node that no accepted push has named has none, which reads
// as not withdrawn. The result drops a node_id that is in neither the node's
// membership nor the push, so a push that names a node the log has not added yet
// still holds its flag when the entry that adds the node is applied next.
//
// member is the node_ids of the node's own membership, from its applied log
// entry; pushed is the push's flags by node_id.
func (f FlagMap) Take(pushed map[NodeID]bool, member []NodeID) FlagMap {
	in := make(map[NodeID]bool, len(member))
	for _, id := range member {
		in[id] = true
	}
	out := make(FlagMap, len(f)+len(pushed))
	for id, w := range f {
		if in[id] || hasKey(pushed, id) {
			out[id] = w
		}
	}
	for id, w := range pushed {
		out[id] = w
	}
	return out
}

// Redelivery is step 2: a push of the same version is a redelivery when every
// node_id that both the push and the map hold has the same flag. An equal version
// with a different flag is a conflict, because the hub never signs two flag maps
// at one version. A node in only one of them proves nothing either way.
func (f FlagMap) Redelivery(pushed map[NodeID]bool) bool {
	for id, w := range pushed {
		if old, ok := f[id]; ok && old != w {
			return false
		}
	}
	return true
}

// WithFlags lays the push version and the flags onto a membership taken from the
// log: each node gets its flag from the map, false when it has none, and the
// table's Version becomes version. The membership, addresses, slots and
// revocations stay as the log gave them (8a.7, wire.ZoneInput). The input is not
// changed.
func WithFlags(in BuildInput, version uint64, f FlagMap) BuildInput {
	out := in
	out.Version = version
	out.Nodes = make([]BuildNode, len(in.Nodes))
	for i, n := range in.Nodes {
		if id, ok := id16(n.ID); ok {
			n.Withdrawn = f[NodeID(id)]
		}
		out.Nodes[i] = n
	}
	return out
}

func hasKey(m map[NodeID]bool, id NodeID) bool {
	_, ok := m[id]
	return ok
}
