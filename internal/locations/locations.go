// Package locations is where the write path learns which locations exist and which a profile may
// use (docs/specs/p2-profiles.md 4). The definition of "allowed" is the shared module's
// (locations.AllowedLocations, EffectiveService, EffectiveSelection), so the page that shows a set
// and the request that saves a choice cannot differ; this package only feeds it the rows.
package locations

import (
	"strings"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Row is a location as the panel stores it: the id a rule's target column holds, the wire id the
// compiler will write, and the key that identifies it across installs.
type Row struct {
	ID     uuid.UUID
	WireID int
	Key    shared.Key
}

// Snapshot is what the write path needs in one read: per node, the locations with an enabled config;
// the global pair; and each location's row. It is a value, so the vector cases and the tests can build
// one by hand.
type Snapshot struct {
	Nodes     shared.NodeSet
	Global    shared.PairRef
	HasGlobal bool
	Rows      []Row

	byID   map[uuid.UUID]Row
	byFold map[shared.Key]Row
}

// fold is the identity two keys are compared by: the country in upper case and the city folded, as
// the shared module compares them; a label-only location is its label alone.
func fold(k shared.Key) shared.Key {
	if k.Country == "" {
		return shared.Key{Label: k.Label}
	}
	return shared.Key{Country: strings.ToUpper(k.Country), City: strings.ToLower(strings.TrimSpace(k.City))}
}

// Index builds the lookups of a snapshot. Both producers call it.
func (s Snapshot) Index() Snapshot {
	s.byID = make(map[uuid.UUID]Row, len(s.Rows))
	s.byFold = make(map[shared.Key]Row, len(s.Rows))
	for _, r := range s.Rows {
		s.byID[r.ID] = r
		s.byFold[fold(r.Key)] = r
	}
	return s
}

// Find returns the location with this key, by the shared comparison (city case and spaces do not
// matter). A key that has no row cannot be stored in a rule (PS 1, target_location_id).
func (s Snapshot) Find(k shared.Key) (Row, bool) {
	r, ok := s.byFold[fold(k)]
	return r, ok
}

// ByID returns the location of a stored target.
func (s Snapshot) ByID(id uuid.UUID) (Row, bool) {
	r, ok := s.byID[id]
	return r, ok
}

// LocationCatalog is what the write path and the locations route read. P4b fills the tables the
// production implementation reads and changes nothing here.
type LocationCatalog interface {
	// Snapshot reads in the caller's transaction.
	Snapshot(tx store.Tx) (Snapshot, error)
}

// Store is the production implementation: it reads location_availability, locations, node_pairs and
// public_settings as the tenant (the tenant role holds SELECT on them, PS 6.2).
type Store struct{}

func nodeID(id uuid.UUID) shared.NodeID { return shared.NodeID(id) }

// Snapshot implements LocationCatalog.
func (Store) Snapshot(tx store.Tx) (Snapshot, error) {
	rows, err := tx.LocationRows()
	if err != nil {
		return Snapshot{}, err
	}
	avail, err := tx.LocationAvailability()
	if err != nil {
		return Snapshot{}, err
	}
	pair, has, err := tx.GlobalPair()
	if err != nil {
		return Snapshot{}, err
	}
	s := Snapshot{Nodes: shared.NodeSet{}, HasGlobal: has}
	keys := map[uuid.UUID]shared.Key{}
	for _, r := range rows {
		k := shared.Key{Country: strings.TrimSpace(r.Country), City: strings.TrimSpace(r.City), Label: r.Label}
		if k.Country != "" {
			k.Label = "" // with a country the label is a display name, not part of the identity
		}
		keys[r.ID] = k
		s.Rows = append(s.Rows, Row{ID: r.ID, WireID: r.WireID, Key: k})
	}
	for _, a := range avail {
		k, ok := keys[a.Location]
		if !ok {
			continue
		}
		n := nodeID(a.Node)
		if s.Nodes[n] == nil {
			s.Nodes[n] = map[shared.Key]struct{}{}
		}
		s.Nodes[n][k] = struct{}{}
	}
	if has {
		s.Global = shared.PairRef{A: nodeID(pair.A), B: nodeID(pair.B)}
	}
	return s.Index(), nil
}

// Allowed is the set of locations the profile may use (SC 10.1): the intersection over the node pair of
// every Endpoint that uses it in any role, with the global pair when none does. In v1 every Endpoint is on
// the global pair (D30); the collection is written so that a pair override needs no change (T-022).
func Allowed(tx store.Tx, snap Snapshot, profile uuid.UUID) ([]shared.Key, error) {
	pairs, err := tx.ProfilePairs(profile)
	if err != nil {
		return nil, err
	}
	var refs []shared.PairRef
	for _, p := range pairs {
		if p == (store.Pair{}) {
			refs = append(refs, snap.Global) // an Endpoint on the global pair
			continue
		}
		refs = append(refs, shared.PairRef{A: nodeID(p.A), B: nodeID(p.B)})
	}
	return shared.AllowedLocations(refs, snap.Global, snap.Nodes), nil
}

// ForService limits a set to the regions a service may be reached from (nil regions: no limit).
func ForService(allowed []shared.Key, regions []string) []shared.Key {
	return shared.EffectiveService(allowed, regions)
}

// ForSelection intersects the sets of several services: the group action offers Redirect only to a
// location every one of them can use.
func ForSelection(sets ...[]shared.Key) []shared.Key { return shared.EffectiveSelection(sets...) }

// Contains reports whether a set has the location, by the shared comparison.
func Contains(set []shared.Key, k shared.Key) bool {
	return len(shared.EffectiveSelection(set, []shared.Key{k})) > 0
}

// AutoRandom is whether Auto and Random are offered: at least two locations (SC 10.2). The API accepts
// them on any non-empty set.
func AutoRandom(set []shared.Key) bool { return len(set) >= 2 }
