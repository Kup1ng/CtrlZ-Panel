package endpoints

import (
	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"

	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// CodeLocationNotAllowed is the field code of a destinations_lost refusal: the member names a profile that would lose a
// location it targets.
const CodeLocationNotAllowed = "location_not_allowed"

// destinations is the check of spec 3.4 (T-066): when a request changes the roles a profile has on Endpoints, the set of
// locations the profile may use (P2 4.2) is computed before and after, and a location its rules, folders, services or Default
// Rule target that is in the first set and not in the second is a refusal unless the request confirms it. In v1 every
// Endpoint is on the global pair (D30), so the set never changes; it is written over the pair of each Endpoint so that an
// override needs no change, and a test sets one directly as owner.
type destinations struct {
	e      *Env
	tx     store.Tx
	snap   locations.Snapshot
	have   bool
	watch  map[uuid.UUID]watched
	member map[uuid.UUID]string
}

type watched struct {
	targets []shared.Key
	before  []shared.Key
}

// watchProfiles records the allowed set of every profile of the list that targets a location, before the write. The profiles
// that target none cannot lose a destination, so they cost one query each and nothing more.
func (e *Env) watchProfiles(tx store.Tx, profiles []uuid.UUID, member map[uuid.UUID]string) (*destinations, error) {
	d := &destinations{e: e, tx: tx, watch: map[uuid.UUID]watched{}, member: member}
	for _, p := range uniqueIDs(profiles) {
		locs, err := tx.ProfileTargetLocations(p)
		if err != nil {
			return nil, err
		}
		if len(locs) == 0 {
			continue
		}
		if err := d.load(); err != nil {
			return nil, err
		}
		var keys []shared.Key
		for _, id := range locs {
			if r, ok := d.snap.ByID(id); ok {
				keys = append(keys, r.Key)
			}
		}
		set, err := locations.Allowed(tx, d.snap, p)
		if err != nil {
			return nil, err
		}
		d.watch[p] = watched{targets: keys, before: set}
	}
	return d, nil
}

func (d *destinations) load() error {
	if d.have {
		return nil
	}
	if d.e.Catalog == nil {
		d.snap = locations.Snapshot{}.Index()
	} else {
		s, err := d.e.Catalog.Snapshot(d.tx)
		if err != nil {
			return err
		}
		d.snap = s
	}
	d.have = true
	return nil
}

// check runs after the write. confirm is the request's confirm_destinations.
func (d *destinations) check(confirm bool) error {
	var fs []Field
	for _, p := range sortedKeys(d.watch) {
		w := d.watch[p]
		after, err := locations.Allowed(d.tx, d.snap, p)
		if err != nil {
			return err
		}
		for _, k := range w.targets {
			if locations.Contains(w.before, k) && !locations.Contains(after, k) {
				name := d.member[p]
				if name == "" {
					name = "/profile_id"
				}
				fs = append(fs, Field{name, CodeLocationNotAllowed})
				break
			}
		}
	}
	if len(fs) > 0 && !confirm {
		return &Error{Kind: KindDestinationsLost, Fields: fs}
	}
	return nil
}

func sortedKeys[V any](m map[uuid.UUID]V) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return uniqueIDs(out)
}
