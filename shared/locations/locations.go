// Package locations holds the one definition of "which locations may this
// profile use" (contract 10.1) and the runtime pick helpers (10.2).
//
// API, UI, Import, Duplicate and Copy all call these functions, so the answer
// to "is this location allowed" cannot differ between the page that shows it
// and the request that saves it.
package locations

import (
	"encoding/binary"
	"sort"
	"strings"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// NodeID identifies a node inside a PairRef. The panel uses the node's UUID.
type NodeID [16]byte

// Key identifies a location across nodes. A configuration with a country is
// identified by (Country, City) and its label is only a display name. One with
// no country is identified by its admin label alone and is shared only with
// the same label on the other node.
type Key struct{ Country, City, Label string }

// NodeSet maps a node to the locations it has at least one enabled config for.
type NodeSet map[NodeID]map[Key]struct{}

// PairRef is one pair of nodes.
type PairRef struct{ A, B NodeID }

// foldCity is the one way a city name is compared, here and in the region
// check of EffectiveService: case and surrounding spaces do not matter. An admin
// who types "Tehran" on one node and "tehran" on the other means one location,
// and before this a capitalization difference made it vanish from the picker
// (review L1-F15).
func foldCity(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// ident reduces a Key to the fields that identify it, with the city as the
// admin spelled it (trimmed). It is what a caller is shown.
func ident(k Key) Key {
	if k.Country == "" {
		return Key{Label: k.Label}
	}
	return Key{Country: strings.ToUpper(k.Country), City: strings.TrimSpace(k.City)}
}

// fold is the identity used to compare two locations: ident with the city
// folded.
func fold(k Key) Key {
	k = ident(k)
	k.City = foldCity(k.City)
	return k
}

// spelled maps the identity of a location (fold) to the spelling that is
// shown. When two nodes spell one city differently the smaller spelling wins,
// so the result does not depend on the order the nodes were given in.
type spelled map[Key]Key

func (s spelled) add(k Key) {
	f, shown := fold(k), ident(k)
	if old, ok := s[f]; !ok || less(shown, old) {
		s[f] = shown
	}
}

func (s spelled) sorted() []Key {
	out := make([]Key, 0, len(s))
	for _, k := range s {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

func less(a, b Key) bool {
	if a.Country != b.Country {
		return a.Country < b.Country
	}
	if a.City != b.City {
		return a.City < b.City
	}
	return a.Label < b.Label
}

func spellSet(s map[Key]struct{}) spelled {
	out := make(spelled, len(s))
	for k := range s {
		out.add(k)
	}
	return out
}

// AllowedLocations is the intersection, over both nodes of every pair in
// pairs, of the locations each node has. An empty pairs uses global, which is
// the answer for a profile no Endpoint uses yet. The caller collects pairs
// from every Endpoint that uses the profile as Enforced, Profile 2, schedule
// window or client profile: a location must work wherever the profile can run.
func AllowedLocations(pairs []PairRef, global PairRef, nodes NodeSet) []Key {
	if len(pairs) == 0 {
		pairs = []PairRef{global}
	}
	var acc spelled
	for _, p := range pairs {
		a, b := spellSet(nodes[p.A]), spellSet(nodes[p.B])
		both := make(spelled)
		for f, ka := range a {
			if kb, ok := b[f]; ok {
				both[f] = ka
				if less(kb, ka) {
					both[f] = kb
				}
			}
		}
		if acc == nil {
			acc = both
			continue
		}
		for f, k := range acc {
			kb, ok := both[f]
			if !ok {
				delete(acc, f)
			} else if less(kb, k) {
				acc[f] = kb
			}
		}
	}
	return acc.sorted()
}

// EffectiveService limits allowed to the regions a service may be reached
// from. Regions are "CC" (a country) or "CC-City". nil regions means the
// service has no limit. A label-only location never satisfies a limited
// service, because nothing says which country it is in.
func EffectiveService(allowed []Key, regions []string) []Key {
	// Results are always sorted by (Country, City, Label), whatever order the
	// caller passes allowed in, so two callers cannot disagree on the order.
	if regions == nil {
		out := append([]Key(nil), allowed...)
		sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
		return out
	}
	out := make([]Key, 0)
	for _, k := range allowed {
		if k.Country == "" {
			continue
		}
		for _, r := range regions {
			cc, city, hasCity := strings.Cut(r, "-")
			if !strings.EqualFold(cc, k.Country) {
				continue
			}
			if hasCity && foldCity(city) != foldCity(k.City) {
				continue
			}
			out = append(out, k)
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// EffectiveSelection intersects any number of sets. An empty result disables
// Redirect and the UI shows the shared-destination message. With no sets the
// result is empty: nothing was offered, so nothing is allowed.
func EffectiveSelection(sets ...[]Key) []Key {
	if len(sets) == 0 {
		return []Key{}
	}
	acc := make(spelled)
	for _, k := range sets[0] {
		acc.add(k)
	}
	for _, s := range sets[1:] {
		has := make(spelled, len(s))
		for _, k := range s {
			has.add(k)
		}
		for f, k := range acc {
			kh, ok := has[f]
			if !ok {
				delete(acc, f)
			} else if less(kh, k) {
				acc[f] = kh
			}
		}
	}
	return acc.sorted()
}

// BitmapFromBytes converts Pair.location_bitmap (bit i of byte i/8, least
// significant bit first) to the word form the evaluator keeps.
func BitmapFromBytes(b []byte) []uint64 {
	out := make([]uint64, (len(b)+7)/8)
	for i, v := range b {
		out[i/8] |= uint64(v) << (8 * uint(i%8))
	}
	return out
}

// BitmapHas reports whether location id is in the bitmap.
func BitmapHas(bm []uint64, id uint16) bool {
	w := int(id) / 64
	return w < len(bm) && bm[w]&(1<<(uint(id)%64)) != 0
}

// Candidates is set intersect pair intersect healthy, sorted ascending and
// without duplicates. healthy may be nil, meaning every location is healthy.
// It never modifies set.
func Candidates(set []uint16, pair []uint64, healthy func(uint16) bool) []uint16 {
	out := make([]uint16, 0, len(set))
	for _, id := range set {
		if !BitmapHas(pair, id) || (healthy != nil && !healthy(id)) {
			continue
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	w := 0
	for i, v := range out {
		if i == 0 || v != out[w-1] {
			out[w] = v
			w++
		}
	}
	return out[:w]
}

// RandomPick chooses one of the sorted candidates for Random Location. The
// index is SipHash(ProfileKey, endpoint_id + qname wire + u32be(day)) mod len,
// where day is floor(now/86400). Including the day makes the choice stable
// within a day for one name (connection reuse works) and different tomorrow.
// The caller guarantees len(candidates) > 0.
func RandomPick(candidates []uint16, endpointID [16]byte, qname []byte, now int64) uint16 {
	buf := make([]byte, 0, 16+len(qname)+4)
	buf = append(buf, endpointID[:]...)
	buf = append(buf, qname...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(floorDiv(now, 86400)))
	h := names.Hash64(names.ProfileKey(), buf)
	return candidates[h%uint64(len(candidates))]
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// Hysteresis of the published latency (p4b-proxy 6.4). The agent smooths the time
// from CONNECT to the first response byte of each location and publishes the
// smoothed value only when it differs from the last published one by more than
// PublishPermille of that value and by more than PublishMinMs, so two locations that
// are a few milliseconds apart do not trade places on every probe. Auto then picks the
// lowest published value, which is what policy.LocationView.Auto is given.
const (
	PublishPermille = 200
	PublishMinMs    = 10
)

// ShouldPublish reports whether a new smoothed latency replaces the last published
// one. last is 0 when nothing was published yet, and then the first value is
// published at once. Both are milliseconds.
func ShouldPublish(last, now uint32) bool {
	if last == 0 {
		return true
	}
	d := now - last
	if now < last {
		d = last - now
	}
	return d > PublishMinMs && uint64(d)*1000 > uint64(last)*PublishPermille
}
