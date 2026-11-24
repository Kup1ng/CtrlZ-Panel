package policy

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/Kup1ng/CtrlZ-Shared/gtable"
)

// FilterWire packs a filter table id: (filter_id << 16) | mode_wire. The
// contract gives TableRef one u32 and FLTS records carry the pair, so the pair
// must fit in it.
func FilterWire(filterID, modeWire uint16) uint32 { return uint32(filterID)<<16 | uint32(modeWire) }

// NewCatalog checks that the opened tables belong together and builds the
// Catalog. Every table must carry the same SipHash key and catalog_version,
// because one query hashes each suffix once and probes every table with that
// hash (2.3). A mixed set would silently miss, so it is refused here instead.
func NewCatalog(services *gtable.Table, filters map[uint32]*gtable.Table, category *gtable.Table, rw Rewrite) (*Catalog, error) {
	c := &Catalog{Services: services, Filters: filters, Category: category, Rewrite: rw}
	var first *gtable.Table
	check := func(t *gtable.Table, want gtable.Kind, what string) error {
		if t == nil {
			return nil
		}
		if t.Kind() != want {
			return fmt.Errorf("policy: %s table has kind %d", what, t.Kind())
		}
		if first == nil {
			first = t
			c.Key = t.Key()
		} else if t.Key() != c.Key || t.CatalogVersion() != first.CatalogVersion() {
			return errors.New("policy: tables of one catalog must share key and catalog_version (" + what + ")")
		}
		if t.MaxLabels() > c.MaxDepth {
			c.MaxDepth = t.MaxLabels()
		}
		return nil
	}
	if err := check(services, gtable.KindService, "service"); err != nil {
		return nil, err
	}
	if err := check(category, gtable.KindCategory, "category"); err != nil {
		return nil, err
	}
	for id, t := range filters {
		if err := check(t, gtable.KindFilter, fmt.Sprintf("filter %#x", id)); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// tableFor returns the table for one filter at one mode, nil if the node does
// not have it.
func tableFor(c *Catalog, id, mode uint16) *gtable.Table {
	if c == nil {
		return nil
	}
	return c.Filters[FilterWire(id, mode)]
}

// trafficCat classifies the qname for analytics (9.5): the service category if
// there is one, else the lowest-numbered native filter category in the mask,
// else 0. The lookup always runs, whatever decided, so history is complete
// (R39). Only the longest matching suffix counts.
func (ev *eval) trafficCat(c *nameCtx) uint16 {
	cat := ev.env.Cat
	if cat == nil || cat.Category == nil {
		return 0
	}
	var out uint16
	ev.probeKeys(c, cat.Category.MaxLabels(), func(key uint64, _ int) bool {
		mask, svc, ok := cat.Category.Category(key)
		if !ok {
			return false
		}
		switch {
		case svc != 0:
			out = uint16(svc)
		case mask != 0:
			out = uint16(bits.TrailingZeros32(mask)) + 1
		}
		return true
	})
	return out
}
