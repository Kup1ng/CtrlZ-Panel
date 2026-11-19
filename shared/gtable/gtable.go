// Package gtable builds, validates and reads CZGT global tables (contract 9.4):
// the filter, service and category lookups that every profile shares.
//
// A table stores 64-bit keyed hashes of names, not the names. That keeps a
// million-entry blocklist at 8 bytes per entry and makes lookups two memory
// reads, at the price of a 2^-63 false-positive chance per probe, which is far
// below the error rate of the lists themselves.
package gtable

import (
	"encoding/binary"
	"sort"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
)

var le = binary.LittleEndian

const (
	Magic     = "CZGT"
	Major     = 1
	Minor     = 0
	HeaderLen = 64
	// MaxSize is the global table cap (2 GiB).
	MaxSize = 2 << 30
	// MaxBucketBits bounds the offsets array to 64 MiB.
	MaxBucketBits = 24
)

// Kind is the table kind.
type Kind uint8

const (
	KindFilter   Kind = 1
	KindService  Kind = 2
	KindCategory Kind = 3
)

func (k Kind) entrySize() int {
	if k == KindFilter {
		return 8
	}
	return 16
}

// Entry is a builder input.
type Entry struct {
	// Name is a canonical wire name (root byte included).
	Name []byte
	// Exact marks a full: or hosts-list entry. Without it the entry is a
	// suffix entry (domain: and wildcard lists), matching the name and below.
	Exact bool
	// Wire is the service wire id (KindService).
	Wire uint32
	// Mask is the native filter category bitmask and SvcCat the service
	// category 101..112 (KindCategory).
	Mask   uint32
	SvcCat uint8
}

// Builder describes a table to build.
type Builder struct {
	Kind           Kind
	CatalogVersion uint64
	// Key is the SipHash key for this catalog_version. It is random per
	// catalog so nobody can pre-compute collisions against a table they have
	// not seen; it is stored in the header so readers need nothing else.
	Key     [16]byte
	Entries []Entry
}

type rec struct {
	key  uint64
	wire uint32
	mask uint32
	svc  uint8
}

// Build returns the deterministic CZGT bytes.
func (b *Builder) Build() ([]byte, error) {
	if b.Kind < KindFilter || b.Kind > KindCategory {
		return nil, reason.New(reason.BadEnum, "", 8, "kind %d", b.Kind)
	}
	maxLabels := 0
	recs := make([]rec, 0, len(b.Entries))
	for i := range b.Entries {
		e := &b.Entries[i]
		n, err := names.FromCanonicalWire(e.Name)
		if err != nil {
			return nil, err
		}
		if n.IsRoot() {
			return nil, reason.New(reason.BadName, "", 0, "the root cannot be a table entry")
		}
		if n.Labels() > maxLabels {
			maxLabels = n.Labels()
		}
		h := names.Hash64(b.Key, n.Wire())
		k := names.SuffixKey(h)
		if e.Exact {
			k = names.ExactKey(h)
		}
		recs = append(recs, rec{key: k, wire: e.Wire, mask: e.Mask, svc: e.SvcCat})
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].key != recs[j].key {
			return recs[i].key < recs[j].key
		}
		return recs[i].wire < recs[j].wire
	})
	// Dedupe: a filter key once, a service (key, wire) once, a category key
	// once with its fields merged.
	out := recs[:0]
	for _, r := range recs {
		if n := len(out); n > 0 && out[n-1].key == r.key {
			last := &out[n-1]
			switch b.Kind {
			case KindFilter:
				continue
			case KindService:
				if last.wire == r.wire {
					continue
				}
			case KindCategory:
				last.mask |= r.mask
				if last.svc == 0 || (r.svc != 0 && r.svc < last.svc) {
					last.svc = r.svc
				}
				continue
			}
		}
		out = append(out, r)
	}
	recs = out

	bits := 0
	for bits < MaxBucketBits && (1<<uint(bits))*4 < len(recs) {
		bits++
	}
	offLen := 4 * ((1 << uint(bits)) + 1)
	bodyStart := (HeaderLen + offLen + 7) &^ 7
	es := b.Kind.entrySize()
	total := bodyStart + es*len(recs)
	if total > MaxSize {
		return nil, reason.New(reason.SizeCap, "", 0, "table of %d bytes", total)
	}
	buf := make([]byte, total)
	copy(buf, Magic)
	le.PutUint16(buf[4:], Major)
	le.PutUint16(buf[6:], Minor)
	buf[8] = byte(b.Kind)
	buf[9] = byte(maxLabels)
	buf[10] = byte(bits)
	le.PutUint32(buf[12:], uint32(len(recs)))
	le.PutUint64(buf[16:], uint64(total))
	le.PutUint64(buf[24:], b.CatalogVersion)
	copy(buf[32:], b.Key[:])

	// offsets[i] is the first entry of bucket i, offsets[2^bits] the count.
	bucket := func(k uint64) int { return int(k >> (64 - uint(bits))) }
	if bits == 0 {
		bucket = func(uint64) int { return 0 }
	}
	idx := 0
	for bk := 0; bk <= 1<<uint(bits); bk++ {
		for idx < len(recs) && bucket(recs[idx].key) < bk {
			idx++
		}
		le.PutUint32(buf[HeaderLen+4*bk:], uint32(idx))
	}
	for i, r := range recs {
		o := bodyStart + i*es
		le.PutUint64(buf[o:], r.key)
		switch b.Kind {
		case KindService:
			le.PutUint32(buf[o+8:], r.wire)
		case KindCategory:
			le.PutUint32(buf[o+8:], r.mask)
			buf[o+12] = r.svc
		}
	}
	if _, err := Open(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Table is a validated table. It is read-only and safe for concurrent use.
type Table struct {
	data      []byte
	kind      Kind
	maxLabels uint8
	bits      uint8
	count     int
	version   uint64
	key       [16]byte
	body      int // offset of the first entry
}

// Open validates data and returns a Table that aliases it. Like blob.Open it
// is guarded against panics and runs in O(len(data)).
func Open(data []byte) (t *Table, err error) {
	defer func() {
		if r := recover(); r != nil {
			t, err = nil, reason.New(reason.Panic, "", 0, "decoder panic")
		}
	}()
	return open(data)
}

func open(data []byte) (*Table, error) {
	if uint64(len(data)) > MaxSize {
		return nil, reason.New(reason.SizeCap, "", 0, "%d bytes", len(data))
	}
	if len(data) < HeaderLen {
		return nil, reason.New(reason.LengthMismatch, "", 0, "%d bytes, header needs %d", len(data), HeaderLen)
	}
	if string(data[:4]) != Magic {
		return nil, reason.New(reason.BadMagic, "", 0, "not a CZGT file")
	}
	if m := le.Uint16(data[4:]); m != Major {
		return nil, reason.New(reason.UnsupportedMajor, "", 4, "major %d", m)
	}
	t := &Table{data: data, kind: Kind(data[8]), maxLabels: data[9], bits: data[10]}
	if t.kind < KindFilter || t.kind > KindCategory {
		return nil, reason.New(reason.BadEnum, "", 8, "kind %d", t.kind)
	}
	if t.maxLabels > 127 {
		return nil, reason.New(reason.BadEnum, "", 9, "max_labels %d", t.maxLabels)
	}
	if t.bits > MaxBucketBits {
		return nil, reason.New(reason.BadEnum, "", 10, "bucket_bits %d", t.bits)
	}
	if data[11] != 0 || !allZero(data[48:64]) {
		return nil, reason.New(reason.BadDirectory, "", 11, "reserved bytes not zero")
	}
	t.count = int(le.Uint32(data[12:]))
	if tl := le.Uint64(data[16:]); tl != uint64(len(data)) {
		return nil, reason.New(reason.LengthMismatch, "", 16, "total_len %d, data is %d", tl, len(data))
	}
	t.version = le.Uint64(data[24:])
	copy(t.key[:], data[32:48])

	nb := 1 << t.bits
	offEnd := HeaderLen + 4*(nb+1)
	t.body = (offEnd + 7) &^ 7
	es := t.kind.entrySize()
	if uint64(t.body)+uint64(es)*uint64(t.count) != uint64(len(data)) {
		return nil, reason.New(reason.LengthMismatch, "", 12, "entry_count %d does not fit the data", t.count)
	}
	if !allZero(data[offEnd:t.body]) {
		return nil, reason.New(reason.BadSection, "offsets", uint64(offEnd), "padding not zero")
	}
	// offsets monotone, last equal to entry_count.
	prev := uint32(0)
	for i := 0; i <= nb; i++ {
		o := le.Uint32(data[HeaderLen+4*i:])
		if o < prev || uint64(o) > uint64(t.count) {
			return nil, reason.New(reason.IndexRange, "offsets", uint64(HeaderLen+4*i), "offset %d", o)
		}
		prev = o
	}
	if first := le.Uint32(data[HeaderLen:]); first != 0 {
		return nil, reason.New(reason.IndexRange, "offsets", HeaderLen, "first offset %d, want 0", first)
	}
	if int(prev) != t.count {
		return nil, reason.New(reason.IndexRange, "offsets", uint64(HeaderLen+4*nb), "last offset %d, want %d", prev, t.count)
	}
	// Entries: every key in its bucket, sorted, pads zero.
	var pk uint64
	for b := 0; b < nb; b++ {
		lo, hi := int(le.Uint32(data[HeaderLen+4*b:])), int(le.Uint32(data[HeaderLen+4*b+4:]))
		for i := lo; i < hi; i++ {
			e := data[t.body+i*es:]
			k := le.Uint64(e)
			off := uint64(t.body + i*es)
			if t.bits > 0 && int(k>>(64-uint(t.bits))) != b {
				return nil, reason.New(reason.IndexRange, "entries", off, "key outside its bucket")
			}
			if i > 0 {
				switch {
				case k < pk:
					return nil, reason.New(reason.Unsorted, "entries", off, "keys not ascending")
				case k == pk:
					switch t.kind {
					case KindFilter, KindCategory:
						return nil, reason.New(reason.Unsorted, "entries", off, "duplicate key")
					case KindService:
						if le.Uint32(e[8:]) <= le.Uint32(data[t.body+(i-1)*es+8:]) {
							return nil, reason.New(reason.Unsorted, "entries", off, "duplicate or unordered service wire")
						}
					}
				}
			}
			pk = k
			switch t.kind {
			case KindService:
				if !allZero(e[12:16]) {
					return nil, reason.New(reason.BadSection, "entries", off+12, "pad not zero")
				}
			case KindCategory:
				if !allZero(e[13:16]) {
					return nil, reason.New(reason.BadSection, "entries", off+13, "pad not zero")
				}
				if sc := e[12]; sc != 0 && (sc < 101 || sc > 112) {
					return nil, reason.New(reason.BadEnum, "entries", off+12, "service category %d", sc)
				}
			}
		}
	}
	return t, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// Kind returns the table kind.
func (t *Table) Kind() Kind { return t.kind }

// MaxLabels is the deepest name in the table. Lookups start no deeper (R36).
func (t *Table) MaxLabels() int { return int(t.maxLabels) }

// Key returns the SipHash key this table was built with.
func (t *Table) Key() [16]byte { return t.key }

// CatalogVersion returns the catalog version the table belongs to.
func (t *Table) CatalogVersion() uint64 { return t.version }

// Count is the number of entries.
func (t *Table) Count() int { return t.count }

// find returns the half-open entry range holding key.
func (t *Table) find(key uint64) (lo, hi int) {
	b := 0
	if t.bits > 0 {
		b = int(key >> (64 - uint(t.bits)))
	}
	lo, hi = int(le.Uint32(t.data[HeaderLen+4*b:])), int(le.Uint32(t.data[HeaderLen+4*b+4:]))
	es := t.kind.entrySize()
	i := lo + sort.Search(hi-lo, func(i int) bool { return le.Uint64(t.data[t.body+(lo+i)*es:]) >= key })
	j := i
	for j < hi && le.Uint64(t.data[t.body+j*es:]) == key {
		j++
	}
	return i, j
}

// Contains reports whether key is present.
func (t *Table) Contains(key uint64) bool {
	i, j := t.find(key)
	return j > i
}

// Services calls yield with the wire id of every service entry under key, in
// ascending wire order, until yield returns false.
func (t *Table) Services(key uint64, yield func(wire uint32) bool) {
	if t.kind != KindService {
		return
	}
	i, j := t.find(key)
	for ; i < j; i++ {
		if !yield(le.Uint32(t.data[t.body+i*16+8:])) {
			return
		}
	}
}

// Category returns the category fields stored under key.
func (t *Table) Category(key uint64) (mask uint32, svcCat uint8, ok bool) {
	if t.kind != KindCategory {
		return 0, 0, false
	}
	i, j := t.find(key)
	if j == i {
		return 0, 0, false
	}
	e := t.data[t.body+i*16:]
	return le.Uint32(e[8:]), e[12], true
}
