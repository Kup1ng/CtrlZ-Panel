package blob

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

// TargetSpec describes where a Redirect goes.
type TargetSpec struct {
	Kind     TargetKind
	Location uint16     // TargetLocation
	Set      []uint16   // TargetAuto and TargetRandom: the effective location set
	Host     []byte     // TargetHost: canonical wire name
	V4, V6   netip.Addr // TargetIP: either or both
}

// RuleSpec is one compiled rule. Enabled and unexpired filtering, `inherit`
// resolution and folder flags are the compiler's job; the blob holds only
// resolved actions (4).
type RuleSpec struct {
	ID                  [16]byte
	Pattern             rules.Pattern
	Action              Action
	Target              *TargetSpec
	ExpiresAt           int64
	DoNotLog            bool
	LocationUnavailable bool
}

// ServiceSpec is one enabled service.
type ServiceSpec struct {
	Wire                uint32
	Action              Action
	Target              *TargetSpec
	DoNotLog            bool
	LocationUnavailable bool
}

// FilterSpec is one enabled filter at one mode.
type FilterSpec struct{ FilterID, ModeWire uint16 }

// Spec is everything a profile blob holds.
type Spec struct {
	DisabledUntil int64
	Options       Options
	Default       Action // ActNone means null
	DefaultTarget *TargetSpec
	Rules         []RuleSpec
	Services      []ServiceSpec
	Filters       []FilterSpec
}

// Build returns the deterministic CZPB bytes for s: the same spec always gives
// the same bytes, with no timestamps, sorted content and zero padding, so
// identical profiles share one hash. It re-opens its own output so the builder
// can never emit a file the reader rejects.
func Build(s *Spec) ([]byte, error) {
	b := &builder{s: s, strOff: map[string]uint32{}, setOff: map[string]uint32{}, tgtIdx: map[string]uint32{}}
	out, err := b.build()
	if err != nil {
		return nil, err
	}
	if _, err := Open(out); err != nil {
		return nil, fmt.Errorf("blob: builder produced an invalid blob: %w", err)
	}
	return out, nil
}

type builder struct {
	s      *Spec
	strs   []byte
	strOff map[string]uint32
	lset   []byte
	setOff map[string]uint32
	targ   []byte
	tgtIdx map[string]uint32
}

func (b *builder) build() ([]byte, error) {
	s := b.s
	// Rules ordered by (kind, key). Keys are unique per profile.
	type keyed struct {
		spec *RuleSpec
		key  string
	}
	ks := make([]keyed, len(s.Rules))
	seen := map[string]bool{}
	for i := range s.Rules {
		r := &s.Rules[i]
		k := r.Pattern.Key()
		if k == "" || seen[k] {
			return nil, fmt.Errorf("blob: empty or duplicate rule_key %q", k)
		}
		seen[k] = true
		ks[i] = keyed{r, k}
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].spec.Pattern.Kind != ks[j].spec.Pattern.Kind {
			return ks[i].spec.Pattern.Kind < ks[j].spec.Pattern.Kind
		}
		return ks[i].key < ks[j].key
	})

	// Pools first: strings, location sets, targets. Collect before encoding so
	// pool order depends only on content.
	var strSet []string
	addStr := func(w []byte) { strSet = append(strSet, string(w)) }
	var tspecs []*TargetSpec
	for _, k := range ks {
		if k.spec.Pattern.Kind.IsName() {
			addStr(k.spec.Pattern.Wire)
		}
		tspecs = append(tspecs, k.spec.Target)
	}
	for i := range s.Services {
		tspecs = append(tspecs, s.Services[i].Target)
	}
	tspecs = append(tspecs, s.DefaultTarget)
	var sets [][]uint16
	for _, t := range tspecs {
		if t == nil {
			continue
		}
		if t.Kind == TargetHost {
			addStr(t.Host)
		}
		if t.Kind == TargetAuto || t.Kind == TargetRandom {
			set := append([]uint16(nil), t.Set...)
			sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
			for i := 1; i < len(set); i++ {
				if set[i] == set[i-1] {
					return nil, errors.New("blob: duplicate location in a set")
				}
			}
			sets = append(sets, set)
		}
	}
	sort.Strings(strSet)
	for i, v := range strSet {
		if i > 0 && v == strSet[i-1] {
			continue
		}
		b.strOff[v] = uint32(len(b.strs))
		b.strs = append(b.strs, v...)
	}
	enc := func(set []uint16) string {
		buf := make([]byte, 2+2*len(set))
		le.PutUint16(buf, uint16(len(set)))
		for i, v := range set {
			le.PutUint16(buf[2+2*i:], v)
		}
		return string(buf)
	}
	var setEnc []string
	for _, set := range sets {
		setEnc = append(setEnc, enc(set))
	}
	sort.Strings(setEnc)
	for i, v := range setEnc {
		if i > 0 && v == setEnc[i-1] {
			continue
		}
		b.setOff[v] = uint32(len(b.lset))
		b.lset = append(b.lset, v...)
	}

	// Targets: encode, dedupe, sort by record bytes.
	recFor := func(t *TargetSpec) (string, error) {
		var r [sizeTARG]byte
		r[0] = byte(t.Kind)
		switch t.Kind {
		case TargetLocation:
			le.PutUint16(r[2:], t.Location)
		case TargetAuto, TargetRandom:
			set := append([]uint16(nil), t.Set...)
			sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
			le.PutUint32(r[4:], b.setOff[enc(set)])
		case TargetHost:
			le.PutUint32(r[8:], b.strOff[string(t.Host)])
			le.PutUint16(r[12:], uint16(len(t.Host)))
		case TargetIP:
			if t.V4.IsValid() {
				if !t.V4.Is4() {
					return "", errors.New("blob: V4 is not an IPv4 address")
				}
				r[1] |= 1
				a := t.V4.As4()
				copy(r[16:], a[:])
			}
			if t.V6.IsValid() {
				if !t.V6.Is6() || t.V6.Is4In6() {
					return "", errors.New("blob: V6 is not an IPv6 address")
				}
				r[1] |= 2
				a := t.V6.As16()
				copy(r[20:], a[:])
			}
		default:
			return "", fmt.Errorf("blob: bad target kind %d", t.Kind)
		}
		return string(r[:]), nil
	}
	var recs []string
	recOf := map[*TargetSpec]string{}
	for _, t := range tspecs {
		if t == nil {
			continue
		}
		if _, ok := recOf[t]; ok {
			continue
		}
		r, err := recFor(t)
		if err != nil {
			return nil, err
		}
		recOf[t] = r
		recs = append(recs, r)
	}
	sort.Strings(recs)
	for i, r := range recs {
		if i > 0 && r == recs[i-1] {
			continue
		}
		b.tgtIdx[r] = uint32(len(b.targ) / sizeTARG)
		b.targ = append(b.targ, r...)
	}
	tidx := func(t *TargetSpec) uint32 {
		if t == nil {
			return NoTarget
		}
		return b.tgtIdx[recOf[t]]
	}
	chk := func(a Action, t *TargetSpec) error {
		if a < ActBlock || a > ActRedirect {
			return fmt.Errorf("blob: bad action %d", a)
		}
		if (a == ActRedirect) != (t != nil) {
			return errors.New("blob: a target is required for Redirect and only for Redirect")
		}
		return nil
	}

	// RULE.
	rulesB := make([]byte, 0, len(ks)*sizeRULE)
	maxLabels := 0
	destGeo := false
	type plix struct {
		h    uint64
		rule uint32
	}
	var plixes []plix
	type wild struct {
		h        uint64
		rule     uint32
		kind     rules.Kind
		labels   uint8
		litBytes uint16
		key      string
	}
	var wilds []wild
	type geo struct {
		g    Geo
		rule uint32
	}
	var geos []geo
	hkey := names.ProfileKey()
	for i, k := range ks {
		r := k.spec
		p := &r.Pattern
		if err := chk(r.Action, r.Target); err != nil {
			return nil, fmt.Errorf("rule %q: %w", k.key, err)
		}
		var rec [sizeRULE]byte
		copy(rec[0:], r.ID[:])
		le.PutUint64(rec[16:], uint64(r.ExpiresAt))
		if p.Kind.IsName() {
			le.PutUint32(rec[24:], b.strOff[string(p.Wire)])
			le.PutUint16(rec[28:], uint16(len(p.Wire)))
		}
		rec[30] = byte(p.Kind)
		rec[31] = byte(r.Action)
		if r.DoNotLog {
			rec[32] |= RuleDoNotLog
		}
		if r.LocationUnavailable {
			rec[32] |= RuleLocationUnavailable
		}
		le.PutUint32(rec[36:], tidx(r.Target))
		rulesB = append(rulesB, rec[:]...)

		switch p.Kind {
		case rules.KindDomain:
			plixes = append(plixes, plix{names.Hash64(hkey, p.Wire), uint32(i)})
			if p.LitLabels > maxLabels {
				maxLabels = p.LitLabels
			}
		case rules.KindSubdomains, rules.KindGlob:
			if p.Labels > 255 || p.LitBytes > 0xFFFF {
				return nil, fmt.Errorf("rule %q: pattern too large", k.key)
			}
			wilds = append(wilds, wild{names.Hash64(hkey, p.LiteralSuffix()), uint32(i), p.Kind, uint8(p.Labels), uint16(p.LitBytes), k.key})
			if p.LitLabels > maxLabels {
				maxLabels = p.LitLabels
			}
		case rules.KindDestCC, rules.KindDestAS, rules.KindSrcCC:
			g := Geo{Negated: p.Negated, CC: p.CC, ASN: p.ASN}
			switch p.Kind {
			case rules.KindDestAS:
				g.Class = 0
				destGeo = true
			case rules.KindDestCC:
				g.Class = 1
				destGeo = true
			default:
				g.Class = 2
			}
			geos = append(geos, geo{g, uint32(i)})
		default:
			return nil, fmt.Errorf("rule %q: bad kind", k.key)
		}
	}
	if maxLabels > 127 {
		return nil, errors.New("blob: literal suffix deeper than 127 labels")
	}

	sort.Slice(plixes, func(i, j int) bool {
		if plixes[i].h != plixes[j].h {
			return plixes[i].h < plixes[j].h
		}
		return plixes[i].rule < plixes[j].rule
	})
	plixB := make([]byte, 0, len(plixes)*sizePLIX)
	for _, e := range plixes {
		var rec [sizePLIX]byte
		le.PutUint64(rec[0:], e.h)
		le.PutUint32(rec[8:], e.rule)
		plixB = append(plixB, rec[:]...)
	}

	// Wildcard buckets: by suffix hash; inside a bucket, more literal bytes
	// first, then rule_key bytes (5.5 rules 3 and 5).
	sort.Slice(wilds, func(i, j int) bool {
		a, c := wilds[i], wilds[j]
		if a.h != c.h {
			return a.h < c.h
		}
		if a.litBytes != c.litBytes {
			return a.litBytes > c.litBytes
		}
		return a.key < c.key
	})
	var wbktB, wildB []byte
	for i := 0; i < len(wilds); {
		j := i
		for j < len(wilds) && wilds[j].h == wilds[i].h {
			j++
		}
		if j-i > MaxBucket {
			return nil, fmt.Errorf("blob: %d wildcard rules share one suffix (max %d)", j-i, MaxBucket)
		}
		var rec [sizeWBKT]byte
		le.PutUint64(rec[0:], wilds[i].h)
		le.PutUint32(rec[8:], uint32(i))
		le.PutUint32(rec[12:], uint32(j-i))
		wbktB = append(wbktB, rec[:]...)
		i = j
	}
	for _, w := range wilds {
		var rec [sizeWILD]byte
		le.PutUint32(rec[0:], w.rule)
		rec[4] = byte(w.kind)
		rec[5] = w.labels
		le.PutUint16(rec[6:], w.litBytes)
		wildB = append(wildB, rec[:]...)
	}

	sort.Slice(geos, func(i, j int) bool { return GeoLess(geos[i].g, geos[j].g) })
	var georB []byte
	for _, e := range geos {
		var rec [sizeGEOR]byte
		rec[0] = e.g.Class
		if e.g.Negated {
			rec[1] = 1
		}
		copy(rec[2:], e.g.CC[:])
		le.PutUint32(rec[4:], e.g.ASN)
		le.PutUint32(rec[8:], e.rule)
		georB = append(georB, rec[:]...)
	}

	svcs := append([]ServiceSpec(nil), s.Services...)
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Wire < svcs[j].Wire })
	var svcsB []byte
	for i, sv := range svcs {
		if i > 0 && svcs[i-1].Wire == sv.Wire {
			return nil, fmt.Errorf("blob: service %d listed twice", sv.Wire)
		}
		if err := chk(sv.Action, sv.Target); err != nil {
			return nil, fmt.Errorf("service %d: %w", sv.Wire, err)
		}
		var rec [sizeSVCS]byte
		le.PutUint32(rec[0:], sv.Wire)
		rec[4] = byte(sv.Action)
		if sv.DoNotLog {
			rec[5] |= RuleDoNotLog
		}
		if sv.LocationUnavailable {
			rec[5] |= RuleLocationUnavailable
		}
		le.PutUint32(rec[8:], tidx(sv.Target))
		svcsB = append(svcsB, rec[:]...)
	}

	flts := append([]FilterSpec(nil), s.Filters...)
	sort.Slice(flts, func(i, j int) bool { return flts[i].FilterID < flts[j].FilterID })
	var fltsB []byte
	for i, f := range flts {
		if i > 0 && flts[i-1].FilterID == f.FilterID {
			return nil, fmt.Errorf("blob: filter %d listed twice", f.FilterID)
		}
		var rec [sizeFLTS]byte
		le.PutUint16(rec[0:], f.FilterID)
		le.PutUint16(rec[2:], f.ModeWire)
		fltsB = append(fltsB, rec[:]...)
	}

	var dflt [sizeDFLT]byte
	dflt[0] = byte(s.Default)
	le.PutUint32(dflt[4:], NoTarget)
	if s.Default != ActNone {
		if err := chk(s.Default, s.DefaultTarget); err != nil {
			return nil, fmt.Errorf("default rule: %w", err)
		}
		le.PutUint32(dflt[4:], tidx(s.DefaultTarget))
	} else if s.DefaultTarget != nil {
		return nil, errors.New("blob: target on a null default rule")
	}

	opts := s.Options.Marshal()

	// Assemble. Sections in id order, each at the next 8-byte boundary.
	secs := [numSecs][]byte{}
	secs[SecOPTS], secs[SecDFLT], secs[SecTARG], secs[SecLSET] = opts[:], dflt[:], b.targ, b.lset
	secs[SecSTRS], secs[SecRULE], secs[SecPLIX], secs[SecWBKT] = b.strs, rulesB, plixB, wbktB
	secs[SecWILD], secs[SecGEOR], secs[SecSVCS], secs[SecFLTS] = wildB, georB, svcsB, fltsB

	count := numSecs - 1
	var body bytes.Buffer
	pos := uint64(HeaderLen + 16*count)
	dir := make([]byte, 16*count)
	for id := 1; id < numSecs; id++ {
		aligned := (pos + 7) &^ 7
		body.Write(make([]byte, aligned-pos))
		pos = aligned
		o := 16 * (id - 1)
		le.PutUint32(dir[o:], uint32(id))
		le.PutUint32(dir[o+4:], 1) // every section of 1.0 is required
		le.PutUint32(dir[o+8:], uint32(pos))
		le.PutUint32(dir[o+12:], uint32(len(secs[id])))
		body.Write(secs[id])
		pos += uint64(len(secs[id]))
	}
	if pos > MaxSize {
		return nil, fmt.Errorf("blob: %d bytes exceeds the %d byte cap", pos, MaxSize)
	}

	out := make([]byte, HeaderLen, pos)
	copy(out, Magic)
	le.PutUint16(out[4:], Major)
	le.PutUint16(out[6:], Minor)
	le.PutUint32(out[8:], HeaderLen)
	le.PutUint32(out[12:], uint32(count))
	le.PutUint64(out[16:], pos)
	le.PutUint32(out[24:], uint32(len(ks)))
	le.PutUint32(out[28:], uint32(len(wilds)))
	out[32] = byte(maxLabels)
	var flags byte
	if destGeo {
		flags |= FlagHasDestGeo
	}
	if len(ks) > 0 || len(svcs) > 0 || len(flts) > 0 || s.Options.Bool(OptExfiltration) {
		flags |= FlagExplicit
	}
	out[33] = flags
	le.PutUint64(out[40:], uint64(s.DisabledUntil))
	out = append(out, dir...)
	out = append(out, body.Bytes()...)
	return out, nil
}
