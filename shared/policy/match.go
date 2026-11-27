package policy

import (
	"context"
	"net/netip"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/names"
)

// decision is an internal verdict before synthesis.
type decision struct {
	hit       bool
	action    Action
	stage     Stage
	ref       Ref
	slot      uint8 // 1 or 2
	target    uint32
	flags     Flags
	widenable bool
	hop       uint8
	hopSet    bool
	hopName   names.Name // the name the CNAME hop matched, valid when hopSet
}

// suffixHashes caches Hash64 of each suffix of one name under one key. A query
// hashes each suffix at most once per key, however many tables it probes.
type suffixHashes struct {
	key    [16]byte
	n      *names.Name
	h      [names.MaxLabels + 1]uint64
	filled [names.MaxLabels + 1]bool
}

func (s *suffixHashes) init(key [16]byte, n *names.Name) {
	s.key, s.n = key, n
	s.filled = [names.MaxLabels + 1]bool{}
}

// get returns the hash of the suffix of k labels.
func (s *suffixHashes) get(k int) uint64 {
	if !s.filled[k] {
		s.h[k] = names.Hash64(s.key, s.n.SuffixWire(k))
		s.filled[k] = true
	}
	return s.h[k]
}

// nameCtx is one name being matched, with the hash caches for it.
type nameCtx struct {
	n  *names.Name
	ph suffixHashes // profile key
	gh suffixHashes // catalog key
}

func (ev *eval) newName(n *names.Name) *nameCtx {
	c := &nameCtx{n: n}
	c.ph.init(names.ProfileKey(), n)
	var ck [16]byte
	if ev.env.Cat != nil {
		ck = ev.env.Cat.Key
	}
	c.gh.init(ck, n)
	return c
}

// eval carries the per-query state shared by Pre and Post.
type eval struct {
	in     *Input
	st     *Stack
	env    *Env
	eff    *blob.Effective
	active [2]bool
	nact   int
	params ResolveParams

	// destinations
	aset     []netip.Addr
	asetDone bool

	trace []TraceStep
	qc    *nameCtx // the qname with its hash caches
	// missing records that a table this stack needs is not on the node.
	missing bool
}

func newEval(in *Input, st *Stack, env *Env) *eval {
	ev := &eval{in: in, st: st, env: env}
	ev.eff, ev.nact = st.options(in.Now)
	for i := 0; i < 2; i++ {
		ev.active[i] = st.active(i, in.Now)
	}
	ev.params = ev.makeParams()
	return ev
}

func (ev *eval) tr(level uint8, stage Stage, slot uint8, hit bool, detail string) {
	if ev.in.Trace {
		ev.trace = append(ev.trace, TraceStep{Level: level, Stage: stage, Slot: slot, Hit: hit, Detail: detail})
	}
}

// makeParams sets what the upstream query must carry (5.11, 6). The node
// always asks its resolver with DO=1; what the client sent only shapes the
// output, never the cache key, so one cache entry serves every client.
func (ev *eval) makeParams() ResolveParams {
	p := ResolveParams{EffectiveCD: ev.in.CD || ev.eff.DisableDNSSEC}
	src := ev.in.Src.Unmap()
	switch ev.eff.ECSMode {
	case blob.ECSAuto:
		if src.IsValid() {
			bits := int(ev.eff.ECSV4Prefix)
			if src.Is6() {
				bits = int(ev.eff.ECSV6Prefix)
			}
			if pfx, err := src.Prefix(bits); err == nil {
				p.ECS = pfx
			}
		}
	case blob.ECSCustom:
		if src.IsValid() {
			if src.Is4() && ev.eff.ECSV4Prefix > 0 {
				if pfx, err := netip.AddrFrom4(ev.eff.ECSV4).Prefix(int(ev.eff.ECSV4Prefix)); err == nil {
					p.ECS = pfx
				}
			} else if src.Is6() && ev.eff.ECSV6Prefix > 0 {
				if pfx, err := netip.AddrFrom16(ev.eff.ECSV6).Prefix(int(ev.eff.ECSV6Prefix)); err == nil {
					p.ECS = pfx
				}
			}
		}
	}
	return p
}

// ---- Level 1: custom rules --------------------------------------------------

type ruleCand struct {
	ok       bool
	slot     int // 0 or 1
	idx      int
	rule     blob.Rule
	wildcard bool
	suffixK  int // labels of the literal suffix (plain: all labels)
	litBytes int
}

// slotBestPlain finds the longest-suffix, unexpired domain rule of one slot.
func (ev *eval) slotBestPlain(c *nameCtx, p *blob.Profile) ruleCand {
	top := c.n.Labels()
	if m := int(p.Header().MaxLabels); m < top {
		top = m
	}
	for k := top; k >= 1; k-- {
		var found ruleCand
		sw := c.n.SuffixWire(k)
		p.PlainRules(c.ph.get(k), func(i int) bool {
			r := p.Rule(i)
			// A hash hit is only a candidate; the bytes decide.
			if r.Expired(ev.in.Now) || string(p.RuleName(&r)) != string(sw) {
				return true
			}
			found = ruleCand{ok: true, idx: i, rule: r, suffixK: k}
			return false
		})
		if found.ok {
			return found
		}
	}
	return ruleCand{}
}

// slotBestWild finds the wildcard rule of one slot with the deepest literal
// suffix, then the most literal bytes. The bucket is already sorted by bytes,
// so the first confirmed entry at the deepest suffix is the answer.
func (ev *eval) slotBestWild(c *nameCtx, p *blob.Profile) ruleCand {
	top := c.n.Labels()
	if m := int(p.Header().MaxLabels); m < top {
		top = m
	}
	for k := top; k >= 1; k-- {
		first, count, ok := p.WildBucket(c.ph.get(k))
		if !ok {
			continue
		}
		sw := c.n.SuffixWire(k)
		for j := first; j < first+count; j++ {
			w := p.Wild(j)
			r := p.Rule(int(w.Rule))
			if r.Expired(ev.in.Now) {
				continue
			}
			if string(p.LiteralSuffixOf(&r)) != string(sw) {
				continue // hash collision with another suffix
			}
			if !blob.WildMatches(r.Kind, p.RuleName(&r), c.n) {
				continue
			}
			return ruleCand{ok: true, idx: int(w.Rule), rule: r, wildcard: true, suffixK: k, litBytes: int(w.LitBytes)}
		}
	}
	return ruleCand{}
}

// level1 applies the specificity order of 5.5 across the active slots:
//
//  1. a plain domain rule beats any wildcard,
//  2. more labels in the literal suffix,
//  3. more literal bytes in the pattern (wildcards only),
//  4. the lower slot,
//  5. the lower rule_key bytes, which the bucket order already encodes.
//
// Tier comes first on purpose: on x.a.example.com the plain example.com beats
// *.a.example.com. That follows the plan's wording; contract section 18 lists
// it as unconfirmed against Control D.
func (ev *eval) level1(c *nameCtx) decision {
	var plain, wild [2]ruleCand
	for s := 0; s < 2; s++ {
		if !ev.active[s] {
			continue
		}
		p := ev.st.Slots[s]
		plain[s] = ev.slotBestPlain(c, p)
		plain[s].slot = s
		if !plain[s].ok {
			wild[s] = ev.slotBestWild(c, p)
			wild[s].slot = s
		}
	}
	best := ruleCand{}
	for s := 0; s < 2; s++ {
		if plain[s].ok && (!best.ok || plain[s].suffixK > best.suffixK) {
			best = plain[s]
		}
	}
	if !best.ok {
		// A slot that has a plain rule never offers a wildcard (see above), but
		// the other slot's plain rule may still beat this slot's wildcard, which
		// is handled by the loop above. Only wildcards remain here.
		for s := 0; s < 2; s++ {
			w := wild[s]
			if !w.ok {
				continue
			}
			if !best.ok || w.suffixK > best.suffixK || (w.suffixK == best.suffixK && w.litBytes > best.litBytes) {
				best = w
			}
		}
	}
	if !best.ok {
		ev.tr(1, StageRule, 0, false, "no custom rule")
		return decision{}
	}
	r := best.rule
	d := decision{
		hit: true, action: r.Action, stage: StageRule, slot: uint8(best.slot + 1),
		ref:       Ref{Kind: RefRule, ID: r.ID},
		target:    r.Target,
		widenable: !best.wildcard,
	}
	if r.Flags&blob.RuleDoNotLog != 0 {
		d.flags |= FlagDoNotLog
	}
	if r.Flags&blob.RuleLocationUnavailable != 0 {
		d.flags |= FlagLocationUnavailable
	}
	ev.tr(1, StageRule, d.slot, true, "rule")
	return d
}

// ---- Level 2: geo rules -----------------------------------------------------

// geoCursor merges the active slots' GEOR lists in level-2 order. An equal key
// takes the earlier slot first, which is how "same rule in both: earlier slot"
// falls out of one ordered walk.
type geoCursor struct {
	p   [2]*blob.Profile
	pos [2]int
	n   [2]int
}

func (ev *eval) geoCursor() *geoCursor {
	g := &geoCursor{}
	for s := 0; s < 2; s++ {
		if ev.active[s] {
			g.p[s] = ev.st.Slots[s]
			g.n[s] = g.p[s].GeoCount()
		}
	}
	return g
}

func (g *geoCursor) next() (blob.Geo, int, bool) {
	var cand [2]blob.Geo
	var have [2]bool
	for s := 0; s < 2; s++ {
		if g.p[s] != nil && g.pos[s] < g.n[s] {
			cand[s], have[s] = g.p[s].Geo(g.pos[s]), true
		}
	}
	s := -1
	switch {
	case have[0] && have[1]:
		if blob.GeoLess(cand[1], cand[0]) {
			s = 1
		} else {
			s = 0
		}
	case have[0]:
		s = 0
	case have[1]:
		s = 1
	default:
		return blob.Geo{}, 0, false
	}
	g.pos[s]++
	return cand[s], s, true
}

// level2 evaluates geo rules in total order (class, negated, value): AS before
// country before source, positive before negated. needAnswer is called lazily
// and only when a destination token is reached, so a profile with only source
// tokens never triggers a lookup.
func (ev *eval) level2(destSet func() []netip.Addr) decision {
	cur := ev.geoCursor()
	for {
		g, s, ok := cur.next()
		if !ok {
			ev.tr(2, StageGeo, 0, false, "no geo rule")
			return decision{}
		}
		r := cur.p[s].Rule(int(g.Rule))
		if r.Expired(ev.in.Now) {
			continue
		}
		if !ev.geoMatches(g, destSet) {
			continue
		}
		d := decision{
			hit: true, action: r.Action, stage: StageGeo, slot: uint8(s + 1),
			ref: Ref{Kind: RefRule, ID: r.ID}, target: r.Target, widenable: true,
		}
		if r.Flags&blob.RuleDoNotLog != 0 {
			d.flags |= FlagDoNotLog
		}
		if r.Flags&blob.RuleLocationUnavailable != 0 {
			d.flags |= FlagLocationUnavailable
		}
		ev.tr(2, StageGeo, d.slot, true, "geo rule")
		return d
	}
}

// geoMatches implements the table of 5.8. A failure, an empty answer or an
// unknown source country matches neither the positive nor the negated form:
// "not in country X" must never fire just because we know nothing.
func (ev *eval) geoMatches(g blob.Geo, destSet func() []netip.Addr) bool {
	switch g.Class {
	case 2:
		if ev.in.SrcCountry == ([2]byte{}) {
			return false
		}
		eq := ev.in.SrcCountry == g.CC
		return eq != g.Negated
	case 0, 1:
		set := destSet()
		if len(set) == 0 || ev.env.Geo == nil {
			return false
		}
		any := false
		for _, a := range set {
			if g.Class == 0 && ev.env.Geo.ASN(a) == g.ASN || g.Class == 1 && ev.env.Geo.Country(a) == g.CC {
				any = true
				break
			}
		}
		return any != g.Negated
	}
	return false
}

// destAddrs returns the A set of the qname's true answer (5.8). For a query
// that is not A it asks the resolver once, so one name gets one decision no
// matter which type was asked. The result is cached for the query.
func (ev *eval) destAddrs(ctx context.Context, ans *TrueAnswer, r Resolver) []netip.Addr {
	if ev.asetDone {
		return ev.aset
	}
	ev.asetDone = true
	var src *TrueAnswer
	if ev.in.QType == TypeA {
		src = ans
	} else if r != nil {
		a, err := r.Lookup(ctx, ev.in.Name, TypeA, ev.params)
		if err == nil {
			src = a
		}
	}
	if src == nil || src.Failed || src.RCode != RCodeNoError || ev.bogusRefused(src) {
		return nil
	}
	for i := range src.Answer {
		if src.Answer[i].Type == TypeA {
			if a, ok := src.Answer[i].Addr(); ok {
				ev.aset = append(ev.aset, a)
			}
		}
	}
	return ev.aset
}

// ---- Levels 3 and 4: global tables ------------------------------------------

// probe walks the suffixes of the name against one table. fn is called for the
// suffix-form key at every depth and for the exact-form key at the full name,
// longest first; it returns true to stop.
func (ev *eval) probeKeys(c *nameCtx, maxLabels int, fn func(key uint64, k int) bool) {
	top := c.n.Labels()
	if maxLabels < top {
		top = maxLabels
	}
	for k := top; k >= 1; k-- {
		h := c.gh.get(k)
		if k == c.n.Labels() && fn(names.ExactKey(h), k) {
			return
		}
		if fn(names.SuffixKey(h), k) {
			return
		}
	}
}

// level3 finds the enabled service with the deepest matching suffix, lowest
// wire id on a tie. Both active slots contribute their enabled services, and a
// service enabled in both uses the earlier slot's action.
func (ev *eval) level3(c *nameCtx) decision {
	cat := ev.env.Cat
	if cat == nil || cat.Services == nil {
		for s := 0; s < 2; s++ {
			if ev.active[s] && ev.st.Slots[s].ServiceCount() > 0 {
				ev.missing = true
			}
		}
		return decision{}
	}
	var best decision
	var bestWire uint32
	depthDone := -1
	ev.probeKeys(c, cat.Services.MaxLabels(), func(key uint64, k int) bool {
		if depthDone >= 0 && k != depthDone {
			return true // an enabled service already matched at a deeper suffix
		}
		cat.Services.Services(key, func(wire uint32) bool {
			for s := 0; s < 2; s++ {
				if !ev.active[s] {
					continue
				}
				sv, ok := ev.st.Slots[s].Service(wire)
				if !ok {
					continue
				}
				if !best.hit || wire < bestWire {
					best = decision{
						hit: true, action: sv.Action, stage: StageService, slot: uint8(s + 1),
						ref: Ref{Kind: RefService, Wire: wire}, target: sv.Target, widenable: true,
					}
					if sv.Flags&blob.RuleDoNotLog != 0 {
						best.flags |= FlagDoNotLog
					}
					if sv.Flags&blob.RuleLocationUnavailable != 0 {
						best.flags |= FlagLocationUnavailable
					}
					bestWire = wire
				}
				break // earlier slot wins for this wire
			}
			return true
		})
		if best.hit {
			depthDone = k
		}
		return false
	})
	ev.tr(3, StageService, best.slot, best.hit, "service")
	return best
}

// level4 applies the union of both slots' filters, lowest filter id first, then
// exfiltration (6). Native ids sort before 3rd Party ids (which start at 1000),
// so "native, 3rd party, exfiltration" is just ascending order plus the last
// step. includeExfil is false for CNAME hops: exfiltration is about what the
// client typed, and a CNAME target is chosen by the zone owner, not the client.
func (ev *eval) level4(c *nameCtx, includeExfil bool) decision {
	cat := ev.env.Cat
	type fm struct {
		id, mode uint16
		slot     uint8
	}
	var filters []fm
	var idx [2]int
	var cnt [2]int
	for s := 0; s < 2; s++ {
		if ev.active[s] {
			cnt[s] = ev.st.Slots[s].FilterCount()
		}
	}
	for {
		var id [2]uint16
		var md [2]uint16
		var have [2]bool
		for s := 0; s < 2; s++ {
			if idx[s] < cnt[s] {
				id[s], md[s] = ev.st.Slots[s].Filter(idx[s])
				have[s] = true
			}
		}
		if !have[0] && !have[1] {
			break
		}
		switch {
		case have[0] && have[1] && id[0] == id[1]:
			// Same filter in both with different modes: the earlier slot's mode.
			filters = append(filters, fm{id[0], md[0], 1})
			idx[0]++
			idx[1]++
		case have[0] && (!have[1] || id[0] < id[1]):
			filters = append(filters, fm{id[0], md[0], 1})
			idx[0]++
		default:
			filters = append(filters, fm{id[1], md[1], 2})
			idx[1]++
		}
	}
	for _, f := range filters {
		t := tableFor(cat, f.id, f.mode)
		if t == nil {
			ev.missing = true
			continue
		}
		hit := false
		ev.probeKeys(c, t.MaxLabels(), func(key uint64, _ int) bool {
			if t.Contains(key) {
				hit = true
				return true
			}
			return false
		})
		if hit {
			ev.tr(4, StageFilter, f.slot, true, "filter")
			return decision{
				hit: true, action: ActionBlock, stage: StageFilter, slot: f.slot,
				ref: Ref{Kind: RefFilter, Wire: uint32(f.id)}, target: blob.NoTarget, widenable: true,
			}

		}
	}
	if includeExfil && ev.eff.Exfiltration && exfiltration(ev.in) {
		// Attributed to the first active slot that sets the option, which is
		// the slot the merge took the value from.
		slot := uint8(1)
		for s := 0; s < 2; s++ {
			if ev.active[s] && ev.st.Slots[s].Options().Has(blob.OptExfiltration) {
				slot = uint8(s + 1)
				break
			}
		}
		ev.tr(4, StageFilter, slot, true, "exfiltration")
		return decision{
			hit: true, action: ActionBlock, stage: StageFilter, slot: slot,
			ref: Ref{Kind: RefExfiltration}, target: blob.NoTarget, widenable: true,
		}
	}
	ev.tr(4, StageFilter, 0, false, "no filter")
	return decision{}
}

// exfiltration is the provisional heuristic of contract 6 (open question 5):
// qtype NULL, a label over 40 bytes, or a name over 180 bytes in wire form.
// The thresholds are invented because the Control D feature was not inspected,
// so they live in this one function.
func exfiltration(in *Input) bool {
	if in.QType == TypeNULL || in.Name.Len() > 180 {
		return true
	}
	for i := 0; i < in.Name.Labels(); i++ {
		if len(in.Name.Label(i)) > 40 {
			return true
		}
	}
	return false
}

// ---- Level 5 -----------------------------------------------------------------

// defaultDecision picks the Default Rule: the first active slot whose default
// is Block or Redirect, else Bypass (5.6).
func (ev *eval) defaultDecision() decision {
	for s := 0; s < 2; s++ {
		if !ev.active[s] {
			continue
		}
		a, t := ev.st.Slots[s].Default()
		if a == ActionBlock || a == ActionRedirect {
			return decision{hit: true, action: a, stage: StageDefault, slot: uint8(s + 1), ref: Ref{Kind: RefDefault}, target: t, widenable: true}
		}
	}
	slot := uint8(0)
	if ev.active[0] {
		slot = 1
	} else if ev.active[1] {
		slot = 2
	}
	return decision{hit: true, action: ActionBypass, stage: StageDefault, slot: slot, ref: Ref{Kind: RefDefault}, target: blob.NoTarget, widenable: true}
}

// explicitMatch evaluates levels 1, 3 and 4 for one CNAME hop, in order. The
// first match, Bypass included, is the verdict. Level 2 is skipped because it
// does not depend on the name and already ran for the qname.
func (ev *eval) explicitMatch(n *names.Name) decision {
	c := ev.newName(n)
	if d := ev.level1(c); d.hit {
		return d
	}
	if d := ev.level3(c); d.hit {
		return d
	}
	return ev.level4(c, false)
}
