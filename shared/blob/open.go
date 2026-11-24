package blob

import (
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
)

// Open validates data and returns a Profile that aliases it.
//
// All checks of contract 9.3 run here, in O(len(data)), without recursion and
// without sizing any allocation from a value read out of the file other than
// through the record counts that the section lengths already bound. A panic
// anywhere in the decoder is turned into reason.Panic: an untrusted blob must
// never take the node down (9.7).
func Open(data []byte) (p *Profile, err error) {
	defer func() {
		if r := recover(); r != nil {
			p, err = nil, reason.New(reason.Panic, "", 0, "decoder panic")
		}
	}()
	return open(data)
}

type dirEntry struct {
	id, flags, off, length uint32
}

func open(data []byte) (*Profile, error) {
	if len(data) > MaxSize {
		return nil, reason.New(reason.SizeCap, "", 0, "%d bytes exceeds %d", len(data), MaxSize)
	}
	// 1. Header.
	if len(data) < HeaderLen {
		return nil, reason.New(reason.LengthMismatch, "", 0, "%d bytes, header needs %d", len(data), HeaderLen)
	}
	if string(data[0:4]) != Magic {
		return nil, reason.New(reason.BadMagic, "", 0, "not a CZPB file")
	}
	var h Header
	h.Major, h.Minor = le.Uint16(data[4:]), le.Uint16(data[6:])
	// 2. Version. A higher minor is allowed: it may only add optional sections.
	if h.Major != Major {
		return nil, reason.New(reason.UnsupportedMajor, "", 4, "major %d", h.Major)
	}
	if hl := le.Uint32(data[8:]); hl != HeaderLen {
		return nil, reason.New(reason.LengthMismatch, "", 8, "header_len %d", hl)
	}
	h.SectionCount = le.Uint32(data[12:])
	h.TotalLen = le.Uint64(data[16:])
	if h.TotalLen != uint64(len(data)) {
		return nil, reason.New(reason.LengthMismatch, "", 16, "total_len %d, data is %d", h.TotalLen, len(data))
	}
	h.RuleCount, h.WildCount = le.Uint32(data[24:]), le.Uint32(data[28:])
	h.MaxLabels, h.Flags = data[32], data[33]
	if le.Uint16(data[34:]) != 0 || le.Uint32(data[36:]) != 0 {
		return nil, reason.New(reason.BadDirectory, "", 34, "reserved header bytes not zero")
	}
	if h.Flags&^(FlagHasDestGeo|FlagExplicit) != 0 {
		return nil, reason.New(reason.BadEnum, "", 33, "unknown header flags %#x", h.Flags)
	}
	if h.MaxLabels > 127 {
		return nil, reason.New(reason.BadEnum, "", 32, "max_labels %d", h.MaxLabels)
	}
	h.DisabledUntil = int64(le.Uint64(data[40:]))

	// 3. Directory.
	if h.SectionCount < 1 || h.SectionCount > maxSecs {
		return nil, reason.New(reason.BadDirectory, "", 12, "section_count %d", h.SectionCount)
	}
	dirEnd := uint64(HeaderLen) + 16*uint64(h.SectionCount)
	if dirEnd > uint64(len(data)) {
		return nil, reason.New(reason.BadDirectory, "", HeaderLen, "directory runs past the end")
	}
	p := &Profile{data: data, hdr: h, hash: contentHash(data)}
	cursor := dirEnd // end of the previous section; bytes up to the next one must be zero padding
	var prevID uint32
	var present [numSecs]bool
	for i := uint32(0); i < h.SectionCount; i++ {
		o := HeaderLen + 16*int(i)
		d := dirEntry{le.Uint32(data[o:]), le.Uint32(data[o+4:]), le.Uint32(data[o+8:]), le.Uint32(data[o+12:])}
		if d.id == 0 || (i > 0 && d.id <= prevID) {
			return nil, reason.New(reason.BadDirectory, "", uint64(o), "section ids not strictly ascending")
		}
		prevID = d.id
		if d.flags&^1 != 0 {
			return nil, reason.New(reason.BadDirectory, "", uint64(o+4), "unknown directory flags %#x", d.flags)
		}
		if d.off%8 != 0 {
			return nil, reason.New(reason.BadDirectory, "", uint64(o+8), "section %d not 8-byte aligned", d.id)
		}
		end := uint64(d.off) + uint64(d.length)
		if end > uint64(len(data)) {
			return nil, reason.New(reason.BadDirectory, "", uint64(o+8), "section %d runs past the end", d.id)
		}
		if uint64(d.off) < cursor {
			return nil, reason.New(reason.BadDirectory, "", uint64(o+8), "section %d overlaps the previous one", d.id)
		}
		if !allZero(data[cursor:d.off]) {
			return nil, reason.New(reason.BadDirectory, "", cursor, "padding before section %d is not zero", d.id)
		}
		cursor = end
		if d.id >= numSecs {
			// Unknown section: a required one means this reader cannot
			// understand the file; an optional one is skipped.
			if d.flags&1 != 0 {
				return nil, reason.New(reason.UnsupportedSection, "", uint64(o), "required unknown section %d", d.id)
			}
			continue
		}
		present[d.id] = true
		p.sec[d.id] = data[d.off:end:end]
	}
	// 10. Nothing follows the last section.
	if cursor != uint64(len(data)) {
		return nil, reason.New(reason.LengthMismatch, "", cursor, "%d trailing bytes after the last section", uint64(len(data))-cursor)
	}
	for id := 1; id < numSecs; id++ {
		if !present[id] {
			return nil, reason.New(reason.MissingSection, secName(id), 0, "required section absent")
		}
	}

	// 4. Record sizes.
	for id := 1; id < numSecs; id++ {
		if rs := recSize(id); rs > 0 && len(p.sec[id])%rs != 0 {
			return nil, reason.New(reason.BadSection, secName(id), 0, "length %d is not a multiple of %d", len(p.sec[id]), rs)
		}
	}
	if len(p.sec[SecOPTS]) != sizeOPTS {
		return nil, reason.New(reason.BadSection, "OPTS", 0, "must hold exactly one record")
	}
	if len(p.sec[SecDFLT]) != sizeDFLT {
		return nil, reason.New(reason.BadSection, "DFLT", 0, "must hold exactly one record")
	}
	// 5. Counts agree with the header.
	nRule := len(p.sec[SecRULE]) / sizeRULE
	nWild := len(p.sec[SecWILD]) / sizeWILD
	if uint64(nRule) != uint64(h.RuleCount) || uint64(nWild) != uint64(h.WildCount) {
		return nil, reason.New(reason.LengthMismatch, "", 24, "header counts %d/%d, sections hold %d/%d", h.RuleCount, h.WildCount, nRule, nWild)
	}

	var err error
	if p.opts, err = ParseOptions(p.sec[SecOPTS]); err != nil {
		return nil, err
	}
	if err := p.checkDefault(); err != nil {
		return nil, err
	}
	starts, err := checkLSET(p.sec[SecLSET])
	if err != nil {
		return nil, err
	}
	if err := p.checkTargets(starts); err != nil {
		return nil, err
	}
	rs, err := p.checkRules()
	if err != nil {
		return nil, err
	}
	if err := p.checkIndexes(rs); err != nil {
		return nil, err
	}
	if err := p.checkServices(); err != nil {
		return nil, err
	}
	if err := p.checkFlags(rs); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Profile) targetOK(sec string, off uint64, action Action, target uint32) error {
	if action < ActBlock || action > ActRedirect {
		return reason.New(reason.BadEnum, sec, off, "action %d", action)
	}
	if action == ActRedirect {
		if target == NoTarget || uint64(target) >= uint64(len(p.sec[SecTARG])/sizeTARG) {
			return reason.New(reason.IndexRange, sec, off, "redirect target %d", target)
		}
	} else if target != NoTarget {
		return reason.New(reason.BadEnum, sec, off, "target on a non-redirect action")
	}
	return nil
}

func (p *Profile) checkDefault() error {
	b := p.sec[SecDFLT]
	a := Action(b[0])
	if !allZero(b[1:4]) {
		return reason.New(reason.BadSection, "DFLT", 1, "pad not zero")
	}
	t := le.Uint32(b[4:])
	if a == ActNone {
		if t != NoTarget {
			return reason.New(reason.BadEnum, "DFLT", 4, "target on a null default")
		}
	} else if err := p.targetOK("DFLT", 0, a, t); err != nil {
		return err
	}
	p.dflt, p.dtgt = a, t
	return nil
}

// checkLSET walks the pool as consecutive sets and returns their start
// offsets, which are the only legal values of set_off.
func checkLSET(b []byte) ([]uint32, error) {
	var starts []uint32
	for off := 0; off < len(b); {
		if off+2 > len(b) {
			return nil, reason.New(reason.BadSection, "LSET", uint64(off), "truncated set header")
		}
		n := int(le.Uint16(b[off:]))
		if off+2+2*n > len(b) {
			return nil, reason.New(reason.IndexRange, "LSET", uint64(off), "set of %d runs past the pool", n)
		}
		var prev int = -1
		for i := 0; i < n; i++ {
			v := int(le.Uint16(b[off+2+2*i:]))
			if v <= prev {
				return nil, reason.New(reason.Unsorted, "LSET", uint64(off+2+2*i), "location ids not strictly ascending")
			}
			prev = v
		}
		starts = append(starts, uint32(off))
		off += 2 + 2*n
	}
	return starts, nil
}

func (p *Profile) checkTargets(setStarts []uint32) error {
	b := p.sec[SecTARG]
	strs := p.sec[SecSTRS]
	for i := 0; i < len(b)/sizeTARG; i++ {
		r := b[i*sizeTARG : (i+1)*sizeTARG]
		off := uint64(i * sizeTARG)
		kind, flags := TargetKind(r[0]), r[1]
		if kind < TargetLocation || kind > TargetHost {
			return reason.New(reason.BadEnum, "TARG", off, "kind %d", kind)
		}
		if flags&^3 != 0 {
			return reason.New(reason.BadEnum, "TARG", off+1, "flags %#x", flags)
		}
		if !allZero(r[14:16]) || !allZero(r[36:40]) {
			return reason.New(reason.BadSection, "TARG", off, "pad not zero")
		}
		setOff, hostOff, hostLen := le.Uint32(r[4:]), le.Uint32(r[8:]), le.Uint16(r[12:])
		isSet := kind == TargetAuto || kind == TargetRandom
		if isSet {
			j := searchU32(setStarts, setOff)
			if j < 0 {
				return reason.New(reason.IndexRange, "TARG", off+4, "set_off %d is not a set start", setOff)
			}
		} else if setOff != 0 {
			return reason.New(reason.BadEnum, "TARG", off+4, "set_off on a non-set target")
		}
		if kind == TargetHost {
			if hostLen == 0 || uint64(hostOff)+uint64(hostLen) > uint64(len(strs)) {
				return reason.New(reason.IndexRange, "TARG", off+8, "host range")
			}
			if _, err := checkPlainName(strs[hostOff : hostOff+uint32(hostLen)]); err != nil {
				return reason.New(reason.BadName, "TARG", off+8, "%v", err)
			}
		} else if hostOff != 0 || hostLen != 0 {
			return reason.New(reason.BadEnum, "TARG", off+8, "host data on a non-host target")
		}
		if kind == TargetIP {
			if flags == 0 {
				return reason.New(reason.BadEnum, "TARG", off+1, "ip target with no address")
			}
		} else if flags != 0 {
			return reason.New(reason.BadEnum, "TARG", off+1, "address flags on a non-ip target")
		}
		if flags&1 == 0 && !allZero(r[16:20]) || flags&2 == 0 && !allZero(r[20:36]) {
			return reason.New(reason.BadSection, "TARG", off+16, "address bytes without their flag")
		}
		if kind != TargetLocation && le.Uint16(r[2:]) != 0 {
			return reason.New(reason.BadEnum, "TARG", off+2, "location on a non-location target")
		}
	}
	return nil
}

func searchU32(sorted []uint32, v uint32) int {
	lo, hi := 0, len(sorted)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if sorted[m] < v {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < len(sorted) && sorted[lo] == v {
		return lo
	}
	return -1
}

// checkPlainName requires canonical wire form: valid labels, already folded,
// no '*', not the root. It returns the label count.
func checkPlainName(w []byte) (int, error) {
	n, err := names.FromCanonicalWire(w)
	if err != nil {
		return 0, err
	}
	if string(n.Wire()) != string(w) {
		return 0, errNotCanonical
	}
	if n.IsRoot() {
		return 0, errRootRule
	}
	for i := 0; i < n.Labels(); i++ {
		for _, c := range n.Label(i) {
			if c == '*' {
				return 0, errStarInPlain
			}
		}
	}
	return n.Labels(), nil
}

// ruleInfo is what checkRules learned about each rule, reused by later checks.
type ruleInfo struct {
	litSuffix []byte // wildcard literal suffix, nil otherwise
	labels    int    // pattern label count (wildcards and domains)
	litLabels int    // labels right of the star, or all labels for a domain
	litBytes  int
}

func (p *Profile) checkRules() ([]ruleInfo, error) {
	n := p.RuleCount()
	info := make([]ruleInfo, n)
	strs := p.sec[SecSTRS]
	for i := 0; i < n; i++ {
		r := p.Rule(i)
		off := uint64(i * sizeRULE)
		b := p.sec[SecRULE][i*sizeRULE:]
		if !allZero(b[33:36]) {
			return nil, reason.New(reason.BadSection, "RULE", off+33, "pad not zero")
		}
		if r.Flags&^(RuleDoNotLog|RuleLocationUnavailable) != 0 {
			return nil, reason.New(reason.BadEnum, "RULE", off+32, "flags %#x", r.Flags)
		}
		if r.Kind < rules.KindDomain || r.Kind > rules.KindSrcCC {
			return nil, reason.New(reason.BadEnum, "RULE", off+30, "kind %d", r.Kind)
		}
		if err := p.targetOK("RULE", off, r.Action, r.Target); err != nil {
			return nil, err
		}
		if !r.Kind.IsName() {
			if r.NameOff != 0 || r.NameLen != 0 {
				return nil, reason.New(reason.BadName, "RULE", off+24, "geo rule has a name")
			}
			continue
		}
		if r.NameLen == 0 || uint64(r.NameOff)+uint64(r.NameLen) > uint64(len(strs)) {
			return nil, reason.New(reason.IndexRange, "RULE", off+24, "name range")
		}
		w := strs[r.NameOff : r.NameOff+uint32(r.NameLen)]
		switch r.Kind {
		case rules.KindDomain, rules.KindSubdomains:
			labels, err := checkPlainName(w)
			if err != nil {
				return nil, reason.New(reason.BadName, "RULE", off+24, "%v", err)
			}
			in := ruleInfo{litSuffix: nil, litLabels: labels}
			in.litBytes = len(w) - 1 - labels
			if r.Kind == rules.KindSubdomains {
				in.litSuffix = w
				in.labels = labels + 1
			} else {
				in.labels = labels
			}
			info[i] = in
		case rules.KindGlob:
			in, err := checkGlob(w)
			if err != nil {
				return nil, reason.New(reason.BadName, "RULE", off+24, "%v", err)
			}
			info[i] = in
		}
	}
	return info, nil
}

func checkGlob(w []byte) (ruleInfo, error) {
	n, err := names.FromCanonicalWire(w)
	if err != nil {
		return ruleInfo{}, err
	}
	if string(n.Wire()) != string(w) {
		return ruleInfo{}, errNotCanonical
	}
	if n.IsRoot() {
		return ruleInfo{}, errRootRule
	}
	star, stars := -1, 0
	lit := 0
	for i := 0; i < n.Labels(); i++ {
		in := 0
		for _, c := range n.Label(i) {
			if c == '*' {
				in++
			} else {
				lit++
			}
		}
		if in > 0 {
			star = i
			stars += in
		}
	}
	if stars != 1 {
		return ruleInfo{}, errStarCount
	}
	if star == n.Labels()-1 {
		return ruleInfo{}, errNoLiteral
	}
	if star == 0 && len(n.Label(0)) == 1 {
		// "*.x" is the subdomains kind, not a glob; accepting it here would give
		// one pattern two meanings.
		return ruleInfo{}, errGlobIsSub
	}
	return ruleInfo{
		litSuffix: n.SuffixWire(n.Labels() - star - 1),
		labels:    n.Labels(),
		litLabels: n.Labels() - star - 1,
		litBytes:  lit,
	}, nil
}

type nameErr string

func (e nameErr) Error() string { return string(e) }

const (
	errNotCanonical nameErr = "name is not in canonical (folded) wire form"
	errRootRule     nameErr = "the root name cannot be a rule"
	errStarInPlain  nameErr = "'*' in a non-glob name"
	errStarCount    nameErr = "glob must hold exactly one '*'"
	errNoLiteral    nameErr = "glob has no literal suffix"
	errGlobIsSub    nameErr = "glob pattern '*.x' must be the subdomains kind"
)

// checkIndexes validates PLIX, WBKT, WILD and GEOR against RULE.
func (p *Profile) checkIndexes(ri []ruleInfo) error {
	nRule := len(ri)
	key := names.ProfileKey()

	// PLIX: every domain rule exactly once, hash right, strictly ascending.
	plix := p.sec[SecPLIX]
	nDomain := 0
	for i := 0; i < nRule; i++ {
		if p.Rule(i).Kind == rules.KindDomain {
			nDomain++
		}
	}
	if len(plix)/sizePLIX != nDomain {
		return reason.New(reason.IndexRange, "PLIX", 0, "%d entries for %d domain rules", len(plix)/sizePLIX, nDomain)
	}
	seen := make([]bool, nRule)
	var prevH uint64
	var prevR uint32
	// run is the rules whose name hashes to the current hash. A name appears
	// once (Build refuses duplicates), so a repeat is a hostile or buggy blob;
	// and a run is bounded, or a query on that name would walk them all (review
	// L2-F17: 800,000 expired rules on one name cost 30 ms per query).
	var run []uint32
	for i := 0; i < len(plix)/sizePLIX; i++ {
		e := plix[i*sizePLIX:]
		h, r := le.Uint64(e), le.Uint32(e[8:])
		off := uint64(i * sizePLIX)
		if !allZero(e[12:16]) {
			return reason.New(reason.BadSection, "PLIX", off+12, "pad not zero")
		}
		if uint64(r) >= uint64(nRule) {
			return reason.New(reason.IndexRange, "PLIX", off+8, "rule %d", r)
		}
		rule := p.Rule(int(r))
		if rule.Kind != rules.KindDomain || seen[r] {
			return reason.New(reason.IndexRange, "PLIX", off+8, "rule %d is not a unique domain rule", r)
		}
		seen[r] = true
		if i > 0 && (h < prevH || (h == prevH && r <= prevR)) {
			return reason.New(reason.Unsorted, "PLIX", off, "not sorted by (hash, rule)")
		}
		if i > 0 && h == prevH {
			if len(run) >= MaxPlainRun {
				return reason.New(reason.SizeCap, "PLIX", off, "more than %d plain rules share one hash", MaxPlainRun)
			}
			name := p.RuleName(&rule)
			for _, q := range run {
				other := p.Rule(int(q))
				if string(p.RuleName(&other)) == string(name) {
					return reason.New(reason.BadSection, "PLIX", off, "rules %d and %d have the same name", q, r)
				}
			}
		} else {
			run = run[:0]
		}
		run = append(run, r)
		prevH, prevR = h, r
	}
	// Hashing every name costs more than the structural checks above, so it
	// comes after them: a crafted index fails the cheap limits first.
	for i := 0; i < len(plix)/sizePLIX; i++ {
		e := plix[i*sizePLIX:]
		rule := p.Rule(int(le.Uint32(e[8:])))
		if le.Uint64(e) != names.Hash64(key, p.RuleName(&rule)) {
			return reason.New(reason.HashMismatch, "PLIX", uint64(i*sizePLIX), "hash does not match the rule's name")
		}
	}

	// WBKT and WILD: buckets tile WILD, hashes ascend, entries are the wildcard rules.
	wbkt, wild := p.sec[SecWBKT], p.sec[SecWILD]
	nWild := len(wild) / sizeWILD
	nWildRules := 0
	for i := 0; i < nRule; i++ {
		if p.Rule(i).Kind.IsWildcard() {
			nWildRules++
		}
	}
	if nWild != nWildRules {
		return reason.New(reason.IndexRange, "WILD", 0, "%d entries for %d wildcard rules", nWild, nWildRules)
	}
	seen = make([]bool, nRule)
	next := uint64(0)
	var prevB uint64
	for i := 0; i < len(wbkt)/sizeWBKT; i++ {
		e := wbkt[i*sizeWBKT:]
		h, first, count := le.Uint64(e), uint64(le.Uint32(e[8:])), uint64(le.Uint32(e[12:]))
		off := uint64(i * sizeWBKT)
		if i > 0 && h <= prevB {
			return reason.New(reason.Unsorted, "WBKT", off, "hashes not strictly ascending")
		}
		prevB = h
		if count == 0 || count > MaxBucket {
			return reason.New(reason.BadEnum, "WBKT", off+12, "bucket of %d entries (max %d)", count, MaxBucket)
		}
		if first != next || first+count > uint64(nWild) {
			return reason.New(reason.IndexRange, "WBKT", off+8, "bucket does not follow the previous one")
		}
		next = first + count
		var prevLit int = 1 << 30
		for j := first; j < first+count; j++ {
			w := p.Wild(int(j))
			woff := j * sizeWILD
			if uint64(w.Rule) >= uint64(nRule) || seen[w.Rule] {
				return reason.New(reason.IndexRange, "WILD", woff, "rule %d", w.Rule)
			}
			seen[w.Rule] = true
			rule := p.Rule(int(w.Rule))
			in := ri[w.Rule]
			if !rule.Kind.IsWildcard() || w.Kind != rule.Kind {
				return reason.New(reason.BadEnum, "WILD", woff+4, "kind disagrees with the rule")
			}
			if int(w.Labels) != in.labels || int(w.LitBytes) != in.litBytes {
				return reason.New(reason.BadSection, "WILD", woff+5, "label or literal counts disagree with the pattern")
			}
			if names.Hash64(key, in.litSuffix) != h {
				return reason.New(reason.HashMismatch, "WBKT", off, "hash does not match the literal suffix")
			}
			if int(w.LitBytes) > prevLit {
				return reason.New(reason.Unsorted, "WILD", woff, "bucket not sorted by literal bytes descending")
			}
			prevLit = int(w.LitBytes)
		}
	}
	if next != uint64(nWild) {
		return reason.New(reason.IndexRange, "WBKT", 0, "buckets cover %d of %d wildcard entries", next, nWild)
	}

	// GEOR: strictly ascending (class, negated, value), one entry per geo rule.
	geor := p.sec[SecGEOR]
	nGeo := 0
	for i := 0; i < nRule; i++ {
		if !p.Rule(i).Kind.IsName() {
			nGeo++
		}
	}
	if len(geor)/sizeGEOR != nGeo {
		return reason.New(reason.IndexRange, "GEOR", 0, "%d entries for %d geo rules", len(geor)/sizeGEOR, nGeo)
	}
	seen = make([]bool, nRule)
	for i := 0; i < len(geor)/sizeGEOR; i++ {
		g := p.Geo(i)
		e := geor[i*sizeGEOR:]
		off := uint64(i * sizeGEOR)
		if !allZero(e[12:16]) || e[1] > 1 {
			return reason.New(reason.BadSection, "GEOR", off, "pad or negated flag invalid")
		}
		if uint64(g.Rule) >= uint64(nRule) || seen[g.Rule] {
			return reason.New(reason.IndexRange, "GEOR", off+8, "rule %d", g.Rule)
		}
		seen[g.Rule] = true
		rule := p.Rule(int(g.Rule))
		var wantClass uint8
		switch rule.Kind {
		case rules.KindDestAS:
			wantClass = 0
		case rules.KindDestCC:
			wantClass = 1
		case rules.KindSrcCC:
			wantClass = 2
		default:
			return reason.New(reason.BadEnum, "GEOR", off+8, "rule %d is not a geo rule", g.Rule)
		}
		if g.Class != wantClass {
			return reason.New(reason.BadEnum, "GEOR", off, "class disagrees with the rule kind")
		}
		if g.Class == 0 {
			if g.ASN == 0 || g.CC != [2]byte{} {
				return reason.New(reason.BadEnum, "GEOR", off+2, "dest_as needs an ASN and no country")
			}
		} else {
			for _, c := range g.CC {
				if c < 'A' || c > 'Z' {
					return reason.New(reason.BadEnum, "GEOR", off+2, "country code not uppercase letters")
				}
			}
			if g.ASN != 0 {
				return reason.New(reason.BadEnum, "GEOR", off+4, "country rule with an ASN")
			}
		}
		if i > 0 {
			q := p.Geo(i - 1)
			if !geoLess(q, g) {
				return reason.New(reason.Unsorted, "GEOR", off, "not strictly ascending by (class, negated, value)")
			}
		}
	}
	return nil
}

// GeoLess is the level-2 total order (5.8): class, then positive before
// negated, then value.
func GeoLess(a, b Geo) bool { return geoLess(a, b) }

func geoLess(a, b Geo) bool {
	if a.Class != b.Class {
		return a.Class < b.Class
	}
	if a.Negated != b.Negated {
		return !a.Negated
	}
	if a.Class == 0 {
		return a.ASN < b.ASN
	}
	return string(a.CC[:]) < string(b.CC[:])
}

func (p *Profile) checkServices() error {
	svcs := p.sec[SecSVCS]
	for i := 0; i < len(svcs)/sizeSVCS; i++ {
		s := p.service(i)
		e := svcs[i*sizeSVCS:]
		off := uint64(i * sizeSVCS)
		if !allZero(e[6:8]) || !allZero(e[12:16]) {
			return reason.New(reason.BadSection, "SVCS", off, "pad not zero")
		}
		if s.Flags&^(RuleDoNotLog|RuleLocationUnavailable) != 0 {
			return reason.New(reason.BadEnum, "SVCS", off+5, "flags %#x", s.Flags)
		}
		if err := p.targetOK("SVCS", off, s.Action, s.Target); err != nil {
			return err
		}
		if i > 0 && le.Uint32(svcs[(i-1)*sizeSVCS:]) >= s.Wire {
			return reason.New(reason.Unsorted, "SVCS", off, "wire ids not strictly ascending")
		}
	}
	flts := p.sec[SecFLTS]
	for i := 1; i < len(flts)/sizeFLTS; i++ {
		if le.Uint16(flts[(i-1)*sizeFLTS:]) >= le.Uint16(flts[i*sizeFLTS:]) {
			return reason.New(reason.Unsorted, "FLTS", uint64(i*sizeFLTS), "filter ids not strictly ascending")
		}
	}
	return nil
}

// checkFlags verifies the derived header fields. They are redundant with the
// sections, and a mismatch means a buggy or hostile writer; the evaluator
// trusts them for its fast path, so they must be right.
func (p *Profile) checkFlags(ri []ruleInfo) error {
	var maxLabels int
	destGeo := false
	for i := range ri {
		r := p.Rule(i)
		switch r.Kind {
		case rules.KindDomain, rules.KindSubdomains, rules.KindGlob:
			if ri[i].litLabels > maxLabels {
				maxLabels = ri[i].litLabels
			}
		case rules.KindDestCC, rules.KindDestAS:
			destGeo = true
		}
	}
	if int(p.hdr.MaxLabels) != maxLabels {
		return reason.New(reason.BadSection, "", 32, "max_labels %d, rules need %d", p.hdr.MaxLabels, maxLabels)
	}
	explicit := len(ri) > 0 || p.ServiceCount() > 0 || p.FilterCount() > 0 || p.opts.Bool(OptExfiltration)
	if p.hdr.HasDestGeo() != destGeo || p.hdr.Explicit() != explicit {
		return reason.New(reason.BadSection, "", 33, "header flags disagree with the content")
	}
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
