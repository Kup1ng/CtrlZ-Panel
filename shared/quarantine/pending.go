package quarantine

import (
	"bytes"
	"crypto/sha256"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// verdict is what admit decided about one fetched blob.
type verdict uint8

const (
	// admitted: the bytes are what the panel named and they open.
	admitted verdict = iota
	// quarantined: the bytes are what the panel named and they do not open, so
	// the hash itself is bad and no later fetch can fix it.
	quarantined
	// transferFailed: the bytes are not what the panel named. The transfer is
	// at fault (a damaged stream, a bad disk at the hub or here), not the hash,
	// so it is reported and tried again.
	transferFailed
)

// Limits of the wanted list (contract 9.7 item 2). They keep the cost of one
// Apply, and so the time before a hard_disable behind a failing blob store is
// applied, independent of how many blobs are waiting. Provisional until the
// P4 load test (D31).
const (
	// MaxWantedPerApply is how many wanted blobs other than the entry's own an
	// Apply fetches.
	MaxWantedPerApply = 16
	// MaxWantedPerRetry is how many a Retry fetches. Retry runs on a timer or
	// when the fetch path recovers, off the entry stream, so it can afford more.
	MaxWantedPerRetry = 256
	// MaxWanted bounds len(State.Wanted). Past it, the hashes no Endpoint binds
	// or waits for are dropped, profiles first; the list exceeds the bound only
	// by what Endpoints wait for.
	MaxWanted = 65536
)

// pass is one Apply or Retry: the blobs it fetched so far, kept in local maps
// until the caller swaps them in, and the wanted list it edits.
type pass struct {
	st       *State
	fetch    Fetcher
	seq      uint64
	rep      *Report
	profiles map[[32]byte]*blob.Profile
	pages    map[[32]byte]bool
	bad      map[[32]byte]reason.Code
	wanted   map[[32]byte]*policyv1.BlobRef
	tried    map[[32]byte]bool
	cursor   [32]byte // the last wanted hash walked; the next walk starts after it
}

func newPass(st *State, fetch Fetcher, seq uint64, rep *Report) *pass {
	p := &pass{
		st: st, fetch: fetch, seq: seq, rep: rep,
		profiles: map[[32]byte]*blob.Profile{}, pages: map[[32]byte]bool{}, bad: map[[32]byte]reason.Code{},
		wanted: make(map[[32]byte]*policyv1.BlobRef, len(st.Wanted)), tried: map[[32]byte]bool{},
		cursor: st.WantedCursor,
	}
	for h, ref := range st.Wanted {
		p.wanted[h] = ref
	}
	return p
}

// settled reports whether a hash needs no fetch: it is loaded or quarantined,
// before this pass or in it.
func (p *pass) settled(h [32]byte) bool {
	if _, ok := p.st.Profiles[h]; ok || p.st.BlockPages[h] {
		return true
	}
	if _, ok := p.st.Quarantined[h]; ok {
		return true
	}
	if _, ok := p.profiles[h]; ok || p.pages[h] {
		return true
	}
	_, bad := p.bad[h]
	return bad
}

// obtain fetches one blob at most once per pass and files the outcome. It
// reports whether it called the Fetcher: a blob that is already settled or was
// tried costs nothing.
func (p *pass) obtain(ref *policyv1.BlobRef) (fetched bool) {
	var h [32]byte
	copy(h[:], ref.Hash)
	if p.tried[h] {
		return false
	}
	p.tried[h] = true
	if p.settled(h) {
		delete(p.wanted, h)
		return false
	}
	data, ok := p.fetch.Fetch(h, ref.Kind, ref.Size)
	if !ok {
		p.rep.Missing = append(p.rep.Missing, h)
		p.keepWanted(h, ref)
		return true
	}
	if p.admit(ref, data) == transferFailed {
		p.keepWanted(h, ref)
		return true
	}
	delete(p.wanted, h)
	return true
}

// keepWanted records a blob as still wanted. A ref with a size is kept over one
// without (a pending Endpoint knows only the hash).
func (p *pass) keepWanted(h [32]byte, ref *policyv1.BlobRef) {
	if cur := p.wanted[h]; cur == nil || ref.Size != 0 {
		p.wanted[h] = ref
	}
}

// want makes sure every blob a pending Endpoint waits for is on the wanted
// list, even when no entry ever named it with a BlobRef.
func (p *pass) want(pd *Pending) {
	for h, ref := range pd.Wants {
		if p.settled(h) {
			continue
		}
		p.keepWanted(h, ref)
	}
}

// walkWanted fetches up to budget wanted blobs that this pass has not tried
// yet. They are walked in hash order, starting after the hash the last pass
// stopped at and wrapping around, so the reports do not depend on map order and
// no hash waits behind the same budget-sized prefix for ever. Walking a blob that
// needs no fetch costs no budget.
func (p *pass) walkWanted(budget int) {
	hashes := make([][32]byte, 0, len(p.wanted))
	for h := range p.wanted {
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i][:], hashes[j][:]) < 0 })
	start := sort.Search(len(hashes), func(i int) bool { return bytes.Compare(hashes[i][:], p.cursor[:]) > 0 })
	for n := 0; n < len(hashes) && budget > 0; n++ {
		h := hashes[(start+n)%len(hashes)]
		p.cursor = h
		if p.obtain(p.wanted[h]) {
			budget--
		}
	}
}

// capWanted keeps len(wanted) within MaxWanted by dropping hashes no Endpoint
// binds or waits for: profiles first, then block pages, each in hash order. A
// hash a pending Endpoint waits for is never dropped, so the list can pass the
// bound only by what the Endpoint count allows. A dropped hash is fetched again
// when a later entry names it.
func capWanted(wanted map[[32]byte]*policyv1.BlobRef, endpoints map[[16]byte]*policyv1.EndpointRecord, pending map[[16]byte]*Pending) {
	excess := len(wanted) - MaxWanted
	if excess <= 0 {
		return
	}
	needed := neededHashes(endpoints, pending)
	var profiles, pages [][32]byte
	for h, ref := range wanted {
		switch {
		case needed[h]:
		case ref.Kind == policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE:
			pages = append(pages, h)
		default:
			profiles = append(profiles, h)
		}
	}
	byHash := func(s [][32]byte) {
		sort.Slice(s, func(i, j int) bool { return bytes.Compare(s[i][:], s[j][:]) < 0 })
	}
	byHash(profiles)
	byHash(pages)
	for _, h := range append(profiles, pages...) {
		if excess == 0 {
			return
		}
		delete(wanted, h)
		excess--
	}
}

// admit checks one fetched blob and files it under profiles, pages or bad. It
// is the single place a blob is judged, so an entry and a Retry cannot
// disagree.
func (p *pass) admit(ref *policyv1.BlobRef, data []byte) verdict {
	var h [32]byte
	copy(h[:], ref.Hash)
	// Size 0 means only the hash is known (a pending ref from an earlier entry);
	// the hash still covers the content.
	if (ref.Size != 0 && uint64(len(data)) != ref.Size) || sha256.Sum256(data) != h {
		p.rep.Failed = append(p.rep.Failed, Failure{Scope: ScopeBlob, Seq: p.seq, Item: ref.Hash, Reason: reason.HashMismatch})
		return transferFailed
	}
	quarantine := func(f *Failure) verdict {
		p.bad[h] = f.Reason
		p.rep.Quarantined = append(p.rep.Quarantined, *f)
		return quarantined
	}
	switch ref.Kind {
	case policyv1.BlobKind_BLOB_KIND_PROFILE:
		prof, err := blob.Open(data)
		if err != nil {
			return quarantine(failureOf(ScopeBlob, p.seq, ref.Hash, err))
		}
		p.profiles[h] = prof
	case policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE:
		if len(data) > wire.MaxBlockPageBlob {
			return quarantine(&Failure{Scope: ScopeBlob, Seq: p.seq, Item: ref.Hash, Reason: reason.SizeCap})
		}
		page := &policyv1.BlockPage{}
		if err := proto.Unmarshal(data, page); err != nil {
			return quarantine(&Failure{Scope: ScopeBlob, Seq: p.seq, Item: ref.Hash, Reason: reason.BadSection})
		}
		// Parsing as protobuf is not enough: a page is served under the block
		// root for a blocked domain, so a javascript: link or a huge title
		// must not get through (review L2-F19).
		if err := wire.ValidateBlockPage(page); err != nil {
			return quarantine(failureOf(ScopeBlob, p.seq, ref.Hash, err))
		}
		p.pages[h] = true
	}
	return admitted
}

// pendingOf returns what to remember about an Endpoint put whose binding is
// not usable, or nil when waiting would be pointless: an unusable hash is
// quarantined, so no fetch can fix it.
func pendingOf(st *State, ep *policyv1.EndpointRecord, refs map[[32]byte]*policyv1.BlobRef, usable func([]byte) bool, isBad func([32]byte) bool) *Pending {
	p := &Pending{Record: ep, Wants: map[[32]byte]*policyv1.BlobRef{}}
	for _, hb := range bindingHashes(ep) {
		if usable(hb) {
			continue
		}
		var h [32]byte
		copy(h[:], hb)
		if isBad(h) {
			return nil
		}
		ref := refs[h]
		if ref == nil {
			ref = st.Wanted[h]
		}
		if ref == nil {
			ref = &policyv1.BlobRef{Hash: hb, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
		}
		p.Wants[h] = ref
	}
	if len(p.Wants) == 0 {
		return nil
	}
	return p
}

// promote switches every pending Endpoint whose blobs are now all usable to
// its intended record, and drops a pending whose blob has been quarantined
// since. It edits the copies it is given. A pending that this entry itself
// created or replaced is skipped: Apply fetched every hash its record binds
// before the swap, so another look would find nothing new.
func promote(st *State, endpoints map[[16]byte]*policyv1.EndpointRecord, degraded map[[16]byte]bool, pending map[[16]byte]*Pending, usable func([]byte) bool, isBad func([32]byte) bool, rep *Report) {
	for k, p := range pending {
		if st.Pending[k] != p {
			continue
		}
		if bindingsUsable(p.Record, usable) {
			endpoints[k] = p.Record
			delete(degraded, k)
			delete(pending, k)
			rep.Promoted = append(rep.Promoted, k)
			rep.Applied++
			continue
		}
		for h := range p.Wants {
			if isBad(h) {
				delete(pending, k)
				break
			}
		}
	}
}

// Retry gives the blobs on the wanted list another chance, without an entry.
// The node calls it when its fetch path recovers or on a timer;
// Report.Promoted lists the Endpoints that switched. It does not move
// applied_seq.
func Retry(st *State, fetch Fetcher) (rep Report) {
	rep.Seq = st.AppliedSeq
	if len(st.Wanted) == 0 && len(st.Pending) == 0 {
		return rep
	}
	ps := newPass(st, fetch, st.AppliedSeq, &rep)
	ps.walkWanted(MaxWantedPerRetry)
	newProfiles, newPages, newBad := ps.profiles, ps.pages, ps.bad

	usable := func(h []byte) bool {
		var k [32]byte
		copy(k[:], h)
		_, a := newProfiles[k]
		_, b := st.Profiles[k]
		return a || b
	}
	isBad := func(h [32]byte) bool {
		_, a := st.Quarantined[h]
		_, b := newBad[h]
		return a || b
	}
	endpoints := make(map[[16]byte]*policyv1.EndpointRecord, len(st.Endpoints))
	for k, v := range st.Endpoints {
		endpoints[k] = v
	}
	degraded := make(map[[16]byte]bool, len(st.Degraded))
	for k, v := range st.Degraded {
		degraded[k] = v
	}
	pending := make(map[[16]byte]*Pending, len(st.Pending))
	for k, v := range st.Pending {
		pending[k] = v
	}
	promote(st, endpoints, degraded, pending, usable, isBad, &rep)
	capWanted(ps.wanted, endpoints, pending)

	profiles := make(map[[32]byte]*blob.Profile, len(st.Profiles)+len(newProfiles))
	for k, v := range st.Profiles {
		profiles[k] = v
	}
	for k, v := range newProfiles {
		profiles[k] = v
	}
	pages := make(map[[32]byte]bool, len(st.BlockPages)+len(newPages))
	for k := range st.BlockPages {
		pages[k] = true
	}
	for k := range newPages {
		pages[k] = true
	}
	bad := make(map[[32]byte]reason.Code, len(st.Quarantined)+len(newBad))
	for k, v := range st.Quarantined {
		bad[k] = v
	}
	for k, v := range newBad {
		bad[k] = v
	}
	st.Endpoints, st.Degraded, st.Pending = endpoints, degraded, pending
	st.Profiles, st.BlockPages, st.Quarantined, st.Wanted = profiles, pages, bad, ps.wanted
	st.WantedCursor = ps.cursor
	return rep
}

// neededHashes is every hash an Endpoint binds to or a pending Endpoint's
// intended record binds. Callers build it once and look hashes up in it: it costs
// one walk of the Endpoints, so asking per hash would multiply that walk by the
// number of hashes.
//
// A pending Endpoint counts everything its record binds, not only Wants. A hash
// of the record that was usable when the wait began is not in Wants, and if it
// were deleted nothing would fetch it again (it is on no list), so the Endpoint
// would never promote.
func neededHashes(endpoints map[[16]byte]*policyv1.EndpointRecord, pending map[[16]byte]*Pending) map[[32]byte]bool {
	needed := map[[32]byte]bool{}
	for _, ep := range endpoints {
		for _, h := range bindingHashes(ep) {
			needed[[32]byte(h)] = true
		}
	}
	for _, pd := range pending {
		for _, h := range bindingHashes(pd.Record) {
			needed[[32]byte(h)] = true
		}
		// pendingOf makes Wants a subset of the record's bindings, so this adds
		// nothing for a Pending it built. It stays for one built by hand, as the
		// tests do, whose Wants may name a hash the record does not bind.
		for h := range pd.Wants {
			needed[h] = true
		}
	}
	return needed
}
