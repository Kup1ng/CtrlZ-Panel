// Package quarantine is the apply transaction of contract 9.7, as a pure
// function over an in-memory State.
//
// A node must never stop serving because one record in the stream is bad. The
// rules are: a bad entry does not advance the node; a bad blob is set aside
// and every other record still applies; an Endpoint whose blob is bad keeps
// its previous policy binding, and an Endpoint with none is served in
// degraded mode until a valid binding arrives. This package encodes those
// rules once so the node and the golden vectors cannot disagree about them.
// Fetching and persistence stay in node glue; here a Fetcher supplies bytes.
package quarantine

import (
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

// Scope of a failure, as in QuarantineReport.scope.
type Scope uint8

const (
	ScopeEntry  Scope = 1
	ScopeBlob   Scope = 2
	ScopeRecord Scope = 3
)

// Fetcher supplies blob bytes by hash. ok is false when the blob is not
// available (yet).
//
// size is 0 when only the hash is known: a binding hash that no entry sent a
// BlobRef for, or a ref that left the size out. Apply checks size and hash only
// after Fetch has returned the bytes, and blob.Open and the block page check cap
// them later still, so an implementation must not take its read limit from size
// alone. For size 0 it caps the read at the largest blob of kind
// (wire.MaxProfileBlob, wire.MaxBlockPageBlob). The refs Apply files itself for a
// binding hash are profiles; a ref from an entry carries its own kind.
type Fetcher interface {
	Fetch(hash [32]byte, kind policyv1.BlobKind, size uint64) (data []byte, ok bool)
}

// Failure is one thing the node set aside.
type Failure struct {
	Scope   Scope
	Seq     uint64
	Item    []byte // blob hash or record id
	Reason  reason.Code
	Section string
	Offset  uint64
}

// State is what a node holds between entries. It is plain data so the same
// type serves the vectors and the node's persistence layer.
type State struct {
	AppliedSeq uint64
	Head       [32]byte // entry hash of AppliedSeq
	// Profiles holds every blob that passed blob.Open.
	Profiles map[[32]byte]*blob.Profile
	// BlockPages holds the hashes of valid block page records.
	BlockPages map[[32]byte]bool
	// Quarantined maps a bad hash to why. It holds only hashes whose bytes were
	// received intact (they hash to the name) and then failed blob.Open or
	// ValidateBlockPage, so no later fetch can change the verdict. It is retried
	// only after the node's decoder version changes or an admin retries (9.7
	// item 6), so a corrupt blob is not re-downloaded and re-parsed on every
	// entry. A transfer that delivered the wrong bytes is never recorded here.
	Quarantined map[[32]byte]reason.Code
	// Wanted holds every blob an entry or a pending Endpoint named that the
	// node does not have yet, whether it was missing or its transfer was
	// damaged, keyed by hash and independent of any Endpoint. Apply and Retry
	// fetch them again a few at a time, in hash order from WantedCursor, so a
	// block page that failed once is not lost for want of an Endpoint to wait on
	// it. A del_blobs entry drops one, and MaxWanted bounds the list.
	Wanted map[[32]byte]*policyv1.BlobRef
	// WantedCursor is the last wanted hash an earlier pass walked. The next pass
	// starts after it and wraps, so a list longer than the per-pass budget is
	// covered over several passes. It lives here, not in the pass, so a restart
	// that restores State resumes where it stopped.
	WantedCursor [32]byte
	Endpoints    map[[16]byte]*policyv1.EndpointRecord
	Claims       map[[16]byte]*policyv1.ClaimRecord
	// Degraded lists Endpoints with no usable policy binding.
	Degraded map[[16]byte]bool
	// Pending holds, per Endpoint, the record the panel meant it to have when
	// that record named a blob the Fetcher could not supply. A missing blob is
	// not quarantined because it may arrive later; without this map nothing
	// would remember what the Endpoint was meant to bind to, and a transient
	// fetch failure would leave it on its old profile (or degraded) until the
	// panel happened to re-emit it. An entry or Retry that makes every blob of a
	// pending record usable switches the Endpoint without a new put.
	Pending map[[16]byte]*Pending
}

// Pending is an Endpoint put whose binding is waiting for blobs.
type Pending struct {
	// Record is the full record of the put, bindings included.
	Record *policyv1.EndpointRecord
	// Wants are the blobs the Fetcher could not supply, by hash. A ref from an
	// earlier entry may have Size 0 when only the hash is known; the hash check
	// still covers the content.
	Wants map[[32]byte]*policyv1.BlobRef
}

// NewState returns an empty state at seq 0.
func NewState() *State {
	return &State{
		Profiles: map[[32]byte]*blob.Profile{}, BlockPages: map[[32]byte]bool{}, Quarantined: map[[32]byte]reason.Code{},
		Endpoints: map[[16]byte]*policyv1.EndpointRecord{}, Claims: map[[16]byte]*policyv1.ClaimRecord{}, Degraded: map[[16]byte]bool{},
		Pending: map[[16]byte]*Pending{}, Wanted: map[[32]byte]*policyv1.BlobRef{},
	}
}

// Report is the result of one Apply.
type Report struct {
	// Advanced is true when applied_seq moved to this entry's seq.
	Advanced bool
	Seq      uint64
	// Entry is set when the entry itself was refused. The state is unchanged
	// and the node refetches from the hub; two nodes reporting the same entry
	// failure raise an admin alert, one node's report acts locally only (R18).
	Entry *Failure
	// Quarantined lists blobs set aside by this entry: bytes that hash to the
	// name and still failed to open.
	Quarantined []Failure
	// Failed lists transfers that delivered bytes whose size or SHA-256 differ
	// from the BlobRef (reason hash_mismatch). That judges the transfer, not
	// the hash the panel named, so the hash is not quarantined: the blob stays
	// in State.Wanted, its Endpoints stay pending, and the next Apply or Retry
	// fetches it again. The node still reports each one.
	Failed []Failure
	// Missing lists referenced blobs the Fetcher could not supply. They are
	// not quarantined, because they may arrive later; the Endpoints that wait
	// for them are in State.Pending, and every Apply and Retry that still lacks
	// them lists them again, so the report is not a one-time event.
	Missing [][32]byte
	// Promoted lists Endpoints that switched to a binding that had been pending
	// on a missing blob.
	Promoted [][16]byte
	// KeptPrevious lists Endpoints that kept their previous binding because
	// their new one referenced a quarantined or missing blob.
	KeptPrevious [][16]byte
	// Degraded lists Endpoints now served in degraded mode.
	Degraded [][16]byte
	// Applied counts records applied (endpoints and claims, put or delete).
	Applied int
}

// Apply applies one stored entry to st. stored must be the exact bytes that
// were hashed into the chain.
func Apply(st *State, stored []byte, fetch Fetcher) (rep Report) {
	defer func() {
		if r := recover(); r != nil {
			rep = Report{Entry: &Failure{Scope: ScopeEntry, Seq: st.AppliedSeq + 1, Reason: reason.Panic}}
		}
	}()

	entry, err := wire.DecodeEntry(stored)
	if err != nil {
		return Report{Entry: failureOf(ScopeEntry, st.AppliedSeq+1, nil, err)}
	}
	rep.Seq = entry.Seq
	if entry.Seq != st.AppliedSeq+1 {
		return Report{Seq: entry.Seq, Entry: &Failure{Scope: ScopeEntry, Seq: entry.Seq, Reason: reason.IndexRange, Section: "seq"}}
	}
	if string(entry.PrevHash) != string(st.Head[:]) {
		return Report{Seq: entry.Seq, Entry: &Failure{Scope: ScopeEntry, Seq: entry.Seq, Reason: reason.HashMismatch, Section: "prev_hash"}}
	}

	// 2 and 3. Fetch, verify and open every named blob. Nothing is visible to
	// the hot path yet: results go to local maps.
	ps := newPass(st, fetch, entry.Seq, &rep)
	for _, ref := range entry.PutBlobs {
		ps.obtain(ref)
	}
	// The blobs an Endpoint put binds are named by this entry too, whether or not
	// a list holds the hash: an earlier entry may have named it, the cap may have
	// dropped it, or no entry the node saw ever did. Fetching them here, outside
	// the walk's budget, keeps the Endpoint from waiting several passes for a blob
	// the store can serve now. The work is bounded by the entry's size, because
	// obtain tries a hash once per pass and skips one that is already settled.
	for _, ep := range entry.PutEndpoints {
		for _, hb := range bindingHashes(ep) {
			var h [32]byte
			copy(h[:], hb)
			ref := ps.wanted[h]
			if ref == nil {
				// Only the hash is known. This is the ref pendingOf would file for it,
				// and the hash check still covers the content; obtain skips a hash that
				// is already settled.
				ref = &policyv1.BlobRef{Hash: hb, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
			}
			ps.obtain(ref)
		}
	}
	// A blob the panel deleted is not worth another try, unless something
	// still binds to it. The set is built once, from the state before this entry:
	// asking the state per hash walks every Endpoint for each of them, and the
	// cost of an entry with many del_blobs would grow with the product.
	if len(entry.DelBlobs) != 0 {
		needed := neededHashes(st.Endpoints, st.Pending)
		for _, h := range entry.DelBlobs {
			var k [32]byte
			copy(k[:], h)
			if !needed[k] {
				delete(ps.wanted, k)
			}
		}
	}
	// Blobs wanted from earlier entries get another try now, a few at a time:
	// the entry stream must not wait behind a long list of blobs the hub
	// cannot serve.
	ps.walkWanted(MaxWantedPerApply)
	newProfiles, newPages, newBad := ps.profiles, ps.pages, ps.bad

	usable := func(h []byte) bool {
		var k [32]byte
		copy(k[:], h)
		_, a := newProfiles[k]
		_, b := st.Profiles[k]
		return a || b
	}

	// 4. Swap. Build the next state from copies; the old maps stay valid until
	// the assignments at the end, which is the atomic part.
	endpoints := make(map[[16]byte]*policyv1.EndpointRecord, len(st.Endpoints))
	for k, v := range st.Endpoints {
		endpoints[k] = v
	}
	degraded := make(map[[16]byte]bool, len(st.Degraded))
	for k, v := range st.Degraded {
		degraded[k] = v
	}
	for _, id := range entry.DelEndpoints {
		var k [16]byte
		copy(k[:], id)
		delete(endpoints, k)
		delete(degraded, k)
		rep.Applied++
	}
	pending := make(map[[16]byte]*Pending, len(st.Pending))
	for k, v := range st.Pending {
		pending[k] = v
	}
	for _, id := range entry.DelEndpoints {
		var k [16]byte
		copy(k[:], id)
		delete(pending, k)
	}
	refs := map[[32]byte]*policyv1.BlobRef{}
	for _, ref := range entry.PutBlobs {
		var h [32]byte
		copy(h[:], ref.Hash)
		refs[h] = ref
	}
	isBad := func(h [32]byte) bool {
		_, a := st.Quarantined[h]
		_, b := newBad[h]
		return a || b
	}
	for _, ep := range entry.PutEndpoints {
		var k [16]byte
		copy(k[:], ep.EndpointId)
		// A newer put replaces whatever was waiting for this Endpoint.
		delete(pending, k)
		if bindingsUsable(ep, usable) {
			endpoints[k] = ep
			delete(degraded, k)
			rep.Applied++
			continue
		}
		if p := pendingOf(st, ep, refs, usable, isBad); p != nil {
			pending[k] = p
			ps.want(p)
		}
		// The new binding is unusable. Non-binding fields (admin_state,
		// Authorized IPs, token hashes) still take effect: a hard_disable must
		// work even while the blob is bad.
		if prev, ok := st.Endpoints[k]; ok && !st.Degraded[k] {
			merged := proto.Clone(ep).(*policyv1.EndpointRecord)
			merged.Base, merged.Schedule, merged.Clients = prev.Base, prev.Schedule, prev.Clients
			endpoints[k] = merged
			rep.KeptPrevious = append(rep.KeptPrevious, k)
		} else {
			endpoints[k] = ep
			degraded[k] = true
			rep.Degraded = append(rep.Degraded, k)
		}
		rep.Applied++
	}
	promote(st, endpoints, degraded, pending, usable, isBad, &rep)
	claims := make(map[[16]byte]*policyv1.ClaimRecord, len(st.Claims))
	for k, v := range st.Claims {
		claims[k] = v
	}
	for _, id := range entry.DelClaims {
		var k [16]byte
		copy(k[:], id)
		delete(claims, k)
		rep.Applied++
	}
	for _, c := range entry.PutClaims {
		var k [16]byte
		copy(k[:], c.ClaimId)
		claims[k] = c
		rep.Applied++
	}

	profiles := make(map[[32]byte]*blob.Profile, len(st.Profiles)+len(newProfiles))
	for k, v := range st.Profiles {
		profiles[k] = v
	}
	for k, v := range newProfiles {
		profiles[k] = v
	}
	// A deleted blob goes only when no Endpoint still binds to it, bound now or
	// waiting to be (a pending Endpoint's whole record counts). The set is built
	// from the state after this entry, and only when there is something to delete.
	if len(entry.DelBlobs) != 0 {
		inUse := neededHashes(endpoints, pending)
		for _, h := range entry.DelBlobs {
			var k [32]byte
			copy(k[:], h)
			if !inUse[k] {
				delete(profiles, k)
				delete(ps.wanted, k)
			}
		}
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
	capWanted(ps.wanted, endpoints, pending)

	st.Endpoints, st.Degraded, st.Claims, st.Pending = endpoints, degraded, claims, pending
	st.Profiles, st.BlockPages, st.Quarantined, st.Wanted = profiles, pages, bad, ps.wanted
	st.WantedCursor = ps.cursor

	// 5. applied_seq advances whatever was quarantined; the quarantined list
	// is separate, so a bad blob never holds the stream back.
	storedHash := wire.EntryHash(st.Head, stored)
	st.AppliedSeq, st.Head = entry.Seq, storedHash
	rep.Advanced = true
	return rep
}

func failureOf(scope Scope, seq uint64, item []byte, err error) *Failure {
	f := &Failure{Scope: scope, Seq: seq, Item: item, Reason: reason.CodeOf(err)}
	if f.Reason == "" {
		f.Reason = reason.BadSection
	}
	if re, ok := err.(*reason.Error); ok {
		f.Section, f.Offset = re.Section, re.Offset
	}
	return f
}

// bindingHashes lists every profile hash an Endpoint record refers to.
func bindingHashes(ep *policyv1.EndpointRecord) [][]byte {
	var out [][]byte
	add := func(s *policyv1.StackRecord) {
		if s == nil {
			return
		}
		out = append(out, s.Profile1Hash)
		if len(s.Profile2Hash) != 0 {
			out = append(out, s.Profile2Hash)
		}
	}
	add(ep.Base)
	if ep.Schedule != nil {
		for _, w := range ep.Schedule.Windows {
			add(w.Stack)
		}
	}
	for _, c := range ep.Clients {
		add(c.Stack)
	}
	return out
}

func bindingsUsable(ep *policyv1.EndpointRecord, usable func([]byte) bool) bool {
	for _, h := range bindingHashes(ep) {
		if !usable(h) {
			return false
		}
	}
	return true
}
