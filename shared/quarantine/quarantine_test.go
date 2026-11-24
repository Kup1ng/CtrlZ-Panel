package quarantine

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
	"github.com/Kup1ng/CtrlZ-Shared/wire"
)

type store map[[32]byte][]byte

func (s store) Fetch(h [32]byte, _ policyv1.BlobKind, _ uint64) ([]byte, bool) {
	d, ok := s[h]
	return d, ok
}

func mkBlob(t *testing.T, token string) []byte {
	t.Helper()
	p, err := rules.Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	d, err := blob.Build(&blob.Spec{Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: p, Action: blob.ActBlock}}})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ref(d []byte) *policyv1.BlobRef {
	h := sha256.Sum256(d)
	return &policyv1.BlobRef{Hash: h[:], Size: uint64(len(d)), Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
}

func ep(id byte, d []byte, admin commonv1.AdminState) *policyv1.EndpointRecord {
	h := sha256.Sum256(d)
	return &policyv1.EndpointRecord{
		EndpointId: bytes.Repeat([]byte{id}, 16), RidHash: bytes.Repeat([]byte{id}, 16), DohTokenHash: bytes.Repeat([]byte{id}, 32),
		PairId: bytes.Repeat([]byte{9}, 16), AdminState: admin, AnalyticsLevel: commonv1.AnalyticsLevel_ANALYTICS_LEVEL_SOME,
		Base: &policyv1.StackRecord{Profile1Hash: h[:]},
	}
}

func marshal(t *testing.T, e *policyv1.ConfigEntry, st *State) []byte {
	t.Helper()
	e.PrevHash = st.Head[:]
	e.Class = commonv1.EntryClass_ENTRY_CLASS_POLICY
	b, err := wire.MarshalEntry(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func key16(b byte) [16]byte { return [16]byte(bytes.Repeat([]byte{b}, 16)) }

func TestOneBadBlobDoesNotStopTheStream(t *testing.T) {
	good := mkBlob(t, "ads.example.com")
	bad := append([]byte(nil), mkBlob(t, "x.example.com")...)
	bad[0] = 'X' // bad magic
	srv := store{sha256.Sum256(good): good, sha256.Sum256(bad): bad}
	st := NewState()

	// Entry 1: e1 is fine, e2 references the corrupt blob and has no previous binding.
	e1 := &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(good), ref(bad)},
		PutEndpoints: []*policyv1.EndpointRecord{ep(1, good, commonv1.AdminState_ADMIN_STATE_ENABLED), ep(2, bad, commonv1.AdminState_ADMIN_STATE_ENABLED)}}
	rep := Apply(st, marshal(t, e1, st), srv)
	if !rep.Advanced || st.AppliedSeq != 1 {
		t.Fatalf("seq did not advance: %+v", rep)
	}
	if len(rep.Quarantined) != 1 || rep.Quarantined[0].Reason != reason.BadMagic || rep.Quarantined[0].Scope != ScopeBlob {
		t.Fatalf("quarantined %+v", rep.Quarantined)
	}
	if _, ok := st.Endpoints[key16(1)]; !ok || st.Degraded[key16(1)] {
		t.Fatal("e1 must be applied and healthy")
	}
	if !st.Degraded[key16(2)] || len(rep.Degraded) != 1 {
		t.Fatalf("e2 must be degraded: %+v", rep)
	}
	if len(st.Profiles) != 1 {
		t.Fatalf("only the good blob is usable: %d", len(st.Profiles))
	}

	// Entry 2: e1 is re-pointed at the quarantined blob and hard-disabled.
	e2 := &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{ep(1, bad, commonv1.AdminState_ADMIN_STATE_HARD_DISABLED)}}
	rep = Apply(st, marshal(t, e2, st), srv)
	if !rep.Advanced || len(rep.KeptPrevious) != 1 {
		t.Fatalf("%+v", rep)
	}
	got := st.Endpoints[key16(1)]
	if got.AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED {
		t.Fatal("a hard_disable must apply even while the blob is bad")
	}
	if !bytes.Equal(got.Base.Profile1Hash, ref(good).Hash) {
		t.Fatal("previous binding must be kept")
	}

	// A quarantined hash is not fetched again.
	delete(srv, sha256.Sum256(bad))
	e3 := &policyv1.ConfigEntry{Seq: 3, PutBlobs: []*policyv1.BlobRef{ref(bad)}}
	rep = Apply(st, marshal(t, e3, st), srv)
	if !rep.Advanced || len(rep.Missing) != 0 || len(rep.Quarantined) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestEntryFailuresDoNotAdvance(t *testing.T) {
	good := mkBlob(t, "ads.example.com")
	srv := store{sha256.Sum256(good): good}
	st := NewState()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(good)}}, st), srv)
	head := st.Head

	for name, raw := range map[string][]byte{
		"garbage":    {1, 2, 3},
		"seq gap":    marshal(t, &policyv1.ConfigEntry{Seq: 5}, st),
		"seq replay": marshal(t, &policyv1.ConfigEntry{Seq: 1}, st),
		"wrong prev": func() []byte {
			e := &policyv1.ConfigEntry{Seq: 2, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, PrevHash: bytes.Repeat([]byte{7}, 32)}
			b, _ := wire.MarshalEntry(e)
			return b
		}(),
	} {
		rep := Apply(st, raw, srv)
		if rep.Advanced || rep.Entry == nil {
			t.Errorf("%s: %+v", name, rep)
		}
		if st.AppliedSeq != 1 || st.Head != head {
			t.Errorf("%s: state changed", name)
		}
	}
}

func TestMissingBlobKeepsPreviousBinding(t *testing.T) {
	a := mkBlob(t, "a.example.com")
	b := mkBlob(t, "b.example.com")
	srv := store{sha256.Sum256(a): a}
	st := NewState()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(a)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), srv)
	rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{ref(b)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), srv)
	if len(rep.Missing) != 1 || len(rep.KeptPrevious) != 1 || !rep.Advanced {
		t.Fatalf("%+v", rep)
	}
	// The blob arrives later: the next entry names it again and the binding moves.
	srv[sha256.Sum256(b)] = b
	rep = Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, PutBlobs: []*policyv1.BlobRef{ref(b)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), srv)
	if len(rep.KeptPrevious) != 0 || !bytes.Equal(st.Endpoints[key16(1)].Base.Profile1Hash, ref(b).Hash) {
		t.Fatalf("%+v", rep)
	}
}

// A size or hash mismatch judges the transfer, not the hash the panel named
// (9.7): it is reported as Failed, never quarantined, and the blob is fetched
// again by the next Retry or entry.
func TestTransferMismatchIsNotAVerdictOnTheHash(t *testing.T) {
	good := mkBlob(t, "a.example.com")
	hg := sha256.Sum256(good)
	flipped := append([]byte(nil), good...)
	flipped[len(flipped)-1] ^= 1
	other := mkBlob(t, "z.example.com")
	for name, bytesServed := range map[string][]byte{
		"a flipped bit":    flipped,
		"the wrong blob":   other,
		"a short transfer": good[:len(good)-1],
	} {
		t.Run(name, func(t *testing.T) {
			fetch := store{hg: bytesServed}
			st := NewState()
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(good)},
				PutEndpoints: []*policyv1.EndpointRecord{ep(1, good, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
			if len(rep.Failed) != 1 || rep.Failed[0].Reason != reason.HashMismatch || rep.Failed[0].Scope != ScopeBlob {
				t.Fatalf("the failure was not reported: %+v", rep)
			}
			if len(rep.Quarantined) != 0 || len(st.Quarantined) != 0 {
				t.Fatalf("a damaged transfer quarantined the hash: %+v %v", rep.Quarantined, st.Quarantined)
			}
			if st.Pending[key(1)] == nil || st.Wanted[hg] == nil || !st.Degraded[key(1)] {
				t.Fatalf("the Endpoint must wait and the blob stay wanted: pending=%v wanted=%v degraded=%v", st.Pending, st.Wanted, st.Degraded)
			}
			// Still damaged: reported again, nothing changes.
			if r := Retry(st, fetch); len(r.Failed) != 1 || len(r.Promoted) != 0 || len(st.Quarantined) != 0 {
				t.Fatalf("retry with the transfer still damaged: %+v", r)
			}
			// A healthy transfer recovers it, with no new entry.
			fetch[hg] = good
			r := Retry(st, fetch)
			if len(r.Promoted) != 1 || boundTo(st, 1) != hg || st.Degraded[key(1)] || len(st.Wanted) != 0 || len(st.Pending) != 0 {
				t.Fatalf("retry after a healthy transfer: %+v bound=%x", r, boundTo(st, 1))
			}
		})
	}
}

// The panel can only re-emit the same hash (builds are deterministic), so an
// entry that names the blob again must fetch it again.
func TestReEmittedHashIsFetchedAfterADamagedTransfer(t *testing.T) {
	good := mkBlob(t, "a.example.com")
	hg := sha256.Sum256(good)
	flipped := append([]byte(nil), good...)
	flipped[0] ^= 0x40
	fetch := store{hg: flipped}
	st := NewState()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(good)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, good, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	fetch[hg] = good
	rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{ref(good)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, good, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	if len(rep.Failed) != 0 || boundTo(st, 1) != hg || st.Degraded[key(1)] {
		t.Fatalf("%+v bound=%x", rep, boundTo(st, 1))
	}
}

func blockPage(t *testing.T, title string) ([]byte, [32]byte, *policyv1.BlobRef) {
	t.Helper()
	d, err := proto.Marshal(&policyv1.BlockPage{Title: title, UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_NONE})
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(d)
	return d, h, &policyv1.BlobRef{Hash: h[:], Size: uint64(len(d)), Kind: policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE}
}

// A block page has no Endpoint to wait on it, yet a missing one must still be
// fetched again by Retry and by later entries (Report.Missing says so).
func TestMissingBlockPageIsRetried(t *testing.T) {
	page, hp, pref := blockPage(t, "Blocked")
	fetch := store{}
	st := NewState()
	r1 := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{pref}}, st), fetch)
	if len(r1.Missing) != 1 || st.Wanted[hp] == nil {
		t.Fatalf("first apply: %+v wanted=%v", r1, st.Wanted)
	}
	// Still missing: an unrelated entry and a Retry both list it again.
	r2 := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2}, st), fetch)
	r3 := Retry(st, fetch)
	if len(r2.Missing) != 1 || len(r3.Missing) != 1 {
		t.Fatalf("missing is not reported again: %+v %+v", r2, r3)
	}
	fetch[hp] = page
	r4 := Retry(st, fetch)
	if !st.BlockPages[hp] || len(r4.Missing) != 0 || len(st.Wanted) != 0 {
		t.Fatalf("retry after the page arrived: %+v pages=%v wanted=%v", r4, st.BlockPages, st.Wanted)
	}
	// Through an entry, with a second page that no Retry has seen.
	page2, h2, ref2 := blockPage(t, "Other")
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, PutBlobs: []*policyv1.BlobRef{ref2}}, st), fetch)
	fetch[h2] = page2
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 4}, st), fetch)
	if !st.BlockPages[h2] {
		t.Fatal("a later entry did not fetch the missing page")
	}
}

// A page whose transfer was damaged is wanted too, and a deleted blob stops
// being wanted.
func TestWantedBlobsEndWithDelBlobs(t *testing.T) {
	page, hp, pref := blockPage(t, "Blocked")
	flipped := append([]byte(nil), page...)
	flipped[len(flipped)-1] ^= 1
	fetch := store{hp: flipped}
	st := NewState()
	r1 := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{pref}}, st), fetch)
	if len(r1.Failed) != 1 || len(st.Quarantined) != 0 || st.Wanted[hp] == nil {
		t.Fatalf("%+v", r1)
	}
	fetch[hp] = page
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, DelBlobs: [][]byte{hp[:]}}, st), fetch)
	if len(st.Wanted) != 0 || st.BlockPages[hp] {
		t.Fatalf("a deleted blob is still wanted or was fetched: wanted=%v pages=%v", st.Wanted, st.BlockPages)
	}
}

// FuzzApply: arbitrary bytes as a stored entry never panic, and an entry that
// does not advance the node leaves its state untouched.
func FuzzApply(f *testing.F) {
	good := mkBlobF(f, "ads.example.com")
	st0 := NewState()
	e := &policyv1.ConfigEntry{Seq: 1, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, PrevHash: st0.Head[:], PutBlobs: []*policyv1.BlobRef{ref(good)},
		PutEndpoints: []*policyv1.EndpointRecord{ep(1, good, commonv1.AdminState_ADMIN_STATE_ENABLED)}}
	seed, _ := wire.MarshalEntry(e)
	f.Add(seed)
	f.Add([]byte{})
	f.Add(seed[:len(seed)/2])
	f.Fuzz(func(t *testing.T, data []byte) {
		st := NewState()
		rep := Apply(st, data, store{sha256.Sum256(good): good})
		if !rep.Advanced && (st.AppliedSeq != 0 || len(st.Endpoints) != 0 || len(st.Profiles) != 0) {
			t.Fatalf("a refused entry changed the state: %+v", rep)
		}
		if rep.Advanced && st.AppliedSeq != 1 {
			t.Fatalf("applied_seq %d", st.AppliedSeq)
		}
	})
}

func mkBlobF(f *testing.F, token string) []byte {
	p, err := rules.Parse(token)
	if err != nil {
		f.Fatal(err)
	}
	d, err := blob.Build(&blob.Spec{Rules: []blob.RuleSpec{{ID: [16]byte{1}, Pattern: p, Action: blob.ActBlock}}})
	if err != nil {
		f.Fatal(err)
	}
	return d
}

// boundTo returns the profile hash an Endpoint serves from.
func boundTo(st *State, id byte) [32]byte {
	var k [16]byte
	copy(k[:], bytes.Repeat([]byte{id}, 16))
	var h [32]byte
	if e := st.Endpoints[k]; e != nil && e.Base != nil {
		copy(h[:], e.Base.Profile1Hash)
	}
	return h
}

func key(id byte) [16]byte {
	var k [16]byte
	copy(k[:], bytes.Repeat([]byte{id}, 16))
	return k
}

// TestMissingBlobIsRetriedLater is the regression test for review F05/F12: a
// transient fetch failure used to leave the Endpoint on its old profile until
// the panel re-emitted it, because nothing remembered the intended binding.
func TestMissingBlobIsRetriedLater(t *testing.T) {
	a, b, c := mkBlob(t, "a.example.com"), mkBlob(t, "b.example.com"), mkBlob(t, "c.example.com")
	ha, hb := sha256.Sum256(a), sha256.Sum256(b)
	fetch := store{ha: a} // b is withheld at first
	st := NewState()

	r1 := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(a)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	if !r1.Advanced || boundTo(st, 1) != ha {
		t.Fatalf("entry 1: advanced=%v bound=%x", r1.Advanced, boundTo(st, 1))
	}
	r2 := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{ref(b)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	if !r2.Advanced || len(r2.Missing) != 1 || len(r2.KeptPrevious) != 1 || boundTo(st, 1) != ha {
		t.Fatalf("entry 2: %+v bound=%x", r2, boundTo(st, 1))
	}
	if p := st.Pending[key(1)]; p == nil || len(p.Wants) != 1 {
		t.Fatalf("the intended binding was not remembered: %+v", st.Pending)
	}

	// Still missing: an unrelated entry keeps the Endpoint on A, keeps the
	// pending record and reports the blob again.
	r3 := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, PutBlobs: []*policyv1.BlobRef{ref(c)}}, st), store{ha: a, sha256.Sum256(c): c})
	if len(r3.Missing) != 1 || len(r3.Promoted) != 0 || boundTo(st, 1) != ha || st.Pending[key(1)] == nil {
		t.Fatalf("entry 3 while b is missing: %+v bound=%x", r3, boundTo(st, 1))
	}

	// The blob arrives. A later entry that does not mention it, and that does
	// not put the Endpoint again, switches the Endpoint to B.
	fetch[hb] = b
	r4 := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 4}, st), fetch)
	if len(r4.Promoted) != 1 || boundTo(st, 1) != hb || st.Pending[key(1)] != nil || st.Profiles[hb] == nil {
		t.Fatalf("entry 4 after b arrived: %+v bound=%x pending=%v", r4, boundTo(st, 1), st.Pending)
	}
	if st.AppliedSeq != 4 {
		t.Errorf("applied_seq %d", st.AppliedSeq)
	}
}

// Retry switches an Endpoint without any entry, and a first-time Endpoint
// leaves degraded mode.
func TestRetryPromotesPendingAndClearsDegraded(t *testing.T) {
	b := mkBlob(t, "b.example.com")
	hb := sha256.Sum256(b)
	fetch := store{}
	st := NewState()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(b)}, PutEndpoints: []*policyv1.EndpointRecord{ep(7, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	if !st.Degraded[key(7)] || st.Pending[key(7)] == nil {
		t.Fatalf("first-time Endpoint with a missing blob: degraded=%v pending=%v", st.Degraded, st.Pending)
	}
	if rep := Retry(st, fetch); len(rep.Promoted) != 0 || len(rep.Missing) != 1 || !st.Degraded[key(7)] {
		t.Fatalf("retry with the blob still missing: %+v", rep)
	}
	fetch[hb] = b
	rep := Retry(st, fetch)
	if len(rep.Promoted) != 1 || st.Degraded[key(7)] || boundTo(st, 7) != hb || len(st.Pending) != 0 {
		t.Fatalf("retry after the blob arrived: %+v degraded=%v", rep, st.Degraded)
	}
	if st.AppliedSeq != 1 || rep.Advanced {
		t.Errorf("Retry must not move applied_seq: %d", st.AppliedSeq)
	}
}

// A newer put, a delete, or a quarantine ends the wait.
func TestPendingEndsOnNewerPutDeleteOrQuarantine(t *testing.T) {
	a, b := mkBlob(t, "a.example.com"), mkBlob(t, "b.example.com")
	ha, hb := sha256.Sum256(a), sha256.Sum256(b)
	setup := func() (*State, store) {
		st := NewState()
		fetch := store{ha: a}
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(a), ref(b)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
		if st.Pending[key(1)] == nil {
			t.Fatal("setup: no pending")
		}
		return st, fetch
	}

	st, fetch := setup()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED)}}, st), fetch)
	fetch[hb] = b
	Retry(st, fetch)
	if boundTo(st, 1) != ha || len(st.Pending) != 0 {
		t.Errorf("a newer put must replace the pending record: bound=%x pending=%v", boundTo(st, 1), st.Pending)
	}

	st, fetch = setup()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, DelEndpoints: [][]byte{bytes.Repeat([]byte{1}, 16)}}, st), fetch)
	fetch[hb] = b
	Retry(st, fetch)
	if _, ok := st.Endpoints[key(1)]; ok || len(st.Pending) != 0 {
		t.Errorf("a deleted Endpoint must not come back: %v", st.Endpoints)
	}

	// The blob arrives with the right hash and does not open: it is
	// quarantined and the wait ends, with the Endpoint still on A. (A damaged
	// transfer is a different case: TestTransferMismatchIsNotAVerdictOnTheHash.)
	bad := append([]byte("X"), b[1:]...)
	hbad := sha256.Sum256(bad)
	st = NewState()
	fetch = store{ha: a}
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(a), ref(bad)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{ep(1, bad, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	if st.Pending[key(1)] == nil {
		t.Fatal("setup: no pending")
	}
	fetch[hbad] = bad
	rep := Retry(st, fetch)
	if len(rep.Quarantined) != 1 || len(st.Pending) != 0 || boundTo(st, 1) != ha || st.Quarantined[hbad] == "" || len(st.Wanted) != 0 {
		t.Errorf("corrupt blob on retry: %+v pending=%v bound=%x wanted=%v", rep, st.Pending, boundTo(st, 1), st.Wanted)
	}
}

// A block page is served for a blocked domain. Parsing as protobuf is not
// enough to admit it: a javascript: link or a huge title is quarantined, a good
// page is kept (review L2-F19).
func TestBlockPageIsValidatedBeforeItIsAdmitted(t *testing.T) {
	mk := func(p *policyv1.BlockPage) ([]byte, *policyv1.BlobRef) {
		d, err := proto.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(d)
		return d, &policyv1.BlobRef{Hash: h[:], Size: uint64(len(d)), Kind: policyv1.BlobKind_BLOB_KIND_BLOCK_PAGE}
	}
	good, goodRef := mk(&policyv1.BlockPage{Title: "Blocked", UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_URL, UnblockUrl: "https://example.com/unblock"})
	evil, evilRef := mk(&policyv1.BlockPage{Title: "Blocked", UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_URL, UnblockUrl: "javascript:alert(1)"})
	huge, hugeRef := mk(&policyv1.BlockPage{Title: string(bytes.Repeat([]byte("a"), 5000)), UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_NONE})
	st := NewState()
	fetch := store{sha256.Sum256(good): good, sha256.Sum256(evil): evil, sha256.Sum256(huge): huge}
	rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{goodRef, evilRef, hugeRef}}, st), fetch)
	if !rep.Advanced || len(rep.Quarantined) != 2 {
		t.Fatalf("%+v", rep)
	}
	if !st.BlockPages[sha256.Sum256(good)] || st.BlockPages[sha256.Sum256(evil)] || st.BlockPages[sha256.Sum256(huge)] {
		t.Errorf("block pages kept: %v", st.BlockPages)
	}
	for _, q := range rep.Quarantined {
		if q.Reason != reason.BadSection {
			t.Errorf("reason %v", q.Reason)
		}
	}
}
