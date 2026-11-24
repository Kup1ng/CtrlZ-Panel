package quarantine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"runtime"
	"sort"
	"testing"
	"time"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/reason"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"
)

// countingStore serves what it holds and counts every call, hits or not.
type countingStore struct {
	store
	calls int
	seen  map[[32]byte]int
}

func newCountingStore() *countingStore {
	return &countingStore{store: store{}, seen: map[[32]byte]int{}}
}

func (c *countingStore) Fetch(h [32]byte, k policyv1.BlobKind, size uint64) ([]byte, bool) {
	c.calls++
	c.seen[h]++
	return c.store.Fetch(h, k, size)
}

// ghost is a profile reference nobody can serve, numbered so its hash is
// stable.
func ghost(i int) *policyv1.BlobRef {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	h := sha256.Sum256(b[:])
	return &policyv1.BlobRef{Hash: h[:], Size: 8, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
}

func hashOf(r *policyv1.BlobRef) [32]byte { return [32]byte(r.Hash) }

// A hub that serves nothing used to make the fetch count of N entries
// quadratic, because every Apply fetched the whole wanted list again. The cost
// of one Apply is now bounded, so the entry stream is not held up behind a blob
// store fault.
func TestFetchWorkIsLinearInEntries(t *testing.T) {
	const entries = 400
	for _, mode := range []string{"missing", "garbage"} {
		t.Run(mode, func(t *testing.T) {
			cs := newCountingStore()
			var fetch Fetcher = cs
			if mode == "garbage" {
				fetch = garbageFetcher{cs}
			}
			st := NewState()
			for i := 1; i <= entries; i++ {
				Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: uint64(i), PutBlobs: []*policyv1.BlobRef{ghost(i)}}, st), fetch)
			}
			if limit := entries + entries*MaxWantedPerApply; cs.calls > limit {
				t.Errorf("%d entries made %d fetches, want at most %d", entries, cs.calls, limit)
			}
			if len(st.Wanted) != entries || st.AppliedSeq != entries {
				t.Errorf("wanted=%d applied=%d: the list must keep what it could not fetch", len(st.Wanted), st.AppliedSeq)
			}
		})
	}
}

// garbageFetcher answers every fetch with bytes that do not match.
type garbageFetcher struct{ c *countingStore }

func (g garbageFetcher) Fetch(h [32]byte, k policyv1.BlobKind, size uint64) ([]byte, bool) {
	g.c.Fetch(h, k, size)
	return []byte("garbage!"), true
}

// An entry's own blobs are always fetched; the wanted list behind them gets at
// most MaxWantedPerApply tries, and the rest wait for a later pass.
func TestApplyFetchesAtMostAFewWantedBlobs(t *testing.T) {
	fetch := newCountingStore()
	st := NewState()
	refs := make([]*policyv1.BlobRef, 0, 3*MaxWantedPerApply)
	for i := 0; i < cap(refs); i++ {
		refs = append(refs, ghost(i))
	}
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: refs}, st), fetch)
	if fetch.calls != len(refs) {
		t.Fatalf("the entry's own blobs: %d fetches, want %d", fetch.calls, len(refs))
	}
	fetch.calls = 0
	own := ghost(1000)
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{own}}, st), fetch)
	if want := 1 + MaxWantedPerApply; fetch.calls != want {
		t.Errorf("one own blob and a long wanted list: %d fetches, want %d", fetch.calls, want)
	}
}

// A block page has no Endpoint, so only the walk gets it. With more hashes
// wanted than one pass covers, the walk still reaches it: Apply continues from
// where the last one stopped, and a Retry covers more than an Apply does.
func TestWantedWalkReachesEveryHash(t *testing.T) {
	// Make the page sort after every ghost, so it is the last the walk reaches
	// from a zero cursor.
	n := 2*MaxWantedPerApply + 9
	ghosts := make([]*policyv1.BlobRef, n)
	var maxGhost [32]byte
	for i := range ghosts {
		ghosts[i] = ghost(i)
		if bytes.Compare(ghosts[i].Hash, maxGhost[:]) > 0 {
			copy(maxGhost[:], ghosts[i].Hash)
		}
	}
	var page []byte
	var hp [32]byte
	var pref *policyv1.BlobRef
	for i := 0; ; i++ {
		page, hp, pref = blockPage(t, "Blocked "+string(rune('a'+i%26))+string(rune('a'+i/26%26)))
		if bytes.Compare(hp[:], maxGhost[:]) > 0 {
			break
		}
	}
	setup := func() (*State, *countingStore) {
		fetch := newCountingStore()
		st := NewState()
		put := append(append([]*policyv1.BlobRef{}, ghosts...), pref)
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: put}, st), fetch)
		if st.Wanted[hp] == nil {
			t.Fatal("setup: the page is not wanted")
		}
		fetch.store[hp] = page
		return st, fetch
	}

	t.Run("later entries", func(t *testing.T) {
		st, fetch := setup()
		passes := (len(st.Wanted) + MaxWantedPerApply - 1) / MaxWantedPerApply
		if passes < 2 {
			t.Fatal("setup: one pass would cover the list")
		}
		for i := 1; i <= passes; i++ {
			Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: uint64(1 + i)}, st), fetch)
			if got := st.BlockPages[hp]; got != (i == passes) {
				t.Fatalf("after %d of %d empty entries the page is fetched=%v", i, passes, got)
			}
		}
	})

	t.Run("one retry", func(t *testing.T) {
		st, fetch := setup()
		Retry(st, fetch)
		if !st.BlockPages[hp] || len(st.Wanted) != len(ghosts) {
			t.Errorf("Retry did not reach the page behind %d hashes: pages=%v wanted=%d", len(ghosts), st.BlockPages, len(st.Wanted))
		}
	})

	t.Run("retry covers its own budget and then continues", func(t *testing.T) {
		fetch := newCountingStore()
		st := NewState()
		for i := 0; i < MaxWantedPerRetry+10; i++ {
			r := ghost(5000 + i)
			st.Wanted[hashOf(r)] = r
		}
		Retry(st, fetch)
		if fetch.calls != MaxWantedPerRetry {
			t.Fatalf("first Retry: %d fetches, want %d", fetch.calls, MaxWantedPerRetry)
		}
		Retry(st, fetch)
		// The second pass starts after the first one stopped, so the ten hashes
		// the first one never reached are tried before any is tried twice.
		for h := range st.Wanted {
			if fetch.seen[h] == 0 {
				t.Fatalf("hash %x was never tried after two Retries", h[:4])
			}
		}
	})
}

// The cap on the wanted list drops hashes nobody needs and never one a pending
// Endpoint waits for.
func TestWantedListIsCapped(t *testing.T) {
	fill := func(st *State, n, base int) [][32]byte {
		var out [][32]byte
		for i := 0; i < n; i++ {
			r := ghost(base + i)
			st.Wanted[hashOf(r)] = r
			out = append(out, hashOf(r))
		}
		return out
	}
	// An Endpoint waiting for the numerically smallest hash there is, which is
	// the first the cap would reach if it did not look.
	waiting := func(st *State, extra ...[32]byte) {
		d := mkBlob(t, "w.example.com")
		pd := &Pending{Record: ep(1, d, commonv1.AdminState_ADMIN_STATE_ENABLED), Wants: map[[32]byte]*policyv1.BlobRef{}}
		for _, h := range extra {
			pd.Wants[h] = st.Wanted[h]
		}
		st.Pending[key(1)] = pd
		st.Endpoints[key(1)] = pd.Record
	}

	t.Run("a hash a pending Endpoint waits for stays", func(t *testing.T) {
		st := NewState()
		low := &policyv1.BlobRef{Hash: make([]byte, 32), Size: 1, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
		st.Wanted[hashOf(low)] = low
		fill(st, MaxWanted+5, 0)
		waiting(st, hashOf(low))
		Retry(st, newCountingStore())
		if st.Wanted[hashOf(low)] == nil {
			t.Error("the hash a pending Endpoint waits for was dropped")
		}
		if len(st.Wanted) != MaxWanted {
			t.Errorf("wanted = %d, want %d", len(st.Wanted), MaxWanted)
		}
	})

	t.Run("profiles go before block pages", func(t *testing.T) {
		st := NewState()
		pageHashes := map[[32]byte]bool{}
		for i := 0; i < 3; i++ {
			_, h, r := blockPage(t, "cap page "+string(rune('a'+i)))
			st.Wanted[h] = r
			pageHashes[h] = true
		}
		fill(st, MaxWanted-3+4, 100) // four over the cap
		Retry(st, newCountingStore())
		if len(st.Wanted) != MaxWanted {
			t.Fatalf("wanted = %d, want %d", len(st.Wanted), MaxWanted)
		}
		for h := range pageHashes {
			if st.Wanted[h] == nil {
				t.Errorf("block page %x dropped while profiles were still droppable", h[:4])
			}
		}
	})

	t.Run("block pages go when only needed profiles remain", func(t *testing.T) {
		st := NewState()
		profiles := fill(st, MaxWanted, 0)
		var pages [][32]byte
		for i := 0; i < 2; i++ {
			_, h, r := blockPage(t, "late page "+string(rune('a'+i)))
			st.Wanted[h] = r
			pages = append(pages, h)
		}
		waiting(st, profiles...)
		Retry(st, newCountingStore())
		for _, h := range pages {
			if st.Wanted[h] != nil {
				t.Errorf("block page %x kept over the cap", h[:4])
			}
		}
		if len(st.Wanted) != MaxWanted {
			t.Errorf("wanted = %d, want %d", len(st.Wanted), MaxWanted)
		}
	})

	t.Run("a hash an Endpoint binds stays", func(t *testing.T) {
		st := NewState()
		low := &policyv1.BlobRef{Hash: make([]byte, 32), Size: 1, Kind: policyv1.BlobKind_BLOB_KIND_PROFILE}
		st.Wanted[hashOf(low)] = low
		fill(st, MaxWanted+5, 0)
		rec := ep(1, mkBlob(t, "w.example.com"), commonv1.AdminState_ADMIN_STATE_ENABLED)
		rec.Base.Profile1Hash = low.Hash
		st.Endpoints[key(1)] = rec
		Retry(st, newCountingStore())
		if st.Wanted[hashOf(low)] == nil {
			t.Error("the hash a bound Endpoint names was dropped")
		}
	})

	// Which hashes go must not depend on map order: the same list gives the same
	// answer on every node and every run. The k numerically smallest of a class go.
	smallest := func(hs [][32]byte, k int) map[[32]byte]bool {
		sort.Slice(hs, func(i, j int) bool { return bytes.Compare(hs[i][:], hs[j][:]) < 0 })
		out := map[[32]byte]bool{}
		for _, h := range hs[:k] {
			out[h] = true
		}
		return out
	}

	t.Run("profiles go in hash order", func(t *testing.T) {
		const k = 5
		st := NewState()
		all := fill(st, MaxWanted+k, 0)
		gone := smallest(append([][32]byte{}, all...), k)
		Retry(st, newCountingStore())
		for _, h := range all {
			if kept := st.Wanted[h] != nil; kept == gone[h] {
				t.Fatalf("hash %x: kept=%v, but the %d smallest hashes are the ones to drop", h[:4], kept, k)
			}
		}
	})

	t.Run("block pages go in hash order", func(t *testing.T) {
		const k, pageCount = 6, 12
		st := NewState()
		// Needed profiles fill the list to k short of the bound, so the pages
		// carry the whole excess.
		profiles := fill(st, MaxWanted-k, 0)
		var pages [][32]byte
		for i := 0; i < pageCount; i++ {
			_, h, r := blockPage(t, "order page "+string(rune('a'+i)))
			st.Wanted[h] = r
			pages = append(pages, h)
		}
		waiting(st, profiles...)
		gone := smallest(append([][32]byte{}, pages...), k)
		Retry(st, newCountingStore())
		for _, h := range pages {
			if kept := st.Wanted[h] != nil; kept == gone[h] {
				t.Fatalf("page %x: kept=%v, but the %d smallest page hashes are the ones to drop", h[:4], kept, k)
			}
		}
		if len(st.Wanted) != MaxWanted {
			t.Errorf("wanted = %d, want %d", len(st.Wanted), MaxWanted)
		}
	})

	t.Run("Apply caps it too", func(t *testing.T) {
		st := NewState()
		fill(st, MaxWanted+3, 0)
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1}, st), newCountingStore())
		if len(st.Wanted) != MaxWanted {
			t.Errorf("wanted = %d, want %d", len(st.Wanted), MaxWanted)
		}
	})

	t.Run("at the bound nothing is dropped", func(t *testing.T) {
		st := NewState()
		fill(st, MaxWanted, 0)
		Retry(st, newCountingStore())
		if len(st.Wanted) != MaxWanted {
			t.Errorf("wanted = %d, want %d", len(st.Wanted), MaxWanted)
		}
	})

	t.Run("a dropped hash comes back when an entry names it", func(t *testing.T) {
		st := NewState()
		fill(st, MaxWanted+1, 0)
		Retry(st, newCountingStore())
		var dropped *policyv1.BlobRef
		for i := 0; i < MaxWanted+1; i++ {
			if r := ghost(i); st.Wanted[hashOf(r)] == nil {
				dropped = r
			}
		}
		if dropped == nil {
			t.Fatal("setup: nothing was dropped")
		}
		fetch := newCountingStore()
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{dropped}}, st), fetch)
		if fetch.seen[hashOf(dropped)] == 0 {
			t.Error("an entry naming a dropped hash did not fetch it")
		}
	})
}

// A pending Endpoint waits for b. Whatever happens to the blob list around it,
// the hash stays wanted until b arrives, and the Endpoint then switches without
// a new put.
func pendingOnB(t *testing.T) (st *State, fetch store, a, b []byte, hb [32]byte) {
	t.Helper()
	a, b = mkBlob(t, "a.example.com"), mkBlob(t, "b.example.com")
	hb = sha256.Sum256(b)
	fetch = store{sha256.Sum256(a): a}
	st = NewState()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(a)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{ref(b)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	if st.Pending[key(1)] == nil || st.Wanted[hb] == nil {
		t.Fatal("setup: the Endpoint is not waiting for b")
	}
	return st, fetch, a, b, hb
}

// An entry deletes the pending Endpoint and the blob it waited for: nothing
// waits for the blob any more, so it must leave the list, or every Retry fetches
// it for ever.
func TestDeletingAnEndpointAndItsBlobEndsTheWait(t *testing.T) {
	st, fetch, _, b, hb := pendingOnB(t)
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, DelEndpoints: [][]byte{bytes.Repeat([]byte{1}, 16)}, DelBlobs: [][]byte{hb[:]}}, st), fetch)
	if len(st.Pending) != 0 || st.Wanted[hb] != nil {
		t.Fatalf("pending=%v wanted=%v: the deleted blob is still wanted", st.Pending, st.Wanted)
	}
	cs := &countingStore{store: fetch, seen: map[[32]byte]int{}}
	cs.store[hb] = b
	Retry(st, cs)
	if cs.seen[hb] != 0 || st.Profiles[hb] != nil {
		t.Errorf("Retry fetched a blob nobody waits for: seen=%d", cs.seen[hb])
	}
}

// del_blobs for a blob a pending Endpoint still waits for leaves it wanted.
func TestDelBlobsKeepsTheBlobAPendingEndpointWaitsFor(t *testing.T) {
	t.Run("named by a later entry", func(t *testing.T) {
		st, fetch, _, b, hb := pendingOnB(t)
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, DelBlobs: [][]byte{hb[:]}}, st), fetch)
		if st.Wanted[hb] == nil || st.Pending[key(1)] == nil {
			t.Fatalf("wanted=%v pending=%v", st.Wanted, st.Pending)
		}
		fetch[hb] = b
		if rep := Retry(st, fetch); len(rep.Promoted) != 1 || boundTo(st, 1) != hb {
			t.Errorf("the Endpoint never got its blob: %+v bound=%x", rep, boundTo(st, 1))
		}
	})
	t.Run("named by the entry that creates the wait", func(t *testing.T) {
		// The Endpoint is pending only after this entry, so the old state does
		// not protect the hash; the new pending record must.
		a, b := mkBlob(t, "a.example.com"), mkBlob(t, "b.example.com")
		ha, hb := sha256.Sum256(a), sha256.Sum256(b)
		fetch := store{ha: a}
		st := NewState()
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(a)}, PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{ref(b)}, DelBlobs: [][]byte{hb[:]},
			PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
		if st.Wanted[hb] == nil || st.Pending[key(1)] == nil {
			t.Fatalf("wanted=%v pending=%v", st.Wanted, st.Pending)
		}
		fetch[hb] = b
		if rep := Retry(st, fetch); len(rep.Promoted) != 1 || boundTo(st, 1) != hb {
			t.Errorf("the Endpoint never got its blob: %+v bound=%x", rep, boundTo(st, 1))
		}
	})
}

// A pending Endpoint counts everything its intended record binds, not only the
// hashes it still waits for. The record below binds a loaded hash A and a missing
// hash B; A is not in Pending.Wants, because it was usable when the wait began,
// and nothing would fetch it again once del_blobs removed it, so the Endpoint
// could never promote.
func TestDelBlobsKeepsALoadedHashAPendingRecordBinds(t *testing.T) {
	// setup leaves E on its previous binding P, waiting on B, with A loaded.
	// delInPutEntry lists A in del_blobs of the entry that creates the wait.
	setup := func(t *testing.T, delInPutEntry bool) (*State, store, [32]byte, [32]byte) {
		t.Helper()
		p, a, b := mkBlob(t, "p.example.com"), mkBlob(t, "a.example.com"), mkBlob(t, "b.example.com")
		ha, hb := sha256.Sum256(a), sha256.Sum256(b)
		fetch := store{sha256.Sum256(p): p, ha: a}
		st := NewState()
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{ref(p), ref(a)},
			PutEndpoints: []*policyv1.EndpointRecord{ep(1, p, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
		rec := ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)
		rec.Base.Profile2Hash = hb[:]
		put := &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{ref(b)}, PutEndpoints: []*policyv1.EndpointRecord{rec}}
		if delInPutEntry {
			put.DelBlobs = [][]byte{ha[:]}
		}
		rep := Apply(st, marshal(t, put, st), fetch)
		if len(rep.KeptPrevious) != 1 || st.Pending[key(1)] == nil || st.Pending[key(1)].Wants[hb] == nil || len(st.Pending[key(1)].Wants) != 1 {
			t.Fatalf("setup: the Endpoint is not waiting on b alone: %+v pending=%v", rep, st.Pending)
		}
		return st, fetch, ha, hb
	}
	check := func(t *testing.T, st *State, fetch store, a, b [32]byte, bData []byte) {
		t.Helper()
		if st.Profiles[a] == nil {
			t.Fatal("del_blobs removed a hash the pending record binds")
		}
		fetch[b] = bData
		rep := Retry(st, fetch)
		if len(rep.Promoted) != 1 || len(st.Pending) != 0 {
			t.Fatalf("the Endpoint never promoted: %+v pending=%v", rep, st.Pending)
		}
		if boundTo(st, 1) != a || [32]byte(st.Endpoints[key(1)].Base.Profile2Hash) != b {
			t.Errorf("the Endpoint is not on the intended stack: %x", boundTo(st, 1))
		}
	}
	bData := mkBlob(t, "b.example.com")

	t.Run("deleted by the entry that creates the wait", func(t *testing.T) {
		st, fetch, a, b := setup(t, true)
		check(t, st, fetch, a, b, bData)
	})
	t.Run("deleted by a later entry", func(t *testing.T) {
		st, fetch, a, b := setup(t, false)
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 3, DelBlobs: [][]byte{a[:]}}, st), fetch)
		check(t, st, fetch, a, b, bData)
	})
}

// An Endpoint can name a hash no entry ever put as a blob (the blob went out in
// an entry the node never saw, or a snapshot). The Endpoint's wait alone must
// put the hash on the list, or nothing would ever fetch it.
func TestEndpointNamingAnUnputHashIsFetchedByRetry(t *testing.T) {
	b := mkBlob(t, "b.example.com")
	hb := sha256.Sum256(b)
	fetch := store{}
	st := NewState()
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
	if st.Wanted[hb] == nil || !st.Degraded[key(1)] {
		t.Fatalf("wanted=%v degraded=%v", st.Wanted, st.Degraded)
	}
	fetch[hb] = b
	if rep := Retry(st, fetch); len(rep.Promoted) != 1 || boundTo(st, 1) != hb {
		t.Errorf("Retry did not fetch the blob the Endpoint names: %+v", rep)
	}
}

// A blob whose bytes hash correctly but whose size differs from the BlobRef is a
// damaged reference, not a profile: it is reported and not admitted. The hash
// check alone would let it through.
func TestWrongSizeWithTheRightHashIsNotAdmitted(t *testing.T) {
	good := mkBlob(t, "a.example.com")
	hg := sha256.Sum256(good)
	r := ref(good)
	r.Size = uint64(len(good)) + 7
	st := NewState()
	rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: []*policyv1.BlobRef{r}}, st), store{hg: good})
	if len(rep.Failed) != 1 || rep.Failed[0].Reason != reason.HashMismatch {
		t.Fatalf("the size mismatch was not reported: %+v", rep)
	}
	if st.Profiles[hg] != nil || st.Wanted[hg] == nil || len(st.Quarantined) != 0 {
		t.Errorf("profiles=%v wanted=%v quarantined=%v", st.Profiles, st.Wanted, st.Quarantined)
	}
}

// A store fault makes every blob of a large entry missing at once. The work of
// one Apply must stay linear in the entry, because Apply is serial and a
// hard_disable in the next entry waits behind it. A comparison scan per missing
// blob does no allocation, so nothing but the clock shows it.
//
// The test compares two entry sizes instead of a wall-clock bound, so the speed
// of the machine cancels. Sixteen times the blobs may cost about sixteen times as
// much, and a quadratic scan costs over a hundred times as much. A load that
// comes and goes still moves one window and not the other, so the sizes are
// timed in turn, every round, and each keeps its best time: the minimum over all
// rounds is the run that nothing interrupted. The test never judges after the
// first round that looks good, because one disturbed window of the small size
// would then make a quadratic scan look linear. A control that is linear by
// construction is timed in the same windows. When the control itself scaled far
// beyond linear, the machine is too busy to judge: the test says so and skips,
// and it never passes in that zone. Otherwise Apply may scale by what the
// control did, with some margin, and by no more.
func TestApplyOfAWithheldEntryIsLinear(t *testing.T) {
	const small, large, rounds = 2500, 40000, 5
	// A linear cost scales to about large/small = 16, and a little more in the
	// cache. The quadratic scan scales to over 200, and to 50 or more even when
	// it is 30 times cheaper than the full scan.
	const limit = 60.0
	// A control that scaled past this is not measuring the work any more. A calm
	// control scales by 12 to 28.
	const noisy = 40.0

	entry := func(n int) []byte {
		refs := make([]*policyv1.BlobRef, n)
		for i := range refs {
			refs[i] = ghost(i)
		}
		return marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: refs}, NewState())
	}
	stored := map[int][]byte{small: entry(small), large: entry(large)}
	apply := func(n int) {
		rep := Apply(NewState(), stored[n], store{})
		if len(rep.Missing) != n || !rep.Advanced {
			t.Fatalf("%d blobs: missing=%d advanced=%v", n, len(rep.Missing), rep.Advanced)
		}
	}
	// The control builds the same kind of map Apply builds, one insert per blob.
	control := func(n int) {
		m := make(map[[32]byte]*policyv1.BlobRef, n)
		for i := 0; i < n; i++ {
			r := ghost(i)
			m[hashOf(r)] = r
		}
		if len(m) != n {
			t.Fatalf("control: %d entries, want %d", len(m), n)
		}
	}
	best := func(cur *time.Duration, f func(int), n int) {
		runtime.GC()
		start := time.Now()
		f(n)
		if d := time.Since(start); *cur == 0 || d < *cur {
			*cur = d
		}
	}
	var as, al, cs, cl time.Duration
	for round := 0; round < rounds; round++ {
		best(&cs, control, small)
		best(&as, apply, small)
		best(&cl, control, large)
		best(&al, apply, large)
	}
	got, ctl := float64(al)/float64(as), float64(cl)/float64(cs)
	t.Logf("apply: %d blobs %v, %d blobs %v, ratio %.1f; control: %v and %v, ratio %.1f", small, as, large, al, got, cs, cl, ctl)
	switch {
	case ctl > noisy:
		t.Skipf("the control scaled %.1f times for %d times the work, so the timing is noise here and proves nothing", ctl, large/small)
	case got > math.Max(limit, 2*ctl):
		t.Errorf("%d times the blobs took %.1f times as long (%v against %v), against %.1f for the control: the cost of one Apply is not linear in the entry", large/small, got, al, as, ctl)
	}
}

// An entry that puts an Endpoint names the blobs it binds, so Apply fetches them
// as it fetches the entry's own PutBlobs, outside the per-Apply budget for the
// rest of the wanted list. Otherwise a blob that is back but sits behind the
// walk's cursor leaves the Endpoint degraded, or on its old policy, for several
// passes.
func TestApplyFetchesTheBlobsAnEndpointPutBinds(t *testing.T) {
	// The walk starts at the smallest wanted hash, because the first Apply
	// walked past every hash and left the cursor at the last. A blob that ranks
	// MaxWantedPerApply or later is therefore outside the first walk.
	const ghosts = 40
	rankOf := func(b []byte) int {
		hb := sha256.Sum256(b)
		rank := 0
		for i := 0; i < ghosts; i++ {
			if g := ghost(i); bytes.Compare(g.Hash, hb[:]) < 0 {
				rank++
			}
		}
		return rank
	}
	pick := func(outside bool) []byte {
		for i := 0; i < 500; i++ {
			b := mkBlob(t, "pick"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example.com")
			if (rankOf(b) >= MaxWantedPerApply) == outside {
				return b
			}
		}
		t.Fatal("setup: no blob with the wanted rank")
		return nil
	}
	// setup: entry 1 puts b with the ghosts while the store is down, so every
	// one of them is wanted. prev, when set, is a blob Endpoint 1 is bound to.
	setup := func(t *testing.T, b []byte, prev []byte) (*State, *countingStore) {
		fetch := newCountingStore()
		if prev != nil {
			fetch.store[sha256.Sum256(prev)] = prev
		}
		st := NewState()
		refs := []*policyv1.BlobRef{ref(b)}
		for i := 0; i < ghosts; i++ {
			refs = append(refs, ghost(i))
		}
		put := &policyv1.ConfigEntry{Seq: 1, PutBlobs: refs}
		if prev != nil {
			put.PutBlobs = append(put.PutBlobs, ref(prev))
			put.PutEndpoints = []*policyv1.EndpointRecord{ep(1, prev, commonv1.AdminState_ADMIN_STATE_ENABLED)}
		}
		Apply(st, marshal(t, put, st), fetch)
		if st.Wanted[sha256.Sum256(b)] == nil || len(st.Wanted) != ghosts+1 {
			t.Fatalf("setup: wanted=%d", len(st.Wanted))
		}
		fetch.store[sha256.Sum256(b)] = b // the store is back
		fetch.calls = 0
		return st, fetch
	}
	for _, outside := range []bool{true, false} {
		name := "a blob inside the walk"
		if outside {
			name = "a blob outside the walk"
		}
		b := pick(outside)
		hb := sha256.Sum256(b)
		t.Run(name+", no previous binding", func(t *testing.T) {
			st, fetch := setup(t, b, nil)
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
			if len(rep.Degraded) != 0 || st.Degraded[key(1)] || len(st.Pending) != 0 || boundTo(st, 1) != hb {
				t.Errorf("the Endpoint did not bind in the Apply that put it: degraded=%v state=%v pending=%d", rep.Degraded, st.Degraded, len(st.Pending))
			}
			if st.Wanted[hb] != nil || st.Profiles[hb] == nil {
				t.Errorf("the blob is still wanted or not loaded")
			}
			// The binding sits outside the walk's budget even when the walk would reach
			// the same blob: counting it against the budget would leave the walk one
			// other wanted hash short.
			if want := 1 + MaxWantedPerApply; fetch.calls != want {
				t.Errorf("%d fetches, want the Endpoint's blob and the budget of the walk, %d", fetch.calls, want)
			}
		})
		t.Run(name+", previous binding", func(t *testing.T) {
			prev := mkBlob(t, "prev.example.com")
			st, fetch := setup(t, b, prev)
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
			if len(rep.KeptPrevious) != 0 || len(st.Pending) != 0 || boundTo(st, 1) != hb {
				t.Errorf("the Endpoint kept its old policy: kept=%v pending=%d bound=%x", rep.KeptPrevious, len(st.Pending), boundTo(st, 1))
			}
		})
		t.Run(name+", second profile of the stack", func(t *testing.T) {
			// Only the first binding hash of a record is not the whole of it.
			a := mkBlob(t, "first.example.com")
			st, fetch := setup(t, b, a)
			rec := ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)
			rec.Base.Profile2Hash = hb[:]
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{rec}}, st), fetch)
			if len(rep.KeptPrevious) != 0 || len(st.Pending) != 0 || st.Endpoints[key(1)].Base.Profile2Hash == nil || !bytes.Equal(st.Endpoints[key(1)].Base.Profile2Hash, hb[:]) {
				t.Errorf("the second profile was not fetched: kept=%v pending=%d", rep.KeptPrevious, len(st.Pending))
			}
		})
		// The contract names the schedule windows and the clients too. Each case
		// keeps the base on a blob that is held and binds only the other place to b.
		t.Run(name+", schedule window", func(t *testing.T) {
			a := mkBlob(t, "first.example.com")
			st, fetch := setup(t, b, a)
			rec := ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)
			rec.Schedule = &policyv1.ScheduleRecord{Zone: "UTC", Grid: make([]byte, schedule.Cells),
				Windows: []*policyv1.WindowRecord{{WindowId: bytes.Repeat([]byte{4}, 16), Stack: &policyv1.StackRecord{Profile1Hash: hb[:]}}}}
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{rec}}, st), fetch)
			got := st.Endpoints[key(1)]
			if !rep.Advanced {
				t.Fatalf("the entry was refused: %+v", rep.Entry)
			}
			if len(rep.KeptPrevious) != 0 || len(st.Pending) != 0 || got.Schedule == nil || len(got.Schedule.Windows) != 1 {
				t.Errorf("the schedule window's profile was not fetched: kept=%v pending=%d", rep.KeptPrevious, len(st.Pending))
			}
		})
		t.Run(name+", client", func(t *testing.T) {
			a := mkBlob(t, "first.example.com")
			st, fetch := setup(t, b, a)
			rec := ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED)
			rec.Clients = []*policyv1.ClientRecord{{ClientId: bytes.Repeat([]byte{5}, 16), ClientHash: bytes.Repeat([]byte{5}, 16), Stack: &policyv1.StackRecord{Profile1Hash: hb[:]}}}
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{rec}}, st), fetch)
			got := st.Endpoints[key(1)]
			if !rep.Advanced {
				t.Fatalf("the entry was refused: %+v", rep.Entry)
			}
			if len(rep.KeptPrevious) != 0 || len(st.Pending) != 0 || len(got.Clients) != 1 {
				t.Errorf("the client's profile was not fetched: kept=%v pending=%d", rep.KeptPrevious, len(st.Pending))
			}
		})
		// An entry that binds b and also deletes it: the Endpoint still binds, so
		// the blob must be fetched, kept and bound.
		t.Run(name+", bound and deleted by the same entry", func(t *testing.T) {
			st, fetch := setup(t, b, nil)
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, DelBlobs: [][]byte{hb[:]},
				PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
			if len(rep.Degraded) != 0 || st.Degraded[key(1)] || len(st.Pending) != 0 || boundTo(st, 1) != hb {
				t.Errorf("the Endpoint did not bind: degraded=%v pending=%d", rep.Degraded, len(st.Pending))
			}
			if st.Profiles[hb] == nil {
				t.Errorf("the profile the Endpoint binds was deleted")
			}
		})
		// Every Endpoint of an entry names its bindings, not only the first.
		t.Run(name+", second Endpoint of the entry", func(t *testing.T) {
			a := mkBlob(t, "first.example.com")
			ha := sha256.Sum256(a)
			st, fetch := setup(t, b, nil)
			fetch.store[ha] = a
			rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutBlobs: []*policyv1.BlobRef{ref(a)},
				PutEndpoints: []*policyv1.EndpointRecord{ep(1, a, commonv1.AdminState_ADMIN_STATE_ENABLED), ep(2, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
			if len(rep.Degraded) != 0 || len(st.Pending) != 0 || boundTo(st, 1) != ha || boundTo(st, 2) != hb {
				t.Errorf("an Endpoint after the first did not bind in the Apply that put it: degraded=%v pending=%d", rep.Degraded, len(st.Pending))
			}
		})
	}
}

// The entry that puts an Endpoint names every hash the record binds, so Apply
// fetches it even when no list holds it: no earlier entry named it, or the cap
// dropped it. Otherwise the Endpoint waits for the walk to come round to a hash
// that was only put on the list after the walk had run, although the store can
// serve it now.
func TestApplyFetchesABindingThatIsOnNoWantedList(t *testing.T) {
	t.Run("never wanted", func(t *testing.T) {
		b := mkBlob(t, "b.example.com")
		hb := sha256.Sum256(b)
		fetch := newCountingStore()
		fetch.store[hb] = b
		st := NewState()
		rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
		if len(rep.Degraded) != 0 || len(st.Pending) != 0 || st.Degraded[key(1)] || boundTo(st, 1) != hb {
			t.Errorf("the Endpoint did not bind in the Apply that put it: degraded=%v pending=%d", rep.Degraded, len(st.Pending))
		}
		if st.Profiles[hb] == nil || st.Wanted[hb] != nil || fetch.seen[hb] != 1 {
			t.Errorf("loaded=%v wanted=%v fetches=%d", st.Profiles[hb] != nil, st.Wanted[hb] != nil, fetch.seen[hb])
		}
	})

	t.Run("dropped by the cap", func(t *testing.T) {
		// Entry 1 names more blobs than the list can hold, while the store is down,
		// and a hash that sorts low among them is the first the cap drops.
		const ghosts = MaxWanted + 4000
		hs := make([][32]byte, ghosts)
		refs := make([]*policyv1.BlobRef, ghosts+1)
		for i := range hs {
			refs[i+1] = ghost(i)
			hs[i] = hashOf(refs[i+1])
		}
		sort.Slice(hs, func(i, j int) bool { return bytes.Compare(hs[i][:], hs[j][:]) < 0 })
		cut := hs[ghosts+1-MaxWanted] // the cap drops the ghosts+1-MaxWanted smallest, so anything below this goes
		var b []byte
		for i := 0; b == nil; i++ {
			if i > 2000 {
				t.Fatal("setup: no blob sorts low enough")
			}
			c := mkBlob(t, "low"+string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('a'+i/676))+".example.com")
			if h := sha256.Sum256(c); bytes.Compare(h[:], cut[:]) < 0 {
				b = c
			}
		}
		hb := sha256.Sum256(b)
		refs[0] = ref(b)
		fetch := newCountingStore()
		st := NewState()
		Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, PutBlobs: refs}, st), fetch)
		if st.Wanted[hb] != nil || len(st.Wanted) != MaxWanted {
			t.Fatalf("setup: the cap did not drop the blob: wanted=%d dropped=%v", len(st.Wanted), st.Wanted[hb] == nil)
		}
		fetch.store[hb] = b // the store is back
		fetch.seen = map[[32]byte]int{}
		rep := Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 2, PutEndpoints: []*policyv1.EndpointRecord{ep(1, b, commonv1.AdminState_ADMIN_STATE_ENABLED)}}, st), fetch)
		if len(rep.Degraded) != 0 || len(st.Pending) != 0 || st.Degraded[key(1)] || boundTo(st, 1) != hb {
			t.Errorf("the Endpoint waited for the walk: degraded=%v pending=%d", rep.Degraded, len(st.Pending))
		}
		if fetch.seen[hb] != 1 {
			t.Errorf("the dropped blob was fetched %d times, want once", fetch.seen[hb])
		}
	})
}

// del_blobs asks, for every hash, whether an Endpoint still binds to it. Asking
// the state once per hash walks every Endpoint each time, so an entry with many
// del_blobs on a node with many Endpoints held every entry behind it for
// minutes. The test counts allocations instead of time: the check allocates per
// Endpoint, so the count does not depend on the machine, and four times the
// Endpoints and hashes cost about four times the allocations when the work is
// linear and about sixteen times when it is quadratic.
func TestApplyOfManyDelBlobsIsLinearInEndpoints(t *testing.T) {
	const runs = 3
	allocs := func(n int) float64 {
		// Apply is measured on states built beforehand: AllocsPerRun runs the
		// function runs+1 times, and Apply changes the state it is given.
		states := make([]*State, runs+1)
		for i := range states {
			st := NewState()
			for j := 0; j < n; j++ {
				var id [16]byte
				binary.BigEndian.PutUint64(id[:], uint64(j))
				h := sha256.Sum256(append([]byte("bound"), id[:]...))
				st.Endpoints[id] = &policyv1.EndpointRecord{EndpointId: id[:], AdminState: commonv1.AdminState_ADMIN_STATE_ENABLED, Base: &policyv1.StackRecord{Profile1Hash: h[:]}}
			}
			states[i] = st
		}
		entry := &policyv1.ConfigEntry{Seq: 1}
		for j := 0; j < n; j++ {
			entry.DelBlobs = append(entry.DelBlobs, ghost(j).Hash)
		}
		stored := marshal(t, entry, states[0])
		next := 0
		return testing.AllocsPerRun(runs, func() {
			st := states[next]
			next++
			if rep := Apply(st, stored, store{}); !rep.Advanced {
				t.Fatalf("the entry was refused: %+v", rep.Entry)
			}
		})
	}
	small, large := allocs(500), allocs(2000)
	t.Logf("500 Endpoints and hashes: %.0f allocations, 2000: %.0f", small, large)
	if large > 8*small {
		t.Errorf("four times the Endpoints and del_blobs cost %.1f times the allocations (%.0f against %.0f): the cost of one Apply is not linear", large/small, large, small)
	}
}

// A del_blobs hash that a bound Endpoint or a pending Endpoint needs stays
// wanted, and one nobody needs leaves the list. The first rule reads the state
// from before the entry.
func TestDelBlobsDropsOnlyTheHashesNobodyNeeds(t *testing.T) {
	st := NewState()
	free, bound, waited := ghost(1), ghost(2), ghost(3)
	for _, r := range []*policyv1.BlobRef{free, bound, waited} {
		st.Wanted[hashOf(r)] = r
	}
	boundRec := ep(1, mkBlob(t, "bound.example.com"), commonv1.AdminState_ADMIN_STATE_ENABLED)
	boundRec.Base.Profile1Hash = bound.Hash
	st.Endpoints[key(1)] = boundRec
	waitRec := ep(2, mkBlob(t, "wait.example.com"), commonv1.AdminState_ADMIN_STATE_ENABLED)
	st.Pending[key(2)] = &Pending{Record: waitRec, Wants: map[[32]byte]*policyv1.BlobRef{hashOf(waited): waited}}
	st.Endpoints[key(2)] = waitRec
	Apply(st, marshal(t, &policyv1.ConfigEntry{Seq: 1, DelBlobs: [][]byte{free.Hash, bound.Hash, waited.Hash}}, st), newCountingStore())
	if st.Wanted[hashOf(free)] != nil {
		t.Errorf("a hash nobody needs is still wanted")
	}
	if st.Wanted[hashOf(bound)] == nil || st.Wanted[hashOf(waited)] == nil {
		t.Errorf("a hash an Endpoint needs was dropped: bound=%v waited=%v", st.Wanted[hashOf(bound)] != nil, st.Wanted[hashOf(waited)] != nil)
	}
}
