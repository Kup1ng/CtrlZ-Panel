package hubview_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubview"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func id16(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

func hash(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func uid(b byte) uuid.UUID { return uuid.UUID(id16(b)) }

// node n has dns address 192.0.2.n and a key unless revoked.
func node(n byte, revoked bool) *policyv1.NodeEntry {
	e := &policyv1.NodeEntry{NodeId: id16(n), DnsIp: []byte{192, 0, 2, n}, ProxyIp: []byte{192, 0, 2, n}, Slot: uint32(n)}
	if !revoked {
		e.SpkiSha256 = hash(n, 32)
	}
	return e
}

func pair(p byte, primary, fallback byte) *policyv1.Pair {
	pr := &policyv1.Pair{PairId: id16(p), Primary: id16(primary)}
	if fallback != 0 {
		pr.Fallback = id16(fallback)
	}
	return pr
}

func table(global byte, nodes []*policyv1.NodeEntry, pairs ...*policyv1.Pair) *policyv1.PairTable {
	return &policyv1.PairTable{GlobalPairId: id16(global), Nodes: nodes, Pairs: pairs}
}

func rec(id byte) *policyv1.EndpointRecord {
	return &policyv1.EndpointRecord{
		EndpointId: id16(id), RidHash: id16(0x40), DohTokenHash: hash(0x50, 32), AdminState: commonv1.AdminState_ADMIN_STATE_ENABLED,
		PairId: make([]byte, 16), ClientCap: 7,
	}
}

func entry(seq uint64, at int64) *policyv1.ConfigEntry {
	return &policyv1.ConfigEntry{Seq: seq, Class: commonv1.EntryClass_ENTRY_CLASS_POLICY, CreatedAt: at}
}

// Which change of a record is a revocation, and which is left to the rollout (5.5).
func TestRevocationsAreDerivedFromTheChangeAgainstThePreviousRecord(t *testing.T) {
	v := hubview.New()
	e := entry(1, 100)
	e.PutEndpoints = []*policyv1.EndpointRecord{rec(1)}
	if a := v.Apply(e); len(a.Revs) != 0 {
		t.Fatalf("a first record revokes nothing: %v", a.Revs)
	}
	change := func(seq uint64, f func(*policyv1.EndpointRecord)) hubview.Applied {
		r := rec(1)
		f(r)
		e := entry(seq, 100)
		e.PutEndpoints = []*policyv1.EndpointRecord{r}
		return v.Apply(e)
	}
	// Each case starts from the record the case before left, so restore it after the ones that change it for good.
	cases := []struct {
		name string
		f    func(*policyv1.EndpointRecord)
		want bool
	}{
		{"nothing changed", func(*policyv1.EndpointRecord) {}, false},
		{"soft disabled", func(r *policyv1.EndpointRecord) { r.AdminState = commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED }, false},
		{"hard disabled", func(r *policyv1.EndpointRecord) { r.AdminState = commonv1.AdminState_ADMIN_STATE_HARD_DISABLED }, true},
		{"still hard disabled", func(r *policyv1.EndpointRecord) { r.AdminState = commonv1.AdminState_ADMIN_STATE_HARD_DISABLED }, false},
		{"rid rotated", func(r *policyv1.EndpointRecord) { r.RidHash = id16(0x41) }, true},
		{"token rotated", func(r *policyv1.EndpointRecord) { r.RidHash = id16(0x41); r.DohTokenHash = hash(0x51, 32) }, true},
		{"require authorized turned on", func(r *policyv1.EndpointRecord) {
			r.RidHash, r.DohTokenHash, r.RequireAuthorizedIps = id16(0x41), hash(0x51, 32), true
		}, true},
		{"require authorized still on", func(r *policyv1.EndpointRecord) {
			r.RidHash, r.DohTokenHash, r.RequireAuthorizedIps = id16(0x41), hash(0x51, 32), true
		}, false},
		{"an authorized prefix lost", func(r *policyv1.EndpointRecord) {
			r.RidHash, r.DohTokenHash, r.RequireAuthorizedIps = id16(0x41), hash(0x51, 32), true
			r.Authorized = nil
		}, false},
		{"require authorized turned off", func(r *policyv1.EndpointRecord) { r.RidHash, r.DohTokenHash = id16(0x41), hash(0x51, 32) }, false},
	}
	for i, c := range cases {
		a := change(uint64(i+2), c.f)
		got := len(a.Revs) == 1 && a.Revs[0].Kind == policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT && len(a.Revs[0].IDs) == 1 && bytes.Equal(a.Revs[0].IDs[0], id16(1))
		if got != c.want || (!c.want && len(a.Revs) != 0) {
			t.Errorf("%s: revoked %v, want %v (%v)", c.name, got, c.want, a.Revs)
		}
		if a.Seq != uint64(i+2) {
			t.Errorf("%s: seq %d", c.name, a.Seq)
		}
	}
	del := entry(50, 100)
	del.DelEndpoints = [][]byte{id16(1), id16(9)}
	del.DelClaims = [][]byte{id16(0x70)}
	a := v.Apply(del)
	if len(a.Revs) != 2 || a.Revs[0].Kind != policyv1.RevocationKind_REVOCATION_KIND_ENDPOINT || len(a.Revs[0].IDs) != 2 ||
		a.Revs[1].Kind != policyv1.RevocationKind_REVOCATION_KIND_CLAIM || !bytes.Equal(a.Revs[1].IDs[0], id16(0x70)) {
		t.Fatalf("a delete revokes the Endpoint and the claim: %v", a.Revs)
	}
	if _, ok := v.ClientCap(uid(1)); ok {
		t.Fatal("a deleted Endpoint is still known")
	}
	for _, r := range a.Revs {
		if err := wire.ValidateRevocation(&policyv1.Revocation{RevSeq: a.Seq, Kind: r.Kind, Ids: r.IDs}); err != nil {
			t.Fatalf("the hub would send a Revocation its nodes refuse: %v", err)
		}
	}
}

// A table that empties a node's SPKI names the node once, and a node that was already empty is not named again.
func TestAnEmptiedSPKIIsReportedOnce(t *testing.T) {
	v := hubview.New()
	e := entry(1, 100)
	e.PairTable = table(1, []*policyv1.NodeEntry{node(1, false), node(2, false)}, pair(1, 1, 2))
	if a := v.Apply(e); len(a.Emptied) != 0 {
		t.Fatalf("emptied %v", a.Emptied)
	}
	e = entry(2, 101)
	e.PairTable = table(1, []*policyv1.NodeEntry{node(1, false), node(2, true)}, pair(1, 1, 2))
	if a := v.Apply(e); len(a.Emptied) != 1 || a.Emptied[0] != uid(2) {
		t.Fatalf("emptied %v", a.Emptied)
	}
	e = entry(3, 102)
	e.PairTable = table(1, []*policyv1.NodeEntry{node(1, false), node(2, true)}, pair(1, 1, 2))
	if a := v.Apply(e); len(a.Emptied) != 0 {
		t.Fatalf("the same revoked node again: %v", a.Emptied)
	}
}

// The pair rule: the current pair, and the previous one for 24 h after a change (D31).
func TestAllowedIsTheCurrentPairAndThePreviousOneForADay(t *testing.T) {
	v := hubview.New()
	t0 := time.Unix(1_000_000, 0)
	e := entry(1, t0.Unix())
	e.PairTable = table(1, []*policyv1.NodeEntry{node(1, false), node(2, false), node(3, false)}, pair(1, 1, 2))
	e.PutEndpoints = []*policyv1.EndpointRecord{rec(0xa)}
	v.Apply(e)
	ep := uid(0xa)
	if !v.Allowed(ep, uid(1), t0) || !v.Allowed(ep, uid(2), t0) || v.Allowed(ep, uid(3), t0) {
		t.Fatal("the current pair is the Endpoint's global pair")
	}
	if v.Allowed(uid(0xb), uid(1), t0) {
		t.Fatal("an Endpoint the view does not know is not allowed")
	}
	if c, ok := v.ClientCap(ep); !ok || c != 7 {
		t.Fatalf("client cap %d %v", c, ok)
	}
	change := t0.Add(time.Hour)
	e = entry(2, change.Unix())
	e.PairTable = table(1, []*policyv1.NodeEntry{node(1, false), node(2, false), node(3, false)}, pair(1, 1, 3))
	v.Apply(e)
	if !v.Allowed(ep, uid(3), change) || !v.Allowed(ep, uid(2), change.Add(23*time.Hour)) {
		t.Fatal("the node taken off the pair is allowed for 24 h after the change")
	}
	if v.Allowed(ep, uid(2), change.Add(24*time.Hour+time.Second)) {
		t.Fatal("the previous pair is forgotten after 24 h")
	}
	if !v.Allowed(ep, uid(1), change.Add(48*time.Hour)) || !v.Allowed(ep, uid(3), change.Add(48*time.Hour)) {
		t.Fatal("the current pair stays allowed")
	}
}

// H-r1-8: an Endpoint whose record moves to another pair id keeps the nodes of its old pair for 24 h, as a membership change of one
// pair id does, and not from the entry that moved it.
func TestAnEndpointMovedToAnotherPairKeepsItsOldPairForADay(t *testing.T) {
	v := hubview.New()
	t0 := time.Unix(1_000_000, 0)
	e := entry(1, t0.Unix())
	nodes := []*policyv1.NodeEntry{node(1, false), node(2, false), node(3, false), node(4, false)}
	e.PairTable = table(1, nodes, pair(1, 1, 2), pair(9, 3, 4))
	r := rec(0xa)
	r.PairId = id16(1)
	e.PutEndpoints = []*policyv1.EndpointRecord{r}
	v.Apply(e)
	ep := uid(0xa)
	if !v.Allowed(ep, uid(1), t0) || v.Allowed(ep, uid(3), t0) {
		t.Fatal("before the move the Endpoint is in pair 1")
	}
	move := t0.Add(time.Hour)
	e = entry(2, move.Unix())
	r = rec(0xa)
	r.PairId = id16(9)
	e.PutEndpoints = []*policyv1.EndpointRecord{r} // the record moves; the table does not change
	v.Apply(e)
	if !v.Allowed(ep, uid(3), move) || !v.Allowed(ep, uid(4), move) {
		t.Fatal("the new pair is allowed")
	}
	if !v.Allowed(ep, uid(1), move.Add(23*time.Hour)) || !v.Allowed(ep, uid(2), move.Add(23*time.Hour)) {
		t.Fatal("the old pair is still allowed inside the 24 h after the move")
	}
	// Past 24 h from the entry that moved it, the old pair is forgotten (the newest table has been in force since before it, so
	// the memory of the table is the memory of the move).
	e = entry(3, move.Add(30*time.Hour).Unix())
	e.PairTable = table(1, nodes, pair(1, 1, 2), pair(9, 3, 4))
	v.Apply(e)
	if v.Allowed(ep, uid(1), move.Add(30*time.Hour+time.Second)) {
		t.Fatal("the old pair is allowed more than 24 h after the move")
	}
	if !v.Allowed(ep, uid(3), move.Add(30*time.Hour)) {
		t.Fatal("the new pair stays allowed")
	}
}

// H-r1-12: a table from before a pair existed names nobody for an Endpoint that was created in that pair: the global-pair fallback
// of a table is for a pair id the table lacks while the Endpoint named it, not for an Endpoint that did not exist yet.
func TestAnEndpointOfANewPairIsNotJudgedByTheGlobalPairOfOlderTables(t *testing.T) {
	v := hubview.New()
	t0 := time.Unix(1_000_000, 0)
	nodes := []*policyv1.NodeEntry{node(1, false), node(2, false), node(3, false), node(4, false)}
	e := entry(1, t0.Unix())
	e.PairTable = table(1, nodes, pair(1, 1, 2)) // global pair only
	v.Apply(e)
	later := t0.Add(time.Hour)
	e = entry(2, later.Unix())
	e.PairTable = table(1, nodes, pair(1, 1, 2), pair(9, 3, 4)) // pair 9 appears with the Endpoint's creation
	r := rec(0xc)
	r.PairId = id16(9)
	e.PutEndpoints = []*policyv1.EndpointRecord{r}
	v.Apply(e)
	ep := uid(0xc)
	if v.Allowed(ep, uid(1), later) || v.Allowed(ep, uid(2), later) {
		t.Fatal("a node of the global pair reports for an Endpoint it never served")
	}
	if !v.Allowed(ep, uid(3), later) || !v.Allowed(ep, uid(4), later) {
		t.Fatal("the Endpoint's own pair is allowed")
	}
}

// The release point of L12 in the cases the contract names: nothing due, a pair change waiting for its event, the event
// committed, and a change reverted before its event.
func TestReleasePoint(t *testing.T) {
	nodes := func() []*policyv1.NodeEntry {
		return []*policyv1.NodeEntry{node(1, false), node(2, false), node(3, false)}
	}
	v := hubview.New()
	e := entry(1, 100)
	e.PairTable = table(1, nodes(), pair(1, 1, 2))
	v.Apply(e)
	e = entry(2, 101) // a tenant-only entry: it carries no table
	v.Apply(e)
	last := hubview.PeersOf(table(1, nodes(), pair(1, 1, 2)))
	if got := v.ReleasePoint(last, 2); got != 2 {
		t.Fatalf("nothing is due: %d", got)
	}
	e = entry(3, 102)
	e.PairTable = table(1, nodes(), pair(1, 1, 3)) // a change of a node's peer
	v.Apply(e)
	e = entry(4, 103)
	v.Apply(e)
	if got := v.ReleasePoint(last, 4); got != 2 {
		t.Fatalf("F0 is due for the latest membership, so the log is served up to the entry before it: %d", got)
	}
	// The event of the new membership committed: last_table has its peers.
	last = hubview.PeersOf(table(1, nodes(), pair(1, 1, 3)))
	if got := v.ReleasePoint(last, 4); got != 4 {
		t.Fatalf("the event has committed: %d", got)
	}
	// A revert before the event: the first change is held, then the revert leaves F0 not due again.
	last = hubview.PeersOf(table(1, nodes(), pair(1, 1, 3)))
	e = entry(5, 104)
	e.PairTable = table(1, nodes(), pair(1, 2, 3))
	v.Apply(e)
	if got := v.ReleasePoint(last, 5); got != 4 {
		t.Fatalf("a second change is due: %d", got)
	}
	e = entry(6, 105)
	e.PairTable = table(1, nodes(), pair(1, 1, 3))
	v.Apply(e)
	if got := v.ReleasePoint(last, 6); got != 6 {
		t.Fatalf("the revert leaves F0 not due, so everything is released: %d", got)
	}
	// A log that no entry ever gave a table to is released to its head.
	if got := hubview.New().ReleasePoint(map[string]string{}, 9); got != 9 {
		t.Fatalf("no table: %d", got)
	}
}

// ---------------------------------------------------------------------------------------------------------------------

type fakeStore struct {
	snaps   []store.SnapshotRow
	rows    []store.LogRow
	readErr error
	reads   int
}

func (f *fakeStore) HubSnapshots(context.Context, int) ([]store.SnapshotRow, error) {
	return f.snaps, nil
}

func (f *fakeStore) HubLogEntries(_ context.Context, after, upTo uint64, limit, _ int) ([]store.LogRow, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	var out []store.LogRow
	for _, r := range f.rows {
		if r.Seq > after && r.Seq <= upTo && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeFiles map[string][]byte

func (f fakeFiles) Get(h []byte) ([]byte, error) {
	if b, ok := f[hex.EncodeToString(h)]; ok {
		return b, nil
	}
	return nil, errors.New("no such file")
}

func logRow(t *testing.T, e *policyv1.ConfigEntry) store.LogRow {
	t.Helper()
	e.PrevHash = hash(0, 32)
	b, err := wire.MarshalEntry(e)
	if err != nil {
		t.Fatal(err)
	}
	return store.LogRow{Seq: e.Seq, Class: "policy", Payload: b}
}

// The view starts from the older kept snapshot and the entries after it, and then catches up entry by entry; a read that fails
// leaves it where it got to and says so.
func TestLoadFromTheOlderSnapshotThenCatchUp(t *testing.T) {
	snapTable := table(1, []*policyv1.NodeEntry{node(1, false), node(2, false)}, pair(1, 1, 2))
	older := &signv1.Snapshot{Seq: 10, EntryHash: hash(1, 32), PairTable: snapTable, Endpoints: []*policyv1.EndpointRecord{rec(0xa)}}
	newer := &signv1.Snapshot{Seq: 20, EntryHash: hash(2, 32), PairTable: snapTable}
	files := fakeFiles{}
	var rows []store.SnapshotRow
	for _, s := range []*signv1.Snapshot{newer, older} { // newest first, as the store lists them
		b, _ := proto.Marshal(s)
		ref := hash(byte(s.Seq), 32)
		files[hex.EncodeToString(ref)] = b
		rows = append(rows, store.SnapshotRow{Seq: s.Seq, EntryHash: s.EntryHash, StoreRef: hex.EncodeToString(ref)})
	}
	st := &fakeStore{snaps: rows}
	for seq := uint64(11); seq <= 13; seq++ {
		e := entry(seq, int64(seq))
		if seq == 12 {
			e.DelClaims = [][]byte{id16(0x70)}
		}
		st.rows = append(st.rows, logRow(t, e))
	}
	v := hubview.New()
	if err := v.Load(context.Background(), st, files); err != nil {
		t.Fatal(err)
	}
	if v.Seq() != 13 {
		t.Fatalf("seq %d: the view starts from the older snapshot (10) and reads the tail to the head", v.Seq())
	}
	if _, ok := v.ClientCap(uid(0xa)); !ok {
		t.Fatal("the Endpoint of the older snapshot is known")
	}
	if tb, seq, ok := v.Membership(); !ok || seq != 10 || len(tb.Nodes) != 2 {
		t.Fatalf("membership %v %d %v", tb, seq, ok)
	}

	st.rows = append(st.rows, logRow(t, entry(14, 14)), logRow(t, func() *policyv1.ConfigEntry {
		e := entry(15, 15)
		e.DelClaims = [][]byte{id16(0x71)}
		return e
	}()))
	st.readErr = errors.New("database down")
	if _, err := v.Catch(context.Background(), st, 15); err == nil || v.Seq() != 13 {
		t.Fatalf("a failed read leaves the view where it was: seq %d err %v", v.Seq(), err)
	}
	st.readErr = nil
	got, err := v.Catch(context.Background(), st, 15)
	if err != nil || len(got) != 2 || got[1].Seq != 15 || len(got[1].Revs) != 1 || v.Seq() != 15 {
		t.Fatalf("catch up: %v %v seq %d", got, err, v.Seq())
	}
	// The view does not read what it has.
	before := st.reads
	if got, err := v.Catch(context.Background(), st, 15); err != nil || len(got) != 0 || st.reads != before {
		t.Fatalf("a caught-up view reads nothing: %v %v", got, err)
	}
}

// With no snapshot at all the view reads the whole log, and an entry that does not decode is passed over and counted, not a
// reason to stop revoking for every entry after it.
func TestLoadWithNoSnapshotReadsTheWholeLogAndSkipsWhatDoesNotDecode(t *testing.T) {
	st := &fakeStore{}
	st.rows = append(st.rows, logRow(t, entry(1, 1)), store.LogRow{Seq: 2, Class: "policy", Payload: []byte{0xff, 0xff}}, logRow(t, entry(3, 3)))
	v := hubview.New()
	if err := v.Load(context.Background(), st, fakeFiles{}); err != nil {
		t.Fatal(err)
	}
	if v.Seq() != 3 || v.Skipped() != 1 {
		t.Fatalf("seq %d skipped %d", v.Seq(), v.Skipped())
	}
	// A gap is an error: the view does not pretend to have seen what it has not.
	st.rows = append(st.rows, logRow(t, entry(5, 5)))
	if _, err := v.Catch(context.Background(), st, 5); err == nil {
		t.Fatal("a gap in the log was passed over")
	}
}
