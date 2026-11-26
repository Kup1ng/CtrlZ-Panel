package store_test

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The failover loop's statements (internal/store/hubfail.go) as ctrlz_hub against the migrated schema: what the column grants of
// nodes, pair_event_state and node_dns_requests allow is what they meet. All of it is global state, with no tenant in it.

func (f *hubFx) addNode(t *testing.T, slot int) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.nodes (id, slot, name, status, spki_sha256) VALUES ($1, $2, 'n', 'active', $3)`, id, slot, bytes.Repeat([]byte{byte(slot)}, 32)); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestHubFailCommitWritesTheFlagsTheVersionAndTheRequestInOneTransaction(t *testing.T) {
	f := newHubFx(t)
	a, b := f.addNode(t, 1), f.addNode(t, 2)
	req := uuid.New()
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.node_dns_requests (id, node_id, kind) VALUES ($1, $2, 'release')`, req, a); err != nil {
		t.Fatal(err)
	}
	st, err := f.hub.HubFailRead(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != 0 || len(st.LastTable) != 0 || len(st.Nodes) != 2 || len(st.Requests) != 1 || st.Requests[0].ID != req || st.Requests[0].Kind != "release" {
		t.Fatalf("initial state %+v", st)
	}
	if st.Requests[0].Age < 0 || st.Requests[0].Age > time.Minute {
		t.Fatalf("the age is the database's now() - requested_at: %v", st.Requests[0].Age)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	fb := now.Add(-time.Hour)
	ev := store.HubFailEvent{
		Now: now, Last: 0, Request: req,
		Changed: []store.HubFailChange{{Node: b, Withdrawn: true, LastFailbackAt: fb, FlapUntil: now.Add(24 * time.Hour)}, {Node: a, Hold: true}},
		Table:   func(v uint64) ([]byte, error) { return []byte{byte(v), 1, 2}, nil },
	}
	v, err := f.hub.HubFailCommit(f.ctx, ev)
	if err != nil {
		t.Fatal(err)
	}
	if v < uint64(now.UnixMilli()) {
		t.Fatalf("version %d is below the clock in ms %d", v, now.UnixMilli())
	}
	st, err = f.hub.HubFailRead(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != v || len(st.LastTable) != 3 || len(st.Requests) != 0 {
		t.Fatalf("state after the event %+v", st)
	}
	for _, n := range st.Nodes {
		switch n.ID {
		case a:
			if !n.Hold || n.Withdrawn || !n.LastFailbackAt.IsZero() {
				t.Fatalf("a %+v", n)
			}
		case b:
			if !n.Withdrawn || n.Hold || !n.LastFailbackAt.Equal(fb) || n.FlapUntil.IsZero() {
				t.Fatalf("b %+v", n)
			}
		}
	}
	var state string
	if err := f.db.Scan(f.ctx, `SELECT state FROM ctrlz.node_dns_requests WHERE id = $1`, []any{req}, &state); err != nil || state != "done" {
		t.Fatalf("request %q %v", state, err)
	}
	// An event written from a version that is not the row's is refused, and writes nothing.
	ev.Last, ev.Request = 0, uuid.Nil
	ev.Changed = []store.HubFailChange{{Node: a, Withdrawn: true}}
	if _, err := f.hub.HubFailCommit(f.ctx, ev); !errors.Is(err, store.ErrFailMoved) {
		t.Fatalf("a stale version: %v", err)
	}
	st, _ = f.hub.HubFailRead(f.ctx)
	for _, n := range st.Nodes {
		if n.ID == a && n.Withdrawn {
			t.Fatal("a refused event wrote a flag")
		}
	}
	// The next event takes a version above the last, even when the clock has not moved.
	ev.Last, ev.Now = v, time.Unix(1, 0)
	v2, err := f.hub.HubFailCommit(f.ctx, ev)
	if err != nil || v2 != v+1 {
		t.Fatalf("next version %d (last %d) %v", v2, v, err)
	}
	// A table that cannot be built aborts the whole event.
	ev.Last = v2
	ev.Table = func(uint64) ([]byte, error) { return nil, errors.New("invalid") }
	ev.Changed = []store.HubFailChange{{Node: b, Withdrawn: false}}
	if _, err := f.hub.HubFailCommit(f.ctx, ev); err == nil {
		t.Fatal("an event with no table committed")
	}
	st, _ = f.hub.HubFailRead(f.ctx)
	for _, n := range st.Nodes {
		if n.ID == b && !n.Withdrawn {
			t.Fatal("the flags of an event whose table failed were written")
		}
	}
}

func TestHubFailDecideMarksARequestOnceAndOnlyWhilePending(t *testing.T) {
	f := newHubFx(t)
	a := f.addNode(t, 1)
	req := uuid.New()
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.node_dns_requests (id, node_id, kind) VALUES ($1, $2, 'hold')`, req, a); err != nil {
		t.Fatal(err)
	}
	if err := f.hub.HubFailDecide(f.ctx, req, "refused", "peer_not_fit"); err != nil {
		t.Fatal(err)
	}
	if err := f.hub.HubFailDecide(f.ctx, req, "expired", ""); err != nil {
		t.Fatal(err)
	}
	var state, reason string
	if err := f.db.Scan(f.ctx, `SELECT state, reason FROM ctrlz.node_dns_requests WHERE id = $1`, []any{req}, &state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "refused" || reason != "peer_not_fit" {
		t.Fatalf("a decided request was decided again: %s %s", state, reason)
	}
	st, err := f.hub.HubFailRead(f.ctx)
	if err != nil || len(st.Requests) != 0 {
		t.Fatalf("a decided request is still read as pending: %v %v", st.Requests, err)
	}
}

// H-r1-7: the byte cap picks the range by size, so the payloads of the entries past the cap are not read. The entry that crosses
// the cap stays, and an entry larger than the cap alone is still returned, or a node would never move past it.
func TestHubLogEntriesStopsAtTheByteCapAndReadsOnlyThoseRows(t *testing.T) {
	f := newHubFx(t)
	for seq := 1; seq <= 6; seq++ {
		size := 100
		if seq == 5 {
			size = 1000 // above the cap on its own
		}
		if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.config_log (seq, class, entry_hash, payload) VALUES ($1, 'policy', $2, $3)`,
			seq, bytes.Repeat([]byte{byte(seq)}, 32), bytes.Repeat([]byte{byte(seq)}, size)); err != nil {
			t.Fatal(err)
		}
	}
	seqs := func(after, upTo uint64, limit, max int) []uint64 {
		t.Helper()
		rows, err := f.hub.HubLogEntries(f.ctx, after, upTo, limit, max)
		if err != nil {
			t.Fatal(err)
		}
		var out []uint64
		for _, r := range rows {
			if len(r.Payload) == 0 || r.Payload[0] != byte(r.Seq) {
				t.Fatalf("entry %d carries the payload of another row", r.Seq)
			}
			out = append(out, r.Seq)
		}
		return out
	}
	if got := seqs(0, 6, 200, 250); len(got) != 3 || got[2] != 3 {
		t.Fatalf("a cap of 250 over 100-byte payloads: %v, want 1 2 3", got)
	}
	if got := seqs(3, 6, 200, 250); len(got) != 2 || got[1] != 5 {
		t.Fatalf("the oversize entry crosses the cap and stays: %v, want 4 5", got)
	}
	if got := seqs(4, 6, 200, 50); len(got) != 1 || got[0] != 5 {
		t.Fatalf("an entry above the cap alone is still returned: %v", got)
	}
	if got := seqs(0, 4, 2, 1<<20); len(got) != 2 {
		t.Fatalf("limit: %v", got)
	}
	if got := seqs(6, 6, 200, 250); len(got) != 0 {
		t.Fatalf("an empty range: %v", got)
	}
}

// H-r1-2: two hubs commit an event from the same version at once. Exactly one wins; the other is ErrFailMoved and its flags are
// rolled back with its transaction, so the rows hold one hub's event and never a mix of both (8a.11 L12, the version check).
func TestHubFailCommitUnderTwoHubsAtOnceKeepsOneEventsFlags(t *testing.T) {
	f := newHubFx(t)
	a, b := f.addNode(t, 1), f.addNode(t, 2)
	for round := 0; round < 8; round++ {
		st, err := f.hub.HubFailRead(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		// Hub X withdraws a, hub Y withdraws b and holds a: any mix of the two would show as both or neither of a pair of flags.
		x := store.HubFailEvent{Now: now, Last: st.Version, Changed: []store.HubFailChange{{Node: a, Withdrawn: true}, {Node: b}},
			Table: func(v uint64) ([]byte, error) { return []byte{'x'}, nil }}
		y := store.HubFailEvent{Now: now, Last: st.Version, Changed: []store.HubFailChange{{Node: a, Hold: true}, {Node: b, Withdrawn: true}},
			Table: func(v uint64) ([]byte, error) { return []byte{'y'}, nil }}
		start := make(chan struct{})
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, ev := range []store.HubFailEvent{x, y} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = f.hub.HubFailCommit(f.ctx, ev)
			}()
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, store.ErrFailMoved):
				t.Fatalf("round %d: %v", round, err)
			}
		}
		if won != 1 {
			t.Fatalf("round %d: %d of 2 commits from one version succeeded", round, won)
		}
		after, err := f.hub.HubFailRead(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		flag := map[uuid.UUID]store.HubFailNode{}
		for _, n := range after.Nodes {
			flag[n.ID] = n
		}
		switch string(after.LastTable) {
		case "x":
			if !flag[a].Withdrawn || flag[a].Hold || flag[b].Withdrawn {
				t.Fatalf("round %d: the table is x's and the flags are not: a %+v b %+v", round, flag[a], flag[b])
			}
		case "y":
			if flag[a].Withdrawn || !flag[a].Hold || !flag[b].Withdrawn {
				t.Fatalf("round %d: the table is y's and the flags are not: a %+v b %+v", round, flag[a], flag[b])
			}
		default:
			t.Fatalf("round %d: table %q", round, after.LastTable)
		}
	}
}

// GP-r1-4: the upsert of node_dns_state as ctrlz_hub, under its column grants and the table's CHECKs. It writes two rows, rewrites
// one with another list and a NULL time, keeps the drain columns of a row whose drain the hub has not seen, writes nothing of a
// batch that names an unknown node, and what it wrote reads back through the admin's NodeGet.
func TestHubNodeStateWriteUpsertsUnderTheHubGrants(t *testing.T) {
	f := newHubFx(t)
	a, b := f.addNode(t, 1), f.addNode(t, 2)
	due := time.Now().UTC().Truncate(time.Millisecond).Add(time.Minute)
	since := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	if err := f.hub.HubNodeStateWrite(f.ctx, []store.HubNodeState{
		{Node: b, F3Unmet: []string{"held"}, Drain: "none"},
		{Node: a, F3Unmet: []string{"hub_fit", "stable_period"}, F3DueAt: due, Drain: "draining", DrainSince: since, DrainKnown: true},
	}); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	read := func(id uuid.UUID) store.NodeRow {
		t.Helper()
		var row store.NodeRow
		err := admin.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			r, ok, err := g.NodeGet(id)
			if err == nil && !ok {
				err = errors.New("the node is not there")
			}
			row = r
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	ra := read(a)
	if len(ra.F3Unmet) != 2 || ra.F3Unmet[0] != "hub_fit" || ra.F3DueAt == nil || !ra.F3DueAt.Equal(due) ||
		ra.DrainState == nil || *ra.DrainState != "draining" || ra.DrainSince == nil || !ra.DrainSince.Equal(since) {
		t.Fatalf("node a reads back as %+v", ra)
	}
	if rb := read(b); len(rb.F3Unmet) != 1 || rb.F3DueAt != nil || rb.DrainState == nil || *rb.DrainState != "none" || rb.DrainSince != nil {
		t.Fatalf("node b reads back as %+v", rb)
	}

	// Rewritten with another list and no due time; the hub has not seen the drain of a, so its drain columns stay.
	if err := f.hub.HubNodeStateWrite(f.ctx, []store.HubNodeState{{Node: a, F3Unmet: nil, Drain: "none"}}); err != nil {
		t.Fatalf("the rewrite: %v", err)
	}
	ra = read(a)
	if len(ra.F3Unmet) != 0 || ra.F3DueAt != nil || ra.DrainState == nil || *ra.DrainState != "draining" || ra.DrainSince == nil || !ra.DrainSince.Equal(since) {
		t.Fatalf("node a after the rewrite: %+v", ra)
	}
	// Once the hub knows, none is written, and the CHECK (none <=> no drain_since) holds.
	if err := f.hub.HubNodeStateWrite(f.ctx, []store.HubNodeState{{Node: a, Drain: "none", DrainKnown: true}}); err != nil {
		t.Fatalf("the write of a known none: %v", err)
	}
	if ra = read(a); ra.DrainState == nil || *ra.DrainState != "none" || ra.DrainSince != nil {
		t.Fatalf("node a after a known none: %+v", ra)
	}

	// One node the table does not have fails the whole batch, and the row of the other stays as it was.
	err := f.hub.HubNodeStateWrite(f.ctx, []store.HubNodeState{{Node: b, F3Unmet: []string{"flapping"}, Drain: "none"}, {Node: uuid.New(), Drain: "none"}})
	if err == nil {
		t.Fatal("a batch with an unknown node was written")
	}
	if rb := read(b); len(rb.F3Unmet) != 1 || rb.F3Unmet[0] != "held" {
		t.Fatalf("node b after the failed batch: %+v", rb)
	}
}
