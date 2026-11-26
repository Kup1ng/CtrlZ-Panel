package store_test

import (
	"bytes"
	"errors"
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
