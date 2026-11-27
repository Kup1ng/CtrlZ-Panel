package endpoints_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// T-531 (spec P3 11.4): the delete of an Endpoint that has many clients against the writers of its clients. The tests above run
// the delete of clients by selector; this is the delete of the Endpoint, which locks the clients first (ClientsLockOf) and then the
// Endpoint row.

// TestEndpointDeleteAgainstConcurrentClientWriters: an Endpoint with 60 clients is deleted while a writer that takes the clients in
// id order, the real activity write of the hub and a manual client create run on it, six rounds. The delete always ends in
// success and the others in success or a refusal of the write path, never in a raw database error (a 5xx at the API). Tenant B's
// Endpoint, with clients of its own, is untouched by every round. Take ClientsLockOf out of Delete and a round ends with a
// deadlock the retry may not cover (the hub's tries are bounded, and the writer's are none).
func TestEndpointDeleteAgainstConcurrentClientWriters(t *testing.T) {
	f := newFx(t)
	A, B := f.A.Tenant, f.B.Tenant
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_clients_per_endpoint = 1000 WHERE tenant_id = $1`, A)
	a := f.auth(A, &fakeVerifier{})
	hub := f.db.Store(f.ctx, t, store.RoleHub)
	node := uuid.New()
	f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) SELECT $1::uuid, $2::uuid, 'b-' || g, 'auto' FROM generate_series(1, 20) g`, B, f.B.Endpoint)
	bBefore := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1`, f.B.Endpoint)

	for round := 0; round < 6; round++ {
		ep := f.create(t, A, f.A.Profile, fmt.Sprintf("doomed-%d", round))[0]
		f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) SELECT $1::uuid, $2::uuid, 'seen-' || g, 'auto' FROM generate_series(1, 60) g`, A, ep.ID)
		at := time.Now().Truncate(time.Minute)
		items := make([]store.HubActivityItem, 0, 70)
		for i := 1; i <= 70; i++ {
			items = append(items, store.HubActivityItem{Endpoint: ep.ID, Label: fmt.Sprintf("seen-%d", i), First: at, Last: at, Node: node, ClientCap: 1000})
		}
		var wg sync.WaitGroup
		var delErr, sqlErr, hubErr, userErr error
		wg.Add(4)
		go func() {
			defer wg.Done()
			delErr = f.env.Delete(f.ctx, f.st, A, opts, a, []uuid.UUID{ep.ID})
		}()
		go func() {
			defer wg.Done()
			// A writer that takes the clients in id order, as PS 4 asks of every writer of clients.
			sqlErr = f.db.Exec(f.ctx, `UPDATE ctrlz.clients SET last_seen_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.clients WHERE endpoint_id = $1 ORDER BY id FOR UPDATE))`, ep.ID)
		}()
		go func() {
			defer wg.Done()
			for try := 0; try < 3; try++ {
				_, hubErr = hub.HubActivityWrite(f.ctx, A, items)
				if hubErr == nil || !errors.Is(hubErr, store.ErrRetry) {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			_, userErr = f.env.CreateClient(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientCreate{Alias: fmt.Sprintf("manual %d", round)})
		}()
		wg.Wait()
		if delErr != nil {
			t.Fatalf("round %d: the delete of the Endpoint ended in %v", round, delErr)
		}
		refusalOrNil(t, "the manual client create", userErr)
		if sqlErr != nil {
			t.Fatalf("round %d: the id-order client writer ended in %v", round, sqlErr)
		}
		if hubErr != nil {
			t.Fatalf("round %d: the hub's write ended in %v", round, hubErr)
		}
		if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1`, ep.ID); n != 0 {
			t.Fatalf("round %d: the Endpoint is still there", round)
		}
		if n := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1`, ep.ID); n != 0 {
			t.Fatalf("round %d: %d clients outlived the Endpoint", round, n)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1`, f.B.Endpoint); n != bBefore {
		t.Errorf("tenant B's Endpoint has %d clients, had %d before the deletes of tenant A", n, bBefore)
	}
}

// TestEndpointDeleteRetriesAFoundDeadlock: a deadlock that the database does find is retried inside the call (spec 3.6). A
// transaction of the test holds the Endpoint row; the delete locks the clients and waits for that row; the test's transaction then
// wants a client the delete holds, which is a cycle. The database aborts the delete, which waited first, with 40P01; the delete
// takes its transaction again, and when the test's transaction is committed it ends in success, with the Endpoint gone and the
// deadlock counted. Without the retry in withRetry the delete answers the raw error (a 503 at the API) and the first check fails.
func TestEndpointDeleteRetriesAFoundDeadlock(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_clients_per_endpoint = 1000 WHERE tenant_id = $1`, A)
	ep := f.create(t, A, f.A.Profile, "deadlocked")[0]
	f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) SELECT $1::uuid, $2::uuid, 'seen-' || g, 'auto' FROM generate_series(1, 5) g`, A, ep.ID)
	var client uuid.UUID
	f.scan(t, `SELECT id FROM ctrlz.clients WHERE endpoint_id = $1 ORDER BY id LIMIT 1`, []any{ep.ID}, &client)
	var before int64
	f.scan(t, `SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`, nil, &before)

	x, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = x.Close(f.ctx) }()
	tx, err := x.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(f.ctx, `SELECT id FROM ctrlz.endpoints WHERE id = $1 FOR UPDATE`, ep.ID); err != nil {
		t.Fatal(err)
	}
	a := f.auth(A, &fakeVerifier{})
	done := make(chan error, 1)
	go func() { done <- f.env.Delete(f.ctx, f.st, A, opts, a, []uuid.UUID{ep.ID}) }()
	// The delete is waiting for the Endpoint row when a lock wait is on a statement that locks the Endpoints of the tenant.
	testwait.Until(t, 20*time.Second, "the delete to wait for the Endpoint row", func() bool {
		var n int
		f.scan(t, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE $1`,
			[]any{"%FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = ANY%"}, &n)
		return n > 0
	})
	// The cycle is made well inside the second the database waits before it looks for one, so the delete, which has waited
	// longer, is the one it aborts.
	if _, err := tx.Exec(f.ctx, `UPDATE ctrlz.clients SET last_seen_at = now() WHERE id = $1`, client); err != nil {
		t.Fatalf("the test's transaction was chosen as the victim of the deadlock: %v", err)
	}
	if err := tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the delete ended in %v after the deadlock, want success from the retry", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the delete did not end")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1`, ep.ID); n != 0 {
		t.Error("the Endpoint is still there after the retry")
	}
	testwait.Until(t, 10*time.Second, "the deadlock to be counted", func() bool {
		var after int64
		f.scan(t, `SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`, nil, &after)
		return after > before
	})
}
