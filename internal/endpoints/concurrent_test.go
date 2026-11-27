package endpoints_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Flow tests of docs/specs/p3-endpoints.md 11.4 that need two writers at once: the write path takes its locks in the order of 3.7,
// retries a deadlock the database finds (3.6), and so none of these pairs may end in anything but a success or a refusal of the
// write path, which the API answers as a 2xx or a 4xx. A raw error here is a 5xx there.

// refusalOrNil fails the test (from the test goroutine) when err is neither nil nor a refusal of the write path.
func refusalOrNil(t *testing.T, what string, err error) {
	t.Helper()
	var e *endpoints.Error
	if err != nil && !errors.As(err, &e) {
		t.Errorf("%s ended in %v, which is no refusal of the write path (a 5xx at the API)", what, err)
	}
}

// A group delete against a batch edit of the same Endpoints: the delete sets the group of each member to none, the edit rewrites
// the same rows, and both take the Endpoint rows in id order (3.7 step 5).
func TestGroupDeleteAgainstABatchEditOfTheSameEndpoints(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_endpoints = 1000 WHERE tenant_id = $1`, A)
	names := make([]string, 24)
	for i := range names {
		names[i] = fmt.Sprintf("member-%02d", i)
	}
	for round := 0; round < 8; round++ {
		rows, err := f.env.Create(f.ctx, f.st, A, opts, endpoints.CreateIn{Type: f.typ, Names: names, ProfileID: f.A.Profile})
		if err != nil {
			t.Fatal(err)
		}
		ids := make([]uuid.UUID, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		g, err := f.env.CreateGroup(f.ctx, f.st, A, opts, fmt.Sprintf("doomed-%d", round), ids)
		if err != nil {
			t.Fatal(err)
		}
		level := "some"
		errs := make([]error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs[0] = f.env.DeleteGroup(f.ctx, f.st, A, opts, g.ID)
		}()
		go func() {
			defer wg.Done()
			_, errs[1] = f.env.Batch(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), endpoints.BatchIn{IDs: ids, Op: "edit", Set: endpoints.Patch{AnalyticsLevel: &level}})
		}()
		wg.Wait()
		refusalOrNil(t, "the group delete", errs[0])
		refusalOrNil(t, "the batch edit", errs[1])
		if errs[0] != nil {
			t.Fatalf("round %d: the group delete was refused: %v", round, errs[0])
		}
		if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE group_id = $1`, g.ID); n != 0 {
			t.Fatalf("round %d: %d Endpoints kept the deleted group", round, n)
		}
		if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1 AND name = ANY($2::text[])`, A, names); n != len(ids) {
			t.Fatalf("round %d: %d of %d Endpoints are left", round, n, len(ids))
		}
		// Clear the way for the next round's names.
		if err := f.env.Delete(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), ids); err != nil {
			t.Fatal(err)
		}
	}
}

// T-531: a delete of clients by selector against a hub-style writer that updates the same rows, and against a manual client
// writer. The clients are locked in id order, so the pair cannot deadlock; a 40P01 that still comes is retried inside the call.
func TestClientDeleteBySelectorAgainstConcurrentWriters(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	ep := f.create(t, A, f.A.Profile, "busy")[0]
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_clients_per_endpoint = 1000 WHERE tenant_id = $1`, A)
	a := f.auth(A, &fakeVerifier{})
	for round := 0; round < 6; round++ {
		f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) SELECT $1::uuid, $2::uuid, 'seen-' || g, 'auto' FROM generate_series(1, 60) g
			ON CONFLICT DO NOTHING`, A, ep.ID)
		var wg sync.WaitGroup
		var affected int
		var delErr, hubErr, userErr error
		wg.Add(3)
		go func() {
			defer wg.Done()
			// Removal in batches: a selector resolves at most 500 clients in one transaction (3.6, T-259).
			affected, _, delErr = f.env.BatchClients(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "delete", All: true})
		}()
		go func() {
			defer wg.Done()
			// The hub's writer: a multi-row update that takes the rows in id order, as PS 4 asks of every writer of clients.
			hubErr = f.db.Exec(f.ctx, `UPDATE ctrlz.clients SET last_seen_at = now() WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.clients WHERE endpoint_id = $1 ORDER BY id FOR UPDATE))`, ep.ID)
		}()
		go func() {
			defer wg.Done()
			_, userErr = f.env.CreateClient(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientCreate{Alias: fmt.Sprintf("manual %d", round)})
		}()
		wg.Wait()
		refusalOrNil(t, "the delete by selector", delErr)
		refusalOrNil(t, "the manual client create", userErr)
		if hubErr != nil {
			t.Fatalf("round %d: the hub-style writer was refused: %v", round, hubErr)
		}
		if delErr != nil {
			t.Fatalf("round %d: the delete by selector was refused: %v", round, delErr)
		}
		if affected < 60 {
			t.Fatalf("round %d: the delete by selector removed %d of the 60 clients that were there before it", round, affected)
		}
		f.exec(t, `DELETE FROM ctrlz.clients WHERE endpoint_id = $1`, ep.ID)
	}
}

// Two requests that both want the same Endpoint's clients and profiles, in opposite orders of naming, take the locks in the one
// order of 3.7 and so do not deadlock: a client edit that names profiles A then B, and a batch edit that names B then A.
func TestClientAndEndpointWritersNameProfilesInOppositeOrders(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	p1, p2 := f.A.Profile, f.A.Profile2
	ep := f.create(t, A, p1, "pair")[0]
	c, err := f.env.CreateClient(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), ep.ID, endpoints.ClientCreate{Alias: "kid", ProfileID: p1})
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 10; round++ {
		a, b := p1, p2
		if round%2 == 1 {
			a, b = b, a
		}
		var wg sync.WaitGroup
		var e1, e2 error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, e1 = f.env.PatchClient(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), ep.ID, c.ID, endpoints.ClientChange{ProfileID: &a, Profile2ID: &b})
		}()
		go func() {
			defer wg.Done()
			_, e2 = f.env.Patch(f.ctx, f.st, A, opts, f.auth(A, &fakeVerifier{}), ep.ID, endpoints.Patch{ProfileID: &b, Profile2ID: &a})
		}()
		wg.Wait()
		refusalOrNil(t, "the client edit", e1)
		refusalOrNil(t, "the Endpoint edit", e2)
	}
}

// A public link route tries again once when its transaction loses a race (a lock timeout or a deadlock against the owner's rotation,
// delete or batch), so a visitor is not turned away by a write that will have finished a moment later; a second loss is the error
// the route answers as 503, after exactly two tries and not three (p3-D6-r1-7 and p3-D6-r2-6).
func TestPublicTransactionTriesAgainOnceAfterALostRace(t *testing.T) {
	f := newFx(t)
	run := func(failures int) (tries int, err error) {
		err = f.env.Public(f.ctx, f.st, f.A.Tenant, opts, func(store.Tx) error {
			tries++
			if tries <= failures {
				return store.ErrRetry
			}
			return nil
		})
		return tries, err
	}
	if tries, err := run(1); err != nil || tries != 2 {
		t.Errorf("one lost race: %d tries, %v; want 2 and success", tries, err)
	}
	if tries, err := run(5); !errors.Is(err, store.ErrRetry) || tries != 2 {
		t.Errorf("a race lost twice: %d tries, %v; want 2 and the retry error", tries, err)
	}
	if tries, err := run(0); err != nil || tries != 1 {
		t.Errorf("no race: %d tries, %v", tries, err)
	}
}
