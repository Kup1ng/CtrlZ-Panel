package endpoints_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
)

// An Endpoint with a suspended claim is not deleted (docs/specs/p3-endpoints.md 11.4 "Delete", p3-D6-r2-3): the pre-check
// (EndpointsHeld) answers KindHeld with the index of the Endpoint, single and in a batch, and nothing of the batch goes. The second
// test is the same refusal reached the other way: the suspension commits between the pre-check and the DELETE, the policy of
// ctrlz.endpoints (which reads its own snapshot) lets the row through, the cascade waits for the claim, and the trigger of the claim
// answers CZ001, which Env.Delete turns into the same KindHeld. A tenant B Endpoint with a suspended claim is not the tenant's to see.
func TestDeleteRefusedForASuspendedClaim(t *testing.T) {
	f := newFx(t)
	rows := f.create(t, f.A.Tenant, f.A.Profile, "free", "claimed")
	bRows := f.create(t, f.B.Tenant, f.B.Profile, "theirs")
	cidr := "203.0.113.60/32"
	r, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, rows[1].ID, endpoints.ClaimAsk{Cidr: &cidr})
	if err != nil {
		t.Fatal(err)
	}
	f.exec(t, `UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1`, r.Claim.ID)
	before := f.endpointsOf(t, f.A.Tenant)
	del := func(ids ...uuid.UUID) error {
		return f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), ids)
	}

	if e := refusal(t, del(rows[1].ID)); e.Kind != endpoints.KindHeld || !hasField(e, "/ids/0", endpoints.CodeInvalid) {
		t.Errorf("a single Endpoint with a suspended claim: %v", e)
	}
	if e := refusal(t, del(rows[0].ID, rows[1].ID)); e.Kind != endpoints.KindHeld || !hasField(e, "/ids/1", endpoints.CodeInvalid) || hasField(e, "/ids/0", endpoints.CodeInvalid) {
		t.Errorf("a batch with one: %v", e)
	}
	if f.endpointsOf(t, f.A.Tenant) != before {
		t.Error("a refused delete removed an Endpoint")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE id = $1 AND state = 'suspended'`, r.Claim.ID); n != 1 {
		t.Error("the suspended claim changed")
	}
	// Tenant B deletes its own Endpoint, which has no claim, and tenant A's claim has no say in it.
	if err := f.env.Delete(f.ctx, f.st, f.B.Tenant, opts, f.auth(f.B.Tenant, &fakeVerifier{}), []uuid.UUID{bRows[0].ID}); err != nil {
		t.Fatal(err)
	}
	// The claim is released by the admin side (here: back to released), and the delete then goes through.
	f.exec(t, `UPDATE ctrlz.ip_claims SET state = 'released' WHERE id = $1`, r.Claim.ID)
	if err := del(rows[0].ID, rows[1].ID); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRefusedForAClaimSuspendedInFlight(t *testing.T) {
	f := newFx(t)
	rows := f.create(t, f.A.Tenant, f.A.Profile, "free", "claimed")
	cidr := "203.0.113.61/32"
	r, err := f.env.RequestClaim(f.ctx, f.st, f.A.Tenant, opts, rows[1].ID, endpoints.ClaimAsk{Cidr: &cidr})
	if err != nil {
		t.Fatal(err)
	}
	before := f.endpointsOf(t, f.A.Tenant)
	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(f.ctx) }()
	// An open transaction holds the suspension, which no other transaction sees: the pre-check finds nothing held.
	stx, err := super.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stx.Exec(f.ctx, `UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1`, r.Claim.ID); err != nil {
		_ = stx.Rollback(f.ctx)
		t.Fatal(err)
	}
	var (
		wg  sync.WaitGroup
		got error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		got = f.env.Delete(f.ctx, f.st, f.A.Tenant, opts, f.auth(f.A.Tenant, &fakeVerifier{}), []uuid.UUID{rows[0].ID, rows[1].ID})
	}()
	// The delete is waiting for the claim row of the cascade when a session of the database waits on a lock; then the suspension commits.
	waiting := false
	for i := 0; i < 100 && !waiting; i++ {
		waiting = f.count(t, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`) > 0
		if !waiting {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !waiting {
		_ = stx.Rollback(f.ctx)
		wg.Wait()
		t.Fatal("the delete never waited for the claim: the test does not reach the in-flight case")
	}
	if err := stx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if e := refusal(t, got); e.Kind != endpoints.KindHeld {
		t.Errorf("a claim suspended between the pre-check and the delete: %v", e)
	}
	if n := f.endpointsOf(t, f.A.Tenant); n != before {
		t.Errorf("%d Endpoints after the refused delete, want %d: the free one went with the batch", n, before)
	}
}
