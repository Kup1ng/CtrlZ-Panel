package catalogtest_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The tests in this file belong to the P0 gate review. Each one fails against
// the database as it was before migration 0010, or, for a review finding that
// was only a gap in the tests, against the mutant the finding names.

// outboxBatches returns the batch ids of the endpoint_set rows of a tenant.
func (l *claimLab) outboxBatches(tenant uuid.UUID) []uuid.UUID {
	l.t.Helper()
	rows, err := l.h.super.Query(l.h.ctx, "SELECT batch_id FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set' ORDER BY id", tenant)
	if err != nil {
		l.t.Fatal(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var b uuid.UUID
		if err := rows.Scan(&b); err != nil {
			l.t.Fatal(err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		l.t.Fatal(err)
	}
	return out
}

// takeInTx runs one take in its own tenant transaction and hands back the
// outcome with the batch id of that transaction. fail makes the callback return
// an error after the take, so the transaction rolls back.
func (l *claimLab) takeInTx(who catalogtest.SeedIDs, claim uuid.UUID, code string, fail error) (out string, batch uuid.UUID) {
	l.t.Helper()
	err := l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		batch = tx.BatchID()
		out, err = tx.IPClaimTake(claim, code)
		if err != nil {
			return err
		}
		return fail
	})
	if !errors.Is(err, fail) && err != nil {
		l.t.Fatalf("take: %v", err)
	}
	return out, batch
}

// rawTx opens a transaction on a connection of its own, as a role, with the
// tenant setting made. It is for the tests that need two transactions at once.
func (l *claimLab) rawTx(role string, tenant uuid.UUID) (tx pgx.Tx, pid int) {
	l.t.Helper()
	conn, err := l.h.db.Super(l.h.ctx)
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { conn.Close(context.Background()) })
	tx, err = conn.Begin(l.h.ctx)
	if err != nil {
		l.t.Fatal(err)
	}
	l.t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if err := tx.QueryRow(l.h.ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		l.t.Fatal(err)
	}
	if role != "" {
		if _, err := tx.Exec(l.h.ctx, "SET LOCAL ROLE ctrlz_"+role); err != nil {
			l.t.Fatal(err)
		}
	}
	if tenant != uuid.Nil {
		if _, err := tx.Exec(l.h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", tenant.String()); err != nil {
			l.t.Fatal(err)
		}
	}
	return tx, pid
}

// waitForLock waits until the backend is waiting for a lock.
func (l *claimLab) waitForLock(pid int) {
	l.t.Helper()
	for i := 0; i < 200; i++ {
		var n int
		if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock'", pid).Scan(&n); err != nil {
			l.t.Fatal(err)
		}
		if n == 1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	l.t.Fatal("the backend never waited for a lock")
}

// inBackground runs a call that is expected to block on a lock, on a
// connection of its own, and reports its single text result on a channel.
func (l *claimLab) inBackground(role string, tenant uuid.UUID, sql string, args ...any) (pid int, result chan string) {
	l.t.Helper()
	tx, pid := l.rawTx(role, tenant)
	result = make(chan string, 1)
	go func() {
		var out string
		if err := tx.QueryRow(l.h.ctx, sql, args...).Scan(&out); err != nil {
			result <- "error: " + err.Error()
			return
		}
		if err := tx.Commit(l.h.ctx); err != nil {
			result <- "commit: " + err.Error()
			return
		}
		result <- out
	}()
	return pid, result
}

func (l *claimLab) await(result chan string) string {
	l.t.Helper()
	select {
	case out := <-result:
		return out
	case <-time.After(20 * time.Second):
		l.t.Fatal("the call did not finish")
		return ""
	}
}

// TestIPClaimTakeMarksTheVictimAndTheTaker (D1): a takeover writes the
// endpoint_set row of the tenant it displaced and of the taker, with the batch
// of the caller's transaction. Without the victim's row the compiler never
// emits the delete of its claim, and the nodes keep serving two customers on
// one address.
func TestIPClaimTakeMarksTheVictimAndTheTaker(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B

	l.closedMode()
	a := l.request(A, "192.0.2.90/32", "manual")
	l.want("A's closed-mode claim", a.Outcome, "active")
	l.openMode()
	b := l.pendingClaim("192.0.2.90")
	l.observe(B, b, "192.0.2.90")

	if n := len(l.outboxBatches(A.Tenant)) + len(l.outboxBatches(B.Tenant)); n != 0 {
		t.Fatalf("%d endpoint_set rows before the take", n)
	}
	// The caller does not mark anything: every row below is the function's own.
	// A P3 route may rely on that, and a test whose caller marked the taker
	// first could not see the function stop writing the taker's row.
	var batch uuid.UUID
	var out string
	err := l.tenant.WithTenant(l.h.ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		batch = tx.BatchID()
		out, err = tx.IPClaimTake(b, "")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	l.want("the takeover", out, "active")
	l.wantState("the victim", a.ClaimID, "released")
	for name, who := range map[string]catalogtest.SeedIDs{"victim": A, "taker": B} {
		got := l.outboxBatches(who.Tenant)
		if len(got) != 1 || got[0] != batch {
			t.Errorf("%s's endpoint_set rows: %v, want exactly one with the batch of the take, %s", name, got, batch)
		}
	}

	// A takeover that displaces nobody still marks the taker: its claim set
	// changed. Again nobody else marks it.
	free := l.pendingClaim("192.0.2.91")
	l.observe(B, free, "192.0.2.91")
	var batch2 uuid.UUID
	if err := l.tenant.WithTenant(l.h.ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		batch2 = tx.BatchID()
		out, err = tx.IPClaimTake(free, "")
		return err
	}); err != nil {
		t.Fatalf("a take of a free address: %v", err)
	}
	l.want("a take of a free address", out, "active")
	if got := l.outboxBatches(B.Tenant); len(got) != 2 || got[1] != batch2 {
		t.Errorf("the taker's rows after a take that displaced nobody: %v, want a second one with batch %s", got, batch2)
	}
	if got := l.outboxBatches(A.Tenant); len(got) != 1 {
		t.Errorf("a take that displaced nobody wrote a row for A: %v", got)
	}

	// The caller marking its own aggregate first must not make a second row: the
	// function's insert meets the caller's row and leaves it alone.
	again := l.pendingClaim("192.0.2.94")
	l.observe(B, again, "192.0.2.94")
	var batch3 uuid.UUID
	if err := l.tenant.WithTenant(l.h.ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		batch3 = tx.BatchID()
		if err := store.MarkDirty(tx, store.AggregateEndpointSet, B.Tenant); err != nil {
			return err
		}
		out, err = tx.IPClaimTake(again, "")
		return err
	}); err != nil {
		t.Fatalf("a take after the caller marked its aggregate: %v", err)
	}
	l.want("a take after the caller marked its aggregate", out, "active")
	if got := l.outboxBatches(B.Tenant); len(got) != 3 || got[2] != batch3 {
		t.Errorf("the taker's rows after the caller marked first: %v, want exactly one more, with batch %s", got, batch3)
	}
}

// TestIPClaimTakeWritesNothingWhenItDoesNotTake: the outbox rows are written in
// the subtransaction of the displacement, so every way a take can end without
// one leaves no row, including the one that fails halfway.
func TestIPClaimTakeWritesNothingWhenItDoesNotTake(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	none := func(what string) {
		t.Helper()
		if n := len(l.outboxBatches(A.Tenant)) + len(l.outboxBatches(B.Tenant)); n != 0 {
			t.Errorf("%s left %d endpoint_set rows", what, n)
		}
	}

	// No evidence.
	l.closedMode()
	a := l.request(A, "192.0.2.92/32", "manual")
	l.openMode()
	b := l.pendingClaim("192.0.2.92")
	out, _ := l.takeInTx(B, b, "", nil)
	l.want("a take with no evidence", out, "no_proof")
	none("a take with no evidence")

	// Blocked by a fresh proven claim.
	l.closedMode()
	p := l.request(A, "192.0.2.93/32", "manual")
	l.observe(A, p.ClaimID, "192.0.2.93")
	l.want("A proves it", l.take(A, p.ClaimID), "active")
	l.exec("DELETE FROM ctrlz.policy_outbox WHERE aggregate_type = 'endpoint_set'") // A's own proof wrote its row
	l.openMode()
	bp := l.pendingClaim("192.0.2.93")
	l.observe(B, bp, "192.0.2.93")
	out, _ = l.takeInTx(B, bp, "", nil)
	l.want("a take against a fresh proven claim", out, "unavailable")
	none("a refused takeover")
	l.wantState("A's claim", a.ClaimID, "active")

	// B holds an approved /24 with evidence from .77, where A holds an unproven
	// /32, and B also holds its own /32 at .200, which the /24 cannot be
	// activated beside.
	l.closedMode()
	v := l.request(A, "198.51.100.77/32", "manual")
	// The /24 is asked for first: a request that overlaps the tenant's own active claim is refused as `own` (D35),
	// but a pending wide row may be there already when the /32 is made, and then nothing stops the take.
	wide := l.request(B, "198.51.100.0/24", "manual")
	l.want("B's /24", wide.Outcome, "wide_requires_approval")
	own := l.request(B, "198.51.100.200/32", "manual")
	l.want("B's own /32", own.Outcome, "active")
	l.approve(wide.ClaimID)
	l.observe(B, wide.ClaimID, "198.51.100.77")
	out, _ = l.takeInTx(B, wide.ClaimID, "", nil)
	// The caller's own claim is in the way: the answer says so (the route maps it to 422 cidr exists, as for the
	// request), not `unavailable`, which means another tenant's claim (P3 4.3). Nothing is displaced or consumed.
	l.want("a take that hits B's own claim", out, "own")
	none("a take blocked by the caller's own claim")
	if st, displaced, _ := l.state(v.ClaimID); st != "active" || displaced {
		t.Errorf("the victim after the blocked take: %s displaced %v, want active and not displaced", st, displaced)
	}
	l.wantState("B's /24", wide.ClaimID, "pending_proof")
	if n := l.unconsumed(wide.ClaimID); n != 1 {
		t.Errorf("the blocked take consumed its evidence: %d left, want 1", n)
	}

	// The take that fails halfway. Since the own check, no state of the data reaches the exclusion constraint after
	// the displacement short of a race, so the race is made: a trigger of the test refuses the activation of the /24
	// with the SQLSTATE of the constraint, after the victim has been released in the same subtransaction.
	l.exec("UPDATE ctrlz.ip_claims SET state = 'released' WHERE id = $1", own.ClaimID)
	l.exec(`CREATE FUNCTION public.p3_test_activation_race() RETURNS trigger LANGUAGE plpgsql AS
$$ BEGIN RAISE EXCEPTION 'raced' USING ERRCODE = '23P01'; END $$`)
	l.exec(`CREATE TRIGGER p3_test_activation_race BEFORE UPDATE ON ctrlz.ip_claims
FOR EACH ROW WHEN (NEW.state = 'active' AND OLD.state = 'pending_proof' AND NEW.cidr = '198.51.100.0/24') EXECUTE FUNCTION public.p3_test_activation_race()`)
	out, _ = l.takeInTx(B, wide.ClaimID, "", nil)
	l.exec("DROP TRIGGER p3_test_activation_race ON ctrlz.ip_claims")
	l.exec("DROP FUNCTION public.p3_test_activation_race()")
	l.want("a take that fails at the activation", out, "unavailable")
	none("a take that failed at the activation")
	if st, displaced, _ := l.state(v.ClaimID); st != "active" || displaced {
		t.Errorf("the victim after the failed take: %s displaced %v, want active and not displaced (the subtransaction must undo the displacement)", st, displaced)
	}
	l.wantState("B's /24", wide.ClaimID, "pending_proof")
	if n := l.unconsumed(wide.ClaimID); n != 1 {
		t.Errorf("the failed take consumed its evidence: %d left, want 1", n)
	}

	// A take that succeeds and then loses its transaction.
	boom := errors.New("the handler failed after the take")
	out, _ = l.takeInTx(B, wide.ClaimID, "", boom)
	l.want("the take inside a failing handler", out, "active")
	none("a rolled-back transaction")
	if st, displaced, _ := l.state(v.ClaimID); st != "active" || displaced {
		t.Errorf("the victim after a rollback: %s displaced %v", st, displaced)
	}
}

// TestIPClaimTakeNeedsABatch (D1): the batch id comes from the caller's
// transaction, and a call without one is refused before it reads anything.
func TestIPClaimTakeNeedsABatch(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	bStr := h.B.Tenant.String()
	var out string
	h.inTx(h.super, "tenant", &bStr, func(tx pgx.Tx) {
		if err := tx.QueryRow(h.ctx, "SELECT outcome FROM ctrlz_fn.ip_claim_take($1, NULL, NULL)", h.B.Claim).Scan(&out); err != nil {
			t.Fatal(err)
		}
	})
	if out != "invalid_batch" {
		t.Errorf("a take without a batch: %q, want invalid_batch", out)
	}
}

// TestAuthMayWriteOnlyEndpointSetRows (D1): the policy that lets
// ip_claim_take write a victim's row is as narrow as the function needs.
func TestAuthMayWriteOnlyEndpointSetRows(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A.Tenant.String(), h.B.Tenant
	insert := "INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) VALUES ($1, $2, $3, gen_random_uuid())"
	for _, c := range []struct {
		what      string
		typ       string
		aggregate uuid.UUID
		ok        bool
	}{
		{"the endpoint_set of another tenant", "endpoint_set", b, true},
		{"a profile aggregate of another tenant", "profile", h.B.Profile, false},
		{"another tenant's row naming a different aggregate", "endpoint_set", h.A.Tenant, false},
	} {
		h.inTx(h.super, "auth", &a, func(tx pgx.Tx) {
			_, err := tx.Exec(h.ctx, insert, b, c.typ, c.aggregate)
			if c.ok && err != nil {
				t.Errorf("%s: %v", c.what, err)
			}
			if !c.ok && !isRLSViolation(err) {
				t.Errorf("%s: %v, want a row-level security violation", c.what, err)
			}
		})
	}
	// It reads nothing there: the policy is for INSERT only.
	h.inTx(h.super, "auth", &a, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, "SELECT count(*) FROM ctrlz.policy_outbox"); !errors.Is(storeErr(err), store.ErrPermission) {
			t.Errorf("auth read the outbox: %v", err)
		}
	})
}

// storeErr maps a raw pgx error the way the store would.
func storeErr(err error) error {
	if pe := pgErr(err); pe != nil && pe.Code == "42501" {
		return store.ErrPermission
	}
	return err
}

// TestEndpointDeleteIsGuarded (B1, D2, B3): an Endpoint with an admin hold, or
// with a suspended claim, cannot be deleted by the tenant. The delete reports
// zero rows and no error, because the policy filters the row out. Deleting the
// Endpoint was a way to erase a suspension and to recreate an Endpoint without
// its hold.
func TestEndpointDeleteIsGuarded(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	ctx := l.h.ctx

	endpoints := 0
	newEndpoint := func(who catalogtest.SeedIDs, name string) uuid.UUID {
		t.Helper()
		id := uuid.Must(uuid.NewV7())
		endpoints++
		// A resolver id is 26 characters of [a-z2-7].
		resolver := strings.Repeat("d", 24) + string(rune('a'+endpoints/26)) + string(rune('a'+endpoints%26))
		l.exec(`INSERT INTO ctrlz.endpoints (tenant_id, id, name, type, resolver_id, profile_id) VALUES ($1, $2, $3, 'doh_client', $4, $5)`,
			who.Tenant, id, name, resolver, who.Profile)
		return id
	}
	tenantDelete := func(who catalogtest.SeedIDs, ep uuid.UUID) (rows int64) {
		t.Helper()
		if err := l.tenant.WithTenant(ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			// The delete cascades into the clients of the Endpoint, which the lock order ranks before the Endpoint: the
			// caller locks them first, in id order, as the delete of a profile does (P2 spec 3.1, 3.3).
			if _, err := tx.DB().Exec(tx.Context(), "SELECT id FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 ORDER BY id FOR UPDATE", tx.TenantID(), ep); err != nil {
				return err
			}
			tag, err := tx.DB().Exec(tx.Context(), "DELETE FROM ctrlz.endpoints WHERE id = $1", ep)
			rows = tag.RowsAffected()
			return err
		}); err != nil {
			t.Fatalf("delete: %v", err)
		}
		return rows
	}
	exists := func(ep uuid.UUID) bool {
		var n int
		if err := l.h.super.QueryRow(ctx, "SELECT count(*) FROM ctrlz.endpoints WHERE id = $1", ep).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}

	// An ordinary Endpoint is deleted, claim and all.
	plain := newEndpoint(A, "plain")
	var pc store.IPClaimResult
	l.closedMode()
	if err := l.tenant.WithTenant(ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		pc, err = tx.IPClaimRequest(plain, netip.MustParsePrefix("192.0.2.140/32"), "manual")
		return err
	}); err != nil || pc.Outcome != "active" {
		t.Fatalf("request on the plain Endpoint: %v %q", err, pc.Outcome)
	}
	if n := tenantDelete(A, plain); n != 1 || exists(plain) {
		t.Errorf("an ordinary Endpoint with an active claim: %d rows, still there %v", n, exists(plain))
	}

	// The admin's hold pins the row, until an admin lifts it.
	held := newEndpoint(A, "held")
	l.exec("UPDATE ctrlz.endpoints SET admin_hold = true WHERE id = $1", held)
	if n := tenantDelete(A, held); n != 0 || !exists(held) {
		t.Errorf("a held Endpoint: %d rows deleted, still there %v; want 0 and kept", n, exists(held))
	}
	if n := tenantDelete(B, held); n != 0 || !exists(held) {
		t.Errorf("tenant B deleting A's held Endpoint: %d rows", n)
	}
	l.exec("UPDATE ctrlz.endpoints SET admin_hold = false WHERE id = $1", held)
	if n := tenantDelete(A, held); n != 1 || exists(held) {
		t.Errorf("an Endpoint after the hold was lifted: %d rows, still there %v", n, exists(held))
	}

	// A suspended claim pins the Endpoint, so it cannot be erased and requested again.
	ep := newEndpoint(A, "suspended")
	if err := l.tenant.WithTenant(ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		pc, err = tx.IPClaimRequest(ep, netip.MustParsePrefix("192.0.2.141/32"), "manual")
		return err
	}); err != nil || pc.Outcome != "active" {
		t.Fatalf("request on the second Endpoint: %v %q", err, pc.Outcome)
	}
	l.workerSets(A, pc.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")
	if n := tenantDelete(A, ep); n != 0 || !exists(ep) {
		t.Errorf("an Endpoint with a suspended claim: %d rows deleted, still there %v; want 0 and kept", n, exists(ep))
	}
	l.wantState("the suspended claim", pc.ClaimID, "suspended")
	l.want("a re-request while the Endpoint cannot be deleted", l.request(A, "192.0.2.141/32", "manual").Outcome, "suspended")
	l.exec("UPDATE ctrlz.ip_claims SET state = 'released' WHERE id = $1", pc.ClaimID)
	if n := tenantDelete(A, ep); n != 1 || exists(ep) {
		t.Errorf("an Endpoint after an admin ended the suspension: %d rows, still there %v", n, exists(ep))
	}

	// Only a suspension pins an Endpoint. The history of a claim in grace goes
	// with the Endpoint, so the tenant can delete one that is only in grace.
	graced := newEndpoint(A, "grace")
	if err := l.tenant.WithTenant(ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		pc, err = tx.IPClaimRequest(graced, netip.MustParsePrefix("192.0.2.143/32"), "manual")
		return err
	}); err != nil || pc.Outcome != "active" {
		t.Fatalf("request on the third Endpoint: %v %q", err, pc.Outcome)
	}
	l.workerSets(A, pc.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + interval '14 days' WHERE id = $1")
	l.wantState("the claim before the delete", pc.ClaimID, "grace")
	if n := tenantDelete(A, graced); n != 1 || exists(graced) {
		t.Errorf("an Endpoint with a claim in grace: %d rows deleted, still there %v; want 1 and gone", n, exists(graced))
	}

	// The worker's purge of a whole tenant still cascades through held and
	// suspended Endpoints: the policy names the tenant role.
	purge := newEndpoint(B, "purge")
	l.exec("UPDATE ctrlz.endpoints SET admin_hold = true WHERE id = $1", purge)
	if err := l.tenant.WithTenant(ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		pc, err = tx.IPClaimRequest(purge, netip.MustParsePrefix("192.0.2.142/32"), "manual")
		return err
	}); err != nil || pc.Outcome != "active" {
		t.Fatalf("request on B's Endpoint: %v %q", err, pc.Outcome)
	}
	l.exec("UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1", pc.ClaimID)
	l.purgeTenant(B)
	var left int
	if err := l.h.super.QueryRow(ctx, "SELECT (SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1) + (SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1)", B.Tenant).Scan(&left); err != nil || left != 0 {
		t.Errorf("after the purge of tenant B: %d endpoint and claim rows, err %v", left, err)
	}
}

// purgeTenant deletes a tenant the way the P5 purge will: by a role that is not the
// tenant role, in a transaction scoped to that tenant, and lets the foreign keys
// cascade. It used to run as ctrlz_worker; the worker holds no DELETE on tenants any
// more (migration 0026, db-r5-6: that grant was the root of every cascade through a
// tenant's credentials and trail), and the purge will be a definer function. The table
// owner is bound by the same FORCE ROW LEVEL SECURITY, so the hold_blocks_delete policy
// (which names the tenant role) is exercised exactly as the worker's delete exercised it.
func (l *claimLab) purgeTenant(who catalogtest.SeedIDs) {
	l.t.Helper()
	tx, err := l.h.super.Begin(l.h.ctx)
	if err != nil {
		l.t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(l.h.ctx, "SET LOCAL ROLE ctrlz_migrator"); err != nil {
		l.t.Fatal(err)
	}
	if _, err := tx.Exec(l.h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", who.Tenant.String()); err != nil {
		l.t.Fatal(err)
	}
	tag, err := tx.Exec(l.h.ctx, "DELETE FROM ctrlz.tenants WHERE id = $1", who.Tenant)
	if err != nil {
		l.t.Fatalf("purge of the tenant: %v", err)
	}
	if tag.RowsAffected() != 1 {
		l.t.Fatalf("the purge deleted %d tenants", tag.RowsAffected())
	}
	if err := tx.Commit(l.h.ctx); err != nil {
		l.t.Fatalf("purge of the tenant: %v", err)
	}
}

// TestSuspendedClaimBlocksItsOverlappingTwins (B2, D3): the tenant's own
// suspended claim keeps every overlapping claim of the tenant from becoming
// active, or from collecting proof.
func TestSuspendedClaimBlocksItsOverlappingTwins(t *testing.T) {
	l := newClaimLab(t)
	B := l.B
	l.openMode()

	// (a) Open mode does not deduplicate pending claims, so B has two for one
	// address. Both have evidence; one is proven, then suspended.
	s1 := l.pendingClaim("198.51.100.8")
	s2 := l.pendingClaim("198.51.100.8")
	l.observe(B, s1, "198.51.100.8")
	l.observe(B, s2, "198.51.100.8")
	l.want("B proves the first", l.take(B, s1), "active")
	l.workerSets(B, s1, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")
	l.want("a new request for the prefix", l.request(B, "198.51.100.8/32", "manual").Outcome, "suspended")
	l.want("the spare, which has evidence on file", l.take(B, s2), "suspended")
	l.wantState("the spare", s2, "pending_proof")
	if _, ok := l.tryOpen(B, s2); ok {
		t.Error("a challenge for the pending twin of a suspended claim")
	}
	// A claim that does not overlap is not affected.
	other := l.pendingClaim("198.51.100.9")
	l.observe(B, other, "198.51.100.9")
	l.want("a disjoint claim", l.take(B, other), "active")
	// Once an admin ends the suspension the twin works again.
	l.exec("UPDATE ctrlz.ip_claims SET state = 'released' WHERE id = $1", s1)
	l.want("the spare after the suspension ended", l.take(B, s2), "active")
}

// TestRequestWaitsForASuspensionInFlight (D3 b): the admin's UPDATE has not
// committed when the tenant asks for the same prefix. The request must not slip
// past it and leave an active row beside the suspended one.
func TestRequestWaitsForASuspensionInFlight(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	l.closedMode()
	c := l.request(A, "203.0.113.50/32", "manual")
	l.want("the claim", c.Outcome, "active")

	admin, _ := l.rawTx("worker", A.Tenant)
	if _, err := admin.Exec(l.h.ctx, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1", c.ClaimID); err != nil {
		t.Fatal(err)
	}
	pid, result := l.inBackground("tenant", A.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_request($1, '203.0.113.50/32', 'manual')", A.Endpoint)
	l.waitForLock(pid)
	if err := admin.Commit(l.h.ctx); err != nil {
		t.Fatal(err)
	}
	l.want("the request that overlapped the suspension", l.await(result), "suspended")
	var active int
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND cidr = '203.0.113.50/32' AND state = 'active'", A.Tenant).Scan(&active); err != nil || active != 0 {
		t.Errorf("%d active rows beside the suspended one, err %v", active, err)
	}
}

// TestTakeLocksTheTenantsClaimsInIDOrder (B2): the take locks the claim and its
// overlapping twins in one statement ordered by id, so twin takes cannot
// deadlock on each other. The order is shown by what is locked while the take
// waits for the other row.
func TestTakeLocksTheTenantsClaimsInIDOrder(t *testing.T) {
	l := newClaimLab(t)
	B := l.B
	l.openMode()
	c1 := l.pendingClaim("198.51.100.20")
	c2 := l.pendingClaim("198.51.100.20")
	lo, hi := c1, c2
	if lo.String() > hi.String() {
		lo, hi = hi, lo
	}
	l.observe(B, lo, "198.51.100.20")
	l.observe(B, hi, "198.51.100.20")

	locked := func(id uuid.UUID) bool {
		conn, err := l.h.db.Super(l.h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(context.Background())
		tx, err := conn.Begin(l.h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		_, err = tx.Exec(l.h.ctx, "SELECT 1 FROM ctrlz.ip_claims WHERE id = $1 FOR UPDATE NOWAIT", id)
		return pgErr(err) != nil && pgErr(err).Code == "55P03"
	}
	for _, c := range []struct {
		what         string
		take, holder uuid.UUID
		wantLocked   uuid.UUID
		wantFree     bool
	}{
		// Taking the lower id while the higher one is held: the lower is locked first.
		{"take the lower id", lo, hi, lo, false},
		// Taking the higher id while the lower one is held: the take waits at the
		// lower one and has locked nothing else.
		{"take the higher id", hi, lo, hi, true},
	} {
		holder, _ := l.rawTx("", uuid.Nil)
		if _, err := holder.Exec(l.h.ctx, "SELECT 1 FROM ctrlz.ip_claims WHERE id = $1 FOR UPDATE", c.holder); err != nil {
			t.Fatal(err)
		}
		pid, result := l.inBackground("tenant", B.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_take($1, NULL, gen_random_uuid())", c.take)
		l.waitForLock(pid)
		if got := locked(c.wantLocked); got == c.wantFree {
			t.Errorf("%s: the claim %s is locked: %v, want %v (locks must be taken in ascending id order)", c.what, c.wantLocked, got, !c.wantFree)
		}
		if err := holder.Rollback(l.h.ctx); err != nil {
			t.Fatal(err)
		}
		if out := l.await(result); out != "active" && out != "unavailable" && out != "own" {
			t.Errorf("%s: %q", c.what, out)
		}
		// Reset for the next case.
		l.exec("UPDATE ctrlz.ip_claims SET state = 'pending_proof', proven_at = NULL, proof_method = NULL WHERE id IN ($1, $2)", lo, hi)
		l.exec("UPDATE ctrlz.ip_proof_challenges SET consumed_at = NULL WHERE claim_id IN ($1, $2)", lo, hi)
	}
}

// TestIPClaimTakeAfterRelease (D5): a released or displaced claim stays dead,
// whatever evidence is left on file, and a release that commits first wins
// against a take that was already running.
func TestIPClaimTakeAfterRelease(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.openMode()

	// Released by its owner, evidence still on file.
	c := l.pendingClaim("192.0.2.150")
	l.observe(B, c, "192.0.2.150")
	l.want("B releases", l.release(B, c), "released")
	l.want("a take after the release", l.take(B, c), "not_found")
	l.wantState("the released claim", c, "released")

	// Displaced by another tenant, who then releases; the old evidence is
	// still unconsumed and must not bring the claim back.
	l.closedMode()
	a := l.request(A, "192.0.2.151/32", "manual")
	l.want("A's claim", a.Outcome, "active")
	l.observe(A, a.ClaimID, "192.0.2.151") // evidence kept for after the displacement
	l.openMode()
	b := l.pendingClaim("192.0.2.151")
	l.observe(B, b, "192.0.2.151")
	l.want("B displaces A's unproven claim", l.take(B, b), "active")
	l.wantState("A's claim", a.ClaimID, "released")
	l.want("B releases", l.release(B, b), "released")
	if n := l.unconsumed(a.ClaimID); n != 1 {
		t.Fatalf("A's old evidence: %d unconsumed, want 1", n)
	}
	l.want("A takes the displaced claim back on old evidence", l.take(A, a.ClaimID), "not_found")
	l.wantState("A's displaced claim", a.ClaimID, "released")

	// The release commits first; the take that started before it must see that.
	r := l.pendingClaim("192.0.2.152")
	l.observe(B, r, "192.0.2.152")
	rel, _ := l.rawTx("tenant", B.Tenant)
	var out string
	if err := rel.QueryRow(l.h.ctx, "SELECT outcome FROM ctrlz_fn.ip_claim_release($1)", r).Scan(&out); err != nil || out != "released" {
		t.Fatalf("release: %q %v", out, err)
	}
	pid, result := l.inBackground("tenant", B.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_take($1, NULL, gen_random_uuid())", r)
	l.waitForLock(pid)
	if err := rel.Commit(l.h.ctx); err != nil {
		t.Fatal(err)
	}
	l.want("a take that was waiting behind the release", l.await(result), "not_found")
	l.wantState("the released claim", r, "released")
}

// TestIPClaimTakeEvidenceRules (D7): four rules of the evidence that no test
// pinned.
func TestIPClaimTakeEvidenceRules(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.openMode()

	t.Run("the whole hash is compared", func(t *testing.T) {
		c := l.pendingClaim("192.0.2.160")
		code := l.observeOver(B, c, "192.0.2.160", "udp")
		// A hash that differs from the right one only in its last byte. A real
		// near-collision cannot be made, so the stored hash is edited.
		l.exec(`UPDATE ctrlz.ip_proof_challenges SET txt_code_hash = set_byte(txt_code_hash, 31, get_byte(txt_code_hash, 31) # 1) WHERE claim_id = $1`, c)
		l.want("the right code against a hash that differs in byte 31", l.takeWith(B, c, code), "no_proof")
		l.wantState("the claim", c, "pending_proof")
	})

	t.Run("a consumed challenge proves nothing again", func(t *testing.T) {
		c := l.pendingClaim("192.0.2.161")
		l.observe(B, c, "192.0.2.161")
		l.want("the first proof", l.take(B, c), "active")
		// An admin clears the claim back to pending.
		l.exec("UPDATE ctrlz.ip_claims SET state = 'pending_proof', proven_at = NULL, proof_method = NULL WHERE id = $1", c)
		l.want("a replay of the spent evidence", l.take(B, c), "no_proof")
		l.wantState("the cleared claim", c, "pending_proof")
	})

	t.Run("evidence of one claim does not prove its twin", func(t *testing.T) {
		c1 := l.pendingClaim("192.0.2.162")
		c2 := l.pendingClaim("192.0.2.162")
		l.observe(B, c1, "192.0.2.162")
		l.want("the twin without evidence of its own", l.take(B, c2), "no_proof")
		l.wantState("the twin", c2, "pending_proof")
		l.want("the claim with evidence", l.take(B, c1), "active")
	})

	t.Run("another tenant's claim id answers not_found", func(t *testing.T) {
		// The oracle: ctrlz_auth reads every tenant's claims, so the function
		// itself must keep the lookup to the caller's tenant. In every state
		// the answer is the one for an id that does not exist.
		l.closedMode()
		active := l.request(A, "192.0.2.163/32", "manual")
		l.openMode()
		pending := l.pendingClaimOf(A, "192.0.2.164")
		suspended := l.pendingClaimOf(A, "192.0.2.165")
		l.exec("UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1", suspended)
		l.observe(A, pending, "192.0.2.164")
		proven := l.pendingClaimOf(A, "192.0.2.166")
		l.observe(A, proven, "192.0.2.166")
		l.want("A proves one", l.take(A, proven), "active")
		for name, id := range map[string]uuid.UUID{"active": active.ClaimID, "pending with evidence": pending, "suspended": suspended, "proven": proven, "unknown": uuid.Must(uuid.NewV7())} {
			l.want("B takes A's "+name+" claim", l.take(B, id), "not_found")
		}
		l.wantState("A's pending claim", pending, "pending_proof")
	})
}

// TestIPClaimOwnerProvesFromGrace (D8): the owner of an unproven claim can prove
// it during its grace, which is the path a user takes in the 14 days. The proof
// ends the grace.
func TestIPClaimOwnerProvesFromGrace(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	l.closedMode()
	g := l.request(A, "192.0.2.170/32", "manual")
	l.want("A's closed-mode claim", g.Outcome, "active")
	l.workerSets(A, g.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + interval '14 days' WHERE id = $1")
	l.observe(A, g.ClaimID, "192.0.2.170")
	l.want("the owner proves its claim in grace", l.take(A, g.ClaimID), "active")
	var graceUntil *time.Time
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT grace_until FROM ctrlz.ip_claims WHERE id = $1", g.ClaimID).Scan(&graceUntil); err != nil {
		t.Fatal(err)
	}
	if st, _, proven := l.state(g.ClaimID); st != "active" || !proven || graceUntil != nil {
		t.Errorf("after the proof: state %s proven %v grace_until %v, want active, proven and no grace", st, proven, graceUntil)
	}
	l.want("a second take", l.take(A, g.ClaimID), "already_active")
}

// TestUnapprovedWideClaimIsNeverProven (D4): proof of one address says nothing
// about the range around it, in any mode. A closed-mode /28 stays active and
// unproven, so the sweep of a later open registration still sees it.
func TestUnapprovedWideClaimIsNeverProven(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	l.closedMode()
	w := l.request(A, "192.0.2.128/28", "manual")
	l.want("a closed-mode /28", w.Outcome, "active")
	l.observe(A, w.ClaimID, "192.0.2.129")
	l.want("a proof from one address of the /28", l.take(A, w.ClaimID), "wide_requires_approval")
	if st, _, proven := l.state(w.ClaimID); st != "active" || proven {
		t.Errorf("the /28 after the refused proof: %s proven %v, want active and unproven", st, proven)
	}
	l.approve(w.ClaimID)
	l.want("the same proof once an admin approved it", l.take(A, w.ClaimID), "active")
}

// TestOTPCooldownHoldsUnderConcurrency (D9, B6): several calls for one phone
// and purpose from different networks overlap, and exactly one message goes
// out. The cooldown check used to run before any lock, so none of them saw the
// others' uncommitted challenge.
func TestOTPCooldownHoldsUnderConcurrency(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	cfg := h.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 16
	s, err := store.Open(h.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	const callers, rounds = 8, 12
	hash := store.OTPCodeHash(func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }, "+989121234567", "login", "123456")
	for round := 0; round < rounds; round++ {
		phone := fmt.Sprintf("+98912555%04d", round)
		var wg sync.WaitGroup
		start := make(chan struct{})
		allowed := make(chan bool, callers)
		for c := 0; c < callers; c++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				// A different /24 for each caller, so none of the per-network
				// caps is what refuses the others.
				ip := netip.MustParseAddr(fmt.Sprintf("198.51.%d.%d", 10+c, 7))
				res, err := s.Auth().OTPIssue(h.ctx, phone, "login", hash, []byte("delivery"), ip, false)
				if err != nil {
					t.Errorf("issue: %v", err)
					allowed <- false
					return
				}
				allowed <- res.Allowed
			}()
		}
		close(start)
		wg.Wait()
		close(allowed)
		n := 0
		for a := range allowed {
			if a {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("round %d: %d messages for one phone and purpose inside the cooldown, want exactly 1", round, n)
		}
		var rows int
		if err := h.super.QueryRow(h.ctx, "SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = $1", phone).Scan(&rows); err != nil || rows != 1 {
			t.Fatalf("round %d: %d challenges stored, err %v", round, rows, err)
		}
		// A refused call left no counter behind: the phone counter is at one.
		var count int
		if err := h.super.QueryRow(h.ctx, "SELECT count FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = $1", phone).Scan(&count); err != nil || count != 1 {
			t.Fatalf("round %d: phone counter %d (err %v), want 1; a refusal must undo the counters", round, count, err)
		}
	}
}

// TestProofChallengesPerClaimAreCapped (D11): at most ten live challenges per
// claim, consumed or not, and the cap frees as they expire.
func TestProofChallengesPerClaimAreCapped(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	l.openMode()
	c := l.pendingClaimOf(A, "192.0.2.180")
	for i := 1; i <= 10; i++ {
		if _, ok := l.tryOpen(A, c); !ok {
			t.Fatalf("challenge %d refused", i)
		}
	}
	if _, ok := l.tryOpen(A, c); ok {
		t.Error("an eleventh live challenge")
	}
	// The count is exact under concurrency: with nine live, two openings that
	// overlap make one more and not two.
	race := l.pendingClaimOf(A, "192.0.2.182")
	for i := 1; i <= 9; i++ {
		l.open(A, race)
	}
	first, _ := l.rawTx("tenant", A.Tenant)
	if err := first.QueryRow(l.h.ctx, "SELECT label FROM ctrlz_fn.ip_claim_open_challenge($1)", race).Scan(new(string)); err != nil {
		t.Fatalf("the tenth challenge: %v", err)
	}
	pid, result := l.inBackground("tenant", A.Tenant, "SELECT COALESCE((SELECT label FROM ctrlz_fn.ip_claim_open_challenge($1)), 'none')", race)
	l.waitForLock(pid)
	if err := first.Commit(l.h.ctx); err != nil {
		t.Fatal(err)
	}
	if got := l.await(result); got != "none" {
		t.Errorf("an opening that overlapped the tenth: %q, want none", got)
	}
	var live int
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_proof_challenges WHERE claim_id = $1", race).Scan(&live); err != nil || live != 10 {
		t.Errorf("%d challenges on the claim, want 10 (err %v)", live, err)
	}
	// Consumed ones count while they are live.
	l.exec("UPDATE ctrlz.ip_proof_challenges SET consumed_at = now() WHERE claim_id = $1", c)
	if _, ok := l.tryOpen(A, c); ok {
		t.Error("a challenge after the live ones were consumed")
	}
	// A different claim has its own cap.
	other := l.pendingClaimOf(A, "192.0.2.181")
	if _, ok := l.tryOpen(A, other); !ok {
		t.Error("the cap of one claim refused another")
	}
	// Expired challenges do not count.
	l.exec("UPDATE ctrlz.ip_proof_challenges SET expires_at = now() - interval '1 minute', created_at = now() - interval '14 minutes' WHERE claim_id = $1 AND id IN (SELECT id FROM ctrlz.ip_proof_challenges WHERE claim_id = $1 LIMIT 3)", c)
	for i := 1; i <= 3; i++ {
		if _, ok := l.tryOpen(A, c); !ok {
			t.Fatalf("challenge %d after three expired", i)
		}
	}
	if _, ok := l.tryOpen(A, c); ok {
		t.Error("a fourth challenge beyond the cap")
	}
}

// TestWorkerSweepsFilterOnExpiry (D11, B5): the worker can select the key and
// expiry columns of the three proof and link tables, so a sweep can say which
// rows to delete, and never the token hashes.
func TestWorkerSweepsFilterOnExpiry(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	sweep := func(sql string) (rows int64, err error) {
		err = l.worker.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			tag, e := tx.DB().Exec(tx.Context(), sql)
			rows = tag.RowsAffected()
			return e
		})
		return
	}
	// The seed rows are alive: the filtered deletes touch none of them, and
	// they succeed instead of failing with permission denied.
	for _, q := range []string{
		"DELETE FROM ctrlz.ip_proof_challenges WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM ctrlz.ip_proof_challenges WHERE consumed_at IS NOT NULL AND expires_at < now()",
		"DELETE FROM ctrlz.setup_share_tokens WHERE expires_at < now() OR revoked_at IS NOT NULL",
		"DELETE FROM ctrlz.profile_download_tokens WHERE expires_at < now()",
	} {
		if n, err := sweep(q); err != nil || n != 0 {
			t.Errorf("%s: %d rows, %v", q, n, err)
		}
	}
	// And they do delete what has expired.
	l.exec("UPDATE ctrlz.ip_proof_challenges SET expires_at = now() - interval '2 days', created_at = now() - interval '2 days' WHERE tenant_id = $1", A.Tenant)
	l.exec("UPDATE ctrlz.setup_share_tokens SET revoked_at = now() WHERE tenant_id = $1", A.Tenant)
	l.exec("UPDATE ctrlz.profile_download_tokens SET expires_at = now() - interval '1 hour' WHERE tenant_id = $1", A.Tenant)
	// The download link goes first: the seeded link was made through the share link (via_share_id), so deleting the
	// share link deletes it as well.
	for _, q := range []string{
		"DELETE FROM ctrlz.ip_proof_challenges WHERE expires_at < now() - interval '1 day'",
		"DELETE FROM ctrlz.profile_download_tokens WHERE expires_at < now()",
		"DELETE FROM ctrlz.setup_share_tokens WHERE expires_at < now() OR revoked_at IS NOT NULL",
	} {
		if n, err := sweep(q); err != nil || n != 1 {
			t.Errorf("%s: %d rows, %v, want 1", q, n, err)
		}
	}
	// Never the hashes.
	for _, q := range []string{
		"DELETE FROM ctrlz.setup_share_tokens WHERE token_hash IS NULL",
		"DELETE FROM ctrlz.profile_download_tokens WHERE token_hash IS NULL",
		"DELETE FROM ctrlz.ip_proof_challenges WHERE txt_code_hash IS NULL",
	} {
		if _, err := sweep(q); !errors.Is(err, store.ErrPermission) {
			t.Errorf("%s: %v, want permission denied", q, err)
		}
	}
}

// TestRequestInheritsTheGraceOfThePrefix (D12): a claim gets one grace. Releasing
// it and requesting the same prefix again must not start a second one.
func TestRequestInheritsTheGraceOfThePrefix(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	firstGrace := func(claim uuid.UUID) (t0 *time.Time) {
		if err := l.h.super.QueryRow(l.h.ctx, "SELECT first_grace_at FROM ctrlz.ip_claims WHERE id = $1", claim).Scan(&t0); err != nil {
			l.t.Fatal(err)
		}
		return t0
	}
	graced := func(prefix string) (uuid.UUID, *time.Time) {
		l.closedMode()
		c := l.request(A, prefix, "manual")
		l.workerSets(A, c.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now() - interval '3 days', grace_until = now() + interval '11 days' WHERE id = $1")
		l.want("release from grace", l.release(A, c.ClaimID), "released")
		return c.ClaimID, firstGrace(c.ClaimID)
	}

	// The three branches of the insert.
	_, old := graced("192.0.2.190/32")
	if old == nil {
		t.Fatal("no first_grace_at on the first claim")
	}
	again := l.request(A, "192.0.2.190/32", "manual") // closed, active
	l.want("closed-mode re-request", again.Outcome, "active")
	if got := firstGrace(again.ClaimID); got == nil || !got.Equal(*old) {
		t.Errorf("closed-mode re-request: first_grace_at %v, want the old %v", got, old)
	}

	_, old = graced("192.0.2.191/32")
	l.openMode()
	again = l.request(A, "192.0.2.191/32", "manual") // open, pending
	l.want("open-mode re-request", again.Outcome, "pending_proof")
	if got := firstGrace(again.ClaimID); got == nil || !got.Equal(*old) {
		t.Errorf("open-mode re-request: first_grace_at %v, want the old %v", got, old)
	}

	l.closedMode()
	_, old = graced("192.0.2.192/32")
	wide := l.request(A, "192.0.2.192/27", "manual") // overlaps, wide, pending
	l.want("wide re-request", wide.Outcome, "wide_requires_approval")
	if got := firstGrace(wide.ClaimID); got == nil || !got.Equal(*old) {
		t.Errorf("wide re-request: first_grace_at %v, want the old %v", got, old)
	}

	// The newest overlapping row need not be the graced one: a wide request over
	// an old graced prefix and a newer ungraced neighbour keeps the grace.
	_, old = graced("198.51.100.8/32")
	newer := l.request(A, "198.51.100.9/32", "manual")
	l.want("the ungraced neighbour", newer.Outcome, "active")
	// An active neighbour would make the wide request `own` (D35); the ungraced row that matters here is a newer one
	// that is no longer held, which the grace still has to look past.
	l.want("the neighbour is released", l.release(A, newer.ClaimID), "released")
	over := l.request(A, "198.51.100.0/26", "manual")
	l.want("wide request over both", over.Outcome, "wide_requires_approval")
	if got := firstGrace(over.ClaimID); got == nil || !got.Equal(*old) {
		t.Errorf("wide request over a graced and a newer row: first_grace_at %v, want the old %v", got, old)
	}

	// A prefix that overlaps nothing the tenant had starts clean, and so does
	// another tenant's request for a prefix that A once held in grace.
	fresh := l.request(A, "192.0.2.230/32", "manual")
	if got := firstGrace(fresh.ClaimID); got != nil {
		t.Errorf("a fresh prefix inherited a grace: %v", got)
	}
	other := l.request(l.B, "192.0.2.192/32", "manual")
	l.want("another tenant's request for A's old prefix", other.Outcome, "active")
	if got := firstGrace(other.ClaimID); got != nil {
		t.Errorf("another tenant's claim carries A's grace: %v", got)
	}
}

// TestTOTPSeedChecksTheTenantSetting (A1): with a tenant setting, the tenant
// argument must be that tenant, and without a setting nothing is returned.
func TestTOTPSeedChecksTheTenantSetting(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	h.exec("UPDATE ctrlz.users SET totp_secret_ct = '\\xdeadbeef' WHERE tenant_id = $1", b.Tenant)
	h.exec("UPDATE ctrlz.users SET totp_secret_ct = '\\xfeed' WHERE tenant_id = $1", a.Tenant)
	aStr := a.Tenant.String()
	seed := func(guc *string, user, tenant uuid.UUID) (rows int, ct []byte) {
		h.inTx(h.super, "tenant", guc, func(tx pgx.Tx) {
			r, err := tx.Query(h.ctx, "SELECT totp_secret_ct FROM ctrlz_fn.auth_totp_seed($1, $2)", user, tenant)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			for r.Next() {
				rows++
				if err := r.Scan(&ct); err != nil {
					t.Fatal(err)
				}
			}
		})
		return
	}
	// No setting, no seed: the branch that served a login lookup before a session
	// existed is gone (db-r5-9), so a connection that never set a tenant gets nothing
	// for any pair of ids.
	if rows, ct := seed(nil, b.User, b.Tenant); rows != 0 {
		t.Errorf("no setting: %d rows %x, want none", rows, ct)
	}
	if rows, ct := seed(nil, a.User, a.Tenant); rows != 0 {
		t.Errorf("no setting, A's ids: %d rows %x, want none", rows, ct)
	}
	if rows, ct := seed(&aStr, a.User, a.Tenant); rows != 1 || string(ct) != "\xfe\xed" {
		t.Errorf("tenant A asking for its own seed: %d rows %x", rows, ct)
	}
	if rows, _ := seed(&aStr, b.User, b.Tenant); rows != 0 {
		t.Errorf("tenant A asking for tenant B's seed given B's ids: %d rows, want 0", rows)
	}
	if rows, _ := seed(&aStr, a.User, b.Tenant); rows != 0 {
		t.Errorf("a mismatched pair under a setting: %d rows", rows)
	}
}

func (h *harness) exec(sql string, args ...any) {
	h.t.Helper()
	if _, err := h.super.Exec(h.ctx, sql, args...); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
}

// TestHubKeepsTheLatestLastSeen (B4): the hub can read last_seen_at on the three
// tables it writes it on, so GREATEST keeps the maximum and a late batch does
// not move the value back.
func TestHubKeepsTheLatestLastSeen(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	for _, tbl := range []string{"ip_claims", "clients", "authorized_ips"} {
		sql := fmt.Sprintf("UPDATE ctrlz.%s SET last_seen_at = GREATEST(last_seen_at, $1) WHERE tenant_id = $2", tbl)
		older := time.Now().Add(-8 * 24 * time.Hour)
		l.exec(fmt.Sprintf("UPDATE ctrlz.%s SET last_seen_at = now() WHERE tenant_id = $1", tbl), A.Tenant)
		if err := l.hub.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, err := tx.DB().Exec(tx.Context(), sql, older, A.Tenant)
			return err
		}); err != nil {
			t.Errorf("%s: GREATEST(last_seen_at, ...) as the hub: %v", tbl, err)
			continue
		}
		var recent bool
		if err := l.h.super.QueryRow(l.h.ctx, fmt.Sprintf("SELECT bool_and(last_seen_at > now() - interval '1 minute') FROM ctrlz.%s WHERE tenant_id = $1", tbl), A.Tenant).Scan(&recent); err != nil || !recent {
			t.Errorf("%s: a late batch moved last_seen_at back (recent=%v, err %v)", tbl, recent, err)
		}
	}
}

// TestShareLinkRevokedDoesNotResolve (D14 2): auth_share_by_hash filters on
// revoked_at.
func TestShareLinkRevokedDoesNotResolve(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A
	resolves := func() int {
		n := 0
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			var err error
			n, err = count(h.ctx, tx, "SELECT count(*) FROM ctrlz_fn.auth_share_by_hash($1)", []byte(a.Share))
			if err != nil {
				t.Fatal(err)
			}
		})
		return n
	}
	if resolves() != 1 {
		t.Fatal("a live share link does not resolve")
	}
	h.exec("UPDATE ctrlz.setup_share_tokens SET revoked_at = now() WHERE tenant_id = $1", a.Tenant)
	if n := resolves(); n != 0 {
		t.Errorf("a revoked share link resolves: %d rows", n)
	}
}

// TestClaimsAreIPv4Only (D14 3): the table refuses an IPv6 prefix even from the
// superuser, which bypasses grants and policies but not CHECKs.
func TestClaimsAreIPv4Only(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A
	code := h.try("", nil, "INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source) VALUES ($1, $2, '2001:db8::/32', 'pending_proof', 'manual')", a.Tenant, a.Endpoint)
	if code != "23514" {
		t.Errorf("an IPv6 claim: SQLSTATE %q, want 23514", code)
	}
	// And the CHECK is what refused it, not the exclusion constraint.
	_, err := h.super.Exec(h.ctx, "INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source) VALUES ($1, $2, '2001:db8::/32', 'pending_proof', 'manual')", a.Tenant, a.Endpoint)
	if pe := pgErr(err); pe == nil || pe.ConstraintName != "ip_claims_ipv4" {
		t.Errorf("the constraint that refused the IPv6 claim: %v, want ip_claims_ipv4", err)
	}
}

// TestProofMethodIsNeverTheCallers (D13): browser_ip is not a proof method.
// How the address was supplied is ip_claims.source.
func TestProofMethodIsNeverTheCallers(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, m := range []string{"verify_tcp", "verify_udp_txt", "secure_dns"} {
		if code := h.try("", nil, "UPDATE ctrlz.ip_claims SET proof_method = $1", m); code != "" {
			t.Errorf("proof_method %s: %q", m, code)
		}
	}
	if code := h.try("", nil, "UPDATE ctrlz.ip_claims SET proof_method = 'browser_ip'"); code != "23514" {
		t.Errorf("proof_method browser_ip: %q, want 23514", code)
	}
	if code := h.try("", nil, "UPDATE ctrlz.ip_claims SET source = 'browser'"); code != "" {
		t.Errorf("source browser: %q", code)
	}
}

// TestCatalogWireIDs (A9): contract 9.5. Native filters are below 1000 and
// third-party ones start there; services use the full u32 range.
func TestCatalogWireIDs(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	const checkViolation = "23514"
	filter := func(kind string, wire int) string {
		return h.try("", nil, "INSERT INTO ctrlz.catalog_filter (id, wire_id, kind, name_en, name_fa) VALUES ('f' || ($2::int)::text, $2::int, $1::text, 'x', 'x')", kind, wire)
	}
	for _, c := range []struct {
		kind string
		wire int
		want string
	}{
		{"native", 900, ""}, {"native", 999, ""}, {"native", 1000, checkViolation}, {"native", 2000, checkViolation},
		{"third_party", 5, checkViolation}, {"third_party", 999, checkViolation}, {"third_party", 5000, ""}, {"third_party", 65535, ""},
		{"third_party", 65536, checkViolation},
	} {
		if got := filter(c.kind, c.wire); got != c.want {
			t.Errorf("%s filter with wire id %d: %q, want %q", c.kind, c.wire, got, c.want)
		}
	}
	service := func(wire int64) string {
		return h.try("", nil, "INSERT INTO ctrlz.catalog_service (slug, wire_id, category_id, name_en, name_fa) VALUES ('s' || ($1::bigint)::text, $1::bigint, 'video', 'x', 'x')", wire)
	}
	for _, c := range []struct {
		wire int64
		want string
	}{
		{0, checkViolation}, {1000000, ""}, {65535, ""}, {70000, ""}, {4294967295, ""}, {4294967296, checkViolation},
	} {
		if got := service(c.wire); got != c.want {
			t.Errorf("service wire id %d: %q, want %q", c.wire, got, c.want)
		}
	}
}

// TestProfileCountsOptions (A8): option_count counts the option units a profile
// sets (P2 spec 2.2 item 10, SC 6): the Default Rule, the Block Response with its
// custom address and ECS with its subnets are one each. default_location_unavailable
// is a flag with a default, not an option. Two tenants, fixed numbers.
func TestProfileCountsOptions(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	// The seeded Profile 1 of each tenant sets two units (the Default Rule with its
	// location, and the Block Response with its custom address); Profile 2 has no
	// options row.
	h.exec("INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'bare')", h.A.Tenant, uuid.MustParse("00000000-0000-7000-8000-00000000a0b1"))
	h.exec("INSERT INTO ctrlz.profile_options (tenant_id, profile_id) VALUES ($1, $2)", h.A.Tenant, uuid.MustParse("00000000-0000-7000-8000-00000000a0b1"))
	counts := func(who catalogtest.SeedIDs) map[uuid.UUID]int {
		out := map[uuid.UUID]int{}
		whoStr := who.Tenant.String()
		h.inTx(h.super, "tenant", &whoStr, func(tx pgx.Tx) {
			r, err := tx.Query(h.ctx, "SELECT profile_id, option_count FROM ctrlz.tenant_profile_counts")
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			for r.Next() {
				var id uuid.UUID
				var n int
				if err := r.Scan(&id, &n); err != nil {
					t.Fatal(err)
				}
				out[id] = n
			}
		})
		return out
	}
	a, b := counts(h.A), counts(h.B)
	for _, c := range []struct {
		what string
		got  map[uuid.UUID]int
		id   uuid.UUID
		want int
	}{
		{"A, two option units set", a, h.A.Profile, 2},
		{"A, no options row", a, h.A.Profile2, 0},
		{"A, a row with every option at its default", a, uuid.MustParse("00000000-0000-7000-8000-00000000a0b1"), 0},
		{"B, two option units set", b, h.B.Profile, 2},
		{"B, no options row", b, h.B.Profile2, 0},
	} {
		if n, ok := c.got[c.id]; !ok || n != c.want {
			t.Errorf("%s: option_count %d (present %v), want %d", c.what, n, ok, c.want)
		}
	}
	if len(a) != 3 || len(b) != 2 {
		t.Errorf("a tenant sees %d and %d profiles, want 3 and 2", len(a), len(b))
	}
}

// TestDeletingProfile1PromotesProfile2 (B9): a client keeps the Profile 2 the
// user chose when its Profile 1 is deleted. It works for the tenant, and for the
// cascade of a tenant purge by the worker.
func TestDeletingProfile1PromotesProfile2(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	ctx := l.h.ctx
	// The seeded client uses Profile 1 with Profile 2. The Endpoint and the
	// schedule window of the seed reference the profiles too and would block
	// the delete (RESTRICT), so they go first.
	l.exec("DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1", A.Tenant)
	l.exec("UPDATE ctrlz.endpoints SET profile_id = $2, profile2_id = NULL WHERE tenant_id = $1", A.Tenant, A.Profile2)

	var rows int64
	if err := l.tenant.WithTenant(ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		// The clients that name the profile are locked first, in id order (spec 3.3).
		if err := tx.ProfileClientsLock(A.Profile); err != nil {
			return err
		}
		tag, err := tx.DB().Exec(tx.Context(), "DELETE FROM ctrlz.profiles WHERE id = $1", A.Profile)
		rows = tag.RowsAffected()
		return err
	}); err != nil || rows != 1 {
		t.Fatalf("deleting Profile 1 as the tenant: %d rows, %v", rows, err)
	}
	var p1, p2 *uuid.UUID
	if err := l.h.super.QueryRow(ctx, "SELECT profile_id, profile2_id FROM ctrlz.clients WHERE tenant_id = $1", A.Tenant).Scan(&p1, &p2); err != nil {
		t.Fatal(err)
	}
	if p1 == nil || *p1 != A.Profile2 || p2 != nil {
		t.Errorf("the client after Profile 1 was deleted: profile %v profile2 %v, want Profile 2 promoted", p1, p2)
	}
	// A client that used the deleted profile as Profile 2 only just loses it.
	// (The seed has none, so make one.)
	l.exec("INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'three')", A.Tenant, uuid.MustParse("00000000-0000-7000-8000-00000000a0b3"))
	l.exec("INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id, profile2_id) VALUES ($1, $2, 'second', $3, $4)", A.Tenant, A.Endpoint, A.Profile2, uuid.MustParse("00000000-0000-7000-8000-00000000a0b3"))
	if err := l.tenant.WithTenant(ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if err := tx.ProfileClientsLock(uuid.MustParse("00000000-0000-7000-8000-00000000a0b3")); err != nil {
			return err
		}
		_, err := tx.DB().Exec(tx.Context(), "DELETE FROM ctrlz.profiles WHERE id = $1", uuid.MustParse("00000000-0000-7000-8000-00000000a0b3"))
		return err
	}); err != nil {
		t.Fatalf("deleting a profile used as Profile 2: %v", err)
	}
	if err := l.h.super.QueryRow(ctx, "SELECT profile_id, profile2_id FROM ctrlz.clients WHERE tenant_id = $1 AND label = 'second'", A.Tenant).Scan(&p1, &p2); err != nil || p1 == nil || *p1 != A.Profile2 || p2 != nil {
		t.Errorf("the client after its Profile 2 was deleted: %v %v err %v", p1, p2, err)
	}
	// Tenant B's client is untouched by A's deletes.
	if err := l.h.super.QueryRow(ctx, "SELECT profile_id, profile2_id FROM ctrlz.clients WHERE tenant_id = $1", B.Tenant).Scan(&p1, &p2); err != nil || p1 == nil || *p1 != B.Profile || p2 == nil || *p2 != B.Profile2 {
		t.Errorf("tenant B's client changed: %v %v err %v", p1, p2, err)
	}

	// The worker's purge of tenant B cascades through its profiles and clients
	// while the clients still stack two profiles.
	l.purgeTenant(B)
	var left int
	if err := l.h.super.QueryRow(ctx, "SELECT (SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1) + (SELECT count(*) FROM ctrlz.clients WHERE tenant_id = $1)", B.Tenant).Scan(&left); err != nil || left != 0 {
		t.Errorf("after the purge: %d profile and client rows, err %v", left, err)
	}

	// The same client in both stored orders. In the seed order its Profile 1 is
	// the row stored first; reversed, Profile 2 is, and a statement that deletes
	// both rows meets the dead Profile 2 while it handles Profile 1. The guard
	// that promotes only a Profile 2 that still exists is what both orders need.
	// Rows are stored in id order here (ids are time ordered and inserted in turn),
	// so "stored first" and "lowest id" are the same row.
	for _, order := range []struct {
		name string
		swap bool
	}{{"Profile 1 stored first", false}, {"Profile 2 stored first", true}} {
		stack := func(l *claimLab, who catalogtest.SeedIDs) (first, second uuid.UUID) {
			first, second = who.Profile, who.Profile2 // Profile was stored first
			if order.swap {
				l.exec("UPDATE ctrlz.clients SET profile_id = $2, profile2_id = $3 WHERE tenant_id = $1", who.Tenant, who.Profile2, who.Profile)
			}
			return first, second
		}
		clientColumns := func(l *claimLab, who catalogtest.SeedIDs) (p1, p2 *uuid.UUID) {
			l.t.Helper()
			if err := l.h.super.QueryRow(l.h.ctx, "SELECT profile_id, profile2_id FROM ctrlz.clients WHERE tenant_id = $1", who.Tenant).Scan(&p1, &p2); err != nil {
				l.t.Fatal(err)
			}
			return p1, p2
		}

		t.Run("purge, "+order.name, func(t *testing.T) {
			l := newClaimLab(t)
			stack(l, l.A)
			// The worker's own store, the role that will run the purge.
			l.purgeTenant(l.A)
			var left int
			if err := l.h.super.QueryRow(l.h.ctx, "SELECT (SELECT count(*) FROM ctrlz.tenants WHERE id = $1) + (SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1) + (SELECT count(*) FROM ctrlz.clients WHERE tenant_id = $1)", l.A.Tenant).Scan(&left); err != nil || left != 0 {
				t.Errorf("after the purge: %d tenant, profile and client rows, err %v", left, err)
			}
		})

		t.Run("one statement deletes both profiles, "+order.name, func(t *testing.T) {
			l := newClaimLab(t)
			A := l.A
			first, second := stack(l, A)
			// Nothing else may hold the two profiles (RESTRICT): the schedule window
			// goes, and the Endpoint moves to a third profile.
			third := uuid.MustParse("00000000-0000-7000-8000-00000000a0c3")
			l.exec("INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'three')", A.Tenant, third)
			l.exec("DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1", A.Tenant)
			l.exec("UPDATE ctrlz.endpoints SET profile_id = $2, profile2_id = NULL WHERE tenant_id = $1", A.Tenant, third)
			var rows int64
			if err := l.tenant.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
				for _, id := range []uuid.UUID{first, second} {
					if err := tx.ProfileClientsLock(id); err != nil {
						return err
					}
				}
				tag, err := tx.DB().Exec(tx.Context(), "DELETE FROM ctrlz.profiles WHERE id = ANY($1)", []uuid.UUID{first, second})
				rows = tag.RowsAffected()
				return err
			}); err != nil || rows != 2 {
				t.Fatalf("deleting both profiles of the stack in one statement: %d rows, %v", rows, err)
			}
			if p1, p2 := clientColumns(l, A); p1 != nil || p2 != nil {
				t.Errorf("the client after both of its profiles went: profile %v profile2 %v, want both NULL", p1, p2)
			}
		})
	}
}
