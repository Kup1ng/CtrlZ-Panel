package catalogtest_test

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The tests in this file belong to the second round of the P0 gate review. As
// in gate_test.go, each one fails against the database as it was, or, for a
// finding that was only a gap in the tests, against the mutant it names.

// rowLocked reports whether another transaction holds a lock on the claim row.
func (l *claimLab) rowLocked(id uuid.UUID) bool {
	l.t.Helper()
	conn, err := l.h.db.Super(l.h.ctx)
	if err != nil {
		l.t.Fatal(err)
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(l.h.ctx)
	if err != nil {
		l.t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	_, err = tx.Exec(l.h.ctx, "SELECT 1 FROM ctrlz.ip_claims WHERE id = $1 FOR UPDATE NOWAIT", id)
	return pgErr(err) != nil && pgErr(err).Code == "55P03"
}

// insertClaim stores a claim row with an id of the test's choosing. Rows are
// stored in the order of the calls, so a test can make the heap order differ
// from the id order, which is the only way a missing ORDER BY shows.
func (l *claimLab) insertClaim(who catalogtest.SeedIDs, id uuid.UUID, cidr, state string) {
	l.t.Helper()
	l.exec("INSERT INTO ctrlz.ip_claims (tenant_id, id, endpoint_id, cidr, state, source) VALUES ($1, $2, $3, $4, $5, 'manual')", who.Tenant, id, who.Endpoint, cidr, state)
}

// newEndpoint adds a second Endpoint to the tenant, for a claim of its own.
func (l *claimLab) newEndpoint(who catalogtest.SeedIDs, name string) uuid.UUID {
	l.t.Helper()
	id := uuid.Must(uuid.NewV7())
	resolver := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:])) // 26 characters of [a-z2-7]
	l.exec(`INSERT INTO ctrlz.endpoints (tenant_id, id, name, type, resolver_id, profile_id) VALUES ($1, $2, $3, 'doh_client', $4, $5)`,
		who.Tenant, id, name, resolver, who.Profile)
	return id
}

// requestOn is request for an Endpoint other than the seeded one.
func (l *claimLab) requestOn(who catalogtest.SeedIDs, endpoint uuid.UUID, prefix string) store.IPClaimResult {
	l.t.Helper()
	var res store.IPClaimResult
	if err := l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		res, err = tx.IPClaimRequest(endpoint, netip.MustParsePrefix(prefix), "manual")
		return err
	}); err != nil {
		l.t.Fatalf("request %s: %v", prefix, err)
	}
	return res
}

// inFlight runs one statement in a transaction of a real login of the given
// store and keeps the transaction open. The returned function commits it. This
// is the second connection that the lock tests need: the row stays locked and
// its new version stays invisible to everyone else until release is called.
func (l *claimLab) inFlight(s *store.Store, tenant uuid.UUID, sql string, args ...any) (release func() error) {
	l.t.Helper()
	started := make(chan struct{})
	hold := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WithTenant(l.h.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, err := tx.DB().Exec(tx.Context(), sql, args...); err != nil {
				return err
			}
			close(started)
			<-hold
			return nil
		})
	}()
	select {
	case <-started:
	case err := <-done:
		l.t.Fatalf("the in-flight statement ended at once: %v", err)
	case <-time.After(20 * time.Second):
		l.t.Fatal("the in-flight statement never started")
	}
	var once sync.Once
	var result error
	release = func() error {
		once.Do(func() {
			close(hold)
			result = <-done
		})
		return result
	}
	l.t.Cleanup(func() { _ = release() })
	return release
}

type deleteResult struct {
	rows int64
	err  error
}

// deleteEndpointInBackground deletes an Endpoint as the tenant's real login, in
// a transaction of its own, and says which backend it runs on so the caller can
// wait for it to block.
func (l *claimLab) deleteEndpointInBackground(who catalogtest.SeedIDs, ep uuid.UUID) (pid int, result chan deleteResult) {
	l.t.Helper()
	pidCh := make(chan int, 1)
	result = make(chan deleteResult, 1)
	go func() {
		var r deleteResult
		r.err = l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			var p int
			if err := tx.DB().QueryRow(tx.Context(), "SELECT pg_backend_pid()").Scan(&p); err != nil {
				return err
			}
			pidCh <- p
			// The delete cascades into the clients of the Endpoint, which the lock order ranks before the Endpoint: the
			// caller locks them first, in id order, as the delete of a profile does (P2 spec 3.1, 3.3).
			if _, err := tx.DB().Exec(tx.Context(), "SELECT id FROM ctrlz.clients WHERE tenant_id = $1 AND endpoint_id = $2 ORDER BY id FOR UPDATE", tx.TenantID(), ep); err != nil {
				return err
			}
			tag, err := tx.DB().Exec(tx.Context(), "DELETE FROM ctrlz.endpoints WHERE id = $1", ep)
			r.rows = tag.RowsAffected()
			return err
		})
		result <- r
	}()
	select {
	case pid = <-pidCh:
	case <-time.After(20 * time.Second):
		l.t.Fatal("the delete never started")
	}
	return pid, result
}

func (l *claimLab) endpointExists(ep uuid.UUID) bool {
	l.t.Helper()
	var n int
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.endpoints WHERE id = $1", ep).Scan(&n); err != nil {
		l.t.Fatal(err)
	}
	return n == 1
}

// TestEndpointDeleteWaitsForASuspensionInFlight (BR3, DR3): the restrictive
// policy reads the snapshot of the DELETE, so a suspension that has not
// committed does not stop it. The cascade then waits for the claim row, and the
// trigger on ip_claims sees the committed suspension and refuses. Two real
// logins, for both roles that may suspend.
func TestEndpointDeleteWaitsForASuspensionInFlight(t *testing.T) {
	for _, role := range []store.Role{store.RoleWorker, store.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			l := newClaimLab(t)
			A := l.A
			ep := l.newEndpoint(A, "pinned")
			l.closedMode()
			claim := l.requestOn(A, ep, "192.0.2.200/32")
			l.want("the claim", claim.Outcome, "active")

			suspender := l.h.db.Store(l.h.ctx, t, role)
			release := l.inFlight(suspender, A.Tenant, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1", claim.ClaimID)
			pid, result := l.deleteEndpointInBackground(A, ep)
			l.waitForLock(pid)
			if err := release(); err != nil {
				t.Fatalf("the suspension did not commit: %v", err)
			}
			var res deleteResult
			select {
			case res = <-result:
			case <-time.After(20 * time.Second):
				t.Fatal("the delete did not finish")
			}
			if !errors.Is(res.err, store.ErrConflict) {
				t.Fatalf("the delete that overlapped the suspension: rows %d, error %v, want a conflict", res.rows, res.err)
			}
			var se *store.Error
			if !errors.As(res.err, &se) || se.SQLState() != "CZ001" {
				t.Errorf("the error is %v, want SQLSTATE CZ001", res.err)
			}
			l.wantState("the suspended claim", claim.ClaimID, "suspended")
			if !l.endpointExists(ep) {
				t.Error("the Endpoint was deleted")
			}
			l.want("a new request for the prefix", l.requestOn(A, ep, "192.0.2.200/32").Outcome, "suspended")
		})
	}

	t.Run("a claim lock that is not a suspension", func(t *testing.T) {
		// The same wait, with the claim only touched: the delete goes through.
		l := newClaimLab(t)
		A := l.A
		ep := l.newEndpoint(A, "plain")
		l.closedMode()
		claim := l.requestOn(A, ep, "192.0.2.201/32")
		release := l.inFlight(l.worker, A.Tenant, "UPDATE ctrlz.ip_claims SET grace_until = grace_until WHERE id = $1", claim.ClaimID)
		pid, result := l.deleteEndpointInBackground(A, ep)
		l.waitForLock(pid)
		if err := release(); err != nil {
			t.Fatal(err)
		}
		res := <-result
		if res.err != nil || res.rows != 1 || l.endpointExists(ep) {
			t.Errorf("a delete that waited for a harmless update: rows %d, error %v, Endpoint still there %v", res.rows, res.err, l.endpointExists(ep))
		}
	})

	t.Run("the purge of a tenant with a suspended claim", func(t *testing.T) {
		l := newClaimLab(t)
		B := l.B
		ep := l.newEndpoint(B, "doomed")
		l.closedMode()
		claim := l.requestOn(B, ep, "192.0.2.202/32")
		l.exec("UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1", claim.ClaimID)
		l.purgeTenant(B)
		var left int
		if err := l.h.super.QueryRow(l.h.ctx, "SELECT (SELECT count(*) FROM ctrlz.tenants WHERE id = $1) + (SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1)", B.Tenant).Scan(&left); err != nil || left != 0 {
			t.Errorf("after the purge: %d tenant and claim rows, err %v", left, err)
		}
	})
}

// TestSuspendedClaimGuardsNeedTheRightClaims (DR6): the suspended guards of
// take and open_challenge look at the tenant's own overlapping claims, wider or
// narrower, and not at another tenant's.
func TestSuspendedClaimGuardsNeedTheRightClaims(t *testing.T) {
	l := newClaimLab(t)
	B := l.B
	l.openMode()

	// A narrow claim and a wide one around it, both with evidence on file.
	narrow := l.pendingClaim("203.0.113.5")
	wide := l.request(B, "203.0.113.0/28", "manual")
	l.want("the /28", wide.Outcome, "wide_requires_approval")
	l.approve(wide.ClaimID)
	l.observe(B, narrow, "203.0.113.5")
	l.observe(B, wide.ClaimID, "203.0.113.5")

	// The narrow claim is suspended: the wide one around it may neither be
	// proven nor collect a challenge.
	l.workerSets(B, narrow, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")
	l.want("a /28 around a suspended /32", l.take(B, wide.ClaimID), "suspended")
	l.wantState("the /28", wide.ClaimID, "pending_proof")
	if _, ok := l.tryOpen(B, wide.ClaimID); ok {
		t.Error("a challenge for a /28 around a suspended /32")
	}

	// The other way round: the wide claim is suspended, the narrow one inside it
	// is refused.
	l.exec("UPDATE ctrlz.ip_claims SET state = 'pending_proof' WHERE id = $1", narrow)
	l.workerSets(B, wide.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")
	l.want("a /32 inside a suspended /28", l.take(B, narrow), "suspended")
	l.wantState("the /32", narrow, "pending_proof")
	if _, ok := l.tryOpen(B, narrow); ok {
		t.Error("a challenge for a /32 inside a suspended /28")
	}

	// Another tenant's suspended claim on the same address stops nothing of B's.
	// A held it while it was active; B's own claim for it works, evidence and all.
	l.closedMode()
	a := l.request(l.A, "203.0.113.40/32", "manual")
	l.want("A's claim", a.Outcome, "active")
	l.workerSets(l.A, a.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")
	l.openMode()
	b := l.pendingClaim("203.0.113.40")
	l.observe(B, b, "203.0.113.40") // opens a challenge: o06 refuses it if A's row counts
	l.want("B's take beside A's suspended claim", l.take(B, b), "active")
	l.wantState("A's suspended claim", a.ClaimID, "suspended")
}

// TestRequestWaitsForAWiderOrNarrowerSuspensionInFlight (DR6, r04): the lock
// of ip_claim_request covers every overlapping claim of the tenant, not only
// the same prefix. Otherwise the request does not look at the suspension until
// the insert waits on the exclusion constraint, and then succeeds.
func TestRequestWaitsForAWiderOrNarrowerSuspensionInFlight(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	l.closedMode()
	for _, c := range []struct {
		what, held, asked string
	}{
		{"a /32 inside a /28 whose suspension is in flight", "198.51.100.64/28", "198.51.100.70/32"},
		{"a /28 around a /32 whose suspension is in flight", "198.51.100.100/32", "198.51.100.96/28"},
	} {
		claim := l.request(A, c.held, "manual")
		l.want("the claim held for "+c.what, claim.Outcome, "active")
		release := l.inFlight(l.worker, A.Tenant, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1", claim.ClaimID)
		pid, result := l.inBackground("tenant", A.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_request($1, $2, 'manual')", A.Endpoint, c.asked)
		l.waitForLock(pid)
		if err := release(); err != nil {
			t.Fatal(err)
		}
		l.want("the request for "+c.what, l.await(result), "suspended")
	}
}

// TestUnapprovedWideClaimIsNeverProvenAtTheBoundary (DR7, t12): the width rule
// stops at /32. A /31 is wider.
func TestUnapprovedWideClaimIsNeverProvenAtTheBoundary(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	l.closedMode()
	w := l.request(A, "192.0.2.130/31", "manual")
	l.want("a closed-mode /31", w.Outcome, "active")
	l.observe(A, w.ClaimID, "192.0.2.130")
	l.want("a proof from one address of the /31", l.take(A, w.ClaimID), "wide_requires_approval")
	if _, _, proven := l.state(w.ClaimID); proven {
		t.Error("an unapproved /31 was proven")
	}
	l.approve(w.ClaimID)
	l.want("the same proof once an admin approved it", l.take(A, w.ClaimID), "active")
}

// TestUnprovenVictimIsDisplacedWhateverTheHubSaw (DR7, t28, D35): a claim that
// was never proven yields to another tenant's proof even when its last_seen_at
// is fresh, because last_seen_at is traffic and traffic from an address proves
// nothing about who controls it. Only a proven claim that is seen is protected.
func TestUnprovenVictimIsDisplacedWhateverTheHubSaw(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()
	a := l.request(A, "192.0.2.210/32", "manual")
	l.want("A's closed-mode claim", a.Outcome, "active")
	l.exec("UPDATE ctrlz.ip_claims SET last_seen_at = now() WHERE id = $1", a.ClaimID)
	l.openMode()
	b := l.pendingClaim("192.0.2.210")
	l.observe(B, b, "192.0.2.210")
	l.want("B's take over an unproven claim that was just seen", l.take(B, b), "active")
	l.wantState("A's unproven claim", a.ClaimID, "released")
}

// TestTakeWaitsForAReleaseInFlight (DR8, t25): the lock on another tenant's
// rows is what makes a take wait for the victim's release that has not
// committed. Without it the take reads the old, proven row and answers
// unavailable although the address is about to be free.
func TestTakeWaitsForAReleaseInFlight(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()
	a := l.request(A, "203.0.113.60/32", "manual")
	l.observe(A, a.ClaimID, "203.0.113.60")
	l.want("A proves its claim", l.take(A, a.ClaimID), "active")
	l.openMode()
	b := l.pendingClaim("203.0.113.60")
	l.observe(B, b, "203.0.113.60")

	rel, _ := l.rawTx("tenant", A.Tenant)
	var out string
	if err := rel.QueryRow(l.h.ctx, "SELECT outcome FROM ctrlz_fn.ip_claim_release($1)", a.ClaimID).Scan(&out); err != nil || out != "released" {
		t.Fatalf("A's release: %q %v", out, err)
	}
	pid, result := l.inBackground("tenant", B.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_take($1, NULL, gen_random_uuid())", b)
	l.waitForLock(pid)
	if err := rel.Commit(l.h.ctx); err != nil {
		t.Fatal(err)
	}
	l.want("a take that waited for the victim's release", l.await(result), "active")
}

// wantLockedInIDOrder runs call twice, once with the lower and once with the
// higher of two claim rows held by another transaction, and checks which of
// the two the call has locked while it waits. Locking in ascending id order
// means: held lower, nothing else locked; held higher, the lower one locked.
func (l *claimLab) wantLockedInIDOrder(what string, lo, hi uuid.UUID, call func() (pid int, result chan string)) {
	l.t.Helper()
	for _, held := range []uuid.UUID{lo, hi} {
		holder, _ := l.rawTx("", uuid.Nil)
		if _, err := holder.Exec(l.h.ctx, "SELECT 1 FROM ctrlz.ip_claims WHERE id = $1 FOR UPDATE", held); err != nil {
			l.t.Fatal(err)
		}
		pid, result := call()
		l.waitForLock(pid)
		other, wantLocked := hi, false
		if held == hi {
			other, wantLocked = lo, true
		}
		if got := l.rowLocked(other); got != wantLocked {
			l.t.Errorf("%s, with the %s id held: the other claim is locked: %v, want %v (rows must be locked in ascending id order)", what, map[bool]string{false: "lower", true: "higher"}[held == hi], got, wantLocked)
		}
		if err := holder.Rollback(l.h.ctx); err != nil {
			l.t.Fatal(err)
		}
		l.await(result)
	}
}

// TestTakeLocksOtherTenantsRowsInIDOrder (DR8, t23 and t24): two takers that
// both reach the same rows of a third tenant must lock them in one order, or
// they deadlock. The later stored row has the lower id, so the plan's natural
// order (the heap) is not the id order and a missing or reversed ORDER BY shows.
func TestTakeLocksOtherTenantsRowsInIDOrder(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	hi := uuid.MustParse("00000000-0000-7000-8000-0000000000f2")
	lo := uuid.MustParse("00000000-0000-7000-8000-0000000000f1")
	l.insertClaim(A, hi, "198.51.100.130/32", "active") // stored first
	l.insertClaim(A, lo, "198.51.100.131/32", "active") // stored second, lower id

	l.openMode()
	wide := l.request(B, "198.51.100.128/28", "manual")
	l.want("B's /28", wide.Outcome, "wide_requires_approval")
	l.approve(wide.ClaimID)
	l.observe(B, wide.ClaimID, "198.51.100.130")
	l.wantLockedInIDOrder("a take over another tenant's rows", lo, hi, func() (int, chan string) {
		return l.inBackground("tenant", B.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_take($1, NULL, gen_random_uuid())", wide.ClaimID)
	})
}

// TestRequestLocksTheTenantsRowsInIDOrder (DR8, r02 and r03): the same for the
// lock that ip_claim_request takes on the tenant's own overlapping rows.
func TestRequestLocksTheTenantsRowsInIDOrder(t *testing.T) {
	l := newClaimLab(t)
	B := l.B
	hi := uuid.MustParse("00000000-0000-7000-8000-0000000000e2")
	lo := uuid.MustParse("00000000-0000-7000-8000-0000000000e1")
	l.insertClaim(B, hi, "198.51.100.145/32", "pending_proof")
	l.insertClaim(B, lo, "198.51.100.146/32", "pending_proof")
	l.openMode()
	l.wantLockedInIDOrder("a request over the tenant's rows", lo, hi, func() (int, chan string) {
		return l.inBackground("tenant", B.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_request($1, '198.51.100.144/28', 'manual')", B.Endpoint)
	})
}

// TestRequestDoesNotWaitForAnotherTenantsRow (DR8, r01): the lock of
// ip_claim_request is the tenant's own rows. A row of another tenant that is
// busy must not hold up the request, or one tenant could stall another's.
func TestRequestDoesNotWaitForAnotherTenantsRow(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.openMode()
	a := l.pendingClaimOf(A, "198.51.100.150")
	holder, _ := l.rawTx("", uuid.Nil)
	if _, err := holder.Exec(l.h.ctx, "SELECT 1 FROM ctrlz.ip_claims WHERE id = $1 FOR UPDATE", a); err != nil {
		t.Fatal(err)
	}
	_, result := l.inBackground("tenant", B.Tenant, "SELECT outcome FROM ctrlz_fn.ip_claim_request($1, '198.51.100.150/32', 'manual')", B.Endpoint)
	select {
	case out := <-result:
		l.want("B's request while A's row is locked", out, "pending_proof")
	case <-time.After(5 * time.Second):
		t.Fatal("B's request waited for a row of tenant A")
	}
}

// TestTwinTakesDoNotDeadlock (DR8, t07): two takes of overlapping claims of one
// tenant lock the same rows. They must lock them exclusively, in one order, so
// the second simply waits for the first. With a share lock both hold a share on
// both rows and then each needs the exclusive one: a deadlock (40P01).
func TestTwinTakesDoNotDeadlock(t *testing.T) {
	l := newClaimLab(t)
	B := l.B
	l.openMode()
	const rounds = 30
	// Two claims a round: well past the default quota.
	l.exec("UPDATE ctrlz.entitlement_defaults SET max_ip_claims = 1000")
	for round := 0; round < rounds; round++ {
		ip := fmt.Sprintf("198.51.100.%d", 160+round)
		c1 := l.pendingClaim(ip)
		c2 := l.pendingClaim(ip)
		l.observe(B, c1, ip)
		l.observe(B, c2, ip)
		outs := make(chan string, 4)
		start := make(chan struct{})
		for _, c := range []uuid.UUID{c1, c2} {
			go func() {
				<-start
				err := l.tenant.WithTenant(l.h.ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
					out, err := tx.IPClaimTake(c, "")
					outs <- out
					return err
				})
				if err != nil {
					outs <- "error: " + err.Error()
				}
			}()
		}
		close(start)
		got := map[string]int{}
		for i := 0; i < 2; i++ {
			select {
			case o := <-outs:
				got[o]++
			case <-time.After(30 * time.Second):
				t.Fatalf("round %d: a take did not finish", round)
			}
		}
		if got["active"] != 1 || got["unavailable"] != 1 {
			t.Fatalf("round %d: twin takes gave %v, want one active and one unavailable", round, got)
		}
	}
}

// TestIPClaimQuota (DR9): a tenant holds a bounded number of claims that are
// not released, by its override or else the default. ip_claims had no bound at
// all: any number of distinct prefixes, or twins of one, each with its own ten
// challenges.
func TestIPClaimQuota(t *testing.T) {
	count := func(l *claimLab, who catalogtest.SeedIDs) (n int) {
		l.t.Helper()
		if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1", who.Tenant).Scan(&n); err != nil {
			l.t.Fatal(err)
		}
		return n
	}

	t.Run("the default, the override and released rows", func(t *testing.T) {
		l := newClaimLab(t)
		A, B := l.A, l.B
		l.openMode()
		// Every tenant starts with its seeded claim, which counts.
		l.exec("UPDATE ctrlz.entitlement_defaults SET max_ip_claims = 3")
		first := l.request(A, "203.0.113.100/32", "manual")
		l.want("the second claim", first.Outcome, "pending_proof")
		l.want("the third claim", l.request(A, "203.0.113.101/32", "manual").Outcome, "pending_proof")
		before := count(l, A)
		over := l.request(A, "203.0.113.102/32", "manual")
		l.want("a fourth claim at a limit of three", over.Outcome, "quota_exceeded")
		if over.ClaimID != uuid.Nil || count(l, A) != before {
			t.Errorf("a refused request left a trace: claim %s, rows %d to %d", over.ClaimID, before, count(l, A))
		}
		// A wide request also makes a row, so it also counts.
		l.want("a /28 at the limit", l.request(A, "203.0.113.112/28", "manual").Outcome, "quota_exceeded")
		// The other tenant has its own count.
		l.want("tenant B's second claim", l.request(B, "203.0.113.103/32", "manual").Outcome, "pending_proof")

		// Releasing one frees a place. A suspended or pending claim does not.
		l.want("A releases a claim", l.release(A, first.ClaimID), "released")
		l.want("a claim after a release", l.request(A, "203.0.113.102/32", "manual").Outcome, "pending_proof")
		l.want("the limit again", l.request(A, "203.0.113.104/32", "manual").Outcome, "quota_exceeded")
		l.exec("UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE tenant_id = $1 AND cidr = '203.0.113.102/32'", A.Tenant)
		l.want("a claim while one is suspended", l.request(A, "203.0.113.104/32", "manual").Outcome, "quota_exceeded")

		// The override replaces the default, up and down.
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 5 WHERE tenant_id = $1", A.Tenant)
		l.want("A, override of five", l.request(A, "203.0.113.104/32", "manual").Outcome, "pending_proof")
		l.want("A, override of five, the last place", l.request(A, "203.0.113.105/32", "manual").Outcome, "pending_proof")
		l.want("A, override of five, full", l.request(A, "203.0.113.106/32", "manual").Outcome, "quota_exceeded")
		l.want("tenant B keeps the default", l.request(B, "203.0.113.107/32", "manual").Outcome, "pending_proof")
		l.want("tenant B at the default", l.request(B, "203.0.113.108/32", "manual").Outcome, "quota_exceeded")
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 0 WHERE tenant_id = $1", B.Tenant)
		l.want("tenant B with an override of zero", l.request(B, "203.0.113.108/32", "manual").Outcome, "quota_exceeded")
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = NULL WHERE tenant_id = $1", A.Tenant)
		l.want("A with the override removed", l.request(A, "203.0.113.109/32", "manual").Outcome, "quota_exceeded")
	})

	t.Run("the default is fifty", func(t *testing.T) {
		l := newClaimLab(t)
		var n int
		if err := l.h.super.QueryRow(l.h.ctx, "SELECT max_ip_claims FROM ctrlz.entitlement_defaults").Scan(&n); err != nil || n != 50 {
			t.Errorf("the default max_ip_claims: %d, err %v, want 50 like max_authorized_ips", n, err)
		}
		var override *int
		if err := l.h.super.QueryRow(l.h.ctx, "SELECT max_ip_claims FROM ctrlz.tenant_entitlements WHERE tenant_id = $1", l.A.Tenant).Scan(&override); err != nil || override != nil {
			t.Errorf("a new tenant's override: %v, err %v, want none", override, err)
		}
	})

	t.Run("parallel requests of one tenant cannot pass the limit", func(t *testing.T) {
		l := newClaimLab(t)
		A := l.A
		l.openMode()
		l.exec("UPDATE ctrlz.entitlement_defaults SET max_ip_claims = 4")
		cfg := l.h.db.StoreConfig(store.RoleTenant)
		cfg.MaxConns = 16
		s, err := store.Open(l.h.ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)

		const callers, rounds = 12, 6
		for round := 0; round < rounds; round++ {
			l.exec("DELETE FROM ctrlz.ip_claims WHERE tenant_id = $1 AND id <> $2", A.Tenant, A.Claim)
			var wg sync.WaitGroup
			start := make(chan struct{})
			outcomes := make(chan string, callers)
			for c := 0; c < callers; c++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					var out string
					err := s.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
						r, err := tx.IPClaimRequest(A.Endpoint, netip.MustParsePrefix(fmt.Sprintf("203.0.%d.%d/32", 113+round, 10+c)), "manual")
						out = r.Outcome
						return err
					})
					if err != nil {
						out = "error: " + err.Error()
					}
					outcomes <- out
				}()
			}
			close(start)
			wg.Wait()
			close(outcomes)
			got := map[string]int{}
			for o := range outcomes {
				got[o]++
			}
			if got["pending_proof"] != 3 || got["quota_exceeded"] != callers-3 {
				t.Fatalf("round %d: %v, want 3 claims made and %d refused", round, got, callers-3)
			}
			if n := count(l, A); n != 4 {
				t.Fatalf("round %d: %d claim rows, want exactly the limit of 4", round, n)
			}
		}
	})
}

// TestBlockPageTableAndValidator (AR3): wire.ValidateBlockPage is the authority
// and the API runs it before every write; the table is the backstop. What the
// validator accepts the table accepts, so a valid save does not fail in the
// database, and the bad shapes of the review are refused by both.
func TestBlockPageTableAndValidator(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A
	const checkViolation = "23514"

	linkInTable := func(url string) string {
		return h.try("", nil, "UPDATE ctrlz.block_pages SET unblock_mode = 'custom', unblock_url = $1 WHERE tenant_id = $2", url, a.Tenant)
	}
	linkInValidator := func(url string) bool {
		return wire.ValidateBlockPage(&policyv1.BlockPage{Title: "t", Message: "m", UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_URL, UnblockUrl: url}) == nil
	}
	for _, url := range []string{
		"https://example.com", "https://example.com/", "https://example.com/unblock?id=1", "https://example.com:8443/x",
		"https://example.com:/x", "https://example.com:99999/x", "https://xn--mgbh0fb.example/x", "https://[2001:db8::1]/x",
		"https://[2001:db8::1]:8443/x", "https://[::1]", "https://[::ffff:192.0.2.1]/x", "https://example.com?ref=1", "https://example.com/a%20b",
		"https://example.com/?q=%zz", "https://example.com/a#b", "https://EXAMPLE.com/Path", "https://a-b.example.com./", "https://127.0.0.1/x",
		"https://example.com/a?b?c", "https://example.com/" + strings.Repeat("a", 2000),
		// Upper-case hex digits in an IPv6 literal and in an escape.
		"https://[2001:DB8::0]/x", "https://example.com/a%2Fb", "https://example.com/a%2fb",
	} {
		if !linkInValidator(url) {
			t.Errorf("%q: the validator refuses a link that is meant to be valid", url)
		}
		if code := linkInTable(url); code != "" {
			t.Errorf("%q: the table refuses it with %q although the validator accepts it", url, code)
		}
	}
	for _, url := range []string{
		// The rows of the review.
		"https://host:port/x", "https://a^b/x", "https://host#frag", "https://ex|ample.com/", "https://a%zz.com/", "https://[x/",
		// Their neighbours.
		"https://example.com/a%zz", "https://example.com/a%2", "https://example.com/%", "https://example.com:80a/x", "https://:80/x",
		"https://user@example.com/", "https://example.com\\x/", "https://exa mple.com/", "https://example.com/\x01", "https://example.com/é",
		"HTTPS://example.com/", "http://example.com/", "//example.com/", "https://", "https:///x", "https://[::1", "https://::1]/", "https://[x]/",
		// Hosts the URL parser takes and the table does not, so the validator
		// holds the table's grammar.
		"https://a_b.example.com/", "https://a!b.example.com/", "https://a~b.example.com/", "https://a%C3%A9.example.com/",
		"https://[2001:db8::1%25eth0]/", "https://-a.example.com/",
	} {
		if linkInValidator(url) {
			t.Errorf("%q: the validator accepts a link that is meant to be bad", url)
		}
		if code := linkInTable(url); code != checkViolation {
			t.Errorf("%q: the table gives %q, want %q", url, code, checkViolation)
		}
	}

	// The table's bracket form is looser than the validator: any run of hex
	// digits, colons and dots passes the table, and only a real IPv6 literal
	// passes the validator. A write that skips the API can store these; the
	// compiler runs the validator on each row. The migration says so.
	for _, url := range []string{"https://[1:2]/", "https://[....]/", "https://[:80]", "https://[1]/", "https://[a:b]/"} {
		if linkInValidator(url) {
			t.Errorf("%q: the validator accepts it", url)
		}
		if code := linkInTable(url); code != "" {
			t.Errorf("%q: the table gives %q; the bracket form is documented as looser than the validator", url, code)
		}
	}

	// Every printable byte in a path, in a query and in an IPv6 literal: a byte
	// the validator takes there is a byte the table takes. A narrowed bound of
	// the regular expression shows here at the byte it cuts off.
	accepted := 0
	for b := 0x21; b <= 0x7e; b++ {
		for _, url := range []string{
			"https://example.com/a" + string(rune(b)) + "b",
			"https://example.com/?a" + string(rune(b)) + "b",
			"https://[2001:db8::" + string(rune(b)) + "]/",
		} {
			if !linkInValidator(url) {
				continue
			}
			accepted++
			if code := linkInTable(url); code != "" {
				t.Errorf("%q: the table gives %q although the validator accepts it", url, code)
			}
		}
	}
	if accepted < 150 {
		t.Errorf("the byte sweep reached %d links the validator takes, want at least 150", accepted)
	}

	// Title and message: no C0 control and no DEL; a message may have a line
	// break and a tab.
	textInTable := func(col, val string) string {
		return h.try("", nil, "UPDATE ctrlz.block_pages SET "+col+" = $1 WHERE tenant_id = $2", val, a.Tenant)
	}
	h.exec("UPDATE ctrlz.block_pages SET unblock_mode = 'none', unblock_url = NULL WHERE tenant_id = $1", a.Tenant)
	titleOK := func(s string) bool {
		return wire.ValidateBlockPage(&policyv1.BlockPage{Title: s, Message: "m", UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_NONE}) == nil
	}
	messageOK := func(s string) bool {
		return wire.ValidateBlockPage(&policyv1.BlockPage{Title: "t", Message: s, UnblockMode: policyv1.UnblockMode_UNBLOCK_MODE_NONE}) == nil
	}
	for _, s := range []string{"Blocked", "", "سلام", "a b", "é", "\u0085", strings.Repeat("a", 120)} {
		if !titleOK(s) {
			t.Errorf("title %q: the validator refuses it", s)
		}
		if code := textInTable("title", s); code != "" {
			t.Errorf("title %q: the table gives %q", s, code)
		}
	}
	for _, s := range []string{"a\nb", "a\x01b", "a\x7fb", "a\tb", "a\rb", "\x1f", "a\x1bb", "a\x0bb", strings.Repeat("a", 121)} {
		if titleOK(s) {
			t.Errorf("title %q: the validator accepts it", s)
		}
		if code := textInTable("title", s); code != checkViolation {
			t.Errorf("title %q: the table gives %q, want %q", s, code, checkViolation)
		}
	}
	for _, s := range []string{"Blocked", "", "line\nbreak", "tab\there", "two\n\nlines\tand tab", "سلام\nدنیا"} {
		if !messageOK(s) {
			t.Errorf("message %q: the validator refuses it", s)
		}
		if code := textInTable("message", s); code != "" {
			t.Errorf("message %q: the table gives %q", s, code)
		}
	}
	for _, s := range []string{"a\rb", "a\x01b", "a\x7fb", "a\x0bb", "a\x0cb", "\x08", "\x1f", "a\x1bb"} {
		if messageOK(s) {
			t.Errorf("message %q: the validator accepts it", s)
		}
		if code := textInTable("message", s); code != checkViolation {
			t.Errorf("message %q: the table gives %q, want %q", s, code, checkViolation)
		}
	}
}
