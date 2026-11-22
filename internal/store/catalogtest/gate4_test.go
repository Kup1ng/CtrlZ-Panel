package catalogtest_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// The tests in this file belong to the fourth round of the P0 gate review. As in
// the files before it, each one fails against the database as it was, or, for
// a finding that was only a gap in the tests, against the mutant it names.

// TestProfile1DeleteDoesNotDeadlockWithAnIDOrderWriter: a statement that locks
// several clients of one tenant locks them in id order, and promote_profile2
// follows the same rule. The rows are stored in the opposite order, so a lock
// taken in table order is the other order. The writer holds the lower id,
// the delete starts and waits for it, then the writer takes the higher id and
// commits. If the delete had taken the higher id first, each would hold the row
// the other wants and one of them would die with 40P01.
func TestProfile1DeleteDoesNotDeadlockWithAnIDOrderWriter(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	hi := uuid.MustParse("00000000-0000-7000-8000-00000000c1f2")
	lo := uuid.MustParse("00000000-0000-7000-8000-00000000c1f1")

	// Nothing else may hold Profile 1 (RESTRICT).
	l.exec("DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1", A.Tenant)
	l.exec("UPDATE ctrlz.endpoints SET profile_id = $2, profile2_id = NULL WHERE tenant_id = $1", A.Tenant, A.Profile2)
	l.exec("DELETE FROM ctrlz.clients WHERE tenant_id = $1", A.Tenant)
	// The higher id is stored first: the heap order is not the id order.
	for _, c := range []struct {
		id    uuid.UUID
		label string
	}{{hi, "hi"}, {lo, "lo"}} {
		l.exec("INSERT INTO ctrlz.clients (tenant_id, id, endpoint_id, label, profile_id, profile2_id) VALUES ($1, $2, $3, $4, $5, $6)",
			A.Tenant, c.id, A.Endpoint, c.label, A.Profile, A.Profile2)
	}

	const touch = "UPDATE ctrlz.clients SET last_seen_at = now() WHERE tenant_id = $1 AND id = $2"
	w, _ := l.rawTx("hub", A.Tenant)
	if _, err := w.Exec(l.h.ctx, touch, A.Tenant, lo); err != nil {
		t.Fatalf("the writer's first row: %v", err)
	}
	pid, result := l.inBackground("tenant", A.Tenant,
		"WITH d AS (DELETE FROM ctrlz.profiles WHERE id = $1 RETURNING 1) SELECT count(*)::text FROM d", A.Profile)
	l.waitForLock(pid)
	if _, err := w.Exec(l.h.ctx, touch, A.Tenant, hi); err != nil {
		t.Fatalf("the writer's second row, while the delete of Profile 1 waits: %v", err)
	}
	if err := w.Commit(l.h.ctx); err != nil {
		t.Fatal(err)
	}
	l.want("the delete of Profile 1 beside a writer in id order", l.await(result), "1")

	var n int
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.clients WHERE tenant_id = $1 AND profile_id = $2 AND profile2_id IS NULL", A.Tenant, A.Profile2).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("%d clients were promoted to Profile 2, want both", n)
	}
}

// heldClaims counts the claims of a tenant that are not released.
func (l *claimLab) heldClaims(tenant uuid.UUID) (n int) {
	l.t.Helper()
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state <> 'released'", tenant).Scan(&n); err != nil {
		l.t.Fatal(err)
	}
	return n
}

// TestLoweredLimitDoesNotStopProofOfHeldClaims: the cap on a tenant's live
// challenges is ten times the larger of its limit and the claims it holds. A
// limit lowered below what is held stops new claims (request), and must not
// stop the proof of the claims already held: a claim in grace that cannot open
// a challenge is suspended at the end of its grace, and only an admin ends that.
func TestLoweredLimitDoesNotStopProofOfHeldClaims(t *testing.T) {
	t.Run("a limit of zero, a claim in grace", func(t *testing.T) {
		l := newClaimLab(t)
		A := l.A
		l.closedMode()
		g := l.request(A, "192.0.2.171/32", "manual")
		l.want("A's closed-mode claim", g.Outcome, "active")
		l.workerSets(A, g.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + interval '14 days' WHERE id = $1")
		// The seed's claim is active and would count as held on its own. With it
		// gone the claim in grace is the only one held, so a count that leaves
		// out grace reads zero here and the cap falls to nothing.
		l.want("the seed claim released", l.release(A, A.Claim), "released")
		if n := l.heldClaims(A.Tenant); n != 1 {
			t.Fatalf("%d claims held, want only the one in grace", n)
		}
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 0 WHERE tenant_id = $1", A.Tenant)

		l.observe(A, g.ClaimID, "192.0.2.171") // fails the test if the open gives no row
		l.want("the owner proves the claim at a limit of zero", l.take(A, g.ClaimID), "active")
		// The limit still does what it is for.
		l.want("a new claim at a limit of zero", l.request(A, "192.0.2.172/32", "manual").Outcome, "quota_exceeded")
	})

	t.Run("a limit of zero, a lone pending claim in open mode", func(t *testing.T) {
		l := newClaimLab(t)
		A := l.A
		l.openMode()
		p := l.pendingClaimOf(A, "192.0.2.177")
		// Same reason as above: only the pending claim may be held, because a
		// count of active claims alone would still see the seed's.
		l.want("the seed claim released", l.release(A, A.Claim), "released")
		if n := l.heldClaims(A.Tenant); n != 1 {
			t.Fatalf("%d claims held, want only the pending one", n)
		}
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 0 WHERE tenant_id = $1", A.Tenant)

		if _, ok := l.tryOpen(A, p); !ok {
			t.Error("a pending claim, the only one held, could not open a challenge at a limit of zero")
		}
		l.want("a new claim at a limit of zero", l.request(A, "192.0.2.178/32", "manual").Outcome, "quota_exceeded")
	})

	t.Run("a limit of one, three claims held", func(t *testing.T) {
		l := newClaimLab(t)
		A := l.A
		l.closedMode()
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 10 WHERE tenant_id = $1", A.Tenant)
		x := l.request(A, "192.0.2.173/32", "manual")
		y := l.request(A, "192.0.2.174/32", "manual")
		l.want("the second claim", y.Outcome, "active")
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 1 WHERE tenant_id = $1", A.Tenant)
		if n := l.heldClaims(A.Tenant); n != 3 {
			t.Fatalf("%d claims held, want 3 (the seed's and two more)", n)
		}

		// Ten live challenges on one claim must not take the places of the
		// others: at a cap of ten times the limit the second claim would be
		// refused for as long as they live.
		for i := 0; i < 10; i++ {
			if _, ok := l.tryOpen(A, x.ClaimID); !ok {
				t.Fatalf("open %d on the first claim gave no row", i+1)
			}
		}
		if _, ok := l.tryOpen(A, y.ClaimID); !ok {
			t.Error("the second claim could not open a challenge while the first held ten")
		}
		if _, ok := l.tryOpen(A, A.Claim); !ok {
			t.Error("the seed claim could not open a challenge while the first held ten")
		}
		l.want("a new claim over the lowered limit", l.request(A, "192.0.2.175/32", "manual").Outcome, "quota_exceeded")
	})
}

// TestOpenChallengeCapEdges (the fourth round): three behaviours of
// ip_claim_open_challenge that the tests did not pin. Each fails against the
// mutant named beside it.
func TestOpenChallengeCapEdges(t *testing.T) {
	const open = "SELECT count(*)::text FROM ctrlz_fn.ip_claim_open_challenge($1)"

	t.Run("consumed challenges still count at the cap", func(t *testing.T) {
		// Mutant: AND ch.consumed_at IS NULL in the tenant's count.
		l := newClaimLab(t)
		A := l.A
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 1 WHERE tenant_id = $1", A.Tenant)
		// A released claim carries them, so the cap of ten per claim is not what
		// refuses the open below.
		dead := uuid.MustParse("00000000-0000-7000-8000-00000000c2f1")
		l.insertClaim(A, dead, "192.0.2.176/32", "released")
		for i := 0; i < 10; i++ {
			l.exec("INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, expires_at, consumed_at) VALUES ($1, $2, $3, now() + interval '5 minutes', now())",
				A.Tenant, dead, fmt.Sprintf("consumed%d", i))
		}
		if _, ok := l.tryOpen(A, A.Claim); ok {
			t.Error("a challenge was opened with ten consumed ones still live at a limit of one")
		}
		l.exec("UPDATE ctrlz.ip_proof_challenges SET expires_at = now() - interval '1 second' WHERE claim_id = $1", dead)
		if _, ok := l.tryOpen(A, A.Claim); !ok {
			t.Error("no challenge was opened after the consumed ones expired: the refusal above was not the cap")
		}
	})

	t.Run("the largest limit opens normally", func(t *testing.T) {
		// Mutant: the limit times ten without the cast to bigint raises 22003.
		l := newClaimLab(t)
		A := l.A
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 2147483647 WHERE tenant_id = $1", A.Tenant)
		if _, ok := l.tryOpen(A, A.Claim); !ok {
			t.Error("no challenge at a limit of 2147483647")
		}
	})

	// Mutant: FOR UPDATE removed from the read of the claim. The advisory lock
	// alone keeps the counts exact, so only the wait for the row tells the two
	// apart.
	for _, tc := range []struct {
		name, role, sql string
		want            string
	}{
		{"a suspension in flight", "worker", "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1", ""},
		{"a release in flight", "tenant", "SELECT outcome FROM ctrlz_fn.ip_claim_release($1)", "released"},
	} {
		t.Run("an open waits behind "+tc.name, func(t *testing.T) {
			l := newClaimLab(t)
			A := l.A
			x, _ := l.rawTx(tc.role, A.Tenant)
			if tc.want == "" {
				if _, err := x.Exec(l.h.ctx, tc.sql, A.Claim); err != nil {
					t.Fatal(err)
				}
			} else {
				var out string
				if err := x.QueryRow(l.h.ctx, tc.sql, A.Claim).Scan(&out); err != nil || out != tc.want {
					t.Fatalf("%s: %q, %v", tc.name, out, err)
				}
			}
			before := l.liveChallenges(A.Tenant)
			pid, result := l.inBackground("tenant", A.Tenant, open, A.Claim)
			// An open that does not wait is the failure here: it never shows up
			// as waiting for a lock.
			l.waitForLock(pid)
			if err := x.Commit(l.h.ctx); err != nil {
				t.Fatal(err)
			}
			l.want("the open after the change committed", l.await(result), "0")
			if after := l.liveChallenges(A.Tenant); after != before {
				t.Errorf("the open wrote a challenge on a claim that was gone: %d live, was %d", after, before)
			}
		})
	}
}
