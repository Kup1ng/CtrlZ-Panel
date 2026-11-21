package catalogtest_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The tests in this file belong to the third round of the P0 gate review. As in
// the two files before it, each one fails against the database as it was, or,
// for a finding that was only a gap in the tests, against the mutant it names.

// TestProfile1DeleteRacesAClientUpdate (DT1): deleting a Profile 1 promotes the
// Profile 2 of the clients that used it, and the promotion has to see a client
// row that another transaction has just changed. T3 changes the client's
// Profile 2 to C and has not committed; T1 deletes Profile 1 and waits on the
// client row. When T3 commits, the update of T1 must run against what T3
// committed, or it skips the client (its Profile 2 no longer matches the row it
// read) and the foreign key's SET NULL leaves (NULL, C), which the table
// refuses.
func TestProfile1DeleteRacesAClientUpdate(t *testing.T) {
	c := uuid.MustParse("00000000-0000-7000-8000-00000000a0d3")
	cases := []struct {
		name string
		// role and sql are the other transaction's change of the client; made says
		// that it creates profile C in the same transaction.
		role, sql string
		made      bool
		// single starts the client with Profile 1 only, which is the commonest
		// client: the lock has to cover it, because the other transaction is
		// about to give it a Profile 2.
		single bool
		// wantP1 says which profile the client holds afterwards; Profile 2 is
		// NULL in every case.
		wantP1 func(l *claimLab) uuid.UUID
	}{
		{"a move to an old profile", "tenant", "UPDATE ctrlz.clients SET profile2_id = $2 WHERE tenant_id = $1", false, false, func(*claimLab) uuid.UUID { return c }},
		{"a move to a profile made in the same transaction", "tenant", "UPDATE ctrlz.clients SET profile2_id = $2 WHERE tenant_id = $1", true, false, func(*claimLab) uuid.UUID { return c }},
		{"an update that leaves Profile 2 alone", "hub", "UPDATE ctrlz.clients SET last_seen_at = now() WHERE tenant_id = $1 AND $2::uuid IS NOT NULL", false, false, func(l *claimLab) uuid.UUID { return l.A.Profile2 }},
		{"a client with no Profile 2 that is given one", "tenant", "UPDATE ctrlz.clients SET profile2_id = $2 WHERE tenant_id = $1", false, true, func(*claimLab) uuid.UUID { return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newClaimLab(t)
			A := l.A
			// Nothing else may hold Profile 1 (RESTRICT).
			l.exec("DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1", A.Tenant)
			l.exec("UPDATE ctrlz.endpoints SET profile_id = $2, profile2_id = NULL WHERE tenant_id = $1", A.Tenant, A.Profile2)
			if tc.single {
				l.exec("UPDATE ctrlz.clients SET profile2_id = NULL WHERE tenant_id = $1", A.Tenant)
			}
			if !tc.made {
				l.exec("INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'three')", A.Tenant, c)
			}

			t3, _ := l.rawTx(tc.role, A.Tenant)
			if tc.made {
				if _, err := t3.Exec(l.h.ctx, "INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'three')", A.Tenant, c); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := t3.Exec(l.h.ctx, tc.sql, A.Tenant, c); err != nil {
				t.Fatalf("the other transaction's change: %v", err)
			}
			pid, result := l.inBackground("tenant", A.Tenant,
				"WITH d AS (DELETE FROM ctrlz.profiles WHERE id = $1 RETURNING 1) SELECT count(*)::text FROM d", A.Profile)
			l.waitForLock(pid)
			if err := t3.Commit(l.h.ctx); err != nil {
				t.Fatal(err)
			}
			l.want("the delete of Profile 1 after the other transaction committed", l.await(result), "1")

			var p1, p2 *uuid.UUID
			if err := l.h.super.QueryRow(l.h.ctx, "SELECT profile_id, profile2_id FROM ctrlz.clients WHERE tenant_id = $1", A.Tenant).Scan(&p1, &p2); err != nil {
				t.Fatal(err)
			}
			if p1 == nil || *p1 != tc.wantP1(l) || p2 != nil {
				t.Errorf("the client afterwards: profile %v profile2 %v, want %s and none", p1, p2, tc.wantP1(l))
			}
		})
	}
}

// liveChallenges counts a tenant's proof challenges whose expiry is still ahead.
func (l *claimLab) liveChallenges(who uuid.UUID) (n int) {
	l.t.Helper()
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_proof_challenges WHERE tenant_id = $1 AND expires_at > now()", who).Scan(&n); err != nil {
		l.t.Fatal(err)
	}
	return n
}

// TestReleaseLoopCannotCollectChallenges (DT2): the quota counts the claims a
// tenant holds, and a released claim is not held. A tenant that requests one
// prefix, opens ten challenges on it and releases it, in a loop, never holds
// more than its quota and still collected ten live challenges a round, without
// a bound. The tenant's live challenges are now capped at ten times its limit,
// released claims included.
func TestReleaseLoopCannotCollectChallenges(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.openMode()
	const limit = 2
	l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = $2 WHERE tenant_id = $1", A.Tenant, limit)
	seeded := l.liveChallenges(A.Tenant) // the seed gives every tenant one

	opened := 0
	const cycles = 40
	for cycle := 0; cycle < cycles; cycle++ {
		r := l.request(A, "203.0.113.50/32", "manual")
		l.want(fmt.Sprintf("request %d", cycle), r.Outcome, "pending_proof")
		for i := 0; i < 10; i++ {
			if _, ok := l.tryOpen(A, r.ClaimID); ok {
				opened++
			}
		}
		l.want(fmt.Sprintf("release %d", cycle), l.release(A, r.ClaimID), "released")
		if n := l.liveChallenges(A.Tenant); n > limit*10 {
			t.Fatalf("cycle %d: %d live challenges at a quota of %d, want at most %d", cycle, n, limit, limit*10)
		}
	}
	if want := limit*10 - seeded; opened != want {
		t.Errorf("%d challenges opened over %d cycles, want exactly the %d that fit under the cap", opened, cycles, want)
	}
	var rows int
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND cidr = '203.0.113.50/32'", A.Tenant).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	// The released rows are not pruned and not capped: the route rate limit of
	// P3 is the only bound on them. This is the state the specs describe.
	if rows != cycles {
		t.Errorf("%d released rows of the prefix after %d cycles, want one a cycle", rows, cycles)
	}

	// The cap is the tenant's own.
	if _, ok := l.tryOpen(B, B.Claim); !ok {
		t.Error("tenant B could not open a challenge while tenant A was at its cap")
	}
	// A challenge that has expired frees its place.
	l.exec("UPDATE ctrlz.ip_proof_challenges SET expires_at = now() - interval '1 second' WHERE tenant_id = $1 AND expires_at > now()", A.Tenant)
	r := l.request(A, "203.0.113.50/32", "manual")
	if _, ok := l.tryOpen(A, r.ClaimID); !ok {
		t.Error("a challenge could not be opened after the live ones expired")
	}
}

// TestOpenChallengeAndRequestShareTheTenantLock (DT2): ip_claim_open_challenge
// takes the lock of ip_claim_request first, so the count of live challenges is
// exact and the lock order cannot deadlock with a request. Either function, in
// flight on one connection, holds the other of the same tenant back on a second
// connection, and another tenant's call is not held back.
func TestOpenChallengeAndRequestShareTheTenantLock(t *testing.T) {
	const request = "SELECT outcome FROM ctrlz_fn.ip_claim_request($1, $2::cidr, 'manual')"
	const open = "SELECT challenge_id::text FROM ctrlz_fn.ip_claim_open_challenge($1)"

	t.Run("a request in flight holds back an open", func(t *testing.T) {
		l := newClaimLab(t)
		A := l.A
		l.openMode()
		claim := l.pendingClaimOf(A, "203.0.113.60")
		x, _ := l.rawTx("tenant", A.Tenant)
		// A prefix that overlaps nothing, so the only thing the open can wait for
		// is the tenant's lock.
		var out string
		if err := x.QueryRow(l.h.ctx, request, A.Endpoint, "203.0.113.61/32").Scan(&out); err != nil || out != "pending_proof" {
			t.Fatalf("the request in flight: %q, %v", out, err)
		}
		pid, result := l.inBackground("tenant", A.Tenant, open, claim)
		l.waitForLock(pid)
		select {
		case r := <-result:
			t.Fatalf("an open finished while a request of its tenant was in flight: %q", r)
		case <-time.After(300 * time.Millisecond):
		}
		if err := x.Commit(l.h.ctx); err != nil {
			t.Fatal(err)
		}
		if got := l.await(result); uuid.Validate(got) != nil {
			t.Errorf("the open after the request committed: %q, want a challenge id", got)
		}
	})

	t.Run("an open in flight holds back a request", func(t *testing.T) {
		l := newClaimLab(t)
		A := l.A
		l.openMode()
		claim := l.pendingClaimOf(A, "203.0.113.62")
		x, _ := l.rawTx("tenant", A.Tenant)
		var id string
		if err := x.QueryRow(l.h.ctx, open, claim).Scan(&id); err != nil {
			t.Fatalf("the open in flight: %v", err)
		}
		pid, result := l.inBackground("tenant", A.Tenant, request, A.Endpoint, "203.0.113.63/32")
		l.waitForLock(pid)
		select {
		case r := <-result:
			t.Fatalf("a request finished while an open of its tenant was in flight: %q", r)
		case <-time.After(300 * time.Millisecond):
		}
		if err := x.Commit(l.h.ctx); err != nil {
			t.Fatal(err)
		}
		l.want("the request after the open committed", l.await(result), "pending_proof")
	})

	t.Run("another tenant's open is not held back", func(t *testing.T) {
		l := newClaimLab(t)
		A, B := l.A, l.B
		l.openMode()
		x, _ := l.rawTx("tenant", A.Tenant)
		var out string
		if err := x.QueryRow(l.h.ctx, request, A.Endpoint, "203.0.113.64/32").Scan(&out); err != nil {
			t.Fatal(err)
		}
		_, result := l.inBackground("tenant", B.Tenant, open, B.Claim)
		select {
		case r := <-result:
			if uuid.Validate(r) != nil {
				t.Errorf("tenant B's open: %q", r)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("tenant B's open waited for a request of tenant A")
		}
	})
}

// TestRequestAndOpenChallengeDoNotDeadlock (DT2): a request and an open on the
// same prefix of one tenant, started together on two connections, both lock the
// tenant's claim row. If one took the row before the tenant's lock and the other
// after it, they would wait for each other.
func TestRequestAndOpenChallengeDoNotDeadlock(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	l.openMode()
	l.exec("UPDATE ctrlz.entitlement_defaults SET max_ip_claims = 1000")
	const rounds = 120
	for round := 0; round < rounds; round++ {
		ip := fmt.Sprintf("203.0.%d.%d", 114+round/200, round%200+10)
		claim := l.pendingClaimOf(A, ip)
		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			errs <- l.tenant.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
				_, err := tx.IPClaimRequest(A.Endpoint, netip.MustParsePrefix(ip+"/32"), "manual")
				return err
			})
		}()
		go func() {
			<-start
			errs <- l.tenant.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
				_, _, err := tx.IPClaimOpenChallenge(claim)
				return err
			})
		}()
		close(start)
		for i := 0; i < 2; i++ {
			select {
			case err := <-errs:
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
			case <-time.After(30 * time.Second):
				t.Fatalf("round %d: a call did not finish", round)
			}
		}
	}
}

// TestQuotaIsPerTenantAndOrderedBeforeSuspended (DT5): what the first round's
// quota tests did not pin. The lock of one tenant's request does not hold up
// another tenant's; the limit columns refuse a negative number and the
// default refuses NULL; a tenant at its limit that asks for a prefix of its own
// suspended claim hears "suspended", not "quota_exceeded".
func TestQuotaIsPerTenantAndOrderedBeforeSuspended(t *testing.T) {
	const request = "SELECT outcome FROM ctrlz_fn.ip_claim_request($1, $2::cidr, 'manual')"

	t.Run("one tenant's request in flight does not hold up another's", func(t *testing.T) {
		l := newClaimLab(t)
		A, B := l.A, l.B
		l.openMode()
		x, _ := l.rawTx("tenant", A.Tenant)
		var out string
		if err := x.QueryRow(l.h.ctx, request, A.Endpoint, "203.0.113.71/32").Scan(&out); err != nil || out != "pending_proof" {
			t.Fatalf("A's request in flight: %q, %v", out, err)
		}
		// Control: A's own next request does wait.
		pidA, resultA := l.inBackground("tenant", A.Tenant, request, A.Endpoint, "203.0.113.72/32")
		l.waitForLock(pidA)
		_, resultB := l.inBackground("tenant", B.Tenant, request, B.Endpoint, "203.0.113.73/32")
		select {
		case out := <-resultB:
			l.want("B's request while A's request is in flight", out, "pending_proof")
		case <-time.After(5 * time.Second):
			t.Fatal("B's request waited for tenant A's request")
		}
		if err := x.Commit(l.h.ctx); err != nil {
			t.Fatal(err)
		}
		l.want("A's second request after the first committed", l.await(resultA), "pending_proof")
	})

	t.Run("the limit columns", func(t *testing.T) {
		h := newHarness(t, testpg.Need(t, cluster))
		a := h.A
		for _, c := range []struct {
			what, sql string
			args      []any
			want      string
		}{
			{"a negative default", "UPDATE ctrlz.entitlement_defaults SET max_ip_claims = -1", nil, "23514"},
			{"a default of NULL", "UPDATE ctrlz.entitlement_defaults SET max_ip_claims = NULL", nil, "23502"},
			{"a negative override", "UPDATE ctrlz.tenant_entitlements SET max_ip_claims = -1 WHERE tenant_id = $1", []any{a.Tenant}, "23514"},
			{"a default of zero", "UPDATE ctrlz.entitlement_defaults SET max_ip_claims = 0", nil, ""},
			{"an override of zero", "UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 0 WHERE tenant_id = $1", []any{a.Tenant}, ""},
			{"an override of NULL", "UPDATE ctrlz.tenant_entitlements SET max_ip_claims = NULL WHERE tenant_id = $1", []any{a.Tenant}, ""},
		} {
			if got := h.try("", nil, c.sql, c.args...); got != c.want {
				t.Errorf("%s: SQLSTATE %q, want %q", c.what, got, c.want)
			}
		}
	})

	t.Run("a suspended prefix is answered before the quota", func(t *testing.T) {
		l := newClaimLab(t)
		A := l.A
		l.openMode()
		l.exec("UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 1 WHERE tenant_id = $1", A.Tenant)
		l.insertClaim(A, uuid.Must(uuid.NewV7()), "203.0.113.80/32", "suspended")
		l.want("a prefix of the tenant's suspended claim, over the limit", l.request(A, "203.0.113.80/32", "manual").Outcome, "suspended")
		l.want("another prefix, over the limit", l.request(A, "203.0.113.81/32", "manual").Outcome, "quota_exceeded")
	})
}
