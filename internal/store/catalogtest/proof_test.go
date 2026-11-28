package catalogtest_test

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// The tests in this file are the second round of the claim work. Each one fails
// if the function it guards is put back to its 0008 form; the mutation checks
// of the review did exactly that.

func (l *claimLab) attempts(claim uuid.UUID) (n, consumed int) {
	l.t.Helper()
	if err := l.h.super.QueryRow(l.h.ctx,
		"SELECT COALESCE(max(attempts), 0), count(consumed_at) FROM ctrlz.ip_proof_challenges WHERE claim_id = $1", claim).Scan(&n, &consumed); err != nil {
		l.t.Fatal(err)
	}
	return
}

func (l *claimLab) openMode() { l.exec("UPDATE ctrlz.system_settings SET registration_mode = 'open'") }

func (l *claimLab) closedMode() {
	l.exec("UPDATE ctrlz.system_settings SET registration_mode = 'closed'")
}

// pendingClaim is a fresh open-mode /32 of tenant B.
func (l *claimLab) pendingClaim(ip string) uuid.UUID { return l.pendingClaimOf(l.B, ip) }

// pendingClaimOf is a fresh open-mode /32 of one tenant.
func (l *claimLab) pendingClaimOf(who catalogtest.SeedIDs, ip string) uuid.UUID {
	l.t.Helper()
	r := l.request(who, ip+"/32", "manual")
	if r.Outcome != "pending_proof" {
		l.t.Fatalf("request %s: %s", ip, r.Outcome)
	}
	return r.ClaimID
}

// TestIPProofEvidence (NEW-1): the transport decides what a proof needs. The
// reproduction was a spoofed UDP query: the hub records the victim's address,
// and the old take accepted it from the attacker with no code at all.
func TestIPProofEvidence(t *testing.T) {
	l := newClaimLab(t)
	B := l.B
	l.openMode()

	t.Run("a spoofed UDP observation takes nothing", func(t *testing.T) {
		// A holds the address (closed mode, never proven); B's challenge was
		// seen over UDP from that address. The code went to the real address,
		// so B has none.
		l.closedMode()
		a := l.request(l.A, "192.0.2.80/32", "manual")
		l.want("A's claim", a.Outcome, "active")
		l.openMode()
		b := l.pendingClaim("192.0.2.80")
		l.observeOver(B, b, "192.0.2.80", "udp")
		l.want("a UDP observation without the code", l.take(B, b), "no_proof")
		l.wantState("A's claim", a.ClaimID, "active")
		l.wantState("B's claim", b, "pending_proof")
		if n, _ := l.attempts(b); n != 0 {
			t.Errorf("a take with no code counted as a wrong code: %d", n)
		}
	})

	t.Run("a wrong code is counted, and the count is committed", func(t *testing.T) {
		c := l.pendingClaim("192.0.2.81")
		chal := l.open(B, c)
		code := l.hubSees(chal.Label, "192.0.2.81", "udp")
		if code == "" {
			t.Fatal("no code")
		}
		l.want("a wrong code", l.takeWith(B, c, "aaaaaaaaaa"), "no_proof")
		if n, _ := l.attempts(c); n != 1 {
			t.Fatalf("attempts after one wrong code: %d, want 1; the increment must persist, so the call may not raise", n)
		}
		// The code that the node would send to a different address is wrong too.
		l.want("the code for another address", l.takeWith(B, c, proofCode(testProofKey, chal.Label, "192.0.2.82")), "no_proof")
		l.want("the code of another label", l.takeWith(B, c, proofCode(testProofKey, "otherlabel", "192.0.2.81")), "no_proof")
		if n, _ := l.attempts(c); n != 3 {
			t.Errorf("attempts: %d, want 3", n)
		}
		l.want("the right code, upper case and padded", l.takeWith(B, c, "  "+strings.ToUpper(code)+" "), "active")
		if got := l.method(c); got != "verify_udp_txt" {
			t.Errorf("proof method %q, want verify_udp_txt (set from the evidence)", got)
		}
		if _, consumed := l.attempts(c); consumed != 1 {
			t.Errorf("the challenge was not consumed")
		}
	})

	t.Run("the fifth wrong code consumes the challenge", func(t *testing.T) {
		c := l.pendingClaim("192.0.2.83")
		chal := l.open(B, c)
		code := l.hubSees(chal.Label, "192.0.2.83", "udp")
		for i := 1; i <= 5; i++ {
			l.want(fmt.Sprintf("wrong code %d", i), l.takeWith(B, c, fmt.Sprintf("zzzzzzzzz%d", i)), "no_proof")
		}
		if n, consumed := l.attempts(c); n != 5 || consumed != 1 {
			t.Errorf("attempts %d consumed %d, want 5 and 1", n, consumed)
		}
		l.want("the right code after the challenge is gone", l.takeWith(B, c, code), "no_proof")
		l.wantState("the claim", c, "pending_proof")
	})

	t.Run("a TCP-class observation needs no code, and sets the method", func(t *testing.T) {
		cases := []struct{ proto, want string }{
			{"tcp", "verify_tcp"},
			{"dot", "secure_dns"},
			{"doh", "secure_dns"},
			{"doq", "secure_dns"},
		}
		for i, c := range cases {
			ip := fmt.Sprintf("192.0.2.%d", 100+i)
			claim := l.pendingClaim(ip)
			l.observeOver(B, claim, ip, c.proto)
			l.want(c.proto, l.take(B, claim), "active")
			if got := l.method(claim); got != c.want {
				t.Errorf("%s: proof_method %q, want %q", c.proto, got, c.want)
			}
		}
	})

	t.Run("TCP evidence wins over a UDP observation, and counts no wrong code", func(t *testing.T) {
		claim := l.pendingClaim("192.0.2.111")
		l.observeOver(B, claim, "192.0.2.111", "udp")
		l.observeOver(B, claim, "192.0.2.111", "tcp")
		l.want("a wrong code beside TCP evidence", l.takeWith(B, claim, "bbbbbbbbbb"), "active")
		if n, _ := l.attempts(claim); n != 0 {
			t.Errorf("attempts %d, want 0", n)
		}
		if got := l.method(claim); got != "verify_tcp" {
			t.Errorf("proof method %q", got)
		}
	})

	t.Run("the hub's write is constrained by the table", func(t *testing.T) {
		claim := l.pendingClaim("192.0.2.112")
		chal := l.open(B, claim)
		hubWrite := func(sql string, args ...any) error {
			return l.hub.WithTenant(l.h.ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
				_, err := tx.DB().Exec(tx.Context(), sql, args...)
				return err
			})
		}
		const q = "UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = '192.0.2.112', observed_protocol = $2, txt_code_hash = $3 WHERE label = $1"
		if err := hubWrite(q, chal.Label, "udp", nil); !errors.Is(err, store.ErrConstraint) {
			t.Errorf("a udp observation without a code hash: %v, want a constraint violation", err)
		}
		if err := hubWrite(q, chal.Label, "icmp", make([]byte, 32)); !errors.Is(err, store.ErrConstraint) {
			t.Errorf("an unknown protocol: %v", err)
		}
		if err := hubWrite(q, chal.Label, "udp", []byte{1}); !errors.Is(err, store.ErrConstraint) {
			t.Errorf("a short code hash: %v", err)
		}
		if err := hubWrite("UPDATE ctrlz.ip_proof_challenges SET observed_at = now() WHERE label = $1", chal.Label); !errors.Is(err, store.ErrConstraint) {
			t.Errorf("a time without an address and a transport: %v", err)
		}
		if err := hubWrite(q, chal.Label, "tcp", nil); err != nil {
			t.Errorf("a tcp observation: %v", err)
		}
	})
}

// TestIPProofGrants: who can read and write the evidence, with two tenants.
func TestIPProofGrants(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.openMode()
	ca := l.pendingClaimOf(A, "192.0.2.120")
	cb := l.pendingClaimOf(B, "192.0.2.121")
	chA := l.open(A, ca)
	chB := l.open(B, cb)
	l.hubSees(chA.Label, "192.0.2.120", "udp")
	l.hubSees(chB.Label, "192.0.2.121", "udp")

	asTenant := func(who uuid.UUID, sql string, args ...any) error {
		return l.tenant.WithTenant(l.h.ctx, who, store.TxOpts{}, func(tx store.Tx) error {
			rows, err := tx.DB().Query(tx.Context(), sql, args...)
			if err != nil {
				return err
			}
			rows.Close()
			return rows.Err()
		})
	}
	// The tenant reads the state of its challenges, not the hash and not the
	// address (an attacker who spoofs a UDP query would otherwise learn whose
	// address the hub saw).
	for _, col := range []string{"txt_code_hash", "observed_ip"} {
		if err := asTenant(A.Tenant, "SELECT "+col+" FROM ctrlz.ip_proof_challenges"); !errors.Is(err, store.ErrPermission) {
			t.Errorf("the tenant read %s: %v", col, err)
		}
	}
	if err := asTenant(A.Tenant, "SELECT * FROM ctrlz.ip_proof_challenges"); !errors.Is(err, store.ErrPermission) {
		t.Errorf("SELECT * as the tenant: %v; the hash and the address must not be reachable by accident", err)
	}
	var labels []string
	if err := l.tenant.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		rows, err := tx.DB().Query(tx.Context(), "SELECT label, observed_protocol, attempts FROM ctrlz.ip_proof_challenges ORDER BY label")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lab string
			var proto *string
			var n int
			if err := rows.Scan(&lab, &proto, &n); err != nil {
				return err
			}
			p := ""
			if proto != nil {
				p = *proto
			}
			labels = append(labels, lab+"/"+p)
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	for _, got := range labels {
		if strings.HasPrefix(got, chB.Label) {
			t.Errorf("tenant A sees tenant B's challenge %s", got)
		}
	}
	found := false
	for _, got := range labels {
		found = found || strings.HasPrefix(got, chA.Label+"/udp")
	}
	if !found {
		t.Errorf("tenant A does not see its own challenge: %v", labels)
	}

	// The tenant writes nothing in the table: no insert, no update.
	for name, sql := range map[string]string{
		"insert":   "INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, expires_at) SELECT tenant_id, id, 'selfmade', now() + interval '1 minute' FROM ctrlz.ip_claims LIMIT 1",
		"consume":  "UPDATE ctrlz.ip_proof_challenges SET consumed_at = now()",
		"attempts": "UPDATE ctrlz.ip_proof_challenges SET attempts = 0",
		"observe":  "UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = '192.0.2.1', observed_protocol = 'tcp'",
		"delete":   "DELETE FROM ctrlz.ip_proof_challenges",
	} {
		if err := l.tenant.WithTenant(l.h.ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, err := tx.DB().Exec(tx.Context(), sql)
			return err
		}); !errors.Is(err, store.ErrPermission) {
			t.Errorf("tenant %s: %v, want permission denied", name, err)
		}
	}

	// The hub writes the four evidence columns and nothing else, and cannot
	// read the hash it wrote.
	hubTry := func(who uuid.UUID, sql string, args ...any) (int64, error) {
		var n int64
		err := l.hub.WithTenant(l.h.ctx, who, store.TxOpts{}, func(tx store.Tx) error {
			tag, err := tx.DB().Exec(tx.Context(), sql, args...)
			n = tag.RowsAffected()
			return err
		})
		return n, err
	}
	if _, err := hubTry(A.Tenant, "UPDATE ctrlz.ip_proof_challenges SET consumed_at = now() WHERE label = $1", chA.Label); !errors.Is(err, store.ErrPermission) {
		t.Errorf("the hub consumed a challenge: %v", err)
	}
	if _, err := hubTry(A.Tenant, "UPDATE ctrlz.ip_proof_challenges SET attempts = 0 WHERE label = $1", chA.Label); !errors.Is(err, store.ErrPermission) {
		t.Errorf("the hub reset attempts: %v", err)
	}
	if _, err := hubTry(A.Tenant, "UPDATE ctrlz.ip_proof_challenges SET expires_at = now() + interval '5 minutes' WHERE label = $1", chA.Label); !errors.Is(err, store.ErrPermission) {
		t.Errorf("the hub moved the expiry: %v", err)
	}
	if _, err := hubTry(A.Tenant, "SELECT txt_code_hash FROM ctrlz.ip_proof_challenges"); !errors.Is(err, store.ErrPermission) {
		t.Errorf("the hub read the code hash: %v", err)
	}
	// In tenant A's transaction the hub cannot write tenant B's challenge.
	if n, err := hubTry(A.Tenant, "UPDATE ctrlz.ip_proof_challenges SET observed_protocol = 'tcp' WHERE label = $1", chB.Label); err != nil || n != 0 {
		t.Errorf("the hub wrote tenant B's row inside tenant A's transaction: %d rows, %v", n, err)
	}
	// Without a tenant the hub can find a label but not write it.
	if err := l.hub.WithGlobal(l.h.ctx, store.TxOpts{}, func(tx store.GlobalTx) error {
		tag, err := tx.DB().Exec(tx.Context(), "UPDATE ctrlz.ip_proof_challenges SET observed_protocol = 'tcp' WHERE label = $1", chA.Label)
		if err == nil && tag.RowsAffected() != 0 {
			t.Errorf("the hub wrote a challenge with no tenant set: %d rows", tag.RowsAffected())
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// TestIPClaimOpenChallenge (NEW-2): the function, not the tenant, picks the
// label and the lifetime, and old evidence does not count.
func TestIPClaimOpenChallenge(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()
	a := l.request(A, "192.0.2.130/32", "manual")
	labelRE := regexp.MustCompile(`^[a-z2-7]{26}$`)

	c1 := l.open(A, a.ClaimID)
	c2 := l.open(A, a.ClaimID)
	for _, c := range []store.Challenge{c1, c2} {
		if !labelRE.MatchString(c.Label) {
			t.Errorf("label %q does not match [a-z2-7]{26}", c.Label)
		}
		if d := time.Until(c.ExpiresAt); d < 9*time.Minute || d > 10*time.Minute+5*time.Second {
			t.Errorf("expiry is %v from now, want ten minutes", d)
		}
	}
	if c1.Label == c2.Label || c1.ID == c2.ID {
		t.Error("two challenges share a label or an id")
	}

	// Not the caller's claim, a claim that does not exist, released, suspended.
	if _, ok := l.tryOpen(B, a.ClaimID); ok {
		t.Error("tenant B opened a challenge on tenant A's claim")
	}
	if _, ok := l.tryOpen(A, uuid.New()); ok {
		t.Error("a challenge for a claim that does not exist")
	}
	var before int
	_ = l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_proof_challenges WHERE claim_id = $1", a.ClaimID).Scan(&before)
	if before != 2 {
		t.Errorf("%d challenges on the claim after the refused openings, want 2", before)
	}
	l.workerSets(A, a.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")
	if _, ok := l.tryOpen(A, a.ClaimID); ok {
		t.Error("a challenge for a suspended claim")
	}
	l.exec("UPDATE ctrlz.ip_claims SET state = 'active' WHERE id = $1", a.ClaimID)
	l.want("release", l.release(A, a.ClaimID), "released")
	if _, ok := l.tryOpen(A, a.ClaimID); ok {
		t.Error("a challenge for a released claim")
	}

	// The table refuses a long lifetime from anybody (the tenant cannot insert
	// at all; this is the superuser, who bypasses grants but not CHECKs).
	_, err := l.h.super.Exec(l.h.ctx, `INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, expires_at)
VALUES ($1, $2, 'tenyearslabel', now() + interval '10 years')`, A.Tenant, a.ClaimID)
	if pe := pgErr(err); pe == nil || pe.Code != "23514" || pe.ConstraintName != "ip_proof_challenges_lifetime" {
		t.Errorf("a ten year expiry: %v, want the lifetime CHECK", err)
	}

	// Recency: evidence older than fifteen minutes is not evidence, whatever the
	// expiry says.
	l.openMode()
	b := l.pendingClaim("192.0.2.131")
	l.observe(B, b, "192.0.2.131")
	l.age(b, 20*time.Minute, 9*time.Minute)
	l.want("an observation from twenty minutes ago", l.take(B, b), "no_proof")
	l.age(b, 14*time.Minute, 9*time.Minute)
	l.want("an observation from fourteen minutes ago", l.take(B, b), "active")
}

// TestIPClaimDisplacementNeedsTheObservedAddress (NEW-3): proof of one address
// displaces only the claims that contain it.
func TestIPClaimDisplacementNeedsTheObservedAddress(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()
	a5 := l.request(A, "198.51.100.5/32", "manual")
	a77 := l.request(A, "198.51.100.77/32", "manual")
	l.want("A's /32 at .5", a5.Outcome, "active")
	l.want("A's /32 at .77", a77.Outcome, "active")
	l.openMode()
	wide := l.request(B, "198.51.100.0/24", "manual")
	l.want("B's /24", wide.Outcome, "wide_requires_approval")
	l.approve(wide.ClaimID)

	// Evidence from .200 only: nothing in A's claims contains it.
	l.observe(B, wide.ClaimID, "198.51.100.200")
	l.want("the /24 with evidence from an unclaimed address", l.take(B, wide.ClaimID), "unavailable")
	l.wantState("A's claim at .5", a5.ClaimID, "active")
	l.wantState("A's claim at .77", a77.ClaimID, "active")

	// Evidence from .77 contains one victim but not the other: the claim at .5
	// still overlaps and was never proven by B, so nothing changes.
	l.observe(B, wide.ClaimID, "198.51.100.77")
	l.want("the /24 with evidence from .77", l.take(B, wide.ClaimID), "unavailable")
	l.wantState("A's claim at .5", a5.ClaimID, "active")
	l.wantState("A's claim at .77", a77.ClaimID, "active")
	l.wantState("B's /24", wide.ClaimID, "pending_proof")

	// With only the claim at .77 left, the same evidence displaces it.
	l.exec("UPDATE ctrlz.ip_claims SET state = 'released' WHERE id = $1", a5.ClaimID)
	l.want("the /24 once only the claim at .77 overlaps", l.take(B, wide.ClaimID), "active")
	if st, displaced, _ := l.state(a77.ClaimID); st != "released" || !displaced {
		t.Errorf("A's claim at .77: %s displaced %v, want released and displaced", st, displaced)
	}
}

// TestIPClaimUnprovenActive (L1-F01): a claim that is active but never proven
// can prove itself, and the Plan's rule for unproven claims stays as written.
func TestIPClaimUnprovenActive(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()

	a := l.request(A, "192.0.2.90/32", "manual")
	l.want("A's closed-mode claim", a.Outcome, "active")
	if _, _, proven := l.state(a.ClaimID); proven {
		t.Fatal("a closed-mode claim starts out proven")
	}
	l.want("A takes without evidence", l.take(A, a.ClaimID), "no_proof")
	l.observe(A, a.ClaimID, "192.0.2.90")
	l.want("A proves its active claim", l.take(A, a.ClaimID), "active")
	if st, _, proven := l.state(a.ClaimID); st != "active" || !proven {
		t.Errorf("after proof: %s proven %v", st, proven)
	}
	if got := l.method(a.ClaimID); got != "verify_tcp" {
		t.Errorf("proof method %q", got)
	}
	l.want("A takes again", l.take(A, a.ClaimID), "already_active")

	// Now B cannot take it with fresh evidence of its own.
	l.openMode()
	b := l.pendingClaim("192.0.2.90")
	l.observe(B, b, "192.0.2.90")
	l.want("B against A's proven claim", l.take(B, b), "unavailable")
	l.wantState("A's proven claim", a.ClaimID, "active")

	// The Plan's rule: an unproven claim is replaced at once by another
	// tenant's fresh proof.
	l.closedMode()
	u := l.request(A, "192.0.2.91/32", "manual")
	l.openMode()
	bu := l.pendingClaim("192.0.2.91")
	l.observe(B, bu, "192.0.2.91")
	l.want("B against A's unproven claim", l.take(B, bu), "active")
	l.wantState("A's unproven claim", u.ClaimID, "released")

	// Grace gives an unproven claim no protection either (decision recorded in
	// the Plan): the worker moved it to grace, but nobody ever proved it.
	l.closedMode()
	g := l.request(A, "192.0.2.92/32", "manual")
	l.workerSets(A, g.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + interval '14 days' WHERE id = $1")
	l.openMode()
	bg := l.pendingClaim("192.0.2.92")
	l.observe(B, bg, "192.0.2.92")
	l.want("B against A's unproven claim in grace", l.take(B, bg), "active")
	l.wantState("A's unproven claim in grace", g.ClaimID, "released")

	// A proven claim in grace is protected while it is fresh.
	l.closedMode()
	p := l.request(A, "192.0.2.93/32", "manual")
	l.observe(A, p.ClaimID, "192.0.2.93")
	l.want("A proves it", l.take(A, p.ClaimID), "active")
	l.workerSets(A, p.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + interval '14 days' WHERE id = $1")
	l.openMode()
	bp := l.pendingClaim("192.0.2.93")
	l.observe(B, bp, "192.0.2.93")
	l.want("B against A's proven claim in grace", l.take(B, bp), "unavailable")
	l.wantState("A's proven claim in grace", p.ClaimID, "grace")
}

// TestIPClaimSuspended (NEW-4): the admin's say cannot be skipped by releasing
// the claim or by asking for the same prefix again.
func TestIPClaimSuspended(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	l.closedMode()
	a := l.request(A, "192.0.2.100/32", "manual")
	l.want("A's claim", a.Outcome, "active")
	l.workerSets(A, a.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")

	l.want("A takes a suspended claim", l.take(A, a.ClaimID), "suspended")
	l.want("A releases a suspended claim", l.release(A, a.ClaimID), "suspended")
	l.wantState("the suspended claim", a.ClaimID, "suspended")
	r := l.request(A, "192.0.2.100/32", "manual")
	l.want("A asks for the same /32 again", r.Outcome, "suspended")
	if r.ClaimID != uuid.Nil {
		t.Error("a claim was created beside the suspended one")
	}
	l.want("A asks for a /28 around it", l.request(A, "192.0.2.96/28", "manual").Outcome, "suspended")
	l.want("A asks for a disjoint prefix", l.request(A, "192.0.2.200/32", "manual").Outcome, "active")

	// A suspension is A's: it does not block B, and B's own state is unaffected.
	l.want("B asks for the suspended /32", l.request(B, "192.0.2.100/32", "manual").Outcome, "active")

	// An admin clears it; then the normal path applies and the release works.
	l.exec("UPDATE ctrlz.ip_claims SET state = 'released' WHERE id = $1", a.ClaimID)
	l.want("release after the admin ended it", l.release(A, a.ClaimID), "not_found")
}

// TestIPClaimAddressClasses (L1-F19): ranges that never carry a customer's
// plain DNS traffic are refused, in every mode and at every width.
func TestIPClaimAddressClasses(t *testing.T) {
	l := newClaimLab(t)
	A := l.A
	bad := []string{
		"0.0.0.0/0", "0.0.0.0/1", "0.1.2.3/32", "10.0.0.0/8", "10.1.2.3/32", "100.64.0.0/10", "100.127.255.255/32",
		"127.0.0.1/32", "127.0.0.0/8", "169.254.1.1/32", "172.16.0.0/12", "172.31.255.255/32", "192.168.1.1/32",
		"224.0.0.1/32", "239.255.255.255/32", "240.0.0.1/32", "255.255.255.255/32",
		"8.0.0.0/5",   // 8 to 15 contains 10/8
		"128.0.0.0/1", // contains 192.168, 224/4, 240/4
	}
	good := []string{
		"192.0.2.5/32", "198.51.100.5/32", "203.0.113.5/32", // documentation ranges stay accepted
		"100.63.255.255/32", "100.128.0.1/32", "172.15.255.255/32", "172.32.0.1/32", "169.253.255.255/32",
		"11.0.0.1/32", "1.1.1.1/32", "223.255.255.254/32", "126.255.255.255/32", "192.167.255.255/32",
	}
	for _, mode := range []string{"closed", "invite", "open"} {
		l.exec("UPDATE ctrlz.system_settings SET registration_mode = $1", mode)
		for _, p := range bad {
			if r := l.request(A, p, "manual"); r.Outcome != "invalid_address" || r.ClaimID != uuid.Nil {
				t.Errorf("%s mode, %s: %q, want invalid_address and no claim", mode, p, r.Outcome)
			}
		}
	}
	l.openMode()
	for _, p := range good {
		if r := l.request(A, p, "manual"); r.Outcome != "pending_proof" {
			t.Errorf("%s: %q, want it accepted", p, r.Outcome)
		}
	}
	if r := l.request(A, "192.0.2.77/32", "carrier_pigeon"); r.Outcome != "invalid_source" || r.ClaimID != uuid.Nil {
		t.Errorf("an unknown source: %q", r.Outcome)
	}
	var n int
	_ = l.h.super.QueryRow(l.h.ctx, "SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state = 'pending_proof'", A.Tenant).Scan(&n)
	if n != len(good) {
		t.Errorf("%d pending claims, want %d: a refused request left a row", n, len(good))
	}
}
