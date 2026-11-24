package catalogtest_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// proofCode is what the hub derives for a ProofObservation (contract 3.5): the
// first 10 characters of lowercase base32 of HMAC-SHA256(proof_key,
// "ctrlz-proof-v1\0" label "\0" source IP text). It mirrors identity.ProofCode
// in the shared module, which the Panel module does not import yet (the hub is
// a stub until P4); TestProofCodeMatchesTheSharedVector pins the two together
// with the committed vector.
func proofCode(key, label, ip string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte("ctrlz-proof-v1\x00" + label + "\x00" + ip))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(m.Sum(nil)))[:10]
}

func TestProofCodeMatchesTheSharedVector(t *testing.T) {
	// shared/vectors/hash.json, "hash-proof".
	if got := proofCode("key", "lbl", "192.0.2.1"); got != "sjgr3tvr53" {
		t.Fatalf("the test copy of the proof code derivation drifted from the contract: %s", got)
	}
}

// testProofKey stands in for the hub's proof_key (a Docker secret in the real
// stack). It is a test constant, not a secret.
const testProofKey = "lab-proof-key"

// claimLab is the shared set-up of the claim tests: the real store API as the
// tenant role, the real hub role writing the evidence the way a
// ProofObservation will, and a superuser session standing in for what an admin
// does (approving a claim) or for moving time.
type claimLab struct {
	t      *testing.T
	h      *harness
	tenant *store.Store
	worker *store.Store
	hub    *store.Store
	A, B   catalogtest.SeedIDs
}

func newClaimLab(t *testing.T) *claimLab {
	h := newHarness(t, testpg.Need(t, cluster))
	return &claimLab{
		t: t, h: h, A: h.A, B: h.B,
		tenant: h.db.Store(h.ctx, t, store.RoleTenant),
		worker: h.db.Store(h.ctx, t, store.RoleWorker),
		hub:    h.db.Store(h.ctx, t, store.RoleHub),
	}
}

func (l *claimLab) request(who catalogtest.SeedIDs, prefix, source string) store.IPClaimResult {
	l.t.Helper()
	var res store.IPClaimResult
	err := l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		res, err = tx.IPClaimRequest(who.Endpoint, netip.MustParsePrefix(prefix), source)
		return err
	})
	if err != nil {
		l.t.Fatalf("request %s: %v", prefix, err)
	}
	return res
}

func (l *claimLab) check(who catalogtest.SeedIDs, prefix string) string {
	l.t.Helper()
	var out string
	if err := l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		out, err = tx.IPClaimCheck(netip.MustParsePrefix(prefix))
		return err
	}); err != nil {
		l.t.Fatalf("check %s: %v", prefix, err)
	}
	return out
}

func (l *claimLab) takeWith(who catalogtest.SeedIDs, claim uuid.UUID, code string) string {
	l.t.Helper()
	var out string
	if err := l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		out, err = tx.IPClaimTake(claim, code)
		return err
	}); err != nil {
		l.t.Fatalf("take: %v", err)
	}
	return out
}

func (l *claimLab) take(who catalogtest.SeedIDs, claim uuid.UUID) string {
	return l.takeWith(who, claim, "")
}

func (l *claimLab) release(who catalogtest.SeedIDs, claim uuid.UUID) string {
	l.t.Helper()
	var out string
	if err := l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		out, err = tx.IPClaimRelease(claim)
		return err
	}); err != nil {
		l.t.Fatalf("release: %v", err)
	}
	return out
}

func (l *claimLab) state(claim uuid.UUID) (st string, displaced, proven bool) {
	l.t.Helper()
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT state, displaced_at IS NOT NULL, proven_at IS NOT NULL FROM ctrlz.ip_claims WHERE id = $1", claim).Scan(&st, &displaced, &proven); err != nil {
		l.t.Fatalf("state of %s: %v", claim, err)
	}
	return
}

// method is the recorded proof method of a claim, "" when none.
func (l *claimLab) method(claim uuid.UUID) string {
	l.t.Helper()
	var p *string
	if err := l.h.super.QueryRow(l.h.ctx, "SELECT proof_method FROM ctrlz.ip_claims WHERE id = $1", claim).Scan(&p); err != nil {
		l.t.Fatal(err)
	}
	if p == nil {
		return ""
	}
	return *p
}

func (l *claimLab) exec(sql string, args ...any) {
	l.t.Helper()
	if _, err := l.h.super.Exec(l.h.ctx, sql, args...); err != nil {
		l.t.Fatalf("%s: %v", sql, err)
	}
}

// open opens a challenge the way the API does, through the function.
func (l *claimLab) open(who catalogtest.SeedIDs, claim uuid.UUID) store.Challenge {
	l.t.Helper()
	c, ok := l.tryOpen(who, claim)
	if !ok {
		l.t.Fatalf("no challenge for claim %s", claim)
	}
	return c
}

func (l *claimLab) tryOpen(who catalogtest.SeedIDs, claim uuid.UUID) (c store.Challenge, ok bool) {
	l.t.Helper()
	if err := l.tenant.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		c, ok, err = tx.IPClaimOpenChallenge(claim)
		return err
	}); err != nil {
		l.t.Fatalf("open challenge: %v", err)
	}
	return c, ok
}

// hubSees plays the hub receiving a ProofObservation for a label: it finds the
// tenant of the label (the hub_label policy), then writes the evidence inside
// that tenant's transaction, as ctrlz_hub. It returns the TXT code the node
// answered with, which the hub derived from proof_key. The WHERE clause is the
// write-once rule the hub code will keep: an observed, consumed or expired
// challenge is not written again.
func (l *claimLab) hubSees(label, ip, protocol string) (code string) {
	l.t.Helper()
	ctx := l.h.ctx
	var tenant uuid.UUID
	if err := l.hub.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(tx store.GlobalTx) error {
		return tx.DB().QueryRow(tx.Context(), "SELECT tenant_id FROM ctrlz.ip_proof_challenges WHERE label = $1", label).Scan(&tenant)
	}); err != nil {
		l.t.Fatalf("hub: find label: %v", err)
	}
	code = proofCode(testProofKey, label, ip)
	sum := sha256.Sum256([]byte(code))
	var n int64
	if err := l.hub.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		tag, err := tx.DB().Exec(tx.Context(), `UPDATE ctrlz.ip_proof_challenges
SET observed_at = now(), observed_ip = $2, observed_protocol = $3, txt_code_hash = $4
WHERE label = $1 AND observed_at IS NULL AND consumed_at IS NULL AND expires_at > now()`, label, ip, protocol, sum[:])
		n = tag.RowsAffected()
		return err
	}); err != nil {
		l.t.Fatalf("hub: record observation: %v", err)
	}
	if n != 1 {
		l.t.Fatalf("hub: the observation of %s changed %d rows", label, n)
	}
	return code
}

// observe opens a challenge and has the hub see it over tcp from ip: valid
// evidence that needs no code.
func (l *claimLab) observe(who catalogtest.SeedIDs, claim uuid.UUID, ip string) {
	l.t.Helper()
	l.observeOver(who, claim, ip, "tcp")
}

// observeOver does the same over any transport and returns the code.
func (l *claimLab) observeOver(who catalogtest.SeedIDs, claim uuid.UUID, ip, protocol string) (code string) {
	l.t.Helper()
	c := l.open(who, claim)
	return l.hubSees(c.Label, ip, protocol)
}

// age moves the unconsumed evidence of a claim into the past, as time passing
// would: observed observedAgo ago, expiring expiresIn from now (negative:
// already gone). Only a superuser can do this, which is the point of the grants.
func (l *claimLab) age(claim uuid.UUID, observedAgo, expiresIn time.Duration) {
	l.t.Helper()
	l.exec(`UPDATE ctrlz.ip_proof_challenges
SET observed_at = now() - $2::interval, expires_at = now() + $3::interval
WHERE claim_id = $1 AND observed_at IS NOT NULL AND consumed_at IS NULL`,
		claim, fmt.Sprintf("%d seconds", int(observedAgo.Seconds())), fmt.Sprintf("%d seconds", int(expiresIn.Seconds())))
}

func (l *claimLab) approve(claim uuid.UUID) {
	l.exec("UPDATE ctrlz.ip_claims SET approved_by_admin = true WHERE id = $1", claim)
}

func (l *claimLab) want(what, got, expect string) {
	l.t.Helper()
	if got != expect {
		l.t.Errorf("%s: got %q, want %q", what, got, expect)
	}
}

func (l *claimLab) wantState(what string, claim uuid.UUID, want string) {
	l.t.Helper()
	if st, _, _ := l.state(claim); st != want {
		l.t.Errorf("%s: claim is %s, want %s", what, st, want)
	}
}

// workerSets runs a statement as the worker for a tenant, the way the grace
// sweep does. The statement takes the claim id as $1.
func (l *claimLab) workerSets(who catalogtest.SeedIDs, claim uuid.UUID, sql string) {
	l.t.Helper()
	if err := l.worker.WithTenant(l.h.ctx, who.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), sql, claim)
		return err
	}); err != nil {
		l.t.Fatalf("worker transition: %v", err)
	}
}

// unconsumed counts the challenges of a claim that could still be spent: not
// consumed, observed from inside the claim, not expired.
func (l *claimLab) unconsumed(claim uuid.UUID) int {
	l.t.Helper()
	var n int
	if err := l.h.super.QueryRow(l.h.ctx, `SELECT count(*) FROM ctrlz.ip_proof_challenges ch
WHERE ch.claim_id = $1 AND ch.consumed_at IS NULL AND ch.observed_at IS NOT NULL AND ch.expires_at > now()
  AND ch.observed_ip <<= (SELECT c.cidr FROM ctrlz.ip_claims c WHERE c.id = $1)`, claim).Scan(&n); err != nil {
		l.t.Fatal(err)
	}
	return n
}

// TestIPClaims is spec test 27, with two tenants and through the real store
// API: overlap across tenants, width, the grace transition, the end of grace,
// and takeover by both rules of D3. Source IP is the identity of a plain DNS
// client, so two tenants must never both hold an active claim on one address,
// and nothing may displace a claim without evidence in the database that the
// taker controls the address.
func TestIPClaims(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B

	// Closed registration: a free prefix is active at once, and a second
	// tenant cannot overlap it. The refusal says nothing about who holds it.
	cA := l.request(A, "192.0.2.0/28", "manual")
	l.want("A takes a free /28", cA.Outcome, "active")
	cB := l.request(B, "192.0.2.8/29", "manual")
	l.want("B overlaps A's /28", cB.Outcome, "unavailable")
	if cB.ClaimID != uuid.Nil {
		t.Errorf("a refused request created claim %s", cB.ClaimID)
	}
	l.want("B's check of the overlap", l.check(B, "192.0.2.0/29"), "unavailable")
	l.want("A's check of its own prefix", l.check(A, "192.0.2.0/29"), "own")
	l.want("B's check of a free prefix", l.check(B, "203.0.113.0/24"), "available")
	l.want("B's request for a disjoint prefix", l.request(B, "198.18.0.0/28", "manual").Outcome, "active")
	l.want("B's request on A's endpoint", func() string {
		var out string
		_ = l.tenant.WithTenant(l.h.ctx, B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			r, err := tx.IPClaimRequest(A.Endpoint, netip.MustParsePrefix("203.0.113.9/32"), "manual")
			out = r.Outcome
			return err
		})
		return out
	}(), "not_found")

	// Width is limited in every mode (R2). A /24 in closed mode used to be
	// active at once and took 256 addresses. Now it leaves a pending row that
	// serves nothing and blocks nothing, for an admin to approve.
	wide := l.request(A, "198.51.100.0/24", "manual")
	l.want("a /24 in closed mode", wide.Outcome, "wide_requires_approval")
	if wide.ClaimID == uuid.Nil {
		t.Fatal("the wide request left no row for an admin to approve")
	}
	l.wantState("the wide request", wide.ClaimID, "pending_proof")
	l.want("a pending wide claim blocks nobody", l.check(B, "198.51.100.0/24"), "available")
	l.want("the wide claim cannot be taken unapproved", l.take(A, wide.ClaimID), "wide_requires_approval")
	l.approve(wide.ClaimID)
	l.observe(A, wide.ClaimID, "198.51.100.77")
	l.want("the approved wide claim with evidence", l.take(A, wide.ClaimID), "active")
	l.want("B against the approved /24", l.request(B, "198.51.100.5/32", "manual").Outcome, "unavailable")

	// Open registration: claims wait for proof and may overlap while they wait.
	l.exec("UPDATE ctrlz.system_settings SET registration_mode = 'open'")
	pend := l.request(B, "192.0.2.5/32", "manual")
	l.want("B's /32 in open mode", pend.Outcome, "pending_proof")
	wide2 := l.request(B, "192.0.2.0/24", "manual")
	l.want("B's /24 in open mode", wide2.Outcome, "wide_requires_approval")
	if wide2.ClaimID == uuid.Nil {
		t.Error("an open-mode wide request left no row")
	}

	// No evidence, no takeover: the method name alone proves nothing, and
	// nothing is displaced.
	l.want("a take without a challenge", l.take(B, pend.ClaimID), "no_proof")
	l.wantState("A's claim after an unproven take", cA.ClaimID, "active")
	l.wantState("B's claim after an unproven take", pend.ClaimID, "pending_proof")
	l.observe(B, pend.ClaimID, "203.0.113.9") // outside the claim
	l.want("evidence from another address", l.take(B, pend.ClaimID), "no_proof")
	l.observe(B, pend.ClaimID, "192.0.2.5")
	l.age(pend.ClaimID, 2*time.Minute, -time.Minute) // a challenge that ran out before the take
	l.want("expired evidence", l.take(B, pend.ClaimID), "no_proof")

	// Valid evidence, but the victim's /28 covers more than the taker proved:
	// one address says nothing about the range around it, so nothing is
	// displaced. A's closed-mode /28 used to be released by a /32 proof.
	l.observe(B, pend.ClaimID, "192.0.2.5")
	l.want("B's /32 proof against A's wider /28", l.take(B, pend.ClaimID), "unavailable")
	l.wantState("A's /28 after the refused takeover", cA.ClaimID, "active")
	l.wantState("B's claim after the refused takeover", pend.ClaimID, "pending_proof")
	if n := l.unconsumed(pend.ClaimID); n != 1 {
		t.Errorf("a refused takeover consumed evidence: %d valid challenges left, want 1", n)
	}

	// First rule: an unproven victim of the same width is replaced at once by
	// a proof that covers it.
	l.exec("UPDATE ctrlz.system_settings SET registration_mode = 'closed'")
	a200 := l.request(A, "192.0.2.200/32", "manual")
	l.want("A's closed-mode /32", a200.Outcome, "active")
	l.exec("UPDATE ctrlz.system_settings SET registration_mode = 'open'")
	b200 := l.request(B, "192.0.2.200/32", "manual")
	l.want("B's open-mode /32", b200.Outcome, "pending_proof")
	l.observe(B, b200.ClaimID, "192.0.2.200")
	l.want("B proves the same /32", l.take(B, b200.ClaimID), "active")
	if st, displaced, _ := l.state(a200.ClaimID); st != "released" || !displaced {
		t.Errorf("A's unproven /32 after takeover: state %s displaced %v, want released and displaced", st, displaced)
	}
	if st, _, proven := l.state(b200.ClaimID); st != "active" || !proven {
		t.Errorf("B's claim after proof: state %s proven %v", st, proven)
	}
	if n := l.unconsumed(b200.ClaimID); n != 0 {
		t.Errorf("the evidence was not consumed: %d left", n)
	}
	l.want("A cannot release B's claim", l.release(A, b200.ClaimID), "not_found")
	l.wantState("B's claim", b200.ClaimID, "active")

	// Second rule: a proven claim holds until it has been idle for
	// takeover_idle_days, or its Endpoint is hard disabled.
	a77 := l.request(A, "192.0.2.77/32", "manual")
	l.want("A's /32 waits for proof", a77.Outcome, "pending_proof")
	l.observe(A, a77.ClaimID, "192.0.2.77")
	l.want("A proves it", l.take(A, a77.ClaimID), "active")
	b77 := l.request(B, "192.0.2.77/32", "manual")
	l.want("B's overlapping request waits", b77.Outcome, "pending_proof")
	l.observe(B, b77.ClaimID, "192.0.2.77")
	l.want("B cannot take a fresh proven claim", l.take(B, b77.ClaimID), "unavailable")
	l.wantState("A's proven claim after a refused takeover", a77.ClaimID, "active")
	l.wantState("B's claim after a refused takeover", b77.ClaimID, "pending_proof")
	l.exec("UPDATE ctrlz.ip_claims SET last_seen_at = now() - interval '8 days' WHERE id = $1", a77.ClaimID)
	l.want("B takes an idle proven claim", l.take(B, b77.ClaimID), "active")
	if st, displaced, _ := l.state(a77.ClaimID); st != "released" || !displaced {
		t.Errorf("A's idle claim: state %s displaced %v", st, displaced)
	}

	a88 := l.request(A, "192.0.2.88/32", "manual")
	l.observe(A, a88.ClaimID, "192.0.2.88")
	l.take(A, a88.ClaimID)
	b88 := l.request(B, "192.0.2.88/32", "manual")
	l.observe(B, b88.ClaimID, "192.0.2.88")
	l.want("B cannot take A's fresh claim", l.take(B, b88.ClaimID), "unavailable")
	l.exec("UPDATE ctrlz.endpoints SET admin_state = 'hard_disabled' WHERE id = $1", A.Endpoint)
	l.want("B takes the claim of a hard disabled endpoint", l.take(B, b88.ClaimID), "active")
	l.exec("UPDATE ctrlz.endpoints SET admin_state = 'enabled' WHERE id = $1", A.Endpoint)

	// DDNS is never proof: a claim from a DDNS name needs the same evidence,
	// and has none until the hub writes it.
	d := l.request(A, "192.0.2.150/32", "ddns")
	l.want("a DDNS claim", d.Outcome, "pending_proof")
	l.want("a DDNS claim without evidence", l.take(A, d.ClaimID), "no_proof")
	l.observe(A, d.ClaimID, "192.0.2.150")
	l.want("a DDNS claim with evidence", l.take(A, d.ClaimID), "active")

	// Grace and its end. The worker, not the tenant, moves a claim into grace.
	l.exec("UPDATE ctrlz.system_settings SET registration_mode = 'closed'")
	a210 := l.request(A, "192.0.2.210/32", "manual")
	l.want("A's closed-mode claim", a210.Outcome, "active")
	l.observe(A, a210.ClaimID, "192.0.2.210") // kept for after the suspension below
	l.workerSets(A, a210.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'grace', first_grace_at = now(), grace_until = now() + interval '14 days' WHERE id = $1")
	l.want("B against a claim in grace", l.request(B, "192.0.2.210/32", "manual").Outcome, "unavailable")
	l.workerSets(A, a210.ClaimID, "UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1")
	b210 := l.request(B, "192.0.2.210/32", "manual")
	l.want("B once grace has ended", b210.Outcome, "active")

	// A suspended claim is not re-activated by its tenant, even with evidence,
	// and displaces nobody. An admin clears it.
	l.want("A takes its suspended claim", l.take(A, a210.ClaimID), "suspended")
	l.wantState("A's suspended claim", a210.ClaimID, "suspended")
	l.wantState("B's claim after A's refused take", b210.ClaimID, "active")
	l.exec("UPDATE ctrlz.ip_claims SET state = 'pending_proof' WHERE id = $1", a210.ClaimID)
	l.want("A takes the cleared claim, with evidence", l.take(A, a210.ClaimID), "active")
	l.wantState("B's unproven claim after A's proof", b210.ClaimID, "released")

	// Release.
	l.want("A releases its claim", l.release(A, a210.ClaimID), "released")
	l.want("A releases it twice", l.release(A, a210.ClaimID), "not_found")
}

// TestIPClaimTakeIsRaceFree: a victim that proves itself while the taker waits
// is not displaced. The taker's check used to be a plain statement on its own
// snapshot, and the displacing UPDATE did not repeat the predicate, so a claim
// that became fresh and proven between the two was released anyway. Now the
// overlapping rows are locked first and the predicate runs again in the UPDATE.
func TestIPClaimTakeIsRaceFree(t *testing.T) {
	l := newClaimLab(t)
	A, B := l.A, l.B
	ctx := l.h.ctx

	// A holds an unproven closed-mode /32 (displaceable); B has valid evidence.
	a := l.request(A, "192.0.2.40/32", "manual")
	l.want("A's claim", a.Outcome, "active")
	l.exec("UPDATE ctrlz.system_settings SET registration_mode = 'open'")
	b := l.request(B, "192.0.2.40/32", "manual")
	l.observe(B, b.ClaimID, "192.0.2.40")

	// Connection 1 is the victim proving itself: it holds the row lock and has
	// not committed.
	victim, err := l.h.db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close(context.Background())
	vtx, err := victim.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer vtx.Rollback(context.Background())
	if _, err := vtx.Exec(ctx, "UPDATE ctrlz.ip_claims SET proven_at = now(), last_seen_at = now() WHERE id = $1", a.ClaimID); err != nil {
		t.Fatal(err)
	}

	// Connection 2 is B's takeover. It must block on the victim's row.
	taker, err := l.h.db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer taker.Close(context.Background())
	var takerPID int
	if err := taker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&takerPID); err != nil {
		t.Fatal(err)
	}
	result := make(chan string, 1)
	go func() {
		tx, err := taker.Begin(ctx)
		if err != nil {
			result <- "begin: " + err.Error()
			return
		}
		defer tx.Rollback(context.Background())
		for _, q := range []string{"SET LOCAL ROLE ctrlz_tenant"} {
			if _, err := tx.Exec(ctx, q); err != nil {
				result <- q + ": " + err.Error()
				return
			}
		}
		if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", B.Tenant.String()); err != nil {
			result <- "set tenant: " + err.Error()
			return
		}
		var out string
		if err := tx.QueryRow(ctx, "SELECT outcome FROM ctrlz_fn.ip_claim_take($1, NULL, $2)", b.ClaimID, uuid.Must(uuid.NewV7())).Scan(&out); err != nil {
			result <- "take: " + err.Error()
			return
		}
		_ = tx.Commit(ctx)
		result <- out
	}()

	// Wait until the taker is waiting on a lock, then let the victim commit.
	blocked := false
	for i := 0; i < 100 && !blocked; i++ {
		var n int
		if err := l.h.super.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock'", takerPID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		blocked = n == 1
		if !blocked {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !blocked {
		t.Fatal("the takeover did not wait for the victim's row lock; the overlapping claims are not locked before the check")
	}
	if err := vtx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case out := <-result:
		if out != "unavailable" {
			t.Errorf("takeover of a claim that proved itself meanwhile: %q, want unavailable", out)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the takeover did not finish")
	}
	l.wantState("the victim", a.ClaimID, "active")
	l.wantState("the taker", b.ClaimID, "pending_proof")
}
