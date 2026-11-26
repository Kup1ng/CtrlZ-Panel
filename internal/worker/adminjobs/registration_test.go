package adminjobs_test

import (
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/adminjobs"
)

// The registration sweep (docs/specs/p3-endpoints.md 4.4, AUTH 11.5, T-269, T-529). The seed gives each of the two tenants one
// active claim that was never proven.

func (r *rig) mode(mode string) {
	r.t.Helper()
	r.env.Exec(r.t, `UPDATE ctrlz.system_settings SET registration_mode = $1, open_grace_days = 7`, mode)
}

func (r *rig) sweep() adminjobs.RegistrationProgress {
	r.t.Helper()
	p, err := r.runner.SweepClaims(r.env.Ctx)
	if err != nil {
		r.t.Fatalf("sweep: %v", err)
	}
	return p
}

func (r *rig) states() map[string]int {
	r.t.Helper()
	out := map[string]int{}
	for _, s := range []string{"active", "grace", "suspended", "released", "pending_proof"} {
		out[s] = r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE state = $1`, s)
	}
	return out
}

func TestSweepGivesEachUnprovenClaimItsOneGrace(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)
	r.mode("open")
	p := r.sweep()
	if p.Tenants != 2 || p.Graced != 2 || p.Suspended != 0 {
		t.Fatalf("progress %+v", p)
	}
	if got := r.states(); got["grace"] != 2 || got["active"] != 0 {
		t.Fatalf("states %v", got)
	}
	// Seven days from now, once.
	if n := r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE state = 'grace' AND first_grace_at IS NOT NULL
		AND grace_until BETWEEN now() + interval '6 days 23 hours' AND now() + interval '7 days 1 hour'`); n != 2 {
		t.Errorf("%d claims have a grace of seven days", n)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'ip_grace_started'`); n != 2 {
		t.Errorf("%d grace notifications, want one per tenant", n)
	}
	// A grace compiles as the active claim did: nothing is marked.
	if n := r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE aggregate_type = 'endpoint_set'`); n != 0 {
		t.Errorf("a grace marked %d times", n)
	}
	// Again: nothing moves and nobody is told twice.
	p = r.sweep()
	if p.Graced != 0 || p.Suspended != 0 || r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'ip_grace_started'`) != 2 {
		t.Errorf("a second run %+v", p)
	}
}

func TestSweepSuspendsAtTheEndOfGraceInOneBatch(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)
	r.mode("open")
	r.sweep()
	r.env.Exec(t, `UPDATE ctrlz.ip_claims SET grace_until = now() - interval '1 minute' WHERE state = 'grace'`)
	p := r.sweep()
	if p.Suspended != 2 {
		t.Fatalf("progress %+v", p)
	}
	if got := r.states(); got["suspended"] != 2 {
		t.Fatalf("states %v", got)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'ip_suspended'`); n != 2 {
		t.Errorf("%d suspension notifications", n)
	}
	// A claim that left the set the nodes serve is marked, and one run is one batch across tenants (Plan: one config entry).
	if n := r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE aggregate_type = 'endpoint_set'`); n != 2 {
		t.Errorf("%d endpoint_set rows", n)
	}
	if n := r.count(`SELECT count(DISTINCT batch_id) FROM ctrlz.policy_outbox WHERE aggregate_type = 'endpoint_set'`); n != 1 {
		t.Errorf("%d batches for one run", n)
	}
	// A suspension stays until an admin ends it, whatever the mode.
	r.mode("closed")
	r.sweep()
	if got := r.states(); got["suspended"] != 2 {
		t.Errorf("closing registration changed a suspension: %v", got)
	}
}

func TestSweepClosingRestoresGraceAndReopeningSuspendsAtOnce(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	r.mode("open")
	r.sweep()
	firstGrace := r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE first_grace_at IS NOT NULL`)
	r.mode("invite")
	p := r.sweep()
	if p.Restored != 2 {
		t.Fatalf("progress %+v", p)
	}
	if n := r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE state = 'active' AND grace_until IS NULL AND first_grace_at IS NOT NULL`); n != 2 || firstGrace != 2 {
		t.Errorf("%d claims are active again with their grace on record", n)
	}
	// Open again: a claim that already had its one grace is suspended at once, and the date of the grace is never lowered.
	var before time.Time
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT min(first_grace_at) FROM ctrlz.ip_claims`, nil, &before); err != nil {
		t.Fatal(err)
	}
	r.mode("open")
	p = r.sweep()
	if p.Suspended != 2 || p.Graced != 0 {
		t.Fatalf("reopening %+v", p)
	}
	var after time.Time
	if err := r.env.DB.Scan(r.env.Ctx, `SELECT min(first_grace_at) FROM ctrlz.ip_claims`, nil, &after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Error("first_grace_at moved")
	}
}

func TestSweepLeavesProvenAndReleasedClaimsAlone(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	r.env.Exec(t, `UPDATE ctrlz.ip_claims SET proven_at = now() WHERE tenant_id = $1`, r.env.A.Tenant)
	r.env.Exec(t, `UPDATE ctrlz.ip_claims SET state = 'released' WHERE tenant_id = $1`, r.env.B.Tenant)
	r.mode("open")
	p := r.sweep()
	if p.Graced != 0 {
		t.Fatalf("progress %+v", p)
	}
	if got := r.states(); got["active"] != 1 || got["released"] != 1 {
		t.Errorf("states %v", got)
	}
}

// The job does the same work as the periodic sweep, from the mode in force when it runs, and reports it.
func TestRegistrationJobSweepsAndReports(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	r.mode("open")
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{"from": "closed", "to": "open", "grace_days": 7})
	r.runOnce()
	state, p := r.job(id)
	if state != "done" || p["tenants"] != float64(2) || p["graced"] != float64(2) {
		t.Errorf("%s %v", state, p)
	}
	if got := r.states(); got["grace"] != 2 {
		t.Errorf("states %v", got)
	}
}

// Two workers do not sweep at once: the lease goes to one holder until it ends.
func TestSweepLease(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	take := func(holder string, secs int) bool {
		var ok bool
		err := r.env.Worker(t).WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
			ok, err = g.LeaseTake("registration_sweep", holder, secs)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !take("one", 60) {
		t.Fatal("the first holder did not get a free lease")
	}
	if take("two", 60) {
		t.Error("a second holder took a live lease")
	}
	if !take("one", 60) {
		t.Error("the holder could not renew its own lease")
	}
	r.env.Exec(t, `UPDATE ctrlz.leases SET expires_at = now() - interval '1 second' WHERE name = 'registration_sweep'`)
	if !take("two", 60) {
		t.Error("a lease that ran out was not taken")
	}
}

// A sweep that stops at its tenant bound is resumed after its last tenant by the next one, and the one after that starts over
// (p3-D3-r1-1, p3-D3-r1-5). Before, every run walked the same first tenants and the later ones were never swept.
func TestSweepResumesAfterItsBound(t *testing.T) {
	r := newRig(t, adminjobs.Config{SweepBudget: 1})
	r.mode("open")
	if p := r.sweep(); p.Tenants != 1 || p.Graced != 1 {
		t.Fatalf("the first run: %+v", p)
	}
	if got := r.states(); got["grace"] != 1 || got["active"] != 1 {
		t.Fatalf("after the first run: %v", got)
	}
	if p := r.sweep(); p.Tenants != 1 || p.Graced != 1 {
		t.Fatalf("the second run walked the first tenant again: %+v", p)
	}
	if got := r.states(); got["grace"] != 2 || got["active"] != 0 {
		t.Fatalf("after the second run: %v", got)
	}
	// The second run stopped at its bound on the last tenant, so the third finds the end of the list at once and wraps; the
	// fourth starts over at the first tenant, where nothing is left to change.
	if p := r.sweep(); p.Tenants != 0 {
		t.Fatalf("the third run: %+v", p)
	}
	if p := r.sweep(); p.Tenants != 1 || p.Graced != 0 {
		t.Fatalf("the fourth run: %+v", p)
	}
}

// The job is not bounded: it walks every tenant, so it never ends as done with tenants left.
func TestRegistrationJobIgnoresTheSweepBound(t *testing.T) {
	r := newRig(t, adminjobs.Config{SweepBudget: 1})
	r.mode("open")
	id := r.queue(adminjobs.KindRegistrationTransition, map[string]any{"from": "closed", "to": "open", "grace_days": 7})
	r.runOnce()
	if state, p := r.job(id); state != "done" || p["tenants"] != float64(2) || p["graced"] != float64(2) {
		t.Errorf("%s %v", state, p)
	}
}
