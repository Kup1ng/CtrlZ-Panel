package sweep_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/sweep"
)

// The per-tenant sweep runs each statement in its own transaction and in batches
// (review sms-r2-4). Two tenants, so the isolation shows. Before the fix the five
// statements shared one transaction: a DELETE that could not run (here the worker
// lost its right on the audit table, as a statement_timeout on a huge backlog
// would also fail it) rolled back the clear of the pending TOTP secret too, run
// after run, in every tenant.
func TestSlowTenantStepsAreBatchedAndOneFailingStepStopsNoOther(t *testing.T) {
	r := newRig(t)
	for _, ids := range []struct{ tenant, user uuid.UUID }{{r.env.A.Tenant, r.env.A.User}, {r.env.B.Tenant, r.env.B.User}} {
		r.env.Exec(t, `INSERT INTO ctrlz.sessions (tenant_id, user_id, token_hash, idle_expires_at, absolute_expires_at, last_seen_at)
SELECT $1, $2, convert_to(gen_random_uuid()::text, 'UTF8'), now() - interval '3 days', now() - interval '2 days', now() FROM generate_series(1, 7)`, ids.tenant, ids.user)
		r.env.Exec(t, `INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, at) VALUES ($1, $2, 'old', now() - interval '400 days')`, ids.tenant, ids.user)
		r.env.Exec(t, `UPDATE ctrlz.users SET totp_secret_ct = '\x01', totp_pending_at = now() - interval '16 minutes' WHERE id = $1`, ids.user)
	}
	r.env.Exec(t, `REVOKE DELETE ON ctrlz.tenant_audit_log FROM ctrlz_worker`)

	// A batch of 3 and enough batches: seven old sessions per tenant take three
	// statements each.
	res, err := r.sweeper(sweep.Config{Batch: 3, MaxBatches: 10}).Slow(r.env.Ctx)
	if err == nil || !errors.Is(err, store.ErrPermission) {
		t.Fatalf("the audit step that could not run was not reported: %v", err)
	}
	if res.Tenant.Sessions != 14 {
		t.Errorf("sessions deleted: %d, want 14 (seven in each tenant)", res.Tenant.Sessions)
	}
	if res.Tenant.PendingTOTP != 2 {
		t.Errorf("pending TOTP cleared: %d, want 2", res.Tenant.PendingTOTP)
	}
	for _, tenant := range []uuid.UUID{r.env.A.Tenant, r.env.B.Tenant} {
		if r.count(`SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND totp_secret_ct IS NOT NULL`, tenant) != 0 {
			t.Errorf("tenant %s: a pending TOTP secret survived another step's failure", tenant)
		}
		if r.count(`SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1 AND absolute_expires_at < now()`, tenant) != 0 {
			t.Errorf("tenant %s: expired sessions were rolled back", tenant)
		}
		if r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'old'`, tenant) != 1 {
			t.Errorf("tenant %s: the unsweepable table lost its row", tenant)
		}
	}
}

// A backlog is worked off by at most MaxBatches batches a run, and the next run
// takes the rest, in the tenant it belongs to and no other.
func TestSlowTenantBacklogIsBoundedPerRun(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `INSERT INTO ctrlz.sessions (tenant_id, user_id, token_hash, idle_expires_at, absolute_expires_at, last_seen_at)
SELECT $1, $2, convert_to(gen_random_uuid()::text, 'UTF8'), now() - interval '3 days', now() - interval '2 days', now() FROM generate_series(1, 25)`, r.env.A.Tenant, r.env.A.User)
	s := r.sweeper(sweep.Config{Batch: 10, MaxBatches: 2})
	bSessions := r.count(`SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1`, r.env.B.Tenant)
	for i, want := range []struct{ deleted, left int }{{20, 5}, {5, 0}} {
		res, err := s.Slow(r.env.Ctx)
		if err != nil {
			t.Fatal(err)
		}
		if res.Tenant.Sessions != want.deleted {
			t.Errorf("run %d deleted %d sessions, want %d", i+1, res.Tenant.Sessions, want.deleted)
		}
		if got := r.count(`SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1 AND absolute_expires_at < now()`, r.env.A.Tenant); got != want.left {
			t.Errorf("run %d left %d expired sessions, want %d", i+1, got, want.left)
		}
	}
	if got := r.count(`SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1`, r.env.B.Tenant); got != bSessions {
		t.Errorf("tenant B had %d sessions, now %d", bSessions, got)
	}
}

// After a long worker outage the fast sweep refunds a backlog of OTPs in bounded
// batches, one transaction each, instead of one transaction that holds row locks
// on the shared counters for as long as it takes (sms-r2-4).
func TestFastRefundsABacklogInBatches(t *testing.T) {
	r := newRig(t)
	total := store.OTPEndBatch*2 + 30
	r.env.Exec(t, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, created_at, ip)
SELECT '+9891211' || lpad(n::text, 5, '0'), 'login', '\x01', '\x02', now() - interval '1 minute', now() - interval '6 minutes', '198.51.100.9'
FROM generate_series(1, $1) n`, total)
	res, err := r.sweeper(sweep.Config{}).Fast(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpiredOTP != total {
		t.Errorf("refunded %d, want %d", res.ExpiredOTP, total)
	}
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE delivery_ct IS NOT NULL`) != 0 {
		t.Error("rows still hold a code")
	}
}
