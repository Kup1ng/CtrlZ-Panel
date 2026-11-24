package catalogtest_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Review round 4, db-r4-3, db-r4-6 and db-r4-7. ctrlz_worker is the long-running
// SMS sender: it opens delivery_ct, so it reads every login code. Anything it can do
// to a second factor, or to the notice and audit row that a switch-off leaves, is
// therefore a way into any account. It must not be able to
//   - read or write the TOTP seed column, switch Enforce Passkey off, or end a
//     user's passkeys, with a plain statement;
//   - call the function that declares a user key lost (that is the key tool's, with
//     a login whose password the worker does not hold);
//   - delete a notice, or an audit row younger than the retention.
//
// The key tool in turn reaches the seeds and nothing else.
func TestWorkerCannotReachASecondFactorOrItsTrail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	aGUC := h.A.Tenant.String()
	for _, c := range []struct{ role, sql string }{
		{"worker", `UPDATE ctrlz.users SET enforce_passkey = false`},
		{"worker", `SELECT enforce_passkey FROM ctrlz.users`},
		{"worker", `SELECT totp_secret_ct FROM ctrlz.users`},
		{"worker", `UPDATE ctrlz.users SET totp_enabled_at = NULL`},
		{"worker", `UPDATE ctrlz.webauthn_credentials SET stale_at = now()`},
		{"worker", `SELECT 1 FROM ctrlz.webauthn_credentials`},
		{"worker", `SELECT ctrlz_fn.keytool_totp_declare_lost(1, ARRAY[gen_random_uuid()], ARRAY['\x435a010001'::bytea])`},
		{"worker", `DELETE FROM ctrlz.notifications`},
		{"keytool", `UPDATE ctrlz.users SET enforce_passkey = false`},
		{"keytool", `UPDATE ctrlz.users SET totp_enabled_at = NULL`},
		{"keytool", `UPDATE ctrlz.users SET password_hash = 'x'`},
		{"keytool", `SELECT password_hash FROM ctrlz.users`},
		{"keytool", `DELETE FROM ctrlz.notifications`},
		{"keytool", `INSERT INTO ctrlz.notifications (tenant_id, kind) VALUES (gen_random_uuid(), 'x')`},
		{"keytool", `DELETE FROM ctrlz.tenant_audit_log`},
		{"keytool", `SELECT 1 FROM ctrlz.otp_challenges`},
		{"keytool", `SELECT 1 FROM ctrlz.sessions`},
		{"keytool", `UPDATE ctrlz.webauthn_credentials SET stale_at = now()`},
	} {
		if !h.denied(c.role, &aGUC, c.sql) {
			t.Errorf("%s could run %.80q", c.role, c.sql)
		}
	}
	// The sweep of unconfirmed secrets is a function since 0020 (role-reach); the
	// statement it replaces is refused (TestWorkerPendingSweepClearsOnlyUnconfirmedSetups).
	if !h.denied("worker", &aGUC, `UPDATE ctrlz.users SET totp_secret_ct = NULL, totp_pending_at = NULL WHERE totp_enabled_at IS NULL`) {
		t.Error("the worker can still clear a seed with a plain statement")
	}

	// The trail: a fresh notice and a fresh audit row of a switch-off survive a
	// worker's DELETE under the tenant's own setting, and an old audit row does not.
	h.exec(`INSERT INTO ctrlz.notifications (tenant_id, kind, severity) VALUES ($1, 'totp_lost', 'warning')`, h.A.Tenant)
	h.exec(`INSERT INTO ctrlz.tenant_audit_log (tenant_id, action) VALUES ($1, 'totp.declared_lost')`, h.A.Tenant)
	h.exec(`INSERT INTO ctrlz.tenant_audit_log (tenant_id, action, at) VALUES ($1, 'old.row', now() - interval '400 days')`, h.A.Tenant)
	h.inTx(h.super, "worker", &aGUC, func(tx pgx.Tx) {
		tag, err := tx.Exec(h.ctx, `DELETE FROM ctrlz.tenant_audit_log`)
		if err != nil {
			t.Fatal(err)
		}
		// The seeded login row and the switch-off row are young; only the old one goes.
		if tag.RowsAffected() != 1 {
			t.Errorf("the worker deleted %d audit rows, want only the one past the retention", tag.RowsAffected())
		}
		asSuper(h, tx, "worker", func() {
			if n, err := count(h.ctx, tx, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'totp.declared_lost'`); err != nil || n != 1 {
				t.Errorf("the fresh audit row: %d rows (err %v), want it kept", n, err)
			}
			if n, err := count(h.ctx, tx, `SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost'`); err != nil || n != 1 {
				t.Errorf("the fresh notice: %d rows (err %v), want it kept", n, err)
			}
		})
	})
}

// Review round 4, db-r4-7. The RP ID job's two statements are functions that act
// for the RP ID in force. A caller that names another one, or has no tenant, changes
// nothing; the real one marks only credentials of another RP ID stale, clears
// Enforce Passkey only for users left with no live credential, tells the tenant, and
// touches no other tenant.
func TestRPIDJobFunctionsActForTheRPIDInForceOnly(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	aGUC, bGUC := h.A.Tenant.String(), h.B.Tenant.String()
	const rp = "panel.localhost"
	h.exec(`UPDATE ctrlz.webauthn_config SET rp_id = $1`, rp)
	h.exec(`UPDATE ctrlz.users SET enforce_passkey = true`)
	// B's user also holds a credential of the RP ID in force.
	h.exec(`INSERT INTO ctrlz.webauthn_credentials (tenant_id, user_id, credential_id, public_key, rp_id) VALUES ($1, $2, '\x0b0b', '\x01', $3)`, h.B.Tenant, h.B.User, rp)

	one := func(sql string, args ...any) (n int) {
		if err := h.super.QueryRow(h.ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return
	}
	live := func(tenant uuid.UUID) int {
		return one(`SELECT count(*) FROM ctrlz.webauthn_credentials WHERE tenant_id = $1 AND stale_at IS NULL`, tenant)
	}
	enforced := func(tenant uuid.UUID) int {
		return one(`SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND enforce_passkey`, tenant)
	}
	// run calls a function as the worker in its own committed transaction.
	run := func(guc *string, sql string, arg any) (n int) {
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(h.ctx)
		if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_worker`); err != nil {
			t.Fatal(err)
		}
		if guc != nil {
			if _, err := tx.Exec(h.ctx, `SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)`, *guc); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.QueryRow(h.ctx, sql, arg).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		if _, err := tx.Exec(h.ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(h.ctx); err != nil {
			t.Fatal(err)
		}
		return
	}
	const mark = `SELECT count(*)::int FROM ctrlz_fn.worker_passkeys_mark_stale($1)`
	const clear = `SELECT ctrlz_fn.worker_enforce_clear_without_live($1)`

	// Another RP ID, none, or no tenant: nothing happens.
	for _, c := range []struct {
		guc *string
		arg any
	}{{&aGUC, "evil.example"}, {&aGUC, ""}, {&aGUC, nil}, {nil, rp}} {
		if n := run(c.guc, mark, c.arg); n != 0 {
			t.Errorf("mark_stale(%v) with guc %v marked %d users", c.arg, c.guc != nil, n)
		}
		if n := run(c.guc, clear, c.arg); n != 0 {
			t.Errorf("enforce_clear(%v) with guc %v cleared %d users", c.arg, c.guc != nil, n)
		}
	}
	if live(h.A.Tenant) != 1 || live(h.B.Tenant) != 2 || enforced(h.A.Tenant) != 1 || enforced(h.B.Tenant) != 1 {
		t.Fatalf("a refused call changed something: live A %d B %d, enforced A %d B %d", live(h.A.Tenant), live(h.B.Tenant), enforced(h.A.Tenant), enforced(h.B.Tenant))
	}

	// The RP ID in force, tenant A: its only credential is of another RP ID.
	if n := run(&aGUC, mark, rp); n != 1 {
		t.Errorf("A: mark_stale marked %d users, want 1", n)
	}
	if n := run(&aGUC, mark, rp); n != 0 {
		t.Errorf("A: a second mark_stale marked %d users, want 0", n)
	}
	if live(h.A.Tenant) != 0 || live(h.B.Tenant) != 2 {
		t.Errorf("after A's job: live A %d (want 0), B %d (want 2, untouched)", live(h.A.Tenant), live(h.B.Tenant))
	}
	if n := run(&aGUC, clear, rp); n != 1 {
		t.Errorf("A: enforce_clear cleared %d users, want 1", n)
	}
	if n := run(&aGUC, clear, rp); n != 0 {
		t.Errorf("A: a second enforce_clear cleared %d users, want 0", n)
	}
	if enforced(h.A.Tenant) != 0 || enforced(h.B.Tenant) != 1 {
		t.Errorf("enforce_passkey after A's job: A %d (want 0), B %d (want 1)", enforced(h.A.Tenant), enforced(h.B.Tenant))
	}

	// Tenant B keeps a live credential of the RP ID in force, so its flag stays.
	if n := run(&bGUC, mark, rp); n != 1 {
		t.Errorf("B: mark_stale marked %d users, want 1 (its old credential)", n)
	}
	if n := run(&bGUC, clear, rp); n != 0 || enforced(h.B.Tenant) != 1 {
		t.Errorf("B: enforce_clear cleared %d users, enforced now %d; a live credential protects the flag", n, enforced(h.B.Tenant))
	}

	// The clear is not silent, and writes to the tenant it ran for only.
	for _, c := range []struct {
		tenant         uuid.UUID
		notices, audit int
	}{{h.A.Tenant, 1, 1}, {h.B.Tenant, 0, 0}} {
		if n := one(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'passkey_enforce_cleared'`, c.tenant); n != c.notices {
			t.Errorf("tenant %s: %d notices, want %d", c.tenant, n, c.notices)
		}
		if n := one(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'passkey.enforce_cleared'`, c.tenant); n != c.audit {
			t.Errorf("tenant %s: %d audit rows, want %d", c.tenant, n, c.audit)
		}
	}
}

// Review round 4, db-r4-8. The sweeps of auth_throttle and auth_tickets are
// functions: the worker holds no grant on either table, so it cannot empty the
// admin login throttle between guesses or delete a live ticket, and the functions
// delete only what the sweeps always deleted.
func TestWorkerSweepsCannotTouchLiveThrottlesOrTickets(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, sql := range []string{
		`DELETE FROM ctrlz.auth_throttle`, `SELECT scope FROM ctrlz.auth_throttle`,
		`DELETE FROM ctrlz.auth_tickets`, `SELECT id FROM ctrlz.auth_tickets`,
	} {
		if !h.denied("worker", nil, sql) {
			t.Errorf("ctrlz_worker could run %q", sql)
		}
	}
	h.exec(`INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES ('admin_login', decode(repeat('0a', 32), 'hex'), now(), 3)`)
	h.exec(`INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES ('admin_totp', decode(repeat('0b', 32), 'hex'), now() - interval '2 days', 3)`)
	h.exec(`INSERT INTO ctrlz.auth_tickets (token_hash, kind, created_at, expires_at) VALUES (decode(repeat('0c', 32), 'hex'), 'mfa', now() - interval '1 hour', now() - interval '55 minutes')`)
	var throttle, tickets int
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_throttle(100)`).Scan(&throttle); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_tickets(100)`).Scan(&tickets); err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{`SELECT ctrlz_fn.worker_sweep_throttle(0)`, `SELECT ctrlz_fn.worker_sweep_tickets(NULL)`} {
			var n int
			if err := tx.QueryRow(h.ctx, bad).Scan(&n); err != nil || n != 0 {
				t.Errorf("%s = %d (err %v), want 0", bad, n, err)
			}
		}
		asSuper(h, tx, "worker", func() {
			var left int
			if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.auth_throttle WHERE scope IN ('admin_login', 'login_net')`).Scan(&left); err != nil || left != 2 {
				t.Errorf("fresh throttle rows left: %d (err %v), want 2", left, err)
			}
			if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.auth_tickets WHERE kind = 'mfa' AND expires_at > now()`).Scan(&left); err != nil || left != 1 {
				t.Errorf("the live ticket: %d rows left (err %v), want 1", left, err)
			}
		})
	})
	if throttle != 1 || tickets != 1 {
		t.Errorf("swept %d throttle rows and %d tickets, want 1 and 1", throttle, tickets)
	}
}

// Review round 4, db-r4-4 and db-r4-9. sms_counters keys the per-phone,
// per-network and per-address rows by raw numbers and networks, decoys included
// (spec 9.5). ctrlz_admin has no grant on the table; its statistics come from a
// function that returns the global rows only.
func TestAdminSeesGlobalSMSCountersOnly(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, sql := range []string{`SELECT key FROM ctrlz.sms_counters`, `SELECT day FROM ctrlz.sms_counters`} {
		if !h.denied("admin", nil, sql) {
			t.Errorf("ctrlz_admin could run %q", sql)
		}
	}
	h.exec(testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 7, 70)`))
	h.exec(testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'phone', '+989121112233', 2), ((now() AT TIME ZONE 'Asia/Tehran')::date, 'ip', '203.0.113.9', 2)`))
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		rows, err := tx.Query(h.ctx, `SELECT day::text, sent, outbox, cost FROM ctrlz_fn.admin_sms_stats(3)`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var day, cost string
			var sent, outbox int
			if err := rows.Scan(&day, &sent, &outbox, &cost); err != nil {
				t.Fatal(err)
			}
			n++
			if sent != 7 || outbox != 0 || !strings.HasPrefix(cost, "70") {
				t.Errorf("day %s: sent %d outbox %d cost %s, want the global row only: 7, 0, 70", day, sent, outbox, cost)
			}
		}
		if n != 1 {
			t.Errorf("%d days, want 1", n)
		}
	})
}

// Review round 4, db-r4-1. Taking the user's row lock must not conflict with the
// FOR KEY SHARE that an insert into sessions or refresh_tokens takes on the same
// row through its foreign key, or a writer that holds the user and a refresh that
// holds the session wait for each other. The admin's lock function is the one in
// the database; store.qUserLock is the same lock and is run by the session tests.
func TestOneTimeLockDoesNotBlockAKeyShare(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	aGUC := h.A.Tenant.String()
	other := h.fresh()
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz_fn.admin_one_time_state($1)`, h.A.User).Scan(&n); err != nil || n != 1 {
			t.Fatalf("admin_one_time_state: %d rows, err %v", n, err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz_fn.admin_reissue_one_time_password($1, 'x')`, h.A.User).Scan(&n); err != nil {
			t.Fatal(err)
		}
		// A second session, with the user row locked by the first.
		tx2, err := other.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx2.Rollback(h.ctx)
		if _, err := tx2.Exec(h.ctx, `SET LOCAL lock_timeout = '2s'`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx2.Exec(h.ctx, `SELECT 1 FROM ctrlz.users WHERE id = $1 FOR KEY SHARE`, h.A.User); err != nil {
			t.Errorf("FOR KEY SHARE waited for the one-time password lock: %v", err)
		}
		// The lock still excludes another writer.
		_, err = tx2.Exec(h.ctx, `SELECT 1 FROM ctrlz.users WHERE id = $1 FOR NO KEY UPDATE`, h.A.User)
		if pe := pgErr(err); pe == nil || pe.Code != "55P03" {
			t.Errorf("a second FOR NO KEY UPDATE got %v, want a lock timeout: the lock must still exclude writers", err)
		}
	})
}

// ownDeletable is how many of a tenant's seeded rows a role may delete under the
// tenant's own setting. The seed is young, and the worker may delete audit rows only
// past the retention (policy worker_retention, db-r4-6), so it removes none of them.
func ownDeletable(table, role string, own int) int {
	if table == "tenant_audit_log" && role == "worker" {
		return 0
	}
	return own
}
