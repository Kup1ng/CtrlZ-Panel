package catalogtest_test

import (
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The refund rule (rules.md topic 4, spec 5.3) is decided by the database, whatever the SQL text
// of any writer says: nothing ever lowers, moves or early-deletes a per-subject counter (phone,
// phone_net, ip), because the per-phone keys of a decoy are never given back and the 429 of the
// next request would tell a phone with an account from one without. Two mechanisms, each with
// its own tests: a trigger that judges every row for every role (migration 0035, sms-r8-6), and
// row-level security that shows the sender the global rows only (sms-r8-3, sms-r8-7).

const (
	cToday = `(now() AT TIME ZONE 'Asia/Tehran')::date`
	cOld   = cToday + ` - 5`
)

// seedCounters leaves one row of each kind: the three per-subject scopes today, an old
// per-subject row past the retention, and the global rows.
func (h *harness) seedCounters() {
	h.t.Helper()
	h.exec(`TRUNCATE ctrlz.sms_counters`)
	h.exec(testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES
	  (` + cToday + `, 'phone', 'p-today', 3),
	  (` + cToday + `, 'phone_net', 'n-today', 3),
	  (` + cToday + `, 'ip', 'i-today', 3),
	  (` + cToday + `, 'global', 'all', 3),
	  (` + cToday + `, 'global', 'outbox', 3),
	  (` + cOld + `, 'phone', 'p-old', 1),
	  (` + cOld + `, 'global', 'all', 1)`))
	// The day's spend, which the money cap is compared with (sms-r9-7).
	h.exec(`UPDATE ctrlz.sms_counters SET cost = 12.5 WHERE scope = 'global' AND key = 'all' AND day = ` + cToday)
}

// subjectRows is what the per-subject rows hold, as one string, for a before and after.
const subjectRows = `SELECT COALESCE(string_agg(scope || '|' || key || '|' || day || '|' || count, ',' ORDER BY scope, key, day), '')
  FROM ctrlz.sms_counters WHERE scope <> 'global'`

// The worker's own statements run; whatever else it writes, however it is spelled, leaves every
// per-subject row as it was. Most of these are refused by the policy without an error (the rows
// are not the worker's to see, so a statement finds none); the ones that reach a row it can see
// are refused by the trigger with 42501.
func TestTheWorkerRoleCannotWriteAPerPhoneCounterRow(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()
	var before string
	if err := h.super.QueryRow(h.ctx, subjectRows).Scan(&before); err != nil {
		t.Fatal(err)
	}

	type try struct {
		name string
		sql  string
		ok   bool // the statement is one the worker needs
		err  bool // the database must refuse it with an error (it reaches a row the worker can see, or writes one it may not)
	}
	for _, c := range []try{
		// What the worker does.
		{"the refund", `UPDATE ctrlz.sms_counters SET count = GREATEST(count - 1, 0) WHERE day = ` + cToday + ` AND scope = 'global' AND key = 'all'`, true, false},
		{"the cost", `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', 'all', 0, 5) ON CONFLICT (day, scope, key) DO UPDATE SET cost = c.cost + EXCLUDED.cost`, true, false},
		{"the outbox count", `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count) VALUES (` + cToday + `, 'global', 'outbox', 1) ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1`, true, false},
		// What a per-phone refund, however it is spelled, would do.
		{"a refund of a phone", `UPDATE ctrlz.sms_counters SET count = GREATEST(count - 1, 0) WHERE scope = 'phone' AND key = 'p-today'`, false, false},
		{"a refund of a network", `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'phone_net'`, false, false},
		{"a refund of an address", `UPDATE ctrlz.sms_counters SET count = 0 WHERE scope = 'ip'`, false, false},
		{"every row at once", `UPDATE ctrlz.sms_counters SET count = count - 1`, false, false},
		{"a phone row moved to a global one", `UPDATE ctrlz.sms_counters SET scope = 'global', key = 'all' WHERE key = 'p-today'`, false, false},
		{"a global row moved to a per-phone scope", `UPDATE ctrlz.sms_counters SET scope = 'phone' WHERE scope = 'global' AND key = 'outbox'`, false, true},
		{"a global row moved to another key", `UPDATE ctrlz.sms_counters SET key = 'x' WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false, true},
		{"a global row moved to another day", `UPDATE ctrlz.sms_counters SET day = day - 1 WHERE scope = 'global' AND key = 'outbox'`, false, true},
		{"a per-phone row made up", `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + cToday + `, 'phone', 'made-up', 1) ON CONFLICT (day, scope, key) DO UPDATE SET count = 1`, false, true},
		{"a per-phone row made up, over an existing one", `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + cToday + `, 'phone', 'p-today', 0) ON CONFLICT (day, scope, key) DO UPDATE SET count = 0`, false, true},
		{"a global row of another key made up", `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + cToday + `, 'global', 'phone', 1)`, false, true},
		// db-r10-1: a row is judged at birth, for any role, because it is the starting value every
		// later cap test adds to. The worker may create the two global keys, but only as a row that
		// could be a real first one.
		{"a global row planted for tomorrow", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + ` + 1, 'global', 'all', 0, 0)`, false, true},
		{"a global row planted for a year ahead", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + ` + 365, 'global', 'outbox', 0, 0)`, false, true},
		{"a global row planted in the past", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + ` - 1, 'global', 'all', 0, 0)`, false, true},
		{"a negative count for today", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', 'outbox', -2000000000, 0) ON CONFLICT (day, scope, key) DO UPDATE SET count = EXCLUDED.count`, false, true},
		{"a negative spend for today", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', 'all', 0, -9999999999) ON CONFLICT (day, scope, key) DO UPDATE SET cost = EXCLUDED.cost`, false, true},
		{"a row that starts above one", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', 'all', 2, 0) ON CONFLICT (day, scope, key) DO UPDATE SET count = EXCLUDED.count`, false, true},
		{"a negative count for a series of future days", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) SELECT ` + cToday + ` + g, 'global', k, -2000000000, -9999999999 FROM generate_series(1, 30) g, (VALUES ('all'), ('outbox')) v(k)`, false, true},
		{"a delete of today's phone row", `DELETE FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = 'p-today'`, false, true},
		{"a delete of an old phone row (the sweep is a function now)", `DELETE FROM ctrlz.sms_counters WHERE scope = 'phone' AND day = ` + cOld, false, true},
		{"a delete of a global row", `DELETE FROM ctrlz.sms_counters WHERE scope = 'global' AND day = ` + cOld, false, true},
		// A statement built at run time reads differently and ends the same.
		{"a refund built by EXECUTE", `DO $$ BEGIN EXECUTE 'UPDATE ctrlz.sms_' || 'counters SET count = count - 1 WHERE scope = ''phone'''; END $$`, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
				_, err := tx.Exec(h.ctx, c.sql)
				switch {
				case c.ok && err != nil:
					t.Errorf("the worker's own statement was refused: %v", err)
				case c.err && err == nil:
					t.Error("the worker wrote a row it may not")
				case err != nil && !c.ok:
					if pe := pgErr(err); pe == nil || pe.Code != "42501" {
						t.Errorf("want SQLSTATE 42501, got %v", err)
					}
				}
				if err != nil {
					return // the transaction is aborted; the error is the refusal
				}
				if _, err := tx.Exec(h.ctx, `RESET ROLE`); err != nil {
					t.Fatal(err)
				}
				var after string
				if err := tx.QueryRow(h.ctx, subjectRows).Scan(&after); err != nil {
					t.Fatal(err)
				}
				if after != before {
					t.Errorf("per-subject rows changed:\n before %s\n after  %s", before, after)
				}
			})
		})
	}
}

// The sender sees the global rows and nothing else, so the raw keys (a phone, the /24 an address
// asked from, whether it was a known device) are out of its reach even though it holds SELECT on
// the column for its own statements (sms-r8-3, sms-r8-7). This is the behavioural proof of
// guarded.yaml row_bound: seed rows outside the predicate, read as the role, find none.
func TestTheWorkerRoleSeesTheGlobalCounterRowsOnly(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()
	h.exec(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES
	  (` + cToday + `, 'phone', '+989121234567|trusted', 1),
	  (` + cToday + `, 'phone_net', '+989121234567|203.0.113.0/24', 1),
	  (` + cToday + `, 'ip', '203.0.113.0/24', 1)`)
	for _, q := range []struct{ name, sql string }{
		{"by scope", `SELECT count(*) FROM ctrlz.sms_counters WHERE scope <> 'global'`},
		{"by key", `SELECT count(*) FROM ctrlz.sms_counters WHERE key LIKE '+98%' OR key LIKE '203.%' OR key LIKE 'p-%'`},
		{"by a subquery over the keys", `SELECT count(*) FROM ctrlz.sms_counters WHERE key IN (SELECT key FROM ctrlz.sms_counters WHERE scope = 'phone')`},
		{"by a join with itself", `SELECT count(*) FROM ctrlz.sms_counters a JOIN ctrlz.sms_counters b USING (key) WHERE a.scope <> 'global'`},
	} {
		t.Run(q.name, func(t *testing.T) {
			h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
				var n int
				if err := tx.QueryRow(h.ctx, q.sql).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Errorf("the worker saw %d per-subject rows", n)
				}
			})
		})
	}
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.sms_counters WHERE scope = 'global'`).Scan(&n); err != nil || n != 3 {
			t.Errorf("the worker sees %d global rows (%v), want the 3 it counts with", n, err)
		}
	})
	// The one role that issues codes and sweeps sees every row.
	h.inTx(h.super, "auth", nil, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.sms_counters`).Scan(&n); err != nil || n != 10 {
			t.Errorf("ctrlz_auth sees %d rows (%v), want 10", n, err)
		}
	})
	// A role with no grant reads nothing and may not try.
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, `SELECT count(*) FROM ctrlz.sms_counters`); pgErr(err) == nil || pgErr(err).Code != "42501" {
			t.Errorf("the admin role read sms_counters: %v", err)
		}
	})
}

// The invariant does not depend on the writer (sms-r8-6): the trigger judges the row for every
// role. The superuser and ctrlz_auth are refused alike; an increment, a new row and the delete
// of a row past its retention pass.
func TestNoRoleCanLowerMoveOrEarlyDeleteAPerSubjectCounter(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()
	for _, role := range []string{"", "auth"} { // "" is the superuser session itself
		who := role
		if who == "" {
			who = "superuser"
		}
		for _, c := range []struct {
			name, sql string
			ok        bool
		}{
			{"a decrement of a phone", `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'phone' AND key = 'p-today'`, false},
			{"a reset to zero of a network", `UPDATE ctrlz.sms_counters SET count = 0 WHERE scope = 'phone_net'`, false},
			{"a decrement of an address", `UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'ip'`, false},
			{"a decrement of an old row", `UPDATE ctrlz.sms_counters SET count = 0 WHERE scope = 'phone' AND key = 'p-old'`, false},
			{"a row moved to another key", `UPDATE ctrlz.sms_counters SET key = 'other' WHERE scope = 'phone' AND key = 'p-today'`, false},
			{"a row moved to another day", `UPDATE ctrlz.sms_counters SET day = day - 1 WHERE scope = 'ip'`, false},
			{"a row moved to the global scope", `UPDATE ctrlz.sms_counters SET scope = 'global', key = 'moved' WHERE scope = 'phone' AND key = 'p-today'`, false},
			{"a global row moved to a per-phone scope", `UPDATE ctrlz.sms_counters SET scope = 'phone', key = 'moved' WHERE scope = 'global' AND key = 'outbox'`, false},
			{"an upsert that lowers", `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + cToday + `, 'phone', 'p-today', 0) ON CONFLICT (day, scope, key) DO UPDATE SET count = EXCLUDED.count`, false},
			{"a delete of today's row", `DELETE FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = 'p-today'`, false},
			{"a delete of every per-subject row", `DELETE FROM ctrlz.sms_counters WHERE scope <> 'global'`, false},
			// The global rows are what otp_cap_global and sms_cost_cap_daily are compared with, and
			// they were judged by the name of the role (sms-r9-7): every role is held to the same
			// invariant now, so none of these resets a cap.
			{"a delete of today's global row", `DELETE FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false},
			{"a delete of every global row of today", `DELETE FROM ctrlz.sms_counters WHERE scope = 'global' AND day = ` + cToday, false},
			{"a global count reset to zero", `UPDATE ctrlz.sms_counters SET count = 0 WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false},
			{"a global count given back two at once", `UPDATE ctrlz.sms_counters SET count = count - 2 WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false},
			{"a global spend reset to zero", `UPDATE ctrlz.sms_counters SET cost = 0 WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false},
			{"a global spend lowered", `UPDATE ctrlz.sms_counters SET cost = cost - 0.0001 WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false},
			{"a global row moved to another key", `UPDATE ctrlz.sms_counters SET key = 'all2' WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false},
			{"a global row moved to another day", `UPDATE ctrlz.sms_counters SET day = day - 3 WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, false},
			{"an upsert that resets the global count", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + cToday + `, 'global', 'all', 0, 0) ON CONFLICT (day, scope, key) DO UPDATE SET count = EXCLUDED.count, cost = EXCLUDED.cost`, false},
			// What the issue function does, and what the sweep does.
			{"an increment", `UPDATE ctrlz.sms_counters SET count = count + 1 WHERE scope = 'phone' AND key = 'p-today'`, true},
			{"an upsert that raises", `INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count) VALUES (` + cToday + `, 'phone', 'p-today', 1) ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1`, true},
			{"a new key", `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + cToday + `, 'phone', 'new', 1)`, true},
			{"a delete past the retention", `DELETE FROM ctrlz.sms_counters WHERE scope = 'phone' AND day = ` + cOld, true},
			{"a global refund of one", `UPDATE ctrlz.sms_counters SET count = GREATEST(count - 1, 0) WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, true},
			{"a global increment and a spend", `UPDATE ctrlz.sms_counters SET count = count + 1, cost = cost + 7 WHERE scope = 'global' AND key = 'all' AND day = ` + cToday, true},
			{"a delete of a global row past the retention", `DELETE FROM ctrlz.sms_counters WHERE scope = 'global' AND day = ` + cOld, true},
		} {
			t.Run(who+" "+c.name, func(t *testing.T) {
				tx, err := h.super.Begin(h.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(h.ctx)
				if role != "" {
					if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_`+role); err != nil {
						t.Fatal(err)
					}
				}
				_, err = tx.Exec(h.ctx, c.sql)
				switch {
				case c.ok && err != nil:
					t.Errorf("refused: %v", err)
				case !c.ok && err == nil:
					t.Error("the row was written")
				case !c.ok:
					if pe := pgErr(err); pe == nil || pe.Code != "42501" {
						t.Errorf("want SQLSTATE 42501, got %v", err)
					}
				}
			})
		}
	}
}

// The scenario of sms-r8-6: a definer function of ctrlz_auth, added later by someone who did not
// know the rule, that gives a phone slot back. The exemption list of migration 0034 let it
// through (current_user was ctrlz_auth, not ctrlz_worker).
func TestADefinerFunctionOfTheAuthRoleCannotGiveAPhoneSlotBack(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(h.ctx)
	for _, s := range []string{
		`CREATE FUNCTION ctrlz_fn.tmp_cancel_login() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
		   AS $$ UPDATE ctrlz.sms_counters SET count = count - 1 WHERE scope = 'phone' AND key = 'p-today' $$`,
		`ALTER FUNCTION ctrlz_fn.tmp_cancel_login() OWNER TO ctrlz_auth`,
	} {
		if _, err := tx.Exec(h.ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	_, err = tx.Exec(h.ctx, `SELECT ctrlz_fn.tmp_cancel_login()`)
	if pe := pgErr(err); pe == nil || pe.Code != "42501" {
		t.Fatalf("a definer function of ctrlz_auth lowered a phone counter: %v", err)
	}
}

// The retention sweep of the per-subject rows is a function of ctrlz_fn that the worker runs: it
// deletes the rows past the retention, at most the batch, and nothing else.
func TestTheCounterSweepFunctionDeletesOnlyWhatIsPastItsRetention(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()
	h.exec(testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES
	  (` + cOld + `, 'phone_net', 'n-old', 1), (` + cOld + `, 'ip', 'i-old', 1), (` + cToday + ` - 3, 'ip', 'i-3', 1), (` + cToday + ` - 2, 'ip', 'i-2', 1)`))
	count := func(tx pgx.Tx, where string) int {
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.sms_counters WHERE `+where).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		// Four rows are past the retention (the two-day-old row is not): the old phone, network and
		// address rows and the one of three days ago.
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_sms_counters(2)`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("a batch of 2 deleted %d (%v)", n, err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_sms_counters(100)`).Scan(&n); err != nil || n != 2 {
			t.Fatalf("the rest deleted %d (%v), want the other 2 old rows", n, err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_sms_counters(0)`).Scan(&n); err != nil || n != 0 {
			t.Errorf("a batch of 0 deleted %d (%v)", n, err)
		}
		if _, err := tx.Exec(h.ctx, `RESET ROLE`); err != nil {
			t.Fatal(err)
		}
		if got := count(tx, `scope <> 'global' AND day < `+cToday+` - 2`); got != 0 {
			t.Errorf("%d per-subject rows past the retention are left", got)
		}
		if got := count(tx, `scope <> 'global' AND day >= `+cToday+` - 2`); got != 4 {
			t.Errorf("%d per-subject rows inside the retention are left, want the 3 of today and the two-day-old one (4)", got)
		}
		if got := count(tx, `scope = 'global'`); got != 3 {
			t.Errorf("%d global rows are left, want all 3 (a global row of an old day is not swept)", got)
		}
	})
	// The admin role may not run it.
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		_, err := tx.Exec(h.ctx, `SELECT ctrlz_fn.worker_sweep_sms_counters(1)`)
		if pe := pgErr(err); pe == nil || pe.Code != "42501" {
			t.Errorf("the admin role ran the sweep: %v", err)
		}
	})
}

// The sender takes the phone it sends to from the code row or the outbox row and reads nothing
// of users: a worker that could list them (the role names any tenant in its setting and no
// policy bounds it) would hold every tenant's phone numbers (sms-r7-4).
func TestTheWorkerRoleCannotReadTheUsersTable(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, col := range []string{"phone_e164", "id", "locale", "tenant_id"} {
		t.Run(col, func(t *testing.T) {
			h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
				_, err := tx.Exec(h.ctx, `SELECT `+col+` FROM ctrlz.users`)
				if pe := pgErr(err); pe == nil || pe.Code != "42501" {
					t.Errorf("the worker read users.%s: %v", col, err)
				}
			})
		})
	}
}

// The scenario of sms-r9-7: a definer function of ctrlz_auth, added later, that tidies today's
// counters or resets the day's spend. The guard of 0035 judged the global rows by role name and
// let every role but the worker through, so the daily global cap and the money cap were reset
// whenever such a function ran. The guard of 0038 judges the row, whoever writes it.
func TestADefinerFunctionOfTheAuthRoleCannotResetTheGlobalCaps(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()
	for name, body := range map[string]string{
		"deletes today's global rows": `DELETE FROM ctrlz.sms_counters WHERE scope = 'global' AND day = ` + cToday,
		"zeroes the spend":            `UPDATE ctrlz.sms_counters SET cost = 0, count = 0 WHERE scope = 'global' AND day = ` + cToday,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(h.ctx)
			for _, s := range []string{
				`CREATE FUNCTION ctrlz_fn.tmp_reset_today() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ ` + body + ` $$`,
				`ALTER FUNCTION ctrlz_fn.tmp_reset_today() OWNER TO ctrlz_auth`,
			} {
				if _, err := tx.Exec(h.ctx, s); err != nil {
					t.Fatalf("%s: %v", s, err)
				}
			}
			_, err = tx.Exec(h.ctx, `SELECT ctrlz_fn.tmp_reset_today()`)
			if pe := pgErr(err); pe == nil || pe.Code != "42501" {
				t.Fatalf("a definer function of ctrlz_auth reset the global counters: %v", err)
			}
		})
	}
}

// db-r10-1: the guard of 0038 judged no value of a NEW row, so a global row made in advance (a
// future day, a negative count, a negative spend) was the starting value that auth_otp_issue and
// both outbox gates later added to and compared with cap_reached: the daily OTP cap and the money
// cap were off for that day, and the retention sweep leaves the global rows, so it stayed. A new
// row is now judged for every role: today's Tehran day, a count of zero or one, a spend of zero or
// more. The role is each writer there is: the sender (whose scope and key limit stays as the
// second line), a SECURITY DEFINER function of ctrlz_auth, the migrator that owns the table and
// the superuser.
func TestNoRoleCanPlantACounterRowThatSwitchesACapOff(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedCounters()
	plant := func(day, scope, key, count, cost string) string {
		return `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES (` + day + `, '` + scope + `', '` + key + `', ` + count + `, ` + cost + `)`
	}
	type try struct {
		name, sql string
		ok        bool
	}
	// The statements are the same for every role; only the key differs where a role may not write
	// a per-subject row at all.
	build := func(scope, key string, worker bool) []try {
		// The sender may create only the keys all and outbox, so its cases cannot carry a suffix; the
		// guard runs before a conflict is looked at, so the rows that must pass say DO NOTHING.
		sub := func(s string) string {
			if worker {
				return key
			}
			return key + s
		}
		doNothing := ` ON CONFLICT (day, scope, key) DO NOTHING`
		return []try{
			{"tomorrow", plant(cToday+` + 1`, scope, key, "0", "0"), false},
			{"tomorrow with a negative count", plant(cToday+` + 1`, scope, key, "-2000000000", "-9999999999"), false},
			{"a year ahead", plant(cToday+` + 365`, scope, key, "0", "0"), false},
			{"ten years ahead", plant(cToday+` + 3650`, scope, key, "0", "0"), false},
			{"yesterday", plant(cToday+` - 1`, scope, key, "0", "0"), false},
			{"today with a negative count", plant(cToday, scope, sub("-n"), "-1", "0"), false},
			{"today with a negative spend", plant(cToday, scope, sub("-c"), "0", "-0.0001"), false},
			{"today starting above one", plant(cToday, scope, sub("-two"), "2", "0"), false},
			{"today starting far above one", plant(cToday, scope, sub("-big"), "1000000", "0"), false},
			{"a series of future days", `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) SELECT ` + cToday + ` + g, '` + scope + `', '` + key + `', -2000000000, -9999999999 FROM generate_series(1, 3650) g`, false},
			{"an upsert whose proposed row is planted", plant(cToday+` + 1`, scope, key, "-5", "0") + ` ON CONFLICT (day, scope, key) DO UPDATE SET count = EXCLUDED.count`, false},
			// What the issue function and the sender do: a first row of today.
			{"a first row of today", plant(cToday, scope, sub("-first"), "1", "0") + doNothing, true},
			{"a spend row of today with no count", plant(cToday, scope, sub("-spend"), "0", "7.5") + doNothing, true},
		}
	}
	for _, role := range []string{"worker", "auth", "migrator", ""} {
		who := role
		if who == "" {
			who = "superuser"
		}
		scope, key := "phone", "+989120000000"
		if role == "worker" {
			scope, key = "global", "all" // the only rows the sender may create
		}
		for _, c := range build(scope, key, role == "worker") {
			t.Run(who+" "+c.name, func(t *testing.T) {
				tx, err := h.super.Begin(h.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(h.ctx)
				if role != "" {
					if _, err := tx.Exec(h.ctx, `SET LOCAL ROLE ctrlz_`+role); err != nil {
						t.Fatal(err)
					}
				}
				_, err = tx.Exec(h.ctx, c.sql)
				switch {
				case c.ok && err != nil:
					t.Errorf("a row a real writer makes was refused: %v", err)
				case !c.ok && err == nil:
					t.Error("a planted row was written")
				case !c.ok:
					if pe := pgErr(err); pe == nil || pe.Code != "42501" {
						t.Errorf("want SQLSTATE 42501 from the guard, got %v", err)
					}
				}
			})
		}
	}
	// A planted row under a definer function of ctrlz_auth, the shape of sms-r8-6 and sms-r9-7.
	for name, body := range map[string]string{
		"plants a future day":      plant(cToday+` + 1`, "global", "all", "0", "0"),
		"plants a negative count":  plant(cToday, "global", "all", "-2000000000", "0") + ` ON CONFLICT (day, scope, key) DO UPDATE SET count = EXCLUDED.count`,
		"plants a negative spend":  plant(cToday, "global", "all", "0", "-9999999999") + ` ON CONFLICT (day, scope, key) DO UPDATE SET cost = EXCLUDED.cost`,
		"plants a phone for later": plant(cToday+` + 1`, "phone", "+989121234567", "-9", "0"),
	} {
		t.Run("a definer function of ctrlz_auth that "+name, func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(h.ctx)
			for _, s := range []string{
				`CREATE FUNCTION ctrlz_fn.tmp_plant() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$ ` + body + ` $$`,
				`ALTER FUNCTION ctrlz_fn.tmp_plant() OWNER TO ctrlz_auth`,
			} {
				if _, err := tx.Exec(h.ctx, s); err != nil {
					t.Fatalf("%s: %v", s, err)
				}
			}
			if _, err := tx.Exec(h.ctx, `SELECT ctrlz_fn.tmp_plant()`); pgErr(err) == nil || pgErr(err).Code != "42501" {
				t.Fatalf("a definer function of ctrlz_auth planted a counter row: %v", err)
			}
		})
	}
}

// The second line (db-r10-1): a CHECK holds for every writer, the superuser included, and it fires
// after the trigger, so it is what is left when the trigger is switched off or replaced. Under
// session_replication_role = replica the trigger does not fire and only the constraint stands.
func TestCounterColumnsRefuseANegativeValueWhenTheGuardDoesNotRun(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, c := range []struct{ name, sql string }{
		{"a negative count", `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + cToday + `, 'global', 'all', -1)`},
		{"a negative spend", `INSERT INTO ctrlz.sms_counters (day, scope, key, cost) VALUES (` + cToday + `, 'global', 'all', -0.0001)`},
		{"a negative count for a future day", `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + cToday + ` + 1, 'global', 'all', -2000000000)`},
		{"a negative throttle count", `INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES ('login_phone', '\x0000000000000000000000000000000000000000000000000000000000000001', now(), -5)`},
	} {
		t.Run(c.name, func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(h.ctx)
			if _, err := tx.Exec(h.ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(h.ctx, c.sql); pgErr(err) == nil || pgErr(err).Code != "23514" {
				t.Fatalf("want SQLSTATE 23514 (check_violation), got %v", err)
			}
		})
	}
	// The migration cleans what already breaks the lines: it is exercised on the real schema by
	// the migrated database being clean, and a row a real writer makes is never refused (the two
	// control cases of TestNoRoleCanPlantACounterRowThatSwitchesACapOff).
}
