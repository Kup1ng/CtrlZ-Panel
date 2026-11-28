package catalogtest_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// P1 auth review round 9, database area (db-r9-3).

const (
	decoyPhone = "+989120000777" // no account: auth_otp_issue stores a row with no sealed code
	realPhone  = "+989121110001" // a code was sealed for it
)

// seedChallenges leaves two decoys (an unknown phone, as login and as phone_new) and one challenge
// with a sealed code in otp_challenges.
func (h *harness) seedChallenges() {
	h.t.Helper()
	h.exec(`DELETE FROM ctrlz.otp_challenges`)
	h.exec(`INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip) VALUES
	  ('` + decoyPhone + `', 'login', '\x01', NULL, now() + interval '5 minutes', '203.0.113.9'),
	  ('` + decoyPhone + `', 'phone_new', '\x01', NULL, now() + interval '5 minutes', '203.0.113.9'),
	  ('` + realPhone + `', 'login', '\x01', '\x0a', now() + interval '5 minutes', '203.0.113.9')`)
}

// TestTheWorkerRoleSeesNoDecoyChallenge is db-r9-3. Round 8 hid the raw counter keys from the
// sender "because a number with no account has no other trace", and it had one: the decoy row of
// otp_challenges, with the phone and the purpose and no sealed code. A row of purpose login or
// reset with no code says "this number has no account"; a phone_new one says it belongs to
// someone else. The sender's statements touch only rows that carry a sealed code, so it sees
// those and no other, through every way a query can reach a row.
func TestTheWorkerRoleSeesNoDecoyChallenge(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedChallenges()
	for _, q := range []struct{ name, sql string }{
		{"by phone", `SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = '` + decoyPhone + `'`},
		{"by the absence of a sealed code", `SELECT count(*) FROM ctrlz.otp_challenges WHERE delivery_ct IS NULL`},
		{"by purpose and attempts", `SELECT count(*) FROM ctrlz.otp_challenges WHERE purpose IN ('login', 'reset', 'phone_new') AND delivery_attempts = 0 AND delivery_ct IS NULL`},
		{"by a subquery over the phones", `SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 IN (SELECT phone_e164 FROM ctrlz.otp_challenges WHERE purpose = 'phone_new')`},
		{"by a join with itself", `SELECT count(*) FROM ctrlz.otp_challenges a JOIN ctrlz.otp_challenges b USING (phone_e164) WHERE a.delivery_ct IS NULL`},
	} {
		t.Run(q.name, func(t *testing.T) {
			h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
				var n int
				if err := tx.QueryRow(h.ctx, q.sql).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != 0 {
					t.Errorf("the worker saw %d decoy rows", n)
				}
			})
		})
	}
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.otp_challenges`).Scan(&n); err != nil || n != 1 {
			t.Errorf("the worker sees %d rows (%v), want the one it has a code to send", n, err)
		}
	})
	// The sender still does its work on the row it can see: when the provider accepted the code it
	// clears the sealed copy. The new row of that UPDATE has no code, and it is still the sender's
	// (the mark is set at insert and does not follow the column).
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, `WITH c AS (UPDATE ctrlz.otp_challenges SET delivery_ct = NULL WHERE phone_e164 = '`+realPhone+`' AND delivery_ct IS NOT NULL RETURNING id) SELECT count(*) FROM c`).Scan(&n); err != nil || n != 1 {
			t.Fatalf("the sender cannot clear a delivered code: %d %v", n, err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.otp_challenges`).Scan(&n); err != nil || n != 1 {
			t.Errorf("after the clear the sender sees %d rows (%v), want its own row still", n, err)
		}
	})
	// It cannot touch a decoy: an UPDATE that would give a decoy a code matches nothing.
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		tag, err := tx.Exec(h.ctx, `UPDATE ctrlz.otp_challenges SET delivery_ct = '\x0b' WHERE phone_e164 = '`+decoyPhone+`'`)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("the sender updated %d decoy rows (%v)", tag.RowsAffected(), err)
		}
	})
	// It cannot delete (the sweep is a function), insert, or change the mark.
	for _, c := range []struct{ name, sql string }{
		{"a delete", `DELETE FROM ctrlz.otp_challenges`},
		{"an insert", `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, expires_at) VALUES ('+989121110002', 'login', '\x01', now())`},
		{"the mark", `UPDATE ctrlz.otp_challenges SET deliverable = false`},
	} {
		t.Run("the worker cannot do "+c.name, func(t *testing.T) {
			h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
				if _, err := tx.Exec(h.ctx, c.sql); pgErr(err) == nil || pgErr(err).Code != "42501" {
					t.Errorf("the worker ran %s: %v", c.name, err)
				}
			})
		})
	}
	// The one role that issues codes sees every row.
	h.inTx(h.super, "auth", nil, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.otp_challenges`).Scan(&n); err != nil || n != 3 {
			t.Errorf("ctrlz_auth sees %d rows (%v), want 3", n, err)
		}
	})
	// A role with no grant reads nothing and may not try.
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		if _, err := tx.Exec(h.ctx, `SELECT count(*) FROM ctrlz.otp_challenges`); pgErr(err) == nil || pgErr(err).Code != "42501" {
			t.Errorf("the admin role read otp_challenges: %v", err)
		}
	})
}

// TestTheDeliverableMarkIsSetAtInsertForEveryWriter: the invariant does not depend on the writer
// (sms-r8-6 for the counters, the same here). The trigger sets the mark from the sealed code, even
// when the statement names another value, and refuses to change it, the superuser included.
func TestTheDeliverableMarkIsSetAtInsertForEveryWriter(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.exec(`DELETE FROM ctrlz.otp_challenges`)
	for _, role := range []string{"", "auth"} {
		who := role
		if who == "" {
			who = "superuser"
		}
		t.Run(who, func(t *testing.T) {
			h.inTx(h.super, "auth", nil, func(tx pgx.Tx) {
				if role == "" {
					if _, err := tx.Exec(h.ctx, `RESET ROLE`); err != nil {
						t.Fatal(err)
					}
				}
				var decoy, sealed bool
				if err := tx.QueryRow(h.ctx, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, deliverable)
				  VALUES ('`+decoyPhone+`', 'login', '\x01', NULL, now() + interval '5 minutes', true) RETURNING deliverable`).Scan(&decoy); err != nil {
					t.Fatal(err)
				}
				if err := tx.QueryRow(h.ctx, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, deliverable)
				  VALUES ('`+realPhone+`', 'login', '\x01', '\x0a', now() + interval '5 minutes', false) RETURNING deliverable`).Scan(&sealed); err != nil {
					t.Fatal(err)
				}
				if decoy || !sealed {
					t.Errorf("deliverable is %v for a decoy and %v for a sealed code; the statement's own value won", decoy, sealed)
				}
				if _, err := tx.Exec(h.ctx, `SAVEPOINT s`); err != nil {
					t.Fatal(err)
				}
				for _, sql := range []string{
					`UPDATE ctrlz.otp_challenges SET deliverable = true WHERE delivery_ct IS NULL`,
					`UPDATE ctrlz.otp_challenges SET deliverable = false WHERE delivery_ct IS NOT NULL`,
				} {
					if _, err := tx.Exec(h.ctx, sql); pgErr(err) == nil || pgErr(err).Code != "42501" {
						t.Errorf("%s: %v", sql, err)
					}
					if _, err := tx.Exec(h.ctx, `ROLLBACK TO SAVEPOINT s`); err != nil {
						t.Fatal(err)
					}
				}
				// Clearing the sealed code is the sender's normal move and leaves the mark alone.
				var after bool
				if err := tx.QueryRow(h.ctx, `UPDATE ctrlz.otp_challenges SET delivery_ct = NULL WHERE phone_e164 = '`+realPhone+`' RETURNING deliverable`).Scan(&after); err != nil || !after {
					t.Errorf("clearing the code moved the mark: %v %v", after, err)
				}
			})
		})
	}
}

// TestTheChallengeSweepIsADefinerFunction: the sender cannot see decoys, so it cannot delete them,
// and the retention sweep it ran as a DELETE is a function of ctrlz_auth that reaches every row.
func TestTheChallengeSweepIsADefinerFunction(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.seedChallenges()
	h.exec(`UPDATE ctrlz.otp_challenges SET created_at = now() - interval '25 hours' WHERE phone_e164 = '` + decoyPhone + `'`)
	h.inTx(h.super, "worker", nil, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_otp_challenges(1)`).Scan(&n); err != nil || n != 1 {
			t.Errorf("the sweep with a limit of 1 deleted %d (%v)", n, err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_otp_challenges(100)`).Scan(&n); err != nil || n != 1 {
			t.Errorf("the second pass deleted %d (%v), want the other old decoy", n, err)
		}
		if err := tx.QueryRow(h.ctx, `SELECT ctrlz_fn.worker_sweep_otp_challenges(0)`).Scan(&n); err != nil || n != 0 {
			t.Errorf("a limit of 0 deleted %d (%v)", n, err)
		}
		// Both decoys are gone; the young row with a code is not.
		if err := tx.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.otp_challenges`).Scan(&n); err != nil || n != 1 {
			t.Errorf("the sender sees %d rows after the sweep (%v)", n, err)
		}
	})
	for _, role := range []string{"tenant", "hub", "compiler", "admin", "keytool"} {
		h.inTx(h.super, role, nil, func(tx pgx.Tx) {
			if _, err := tx.Exec(h.ctx, `SELECT ctrlz_fn.worker_sweep_otp_challenges(10)`); pgErr(err) == nil || pgErr(err).Code != "42501" {
				t.Errorf("%s ran the sender's sweep: %v", role, err)
			}
		})
	}
}

// TestEveryReaderOfAGlobalTableIsBoundedOrSaysWhyItSeesEveryRow is the rule half of db-r9-3.
// Check 22 asked "which rows?" only of a table that already had a policy, so otp_challenges, whose
// declared reader needed only some rows, was never asked. Now every declared reader of a secret or
// personal column of a global table is in row_bound (a policy) or in all_rows (a reason).
func TestEveryReaderOfAGlobalTableIsBoundedOrSaysWhyItSeesEveryRow(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	fx0, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	if v := breakIn(t, h, fx0); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for checks 22 and 23: %v", v)
	}
	// otp_challenges is bounded, and the check says so by having no all_rows entry for it.
	if _, ok := fx0.Guarded.RowBound["otp_challenges"]["worker"]; !ok {
		t.Fatal("otp_challenges.worker has no row_bound entry")
	}
	if _, ok := fx0.Guarded.AllRows["otp_challenges"]["worker"]; ok {
		t.Fatal("otp_challenges.worker is in all_rows too")
	}
	for _, m := range []struct {
		name, want string
		edit       func(g *catalogtest.GuardedFile)
	}{
		{"the row bound of the sender on the challenges is forgotten", "worker reads a secret or personal column of otp_challenges, a global table",
			func(g *catalogtest.GuardedFile) { delete(g.RowBound["otp_challenges"], "worker") }},
		{"a reader of another global table with neither", "worker reads a secret or personal column of sms_outbox, a global table",
			func(g *catalogtest.GuardedFile) { delete(g.AllRows["sms_outbox"], "worker") }},
		{"a reader that is both bounded and all-seeing", "otp_challenges.worker is in row_bound and in all_rows",
			func(g *catalogtest.GuardedFile) {
				g.AllRows["otp_challenges"] = map[string]string{"worker": "it sends"}
			}},
		{"a reason that is empty", "all_rows.sms_outbox.worker gives no reason",
			func(g *catalogtest.GuardedFile) { g.AllRows["sms_outbox"]["worker"] = "  " }},
		{"an entry for a tenant table whose only bound is tenant_isolation", "all_rows.users.tenant: no policy besides tenant_isolation",
			func(g *catalogtest.GuardedFile) { g.AllRows["users"]["tenant"] = "why not" }},
		{"an entry for a role that reads nothing there", "all_rows.sms_outbox.hub: the role is no declared reader",
			func(g *catalogtest.GuardedFile) { g.AllRows["sms_outbox"]["hub"] = "why not" }},
	} {
		t.Run(m.name, func(t *testing.T) {
			fx, err := catalogtest.Load()
			if err != nil {
				t.Fatal(err)
			}
			// Load shares nothing between calls, but the maps are edited in place here.
			if fx.Guarded.AllRows == nil {
				fx.Guarded.AllRows = map[string]map[string]string{}
			}
			m.edit(&fx.Guarded)
			if v := breakIn(t, h, fx); !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 22 did not report %q: %v", m.want, v)
			}
		})
	}
}

// TestEveryReaderOfATenantTableThatAPolicyShowsInFullIsBoundedOrSaysWhy is db-r10-2. The which-rows
// question of check 22 skipped every tenant table on the premise that tenant_isolation bounds
// it. It bounds a bug and not a reader: a service role can open WithTenant for any tenant, and a
// permissive policy besides tenant_isolation (admin_read on users and ip_claims, USING (true)) lifts
// the bound for its role outright. So the question is asked of a declared reader of a secret or
// personal column of a tenant table whenever such a policy applies to the role, written to it, to
// PUBLIC or to a role it is a member of.
func TestEveryReaderOfATenantTableThatAPolicyShowsInFullIsBoundedOrSaysWhy(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	fx0, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	if v := breakIn(t, h, fx0); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for checks 22 and 23: %v", v)
	}
	// The two readers the schema has today are answered with a reason.
	for _, pair := range [][2]string{{"users", "admin"}, {"ip_claims", "admin"}} {
		if fx0.Guarded.AllRows[pair[0]][pair[1]] == "" {
			t.Fatalf("all_rows.%s.%s has no reason", pair[0], pair[1])
		}
	}
	// declareWorker makes the worker a declared reader of users.phone_e164, as a change that adds
	// the grant and the policy would do in guarded.yaml with a one-line reason.
	declareWorker := func(g *catalogtest.GuardedFile) {
		g.Personal["users"]["phone_e164"] = append(g.Personal["users"]["phone_e164"], "worker")
	}
	const grant = `GRANT SELECT (phone_e164) ON ctrlz.users TO ctrlz_worker`
	for _, m := range []struct {
		name  string
		sql   []string
		edit  func(g *catalogtest.GuardedFile)
		want  string // "" means the check must report nothing about the pair
		clear string
	}{
		{name: "the admin's reason on users is forgotten",
			edit: func(g *catalogtest.GuardedFile) { delete(g.AllRows["users"], "admin") },
			want: "admin reads a secret or personal column of users, a tenant table"},
		{name: "the admin's reason on ip_claims is forgotten",
			edit: func(g *catalogtest.GuardedFile) { delete(g.AllRows["ip_claims"], "admin") },
			want: "admin reads a secret or personal column of ip_claims, a tenant table"},
		{name: "a new named policy for the worker with a one-line declared read and no answer",
			sql:  []string{`CREATE POLICY worker_read ON ctrlz.users FOR SELECT TO ctrlz_worker USING (true)`, grant},
			edit: declareWorker,
			want: "worker reads a secret or personal column of users, a tenant table"},
		{name: "the same policy, answered with a reason",
			sql: []string{`CREATE POLICY worker_read ON ctrlz.users FOR SELECT TO ctrlz_worker USING (true)`, grant},
			edit: func(g *catalogtest.GuardedFile) {
				declareWorker(g)
				g.AllRows["users"]["worker"] = "the sender needs every phone"
			},
			clear: "worker reads"},
		{name: "the same policy, answered with its predicate",
			sql: []string{`CREATE POLICY worker_read ON ctrlz.users FOR SELECT TO ctrlz_worker USING (true)`, grant},
			edit: func(g *catalogtest.GuardedFile) {
				declareWorker(g)
				g.RowBound["users"] = map[string]string{"worker": "true"}
			},
			clear: "worker reads"},
		{name: "a policy written to PUBLIC reaches every declared reader",
			sql:  []string{`CREATE POLICY everyone ON ctrlz.users FOR SELECT TO PUBLIC USING (true)`},
			want: "tenant reads a secret or personal column of users, a tenant table"},
		{name: "a policy of a role the worker is a member of",
			sql:  []string{`CREATE POLICY auth_users ON ctrlz.users FOR SELECT TO ctrlz_keytool USING (true)`, `GRANT ctrlz_keytool TO ctrlz_worker`, grant},
			edit: declareWorker,
			want: "worker reads a secret or personal column of users, a tenant table"},
		{name: "a restrictive policy lifts nothing",
			sql:   []string{`CREATE POLICY narrow ON ctrlz.users AS RESTRICTIVE FOR SELECT TO ctrlz_worker USING (false)`, grant},
			edit:  declareWorker,
			clear: "worker reads"},
		{name: "a reason where only tenant_isolation applies",
			edit: func(g *catalogtest.GuardedFile) { g.AllRows["users"]["tenant"] = "why not" },
			want: "all_rows.users.tenant: no policy besides tenant_isolation"},
		{name: "a predicate where only tenant_isolation applies",
			edit: func(g *catalogtest.GuardedFile) { g.RowBound["users"] = map[string]string{"tenant": "true"} },
			want: "row_bound.users.tenant: no policy besides tenant_isolation"},
	} {
		t.Run(m.name, func(t *testing.T) {
			fx, err := catalogtest.Load()
			if err != nil {
				t.Fatal(err)
			}
			if fx.Guarded.AllRows == nil {
				fx.Guarded.AllRows = map[string]map[string]string{}
			}
			if fx.Guarded.RowBound == nil {
				fx.Guarded.RowBound = map[string]map[string]string{}
			}
			if m.edit != nil {
				m.edit(&fx.Guarded)
			}
			got := strings.Join(breakIn(t, h, fx, m.sql...), "\n")
			if m.want != "" && !strings.Contains(got, m.want) {
				t.Errorf("check 22 did not report %q:\n%s", m.want, got)
			}
			if m.clear != "" && strings.Contains(got, m.clear) {
				t.Errorf("check 22 reported %q for an answered reader:\n%s", m.clear, got)
			}
		})
	}
}
