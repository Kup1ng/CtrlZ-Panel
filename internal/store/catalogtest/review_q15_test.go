package catalogtest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Question 15 (owner decision of 2026-11-24, migration 0061, finding db-r18-17): row-level security under every
// definer function that acts for a tenant. The tests below are the behaviour half; the shape of the catalog is judged
// by checks 04, 05, 10 and 12 and by TestScopedRoleSeesOneTenantOnEveryTableItReaches.
// None of them is a test of the Go statements of the issue (internal/api and internal/auth/otp drive those); they read the
// database the migration made, as the roles the services log in as.

// TestTheMovedFunctionsAreIsolatedWithoutTheirPredicate is the proof that the policy, and not the body, keeps the
// tenants apart for the four functions question 15 put under row-level security (the three it moved to ctrlz_scoped
// and announcements_for_tenant, whose table had no policy). Each function is rewritten inside a rolled back
// transaction with its tenant predicate cut out of the text, keeps its owner, and is called under tenant A with
// B's ids: nothing of B's is read or changed. The CONTROL is the same rewritten function with ctrlz_scoped made to
// bypass row-level security, which must show the leak: a case whose control does not leak proves nothing.
func TestTheMovedFunctionsAreIsolatedWithoutTheirPredicate(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	fixtures := h.fnFixtures()
	A, B := h.A, h.B
	repl := strings.NewReplacer(
		A.Tenant.String(), "A.tenant", B.Tenant.String(), "B.tenant", A.User.String(), "A.user", B.User.String(), "B.user",
		A.Endpoint.String(), "A.endpoint", B.Endpoint.String(), "B.endpoint", A.Claim.String(), "A.claim", B.Claim.String(), "B.claim")

	cases := []struct {
		name string
		cut  []string // every occurrence of each text is removed from the function
	}{
		{"auth_tickets_revoke", []string{"x.subject_tenant = ctrlz.current_tenant_id() AND "}},
		{"auth_phone_mark_verified", []string{"u.tenant_id = v_tenant AND "}},
		{"auth_phone_change_complete", []string{"p.tenant_id = v_tenant AND ", "u.tenant_id = v_tenant AND "}},
		{"announcements_for_tenant", []string{"AND (a.audience = 'all' OR a.tenant_id = ctrlz.current_tenant_id())"}},
	}
	// run makes the rewritten function and calls it as ctrlz_tenant with the setting at caller and the ids of subject.
	run := func(t *testing.T, name string, cut []string, bypass bool, caller, subject catalogtest.SeedIDs) (answer string, dA, dB string) {
		t.Helper()
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		f := &fnCtx{h: h, tx: tx, ids: map[string]uuid.UUID{}, repl: repl}
		fix := fixtures[name]
		if fix.arrange != nil {
			fix.arrange(f, A)
			fix.arrange(f, B)
		}
		var def, owner string
		if err := tx.QueryRow(h.ctx, `SELECT pg_get_functiondef(p.oid), pg_get_userbyid(p.proowner) FROM pg_proc p
WHERE p.pronamespace = 'ctrlz_fn'::regnamespace AND p.proname = $1`, name).Scan(&def, &owner); err != nil {
			t.Fatal(err)
		}
		if owner != "ctrlz_scoped" {
			t.Fatalf("%s is owned by %s, not ctrlz_scoped", name, owner)
		}
		for _, c := range cut {
			if !strings.Contains(def, c) {
				t.Fatalf("%s has no %q to cut: the case proves nothing", name, c)
			}
			def = strings.ReplaceAll(def, c, "")
		}
		// CREATE OR REPLACE keeps the owner and the grants of the function, so only the text changes.
		if _, err := tx.Exec(h.ctx, def); err != nil {
			t.Fatalf("rewrite %s: %v", name, err)
		}
		if bypass {
			if _, err := tx.Exec(h.ctx, "ALTER ROLE ctrlz_scoped BYPASSRLS"); err != nil {
				t.Fatal(err)
			}
		}
		a0, b0 := f.digest(A), f.digest(B)
		args := []any(nil)
		if fix.args != nil {
			args = fix.args(caller, subject)
		}
		if ids, ok := f.argsWithIDs(name, caller, subject); ok {
			args = ids
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", caller.Tenant.String()); err != nil {
			t.Fatal(err)
		}
		rows, err := tx.Query(h.ctx, fix.call, args...)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		answer = f.summary(rows)
		if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		return answer, diffDigest(a0, f.digest(A)), diffDigest(b0, f.digest(B))
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fix := fixtures[c.name]
			if fix.noCross {
				// announcements_for_tenant takes no id: the setting is its only selector, so the call is A's own and the
				// proof is that A is shown its own and the ones for everybody, never B's.
				want := strings.ReplaceAll(fix.own, "B.tenant", "A.tenant")
				got, _, dB := run(t, c.name, c.cut, false, A, A)
				if got != want || dB != "" {
					t.Errorf("without its predicate %s answered %q (changed B: %q), want %q", c.name, got, dB, want)
				}
				if leak, _, _ := run(t, c.name, c.cut, true, A, A); leak == want {
					t.Errorf("the control did not leak: with row-level security bypassed the rewritten %s still answers %q, so the case proves nothing", c.name, leak)
				}
				return
			}
			// The cross call: A's setting, B's ids. The rewritten body has nothing but the policy between it and B's rows.
			got, dA, dB := run(t, c.name, c.cut, false, A, B)
			if fix.cross != "*" && got != fix.cross {
				t.Errorf("without its predicate %s answered %q to A about B's rows, want %q", c.name, got, fix.cross)
			}
			if dA != "" || dB != "" {
				t.Errorf("without its predicate %s changed rows of A (%q) or of B (%q) when A's setting named B's ids", c.name, dA, dB)
			}
			// The control: the same text with the policy out of the way reaches B, so the case above could fail.
			if _, _, leaked := run(t, c.name, c.cut, true, A, B); leaked == "" {
				t.Errorf("the control did not leak: with row-level security bypassed the rewritten %s left B's rows alone, so the case proves nothing", c.name)
			}
			// And the same rewritten body still does its job for the tenant it acts for.
			own, _, changed := run(t, c.name, c.cut, false, B, B)
			if own != fix.own || changed == "" {
				t.Errorf("without its predicate %s answered %q for B's own ids (changed B: %q), want %q and a change", c.name, own, changed, fix.own)
			}
		})
	}
}

// TestAPhoneChangeCannotBorrowTheChallengesOfAnotherTenant is the case the predicate test above cannot make: the
// request and the user are the caller's own, every check of the body on the number, the purpose and the time passes,
// and the only thing that differs is the tenant stamped on the challenge. auth_phone_change_complete has no tenant
// predicate on otp_challenges at all (the table had no tenant column when it was written), so the policy
// `scoped_tenant` is the whole defence, and a code stamped with the other tenant, or with none, must not be found.
// The control row (both stamped with the caller's own tenant) completes, so the refusals are the stamp's and nothing else's.
func TestAPhoneChangeCannotBorrowTheChallengesOfAnotherTenant(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	A, B := h.A, h.B
	tenantOf := map[string]*uuid.UUID{"A": &A.Tenant, "B": &B.Tenant, "none": nil}
	cases := []struct{ name, old, new, want string }{
		{"both its own", "A", "A", "ok"},
		{"the old-number code is another tenant's", "B", "A", "invalid"},
		{"the new-number code is another tenant's", "A", "B", "invalid"},
		{"both are another tenant's", "B", "B", "invalid"},
		{"the new-number code has no tenant", "A", "none", "invalid"},
		{"the old-number code has no tenant", "none", "A", "invalid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := tx.Exec(h.ctx, sql, args...); err != nil {
					t.Fatalf("%v\n%s", err, sql)
				}
			}
			oldID, newID, req := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
			exec(`DELETE FROM ctrlz.phone_change_requests WHERE tenant_id = $1`, A.Tenant)
			// The phones are A's: the old code is for A's number and the new one for the number A asked to move to.
			// The request is an hour old, so a code consumed a minute ago comes after it, as the body demands.
			exec(`INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at, tenant_id) VALUES
				($1, $3, 'phone_old', '\x01', now() + interval '5 minutes', now() - interval '1 minute', $5),
				($2, $4, 'phone_new', '\x01', now() + interval '5 minutes', now() - interval '1 minute', $6)`,
				oldID, newID, A.Phone, newPhone(A), tenantOf[c.old], tenantOf[c.new])
			exec(`INSERT INTO ctrlz.phone_change_requests (tenant_id, id, user_id, new_phone_e164, old_otp_id, new_otp_id, created_at, expires_at)
				VALUES ($1, $2, $3, $4, $5, $6, now() - interval '1 hour', now() + interval '10 minutes')`,
				A.Tenant, req, A.User, newPhone(A), oldID, newID)
			exec("SET LOCAL ROLE ctrlz_tenant")
			exec("SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", A.Tenant.String())
			var got string
			if err := tx.QueryRow(h.ctx, "SELECT outcome FROM ctrlz_fn.auth_phone_change_complete($1)", req).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("a request of A with an old code of %s and a new code of %s answered %q, want %q", c.old, c.new, got, c.want)
			}
			exec("RESET ROLE")
			var phone string
			if err := tx.QueryRow(h.ctx, "SELECT phone_e164 FROM ctrlz.users WHERE id = $1", A.User).Scan(&phone); err != nil {
				t.Fatal(err)
			}
			if moved := phone == newPhone(A); moved != (c.want == "ok") {
				t.Errorf("A's number is %s after %q", phone, got)
			}
		})
	}
}

// TestAChallengeCarriesTheTenantOfItsAccount is the stamp of auth_otp_issue (0061): whatever the caller asks, the
// tenant of a challenge is the tenant of the account of its phone for login, reset and phone_old, the tenant of the
// transaction setting for phone_new, and nothing for signup, invite and every decoy. The worker, which sends the codes,
// cannot read the column.
func TestAChallengeCarriesTheTenantOfItsAccount(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aStr, bStr := a.Tenant.String(), b.Tenant.String()
	const free = "+989129990001" // a number with no account
	issue := func(guc *string, phone, purpose string, real bool) (stamped *uuid.UUID, allowed bool) {
		t.Helper()
		h.inTx(h.super, "tenant", guc, func(tx pgx.Tx) {
			var ct any
			if real {
				ct = []byte{2}
			}
			var id *uuid.UUID
			if err := tx.QueryRow(h.ctx, `SELECT id, allowed FROM ctrlz_fn.auth_otp_issue($1, $2, '\x01'::bytea, $3::bytea, '198.51.100.7'::inet, false)`,
				phone, purpose, ct).Scan(&id, &allowed); err != nil {
				t.Fatalf("%s %s: %v", purpose, phone, err)
			}
			if !allowed || id == nil {
				return
			}
			if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(h.ctx, "SELECT tenant_id FROM ctrlz.otp_challenges WHERE id = $1", *id).Scan(&stamped); err != nil {
				t.Fatal(err)
			}
		})
		return stamped, allowed
	}
	for _, c := range []struct {
		name    string
		guc     *string
		phone   string
		purpose string
		real    bool
		want    *uuid.UUID
	}{
		{"login of tenant A's phone", nil, a.Phone, "login", true, &a.Tenant},
		{"login of tenant B's phone", nil, b.Phone, "login", true, &b.Tenant},
		{"reset of tenant B's phone", nil, b.Phone, "reset", true, &b.Tenant},
		{"phone_old of tenant A's phone", &aStr, a.Phone, "phone_old", true, &a.Tenant},
		{"phone_old of tenant A's phone asked under B's setting", &bStr, a.Phone, "phone_old", true, &a.Tenant},
		{"phone_new under A's setting", &aStr, free, "phone_new", true, &a.Tenant},
		{"phone_new under B's setting", &bStr, free, "phone_new", true, &b.Tenant},
		{"phone_new with no setting", nil, free, "phone_new", true, nil},
		{"signup of a free number", nil, free, "signup", true, nil},
		{"signup of tenant A's phone", nil, a.Phone, "signup", true, nil},
		{"invite of a free number", nil, free, "invite", true, nil},
		{"a login decoy for a free number", nil, free, "login", false, nil},
		{"a login decoy that names tenant A's phone", nil, a.Phone, "login", false, nil},
		{"a phone_new decoy under A's setting", &aStr, free, "phone_new", false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, allowed := issue(c.guc, c.phone, c.purpose, c.real)
			if !allowed {
				t.Fatal("the issue was refused: the case proves nothing")
			}
			switch {
			case c.want == nil && got != nil:
				t.Errorf("the challenge carries tenant %s, want none", got)
			case c.want != nil && (got == nil || *got != *c.want):
				t.Errorf("the challenge carries %v, want %s", got, c.want)
			}
		})
	}
	// The column is outside the sender's reach: it holds a tenant per code, and the sender must not learn which
	// numbers have an account (the decoy rule of db-r9-3), so a statement that names it is refused.
	if !h.denied("worker", nil, "SELECT tenant_id FROM ctrlz.otp_challenges") {
		t.Error("the worker may read otp_challenges.tenant_id")
	}
	if !h.denied("worker", nil, "UPDATE ctrlz.otp_challenges SET tenant_id = NULL") {
		t.Error("the worker may write otp_challenges.tenant_id")
	}
	// The value of the column is checked by the table: only the four purposes of an account may carry one.
	if _, err := h.super.Exec(h.ctx, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, expires_at, tenant_id)
VALUES ('+989129990002', 'signup', '\x01', now() + interval '5 minutes', $1)`, a.Tenant); err == nil {
		t.Error("a signup challenge was stored with a tenant")
	}
}

// TestMigration0061KeepsALoginAndAPhoneChangeInFlight migrates an installed database to the version before 0061, with
// a consumed login code and an open phone change of two tenants in it (the state of a request that was made a minute
// before the upgrade), applies 0061, and finishes both: each challenge is stamped with the tenant of its own account,
// the codes of the other tenant are not found, and the change and the verification complete. A migration that stamps
// nothing fails the count.
func TestMigration0061KeepsALoginAndAPhoneChangeInFlight(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	super, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())
	if _, err := migrate.UpTo(ctx, db, 60); err != nil {
		t.Fatal(err)
	}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}
	tenants := []catalogtest.SeedIDs{catalogtest.NewSeedIDs(1), catalogtest.NewSeedIDs(2)}
	type flight struct{ login, old, new, req, pendingLogin, pendingNew uuid.UUID }
	flights := make([]flight, len(tenants))
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%v\n%s", err, sql)
		}
	}
	for i, s := range tenants {
		if err := catalogtest.SeedTenant(ctx, super, s); err != nil {
			t.Fatal(err)
		}
		// The seed made a request with random challenge ids; this one is the request in flight.
		exec(`DELETE FROM ctrlz.phone_change_requests WHERE tenant_id = $1`, s.Tenant)
		f := flight{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
		flights[i] = f
		newPhone := "+98913111100" + string(rune('0'+s.Index))
		exec(`UPDATE ctrlz.users SET phone_verified_at = NULL WHERE id = $1`, s.User)
		// A code consumed a moment ago and a pair of codes of the phone change, both consumed after the request was
		// made. These carry no sealed copy, so they are in the window by being consumed. Rows of the issue function of
		// 0055 carry no tenant.
		exec(`INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at) VALUES
			($1, $4, 'login', '\x01', now() + interval '5 minutes', now()),
			($2, $4, 'phone_old', '\x01', now() + interval '5 minutes', now() + interval '1 second'),
			($3, $5, 'phone_new', '\x01', now() + interval '5 minutes', now() + interval '1 second')`,
			f.login, f.old, f.new, s.Phone, newPhone)
		// The usual state at upgrade time: a code that was sent and sits unconsumed with its sealed copy (deliverable,
		// set at insert by the trigger of 0039), for a login and for a phone change whose request names it. They are in
		// the window by being deliverable alone, so a backfill that asks only for consumed rows leaves them out.
		pendingPhone := "+98913222200" + string(rune('0'+s.Index))
		exec(`INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, delivery_ct, expires_at) VALUES
			($1, $3, 'login', '\x01', '\x02', now() + interval '5 minutes'),
			($2, $4, 'phone_new', '\x01', '\x02', now() + interval '5 minutes')`, f.pendingLogin, f.pendingNew, s.Phone, pendingPhone)
		exec(`INSERT INTO ctrlz.phone_change_requests (tenant_id, id, user_id, new_phone_e164, old_otp_id, new_otp_id, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, now() + interval '10 minutes')`, s.Tenant, uuid.Must(uuid.NewV7()), s.User, pendingPhone, f.old, f.pendingNew)
		exec(`INSERT INTO ctrlz.phone_change_requests (tenant_id, id, user_id, new_phone_e164, old_otp_id, new_otp_id, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, now() + interval '10 minutes')`, s.Tenant, f.req, s.User, newPhone, f.old, f.new)
	}
	// Rows the migration must leave alone: a code more than an hour old, and one nobody has consumed or can send (a decoy).
	oldRow, decoyRow := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	exec(`INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at, created_at) VALUES
		($1, $2, 'login', '\x01', now() - interval '1 hour', now() - interval '2 hours', now() - interval '2 hours')`, oldRow, tenants[0].Phone)
	exec(`INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at) VALUES ($1, $2, 'login', '\x01', now() + interval '5 minutes')`, decoyRow, tenants[1].Phone)

	if _, err := migrate.UpTo(ctx, db, 61); err != nil {
		t.Fatalf("0061: %v", err)
	}

	stamp := func(id uuid.UUID) *uuid.UUID {
		var s *uuid.UUID
		if err := super.QueryRow(ctx, "SELECT tenant_id FROM ctrlz.otp_challenges WHERE id = $1", id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	var stamped int
	if err := super.QueryRow(ctx, "SELECT count(*) FROM ctrlz.otp_challenges WHERE tenant_id IS NOT NULL").Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	if stamped != 10 {
		t.Fatalf("0061 stamped %d challenges, want the 10 of the two tenants (a consumed and a pending login, a consumed and a pending phone change each)", stamped)
	}
	for i, s := range tenants {
		for name, id := range map[string]uuid.UUID{"login": flights[i].login, "phone_old": flights[i].old, "phone_new": flights[i].new,
			"pending login": flights[i].pendingLogin, "pending phone_new": flights[i].pendingNew} {
			if got := stamp(id); got == nil || *got != s.Tenant {
				t.Errorf("tenant %d: the %s code carries %v, want its own tenant", s.Index, name, got)
			}
		}
	}
	if got := stamp(oldRow); got != nil {
		t.Errorf("a code from two hours ago was stamped (%v): the window is the last hour", got)
	}
	if got := stamp(decoyRow); got != nil {
		t.Errorf("a code nobody consumed and nobody can be sent was stamped (%v)", got)
	}

	// Both flights finish, each under its own tenant, and neither finishes under the other's.
	call := func(tenant uuid.UUID, sql string, args ...any) string {
		t.Helper()
		tx, err := super.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", tenant.String()); err != nil {
			t.Fatal(err)
		}
		var out string
		if err := tx.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return out
	}
	for i, s := range tenants {
		other := tenants[1-i]
		if got := call(other.Tenant, "SELECT outcome FROM ctrlz_fn.auth_phone_change_complete($1)", flights[i].req); got != "invalid" {
			t.Errorf("tenant %d's phone change completed under tenant %d's setting: %q", s.Index, other.Index, got)
		}
		if got := call(s.Tenant, "SELECT outcome FROM ctrlz_fn.auth_phone_change_complete($1)", flights[i].req); got != "ok" {
			t.Errorf("tenant %d's phone change in flight did not complete after 0061: %q", s.Index, got)
		}
	}
	// The verification uses the login code consumed before the upgrade. The phone of tenant 1 changed above in a
	// rolled back transaction, so its user still has the number the code was made for.
	for i, s := range tenants {
		if got := call(s.Tenant, "SELECT outcome FROM ctrlz_fn.auth_phone_mark_verified($1, $2)", s.User, flights[i].login); got != "ok" {
			t.Errorf("tenant %d's login code consumed before 0061 no longer verifies its phone: %q", s.Index, got)
		}
		if got := call(tenants[1-i].Tenant, "SELECT outcome FROM ctrlz_fn.auth_phone_mark_verified($1, $2)", tenants[1-i].User, flights[i].login); got != "invalid" {
			t.Errorf("tenant %d's login code verified a phone of tenant %d: %q", s.Index, tenants[1-i].Index, got)
		}
	}
}
