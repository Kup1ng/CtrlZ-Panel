package catalogtest_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Test 40: the grants T-536 (10.7) relies on. Each statement of step 3 runs as
// ctrlz_admin under a tenant setting on that tenant's user, changes no row of
// another tenant's user, and changes no row at all without a setting. The admin
// still cannot read the secrets it never needed.
func TestAdminReissueGrants(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aGUC := a.Tenant.String()

	// A user with a one-time password, a session, a refresh token and an open
	// ticket, in each tenant. Made as the superuser; the seed already has a
	// session and a refresh token for each user.
	for _, u := range []uuid.UUID{a.User, b.User} {
		if _, err := h.super.Exec(h.ctx, "UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '1 hour' WHERE id = $1", u); err != nil {
			t.Fatal(err)
		}
	}
	for i, ids := range []struct{ tenant, user uuid.UUID }{{a.Tenant, a.User}, {b.Tenant, b.User}} {
		if _, err := h.super.Exec(h.ctx, `INSERT INTO ctrlz.auth_tickets (token_hash, kind, subject_tenant, subject_user, expires_at)
VALUES (decode(repeat($1, 32), 'hex'), 'mfa', $2, $3, now() + interval '5 minutes')`, []string{"51", "52"}[i], ids.tenant, ids.user); err != nil {
			t.Fatal(err)
		}
	}

	// The seed gives each user a passkey, which makes a user ineligible (10.7); the
	// statements below are about an eligible one.
	if _, err := h.super.Exec(h.ctx, "DELETE FROM ctrlz.webauthn_credentials WHERE user_id = ANY ($1)", []uuid.UUID{a.User, b.User}); err != nil {
		t.Fatal(err)
	}

	// Step 3a: the lock-and-read, on A's user and then on B's.
	// ctrlz_admin has no UPDATE on users, so the lock (which Postgres allows only with
	// UPDATE on a column) is taken inside ctrlz_fn.admin_one_time_state.
	read := `SELECT cred_state, no_second_factor, tenant_status FROM ctrlz_fn.admin_one_time_state($1)`
	steps := []struct {
		name string
		sql  string
		args func(tenant, user uuid.UUID) []any
	}{
		// Steps c and d are one function since 0020 (the admin has no UPDATE on the
		// session tables). The query returns a row only when it revoked something, so
		// the row count below reads as "changed".
		{"c, d: revoke sessions and refresh tokens", `SELECT 1 FROM ctrlz_fn.admin_revoke_user_sessions($1) n WHERE n > 0`,
			func(tn, u uuid.UUID) []any { return []any{u} }},
	}
	rowsOf := func(tx pgx.Tx, sql string, args ...any) int {
		t.Helper()
		r, err := tx.Query(h.ctx, sql, args...)
		if err != nil {
			t.Fatalf("%.40s: %v", sql, err)
		}
		defer r.Close()
		n := 0
		for r.Next() {
			n++
		}
		if err := r.Err(); err != nil {
			t.Fatalf("%.40s: %v", sql, err)
		}
		return n
	}
	changedRows := func(tx pgx.Tx, sql string, args ...any) int64 {
		t.Helper()
		tag, err := tx.Exec(h.ctx, sql, args...)
		if err != nil {
			t.Fatalf("%.40s: %v", sql, err)
		}
		return tag.RowsAffected()
	}

	// Setting A: A's user is reached, B's is not.
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		if n := rowsOf(tx, read, a.User); n != 1 {
			t.Errorf("step a on A's user: %d rows", n)
		}
		if n := rowsOf(tx, read, b.User); n != 0 {
			t.Errorf("step a on B's user under A's setting: %d rows", n)
		}
		for _, s := range steps {
			if n := changedRows(tx, s.sql, s.args(b.Tenant, b.User)...); n != 0 {
				t.Errorf("%s changed %d rows of B under A's setting", s.name, n)
			}
		}
		if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.auth_tickets_revoke($1)", b.User); err != nil {
			t.Fatal(err)
		}
		for _, s := range steps {
			if n := changedRows(tx, s.sql, s.args(a.Tenant, a.User)...); n != 1 {
				t.Errorf("%s changed %d rows of A", s.name, n)
			}
		}
		// Step b is the database function. Under A's setting it reaches A's user and
		// not B's.
		if o := reissueOutcome(t, h, tx, b.User, "hijack-b"); o != "not_found" {
			t.Errorf("b: the function on B's user under A's setting: %q", o)
		}
		if o := reissueOutcome(t, h, tx, a.User, "new-hash"); o != "ok" {
			t.Errorf("b: the function on A's user: %q", o)
		}
		if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.auth_tickets_revoke($1)", a.User); err != nil {
			t.Fatal(err)
		}
		asSuper(h, tx, "admin", func() {
			for hex, wantConsumed := range map[string]bool{"51": true, "52": false} {
				var consumed bool
				if err := tx.QueryRow(h.ctx, "SELECT consumed_at IS NOT NULL FROM ctrlz.auth_tickets WHERE token_hash = decode(repeat($1, 32), 'hex')", hex).Scan(&consumed); err != nil {
					t.Fatal(err)
				}
				if consumed != wantConsumed {
					t.Errorf("ticket %s consumed=%v, want %v", hex, consumed, wantConsumed)
				}
			}
			var hash string
			if err := tx.QueryRow(h.ctx, "SELECT password_hash FROM ctrlz.users WHERE id = $1", b.User).Scan(&hash); err != nil || hash != "argon2id$seed" {
				t.Errorf("B's hash is %q (%v)", hash, err)
			}
		})
	})
	// No setting: nothing at all.
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		if n := rowsOf(tx, read, a.User); n != 0 {
			t.Errorf("step a with no setting: %d rows", n)
		}
		for _, s := range steps {
			if n := changedRows(tx, s.sql, s.args(a.Tenant, a.User)...); n != 0 {
				t.Errorf("%s changed %d rows with no setting", s.name, n)
			}
		}
	})

	// What the admin still cannot read.
	for _, sql := range []string{
		"SELECT password_hash FROM ctrlz.users",
		"SELECT totp_secret_ct FROM ctrlz.users",
		"SELECT token_hash FROM ctrlz.refresh_tokens",
		"SELECT token_hash FROM ctrlz.sessions",
		"SELECT ip FROM ctrlz.sessions",
		"SELECT user_agent FROM ctrlz.sessions",
	} {
		if !h.denied("admin", &aGUC, sql) {
			t.Errorf("ctrlz_admin could run %q", sql)
		}
	}
}

// Test 41: the CHECK that makes password_expires_at mean "an admin-issued
// one-time password".
func TestOneTimePasswordCheck(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	// Refused: an expiry with must_reset false, and an expiry with no hash. The
	// statements run as the owner of the connection (a superuser): the CHECK holds
	// for every role, which is the point of a constraint.
	for _, sql := range []string{
		"UPDATE ctrlz.users SET password_expires_at = now() WHERE id = $1",
		"UPDATE ctrlz.users SET password_hash = NULL, must_reset = true, password_expires_at = now() WHERE id = $1",
	} {
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(h.ctx, sql, h.A.User)
		if pe := pgErr(err); pe == nil || pe.Code != "23514" {
			t.Errorf("%q: want a check violation, got %v", sql, err)
		}
		_ = tx.Rollback(h.ctx)
	}
	// Accepted: one UPDATE that clears both together, and what admin_create_user makes.
	tx, err := h.super.Begin(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, "UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '1 hour' WHERE id = $1", h.A.User); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, "UPDATE ctrlz.users SET must_reset = false, password_expires_at = NULL WHERE id = $1", h.A.User); err != nil {
		t.Errorf("clearing both together: %v", err)
	}
	_ = tx.Rollback(h.ctx)
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		if n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz_fn.admin_create_user('+989121119998', 'hash', 'fa')"); err != nil || n != 1 {
			t.Errorf("admin_create_user: %d rows, err %v", n, err)
		}
	})
}

// reissueOutcome calls the function of step 3b and returns its outcome.
func reissueOutcome(t *testing.T, h *harness, tx pgx.Tx, user uuid.UUID, hash string) string {
	t.Helper()
	var outcome string
	if err := tx.QueryRow(h.ctx, "SELECT outcome FROM ctrlz_fn.admin_reissue_one_time_password($1, $2)", user, hash).Scan(&outcome); err != nil {
		t.Fatalf("admin_reissue_one_time_password: %v", err)
	}
	return outcome
}

// Test 42 (review round 1, admin-r1-17): the rule against taking over a user's
// own password holds in the database, not only in the Go handler. ctrlz_admin
// cannot write the password columns by any statement, and the one function that
// may write them refuses a user whose password is their own, one with a second
// factor, a missing user and a tenant being deleted. Two tenants: the function
// reaches only the tenant of the setting.
func TestAdminCannotTakeOverAUsersOwnPassword(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aGUC := a.Tenant.String()

	// 1. No statement writes the columns, whatever the setting.
	for _, sql := range []string{
		"UPDATE ctrlz.users SET password_hash = 'known'",
		"UPDATE ctrlz.users SET must_reset = true",
		"UPDATE ctrlz.users SET password_expires_at = now() + interval '72 hours'",
		"UPDATE ctrlz.users SET password_hash = 'known', password_expires_at = now() + interval '72 hours', must_reset = true WHERE id = '" + a.User.String() + "'",
	} {
		if !h.denied("admin", &aGUC, sql) {
			t.Errorf("ctrlz_admin could run %q", sql)
		}
	}

	hashOf := func(user uuid.UUID) string {
		var s string
		if err := h.super.QueryRow(h.ctx, "SELECT password_hash FROM ctrlz.users WHERE id = $1", user).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// 2. A user's own password (no expiry): refused, nothing changes.
	before := hashOf(a.User)
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		if o := reissueOutcome(t, h, tx, a.User, "known"); o != "not_one_time" {
			t.Errorf("a user's own password: %q", o)
		}
	})
	if hashOf(a.User) != before {
		t.Fatal("the function replaced a user's own password")
	}

	// 3. An admin-issued one-time password: replaced, and only A's user.
	for _, u := range []uuid.UUID{a.User, b.User} {
		if _, err := h.super.Exec(h.ctx, "UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '1 hour' WHERE id = $1", u); err != nil {
			t.Fatal(err)
		}
	}
	// A one-time password and a passkey (the seed has one): the passkey wins.
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		if o := reissueOutcome(t, h, tx, a.User, "known"); o != "not_one_time" {
			t.Errorf("a user with a passkey: %q", o)
		}
	})
	if _, err := h.super.Exec(h.ctx, "DELETE FROM ctrlz.webauthn_credentials WHERE user_id = ANY ($1)", []uuid.UUID{a.User, b.User}); err != nil {
		t.Fatal(err)
	}
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		if o := reissueOutcome(t, h, tx, b.User, "known"); o != "not_found" {
			t.Errorf("B's user under A's setting: %q", o)
		}
		if o := reissueOutcome(t, h, tx, a.User, "known"); o != "ok" {
			t.Errorf("A's one-time password: %q", o)
		}
		asSuper(h, tx, "admin", func() {
			var got string
			if err := tx.QueryRow(h.ctx, "SELECT password_hash FROM ctrlz.users WHERE id = $1", a.User).Scan(&got); err != nil || got != "known" {
				t.Errorf("A's hash is %q (%v)", got, err)
			}
		})
	})
	if hashOf(b.User) != "argon2id$seed" {
		t.Fatal("the function changed B's password")
	}
	// No setting: nothing is found.
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		if o := reissueOutcome(t, h, tx, a.User, "known2"); o != "not_found" {
			t.Errorf("no setting: %q", o)
		}
	})

	// 4. A second factor, and a tenant being deleted, are refused.
	if _, err := h.super.Exec(h.ctx, "UPDATE ctrlz.users SET enforce_passkey = true WHERE id = $1", a.User); err != nil {
		t.Fatal(err)
	}
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		if o := reissueOutcome(t, h, tx, a.User, "known3"); o != "not_one_time" {
			t.Errorf("a user who must use a passkey: %q", o)
		}
	})
	if _, err := h.super.Exec(h.ctx, "UPDATE ctrlz.users SET enforce_passkey = false WHERE id = $1", a.User); err != nil {
		t.Fatal(err)
	}
	if _, err := h.super.Exec(h.ctx, "UPDATE ctrlz.tenants SET status = 'deleting' WHERE id = $1", a.Tenant); err != nil {
		t.Fatal(err)
	}
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		if o := reissueOutcome(t, h, tx, a.User, "known4"); o != "not_found" {
			t.Errorf("a tenant being deleted: %q", o)
		}
	})
	// The other roles cannot call it.
	for _, role := range []string{"tenant", "worker", "hub"} {
		if !h.denied(role, &aGUC, "SELECT outcome FROM ctrlz_fn.admin_reissue_one_time_password($1, 'x')", a.User) {
			t.Errorf("ctrlz_%s can execute the re-issue function", role)
		}
	}
}
