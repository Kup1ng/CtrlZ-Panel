package catalogtest_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Review round 2, db-r2-1 / db-r2-5 / db-r2-2. ctrlz_admin may open WithTenant
// on any tenant, so a table-level UPDATE on a credential table is a takeover of
// any user in the tenant it picks: session and refresh token hashes are plain
// SHA-256, so it can write the hash of a token it chose. 0012 closed this for
// users.password_hash only. Here every column of the four tables is asked for,
// so a column added later, or a grant widened back to a plain 'U', fails.
func TestAdminCannotRewriteCredentialsOrTokens(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aGUC := a.Tenant.String()

	// The admin role writes no column of these tables since 0020: the revocation
	// of a user's sessions is ctrlz_fn.admin_revoke_user_sessions (role-reach).
	allowed := map[string]string{}
	for _, table := range []string{"sessions", "refresh_tokens", "api_tokens", "webauthn_credentials"} {
		if len(h.columns[table]) == 0 {
			t.Fatalf("no columns for %s", table)
		}
		var tableLevel bool
		if err := h.super.QueryRow(h.ctx, "SELECT has_table_privilege('ctrlz_admin', $1, 'UPDATE')", "ctrlz."+table).Scan(&tableLevel); err != nil {
			t.Fatal(err)
		}
		if tableLevel {
			t.Errorf("ctrlz_admin has table-level UPDATE on %s", table)
		}
		for _, col := range h.columns[table] {
			var ok bool
			if err := h.super.QueryRow(h.ctx, "SELECT has_column_privilege('ctrlz_admin', $1, $2, 'UPDATE')", "ctrlz."+table, col).Scan(&ok); err != nil {
				t.Fatal(err)
			}
			if want := allowed[table] == col; ok != want {
				t.Errorf("ctrlz_admin UPDATE on %s.%s = %v, want %v", table, col, ok, want)
			}
		}
	}

	// The statements of the takeover, run under A's setting on A's own user:
	// each must be refused by privilege, not merely by an empty WHERE.
	hash := `decode(repeat('ab', 32), 'hex')`
	for _, sql := range []string{
		`UPDATE ctrlz.sessions SET token_hash = ` + hash + `, revoked_at = NULL, restricted = false, reauth_at = now(),
  idle_expires_at = now() + interval '1 day', absolute_expires_at = now() + interval '30 days' WHERE tenant_id = '` + a.Tenant.String() + `' AND user_id = '` + a.User.String() + `'`,
		`UPDATE ctrlz.sessions SET revoked_at = NULL, token_hash = ` + hash,
		`UPDATE ctrlz.refresh_tokens SET token_hash = ` + hash + `, revoked_at = NULL, expires_at = now() + interval '30 days' WHERE user_id = '` + a.User.String() + `'`,
		`UPDATE ctrlz.api_tokens SET token_hash = ` + hash + `, revoked_at = NULL, allowed_ips = NULL`,
		`UPDATE ctrlz.api_tokens SET revoked_at = now()`,
		`UPDATE ctrlz.webauthn_credentials SET public_key = '\x01', sign_count = 0, stale_at = NULL WHERE user_id = '` + a.User.String() + `'`,
		`UPDATE ctrlz.webauthn_credentials SET credential_id = '\x0102'`,
		`UPDATE ctrlz.webauthn_credentials SET stale_at = NULL`,
	} {
		if !h.denied("admin", &aGUC, sql) {
			t.Errorf("ctrlz_admin could run %.60q", sql)
		}
	}

	// What it may still do is scoped by the setting: revoke A's sessions and
	// refresh tokens through the function, and none of B's.
	h.inTx(h.super, "admin", &aGUC, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, "SELECT ctrlz_fn.admin_revoke_user_sessions($1)", b.User).Scan(&n); err != nil || n != 0 {
			t.Errorf("B's user under A's setting: %d sessions revoked, %v", n, err)
		}
		if err := tx.QueryRow(h.ctx, "SELECT ctrlz_fn.admin_revoke_user_sessions($1)", a.User).Scan(&n); err != nil || n == 0 {
			t.Errorf("A's user under A's setting: %d sessions revoked, %v", n, err)
		}
		asSuper(h, tx, "admin", func() {
			for _, table := range []string{"sessions", "refresh_tokens"} {
				if got, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz."+table+" WHERE revoked_at IS NULL AND user_id = $1", a.User); err != nil || got != 0 {
					t.Errorf("%s of A still live after the revoke: %d, %v", table, got, err)
				}
				if got, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz."+table+" WHERE revoked_at IS NULL AND user_id = $1", b.User); err != nil || got == 0 {
					t.Errorf("%s of B were revoked by a call under A's setting: %d, %v", table, got, err)
				}
			}
		})
	})
}

// db-r2-4, checked and found not to be a defect: two requests for one phone and
// purpose from different networks, one from a known device and one not, count
// on different phone and network keys, but every request that sends a message
// also counts on the global key 'all', and the cooldown is read after that
// bump. The global counter row lock is therefore held by the first request until
// its transaction ends, and the second one meets its challenge. (A decoy skips
// the global key, and sends nothing.) This test pins that: if a sending request
// ever stops counting on a row shared with every other, two messages go out
// inside the cooldown and this fails.
func TestOTPCooldownHoldsAcrossTrustedAndUntrusted(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	issue := func(ctx context.Context, tx pgx.Tx, ip string, trusted bool) bool {
		var ok bool
		var id *string
		err := tx.QueryRow(ctx, "SELECT id::text, allowed FROM ctrlz_fn.auth_otp_issue('+989121234567', 'login', '\x0a0b', '\x0c'::bytea, $1::inet, $2)",
			ip, trusted).Scan(&id, &ok)
		if err != nil {
			t.Error(err)
		}
		return ok
	}
	begin := func(conn *pgx.Conn) pgx.Tx {
		tx, err := conn.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tx.Rollback(context.Background()) })
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	tx1, tx2 := begin(h.super), begin(h.fresh())

	if !issue(h.ctx, tx1, "198.51.100.7", false) {
		t.Fatal("the first request was refused")
	}
	// The second request, from another /24 and a trusted device, starts while the
	// first has not committed.
	type result struct{ ok bool }
	done := make(chan result, 1)
	go func() { done <- result{issue(h.ctx, tx2, "203.0.113.9", true)} }()
	select {
	case r := <-done:
		t.Fatalf("the second request ran past the first one's counter lock (allowed=%v)", r.ok)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx1.Commit(h.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.ok {
			t.Fatal("two messages went out inside the cooldown")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the second request never finished after the first committed")
	}
}

// Review round 2, admin-r2-5. The second-factor columns of users: ctrlz_admin
// may open WithTenant on any tenant, so UPDATE on totp_enabled_at or
// enforce_passkey lets it switch off a victim's second factor before a phished
// password is tried. ctrlz_admin has no UPDATE on users at all; declare-lost
// declare-lost is the key tool role's (ctrlz_fn.keytool_totp_declare_lost, 0017).
func TestAdminCannotSwitchOffASecondFactor(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aGUC := a.Tenant.String()

	if len(h.columns["users"]) == 0 {
		t.Fatal("no columns for users")
	}
	var tableLevel bool
	if err := h.super.QueryRow(h.ctx, "SELECT has_table_privilege('ctrlz_admin', 'ctrlz.users', 'UPDATE')").Scan(&tableLevel); err != nil {
		t.Fatal(err)
	}
	if tableLevel {
		t.Error("ctrlz_admin has table-level UPDATE on users")
	}
	for _, col := range h.columns["users"] {
		var ok bool
		if err := h.super.QueryRow(h.ctx, "SELECT has_column_privilege('ctrlz_admin', 'ctrlz.users', $1, 'UPDATE')", col).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("ctrlz_admin can UPDATE users.%s", col)
		}
	}
	for _, sql := range []string{
		`UPDATE ctrlz.users SET totp_enabled_at = NULL WHERE id = '` + a.User.String() + `'`,
		`UPDATE ctrlz.users SET totp_secret_ct = '\x01'`,
		`UPDATE ctrlz.users SET totp_last_step = NULL`,
		`UPDATE ctrlz.users SET enforce_passkey = false`,
		`UPDATE ctrlz.users SET password_hash = '$argon2id$x'`,
	} {
		if !h.denied("admin", &aGUC, sql) {
			t.Errorf("ctrlz_admin could run %.60q", sql)
		}
	}

	// The function that clears a user's TOTP is the key tool's, not the admin's or the worker's
	// (review round 3, db-r3-1 and db-r3-5): a call is as good as an UPDATE for the
	// attack, and the tenant setting is a GUC that any session can set. Every other
	// role is refused too, and the old admin function is gone.
	for _, u := range []uuid.UUID{a.User, b.User} {
		if _, err := h.super.Exec(h.ctx, `UPDATE ctrlz.users SET totp_secret_ct = `+declaredLostCT(1)+`, totp_enabled_at = now(), totp_last_step = 7, enforce_passkey = true WHERE id = $1`, u); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{"admin", "tenant", "compiler", "hub", "worker"} {
		if !h.denied(role, &aGUC, `SELECT ctrlz_fn.keytool_totp_declare_lost(1, ARRAY[gen_random_uuid()], ARRAY['\x435a010001'::bytea])`) {
			t.Errorf("role %s can execute keytool_totp_declare_lost", role)
		}
	}
	var gone bool
	if err := h.super.QueryRow(h.ctx, "SELECT NOT EXISTS (SELECT 1 FROM pg_proc WHERE pronamespace = 'ctrlz_fn'::regnamespace AND proname = 'admin_totp_declare_lost')").Scan(&gone); err != nil || !gone {
		t.Errorf("admin_totp_declare_lost still exists: %v", err)
	}
	// Nothing was cleared by the refused calls.
	var left int
	if err := h.super.QueryRow(h.ctx, "SELECT count(*) FROM ctrlz.users WHERE totp_enabled_at IS NOT NULL AND totp_secret_ct IS NOT NULL").Scan(&left); err != nil || left < 2 {
		t.Errorf("%d users keep their second factor after the refused calls (err %v), want at least both", left, err)
	}
	// The key tool's call leaves enforce_passkey alone.
	h.inTx(h.super, "keytool", &aGUC, func(tx pgx.Tx) {
		var n int
		// The tool lists the seed it could not open (admin-r13-3): A's, whose ciphertext is the planted one.
		if err := tx.QueryRow(h.ctx, "SELECT ctrlz_fn.keytool_totp_declare_lost(1, ARRAY[$1]::uuid[], ARRAY["+declaredLostCT(1)+"])", a.User).Scan(&n); err != nil || n != 1 {
			t.Fatalf("under A's setting: cleared %d, err %v, want 1", n, err)
		}
		asSuper(h, tx, "keytool", func() {
			var enforce bool
			if err := tx.QueryRow(h.ctx, "SELECT enforce_passkey FROM ctrlz.users WHERE id = $1", a.User).Scan(&enforce); err != nil || !enforce {
				t.Errorf("enforce_passkey after declare-lost: %v %v; the function must not touch it", enforce, err)
			}
		})
	})
}
