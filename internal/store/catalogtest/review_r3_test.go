package catalogtest_test

import (
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Review round 3, db-r3-6. A column grant cannot limit the value written, so
// UPDATE (revoked_at) lets ctrlz_admin set revoked_at = NULL and bring back a
// session or refresh token that "log out all", a password change or a refresh
// reuse had revoked. Revoked rows stay until their expiry. The trigger
// revocation_stays makes revocation one way for every role, so the stolen cookie
// of a victim stays dead whoever asks.
func TestRevocationIsOneWay(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aGUC, bGUC := a.Tenant.String(), b.Tenant.String()

	tables := []string{"sessions", "refresh_tokens", "api_tokens"}
	// A's user has logged out everywhere; B's has not.
	for _, table := range tables {
		if _, err := h.super.Exec(h.ctx, "UPDATE ctrlz."+table+" SET revoked_at = now() WHERE user_id = $1", a.User); err != nil {
			t.Fatalf("revoke %s: %v", table, err)
		}
	}
	revoked := func(table string, tenantID string) int {
		var n int
		if err := h.super.QueryRow(h.ctx, "SELECT count(*) FROM ctrlz."+table+" WHERE tenant_id = $1 AND revoked_at IS NOT NULL", tenantID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := map[string]int{}
	for _, table := range tables {
		before[table] = revoked(table, aGUC)
		if before[table] == 0 {
			t.Fatalf("the seed has no %s row for A to revoke", table)
		}
	}

	type attempt struct {
		role   string
		tables []string
	}
	// The admin role holds UPDATE (revoked_at) on the first two; the tenant role on
	// all three. A role without the grant is refused for another reason, which is
	// the existing grant test's business.
	for _, at := range []attempt{{"admin", tables[:2]}, {"tenant", tables}} {
		for _, table := range at.tables {
			for _, sql := range []string{
				"UPDATE ctrlz." + table + " SET revoked_at = NULL WHERE user_id = '" + a.User.String() + "'",
				"UPDATE ctrlz." + table + " SET revoked_at = NULL",
				// A different value is a change too: later or earlier, it is not the instant
				// the revocation was made.
				"UPDATE ctrlz." + table + " SET revoked_at = now() + interval '30 days'",
				"UPDATE ctrlz." + table + " SET revoked_at = now() - interval '30 days' WHERE user_id = '" + a.User.String() + "'",
			} {
				if !h.denied(at.role, &aGUC, sql) {
					t.Errorf("%s could run %.80q", at.role, sql)
				}
			}
		}
	}
	for _, table := range tables {
		if got := revoked(table, aGUC); got != before[table] {
			t.Errorf("%s: %d revoked rows of A after the attempts, was %d", table, got, before[table])
		}
	}

	// What stays allowed: revoking a live row, once, through the admin's function
	// (which touches only live rows, so a repeat is a no-op and not a failure).
	h.inTx(h.super, "admin", &bGUC, func(tx pgx.Tx) {
		var n int
		if err := tx.QueryRow(h.ctx, "SELECT ctrlz_fn.admin_revoke_user_sessions($1)", b.User).Scan(&n); err != nil || n == 0 {
			t.Errorf("admin revoke of B's sessions: %d, %v", n, err)
		}
		if err := tx.QueryRow(h.ctx, "SELECT ctrlz_fn.admin_revoke_user_sessions($1)", b.User).Scan(&n); err != nil || n != 0 {
			t.Errorf("a repeat of the admin revoke: %d, %v", n, err)
		}
	})
	h.inTx(h.super, "tenant", &bGUC, func(tx pgx.Tx) {
		tag, err := tx.Exec(h.ctx, "UPDATE ctrlz.api_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", b.User)
		if err != nil || tag.RowsAffected() == 0 {
			t.Errorf("B revoking its own API token: %d rows, %v", tag.RowsAffected(), err)
		}
	})
	// The other tenant's rows are untouched by A's attempts and by B's revokes.
	if got := revoked("sessions", aGUC); got != before["sessions"] {
		t.Errorf("A's revoked sessions changed to %d", got)
	}
}
