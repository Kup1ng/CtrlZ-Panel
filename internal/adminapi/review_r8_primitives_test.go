package adminapi

import (
	"testing"

	"github.com/google/uuid"
)

// TestAnUnreadableStoredAdminHashIsAWrongPasswordOnBothRoutes is primitives-r8-5, the admin half. The
// two routes that verify an admin password (POST /auth/login and POST /me/password) each used to map
// the primitive's ErrMalformed by hand, and only the tenant reauth had a test. The mapping is inside
// Hasher.Verify/VerifyGateFree now; this holds both admin routes to it with a damaged hash and with
// one above the Argon2 ceiling (an operator lowered the budget): a plain 401 invalid_credentials, no
// 500, and a second admin's row is not touched.
func TestAnUnreadableStoredAdminHashIsAWrongPasswordOnBothRoutes(t *testing.T) {
	for name, stored := range map[string]string{
		"damaged":   "not-a-hash",
		"oversized": "$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.setupAdmin(t, false)
			owner := r.browser()
			owner.login(adminPW, "").want(200, "")
			other := uuid.MustParse("00000000-0000-7000-8000-0000000000e2")
			r.env.Exec(t, `INSERT INTO ctrlz.admin_users (id, username, password_hash) VALUES ($1, 'second-admin', 'x')`, other)
			r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2 WHERE id = $1`, seedAdmin, stored)

			before := r.hasher.Unreadable()
			r.browser().login(adminPW, "").want(401, "invalid_credentials")
			owner.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW}).want(401, "invalid_credentials")
			if got := r.hasher.Unreadable() - before; got != 2 {
				t.Errorf("the hasher counted %d unreadable hashes, want 2 (one per route)", got)
			}
			var hash string
			r.env.Scan(t, `SELECT password_hash FROM ctrlz.admin_users WHERE id = $1`, []any{other}, &hash)
			if hash != "x" {
				t.Error("the second admin's row changed")
			}
		})
	}
}
