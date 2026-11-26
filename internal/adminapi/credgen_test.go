package adminapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// Rule credential-generation (P1 auth review round 5, topic 5), the admin half. See
// internal/api/credgen_test.go for the idea: the owner changes each credential column
// of migrations/catalog/guarded.yaml behind the application's back, and an artefact
// derived from a first-factor check before the change is refused after it. The admin
// has two such artefacts: a password-and-code login that is waiting for the row lock
// (admin-r3-2, the whole check was missing for the admin before), and the device
// marker (admin-r3-14, admin-r4-4).
//
// The marker is observed through what it exists for: a request that carries a known
// marker is not counted on the admin_login_user scope.

type adminSnapshot struct {
	username    string
	hash        string
	changed     *time.Time
	expires     *time.Time
	must        bool
	seed        []byte
	totpEnabled *time.Time
	disabled    *time.Time
}

func (r *rig) snapshotAdmin(t *testing.T) adminSnapshot {
	t.Helper()
	var s adminSnapshot
	r.env.Scan(t, `SELECT username, password_hash, password_changed_at, password_expires_at, must_change_password, totp_secret_ct,
  totp_enabled_at, disabled_at FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin},
		&s.username, &s.hash, &s.changed, &s.expires, &s.must, &s.seed, &s.totpEnabled, &s.disabled)
	return s
}

func (r *rig) restoreAdmin(t *testing.T, s adminSnapshot) {
	t.Helper()
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET username = $2, password_hash = $3, password_changed_at = $4, password_expires_at = $5,
  must_change_password = $6, totp_secret_ct = $7, totp_enabled_at = $8, disabled_at = $9 WHERE id = $1`,
		seedAdmin, s.username, s.hash, s.changed, s.expires, s.must, s.seed, s.totpEnabled, s.disabled)
}

func (r *rig) holdUpdate(t *testing.T, sql string, args ...any) (release func()) {
	t.Helper()
	conn, err := r.env.DB.Super(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(r.env.Ctx, sql, args...); err != nil {
		t.Fatalf("held change: %v", err)
	}
	return func() {
		if err := tx.Commit(r.env.Ctx); err != nil {
			t.Errorf("commit held change: %v", err)
		}
		_ = conn.Close(r.env.Ctx)
	}
}

func (r *rig) waitBlocked(t *testing.T) {
	t.Helper()
	testwait.UntilEvery(t, 20*time.Second, 25*time.Millisecond, "a request to wait for a row lock (the test proves nothing without one)", func() bool {
		return r.count(t, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`) > 0
	})
}

func TestCredentialGenerationRefusesEveryAdminArtefact(t *testing.T) {
	r := newRig(t)
	seed := r.setupAdmin(t, true)
	orig := r.snapshotAdmin(t)
	const otherName = "renamed-admin"

	cases := []struct{ column, change string }{
		{"username", `username = '` + otherName + `'`},
		{"password_hash", `password_hash = 'not-the-old-hash'`},
		{"password_changed_at", `password_changed_at = now()`},
		{"password_expires_at", `password_expires_at = now() + interval '72 hours'`},
		{"must_change_password", `must_change_password = true`},
		// totp_secret_ct is not here on purpose (db-r6-4): with totp_enabled_at set and unchanged a
		// different ciphertext is a re-seal of the same second factor and keeps every artefact
		// (internal/store/catalogtest TestCredentialGenIgnoresAReSealOfTheSeedInForce, and the
		// rekey test of internal/admincli); the factor changing is totp_enabled_at, below.
		{"totp_enabled_at", `totp_enabled_at = now() - interval '1 day'`},
		{"disabled_at", `disabled_at = now()`},
	}
	spent := func() int {
		return r.count(t, `SELECT count(*) FROM ctrlz.auth_throttle WHERE scope = 'admin_login_user'`)
	}
	for _, tc := range cases {
		t.Run(tc.column, func(t *testing.T) {
			name := adminName
			reset := func() {
				r.restoreAdmin(t, orig)
				r.clearAdminThrottle(t)
				r.freeStep(t)
			}

			// 1. A marker made under the credentials as they are.
			reset()
			home := r.browser()
			home.mustLogin(seed)
			marker := home.jar[session.CookieAdminDevice]
			if marker == nil {
				t.Fatal("a login left no device marker")
			}
			probe := func(as string) int {
				t.Helper()
				r.clearAdminThrottle(t)
				b := r.browser()
				b.jar[session.CookieAdminDevice] = &http.Cookie{Name: session.CookieAdminDevice, Value: marker.Value}
				b.post("/auth/login", map[string]any{"username": as, "password": "wrong-wrong-wrong-1"})
				return spent()
			}
			if got := probe(name); got != 0 {
				t.Fatalf("control: a fresh marker counted on admin_login_user (%d)", got)
			}

			// 2. The owner changes the column.
			r.env.Exec(t, `UPDATE ctrlz.admin_users SET `+tc.change+` WHERE id = $1`, seedAdmin)
			if tc.column == "username" {
				name = otherName
			}
			if got := probe(name); got != 1 {
				t.Errorf("a marker issued before the change of %s is still a known device (admin_login_user rows %d, want 1)", tc.column, got)
			}

			// 3. A login that verified the old credentials and waits for the lock.
			reset()
			release := r.holdUpdate(t, `UPDATE ctrlz.admin_users SET `+tc.change+` WHERE id = $1`, seedAdmin)
			done := make(chan *aresp, 1)
			go func() { done <- r.browser().login(adminPW, totpNow(seed)) }()
			r.waitBlocked(t)
			release()
			res := <-done
			if res.Code != http.StatusUnauthorized || res.errCode() != "invalid_credentials" {
				t.Errorf("a login that verified the credentials before the change of %s: %d %s, want 401 invalid_credentials", tc.column, res.Code, res.Body)
			}
		})
	}
	r.restoreAdmin(t, orig)
}
