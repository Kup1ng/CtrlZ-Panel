package adminapi

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestARehashNeverOverwritesAPasswordThatChangedMeanwhile is admin-r10-1. The rehash of a hash made
// under older Argon2 parameters runs after the login committed and after Hash spent 100 to 500 ms
// under the gate. A console reset (`ctrlz-admin reset-password`) or the admin's own password change
// that commits in that window must win: the write compares credential_gen and comes back stale,
// and the browser gets no device marker for credentials that no longer exist. Without the compare
// the hash of the OLD password lands over the new one, so the old password works again as the live
// console one-time password, or a change made after a suspected compromise is reverted, and the
// only trace is a generation bump. The seam stands for the other writer and commits between the
// hash and its write; the tenant side has the same case in login's
// TestRehashIsStoredUnlessThePasswordChangedMeanwhile.
func TestARehashNeverOverwritesAPasswordThatChangedMeanwhile(t *testing.T) {
	const changedPW = "A-completely-different-1-password"
	old, err := password.NewHasher(password.Params{MemoryKiB: 96, Time: 1, Threads: 1}, password.NewGate(2, 5*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		pw   string
		// change is what the other writer commits in the gap and returns the hash it stored.
		change func(t *testing.T, r *rig) secret.String
	}{
		{"console reset-password", oneTimeShaped, func(t *testing.T, r *rig) secret.String {
			one, err := r.hasher.HashOneTime(secret.New(oneTimeShaped))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.deps.Store.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
				if _, ok, err := g.AdminUserLockByID(seedAdmin); err != nil || !ok {
					t.Fatalf("lock: %v %v", ok, err)
				}
				if ok, err := g.AdminReset(seedAdmin, one, false); err != nil || !ok {
					t.Fatalf("reset: %v %v", ok, err)
				}
				_, err := g.AdminSessionsRevokeOthers(seedAdmin, uuid.Nil)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			return one
		}},
		{"the admin's own password change", changedPW, func(t *testing.T, r *rig) secret.String {
			h, err := r.hasher.Hash(r.env.Ctx, secret.New(changedPW))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.deps.Store.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
				if _, ok, err := g.AdminSetPassword(seedAdmin, h); err != nil || !ok {
					t.Fatalf("set password: %v %v", ok, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			return h
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			seed := r.setupAdmin(t, true)
			oldHash, err := old.Hash(r.env.Ctx, secret.New(adminPW))
			if err != nil {
				t.Fatal(err)
			}
			setOld := func() {
				r.env.Exec(t, `UPDATE ctrlz.admin_users SET password_hash = $2, must_change_password = false,
				  password_expires_at = NULL WHERE id = $1`, seedAdmin, oldHash.Reveal())
				r.freeStep(t)
				r.clearAdminThrottle(t)
			}
			stored := func() secret.String {
				var h string
				r.env.Scan(t, `SELECT password_hash FROM ctrlz.admin_users WHERE id = $1`, []any{seedAdmin}, &h)
				return secret.New(h)
			}

			// Control: nobody interferes, the rehash lands and the browser gets its marker. A seam
			// that never ran, or a login that never reaches the rehash, would make the case below
			// pass for the wrong reason.
			setOld()
			fired := 0
			quiet := r.handler(t, func(d *Deps) { d.rehashGap = func() { fired++ } })
			b := r.browser()
			b.callOn(quiet, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": adminPW, "totp_code": totpNow(seed)}).want(200, "")
			if fired != 1 {
				t.Fatalf("the seam ran %d times in the control: the login does not reach the rehash", fired)
			}
			if r.hasher.NeedsRehash(stored()) {
				t.Fatal("control: the hash was not replaced")
			}
			if b.jar[session.CookieAdminDevice] == nil {
				t.Fatal("control: a rehashing login left no device marker")
			}

			// The other writer commits between the hash and its write.
			setOld()
			var theirs secret.String
			racing := r.handler(t, func(d *Deps) { d.rehashGap = func() { theirs = tc.change(t, r) } })
			b = r.browser()
			b.callOn(racing, adminHost, "POST", "/auth/login", map[string]any{"username": adminName, "password": adminPW, "totp_code": totpNow(seed)}).want(200, "")
			if theirs.IsZero() {
				t.Fatal("the seam did not run: the test proves nothing")
			}
			if got := stored(); got.Reveal() != theirs.Reveal() {
				t.Fatal("the rehash of the old password overwrote the hash that was stored after the login")
			}
			if ok, err := r.hasher.Verify(r.env.Ctx, secret.New(adminPW), stored()); err != nil || ok {
				t.Fatalf("the old password verifies again: %v %v", ok, err)
			}
			if ok, err := r.hasher.Verify(r.env.Ctx, secret.New(tc.pw), stored()); err != nil || !ok {
				t.Fatalf("the new password no longer verifies: %v %v", ok, err)
			}
			if b.jar[session.CookieAdminDevice] != nil {
				t.Error("a device marker was issued for credentials that no longer exist")
			}
			r.freeStep(t)
			r.clearAdminThrottle(t)
			r.browser().login(adminPW, totpNow(seed)).want(401, "invalid_credentials")
		})
	}
}
