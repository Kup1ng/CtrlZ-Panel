package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/credstate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestCredentialStateEdges is the database half of the one-time-state rule (spec 4.4,
// 10.1, 10.3, 10.7; internal/auth/credstate). Every transition is a definer function; this
// puts a row in each state as the owner, runs each function from it, and compares what
// happened with credstate.Edges: refused where the table has no edge, and ending in one of
// the states the table names where it has. It also pins the lifetimes the functions
// hard-code to the Go constants, and shows the state on the database clock.

type adminRow struct {
	name  string
	state credstate.State // what credential_state must say of the row
	set   string          // SQL that puts the seed admin in it
}

// adminRows gives each state, and the variants of a state that the four words do not tell
// apart (an authenticator enrolled or pending, a chosen password past its hour).
func adminRows() []adminRow {
	const base = "UPDATE ctrlz.admin_users SET "
	return []adminRow{
		{"live, no authenticator", credstate.OneTimeLive, base + "must_change_password = true, password_expires_at = now() + interval '1 hour', totp_secret_ct = 'ct', totp_enabled_at = NULL"},
		{"live, authenticator enrolled (after reset-password)", credstate.OneTimeLive, base + "must_change_password = true, password_expires_at = now() + interval '1 hour', totp_secret_ct = 'ct', totp_enabled_at = now()"},
		{"expired console password", credstate.OneTimeExpired, base + "must_change_password = true, password_expires_at = now() - interval '1 minute', totp_secret_ct = 'ct', totp_enabled_at = NULL"},
		{"chosen password past its hour", credstate.OneTimeExpired, base + "must_change_password = false, password_expires_at = now() - interval '1 minute', totp_secret_ct = 'ct', totp_enabled_at = NULL"},
		{"chosen, no authenticator", credstate.ChosenNoSecondFactor, base + "must_change_password = false, password_expires_at = now() + interval '30 minutes', totp_secret_ct = 'ct', totp_enabled_at = NULL"},
		{"ready", credstate.Ready, base + "must_change_password = false, password_expires_at = NULL, totp_secret_ct = 'ct', totp_enabled_at = now()"},
	}
}

func contains(set []credstate.State, s credstate.State) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

func TestCredentialStateEdges(t *testing.T) {
	f := newFixture(t)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	super := f.superConn(t)
	id := edgeAdmin

	read := func(g store.GlobalTx) credstate.State {
		u, ok, err := g.AdminUserByID(id)
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		return u.State
	}

	for _, row := range adminRows() {
		// Each transition from this row. A function that refuses leaves the row alone.
		type step struct {
			tr  credstate.Transition
			run func(g store.GlobalTx) (ok bool, err error)
		}
		steps := []step{
			{credstate.AdminSetPass, func(g store.GlobalTx) (bool, error) {
				_, ok, err := g.AdminSetPassword(id, secret.New("chosen-hash"))
				return ok, err
			}},
			{credstate.AdminTOTPEnable, func(g store.GlobalTx) (bool, error) {
				_, ok, err := g.AdminTOTPEnable(id, 9)
				return ok, err
			}},
			{credstate.AdminReset, func(g store.GlobalTx) (bool, error) { return g.AdminReset(id, secret.New("otp-hash"), false) }},
			{credstate.AdminResetTOTP, func(g store.GlobalTx) (bool, error) { return g.AdminReset(id, secret.New("otp-hash"), true) }},
			{credstate.AdminBootstrap, func(g store.GlobalTx) (bool, error) {
				_, ok, err := g.AdminBootstrap("second", secret.New("h"))
				return ok, err
			}},
		}
		for _, s := range steps {
			if _, err := super.Exec(f.ctx, row.set+" WHERE id = $1", id); err != nil {
				t.Fatal(err)
			}
			f.global(t, admin, func(g store.GlobalTx) {
				if got := read(g); got != row.state {
					t.Fatalf("%s: credential_state says %s, the row was built as %s", row.name, got, row.state)
				}
			})
			var ran bool
			var after credstate.State
			// The bootstrap function refuses any isolation but SERIALIZABLE (db-r7-1); the other
			// edges run as the routes run them.
			opts := store.TxOpts{}
			if s.tr == credstate.AdminBootstrap {
				opts.Isolation = store.Serializable
			}
			err := admin.WithGlobal(f.ctx, opts, func(g store.GlobalTx) error {
				ok, err := s.run(g)
				if err != nil {
					return err
				}
				ran = ok
				after = read(g)
				return nil
			})
			if err != nil {
				t.Fatalf("%s from %s: %v", s.tr, row.name, err)
			}
			edge := credstate.Edges()[s.tr]
			if ran != edge.From[row.state] {
				// AdminTOTPEnable also needs a pending secret and no authenticator: a "live,
				// authenticator enrolled" row has nothing to enrol whatever the state says.
				if s.tr == credstate.AdminTOTPEnable && row.name == "live, authenticator enrolled (after reset-password)" && !ran {
					continue
				}
				t.Errorf("%s from %s (%s): ran %v, the table says %v", s.tr, row.name, row.state, ran, edge.From[row.state])
				continue
			}
			if ran && !contains(edge.To[row.state], after) {
				t.Errorf("%s from %s (%s) ended in %s, the table allows %v", s.tr, row.name, row.state, after, edge.To[row.state])
			}
			if !ran && after != row.state {
				t.Errorf("%s from %s was refused and still moved the row to %s", s.tr, row.name, after)
			}
		}
	}

	// The lifetimes the functions hard-code are the Go constants.
	f.global(t, admin, func(g store.GlobalTx) {
		if ok, err := g.AdminReset(id, secret.New("otp-hash"), false); err != nil || !ok {
			t.Fatal(ok, err)
		}
	})
	if d := f.expiresIn(t, "SELECT password_expires_at - now() FROM ctrlz.admin_users WHERE id = $1", id); d > password.AdminOneTimeLife || d < password.AdminOneTimeLife-time.Minute {
		t.Errorf("a console reset lives %v, password.AdminOneTimeLife is %v", d, password.AdminOneTimeLife)
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.admin_users SET totp_enabled_at = NULL WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	f.global(t, admin, func(g store.GlobalTx) {
		if _, ok, err := g.AdminSetPassword(id, secret.New("mine")); err != nil || !ok {
			t.Fatal(ok, err)
		}
	})
	if d := f.expiresIn(t, "SELECT password_expires_at - now() FROM ctrlz.admin_users WHERE id = $1", id); d > time.Hour || d < time.Hour-time.Minute {
		t.Errorf("a chosen password without an authenticator lives %v, want an hour", d)
	}
	reg, ok, err := admin.Admin().CreateUser(f.ctx, "+989121110077", secret.New("h"), "fa")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if d := f.expiresIn(t, "SELECT password_expires_at - now() FROM ctrlz.users WHERE id = $1", reg.UserID); d > password.UserOneTimeLife || d < password.UserOneTimeLife-time.Minute {
		t.Errorf("a created user's one-time password lives %v, password.UserOneTimeLife is %v", d, password.UserOneTimeLife)
	}
}

// TestUserCredentialStateEdges is the same for the tenant side, with two tenants: the
// functions act on the tenant of the transaction and on nobody else.
func TestUserCredentialStateEdges(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	super := f.superConn(t)

	rows := []struct {
		name  string
		state credstate.State
		set   string
	}{
		{"live", credstate.OneTimeLive, "must_reset = true, password_expires_at = now() + interval '1 hour'"},
		{"expired", credstate.OneTimeExpired, "must_reset = true, password_expires_at = now() - interval '1 minute'"},
		{"ready", credstate.Ready, "must_reset = false, password_expires_at = NULL"},
	}
	stateOf := func(user uuid.UUID, tn uuid.UUID) credstate.State {
		var st credstate.State
		f.inTenant(t, tenant, tn, func(tx store.Tx) {
			u, ok, err := tx.User(user)
			if err != nil || !ok {
				t.Fatal(ok, err)
			}
			st = u.State
		})
		return st
	}
	for _, row := range rows {
		reset := func() {
			// Both tenants' users are put in the same state, so a leak between tenants shows.
			for _, u := range []uuid.UUID{f.A.User, f.B.User} {
				// No second factor, which is what makes a one-time password eligible for a
				// re-issue (10.7); the seed users have a TOTP.
				if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.webauthn_credentials WHERE user_id = $1", u); err != nil {
					t.Fatal(err)
				}
				if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET totp_enabled_at = NULL, totp_secret_ct = NULL, enforce_passkey = false, "+row.set+" WHERE id = $1", u); err != nil {
					t.Fatal(err)
				}
			}
			if got := stateOf(f.A.User, f.A.Tenant); got != row.state {
				t.Fatalf("%s: credential_state says %s", row.name, got)
			}
		}

		// UserSetPassword.
		reset()
		edge := credstate.Edges()[credstate.UserSetPassword]
		var ok bool
		f.inTenant(t, tenant, f.A.Tenant, func(tx store.Tx) {
			var err error
			if ok, err = tx.SetPassword(f.A.User, secret.New("new-hash")); err != nil {
				t.Fatal(err)
			}
		})
		if ok != edge.From[row.state] {
			t.Errorf("set password from %s: ran %v, the table says %v", row.name, ok, edge.From[row.state])
		}
		if after := stateOf(f.A.User, f.A.Tenant); ok && !contains(edge.To[row.state], after) {
			t.Errorf("set password from %s ended in %s", row.name, after)
		}
		// Two tenants: B's user is untouched by A's change, and A's transaction cannot name B's user.
		if got := stateOf(f.B.User, f.B.Tenant); got != row.state {
			t.Errorf("tenant B's user moved from %s to %s when tenant A changed a password", row.state, got)
		}
		reset()
		f.inTenant(t, tenant, f.A.Tenant, func(tx store.Tx) {
			if ok, err := tx.SetPassword(f.B.User, secret.New("hijack")); err != nil || ok {
				t.Errorf("tenant A set tenant B's user's password from %s: %v %v", row.name, ok, err)
			}
		})
		if got := stateOf(f.B.User, f.B.Tenant); got != row.state {
			t.Errorf("tenant B's user moved from %s to %s", row.state, got)
		}

		// UserReissue, as the admin on the tenant of the path.
		reset()
		edge = credstate.Edges()[credstate.UserReissue]
		var outcome string
		if err := admin.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			r, err := tx.OneTimePasswordReissue(f.A.User, secret.New("otp-2"))
			outcome = r.Outcome
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if (outcome == "ok") != edge.From[row.state] {
			t.Errorf("re-issue from %s: outcome %q, the table says %v", row.name, outcome, edge.From[row.state])
		}
		if after := stateOf(f.A.User, f.A.Tenant); outcome == "ok" && !contains(edge.To[row.state], after) {
			t.Errorf("re-issue from %s ended in %s", row.name, after)
		}
		if outcome != "ok" && stateOf(f.A.User, f.A.Tenant) != row.state {
			t.Errorf("a refused re-issue from %s moved the row", row.name)
		}
		if err := admin.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, err := tx.OneTimePasswordSet(f.B.User, secret.New("hijack"))
			if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("re-issue of tenant B's user from tenant A's transaction: %v", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The tenant role cannot move the state with a statement of its own: it holds no UPDATE
	// on the columns, so the definer function is the only way.
	for _, sql := range []string{
		"UPDATE ctrlz.users SET must_reset = false WHERE id = $1",
		"UPDATE ctrlz.users SET password_expires_at = NULL WHERE id = $1",
		"UPDATE ctrlz.users SET password_changed_at = now() WHERE id = $1",
	} {
		// One transaction each: a refused statement aborts its transaction.
		_ = tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, err := tx.DB().Exec(tx.Context(), sql, f.A.User)
			if err == nil {
				t.Errorf("the tenant role ran %q", sql)
			}
			return err
		})
	}
}

// edgeAdmin is the admin the global seed makes (catalogtest.SeedGlobal).
var edgeAdmin = uuid.MustParse("00000000-0000-7000-8000-0000000000e1")
