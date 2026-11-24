package catalogtest_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Rule credential-generation (P1 auth review round 5, topic 5), the database half.
//
// recipe is how a test changes one column of a row, from a state in which the change
// is legal (the one-time password CHECK ties password_expires_at to must_reset).
type recipe struct{ arrange, change string }

// userRecipes and adminRecipes cover every credential column of guarded.yaml. A column
// added to credential_gen.*.columns without a recipe fails TestCredentialGenTrigger,
// so the trigger test cannot fall behind the list.
var userRecipes = map[string]recipe{
	"phone_e164":          {"", "phone_e164 = '+989129990042'"},
	"password_hash":       {"", "password_hash = 'not-the-old-hash'"},
	"password_changed_at": {"", "password_changed_at = now()"},
	"password_expires_at": {"must_reset = true, password_expires_at = now()", "password_expires_at = now() + interval '1 hour'"},
	"must_reset":          {"", "must_reset = true"},
	"totp_secret_ct":      {"", "totp_secret_ct = '\\x01'::bytea"},
	"totp_enabled_at":     {"", "totp_enabled_at = now()"},
	"enforce_passkey":     {"", "enforce_passkey = true"},
	"enforce_lift_at":     {"", "enforce_lift_at = now()"},
}

var adminRecipes = map[string]recipe{
	"username":             {"", "username = 'renamed'"},
	"password_hash":        {"", "password_hash = 'not-the-old-hash'"},
	"password_changed_at":  {"", "password_changed_at = now()"},
	"password_expires_at":  {"", "password_expires_at = now()"},
	"must_change_password": {"", "must_change_password = false"},
	"totp_secret_ct":       {"", "totp_secret_ct = '\\x01'::bytea"},
	"totp_enabled_at":      {"", "totp_enabled_at = now()"},
	"disabled_at":          {"", "disabled_at = now()"},
}

// untouched are columns of the same rows that are not credentials: writing them is the
// ordinary traffic of a login or a settings page and must not end any artefact.
var untouched = map[string][]string{
	"users": {"last_login_at = now()", "totp_last_step = 5", "phone_verified_at = now()", "totp_pending_at = now()",
		"passkey_review_at = now()", "locale = 'en'", "theme = 'dark'", "onboarding_state = '{\"x\":1}'"},
	"admin_users": {"last_login_at = now()", "totp_last_step = 5", "pending_notice = '{}'::jsonb"},
}

func TestCredentialGenTrigger(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	const adminID = "00000000-0000-7000-8000-0000000000e1"
	type subject struct {
		table, id, control string
		recipes            map[string]recipe
	}
	for _, s := range []subject{
		{"users", h.A.User.String(), h.B.User.String(), userRecipes},
		{"admin_users", adminID, "", adminRecipes},
	} {
		spec := h.fx.Guarded.CredentialGen[s.table]
		listed := append([]string(nil), spec.Columns...)
		sort.Strings(listed)
		gen := func(tx catalogtest.Querier, id string) int64 {
			t.Helper()
			var g int64
			if err := tx.QueryRow(h.ctx, `SELECT credential_gen FROM ctrlz.`+s.table+` WHERE id = $1`, id).Scan(&g); err != nil {
				t.Fatal(err)
			}
			return g
		}
		for _, col := range listed {
			rc, ok := s.recipes[col]
			if !ok {
				t.Errorf("%s.%s is a credential column of guarded.yaml and this test has no way to change it: add a recipe", s.table, col)
				continue
			}
			t.Run(s.table+"."+col, func(t *testing.T) {
				tx, err := h.super.Begin(h.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				exec := func(sql string) {
					t.Helper()
					if _, err := tx.Exec(h.ctx, sql, s.id); err != nil {
						t.Fatalf("%.100s: %v", sql, err)
					}
				}
				if rc.arrange != "" {
					exec(`UPDATE ctrlz.` + s.table + ` SET ` + rc.arrange + ` WHERE id = $1`)
				}
				before := gen(tx, s.id)
				var controlBefore int64
				if s.control != "" {
					controlBefore = gen(tx, s.control)
				}
				exec(`UPDATE ctrlz.` + s.table + ` SET ` + rc.change + ` WHERE id = $1`)
				if got := gen(tx, s.id); got != before+1 {
					t.Fatalf("changing %s moved credential_gen from %d to %d, want one step", col, before, got)
				}
				// Writing the same value is not a change.
				exec(`UPDATE ctrlz.` + s.table + ` SET ` + col + ` = ` + col + ` WHERE id = $1`)
				if got := gen(tx, s.id); got != before+1 {
					t.Errorf("writing %s back to what it was moved credential_gen to %d", col, got)
				}
				// Nobody sets the counter: a statement that tries is overwritten, and it
				// moves by one for a change next to it, not by the number written.
				exec(`UPDATE ctrlz.` + s.table + ` SET credential_gen = 1000 WHERE id = $1`)
				if got := gen(tx, s.id); got != before+1 {
					t.Errorf("a write to credential_gen itself moved it to %d", got)
				}
				// The other tenant's user did not move (the control of the two-tenant test).
				if s.control != "" {
					if got := gen(tx, s.control); got != controlBefore {
						t.Errorf("a change to one user moved another tenant's credential_gen from %d to %d", controlBefore, got)
					}
				}
			})
		}

		t.Run(s.table+" other columns", func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			before := gen(tx, s.id)
			for _, set := range untouched[s.table] {
				if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.`+s.table+` SET `+set+` WHERE id = $1`, s.id); err != nil {
					t.Fatalf("%s: %v", set, err)
				}
			}
			if got := gen(tx, s.id); got != before {
				t.Errorf("ordinary writes moved credential_gen from %d to %d", before, got)
			}
		})

		t.Run(s.table+" several columns at once", func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			before := gen(tx, s.id)
			var set []string
			for _, col := range listed {
				if col == "password_expires_at" || col == "must_reset" {
					continue // tied together by a CHECK; covered one by one
				}
				set = append(set, s.recipes[col].change)
			}
			if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.`+s.table+` SET `+strings.Join(set, ", ")+` WHERE id = $1`, s.id); err != nil {
				t.Fatal(err)
			}
			if got := gen(tx, s.id); got != before+1 {
				t.Errorf("one statement that changed %d credential columns moved credential_gen from %d to %d, want one step", len(set), before, got)
			}
		})

		t.Run(s.table+" a column the trigger names that does not exist", func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := tx.Exec(h.ctx, `CREATE TRIGGER zz_typo BEFORE UPDATE ON ctrlz.`+s.table+` FOR EACH ROW EXECUTE FUNCTION ctrlz.credential_gen_bump('no_such_column')`); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(h.ctx, `UPDATE ctrlz.`+s.table+` SET credential_gen = credential_gen WHERE id = $1`, s.id)
			if err == nil || !strings.Contains(err.Error(), "no_such_column") {
				t.Errorf("a typo in the trigger's columns watched nothing and said nothing: %v", err)
			}
		})
	}
}

// TestCredentialGenCheckCanFail applies, one at a time, the changes check 25 exists to
// stop. Each must be reported by the check on its own, so a check that quietly stopped
// looking would fail here (rule credential-generation, mutants of the task).
func TestCredentialGenCheckCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	run := func(sql ...string) []string {
		tx, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		for _, s := range sql {
			if _, err := tx.Exec(h.ctx, s); err != nil {
				t.Fatalf("mutation %.80q does not apply: %v", s, err)
			}
		}
		v, err := catalogtest.CheckCredentialGen(h.ctx, tx, h.fx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := run(); len(v) != 0 {
		t.Fatalf("the migrated database is not clean for check 25: %v", v)
	}
	// The trigger of users as the migration made it, with one argument left out.
	recreate := func(table, cols string) []string {
		return []string{
			`DROP TRIGGER credential_gen_bump ON ctrlz.` + table,
			`CREATE TRIGGER credential_gen_bump BEFORE UPDATE ON ctrlz.` + table + ` FOR EACH ROW EXECUTE FUNCTION ctrlz.credential_gen_bump(` + cols + `)`,
		}
	}
	for _, m := range []struct {
		name, want string
		sql        []string
	}{
		{"totp_secret_ct dropped from the users trigger", "credential_gen trigger arguments of users: missing totp_secret_ct",
			recreate("users", `'phone_e164', 'password_hash', 'password_changed_at', 'password_expires_at', 'must_reset', 'totp_enabled_at', 'enforce_passkey', 'enforce_lift_at'`)},
		{"password_changed_at dropped from the admin trigger", "credential_gen trigger arguments of admin_users: missing password_changed_at",
			recreate("admin_users", `'username', 'password_hash', 'password_expires_at', 'must_change_password', 'totp_secret_ct', 'totp_enabled_at', 'disabled_at'`)},
		{"a column that is not a credential watched", "credential_gen trigger arguments of users: unexpected last_login_at",
			recreate("users", `'phone_e164', 'password_hash', 'password_changed_at', 'password_expires_at', 'must_reset', 'totp_secret_ct', 'totp_enabled_at', 'enforce_passkey', 'enforce_lift_at', 'last_login_at'`)},
		{"the trigger is disabled", "not enabled",
			[]string{`ALTER TABLE ctrlz.users DISABLE TRIGGER credential_gen_bump`}},
		{"the trigger is dropped", "admin_users has no credential_gen trigger",
			[]string{`DROP TRIGGER credential_gen_bump ON ctrlz.admin_users`}},
		{"the trigger has a WHEN clause", "has a WHEN clause",
			[]string{`DROP TRIGGER credential_gen_bump ON ctrlz.users`,
				`CREATE TRIGGER credential_gen_bump BEFORE UPDATE ON ctrlz.users FOR EACH ROW WHEN (OLD.password_hash IS DISTINCT FROM NEW.password_hash) EXECUTE FUNCTION ctrlz.credential_gen_bump('phone_e164', 'password_hash', 'password_changed_at', 'password_expires_at', 'must_reset', 'totp_secret_ct', 'totp_enabled_at', 'enforce_passkey', 'enforce_lift_at')`}},
		{"the trigger is limited to some columns", "limited to UPDATE OF columns",
			[]string{`DROP TRIGGER credential_gen_bump ON ctrlz.users`,
				`CREATE TRIGGER credential_gen_bump BEFORE UPDATE OF password_hash ON ctrlz.users FOR EACH ROW EXECUTE FUNCTION ctrlz.credential_gen_bump('phone_e164', 'password_hash', 'password_changed_at', 'password_expires_at', 'must_reset', 'totp_secret_ct', 'totp_enabled_at', 'enforce_passkey', 'enforce_lift_at')`}},
		{"the trigger runs after the write", "has type",
			[]string{`DROP TRIGGER credential_gen_bump ON ctrlz.users`,
				`CREATE TRIGGER credential_gen_bump AFTER UPDATE ON ctrlz.users FOR EACH ROW EXECUTE FUNCTION ctrlz.credential_gen_bump('phone_e164', 'password_hash', 'password_changed_at', 'password_expires_at', 'must_reset', 'totp_secret_ct', 'totp_enabled_at', 'enforce_passkey', 'enforce_lift_at')`}},
		{"a second trigger", "has 2 credential_gen triggers",
			[]string{`CREATE TRIGGER zz_second BEFORE UPDATE ON ctrlz.users FOR EACH ROW EXECUTE FUNCTION ctrlz.credential_gen_bump('password_hash')`}},
		{"a guarded column nobody decided about", "users.probe is a guarded column with no decision",
			[]string{`ALTER TABLE ctrlz.users ADD COLUMN probe text`}},
		{"a guarded column of the admin nobody decided about", "admin_users.probe is a guarded column with no decision",
			[]string{`ALTER TABLE ctrlz.admin_users ADD COLUMN probe text`}},
		{"the counter is gone", "users has no credential_gen column",
			[]string{`DROP TRIGGER credential_gen_bump ON ctrlz.users`, `ALTER TABLE ctrlz.users DROP COLUMN credential_gen CASCADE`}},
		{"another table carries a counter nobody listed", "tables with a credential_gen column: unexpected sessions",
			[]string{`ALTER TABLE ctrlz.sessions ADD COLUMN credential_gen bigint`}},
	} {
		t.Run(m.name, func(t *testing.T) {
			v := run(m.sql...)
			if !strings.Contains(strings.Join(v, "\n"), m.want) {
				t.Errorf("check 25 did not report %q after %v; it said %v", m.want, m.sql, v)
			}
		})
	}
}

// TestCredentialGenIgnoresAReSealOfTheSeedInForce is db-r6-4 and db-r7-4. With totp_enabled_at
// set and the same on both sides, a different totp_secret_ct is either a re-seal under another
// key or a new seed, and the trigger cannot tell them apart by the shape of the write. So the
// exemption belongs to the WRITER: only the definer functions made for it (keytool_totp_replace,
// admin_totp_replace, run as ctrlz_auth) leave credential_gen alone. A service role that
// replaces a live seed with an UPDATE of its own, and the table owner at a console, move it,
// whatever the two seeds are. A seed written while no factor is in force still moves it (the
// recipes above), and so does the factor itself changing.
func TestCredentialGenIgnoresAReSealOfTheSeedInForce(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	const adminID = "00000000-0000-7000-8000-0000000000e1"
	for _, s := range []struct {
		table, id, role string
		replace         string // the definer function of the re-seal, as called by its role
		tenant          bool
	}{
		{"users", h.A.User.String(), "keytool", `SELECT ctrlz_fn.keytool_totp_replace($1, $2, $3)`, true},
		{"admin_users", adminID, "admin", `SELECT ctrlz_fn.admin_totp_replace($1, $2, $3)`, false},
	} {
		t.Run(s.table, func(t *testing.T) {
			tx, err := h.super.Begin(h.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			exec := func(set string) {
				t.Helper()
				if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.`+s.table+` SET `+set+` WHERE id = $1`, s.id); err != nil {
					t.Fatalf("%s: %v", set, err)
				}
			}
			gen := func() (g int64) {
				t.Helper()
				if err := tx.QueryRow(h.ctx, `SELECT credential_gen FROM ctrlz.`+s.table+` WHERE id = $1`, s.id).Scan(&g); err != nil {
					t.Fatal(err)
				}
				return g
			}
			// asRole runs fn as a service role inside the transaction and comes back to the
			// owner. The tenant setting is the transaction's, as WithTenant sets it.
			asRole := func(role string, fn func()) {
				t.Helper()
				if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_"+role); err != nil {
					t.Fatal(err)
				}
				if s.tenant {
					if _, err := tx.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", h.A.Tenant.String()); err != nil {
						t.Fatal(err)
					}
				}
				fn()
				if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
					t.Fatal(err)
				}
			}
			seed := func(n byte) []byte { return []byte{0x43, 0x5a, 0x01, n} }
			exec(`totp_secret_ct = '\x435a0101'::bytea, totp_enabled_at = now() - interval '1 day'`)
			base := gen()

			// The re-seal function, as its one role: the generation stays.
			asRole(s.role, func() {
				var ok bool
				if err := tx.QueryRow(h.ctx, s.replace, s.id, seed(1), seed(2)).Scan(&ok); err != nil || !ok {
					t.Fatalf("the re-seal function: %v %v", ok, err)
				}
			})
			if got := gen(); got != base {
				t.Errorf("a re-seal by %s moved credential_gen from %d to %d", s.replace, base, got)
			}

			// A plain UPDATE of the seed in force by the service role that holds the column
			// grant moves it: the database cannot know that it was meant as a re-seal.
			writer := map[string]string{"users": "tenant", "admin_users": "admin"}[s.table]
			asRole(writer, func() {
				if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.`+s.table+` SET totp_secret_ct = '\xdeadbeef'::bytea WHERE id = $1`, s.id); err != nil {
					t.Fatalf("the service role's own write of the seed: %v", err)
				}
			})
			if got := gen(); got != base+1 {
				t.Errorf("%s replacing the seed in force moved credential_gen to %d, want %d (a live authenticator was swapped in place)", writer, got, base+1)
			}
			// So does the owner at a console.
			exec(`totp_secret_ct = '\x02'::bytea`)
			if got := gen(); got != base+2 {
				t.Errorf("the owner replacing the seed in force moved credential_gen to %d, want %d", got, base+2)
			}

			// The seed and the moment together are still the factor changing.
			exec(`totp_secret_ct = '\x03'::bytea, totp_enabled_at = now()`)
			if got := gen(); got != base+3 {
				t.Errorf("a new factor moved credential_gen to %d, want %d", got, base+3)
			}
			// Removing the factor moves it, and so does a seed written while none is in force.
			exec(`totp_secret_ct = NULL, totp_enabled_at = NULL`)
			if got := gen(); got != base+4 {
				t.Errorf("removing the factor moved credential_gen to %d, want %d", got, base+4)
			}
			exec(`totp_secret_ct = '\x04'::bytea`)
			if got := gen(); got != base+5 {
				t.Errorf("a pending seed moved credential_gen to %d, want %d", got, base+5)
			}
		})
	}
}
