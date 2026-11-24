package store_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// oneConn opens a store whose pool has exactly one connection, so that two
// transactions in a row are certain to run on the same session.
func oneConn(t *testing.T, f *fixture, role store.Role) *store.Store {
	t.Helper()
	cfg := f.db.StoreConfig(role)
	cfg.MaxConns = 1
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

const readTenantSetting = "SELECT COALESCE(pg_catalog.current_setting('ctrlz.tenant_id', true), '')"

// TestTenantSettingNeverSurvivesATransaction is the regression test for review
// F08 (both lists). The old test checked the post-condition on a different
// store, whose pool had never run WithTenant, so it could not fail. Here it is
// the same one-connection pool throughout.
//
// The callback is also made to do the one thing that breaks fail-closed: a
// session-level set_config of another tenant. Test code may build such SQL; the
// lint test is what keeps it out of the services. With the setting left on the
// pooled connection, the next global transaction used to read tenant B's rows
// with no tenant context at all.
func TestTenantSettingNeverSurvivesATransaction(t *testing.T) {
	f := newFixture(t)
	for _, role := range []store.Role{store.RoleWorker, store.RoleCompiler} {
		s := oneConn(t, f, role)

		// An ordinary transaction-local setting is gone afterwards.
		if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error { return nil }); err != nil {
			t.Fatal(err)
		}
		readGlobal := func() (setting string, hasTenant bool) {
			t.Helper()
			if err := s.WithGlobal(f.ctx, store.TxOpts{ReadOnly: true}, func(tx store.GlobalTx) error {
				if err := tx.DB().QueryRow(tx.Context(), readTenantSetting).Scan(&setting); err != nil {
					return err
				}
				// What the row level security policies actually key on.
				return tx.DB().QueryRow(tx.Context(), "SELECT ctrlz.current_tenant_id() IS NOT NULL").Scan(&hasTenant)
			}); err != nil {
				t.Fatal(err)
			}
			return
		}
		if v, _ := readGlobal(); v != "" {
			t.Errorf("%s: after WithTenant the global transaction sees %q", role, v)
		}

		// A helper that sets it for the session instead.
		if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			_, err := tx.DB().Exec(tx.Context(), "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, false)", f.B.Tenant.String())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		v, has := readGlobal()
		if v != "" || has {
			t.Errorf("%s: a session-level setting leaked into the next global transaction: %q, current_tenant_id set %v", role, v, has)
		}
	}
}

// TestNestedWithTenantThroughTheOuterContext documents what the guard does and
// does not do. It catches a call that passes the callback's own context (see
// TestWithTenantGuards). A call with a context captured from outside is not
// caught, and this test pins that it is harmless to isolation: a separate
// transaction on its own connection, with its own tenant, and the outer one
// still has its own after the inner returns.
func TestNestedWithTenantThroughTheOuterContext(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	setting := func(tx store.Tx) string {
		var v string
		if err := tx.DB().QueryRow(tx.Context(), readTenantSetting).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(outer store.Tx) error {
		if got := setting(outer); got != f.A.Tenant.String() {
			t.Errorf("outer setting %q", got)
		}
		inner := s.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{ReadOnly: true}, func(in store.Tx) error {
			if got := setting(in); got != f.B.Tenant.String() {
				t.Errorf("inner setting %q, want tenant B", got)
			}
			return nil
		})
		if inner != nil {
			t.Errorf("inner: %v", inner)
		}
		if got := setting(outer); got != f.A.Tenant.String() {
			t.Errorf("after the inner transaction the outer setting is %q", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// DB() hands out the three DBTX methods and nothing that reaches the
// connection. Before, it returned the pgx.Tx itself, which can be asserted back
// to pgx.Tx and then asked for Conn().
func TestDBHandleIsNarrow(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleWorker)
	check := func(db store.DBTX) {
		t.Helper()
		if _, ok := db.(pgx.Tx); ok {
			t.Error("DB() returns the pgx.Tx")
		}
		if _, ok := db.(interface{ Conn() *pgx.Conn }); ok {
			t.Error("DB() exposes the connection")
		}
		if _, ok := db.(interface {
			Begin(context.Context) (pgx.Tx, error)
		}); ok {
			t.Error("DB() can begin a nested transaction")
		}
	}
	if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error { check(tx.DB()); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.WithGlobal(f.ctx, store.TxOpts{ReadOnly: true}, func(tx store.GlobalTx) error { check(tx.DB()); return nil }); err != nil {
		t.Fatal(err)
	}
}

// TestAnnouncementsAreFilteredByTenant is the store side of review F04/F06: a
// notice addressed to tenant B is not readable by A, by the function or by the
// table.
func TestAnnouncementsAreFilteredByTenant(t *testing.T) {
	f := newFixture(t)
	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.announcements (audience, tenant_id, body) VALUES
  ('tenant', $1, 'only for B'), ('tenant', $2, 'only for A'),
  ('all', NULL, 'expired'), ('all', NULL, 'later')`, f.B.Tenant, f.A.Tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.announcements SET ends_at = now() - interval '1 hour' WHERE body = 'expired'`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.announcements SET starts_at = now() + interval '1 hour' WHERE body = 'later'`); err != nil {
		t.Fatal(err)
	}
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	bodies := func(tenant uuid.UUID) map[string]bool {
		out := map[string]bool{}
		if err := s.WithTenant(f.ctx, tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			list, err := tx.Announcements()
			for _, a := range list {
				out[a.Body] = true
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	a, b := bodies(f.A.Tenant), bodies(f.B.Tenant)
	if !a["hello"] || !a["only for A"] || a["only for B"] || a["expired"] || a["later"] {
		t.Errorf("tenant A sees %v", a)
	}
	if !b["hello"] || !b["only for B"] || b["only for A"] {
		t.Errorf("tenant B sees %v", b)
	}
	// The table itself is closed to the tenant role.
	err = s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), "SELECT body FROM ctrlz.announcements")
		return err
	})
	if !errors.Is(err, store.ErrPermission) {
		t.Errorf("SELECT on announcements as the tenant role: %v", err)
	}
}

func TestOTPCodeHash(t *testing.T) {
	// The keyed function is internal/keyring's job; HMAC-SHA256 stands in for it
	// here, with two keys to show that the key matters.
	macWith := func(key string) func([]byte) []byte {
		return func(b []byte) []byte {
			m := hmac.New(sha256.New, []byte(key))
			m.Write(b)
			return m.Sum(nil)
		}
	}
	key, other := macWith("0123456789abcdef0123456789abcdef"), macWith("fedcba9876543210fedcba9876543210")
	base := store.OTPCodeHash(key, "+989121234567", "login", "123456")
	if len(base) != 32 {
		t.Fatalf("hash length %d", len(base))
	}
	same := store.OTPCodeHash(key, "+989121234567", "login", "123456")
	if string(base) != string(same) {
		t.Error("not deterministic")
	}
	for name, h := range map[string][]byte{
		"other key":     store.OTPCodeHash(other, "+989121234567", "login", "123456"),
		"other phone":   store.OTPCodeHash(key, "+989121234568", "login", "123456"),
		"other purpose": store.OTPCodeHash(key, "+989121234567", "reset", "123456"),
		"other code":    store.OTPCodeHash(key, "+989121234567", "login", "123457"),
		// The separators matter: moving a byte between fields changes the input.
		"shifted field": store.OTPCodeHash(key, "+98912123456", "7login", "123456"),
	} {
		if string(h) == string(base) {
			t.Errorf("%s gives the same hash", name)
		}
	}
	// The function sees one buffer with the fixed prefix and a NUL between the
	// fields, so a keyring MAC over it cannot be confused with another use.
	var seen []byte
	store.OTPCodeHash(func(b []byte) []byte { seen = b; return nil }, "+989121234567", "login", "123456")
	if string(seen) != "ctrlz-otp-v1\x00+989121234567\x00login\x00123456" {
		t.Errorf("MAC input is %q", seen)
	}
}
