package store_test

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

// fixture is a migrated database with two seeded tenants.
type fixture struct {
	ctx  context.Context
	db   *testpg.DB
	A, B catalogtest.SeedIDs
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	db := c.NewDB(ctx, t)
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	f := &fixture{ctx: ctx, db: db, A: catalogtest.NewSeedIDs(1), B: catalogtest.NewSeedIDs(2)}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}
	for _, ids := range []catalogtest.SeedIDs{f.A, f.B} {
		if err := catalogtest.SeedTenant(ctx, super, ids); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestWithTenantSetsAndResetsTheTenant(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)

	read := func(tx store.Tx) (string, error) {
		var v string
		err := tx.DB().QueryRow(tx.Context(), "SELECT COALESCE(pg_catalog.current_setting('ctrlz.tenant_id', true), '<null>')").Scan(&v)
		return v, err
	}
	for _, id := range []uuid.UUID{f.A.Tenant, f.B.Tenant, f.A.Tenant} {
		if err := tenant.WithTenant(f.ctx, id, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			got, err := read(tx)
			if err != nil {
				return err
			}
			if got != id.String() || tx.TenantID() != id {
				t.Errorf("inside the transaction the setting is %q, want %s", got, id)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Whatever connection the pool hands out next, the setting is gone: a
	// global transaction sees no tenant (empty string, or NULL on a connection
	// that never set it).
	for i := 0; i < 8; i++ {
		if err := worker.WithGlobal(f.ctx, store.TxOpts{ReadOnly: true}, func(tx store.GlobalTx) error {
			var v string
			if err := tx.DB().QueryRow(tx.Context(), "SELECT COALESCE(pg_catalog.current_setting('ctrlz.tenant_id', true), '')").Scan(&v); err != nil {
				return err
			}
			if v != "" {
				t.Errorf("a global transaction sees tenant setting %q", v)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWithTenantGuards(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	called := false

	err := tenant.WithTenant(f.ctx, uuid.Nil, store.TxOpts{}, func(store.Tx) error { called = true; return nil })
	if !errors.Is(err, store.ErrNilTenant) || called {
		t.Errorf("nil tenant: err %v, callback ran %v", err, called)
	}

	// A call from inside the callback, using the callback's context, is refused
	// before any SQL.
	err = tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		inner := tenant.WithTenant(tx.Context(), f.B.Tenant, store.TxOpts{}, func(store.Tx) error { called = true; return nil })
		if !errors.Is(inner, store.ErrNested) {
			t.Errorf("nested WithTenant: %v", inner)
		}
		return nil
	})
	if err != nil || called {
		t.Errorf("outer transaction: err %v, nested callback ran %v", err, called)
	}

	// The tenant role has no use for a global transaction.
	err = tenant.WithGlobal(f.ctx, store.TxOpts{}, func(store.GlobalTx) error { called = true; return nil })
	if !errors.Is(err, store.ErrWrongRole) || called {
		t.Errorf("WithGlobal as ctrlz_tenant: err %v, callback ran %v", err, called)
	}
}

func TestRollbackOnErrorAndPanic(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	insert := func(tx store.Tx, kind string) error {
		_, err := tx.DB().Exec(tx.Context(), "INSERT INTO ctrlz.tenant_audit_log (tenant_id, action) VALUES ($1, $2)", tx.TenantID(), kind)
		return err
	}
	countKind := func(kind string) int {
		var n int
		if err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			return tx.DB().QueryRow(tx.Context(), "SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = $1", kind).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	sentinel := errors.New("application error")
	err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if err := insert(tx, "rolled-back"); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("the callback's own error must come through: %v", err)
	}
	if n := countKind("rolled-back"); n != 0 {
		t.Errorf("a failed transaction left %d rows", n)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed")
			}
		}()
		_ = tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if err := insert(tx, "panicked"); err != nil {
				return err
			}
			panic("boom")
		})
	}()
	if n := countKind("panicked"); n != 0 {
		t.Errorf("a panicking transaction left %d rows", n)
	}

	if err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error { return insert(tx, "kept") }); err != nil {
		t.Fatal(err)
	}
	if n := countKind("kept"); n != 1 {
		t.Errorf("a committed row is missing: %d", n)
	}
	// Tenant B does not see A's audit entry.
	var n int
	if err := tenant.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		return tx.DB().QueryRow(tx.Context(), "SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'kept'").Scan(&n)
	}); err != nil || n != 0 {
		t.Errorf("tenant B sees %d of A's audit entrys (err %v)", n, err)
	}

	// Cancelling the context does not leave a transaction open.
	cctx, cancel := context.WithCancel(f.ctx)
	err = tenant.WithTenant(cctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if err := insert(tx, "cancelled"); err != nil {
			return err
		}
		cancel()
		return cctx.Err()
	})
	if err == nil {
		t.Error("a cancelled transaction reported success")
	}
	if n := countKind("cancelled"); n != 0 {
		t.Errorf("a cancelled transaction left %d rows", n)
	}
}

func TestErrorsCarryNoDriverDetail(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	// k1 for tenant A already exists: a unique violation whose driver message
	// names the key and the tenant id.
	err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), `INSERT INTO ctrlz.idempotency_keys (tenant_id, key, route, request_hash, expires_at)
VALUES ($1, 'k1', '/x', '\x01', now() + interval '1 day')`, tx.TenantID())
		return err
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a unique violation must map to ErrConflict, got %v", err)
	}
	var se *store.Error
	if !errors.As(err, &se) || se.SQLState() != "23505" {
		t.Errorf("SQLSTATE: %v", err)
	}
	for _, leak := range []string{f.A.Tenant.String(), "k1", "idempotency", "already exists", "Key ("} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error text %q leaks %q", err.Error(), leak)
		}
	}

	// A missing privilege is its own class.
	err = tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), "SELECT count(*) FROM ctrlz.audit_log")
		return err
	})
	if !errors.Is(err, store.ErrPermission) {
		t.Errorf("a missing grant must map to ErrPermission, got %v", err)
	}
}

func TestOpenRefusesARoleThatBypassesRLS(t *testing.T) {
	f := newFixture(t)
	// Roles are cluster wide, so the change is undone before the test ends.
	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())
	if _, err := super.Exec(f.ctx, "ALTER ROLE ctrlz_tenant BYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = super.Exec(context.Background(), "ALTER ROLE ctrlz_tenant NOBYPASSRLS") })

	_, err = store.Open(f.ctx, f.db.StoreConfig(store.RoleTenant))
	if err == nil || !strings.Contains(err.Error(), "bypass row level security") {
		t.Errorf("Open must refuse a role that bypasses RLS, got %v", err)
	}

	if _, err := super.Exec(f.ctx, "ALTER ROLE ctrlz_tenant NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(f.ctx, f.db.StoreConfig(store.RoleTenant))
	if err != nil {
		t.Fatalf("Open after the fix: %v", err)
	}
	s.Close()
}

func TestOpenRejectsBadConfigAndPassword(t *testing.T) {
	f := newFixture(t)
	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.Role = "ctrlz_migrator"
	if _, err := store.Open(f.ctx, cfg); err == nil {
		t.Error("the migrator is not a service role")
	}
	cfg = f.db.StoreConfig(store.RoleTenant)
	cfg.Password = f.db.StoreConfig(store.RoleHub).Password
	_, err := store.Open(f.ctx, cfg)
	if err == nil {
		t.Fatal("a wrong password was accepted")
	}
	// The error must not repeat either password.
	for _, pw := range []string{f.db.StoreConfig(store.RoleTenant).Password.Reveal(), cfg.Password.Reveal()} {
		if strings.Contains(err.Error(), pw) {
			t.Errorf("connection error repeats a password: %v", err)
		}
	}
}

func TestAuthLookups(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	a := s.Auth()

	u, ok, err := a.UserByPhone(f.ctx, f.A.Phone)
	if err != nil || !ok {
		t.Fatalf("UserByPhone: %v %v", ok, err)
	}
	if u.TenantID != f.A.Tenant || u.UserID != f.A.User || u.PasswordHash.Reveal() != "argon2id$seed" || u.TenantStatus != "active" || u.TOTPEnabled {
		t.Errorf("unexpected login row %+v", u)
	}
	if _, ok, err := a.UserByPhone(f.ctx, "+989000000000"); err != nil || ok {
		t.Errorf("unknown phone: found=%v err=%v", ok, err)
	}

	sess, ok, err := a.SessionByHash(f.ctx, []byte(f.B.Session))
	if err != nil || !ok || sess.TenantID != f.B.Tenant || sess.UserID != f.B.User || sess.RevokedAt != nil {
		t.Errorf("SessionByHash: %+v %v %v", sess, ok, err)
	}
	if _, ok, _ := a.SessionByHash(f.ctx, []byte("nope")); ok {
		t.Error("an unknown session hash was found")
	}

	tok, ok, err := a.TokenByHash(f.ctx, []byte(f.A.APIToken))
	if err != nil || !ok || tok.Kind != "read" || len(tok.AllowedIPs) != 1 || tok.AllowedIPs[0] != netip.MustParsePrefix("198.51.100.0/24") {
		t.Errorf("TokenByHash: %+v %v %v", tok, ok, err)
	}
	if r, ok, err := a.RefreshByHash(f.ctx, []byte(f.A.Refresh)); err != nil || !ok || r.TenantID != f.A.Tenant {
		t.Errorf("RefreshByHash: %+v %v %v", r, ok, err)
	}
	if p, ok, err := a.PasskeyByCredential(f.ctx, []byte(f.A.Passkey)); err != nil || !ok || p.RPID != "example.test" {
		t.Errorf("PasskeyByCredential: %+v %v %v", p, ok, err)
	}
	if l, ok, err := a.ShareByHash(f.ctx, []byte(f.A.Share)); err != nil || !ok || l.EndpointID != f.A.Endpoint || l.Client != "default" || l.UsesLeft != 10 {
		t.Errorf("ShareByHash: %+v %v %v", l, ok, err)
	}
	if l, ok, err := a.DownloadByHash(f.ctx, []byte(f.B.Download)); err != nil || !ok || l.TenantID != f.B.Tenant || l.UsesLeft != 1 {
		t.Errorf("DownloadByHash: %+v %v %v", l, ok, err)
	}

	// OTP: issue, wrong code, right code.
	iss, err := a.OTPIssue(f.ctx, "+989121234567", "login", []byte{1, 2}, nil, netip.MustParseAddr("198.51.100.1"), false)
	if err != nil || !iss.Allowed || iss.ID == uuid.Nil {
		t.Fatalf("OTPIssue: %+v %v", iss, err)
	}
	if out, err := a.OTPConsume(f.ctx, iss.ID, "+989121234567", "login", []byte{9}); err != nil || out != "invalid" {
		t.Errorf("wrong code: %q %v", out, err)
	}
	// The code is right, but it was issued for another phone or purpose: the
	// generic "invalid", and no try is spent (review F07).
	if out, err := a.OTPConsume(f.ctx, iss.ID, "+989129999999", "login", []byte{1, 2}); err != nil || out != "invalid" {
		t.Errorf("right code for another phone: %q %v", out, err)
	}
	if out, err := a.OTPConsume(f.ctx, iss.ID, "+989121234567", "reset", []byte{1, 2}); err != nil || out != "invalid" {
		t.Errorf("right code for another purpose: %q %v", out, err)
	}
	if out, err := a.OTPConsume(f.ctx, iss.ID, "+989121234567", "login", []byte{1, 2}); err != nil || out != "ok" {
		t.Errorf("right code: %q %v", out, err)
	}

	// Registration is closed by default, and the refusal is silent.
	if _, ok, err := a.RegisterUser(f.ctx, "+989129999999", "hash", "fa", uuid.Nil, uuid.Nil); err != nil || ok {
		t.Errorf("closed registration: ok=%v err=%v", ok, err)
	}
}

func TestTenantFunctionsAndOutbox(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	compiler := f.db.Store(f.ctx, t, store.RoleCompiler)

	var pairs []store.EndpointPair
	if err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (err error) {
		pairs, err = tx.EndpointPairIPs()
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 || pairs[0].EndpointID != f.A.Endpoint || pairs[0].PrimaryDNSIP.String() != "192.0.2.1" || pairs[0].FallbackDNSIP.String() != "192.0.2.2" {
		t.Errorf("EndpointPairIPs: %+v", pairs)
	}

	// MarkDirty: one row per aggregate per transaction, however many writes.
	countOutbox := func(agg uuid.UUID) int {
		var n int
		if err := compiler.WithGlobal(f.ctx, store.TxOpts{ReadOnly: true}, func(tx store.GlobalTx) error {
			return tx.DB().QueryRow(tx.Context(), "SELECT count(*) FROM ctrlz.policy_outbox WHERE aggregate_id = $1", agg).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	profile := f.A.Profile2
	for i := 0; i < 2; i++ { // two transactions, so two batches
		if err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			for j := 0; j < 5; j++ { // five rule writes in one transaction
				if err := store.MarkDirty(tx, store.AggregateProfile, profile); err != nil {
					return err
				}
			}
			return store.MarkDirty(tx, store.AggregateEndpointSet, f.A.Tenant)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n := countOutbox(profile); n != 2 {
		t.Errorf("5 writes in each of 2 transactions made %d outbox rows, want 2", n)
	}
	if n := countOutbox(f.A.Tenant); n != 2 {
		t.Errorf("endpoint_set rows: %d, want 2", n)
	}
	// The tenant role cannot read the outbox, only write it.
	err := tenant.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), "SELECT count(*) FROM ctrlz.policy_outbox")
		return err
	})
	if !errors.Is(err, store.ErrPermission) {
		t.Errorf("tenant read of policy_outbox: %v", err)
	}
}

func TestRolesSeeWhatTheirPoliciesAllow(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		role store.Role
		sql  string
		want int
	}{
		{store.RoleWorker, "SELECT count(*) FROM ctrlz.tenants", 2},   // worker_list
		{store.RoleCompiler, "SELECT count(*) FROM ctrlz.tenants", 2}, // compiler_list
		{store.RoleAdmin, "SELECT count(*) FROM ctrlz.admin_tenant_summary", 2},
		{store.RoleHub, "SELECT count(*) FROM ctrlz.hub_endpoint_index", 2}, // hub_index
		// Since 0011 the worker may select the key and expiry columns of sessions,
		// because a sweep's DELETE filters on them. With no tenant set the policy
		// still shows it no row.
		{store.RoleWorker, "SELECT count(*) FROM ctrlz.sessions", 0},
	} {
		s := f.db.Store(f.ctx, t, c.role)
		var n int
		err := s.WithGlobal(f.ctx, store.TxOpts{ReadOnly: true}, func(tx store.GlobalTx) error {
			return tx.DB().QueryRow(tx.Context(), c.sql).Scan(&n)
		})
		if err != nil || n != c.want {
			t.Errorf("%s %q: %d rows, err %v, want %d", c.role, c.sql, n, err, c.want)
		}
	}
}
