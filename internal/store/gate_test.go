package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestAssertRoleComparesTheExpectedRole (P0 gate review, D14 5): a connection
// that is logged in as a role other than the one the service expects is
// refused, even when that role is a harmless one. Open logs in as the role it
// was given, so the comparison is only reachable here.
func TestAssertRoleComparesTheExpectedRole(t *testing.T) {
	f := newFixture(t)
	conn, err := f.db.Conn(f.ctx, "ctrlz_hub")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if err := store.AssertRole(f.ctx, conn, store.RoleHub); err != nil {
		t.Errorf("the hub connection, expected as the hub: %v", err)
	}
	err = store.AssertRole(f.ctx, conn, store.RoleTenant)
	if err == nil || !strings.Contains(err.Error(), "connected as ctrlz_hub, expected ctrlz_tenant") {
		t.Errorf("the hub connection, expected as the tenant: %v, want a refusal naming both roles", err)
	}
}

// TestCancelledTransactionKeepsItsConnection (P0 gate review, D14 6): the
// rollback of a failed transaction runs on a context that survives the
// cancellation of the request. With the request's own context the rollback is
// refused before it is sent, the driver then closes the connection, and every
// cancelled request costs a new connection. The rows are gone either way (the
// server rolls back a closed session), so what shows the difference is the
// session itself: the next transaction runs on the same backend.
func TestCancelledTransactionKeepsItsConnection(t *testing.T) {
	f := newFixture(t)
	s := oneConn(t, f, store.RoleTenant)
	pid := func() (p int) {
		if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			return tx.DB().QueryRow(tx.Context(), "SELECT pg_catalog.pg_backend_pid()").Scan(&p)
		}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := pid()

	cctx, cancel := context.WithCancel(f.ctx)
	boom := errors.New("cancelled by the client")
	err := s.WithTenant(cctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if _, err := tx.DB().Exec(tx.Context(), "INSERT INTO ctrlz.tenant_audit_log (tenant_id, action) VALUES ($1, 'cancelled-keeps-conn')", tx.TenantID()); err != nil {
			return err
		}
		cancel()
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the handler's own error", err)
	}
	if after := pid(); after != before {
		t.Errorf("the next transaction ran on backend %d, not %d: the rollback of a cancelled request closed the connection", after, before)
	}
	var n int
	if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		return tx.DB().QueryRow(tx.Context(), "SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'cancelled-keeps-conn'").Scan(&n)
	}); err != nil || n != 0 {
		t.Errorf("the cancelled transaction left %d rows (err %v)", n, err)
	}
}
