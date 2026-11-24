package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

// RawTenantSetting reads ctrlz.tenant_id straight from the pool, outside any
// WithTenant or WithGlobal. The fault tests use it to see what a connection
// carries after a transaction ended badly. It exists only in test builds.
func (s *Store) RawTenantSetting(ctx context.Context) (string, error) {
	var v string
	err := s.pool.QueryRow(ctx, "SELECT COALESCE(pg_catalog.current_setting('ctrlz.tenant_id', true), '')").Scan(&v)
	return v, sanitize(err)
}

// RollbackTimeout is the bound on a rollback, for the test that measures it.
const RollbackTimeout = rollbackTimeout

// AssertRole is the startup assertion, for the test that gives it a connection
// that is logged in as a different role than the one expected.
func AssertRole(ctx context.Context, c *pgx.Conn, want Role) error { return assertRole(ctx, c, want) }

// PoolSize reports the size poolConfig gives the one pool, without connecting.
func PoolSize(cfg Config, role Role) (int32, error) {
	m, err := poolConfig("host=localhost port=1 dbname=x user="+string(role), cfg, role)
	if err != nil {
		return 0, err
	}
	return m.MaxConns, nil
}

// HoldConns takes n connections from the pool and keeps them until the returned
// function runs, so a fault test can exhaust the pool that carries every call,
// the Auth() and Admin() ones included, without a slow SQL function. It exists
// only in test builds.
func (s *Store) HoldConns(ctx context.Context, n int) (release func(), err error) {
	var held []*pgxpool.Conn
	release = func() {
		for _, c := range held {
			c.Release()
		}
		held = nil
	}
	for i := 0; i < n; i++ {
		c, err := s.pool.Acquire(ctx)
		if err != nil {
			release()
			return func() {}, sanitize(err)
		}
		held = append(held, c)
	}
	return release, nil
}

// ForgetLocks makes the transaction forget what it holds, for a test that calls
// many methods in one transaction for a reason other than their order (each is
// aimed at a row it cannot reach, so none locks anything). Production code has no
// such call, and the lock order check is not available to it.
func (t Tx) ForgetLocks() { t.tx.st = lockrank.State{} }

// ForgetLocks is Tx.ForgetLocks for a global transaction.
func (g GlobalTx) ForgetLocks() { g.tx.st = lockrank.State{} }

// DeclareLostBatch is the size of one declare-lost call, and DeclareLostIn runs a declaration with a
// smaller one, for the test of what a declaration larger than one call records.
const DeclareLostBatch = declareLostBatch

func (t Tx) DeclareLostIn(keyNumber int, lost []TOTPSecret, batch int) (int, error) {
	return t.declareLost(keyNumber, lost, batch)
}

// The folder statements, so the plan test can run EXPLAIN on exactly the text the store sends.
const (
	QFoldersList   = qFoldersList
	QFolderCounted = qFolderCounted
)

// The profile statements of round 13, for the same plan test.
const (
	QProfilePairs       = qProfilePairs
	QProfileClientsLock = qProfileClientsLock
	QProfileCountsOne   = qProfileCountsOne
)
