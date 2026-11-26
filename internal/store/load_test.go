package store_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The load baseline of the store (T-388). It answers one question, and it is
// not a capacity number: with more callers than connections, on a small pool
// that hands the same connections back and forth between two tenants, does any
// transaction see the other tenant's rows or keep a write it rolled back? The
// rate it logs depends on the machine, so nothing here passes or fails on it.

const (
	insertLoadKey = `INSERT INTO ctrlz.idempotency_keys (tenant_id, key, route, request_hash, expires_at)
VALUES ($1, $2, '/load', '\x01', now() + interval '1 day')`
	readLoadKeys = `SELECT tenant_id, count(*) FROM ctrlz.idempotency_keys WHERE route = '/load' GROUP BY tenant_id`
)

var errLoadRollback = errors.New("rolled back on purpose")

// TestParallelTenantsKeepTheirRowsAtPoolSize runs four callers per connection,
// half for each tenant. Every third transaction fails after its write. Each
// transaction reads every row its role can see on the table, so a tenant
// setting left on a connection by the previous holder shows up as a foreign
// tenant_id or as a transaction that reads nothing of its own.
func TestParallelTenantsKeepTheirRowsAtPoolSize(t *testing.T) {
	f := newFixture(t)
	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 8
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	const (
		callers = 32
		rounds  = 40
	)
	type outcome struct {
		kept, rolled int
		err          error
	}
	results := make([]outcome, callers)
	start := time.Now()
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tenant := f.A.Tenant
			if i%2 == 1 {
				tenant = f.B.Tenant
			}
			for round := range rounds {
				fail := round%3 == 2
				err := s.WithTenant(f.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
					key := fmt.Sprintf("load-%d-%d", i, round)
					if _, err := tx.DB().Exec(tx.Context(), insertLoadKey, tx.TenantID(), key); err != nil {
						return err
					}
					rows, err := tx.DB().Query(tx.Context(), readLoadKeys)
					if err != nil {
						return err
					}
					defer rows.Close()
					seen := 0
					for rows.Next() {
						var owner uuid.UUID
						var n int
						if err := rows.Scan(&owner, &n); err != nil {
							return err
						}
						if owner != tenant {
							return fmt.Errorf("tenant %s read %d rows of %s", tenant, n, owner)
						}
						seen += n
					}
					if err := rows.Err(); err != nil {
						return err
					}
					if seen == 0 {
						return errors.New("the transaction does not see its own write")
					}
					if fail {
						return errLoadRollback
					}
					return nil
				})
				switch {
				case err == nil:
					results[i].kept++
				case errors.Is(err, errLoadRollback):
					results[i].rolled++
				default:
					results[i].err = err
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	want := map[uuid.UUID]int{}
	total := 0
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("caller %d: %v", i, r.err)
		}
		tenant := f.A.Tenant
		if i%2 == 1 {
			tenant = f.B.Tenant
		}
		want[tenant] += r.kept
		total += r.kept + r.rolled
	}
	t.Logf("%d transactions on %d connections in %v (%.0f a second, this machine only)",
		total, cfg.MaxConns, elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds())

	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(f.ctx)
	rows, err := super.Query(f.ctx, readLoadKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[uuid.UUID]int{}
	for rows.Next() {
		var owner uuid.UUID
		var n int
		if err := rows.Scan(&owner, &n); err != nil {
			t.Fatal(err)
		}
		got[owner] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[f.A.Tenant] != want[f.A.Tenant] || got[f.B.Tenant] != want[f.B.Tenant] {
		t.Errorf("rows kept %v, want %v: a rolled-back write stayed, or a committed one was lost", got, want)
	}
}
