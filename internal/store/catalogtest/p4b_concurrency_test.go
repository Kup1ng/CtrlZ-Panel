package catalogtest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// Two writers of migration 0105's triggers, on two connections (B2-r1-2, B2-r1-6). The first holds its transaction open
// while the second writes, so the second can only be right if the trigger made it wait for the first and then look again:
// a sequential test cannot tell a lock from no lock.

// race runs first as role in an open transaction, then second as role in another one, and commits the first only once the
// second is waiting on a lock of the server. It returns the SQLSTATE of the second (its commit included), "" for success.
// guc is the tenant setting of both, nil for none. A second that never waits is a trigger that took no lock, and fails the
// test: the statements of a caller are chosen so that, without the lock, they would both pass.
func (h *harness) race(role string, guc *string, first, second string) string {
	h.t.Helper()
	// The observer never leaves the superuser role: SET LOCAL ROLE would make pg_stat_activity unreadable.
	observer := h.fresh()
	begin := func(conn *pgx.Conn) pgx.Tx {
		tx, err := conn.Begin(h.ctx)
		if err != nil {
			h.t.Fatal(err)
		}
		h.t.Cleanup(func() { tx.Rollback(h.ctx) })
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE "+pgx.Identifier{"ctrlz_" + role}.Sanitize()); err != nil {
			h.t.Fatal(err)
		}
		if guc != nil {
			if _, err := tx.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", *guc); err != nil {
				h.t.Fatal(err)
			}
		}
		return tx
	}
	one := begin(h.fresh())
	if _, err := one.Exec(h.ctx, first); err != nil {
		h.t.Fatalf("the first writer: %v", err)
	}
	twoConn := h.fresh()
	two := begin(twoConn)
	done := make(chan string, 1)
	go func() {
		if _, err := two.Exec(h.ctx, second); err != nil {
			if pe := pgErr(err); pe != nil {
				done <- pe.Code
				return
			}
			done <- "error: " + err.Error()
			return
		}
		if err := two.Commit(h.ctx); err != nil {
			if pe := pgErr(err); pe != nil {
				done <- pe.Code
				return
			}
			done <- "error: " + err.Error()
			return
		}
		done <- ""
	}()
	pid := int(twoConn.PgConn().PID())
	testwait.Until(h.t, 10*time.Second, "the second writer to wait for the first", func() bool {
		select {
		case code := <-done:
			h.t.Fatalf("the second writer finished (%q) while the first held its transaction open: the trigger took no lock", code)
		default:
		}
		var n int
		if err := observer.QueryRow(h.ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid = $1 AND wait_event_type = 'Lock'", pid).Scan(&n); err != nil {
			h.t.Fatal(err)
		}
		return n == 1
	})
	if err := one.Commit(h.ctx); err != nil {
		h.t.Fatalf("the first writer's commit: %v", err)
	}
	return testwait.Receive(h.t, done, 10*time.Second, "the second writer after the first committed")
}

// disableTrigger switches a trigger off for the rest of the test, so that the lock under test is not hidden by the lock
// of another trigger of the same write (both take the node's row). The harness database is the test's own.
func (h *harness) disableTrigger(table, trigger string) {
	h.t.Helper()
	h.exec(fmt.Sprintf(`ALTER TABLE ctrlz.%s DISABLE TRIGGER %s`, table, trigger))
}

// TestP4bAvailabilitySyncUnderConcurrentWrites: two admins each switch off one of the two enabled configs of one
// (node, location). Each sees the other's config still enabled, unless the second waits for the first.
func TestP4bAvailabilitySyncUnderConcurrentWrites(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	// The limit trigger also locks the node's row, after this one in the order of their names; without it the lock of the
	// sync trigger is the only one, and it is the one this test is about.
	h.disableTrigger("node_location_configs", "node_location_configs_limit")
	h.exec(cfgInsert(nodeC1, frankfurt, "a1", true))
	h.exec(cfgInsert(nodeC1, frankfurt, "a2", true))
	off := func(tag string) string {
		return `UPDATE ctrlz.node_location_configs SET enabled = false WHERE tag = '` + tag + `'`
	}
	if code := h.race("admin", nil, off("a1"), off("a2")); code != "" {
		t.Fatalf("the second switch-off: %s", code)
	}
	if got := h.one(`SELECT count(*) FROM ctrlz.node_location_configs WHERE enabled`); got != 0 {
		t.Fatalf("%d configs are still enabled", got)
	}
	if got := h.one(`SELECT count(*) FROM ctrlz.location_availability WHERE node_id = $1 AND location_id = $2`, nodeC1, frankfurt); got != 0 {
		t.Errorf("%d availability rows stay with no enabled config: the location would be offered with no exit", got)
	}
}

// TestP4bConfigLimitUnderConcurrentWrites: two admins each insert the 64th config of one node. Each counts 64, unless the
// second waits for the first and counts again.
func TestP4bConfigLimitUnderConcurrentWrites(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.disableTrigger("node_location_configs", "location_availability_sync")
	h.exec(cfgMany(nodeC1, frankfurt, 63, 100))
	code := h.race("admin", nil, cfgInsert(nodeC1, frankfurt, "last-a", true), cfgInsert(nodeC1, frankfurt, "last-b", true))
	if code != "23514" {
		t.Errorf("the second 64th config: %q, want 23514", code)
	}
	if got := h.one(`SELECT count(*) FROM ctrlz.node_location_configs WHERE node_id = $1`, nodeC1); got != 64 {
		t.Errorf("the node holds %d configs, want exactly 64", got)
	}
}

// TestP4bAssetLimitUnderConcurrentWrites: one tenant, two connections, the 20th asset each. The trigger takes the tenant's
// quota lock itself, so a writer that skipped assets.Store's QuotaLock is still bound.
func TestP4bAssetLimitUnderConcurrentWrites(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()
	asset := func(n int) string {
		return fmt.Sprintf(`INSERT INTO ctrlz.tenant_assets (tenant_id, kind, sha256, mime, size, bytes)
			SELECT '%s', 'logo', decode(repeat('ab', 32), 'hex'), 'image/png', 4, '\x89504e47' FROM generate_series(1, %d)`, a, n)
	}
	h.exec(asset(18)) // the seed holds one: 19
	code := h.race("tenant", &a, asset(1), asset(1))
	if code != "23514" {
		t.Errorf("the second 20th asset: %q, want 23514", code)
	}
	if got := h.one(`SELECT count(*) FROM ctrlz.tenant_assets WHERE tenant_id = $1`, a); got != 20 {
		t.Errorf("tenant A holds %d assets, want exactly 20", got)
	}
}
