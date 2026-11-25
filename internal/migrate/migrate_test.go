package migrate_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

func migrationFiles(t *testing.T) int {
	t.Helper()
	entries, err := pgmigrations.Migrations.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestUpIsCompleteAndIdempotent(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	want := migrationFiles(t)
	if want < 7 {
		t.Fatalf("only %d embedded migrations", want)
	}
	n, err := migrate.Up(ctx, db)
	if err != nil || n != want {
		t.Fatalf("first Up applied %d of %d: %v", n, want, err)
	}
	n, err = migrate.Up(ctx, db)
	if err != nil || n != 0 {
		t.Errorf("second Up applied %d, want 0: %v", n, err)
	}
	st, err := migrate.List(ctx, db)
	if err != nil || len(st) != want {
		t.Fatalf("List: %d entries, err %v", len(st), err)
	}
	for _, s := range st {
		if !s.Applied {
			t.Errorf("migration %d is not applied", s.Version)
		}
	}
	// The version table lives in ctrlz and holds one row per migration.
	var rows int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM ctrlz.schema_migrations WHERE version_id > 0").Scan(&rows); err != nil || rows != want {
		t.Errorf("schema_migrations has %d rows (err %v), want %d", rows, err, want)
	}
}

// TestConcurrentRunsAreSafe: two migrate containers starting together must not
// both apply the schema. goose takes an advisory lock.
func TestConcurrentRunsAreSafe(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)

	var wg sync.WaitGroup
	counts := make([]int, 3)
	errs := make([]error, 3)
	for i := range counts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			db, err := d.MigratorDB()
			if err != nil {
				errs[i] = err
				return
			}
			defer db.Close()
			counts[i], errs[i] = migrate.Up(ctx, db)
		}()
	}
	wg.Wait()
	total := 0
	for i := range counts {
		if errs[i] != nil {
			t.Fatalf("runner %d: %v", i, errs[i])
		}
		total += counts[i]
	}
	if want := migrationFiles(t); total != want {
		t.Errorf("three concurrent runners applied %d migrations between them, want exactly %d", total, want)
	}
}

// TestCheckReachRefusesADatabaseTheBootstrapDidNotClose is db-r15-2 and db-r15-8. The pg_catalog
// revokes live in a superuser step that runs once, on an empty data directory, so an installed
// database that was upgraded without re-running it, a restored dump, or a Postgres that adds a
// function under a matched name stays open while every migration succeeds. CheckReach is the
// standing question the migrate container asks on every start: a clean database passes, and each way
// it can be open (PUBLIC holding a lock function, a statistics view, a size function, a service role
// holding one it was not given, the goose locker taken from the migrator) is refused with the file
// that closes it named.
func TestCheckReachRefusesADatabaseTheBootstrapDidNotClose(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrate.CheckReach(ctx, db); err != nil {
		t.Fatalf("a freshly bootstrapped and migrated database is refused: %v", err)
	}
	for _, m := range []struct {
		name, open, close, want string
	}{
		{"the advisory lock the audit chain waits on", `GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) TO PUBLIC`,
			`REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_lock(bigint) FROM PUBLIC`, "PUBLIC holds EXECUTE on pg_catalog function pg_advisory_lock(bigint)"},
		{"the statistics function that counts rows", `GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_get_tuples_inserted(oid) TO PUBLIC`,
			`REVOKE EXECUTE ON FUNCTION pg_catalog.pg_stat_get_tuples_inserted(oid) FROM PUBLIC`, "pg_stat_get_tuples_inserted(oid)"},
		{"the lock table", `GRANT SELECT ON pg_catalog.pg_locks TO PUBLIC`, `REVOKE SELECT ON pg_catalog.pg_locks FROM PUBLIC`, "pg_locks"},
		{"a size function for a service role", `GRANT EXECUTE ON FUNCTION pg_catalog.pg_total_relation_size(regclass) TO ctrlz_hub`,
			`REVOKE EXECUTE ON FUNCTION pg_catalog.pg_total_relation_size(regclass) FROM ctrlz_hub`, "ctrlz_hub holds EXECUTE"},
	} {
		t.Run(m.name, func(t *testing.T) {
			sup, err := d.Super(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer sup.Close(context.Background())
			if _, err := sup.Exec(ctx, m.open); err != nil {
				t.Fatal(err)
			}
			err = migrate.CheckReach(ctx, db)
			var re *migrate.ReachError
			if !errors.As(err, &re) {
				t.Fatalf("CheckReach said %v, want a ReachError", err)
			}
			if !strings.Contains(err.Error(), m.want) || !strings.Contains(err.Error(), "bootstrap/20-database.sql") {
				t.Errorf("the error does not say what is open and which file closes it: %v", err)
			}
			if _, err := sup.Exec(ctx, m.close); err != nil {
				t.Fatal(err)
			}
			if err := migrate.CheckReach(ctx, db); err != nil {
				t.Errorf("closed again, CheckReach still says: %v", err)
			}
		})
	}
}
