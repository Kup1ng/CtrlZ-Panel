package catalogtest_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var update = flag.Bool("update", false, "rewrite golden files")

// cluster is shared by every test in this package; TestMain starts it once.
var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

func mustFixtures(t *testing.T) *catalogtest.Fixtures {
	t.Helper()
	fx, err := catalogtest.Load()
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	return fx
}

// catalogConn is a superuser session with an empty search_path, so deparsed
// expressions in pg_policies and pg_get_constraintdef are schema qualified and
// compare equal to the fixture text.
func catalogConn(ctx context.Context, t *testing.T, db *testpg.DB) *pgx.Conn {
	t.Helper()
	conn, err := db.Super(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, "SET search_path = pg_catalog"); err != nil {
		t.Fatal(err)
	}
	return conn
}

func slug(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, strings.ToLower(s))
}

// TestCatalog runs spec section 12, tests 1 to 20, against a freshly migrated
// Postgres 18. Every check must report nothing.
func TestCatalog(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if v, err := c.Version(ctx); err == nil {
		t.Logf("Postgres %s", v)
	}
	fx := mustFixtures(t)
	db := c.NewDB(ctx, t)
	conn := catalogConn(ctx, t, db)
	for _, ck := range catalogtest.Checks() {
		t.Run(ck.ID+"_"+slug(ck.Name), func(t *testing.T) {
			violations, err := ck.Run(ctx, conn, fx)
			if err != nil {
				t.Fatalf("check could not run: %v", err)
			}
			for _, v := range violations {
				t.Error(v)
			}
		})
	}
}

// TestRoleGrantsGolden prints everything each role can do (table and column
// privileges, schema USAGE, EXECUTE on every function by any route, and the
// policies that apply) as a sorted list and compares it with the committed copy,
// one file per role, so any change to what a role can do is a visible diff in
// review (R5, test 12; rule role-reach, which extended it from the tenant role to
// all of them).
func TestRoleGrantsGolden(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fx := mustFixtures(t)
	db := c.NewDB(ctx, t)
	conn := catalogConn(ctx, t, db)
	for _, rolname := range catalogtest.GoldenRoles(fx) {
		t.Run(rolname, func(t *testing.T) {
			lines, err := catalogtest.RoleGrantList(ctx, conn, rolname)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(lines, "\n") + "\n"
			path := filepath.Join("testdata", rolname+"_grants.golden")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run with -update to create it): %v", err)
			}
			if string(want) != got {
				t.Errorf("what %s can do changed; review the diff and run `go test ./internal/store/catalogtest -run RoleGrantsGolden -update`\n--- golden\n%s\n--- actual\n%s", rolname, want, got)
			}
		})
	}
}
