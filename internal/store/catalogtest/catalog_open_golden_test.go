package catalogtest_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestOpenCatalogGolden rewrites migrations/catalog/pg_catalog_open.golden with -update, from a freshly
// bootstrapped and migrated database. Without the flag it does nothing: check 31 (TestCatalog) is the
// comparison.
func TestOpenCatalogGolden(t *testing.T) {
	if !*update {
		t.Skip("run with -update to rewrite migrations/catalog/pg_catalog_open.golden")
	}
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	db := c.NewDB(ctx, t)
	conn := catalogConn(ctx, t, db)
	lines, err := catalogtest.OpenCatalog(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	head := "# What PUBLIC may use in pg_catalog on the Postgres under test (check 31, db-r15-9), after bootstrap/20-database.sql.\n" +
		"# Reviewed once from the image; a function a later release adds fails the check until a person revokes it or adds it here.\n" +
		"# Regenerate: go test ./internal/store/catalogtest -run TestOpenCatalogGolden -update\n"
	if err := os.WriteFile("../../../migrations/catalog/pg_catalog_open.golden", []byte(head+strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d lines", len(lines))
}
