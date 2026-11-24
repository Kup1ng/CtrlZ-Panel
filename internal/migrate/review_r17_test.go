package migrate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/reachcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestTheOwnerQuestionFailsClosedOnAFileThatForgetsAnOwner is db-r17-11. The owners that the bootstrap and the
// migrations set are asked on every start against roles.yaml, and a roles.yaml that names no owner for the
// database, the relations or the functions must not make the question vanish: it is itself a security
// finding, so an edit of the file that drops a line fails the start instead of silencing the check.
func TestTheOwnerQuestionFailsClosedOnAFileThatForgetsAnOwner(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())
	q := reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
		return sup.Query(ctx, sql, args...)
	})
	spec, err := reachcheck.EmbeddedRoles()
	if err != nil {
		t.Fatal(err)
	}
	judge := func(s reachcheck.RolesFile) string {
		t.Helper()
		fs, err := reachcheck.JudgeBootstrapState(ctx, q, s)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(reachcheck.Texts(reachcheck.SecurityOnly(fs)), "\n")
	}
	if got := judge(spec); got != "" {
		t.Fatalf("the embedded roles.yaml is refused on a fresh database: %s", got)
	}
	noDB, noSchema := spec, spec
	noDB.DatabaseOwner = ""
	noSchema.SchemaOwners = nil
	for _, c := range []struct {
		name string
		spec reachcheck.RolesFile
		want string
	}{
		{"no database owner", noDB, "names no database_owner"},
		{"no schema owners", noSchema, "names no schema_owners"},
	} {
		if got := judge(c.spec); !strings.Contains(got, c.want) {
			t.Errorf("%s: the judgement says %q, want it to say %q", c.name, got, c.want)
		}
	}
}

// TestTheOwnerQuestionAsksEveryOwnedKind is db-r17-15. The owner question must cover every kind of object a
// schema can hold, and the list of kinds is not ours to keep: it is read here from the live catalog, as every
// table of pg_catalog that has one column ending in "namespace" and one ending in "owner" (pg_class, pg_proc,
// pg_type, pg_operator, ... pg_extension). A kind a later Postgres adds, or one that reachcheck.OwnedObjectsQuery
// forgot, fails this test instead of being a silent gap.
func TestTheOwnerQuestionAsksEveryOwnedKind(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())
	rows, err := sup.Query(ctx, `
SELECT c.relname FROM pg_class c
WHERE c.relnamespace = 'pg_catalog'::regnamespace AND c.relkind = 'r'
  AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND a.attname ~ 'namespace$')
  AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND a.attname ~ 'owner$')
ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var live []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		live = append(live, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// What the query reads is what it says: every listed catalog is in its text, and nothing else is listed.
	asked := map[string]bool{}
	for _, n := range reachcheck.OwnedCatalogs() {
		asked[n] = true
		if !strings.Contains(reachcheck.OwnedObjectsQuery, " "+n+" ") {
			t.Errorf("OwnedCatalogs lists %s, which OwnedObjectsQuery does not read", n)
		}
	}
	for _, n := range live {
		if !asked[n] {
			t.Errorf("pg_catalog.%s has a schema and an owner column and the owner question does not ask it: add it to reachcheck.OwnedObjectsQuery and OwnedCatalogs", n)
		}
		delete(asked, n)
	}
	for n := range asked {
		t.Errorf("OwnedCatalogs lists %s, which this server has no such catalog for: remove it", n)
	}
}
