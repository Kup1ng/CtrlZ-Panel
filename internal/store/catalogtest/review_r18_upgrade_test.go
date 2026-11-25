package catalogtest_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestMigration0055OnAnInstalledDatabase is db-r18-21: the paths of the migration that a fresh install never
// takes. Every other test migrates an empty database from the bootstrap, where ctrlz_scoped always exists and
// there is nothing to move, so the two claims about an INSTALLED database had no run:
//
//  1. a database that was installed before the role existed stops at 0055 with the message that names the
//     fix, and stops whole: the version stays 0054, and no function changed hands (a half-moved set would
//     leave the twelve functions owned by two roles and the catalog check failing only at the next start);
//  2. once the role exists, 0055 moves exactly the functions that functions.yaml says belong to
//     ctrlz_scoped from ctrlz_auth, and every function keeps the roles that may execute it, so no login role
//     loses a call it makes and none gains one.
//
// The role is renamed away for the first half, not dropped: it owns nothing yet, and the rename is undone
// before the test ends whatever happens, since the cluster is shared by the tests of the package.
func TestMigration0055OnAnInstalledDatabase(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	d := c.NewEmptyDB(ctx, t)
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	super, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())

	if _, err := migrate.UpTo(ctx, db, 54); err != nil {
		t.Fatal(err)
	}
	type fn struct{ owner, execute string }
	read := func() map[string]fn {
		t.Helper()
		rows, err := super.Query(ctx, `SELECT p.oid::regprocedure::text, p.proowner::regrole::text,
		    COALESCE((SELECT string_agg(DISTINCT a.grantee::regrole::text, ',' ORDER BY a.grantee::regrole::text)
		              FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a WHERE a.privilege_type = 'EXECUTE'), '')
		  FROM pg_proc p WHERE p.pronamespace = 'ctrlz_fn'::regnamespace`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]fn{}
		for rows.Next() {
			var sig string
			var f fn
			if err := rows.Scan(&sig, &f.owner, &f.execute); err != nil {
				t.Fatal(err)
			}
			out[sig] = f
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := read()

	if _, err := super.Exec(ctx, `ALTER ROLE ctrlz_scoped RENAME TO ctrlz_scoped_away`); err != nil {
		t.Fatal(err)
	}
	renamed := true
	restore := func() {
		if renamed {
			_, _ = super.Exec(context.Background(), `ALTER ROLE ctrlz_scoped_away RENAME TO ctrlz_scoped`)
			renamed = false
		}
	}
	defer restore()
	_, err = migrate.UpTo(ctx, db, 55)
	if err == nil || !strings.Contains(err.Error(), "ctrlz_scoped does not exist") {
		t.Fatalf("0055 without the role: %v, want a refusal that names the role", err)
	}
	var version int
	if err := super.QueryRow(ctx, `SELECT COALESCE(max(version_id), 0) FROM ctrlz.schema_migrations WHERE is_applied`).Scan(&version); err != nil {
		t.Fatalf("read the version: %v", err)
	}
	if version != 54 {
		t.Errorf("the database is at %d after a refused 0055, want 54", version)
	}
	if got := read(); len(got) != len(before) {
		t.Errorf("a refused 0055 left %d functions where there were %d", len(got), len(before))
	} else {
		for sig, f := range got {
			if f != before[sig] {
				t.Errorf("a refused 0055 changed %s from %+v to %+v", sig, before[sig], f)
			}
		}
	}
	restore()

	if _, err := migrate.UpTo(ctx, db, 55); err != nil {
		t.Fatalf("0055 with the role: %v", err)
	}
	after := read()
	moved := 0
	for sig, f := range after {
		b, existed := before[sig]
		if !existed {
			continue
		}
		if f.owner != b.owner {
			if b.owner != "ctrlz_auth" || f.owner != "ctrlz_scoped" {
				t.Errorf("%s changed hands from %s to %s, want ctrlz_auth to ctrlz_scoped", sig, b.owner, f.owner)
			}
			moved++
		}
		// The grantee list names the owner too (an owner may execute its own function), so it is compared with
		// the owner's name taken out.
		strip := func(x fn) string {
			var keep []string
			for _, g := range strings.Split(x.execute, ",") {
				if g != x.owner {
					keep = append(keep, g)
				}
			}
			return strings.Join(keep, ",")
		}
		if strip(f) != strip(b) {
			t.Errorf("%s: the roles that may execute it changed from %q to %q", sig, strip(b), strip(f))
		}
	}
	// The list is the catalogue, not a number of ours: every function that functions.yaml gives to the scoped role
	// is one that an installed database had at 0054 and 0055 moved.
	fx, err := catalogtest.Load()
	if err != nil {
		t.Fatal(err)
	}
	// A function a later migration made as ctrlz_scoped (tenant_plan, 0074) was never at 0054, so 0055 moved none of it.
	atFiftyFour := map[string]bool{}
	for sig := range before {
		atFiftyFour[strings.SplitN(strings.TrimPrefix(sig, "ctrlz_fn."), "(", 2)[0]] = true
	}
	want := 0
	for _, f := range fx.Functions.SecurityDefiner {
		if f.Owner == "scoped" && atFiftyFour[f.Name] {
			want++
		}
	}
	if want == 0 || moved != want {
		t.Errorf("0055 moved %d functions to ctrlz_scoped on an installed database, functions.yaml lists %d", moved, want)
	}
}
