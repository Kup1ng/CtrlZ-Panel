package migrate_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrate"
	"github.com/Kup1ng/CtrlZ-Panel/internal/reachcheck"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"
)

var serviceRoles = []string{"ctrlz_tenant", "ctrlz_hub", "ctrlz_compiler", "ctrlz_worker", "ctrlz_admin", "ctrlz_keytool"}

// reachErr runs CheckReach and returns its ReachError, or nil when the database is accepted.
func reachErr(t *testing.T, ctx context.Context, d *testpg.DB) *migrate.ReachError {
	t.Helper()
	db, err := d.MigratorDB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = migrate.CheckReach(ctx, db)
	if err == nil {
		return nil
	}
	var re *migrate.ReachError
	if !errors.As(err, &re) {
		t.Fatalf("CheckReach failed with something that is not a ReachError: %v", err)
	}
	return re
}

// TestCheckReachAsksAboutTheRoleBoundsToo is db-r16-5. The superuser bootstrap sets the attributes,
// the connection limits and the role defaults once, and only catalog check 08 on a fresh CI cluster
// read them back; round 15 added transaction_timeout to a file that cannot run again, so a database
// upgraded to that release migrated cleanly and started with no such bound on any service role, and a
// role may rewrite its own defaults for good (ALTER ROLE itself SET statement_timeout = 0). Every
// way a bound can be lost is refused on the next start with the repair file named, the repair file
// closes each of them, and a database in the pre-0049 state (no transaction_timeout) is one of them.
func TestCheckReachAsksAboutTheRoleBoundsToo(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	if re := reachErr(t, ctx, d); re != nil {
		t.Fatalf("a freshly bootstrapped and migrated database is refused: %v", re)
	}
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())

	cases := []struct{ name, plant, want string }{
		{"the pre-0049 state: no transaction_timeout on any service role", strings.Join(resetAll(serviceRoles, "transaction_timeout"), "; "), "has no role default for transaction_timeout"},
		{"a role default set to zero", "ALTER ROLE ctrlz_hub SET statement_timeout = 0", "statement_timeout is \"0\""},
		{"a role default set to zero seconds", "ALTER ROLE ctrlz_hub SET lock_timeout = '0s'", "lock_timeout is \"0s\""},
		{"a default that is not listed", "ALTER ROLE ctrlz_worker SET session_replication_role = replica", "role default roles.yaml does not list: session_replication_role"},
		{"a search_path that puts ctrlz first", "ALTER ROLE ctrlz_tenant SET search_path = ctrlz, pg_catalog", "ctrlz_tenant: search_path is not what roles.yaml says"},
		{"a setting for one database only", "ALTER ROLE ctrlz_admin IN DATABASE " + d.Name + " SET idle_in_transaction_session_timeout = 0", "ctrlz_admin has a setting for one database"},
		{"a default for every login", "ALTER ROLE ALL SET statement_timeout = 0", "ALTER ROLE ALL SET holds statement_timeout"},
		{"no connection limit", "ALTER ROLE ctrlz_compiler CONNECTION LIMIT -1", "ctrlz_compiler has no connection limit"},
		{"a login role that bypasses RLS", "ALTER ROLE ctrlz_keytool BYPASSRLS", "ctrlz_keytool has a forbidden attribute"},
	}
	for _, m := range cases {
		t.Run(m.name, func(t *testing.T) {
			if _, err := sup.Exec(ctx, m.plant); err != nil {
				t.Fatalf("%s: %v", m.plant, err)
			}
			re := reachErr(t, ctx, d)
			if re == nil {
				t.Fatal("CheckReach accepted a database with a lost role bound")
			}
			if !strings.Contains(re.Error(), m.want) || !strings.Contains(re.Error(), "bootstrap/15-role-bounds.sql") {
				t.Errorf("the error does not say what is lost and which file repairs it: %v", re)
			}
			if err := d.RunBootstrapFile(ctx, "15-role-bounds.sql"); err != nil {
				t.Fatalf("the repair file failed: %v", err)
			}
			if re := reachErr(t, ctx, d); re != nil {
				t.Errorf("after the repair file CheckReach still says: %v", re)
			}
		})
	}
}

func resetAll(roles []string, param string) []string {
	var out []string
	for _, r := range roles {
		out = append(out, "ALTER ROLE "+r+" RESET "+param)
	}
	return out
}

// TestARoleCanRewriteItsOwnDefaultsAndMigrateSeesIt proves the premise of db-r16-5 with a real login:
// the service role itself removes its statement_timeout for good, nothing in Postgres stops it, and the
// next ctrlz migrate refuses. The repair file also puts the role's other connections back on the bound.
func TestARoleCanRewriteItsOwnDefaultsAndMigrateSeesIt(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	conn, err := d.Conn(ctx, "ctrlz_tenant")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	for _, stmt := range []string{"ALTER ROLE ctrlz_tenant SET statement_timeout = 0", "ALTER ROLE ctrlz_tenant SET transaction_timeout = 0"} {
		// The premise of the finding: an ordinary login role may rewrite its own defaults for good. If a
		// later Postgres stops it, this fails, and the judgement (which would then be belt and braces) can
		// be reconsidered by a person, not skipped by a test.
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	re := reachErr(t, ctx, d)
	if re == nil || !strings.Contains(re.Error(), "ctrlz_tenant: statement_timeout is \"0\"") {
		t.Fatalf("a role that zeroed its own defaults was not refused: %v", re)
	}
	if err := d.RunBootstrapFile(ctx, "15-role-bounds.sql"); err != nil {
		t.Fatal(err)
	}
	if re := reachErr(t, ctx, d); re != nil {
		t.Errorf("after the repair: %v", re)
	}
}

// TestCheckReachRefusesAnOpenFunctionNoFamilyNames is db-r16-11. Check 30 judges the families of
// catalog_reach.yaml, and an install that pulled a newer Postgres can hold a pg_catalog function that
// PUBLIC can use and no family names (18.7 added one; CI check 31 caught it, a production start did
// not). The migrate step asks check 31's question too: everything PUBLIC may use is on the reviewed
// list, and the error carries the statement that closes it, because no bootstrap file can.
func TestCheckReachRefusesAnOpenFunctionNoFamilyNames(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())
	// pg_ls_waldir is superuser-only by default and is in no family and not on the golden: the stand-in
	// for a function a later minor adds, which cannot be created in pg_catalog from here.
	if _, err := sup.Exec(ctx, `GRANT EXECUTE ON FUNCTION pg_catalog.pg_ls_waldir() TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	re := reachErr(t, ctx, d)
	if re == nil {
		t.Fatal("an unreviewed function open to PUBLIC was accepted")
	}
	if !strings.Contains(re.Error(), "pg_ls_waldir") || !strings.Contains(re.Error(), "REVOKE EXECUTE ON FUNCTION pg_ls_waldir() FROM PUBLIC") {
		t.Errorf("the error does not name the function and the statement that closes it: %v", re)
	}
	if len(re.Repairs) != 0 {
		t.Errorf("no bootstrap file closes this one, but the error names %v", re.Repairs)
	}
	if _, err := sup.Exec(ctx, `REVOKE EXECUTE ON FUNCTION pg_catalog.pg_ls_waldir() FROM PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if re := reachErr(t, ctx, d); re != nil {
		t.Errorf("closed again, CheckReach still says: %v", re)
	}
}

// TestAStaleEntryOrALostGrantDoesNotKeepTheStackDown is db-r16-6. Judge reports the hygiene of the
// files too (a name that matches no object, a family that matches none, a role named for a privilege
// it lacks), and those are CI's: a Postgres that drops a listed function must not keep the migrate
// container failing on every start with a message that names a repair file that cannot repair it.
func TestAStaleEntryOrALostGrantDoesNotKeepTheStackDown(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())

	// The definer owner loses the one grant the bootstrap gives back: a finding for CI (check 30), and
	// no reason to refuse a start (the functions that need it fail on their own, loudly).
	if _, err := sup.Exec(ctx, `REVOKE EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) FROM ctrlz_auth`); err != nil {
		t.Fatal(err)
	}
	defer sup.Exec(context.Background(), `GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO ctrlz_auth`)
	if re := reachErr(t, ctx, d); re != nil {
		t.Errorf("a lost grant that is no hole kept the stack down: %v", re)
	}

	file, err := reachcheck.ParseFile([]byte(`
functions:
  - family: ghost
    names: [pg_no_such_function]
    why: a name a release dropped
    execute: {"pg_no_such_function()": [auth]}
  - family: typo
    like: ['pg\_no\_such\_%']
    why: a pattern that matches nothing
    execute: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.Conn(ctx, "ctrlz_migrator")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	q := reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
		return conn.Query(ctx, sql, args...)
	})
	fs, err := reachcheck.Judge(ctx, q, file, []string{"ctrlz_auth"})
	if err != nil {
		t.Fatal(err)
	}
	var texts string
	for _, f := range fs {
		texts += f.Text + "\n"
	}
	for _, want := range []string{"the family matches no function of pg_catalog", "pg_no_such_function() is named in catalog_reach.yaml and matches no object"} {
		if !strings.Contains(texts, want) {
			t.Errorf("CI's judgement did not report %q:\n%s", want, texts)
		}
	}
	if sec := reachcheck.SecurityOnly(fs); len(sec) != 0 {
		t.Errorf("hygiene findings are marked as holes, so a stale entry would stop a start: %v", reachcheck.Texts(sec))
	}
}

// TestACatalogFileWithAMistypedKeyIsRefused is the second half of db-r16-11: Embedded used a lenient
// decode, so a family whose 'like' was mistyped had no pattern, matched nothing and was judged clean.
func TestACatalogFileWithAMistypedKeyIsRefused(t *testing.T) {
	if _, err := reachcheck.ParseFile([]byte("functions:\n  - family: x\n    lke: ['a%']\n    execute: {}\n")); err == nil {
		t.Fatal("a mistyped key was accepted")
	}
	if _, _, err := reachcheck.Embedded(); err != nil {
		t.Fatalf("the embedded file is not strictly decodable: %v", err)
	}
	if _, err := reachcheck.EmbeddedRoles(); err != nil {
		t.Fatalf("roles.yaml is not strictly decodable: %v", err)
	}
}

// TestCheckReachAsksTheRestOfTheBootstrapState is db-r16-24. The superuser bootstrap sets more than the
// role bounds once: the REVOKE of PUBLIC's CONNECT and TEMP on the database, the empty public schema
// (nothing for PUBLIC and for pg_database_owner), the memberships and the owners of the schemas. Only CI
// asked them (catalog checks 08 and 12, on a fresh cluster), so a restored dump or a database whose
// bootstrap ran in part kept PUBLIC TEMP and a public schema anybody could create in, and migrate started
// anyway. Each way the state can be lost is refused on the next start, and the two that the bootstrap
// file closes name the repair command.
func TestCheckReachAsksTheRestOfTheBootstrapState(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	if re := reachErr(t, ctx, d); re != nil {
		t.Fatalf("a freshly bootstrapped and migrated database is refused: %v", re)
	}
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())

	cases := []struct {
		name, plant, want, undo, stmt string
		repairFile                    string // the bootstrap file that repairs it, "" when the error prints the statement (stmt)
	}{
		{"PUBLIC may use temporary tables", "GRANT TEMPORARY ON DATABASE " + d.Name + " TO PUBLIC", "PUBLIC holds TEMPORARY on the database", "", "", "20-database.sql"},
		{"PUBLIC may connect (the default ACL back)", "GRANT CONNECT ON DATABASE " + d.Name + " TO PUBLIC", "PUBLIC holds CONNECT on the database", "", "", "20-database.sql"},
		{"a service role may create in the database", "GRANT CREATE ON DATABASE " + d.Name + " TO ctrlz_tenant", "ctrlz_tenant holds CREATE on the database", "", "", "20-database.sql"},
		{"anybody may create in the public schema", "GRANT CREATE ON SCHEMA public TO PUBLIC", "PUBLIC holds CREATE on schema public", "", "", "20-database.sql"},
		{"the owner of the database keeps its rights on public", "GRANT USAGE ON SCHEMA public TO pg_database_owner", "pg_database_owner holds USAGE on schema public", "", "", "20-database.sql"},
		{"a service role is a member of a built-in reader", "GRANT pg_read_all_data TO ctrlz_worker", "membership: role pg_read_all_data has member ctrlz_worker", "REVOKE pg_read_all_data FROM ctrlz_worker", `REVOKE "pg_read_all_data" FROM "ctrlz_worker"`, ""},
		{"the migrator inherits the definer role", "GRANT ctrlz_auth TO ctrlz_migrator WITH INHERIT TRUE", "membership: role ctrlz_auth has member ctrlz_migrator (inherit true", "REVOKE ctrlz_auth FROM ctrlz_migrator; GRANT ctrlz_auth TO ctrlz_migrator WITH INHERIT FALSE, SET TRUE", `REVOKE "ctrlz_auth" FROM "ctrlz_migrator"`, ""},
		{"a schema owned by a service role", "ALTER SCHEMA ctrlz_ext OWNER TO ctrlz_hub", "schema ctrlz_ext is owned by ctrlz_hub", "ALTER SCHEMA ctrlz_ext OWNER TO ctrlz_migrator", `ALTER SCHEMA "ctrlz_ext" OWNER TO "ctrlz_migrator"`, ""},
	}
	for _, m := range cases {
		t.Run(m.name, func(t *testing.T) {
			if _, err := sup.Exec(ctx, m.plant); err != nil {
				t.Fatalf("%s: %v", m.plant, err)
			}
			re := reachErr(t, ctx, d)
			if re == nil {
				t.Fatal("CheckReach accepted a database that lost bootstrap state")
			}
			if !strings.Contains(re.Error(), m.want) {
				t.Errorf("the error does not say what is lost (want %q): %v", m.want, re)
			}
			if m.repairFile != "" {
				if !strings.Contains(re.Error(), "bootstrap/"+m.repairFile) || !strings.Contains(re.Error(), "sh /ctrlz-bootstrap/repair.sh") {
					t.Errorf("the error does not name the repair file and the command that runs it: %v", re)
				}
				if err := d.RunBootstrapFile(ctx, m.repairFile); err != nil {
					t.Fatalf("the repair file failed: %v", err)
				}
			} else {
				if !strings.Contains(re.Error(), m.stmt) {
					t.Errorf("the error does not print the statement that closes it (%q): %v", m.stmt, re)
				}
				for _, s := range strings.Split(m.undo, "; ") {
					if _, err := sup.Exec(ctx, s); err != nil {
						t.Fatalf("%s: %v", s, err)
					}
				}
			}
			if re := reachErr(t, ctx, d); re != nil {
				t.Errorf("after the repair CheckReach still says: %v", re)
			}
		})
	}

	// What is only hygiene does not keep the stack down: a login role that lost CONNECT fails to connect,
	// loudly, and the repair is the same file.
	t.Run("a lost CONNECT is no hole", func(t *testing.T) {
		if _, err := sup.Exec(ctx, "REVOKE CONNECT ON DATABASE "+d.Name+" FROM ctrlz_keytool"); err != nil {
			t.Fatal(err)
		}
		if re := reachErr(t, ctx, d); re != nil {
			t.Errorf("a lost CONNECT kept the stack down: %v", re)
		}
		if err := d.RunBootstrapFile(ctx, "20-database.sql"); err != nil {
			t.Fatal(err)
		}
	})
}

// TestTheRepairScriptRunsAsWritten is db-r16-26. ctrlz migrate told the operator to re-run
// bootstrap/15-role-bounds.sql as the superuser, and the file needs twelve psql variables that only the
// initdb hook set, so `psql -f` died on a syntax error and repaired nothing: the repair of an installed
// database could not be run as written. The variables are one file now (vars.sh, which the hook sources
// too), and repair.sh runs the two idempotent files with the container's own environment. The test runs
// the real script in the server's container against a database that lost a role bound and PUBLIC's
// temporary privilege, after showing that the file alone, as the old message said, repairs nothing.
func TestTheRepairScriptRunsAsWritten(t *testing.T) {
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d := c.NewDB(ctx, t)
	sup, err := d.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer sup.Close(context.Background())
	for _, stmt := range []string{"ALTER ROLE ctrlz_tenant SET statement_timeout = 0", "GRANT TEMPORARY ON DATABASE " + d.Name + " TO PUBLIC"} {
		if _, err := sup.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if re := reachErr(t, ctx, d); re == nil || !strings.Contains(re.Error(), "sh /ctrlz-bootstrap/repair.sh") {
		t.Fatalf("the refusal does not name the repair command: %v", re)
	}

	dir := "/tmp/ctrlz-bootstrap"
	if out, code, err := c.Exec(ctx, "", nil, "mkdir", "-p", dir); err != nil || code != 0 {
		t.Fatalf("mkdir: %q %d %v", out, code, err)
	}
	for _, name := range []string{"repair.sh", "vars.sh"} {
		b, err := os.ReadFile("../../migrations/postgres/bootstrap/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.CopyIn(ctx, dir+"/"+name, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"15-role-bounds.sql", "20-database.sql"} {
		b, err := pgmigrations.Bootstrap.ReadFile("bootstrap/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.CopyIn(ctx, dir+"/"+name, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The old advice: the file by itself, no variables.
	if out, code, err := c.Exec(ctx, "postgres", nil, "psql", "-v", "ON_ERROR_STOP=1", "--username", "postgres", "--dbname", "postgres", "--no-psqlrc", "-f", dir+"/15-role-bounds.sql"); err != nil || code == 0 {
		t.Fatalf("the file alone ran (%q, exit %d, %v): the premise of the finding is gone", out, code, err)
	}
	if re := reachErr(t, ctx, d); re == nil {
		t.Fatal("the file alone repaired the database")
	}

	// The command the message names.
	out, code, err := c.Exec(ctx, "postgres", []string{"CTRLZ_BOOTSTRAP_DIR=" + dir, "CTRLZ_DB_NAME=" + d.Name}, "sh", dir+"/repair.sh")
	if err != nil || code != 0 {
		t.Fatalf("repair.sh: %q exit %d: %v", out, code, err)
	}
	if re := reachErr(t, ctx, d); re != nil {
		t.Errorf("after repair.sh CheckReach still says: %v", re)
	}
	// And again: it is idempotent.
	if out, code, err := c.Exec(ctx, "postgres", []string{"CTRLZ_BOOTSTRAP_DIR=" + dir, "CTRLZ_DB_NAME=" + d.Name}, "sh", dir+"/repair.sh"); err != nil || code != 0 {
		t.Fatalf("repair.sh the second time: %q exit %d: %v", out, code, err)
	}
	if re := reachErr(t, ctx, d); re != nil {
		t.Errorf("after the second run CheckReach says: %v", re)
	}
}
