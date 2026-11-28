package catalogtest_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// serviceRoles are the five roles that log in for a service, plus auth, which
// only SECURITY DEFINER functions run as. Behaviour tests exercise all six
// against every tenant table they have a grant on.
func serviceRoles() []string {
	return []string{"tenant", "hub", "compiler", "worker", "admin", "auth"}
}

// harness is the two-tenant harness: one migrated database holding two seeded
// tenants, A and B, with exactly one row of each in every tenant table. Tests
// act as a role with SET LOCAL ROLE on a superuser session, inside a
// transaction that is always rolled back. SET ROLE changes the user id that
// privilege and row security checks use, so the checks are exactly those of a
// login as that role, and the superuser session can look at the result
// afterwards without being filtered.
type harness struct {
	t     *testing.T
	ctx   context.Context
	fx    *catalogtest.Fixtures
	db    *testpg.DB
	super *pgx.Conn
	A, B  catalogtest.SeedIDs

	columns map[string][]string
	// privs[table][role] is the parsed privilege list.
	privs map[string]map[string][]catalogtest.Priv
}

func newHarness(t *testing.T, c *testpg.Cluster) *harness {
	t.Helper()
	// TestMutations used about half of a three minute context on a loaded
	// machine, and TestReleaseLoopCannotCollectChallenges once took two minutes
	// of it, and TestMutations used all ten on a loaded machine
	// after the plans table added its mutations to the list. The context is a backstop against a hang, not a budget, so it is
	// generous: a test that is slow is not a test that failed.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	t.Cleanup(cancel)
	fx := mustFixtures(t)
	db := c.NewDB(ctx, t)
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { super.Close(context.Background()) })
	h := &harness{t: t, ctx: ctx, fx: fx, db: db, super: super,
		A: catalogtest.NewSeedIDs(1), B: catalogtest.NewSeedIDs(2),
		columns: map[string][]string{}, privs: map[string]map[string][]catalogtest.Priv{}}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatalf("seed global: %v", err)
	}
	for _, ids := range []catalogtest.SeedIDs{h.A, h.B} {
		if err := catalogtest.SeedTenant(ctx, super, ids); err != nil {
			t.Fatalf("seed tenant %d: %v", ids.Index, err)
		}
	}
	rows, err := super.Query(ctx, `
SELECT c.relname, a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tbl, col string
		if err := rows.Scan(&tbl, &col); err != nil {
			t.Fatal(err)
		}
		h.columns[tbl] = append(h.columns[tbl], col)
	}
	rows.Close()
	for tbl, byRole := range fx.Grants.Tables {
		h.privs[tbl] = map[string][]catalogtest.Priv{}
		for role, spec := range byRole {
			ps, err := catalogtest.ParsePrivs(tbl, role, spec, h.columns[tbl])
			if err != nil {
				t.Fatal(err)
			}
			h.privs[tbl][role] = ps
		}
	}
	return h
}

// ident quotes a table in ctrlz.
func ident(table string) string { return pgx.Identifier{"ctrlz", table}.Sanitize() }

// has reports whether role holds a privilege of the kind on the table at all.
func (h *harness) has(table, role, kind string) bool {
	for _, p := range h.privs[table][role] {
		if p.Kind == kind {
			return true
		}
	}
	return false
}

// privCols returns the columns a role may use for a kind: all of them for a
// table-level grant, or the listed ones.
func (h *harness) privCols(table, role, kind string) (cols []string, whole bool) {
	for _, p := range h.privs[table][role] {
		if p.Kind != kind {
			continue
		}
		if p.Col == "*" {
			return h.columns[table], true
		}
		cols = append(cols, p.Col)
	}
	return cols, false
}

// namedAll reports whether a named policy gives the role a true-for-all-rows
// policy for the command, which makes every tenant's row reachable by design.
func (h *harness) namedAll(table, role, kind string) bool {
	isTrue := func(p *string) bool { return p != nil && *p == "true" }
	for _, p := range h.fx.Policies.Named {
		// A restrictive policy narrows access and never opens it.
		if p.Table != table || p.Role != "ctrlz_"+role || p.Restrictive {
			continue
		}
		if p.Cmd != "ALL" && p.Cmd != kind {
			continue
		}
		// An INSERT is judged by WITH CHECK, which for an ALL policy without
		// one is the USING expression. The other commands use USING. A policy
		// that names conditions (the outbox insert of ip_claim_take) is not
		// "all rows".
		if kind == "INSERT" {
			if isTrue(p.WithCheck) || (p.WithCheck == nil && isTrue(p.Qual)) {
				return true
			}
			continue
		}
		if isTrue(p.Qual) {
			return true
		}
	}
	return false
}

// inTx runs fn as role inside a transaction that is rolled back. guc is the
// value of ctrlz.tenant_id: nil leaves it untouched.
func (h *harness) inTx(conn *pgx.Conn, role string, guc *string, fn func(tx pgx.Tx)) {
	h.t.Helper()
	tx, err := conn.Begin(h.ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE "+pgx.Identifier{"ctrlz_" + role}.Sanitize()); err != nil {
		h.t.Fatalf("set role %s: %v", role, err)
	}
	if guc != nil {
		if _, err := tx.Exec(h.ctx, "SELECT pg_catalog.set_config('ctrlz.tenant_id', $1, true)", *guc); err != nil {
			h.t.Fatal(err)
		}
	}
	fn(tx)
}

func str(s string) *string { return &s }

// fresh opens a new superuser session, one that has never set the tenant
// setting, for the "unset" case.
func (h *harness) fresh() *pgx.Conn {
	h.t.Helper()
	conn, err := h.db.Super(h.ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func count(ctx context.Context, tx pgx.Tx, sql string, args ...any) (int, error) {
	var n int
	err := tx.QueryRow(ctx, sql, args...).Scan(&n)
	return n, err
}

// pgErr extracts the Postgres error, if any.
func pgErr(err error) *pgconn.PgError {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

func isRLSViolation(err error) bool {
	pe := pgErr(err)
	return pe != nil && pe.Code == "42501" && strings.Contains(pe.Message, "row-level security")
}

// defaultable reports whether a column accepts SET c = DEFAULT: it is

// defaultable reports whether a column accepts SET c = DEFAULT: it is
// nullable or has a default.
func (h *harness) defaultable(table, col string) bool {
	var ok bool
	err := h.super.QueryRow(h.ctx, `
SELECT NOT a.attnotnull OR a.atthasdef FROM pg_attribute a
WHERE a.attrelid = ('ctrlz.' || quote_ident($1))::regclass AND a.attname = $2`, table, col).Scan(&ok)
	return err == nil && ok
}
