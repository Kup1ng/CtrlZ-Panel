package catalogtest_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The definer half of db-r16-19 (rule lock-order, "inside a rank"). The Go statements of internal/store take the
// rows of a table in key order through one shape (locks.go orderedUpdate, orderedDelete and keyOrder, and
// sweepKeyed for the tables the worker cannot lock), and internal/lint TestMultiRowWritesLockInKeyOrder holds
// them. A ctrlz_fn function writes rows too, and its text is in the catalog and not in a Go file. The class is
// "a table that any multi-row writer locks in key order is locked in key order by EVERY multi-row writer", and
// the tables are derived from the source rather than listed: every table that a store constant names beside
// one of the ordering identifiers.

var orderIdents = map[string]bool{"orderedUpdate": true, "orderedDelete": true, "keyOrder": true}

var ctrlzTable = regexp.MustCompile(`ctrlz\.([a-z_]+)`)

// tablesLockedInKeyOrder reads internal/store and returns the tables of the constants that carry an ordering
// identifier in their expression.
func tablesLockedInKeyOrder(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.Join("..")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			ordered := false
			var lits []string
			for _, v := range vs.Values {
				ast.Inspect(v, func(m ast.Node) bool {
					switch x := m.(type) {
					case *ast.Ident:
						if orderIdents[x.Name] {
							ordered = true
						}
					case *ast.BasicLit:
						if x.Kind == token.STRING {
							lits = append(lits, x.Value)
						}
					}
					return true
				})
			}
			if ordered {
				for _, l := range lits {
					for _, m := range ctrlzTable.FindAllStringSubmatch(l, -1) {
						out[m[1]] = true
					}
				}
			}
			return true
		})
	}
	return out
}

// definerWriteExempt are the functions whose multi-row writes to an ordered table need no key order, each with
// the reason. The key is the function name.
var definerWriteExempt = map[string]string{}

// unorderedWrite is one multi-row write of a function that takes its rows in no declared order.
type unorderedWrite struct{ fn, kind string }

func TestDefinerWritesLockInKeyOrder(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	problems, used := definerWriteProblems(t, h)
	for _, p := range problems {
		t.Error(p)
	}
	for name := range definerWriteExempt {
		if !used[name] {
			t.Errorf("definerWriteExempt names %s, which has no unordered multi-row write to an ordered table: remove the entry", name)
		}
	}
}

// definerWriteProblems is the judgement: it reads every function of ctrlz_fn, of every language, and the tables
// that a Go constant orders, and reports each multi-row write that breaks the class.
func definerWriteProblems(t *testing.T, h *harness) (problems []string, used map[string]bool) {
	t.Helper()
	ordered := tablesLockedInKeyOrder(t)
	for _, want := range []string{"sessions", "refresh_tokens", "api_tokens", "admin_sessions"} {
		if !ordered[want] {
			t.Fatalf("the derivation does not find %s among the tables locked in key order (%v): the source of truth moved", want, ordered)
		}
	}
	unique := uniqueKeys(t, h)
	// Every language: a LANGUAGE sql function is a definer function too (db-r16-21: the filter on plpgsql hid
	// auth_tickets_revoke). Only the functions of the ctrlz_fn schema write rows of ctrlz, so that is the set.
	rows, err := h.super.Query(h.ctx, `
SELECT p.proname, p.prosrc FROM pg_proc p
WHERE p.pronamespace = 'ctrlz_fn'::regnamespace AND p.prokind = 'f'
  AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('plpgsql', 'sql'))
ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	used = map[string]bool{}
	unordered := map[string][]unorderedWrite{}
	for rows.Next() {
		var name, src string
		if err := rows.Scan(&name, &src); err != nil {
			t.Fatal(err)
		}
		ws, err := lockrank.Writes(src)
		if err != nil {
			problems = append(problems, name+": "+err.Error())
			continue
		}
		for _, w := range ws {
			if w.Keyed || w.Ordered || w.NoWait || namesOneRow(unique[w.Table], w.Pinned) {
				continue
			}
			unordered[w.Table] = append(unordered[w.Table], unorderedWrite{name, w.Kind})
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for table, ws := range unordered {
		// The class (db-r16-19, db-r16-21): two statements that can touch several rows of one table lock them
		// in the order each one scans them, so a table is safe when at most ONE statement writes its rows
		// unordered (a statement meets itself in its own plan order), and it is not safe when any Go statement
		// or any other function orders it (then the others must too) or when two statements do not.
		if len(ws) < 2 && !ordered[table] {
			continue
		}
		for _, w := range ws {
			if _, ok := definerWriteExempt[w.fn]; ok {
				used[w.fn] = true
				continue
			}
			why := "and the Go statements that write that table do"
			if !ordered[table] {
				why = fmt.Sprintf("and %d statements of the functions write that table without one", len(ws))
			}
			problems = append(problems, w.fn+": a "+w.kind+" of ctrlz."+table+" that can touch several rows does not lock them in key order, "+why)
		}
	}
	sort.Strings(problems)
	return problems, used
}

// TestDefinerWriteLintCanFail plants functions in every language the check reads and requires the verdict:
// a LANGUAGE sql function that writes a table a Go statement orders, two functions (one sql, one plpgsql)
// that write one unordered table between them, and the shapes that must pass (a row named by a unique key,
// a function that takes the ordered shape).
func TestDefinerWriteLintCanFail(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	create := func(sql string) {
		t.Helper()
		if _, err := h.super.Exec(h.ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// Planted by the superuser into ctrlz_fn, and dropped with the test database.
	create(`CREATE FUNCTION ctrlz_fn.planted_sql_orders(p uuid) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.api_tokens SET revoked_at = now() WHERE user_id = p $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_sql_a(p uuid) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.notifications SET read_at = now() WHERE tenant_id = ctrlz.current_tenant_id() $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_plpgsql_b(p uuid) RETURNS void LANGUAGE plpgsql AS $$ BEGIN DELETE FROM ctrlz.notifications WHERE created_at < now(); END $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_one_row(p bytea) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.auth_tickets SET attempts = attempts + 1 WHERE token_hash = p $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_ordered(p uuid) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.api_tokens SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT x.id FROM ctrlz.api_tokens x WHERE x.user_id = p ORDER BY x.id FOR NO KEY UPDATE)) $$`)
	problems, _ := definerWriteProblems(t, h)
	got := strings.Join(problems, "\n")
	for _, want := range []string{
		"planted_sql_orders: a update of ctrlz.api_tokens",
		"planted_sql_a: a update of ctrlz.notifications",
		"planted_plpgsql_b: a delete of ctrlz.notifications",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the check did not report %q:\n%s", want, got)
		}
	}
	for _, not := range []string{"planted_one_row", "planted_ordered"} {
		if strings.Contains(got, not) {
			t.Errorf("the check reported %s, which names its row or takes the ordered shape:\n%s", not, got)
		}
	}
}

// uniqueKeys reads, from the live catalog, the column sets of every plain unique index (primary keys included)
// of the ctrlz tables. A write that equates all columns of one of them to a parameter names one row, whatever
// the column is called (a token hash, a composite primary key): the source of truth is the schema, not a list.
func uniqueKeys(t *testing.T, h *harness) map[string][][]string {
	t.Helper()
	rows, err := h.super.Query(h.ctx, `
SELECT c.relname, array_agg(a.attname::text ORDER BY k.ord)
FROM pg_index i
JOIN pg_class c ON c.oid = i.indrelid
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'ctrlz'
CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
WHERE i.indisunique AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indisvalid
GROUP BY c.relname, i.indexrelid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][][]string{}
	for rows.Next() {
		var table string
		var cols []string
		if err := rows.Scan(&table, &cols); err != nil {
			t.Fatal(err)
		}
		out[table] = append(out[table], cols)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out["auth_tickets"]) == 0 || len(out["auth_throttle"]) == 0 {
		t.Fatalf("the unique keys of auth_tickets and auth_throttle are not read (%v): the source of truth moved", out)
	}
	return out
}

// namesOneRow says whether the pinned columns hold every column of one unique key.
func namesOneRow(keys [][]string, pinned []string) bool {
	have := map[string]bool{}
	for _, p := range pinned {
		have[p] = true
	}
	for _, k := range keys {
		all := true
		for _, c := range k {
			all = all && have[c]
		}
		if all {
			return true
		}
	}
	return false
}
