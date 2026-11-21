package catalogtest_test

import (
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

// unorderedWrite is one multi-row write of a function that takes its rows in no declared order.
type unorderedWrite struct{ fn, kind string }

func TestDefinerWritesLockInKeyOrder(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	// No function is exempt by name (db-r17-13): ip_claim_take was, on the strength of a comment that said it
	// locked its rows first, and nothing read that text. It now takes the ordered shape like every other writer.
	for _, p := range definerWriteProblems(t, h) {
		t.Error(p)
	}
}

// definerWriteProblems is the judgement: it reads every function of ctrlz_fn, of every language, and the tables
// that a Go constant orders, and reports each multi-row write that breaks the class.
func definerWriteProblems(t *testing.T, h *harness) (problems []string) {
	t.Helper()
	ordered := tablesLockedInKeyOrder(t)
	for _, want := range []string{"sessions", "refresh_tokens", "api_tokens", "admin_sessions"} {
		if !ordered[want] {
			t.Fatalf("the derivation does not find %s among the tables locked in key order (%v): the source of truth moved", want, ordered)
		}
	}
	unique := uniqueKeys(t, h)
	lockKeys := lockOrderKeys(t, h)
	srf := setReturningFunctions(t, h)
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
		// The INSERT half of the class (db-r17-17): a statement that can add several rows waits for another
		// transaction's uncommitted row of the same key in the order its plan produces them, so it is sorted.
		// There is no exemption: a function that adds one row from a SELECT writes it as VALUES.
		is, err := lockrank.InsertsWith(src, srf)
		if err != nil {
			problems = append(problems, name+": "+err.Error())
			continue
		}
		for _, in := range is {
			if in.Multi && !in.Sorted {
				problems = append(problems, name+": an INSERT into ctrlz."+in.Table+" that can add several rows does not sort them (ORDER BY), so two transactions that insert the same keys can wait for each other")
			}
		}
		for _, w := range ws {
			if w.Keyed || w.Ordered || w.NoWait || namesOneRow(unique[w.Table], w.Pinned) || sortsByLockOrder(lockKeys[w.Table], w.OrderedBy) {
				continue
			}
			unordered[w.Table] = append(unordered[w.Table], unorderedWrite{name, w.Kind})
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for table, ws := range unordered {
		// The class (db-r16-19, db-r16-21, db-r17-4): two statements that can touch several rows of one table
		// lock them in the order each one scans them, and so does one statement against ITSELF: a plan is not
		// fixed (a custom and a generic plan, a sequential and an index scan, new statistics each give another
		// row order), so two concurrent runs of one function over overlapping rows can lock them in opposite
		// orders. Every multi-row writer therefore takes the ordered or the skip-locked shape, names one row by
		// a unique key. There is no exemption by name (db-r17-13).
		for _, w := range ws {
			why := "and the Go statements that write that table do"
			if !ordered[table] {
				why = "and a plan is not fixed, so even one statement can meet itself in another order"
			}
			problems = append(problems, w.fn+": a "+w.kind+" of ctrlz."+table+" that can touch several rows does not lock them in key order, "+why)
		}
	}
	sort.Strings(problems)
	return problems
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
	create(`CREATE FUNCTION ctrlz_fn.planted_one_row(p_hash bytea) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.auth_tickets SET attempts = attempts + 1 WHERE token_hash = p_hash $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_ordered(p uuid) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.api_tokens SET revoked_at = now() WHERE id = ANY (ARRAY(SELECT x.id FROM ctrlz.api_tokens x WHERE x.user_id = p ORDER BY x.id FOR NO KEY UPDATE)) $$`)
	// db-r17-4: ONE function that writes a table in plan order is not safe either (a plan is not fixed).
	create(`CREATE FUNCTION ctrlz_fn.planted_single_writer(p uuid) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.schedule_windows SET updated_at = now() WHERE tenant_id = ctrlz.current_tenant_id() $$`)
	// A table with no id: the sort that is the unique key is the one order, any other sort is not.
	create(`CREATE FUNCTION ctrlz_fn.planted_key_sorted(p text) RETURNS void LANGUAGE sql AS $$ DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.scope = p ORDER BY s.scope, s.key FOR UPDATE)) $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_key_sorted_wrong(p text) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.auth_throttle t SET count = 0 WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.scope = p ORDER BY s.key, s.scope FOR UPDATE)) $$`)
	// db-r17-12: the one order is the id (a table that has one) or the primary key, never another unique key.
	create(`CREATE FUNCTION ctrlz_fn.planted_other_unique_key(p uuid) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.api_tokens t SET revoked_at = now() WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.api_tokens s WHERE s.user_id = p ORDER BY s.token_hash FOR NO KEY UPDATE)) $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_ctid_by_id(p uuid) RETURNS void LANGUAGE sql AS $$ UPDATE ctrlz.api_tokens t SET revoked_at = now() WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.api_tokens s WHERE s.user_id = p ORDER BY s.id FOR NO KEY UPDATE)) $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_key_prefix_only(p text) RETURNS void LANGUAGE sql AS $$ DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s WHERE s.scope = p ORDER BY s.scope FOR UPDATE)) $$`)
	// db-r17-17: an INSERT of several rows is sorted, in either language; one row from VALUES is not judged.
	create(`CREATE FUNCTION ctrlz_fn.planted_insert_unsorted(p uuid) RETURNS void LANGUAGE sql AS $$ INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT t.id, 'endpoint_set', t.id, gen_random_uuid() FROM ctrlz.tenants t ON CONFLICT DO NOTHING $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_insert_unsorted_plpgsql(p uuid[]) RETURNS void LANGUAGE plpgsql AS $$ BEGIN INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT x, 'endpoint_set', x, gen_random_uuid() FROM unnest(p) AS x; END $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_insert_sorted(p uuid[]) RETURNS void LANGUAGE plpgsql AS $$ BEGIN INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT x, 'endpoint_set', x, gen_random_uuid() FROM unnest(p) AS x ORDER BY x ON CONFLICT DO NOTHING; END $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_insert_one_tuple(p uuid) RETURNS void LANGUAGE sql AS $$ INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) VALUES (p, 'endpoint_set', p, gen_random_uuid()) ON CONFLICT DO NOTHING $$`)
	// A SELECT with no FROM item adds one row, unless a function in it returns a set (read from the catalog).
	create(`CREATE FUNCTION ctrlz_fn.planted_insert_one_row_select(p uuid) RETURNS void LANGUAGE sql AS $$ INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT p, 'endpoint_set', p, gen_random_uuid() WHERE NOT EXISTS (SELECT 1 FROM ctrlz.policy_outbox) $$`)
	create(`CREATE FUNCTION ctrlz_fn.planted_insert_srf(p uuid[]) RETURNS void LANGUAGE sql AS $$ INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) SELECT unnest(p), 'endpoint_set', gen_random_uuid(), gen_random_uuid() $$`)
	problems := definerWriteProblems(t, h)
	got := strings.Join(problems, "\n")
	for _, want := range []string{
		"planted_sql_orders: a update of ctrlz.api_tokens",
		"planted_sql_a: a update of ctrlz.notifications",
		"planted_plpgsql_b: a delete of ctrlz.notifications",
		"planted_single_writer: a update of ctrlz.schedule_windows",
		"planted_key_sorted_wrong: a update of ctrlz.auth_throttle",
		"planted_other_unique_key: a update of ctrlz.api_tokens",
		"planted_insert_unsorted: an INSERT into ctrlz.policy_outbox",
		"planted_insert_unsorted_plpgsql: an INSERT into ctrlz.policy_outbox",
		"planted_insert_srf: an INSERT into ctrlz.policy_outbox",
		"planted_key_prefix_only: a delete of ctrlz.auth_throttle",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the check did not report %q:\n%s", want, got)
		}
	}
	for _, not := range []string{"planted_one_row", "planted_ordered", "planted_key_sorted:", "planted_ctid_by_id", "planted_insert_sorted", "planted_insert_one_tuple", "planted_insert_one_row_select"} {
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

// lockOrderKeys reads, from the live catalog, the one order in which the rows of each ctrlz table are locked
// (db-r17-12): `id` for a table that has an id column, which is the order of every Go statement (locks.go
// keyOrder) and every ordered definer write, and the primary key, in its column order, for a table with no id.
// A second unique key (a token hash) is a way to FIND a row, never an order to lock them in, so it is not
// here: a write that sorts by it meets a writer that sorts by id in the opposite order.
func lockOrderKeys(t *testing.T, h *harness) map[string][]string {
	t.Helper()
	rows, err := h.super.Query(h.ctx, `
SELECT c.relname,
  CASE WHEN EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'id' AND a.attnum > 0 AND NOT a.attisdropped)
       THEN ARRAY['id']
       ELSE (SELECT array_agg(a.attname::text ORDER BY k.ord)
             FROM pg_index i
             CROSS JOIN LATERAL unnest(i.indkey::int2[]) WITH ORDINALITY AS k(attnum, ord)
             JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
             WHERE i.indrelid = c.oid AND i.indisprimary)
  END
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'ctrlz'
WHERE c.relkind IN ('r', 'p')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var table string
		var cols []string
		if err := rows.Scan(&table, &cols); err != nil {
			t.Fatal(err)
		}
		out[table] = cols
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out["api_tokens"]) != 1 || len(out["auth_throttle"]) != 2 {
		t.Fatalf("the lock order of api_tokens and auth_throttle is not read (%v): the source of truth moved", out)
	}
	return out
}

// sortsByLockOrder says whether the locking subselect sorts by the table's one lock order, ascending and
// whole (see lockOrderKeys). A table with no key has none, so nothing it sorts by counts.
func sortsByLockOrder(key, by []string) bool {
	if len(key) == 0 || len(by) != len(key) {
		return false
	}
	for i := range key {
		if by[i] != key[i] {
			return false
		}
	}
	return true
}

// setReturningFunctions reads, from the live catalog, the names of the functions that return a set
// (pg_proc.proretset), so a SELECT with no FROM item is read as one row only when nothing in it can return
// several (db-r17-17): the list is the server's, not ours.
func setReturningFunctions(t *testing.T, h *harness) func(string) bool {
	t.Helper()
	rows, err := h.super.Query(h.ctx, `SELECT DISTINCT lower(proname::text) FROM pg_proc WHERE proretset AND prokind = 'f'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	names := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names[n] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !names["unnest"] || !names["generate_series"] {
		t.Fatalf("the set-returning functions are not read (%d names): the source of truth moved", len(names))
	}
	return func(name string) bool { return names[strings.ToLower(name)] }
}
