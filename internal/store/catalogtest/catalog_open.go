package catalogtest

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strings"
)

// openGolden is the reviewed list of what PUBLIC may use in pg_catalog, one line per function
// ("function name(identity args)") and relation ("relation name"). Regenerate with
// `go test ./internal/store/catalogtest -run TestOpenCatalogGolden -update` and read the diff.
//
//go:embed testdata/pg_catalog_open.golden
var openGoldenFS embed.FS

// CheckCatalogOpen is check 31 (db-r15-9). Check 30 is default deny only INSIDE its families, and the
// families are name patterns somebody wrote, so a pg_catalog function outside every pattern was never
// judged: pg_blocking_pids and pg_control_checkpoint stayed open to PUBLIC although the families' own
// reasons (what other sessions hold, what the log position measures) forbid them. This check inverts
// the question. It lists EVERY function and relation of pg_catalog that PUBLIC can use, after the
// bootstrap, and compares the list with the reviewed golden in both directions: a Postgres release or
// a pg_upgrade that adds one fails CI until a person decides it (revoke it in
// bootstrap/20-database.sql and add it to catalog_reach.yaml, or accept it in the golden), and one
// that disappears fails too, so the golden cannot collect names. Anything check 30 names is closed
// and so never appears here.
func CheckCatalogOpen(ctx context.Context, q Querier, _ *Fixtures) ([]string, error) {
	live, err := OpenCatalog(ctx, q)
	if err != nil {
		return nil, err
	}
	golden, err := openGoldenFS.ReadFile("testdata/pg_catalog_open.golden")
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, l := range strings.Split(string(golden), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			want[l] = true
		}
	}
	have := map[string]bool{}
	var out []string
	for _, l := range live {
		have[l] = true
		if !want[l] {
			out = append(out, fmt.Sprintf("catalog open: PUBLIC can use pg_catalog %s, which is not in testdata/pg_catalog_open.golden: revoke it in bootstrap/20-database.sql (and name it in catalog_reach.yaml) or accept it in the golden", l))
		}
	}
	for l := range want {
		if !have[l] {
			out = append(out, fmt.Sprintf("catalog open: %s is in testdata/pg_catalog_open.golden and PUBLIC cannot use it any more", l))
		}
	}
	sort.Strings(out)
	return out, nil
}

// OpenCatalog lists what PUBLIC can use in pg_catalog, sorted, one "function ..." or "relation ..." line each.
func OpenCatalog(ctx context.Context, q Querier) ([]string, error) {
	fns, err := strs(ctx, q, `
SELECT 'function ' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
FROM pg_proc p
WHERE p.pronamespace = 'pg_catalog'::regnamespace
  AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')`)
	if err != nil {
		return nil, err
	}
	rels, err := strs(ctx, q, `
SELECT 'relation ' || c.relname
FROM pg_class c
WHERE c.relnamespace = 'pg_catalog'::regnamespace AND c.relkind IN ('r', 'v', 'm')
  AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'SELECT')`)
	if err != nil {
		return nil, err
	}
	out := append(fns, rels...)
	sort.Strings(out)
	return out, nil
}
