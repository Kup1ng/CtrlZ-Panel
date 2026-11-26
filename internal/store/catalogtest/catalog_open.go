package catalogtest

import (
	"context"
	"fmt"
	"sort"

	"github.com/Kup1ng/CtrlZ-Panel/internal/reachcheck"
)

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
//
// The security direction (an open object the golden does not hold) is internal/reachcheck's, which the
// migrate step of every start asks too (db-r16-11); the stale direction is CI's alone, because a
// dropped function is a file to tidy and not a reason to keep the stack down.
func CheckCatalogOpen(ctx context.Context, q Querier, _ *Fixtures) ([]string, error) {
	live, err := reachcheck.Open(ctx, reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
		return q.Query(ctx, sql, args...)
	}))
	if err != nil {
		return nil, err
	}
	want, err := reachcheck.OpenGolden()
	if err != nil {
		return nil, err
	}
	out := reachcheck.Texts(reachcheck.JudgeOpen(live, want))
	have := map[string]bool{}
	for _, o := range live {
		have[o.Line] = true
	}
	for l := range want {
		if !have[l] {
			out = append(out, fmt.Sprintf("catalog open: %s is in migrations/catalog/%s and PUBLIC cannot use it any more", l, reachcheck.OpenGoldenName))
		}
	}
	sort.Strings(out)
	return out, nil
}

// OpenCatalog lists what PUBLIC can use in pg_catalog, sorted, one "function ..." or "relation ..." line each.
func OpenCatalog(ctx context.Context, q Querier) ([]string, error) {
	live, err := reachcheck.Open(ctx, reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
		return q.Query(ctx, sql, args...)
	}))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(live))
	for _, o := range live {
		out = append(out, o.Line)
	}
	return out, nil
}
