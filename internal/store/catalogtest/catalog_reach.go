package catalogtest

import (
	"context"
	"sort"

	"github.com/Kup1ng/CtrlZ-Panel/internal/reachcheck"
)

// ReachFamily is one family of pg_catalog objects that PUBLIC can use by default and that either
// hold shared server state or show what other sessions do (catalog_reach.yaml).
type ReachFamily = reachcheck.Family

// CatalogReachFile is catalog_reach.yaml.
type CatalogReachFile = reachcheck.File

// CheckCatalogReach is check 30 (db-r14-3, db-r14-4). The role-reach rule asked about OUR tables,
// columns, functions and policies, and a login role also reaches what Postgres leaves open to
// PUBLIC in pg_catalog: the advisory lock functions (one session's lock stops every other, and
// the keys the system takes can be computed by anyone), and the statistics, lock views, sizes and WAL
// position (what other sessions did, readable with no privilege on the tables they did it to).
//
// The judgement is internal/reachcheck's: the migrate step of every start asks the same question of
// the live database (db-r15-2, db-r15-8), so the two cannot drift apart.
func CheckCatalogReach(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	roles := make([]string, 0, len(fx.Roles.Roles))
	for n := range fx.Roles.Roles {
		roles = append(roles, n)
	}
	sort.Strings(roles)
	findings, err := reachcheck.Judge(ctx, reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
		return q.Query(ctx, sql, args...)
	}), fx.Reach, roles)
	return reachcheck.Texts(findings), err
}
