package catalogtest

import (
	"context"
	"fmt"
)

// CheckNoNotify is check 32 (db-r15-1, db-r15-3, db-r15-6). Nothing the database commits for a request
// may depend on NOTIFY. Postgres has one notification queue for the whole cluster and no privilege for
// LISTEN or NOTIFY: a login role that listens and stops reading keeps the queue from being emptied, a
// second one fills it, and from then on every transaction that notified fails at COMMIT (54000, which
// no EXCEPTION block of ours catches), for every tenant. auth_otp_issue notified for every accepted
// request, so no OTP could be issued; the admin outbox insert did the same. The notification was only
// a hint (the worker polls), so the rule is that there is none.
//
// Two readings, because neither sees everything. (1) Every function and procedure outside pg_catalog
// whose definition mentions pg_notify or a NOTIFY, LISTEN or UNLISTEN statement, in any schema and
// any language, comments removed (the first version looked for the text pg_notify in two schemas
// only, so a plpgsql NOTIFY statement or a function in another schema was invisible). (2) Every
// object that CARRIES a call of pg_notify (a column default, a view, a rule, a policy, a trigger condition,
// a constraint, an index), read from the deparsed expression, which no text search of a function body reaches.
func CheckNoNotify(ctx context.Context, q Querier, _ *Fixtures) ([]string, error) {
	var out []string
	bodies, err := strs(ctx, q, `
SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND p.prokind IN ('f', 'p')
  AND regexp_replace(pg_get_functiondef(p.oid), '--[^\n]*|/\*.*?\*/', ' ', 'gs') ~* '(pg_notify|\m(notify|listen|unlisten)\M)'`)
	if err != nil {
		return nil, err
	}
	for _, b := range bodies {
		out = append(out, fmt.Sprintf("notify: function %s sends or waits for a notification (a full cluster queue would fail the commit of every caller)", b))
	}
	// pg_depend has no row for a call of a pinned (system) function, so the dependency cannot be
	// asked; the deparsed text of every expression a database object carries can.
	exprs, err := strs(ctx, q, `
SELECT what FROM (
  SELECT 'default of ' || a.adrelid::regclass || '.' || a.adnum AS what, pg_get_expr(a.adbin, a.adrelid) AS t FROM pg_attrdef a
  UNION ALL SELECT 'view ' || c.oid::regclass, pg_get_viewdef(c.oid) FROM pg_class c WHERE c.relkind IN ('v', 'm')
  UNION ALL SELECT 'constraint ' || k.conname, pg_get_constraintdef(k.oid) FROM pg_constraint k
  UNION ALL SELECT 'trigger ' || g.tgname, pg_get_triggerdef(g.oid) FROM pg_trigger g WHERE NOT g.tgisinternal
  UNION ALL SELECT 'rule ' || r.rulename, pg_get_ruledef(r.oid) FROM pg_rewrite r
  UNION ALL SELECT 'policy ' || p.polname, COALESCE(pg_get_expr(p.polqual, p.polrelid), '') || ' ' || COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '') FROM pg_policy p
  UNION ALL SELECT 'index ' || i.indexrelid::regclass, pg_get_indexdef(i.indexrelid) FROM pg_index i
) x
WHERE what IS NOT NULL AND t ~* 'pg_notify'
  AND what NOT LIKE 'view pg\_catalog.%' AND what NOT LIKE 'view information\_schema.%' AND what NOT LIKE 'rule \_RETURN'`)
	if err != nil {
		return nil, err
	}
	for _, e := range exprs {
		out = append(out, fmt.Sprintf("notify: %s calls pg_notify", e))
	}
	return out, nil
}
