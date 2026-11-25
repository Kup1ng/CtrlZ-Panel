package catalogtest

import (
	"context"
	"fmt"
)

// CheckConstraintsEnforced is catalog check 28 (rule role-reach, db-r13-3). Postgres 18 accepts NOT
// ENFORCED on a foreign key and a CHECK, and NOT VALID on a constraint added to a table that already
// has rows, and the server then stores what the constraint was there to refuse: a child row whose
// tenant key names another tenant's parent, a hash with no expiry, a NaN spend. The text of such a
// constraint still contains its expression (pg_get_constraintdef appends a suffix), so a check that
// matches on the expression cannot tell it from a live one.
//
// The rule is one line and it is asked of every constraint of ctrlz and river, domains included,
// whatever its kind and whoever reads it: pg_constraint.conenforced AND convalidated, or it is a
// finding. Nothing is allow-listed: a constraint that must exist unenforced has no use in this schema.
// Checks 07, 17 and 27 read the same two columns as well, so each of them fails for the constraint it
// owns and this one for any other.
func CheckConstraintsEnforced(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT n.nspname, COALESCE(cl.relname, 'domain ' || t.typname), c.conname, c.contype::text, c.conenforced, c.convalidated
FROM pg_constraint c
JOIN pg_namespace n ON n.oid = c.connamespace
LEFT JOIN pg_class cl ON cl.oid = c.conrelid
LEFT JOIN pg_type t ON t.oid = c.contypid
WHERE n.nspname IN ('ctrlz', 'river') AND (NOT c.conenforced OR NOT c.convalidated)
ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var schema, rel, name, kind string
		var enforced, validated bool
		if err := rows.Scan(&schema, &rel, &name, &kind, &enforced, &validated); err != nil {
			return nil, err
		}
		what := ""
		if !enforced {
			what += " NOT ENFORCED"
		}
		if !validated {
			what += " NOT VALID"
		}
		out = append(out, fmt.Sprintf("constraint %s on %s.%s (type %s) is%s: it refuses nothing the server would not store", name, schema, rel, kind, what))
	}
	return out, rows.Err()
}

// CheckNoRules is catalog check 29 (rule role-reach, db-r13-4). A rewrite rule's actions run with
// the privileges of the table's OWNER, not of the role whose statement fired it, so a rule on a
// ctrlz table is a second way to write what the column grants of guarded.yaml keep a login role from
// writing (the same reason the ON DELETE and ON UPDATE actions of a foreign key are judged), and a
// DO INSTEAD rule can make a write the design depends on, such as the revocation of a session, a
// no-op. Grants, guarded.yaml, the lock order, the trail rule and the credential generation list
// read statements and ACLs and none of them reads pg_rewrite.
//
// An allow list that fails closed: in every schema of the database but the system ones, the only
// rewrite rule permitted is the _RETURN rule of a view that views.yaml lists in ctrlz (every view has
// exactly that one rule). Anything else, on a table, a view or a materialized view, is a finding.
// The flag pg_class.relhasrules is not read: it is cleared lazily after DROP RULE, so it is stale
// information, while pg_rewrite is the rules themselves.
func CheckNoRules(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT n.nspname || '.' || c.relname, c.relkind::text, r.rulename, r.ev_type::text, r.is_instead
FROM pg_rewrite r
JOIN pg_class c ON c.oid = r.ev_class
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast'
  AND NOT (n.nspname = 'ctrlz' AND c.relkind = 'v' AND r.rulename = '_RETURN' AND c.relname = ANY($1::text[]))
ORDER BY 1, 3`, fx.Views.Views)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var rel, kind, rule, event string
		var instead bool
		if err := rows.Scan(&rel, &kind, &rule, &event, &instead); err != nil {
			return nil, err
		}
		also := "ALSO"
		if instead {
			also = "INSTEAD"
		}
		out = append(out, fmt.Sprintf("rewrite rule %s on %s (relkind %s, event %s, DO %s): a rule runs as the table's owner and can write guarded columns or silence a write; nothing but a listed view's own _RETURN rule is allowed", rule, rel, kind, event, also))
	}
	return out, rows.Err()
}
