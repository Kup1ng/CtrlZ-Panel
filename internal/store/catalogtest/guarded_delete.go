package catalogtest

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// The second half of rule role-reach (P1 auth review round 5, findings db-r5-1, db-r5-6,
// db-r5-8). Check 22 judged INSERT and UPDATE on the guarded columns, SELECT on a hand
// picked list of secret columns, and DELETE and TRUNCATE on the four trail tables only.
// That left holes of one kind, each a list somebody had to remember to extend:
//
//   - DELETE on a credential or authority table (admin_users, recovery_codes) was never
//     judged, and ctrlz_worker held DELETE on tenants, whose foreign keys cascade through
//     every row of a tenant, trail included, outside any policy;
//   - a secret column that nobody put on the `read` list (the sealed SMS credentials, the
//     sealed outbox parameters, the DoH token, the certificate key) was never judged at
//     all, so a later grant passed.
//
// Both are now decided by what the database holds, not by what a list remembers.

// checkDeleteReach judges DELETE and TRUNCATE for every login role that is not an owner.
func checkDeleteReach(ctx context.Context, q Querier, g GuardedFile, roles []string, owner map[string]bool, known func(string) bool) ([]string, error) {
	var out []string

	// What the schema lets a role delete: its own DELETE grants, and the children each
	// of those cascades into. A cascade is performed by the referential trigger as the
	// owner of the child table, so neither the role's grants on the child nor a policy
	// for the role is consulted; a DELETE on a parent is a DELETE of the whole subtree.
	del, trunc, err := deleteTruncatePrivileges(ctx, q)
	if err != nil {
		return nil, err
	}
	children, onDelete, onUpdate, err := foreignKeyReach(ctx, q)
	if err != nil {
		return nil, err
	}

	// TRUNCATE is refused to every role on every table of the schema: it ignores the
	// row policies, and nothing in the system truncates as a service.
	for _, k := range sortedKeys(trunc) {
		p := strings.Split(k, "|")
		if owner[p[0]] {
			continue
		}
		out = append(out, fmt.Sprintf("role reach: %s can TRUNCATE %s", p[0], p[1]))
	}

	// The tables whose rows are judged: every write-guarded table and every trail table.
	for t := range g.Delete {
		if _, ok := g.Write[t]; !ok {
			out = append(out, "guarded.yaml: delete lists "+t+", which is not a write-guarded table")
		}
	}
	for _, t := range sortedKeys(g.Write) {
		if _, ok := g.Delete[t]; !ok {
			out = append(out, "guarded.yaml: delete has no entry for the write-guarded table "+t+" ({} means nobody)")
		}
	}
	for t, m := range g.Delete {
		for r, why := range m {
			if !contains(allRoles(), r) {
				out = append(out, fmt.Sprintf("guarded.yaml: delete.%s: unknown role %q", t, r))
			}
			if len(strings.TrimSpace(why)) < 15 {
				out = append(out, fmt.Sprintf("guarded.yaml: delete.%s.%s: the reason is missing", t, r))
			}
		}
	}

	for _, r := range roles {
		if owner[r] {
			continue
		}
		direct := map[string]bool{}
		for _, k := range sortedKeys(del) {
			if p := strings.Split(k, "|"); p[0] == r {
				direct[p[1]] = true
			}
		}
		// via[t] is the first parent, in name order, whose DELETE reaches t by cascade.
		via := map[string]string{}
		for _, root := range sortedKeys(direct) {
			seen := map[string]bool{root: true}
			queue := []string{root}
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for _, c := range children[cur] {
					if seen[c] {
						continue
					}
					seen[c] = true
					if _, ok := via[c]; !ok {
						via[c] = root
					}
					queue = append(queue, c)
				}
			}
		}
		for _, table := range sortedKeys(g.Trail) {
			if !known(table) {
				continue
			}
			// A direct DELETE on a trail table is judged with the trail (an age-bounded
			// RESTRICTIVE policy). A cascade into it is bounded by nothing.
			if parent, ok := via[table]; ok {
				out = append(out, fmt.Sprintf("role reach: %s can DELETE trail table %s through the ON DELETE CASCADE of %s, which no policy bounds", r, table, parent))
			}
		}
		for _, table := range sortedKeys(g.Write) {
			if !known(table) {
				continue
			}
			parent, cascaded := via[table]
			reach := direct[table] || cascaded
			_, declared := g.Delete[table][short(r)]
			switch {
			case reach && !declared && direct[table]:
				out = append(out, fmt.Sprintf("role reach: %s can DELETE from %s; guarded.yaml delete does not declare it (use a function in ctrlz_fn)", r, table))
			case reach && !declared:
				out = append(out, fmt.Sprintf("role reach: %s can DELETE from %s through the ON DELETE CASCADE of %s; guarded.yaml delete does not declare it", r, table, parent))
			case !reach && declared:
				out = append(out, fmt.Sprintf("guarded.yaml: delete.%s declares %s, which no longer reaches a DELETE of the table; remove it", table, short(r)))
			}
		}
		out = append(out, judgeRewrites(g, r, direct, via, onDelete, onUpdate)...)
	}
	return out, nil
}

// checkSecretNames fails every column that guarded.yaml does not decide, in the two layers of
// secretName and freeForm: a column whose NAME looks secret is decided under `read`, `secrets`
// or `read_open` (its readers, or the reason anyone may read it), and a column of a free-form
// type that is not a name hit is listed under `open`. The test is over every table of the
// schema, so a column added by a later migration is judged the day it exists, whatever its
// name (db-r6-3, db-r6-10).
func checkSecretNames(g GuardedFile, cols map[string][]column) []string {
	var out []string
	named := func(table, col string) bool {
		if _, ok := g.Read[table][col]; ok {
			return true
		}
		if _, ok := g.Secrets[table][col]; ok {
			return true
		}
		_, ok := g.ReadOpen[table][col]
		return ok
	}
	personalNamed := func(table, col string) bool {
		if _, ok := g.Personal[table][col]; ok {
			return true
		}
		_, ok := g.PersonalOpen[table][col]
		return ok
	}
	openIn := func(table, col string) bool {
		for _, c := range g.Open[table].Columns {
			if c == col {
				return true
			}
		}
		return false
	}
	live := func(table, col string) (column, bool) {
		for _, c := range cols[table] {
			if c.Name == col {
				return c, true
			}
		}
		return column{}, false
	}
	for _, table := range sortedKeys(cols) {
		for _, c := range cols[table] {
			switch {
			case secretName(c) && !named(table, c.Name):
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s (%s) has a secret-looking name and no entry; give its readers under read or secrets, or the reason it is open under read_open", table, c.Name, c.Type))
			case personalName(c) && !personalNamed(table, c.Name) && !named(table, c.Name):
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s (%s) looks like personal data (a phone, an address or a user agent) and has no entry; give its readers under personal, or the reason it is open under personal_open", table, c.Name, c.Type))
			case !secretName(c) && !personalName(c) && freeForm(c) && !named(table, c.Name) && !personalNamed(table, c.Name) && !openIn(table, c.Name):
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s (%s) is a free-form column with no decision; list it under open (it holds no credential), under personal with its readers (it holds what a person put there) or, if it holds a credential, under read or secrets with its readers", table, c.Name, c.Type))
			}
		}
	}
	for _, table := range sortedKeys(g.ReadOpen) {
		for _, col := range sortedKeys(g.ReadOpen[table]) {
			c, found := live(table, col)
			switch {
			case !found:
				out = append(out, fmt.Sprintf("guarded.yaml: read_open.%s.%s is not a column", table, col))
			case !secretName(c):
				out = append(out, fmt.Sprintf("guarded.yaml: read_open.%s.%s does not look secret; remove it (a free-form column that is not a credential goes under open)", table, col))
			case len(strings.TrimSpace(g.ReadOpen[table][col])) < 15:
				out = append(out, fmt.Sprintf("guarded.yaml: read_open.%s.%s: the reason is missing", table, col))
			}
			if _, dup := g.Read[table][col]; dup {
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s is in both read and read_open", table, col))
			}
			if _, dup := g.Secrets[table][col]; dup {
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s is in both secrets and read_open", table, col))
			}
		}
	}
	for _, table := range sortedKeys(g.Personal) {
		for _, col := range sortedKeys(g.Personal[table]) {
			if _, found := live(table, col); !found {
				out = append(out, fmt.Sprintf("guarded.yaml: personal.%s.%s is not a column", table, col))
			}
			if _, dup := g.PersonalOpen[table][col]; dup {
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s is in both personal and personal_open", table, col))
			}
		}
	}
	for _, table := range sortedKeys(g.PersonalOpen) {
		for _, col := range sortedKeys(g.PersonalOpen[table]) {
			c, found := live(table, col)
			switch {
			case !found:
				out = append(out, fmt.Sprintf("guarded.yaml: personal_open.%s.%s is not a column", table, col))
			case !personalName(c):
				out = append(out, fmt.Sprintf("guarded.yaml: personal_open.%s.%s does not look like personal data; remove it", table, col))
			case len(strings.TrimSpace(g.PersonalOpen[table][col])) < 15:
				out = append(out, fmt.Sprintf("guarded.yaml: personal_open.%s.%s: the reason is missing", table, col))
			}
		}
	}
	for _, table := range sortedKeys(g.Open) {
		o := g.Open[table]
		if len(strings.TrimSpace(o.Why)) < 15 {
			out = append(out, fmt.Sprintf("guarded.yaml: open.%s: the reason is missing", table))
		}
		if len(strings.TrimSpace(o.NoPersonal)) < 15 {
			out = append(out, fmt.Sprintf("guarded.yaml: open.%s: no_personal is missing; say why none of the columns is about a person, or move the column that is to personal", table))
		}
		for _, col := range o.Columns {
			c, found := live(table, col)
			switch {
			case !found:
				out = append(out, fmt.Sprintf("guarded.yaml: open.%s.%s is not a column", table, col))
			case secretName(c):
				out = append(out, fmt.Sprintf("guarded.yaml: open.%s.%s has a secret-looking name; decide it under read, secrets or read_open", table, col))
			case personalName(c):
				out = append(out, fmt.Sprintf("guarded.yaml: open.%s.%s looks like personal data; decide it under personal or personal_open", table, col))
			case !freeForm(c):
				out = append(out, fmt.Sprintf("guarded.yaml: open.%s.%s is %s, which is not asked; remove it", table, col, c.Type))
			}
			if named(table, col) || personalNamed(table, col) {
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s is in open and in read, secrets, read_open, personal or personal_open", table, col))
			}
		}
	}
	sort.Strings(out)
	return out
}

// deleteTruncatePrivileges returns "role|table" for every DELETE, and every TRUNCATE, that
// a login role (not a superuser) holds at table level on any table of ctrlz, by any
// route: a direct grant, PUBLIC or membership.
func deleteTruncatePrivileges(ctx context.Context, q Querier) (del, trunc map[string]bool, err error) {
	rows, err := q.Query(ctx, `
SELECT r.rolname, c.relname, k.kind
FROM pg_roles r CROSS JOIN pg_class c CROSS JOIN (VALUES ('DELETE'), ('TRUNCATE')) AS k(kind)
WHERE r.rolcanlogin AND NOT r.rolsuper AND c.relnamespace = 'ctrlz'::regnamespace
  AND c.relkind IN ('r', 'p') AND has_table_privilege(r.oid, c.oid, k.kind)`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	del, trunc = map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var r, t, k string
		if err := rows.Scan(&r, &t, &k); err != nil {
			return nil, nil, err
		}
		if k == "DELETE" {
			del[r+"|"+t] = true
		} else {
			trunc[r+"|"+t] = true
		}
	}
	return del, trunc, rows.Err()
}

// rewrite is a change a referential action makes to the rows of a child table when a parent
// row is deleted (ON DELETE SET NULL, SET DEFAULT) or its key changes (ON UPDATE CASCADE, SET
// NULL, SET DEFAULT). It is performed as the owner of the child, so the role's column grants on
// the child, its policies and the trail rule are none of them consulted, exactly as for a
// cascading delete (db-r6-8).
type rewrite struct {
	parent, child string
	cols          []string
	how           string
}

// foreignKeyReach reads every foreign key of ctrlz that does more than refuse: the ON DELETE
// CASCADE children by parent, the rewrites an ON DELETE SET NULL or SET DEFAULT performs by
// parent, and the rewrites an ON UPDATE action performs by the role that can UPDATE a key
// column the key refers to.
func foreignKeyReach(ctx context.Context, q Querier) (cascade map[string][]string, onDelete map[string][]rewrite, onUpdate map[string][]rewrite, err error) {
	rows, err := q.Query(ctx, `
SELECT parent.relname, child.relname, c.confdeltype::text,
       (SELECT array_agg(a.attname::text ORDER BY k.n) FROM unnest(c.conkey) WITH ORDINALITY k(attnum, n)
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum)
FROM pg_constraint c
JOIN pg_class child ON child.oid = c.conrelid
JOIN pg_class parent ON parent.oid = c.confrelid
WHERE c.contype = 'f' AND c.confdeltype IN ('c', 'n', 'd')
  AND child.relnamespace = 'ctrlz'::regnamespace AND parent.relnamespace = 'ctrlz'::regnamespace
ORDER BY 1, 2`)
	if err != nil {
		return nil, nil, nil, err
	}
	cascade, onDelete, onUpdate = map[string][]string{}, map[string][]rewrite{}, map[string][]rewrite{}
	for rows.Next() {
		var p, c, kind string
		var cols []string
		if err := rows.Scan(&p, &c, &kind, &cols); err != nil {
			rows.Close()
			return nil, nil, nil, err
		}
		if kind == "c" {
			cascade[p] = append(cascade[p], c)
			continue
		}
		how := "ON DELETE SET NULL"
		if kind == "d" {
			how = "ON DELETE SET DEFAULT"
		}
		onDelete[p] = append(onDelete[p], rewrite{parent: p, child: c, cols: cols, how: how})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	// ON UPDATE actions run when a key the foreign key refers to changes: the role that can
	// UPDATE one of those key columns of the parent reaches them.
	rows, err = q.Query(ctx, `
SELECT r.rolname, parent.relname, child.relname, c.confupdtype::text,
       (SELECT array_agg(a.attname::text ORDER BY k.n) FROM unnest(c.conkey) WITH ORDINALITY k(attnum, n)
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum)
FROM pg_constraint c
JOIN pg_class child ON child.oid = c.conrelid
JOIN pg_class parent ON parent.oid = c.confrelid
CROSS JOIN pg_roles r
WHERE c.contype = 'f' AND c.confupdtype NOT IN ('a', 'r')
  AND child.relnamespace = 'ctrlz'::regnamespace AND parent.relnamespace = 'ctrlz'::regnamespace
  AND r.rolcanlogin AND NOT r.rolsuper
  AND EXISTS (SELECT 1 FROM unnest(c.confkey) k(attnum) WHERE has_column_privilege(r.oid, c.confrelid, k.attnum, 'UPDATE'))
ORDER BY 1, 2, 3`)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var role, p, c, kind string
		var cols []string
		if err := rows.Scan(&role, &p, &c, &kind, &cols); err != nil {
			return nil, nil, nil, err
		}
		how := map[string]string{"c": "ON UPDATE CASCADE", "n": "ON UPDATE SET NULL", "d": "ON UPDATE SET DEFAULT"}[kind]
		onUpdate[role] = append(onUpdate[role], rewrite{parent: p, child: c, cols: cols, how: how})
	}
	return cascade, onDelete, onUpdate, rows.Err()
}

// judgeRewrites decides, for one role, the rewrites its DELETE reach (a direct grant, or a
// parent a cascade reaches) and its UPDATE reach perform. A rewrite of a trail table is never
// allowed: it would erase which gateway carried each send, or who did what, outside the trail's
// rule. A rewrite of a write-guarded table is judged like a write by the role: it must be free
// or declared for the role in `write`, because the referential action is a write of those
// columns as the owner.
func judgeRewrites(g GuardedFile, r string, direct map[string]bool, via map[string]string, onDelete, onUpdate map[string][]rewrite) []string {
	var out []string
	reached := map[string]bool{}
	for t := range direct {
		reached[t] = true
	}
	for t := range via {
		reached[t] = true
	}
	var all []rewrite
	for _, t := range sortedKeys(reached) {
		all = append(all, onDelete[t]...)
	}
	all = append(all, onUpdate[r]...)
	for _, rw := range all {
		cols := strings.Join(rw.cols, ", ")
		if _, isTrail := g.Trail[rw.child]; isTrail {
			out = append(out, fmt.Sprintf("role reach: %s can rewrite trail table %s (%s) through the %s of %s, which no policy bounds", r, rw.child, cols, rw.how, rw.parent))
			continue
		}
		w, guarded := g.Write[rw.child]
		if !guarded {
			continue
		}
		decl := w.Declared[short(r)]
		for _, c := range rw.cols {
			if contains(w.Free, c) || decl.all() || contains(decl, c) {
				continue
			}
			out = append(out, fmt.Sprintf("role reach: %s can rewrite %s.%s through the %s of %s; guarded.yaml write does not declare it for the role", r, rw.child, c, rw.how, rw.parent))
		}
	}
	return out
}
