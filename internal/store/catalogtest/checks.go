package catalogtest

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
	"github.com/Kup1ng/CtrlZ-Panel/internal/reachcheck"
)

// Querier is what the checks need. *pgx.Conn and pgx.Tx both satisfy it, so
// the mutation test can break the database inside a transaction, run the
// checks in that transaction, and roll back.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Check is one numbered test of spec section 12.
type Check struct {
	// ID is the spec's number, e.g. "01".
	ID   string
	Name string
	Run  func(ctx context.Context, q Querier, fx *Fixtures) ([]string, error)
}

// Checks returns the catalog checks in spec order.
func Checks() []Check {
	return []Check{
		{"01", "every relation in ctrlz is listed", checkRelationsListed},
		{"02", "tenant tables key on tenant_id and force RLS", checkTenantTables},
		{"03", "tenant_isolation policy text", checkTenantIsolation},
		{"04", "global tables have no tenant_id and no RLS", checkGlobalTables},
		{"05", "policies equal the list exactly", checkPolicies},
		{"06", "primary keys and indexes lead with tenant_id", checkIndexes},
		{"07", "foreign keys are composite and complete", checkForeignKeys},
		{"08", "roles and memberships", checkRoles},
		{"09", "ownership", checkOwners},
		{"10", "SECURITY DEFINER list equals the allow-list", checkSecurityDefiner},
		{"11", "helper functions", checkHelpers},
		{"12", "grants equal the fixture", checkGrants},
		{"13", "default privileges", checkDefaultACL},
		{"14", "views are security_invoker", checkViews},
		{"15", "public schema is empty", checkPublicEmpty},
		{"16", "extensions", checkExtensions},
		{"17", "named constraints", checkNamedConstraints},
		{"18", "no email and no ai_malware column", checkForbiddenColumns},
		{"19", "tenant cannot write pair, hold and activity columns", checkTenantWriteDenied},
		{"20", "river belongs to the worker alone", checkRiver},
		{"21", "lock ranks of the functions and tables", checkLockRanks},
		{"22", "role reach: guarded columns, secrets and trail rows", CheckRoleReach},
		{"23", "guarded writes are functions that leave their trail", CheckGuardedFunctions},
		{"24", "one clock per security timestamp column", CheckClocks},
		{"25", "one credential generation per subject, moved by a trigger on the credential columns", CheckCredentialGen},
		{"26", "every cap is compared with ctrlz.cap_reached and is in internal/caps", CheckCaps},
		{"27", "every numeric column refuses NaN and infinity (or says why not)", CheckNaN},
		{"28", "every constraint is enforced and validated", CheckConstraintsEnforced},
		{"29", "no rewrite rule except the views' own", CheckNoRules},
		{"30", "pg_catalog reach: advisory locks, statistics, lock views, sizes and WAL position are nobody's but the named", CheckCatalogReach},
		{"31", "everything PUBLIC may use in pg_catalog is on the reviewed list", CheckCatalogOpen},
		{"32", "nothing notifies: no function, rule, view or default calls pg_notify or runs NOTIFY or LISTEN", CheckNoNotify},
	}
}

// strs runs a query and returns its first column as text, sorted.
func strs(ctx context.Context, q Querier, sql string, args ...any) ([]string, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// diff reports every element in only one of the two lists.
func diff(what string, want, got []string) []string {
	w := map[string]bool{}
	for _, s := range want {
		w[s] = true
	}
	g := map[string]bool{}
	for _, s := range got {
		g[s] = true
	}
	var out []string
	for _, s := range want {
		if !g[s] {
			out = append(out, fmt.Sprintf("%s: missing %s", what, s))
		}
	}
	for _, s := range got {
		if !w[s] {
			out = append(out, fmt.Sprintf("%s: unexpected %s", what, s))
		}
	}
	sort.Strings(out)
	return out
}

func role(short string) string { return "ctrlz_" + short }

// allRoles are the short names the fixtures may use.
func allRoles() []string {
	return []string{"tenant", "hub", "compiler", "worker", "admin", "auth", "backfill", "migrator", "keytool", "scoped"}
}

// column is one live column.
type column struct {
	Name    string
	Type    string
	NotNull bool
}

// liveColumns returns the columns of every ordinary table in ctrlz, in order.
func liveColumns(ctx context.Context, q Querier) (map[string][]column, error) {
	rows, err := q.Query(ctx, `
SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'ctrlz' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY c.relname, a.attnum`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]column{}
	for rows.Next() {
		var t string
		var c column
		if err := rows.Scan(&t, &c.Name, &c.Type, &c.NotNull); err != nil {
			return nil, err
		}
		out[t] = append(out[t], c)
	}
	return out, rows.Err()
}

func columnNames(cols []column) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = c.Name
	}
	return out
}

// 01 ---------------------------------------------------------------------------

func checkRelationsListed(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	got, err := strs(ctx, q, `
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'ctrlz' AND c.relkind IN ('r', 'p')`)
	if err != nil {
		return nil, err
	}
	return diff("tables.yaml", fx.AllTables(), got), nil
}

// 02 ---------------------------------------------------------------------------

func checkTenantTables(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	cols, err := liveColumns(ctx, q)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `
SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'ctrlz' AND c.relkind IN ('r', 'p')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rls := map[string][2]bool{}
	for rows.Next() {
		var t string
		var on, force bool
		if err := rows.Scan(&t, &on, &force); err != nil {
			return nil, err
		}
		rls[t] = [2]bool{on, force}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []string
	for _, t := range fx.Tables.Tenant {
		key := fx.KeyColumn(t)
		found := false
		for _, c := range cols[t] {
			if c.Name == key {
				found = true
				if c.Type != "uuid" || !c.NotNull {
					out = append(out, fmt.Sprintf("%s.%s must be uuid NOT NULL, is %s notnull=%v", t, key, c.Type, c.NotNull))
				}
			}
		}
		if !found {
			out = append(out, fmt.Sprintf("%s has no %s column", t, key))
		}
		st, ok := rls[t]
		switch {
		case !ok:
			// reported by check 01
		case !st[0]:
			out = append(out, fmt.Sprintf("%s: row level security is not enabled", t))
		case !st[1]:
			out = append(out, fmt.Sprintf("%s: row level security is not FORCED", t))
		}
	}
	return out, nil
}

// 03 ---------------------------------------------------------------------------

func checkTenantIsolation(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT tablename, permissive, roles::text, cmd, COALESCE(qual, '<null>'), COALESCE(with_check, '<null>')
FROM pg_policies WHERE schemaname = 'ctrlz' AND policyname = 'tenant_isolation'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type pol struct{ permissive, roles, cmd, qual, check string }
	have := map[string]pol{}
	for rows.Next() {
		var t string
		var p pol
		if err := rows.Scan(&t, &p.permissive, &p.roles, &p.cmd, &p.qual, &p.check); err != nil {
			return nil, err
		}
		have[t] = p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []string
	for _, t := range fx.Tables.Tenant {
		want := fmt.Sprintf("(%s = ctrlz.current_tenant_id())", fx.KeyColumn(t))
		p, ok := have[t]
		if !ok {
			out = append(out, fmt.Sprintf("%s: no tenant_isolation policy", t))
			continue
		}
		if p.permissive != "PERMISSIVE" || p.roles != "{public}" || p.cmd != "ALL" {
			out = append(out, fmt.Sprintf("%s: tenant_isolation is %s %s %s, want PERMISSIVE {public} ALL", t, p.permissive, p.roles, p.cmd))
		}
		if p.qual != want {
			out = append(out, fmt.Sprintf("%s: tenant_isolation USING is %s, want %s", t, p.qual, want))
		}
		if p.check != want {
			out = append(out, fmt.Sprintf("%s: tenant_isolation WITH CHECK is %s, want %s", t, p.check, want))
		}
	}
	return out, nil
}

// 04 ---------------------------------------------------------------------------

var tenantIDName = regexp.MustCompile(`(^|_)tenant_id$`)

func checkGlobalTables(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	cols, err := liveColumns(ctx, q)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `
SELECT c.relname, c.relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'ctrlz' AND c.relkind IN ('r', 'p')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rls := map[string]bool{}
	for rows.Next() {
		var t string
		var on bool
		if err := rows.Scan(&t, &on); err != nil {
			return nil, err
		}
		rls[t] = on
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, v := range fx.Tables.ValueColumns {
		allowed[v] = true
	}
	var out []string
	usedAllowed := map[string]bool{}
	// A global table may have RLS only when tables.yaml says so (its policies are then judged by
	// check 05). The list is the allow list: one reason exists today, the raw keys of
	// sms_counters that the sender must not read (sms-r8-3).
	wantRLS := map[string]bool{}
	for _, t := range fx.Tables.GlobalRLS {
		wantRLS[t] = true
	}
	for _, t := range fx.Tables.Global {
		switch {
		case rls[t] && !wantRLS[t]:
			out = append(out, fmt.Sprintf("%s: global table has row level security on", t))
		case !rls[t] && wantRLS[t]:
			out = append(out, fmt.Sprintf("%s: global table is listed under global_rls and has row level security off", t))
		}
		for _, c := range cols[t] {
			if tenantIDName.MatchString(c.Name) {
				key := t + "." + c.Name
				if !allowed[key] {
					out = append(out, fmt.Sprintf("%s: global table has a tenant id column, not listed as a value column", key))
				}
				usedAllowed[key] = true
			}
		}
	}
	isGlobal := map[string]bool{}
	for _, t := range fx.Tables.Global {
		isGlobal[t] = true
	}
	for t := range wantRLS {
		if !isGlobal[t] {
			out = append(out, fmt.Sprintf("tables.yaml global_rls lists %s, which is not a global table", t))
		}
	}
	for v := range allowed {
		if !usedAllowed[v] {
			out = append(out, fmt.Sprintf("tables.yaml value column %s does not exist", v))
		}
	}
	return out, nil
}

// 05 ---------------------------------------------------------------------------

func checkPolicies(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	var want []string
	for _, t := range fx.Tables.Tenant {
		e := fmt.Sprintf("(%s = ctrlz.current_tenant_id())", fx.KeyColumn(t))
		want = append(want, fmt.Sprintf("%s|tenant_isolation|ALL|{public}|%s|%s|PERMISSIVE", t, e, e))
	}
	for _, p := range fx.Policies.Named {
		if p.Name == "tenant_isolation" {
			return []string{"policies.yaml must not list tenant_isolation; it is derived from tables.yaml"}, nil
		}
		qual, check := "<null>", "<null>"
		if p.Qual != nil {
			qual = *p.Qual
		}
		if p.WithCheck != nil {
			check = *p.WithCheck
		}
		kind := "PERMISSIVE"
		if p.Restrictive {
			kind = "RESTRICTIVE"
		}
		want = append(want, fmt.Sprintf("%s|%s|%s|{%s}|%s|%s|%s", p.Table, p.Name, p.Cmd, p.Role, qual, check, kind))
	}
	got, err := strs(ctx, q, `
SELECT format('%s|%s|%s|%s|%s|%s|%s', tablename, policyname, cmd, roles::text, COALESCE(qual, '<null>'), COALESCE(with_check, '<null>'), permissive)
FROM pg_policies WHERE schemaname = 'ctrlz'`)
	if err != nil {
		return nil, err
	}
	out := diff("pg_policies", want, got)

	// The two rules of the spec, stated on their own so that a failure names
	// the rule and not only the row.
	loose, err := strs(ctx, q, `
SELECT format('%s.%s', tablename, policyname) FROM pg_policies
WHERE schemaname = 'ctrlz' AND policyname <> 'tenant_isolation' AND roles = '{public}'`)
	if err != nil {
		return nil, err
	}
	for _, l := range loose {
		out = append(out, "policy on PUBLIC other than tenant_isolation: "+l)
	}
	open, err := strs(ctx, q, `
SELECT format('%s.%s', tablename, policyname) FROM pg_policies
WHERE schemaname = 'ctrlz' AND policyname <> 'tenant_isolation' AND roles = '{public}' AND (qual = 'true' OR with_check = 'true')`)
	if err != nil {
		return nil, err
	}
	for _, l := range open {
		out = append(out, "USING (true) outside a named role: "+l)
	}
	return out, nil
}

// 06 ---------------------------------------------------------------------------

var indexAllow = regexp.MustCompile(`^([a-z_]+)\(([a-z0-9_]+)\)$`)

func checkIndexes(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	allow := map[string]bool{}
	for _, a := range fx.Tables.NonLeadingIndexes {
		m := indexAllow.FindStringSubmatch(a)
		if m == nil {
			return []string{"tables.yaml: bad non_leading_indexes entry " + a}, nil
		}
		allow[m[1]+"("+m[2]+")"] = true
	}
	rows, err := q.Query(ctx, `
SELECT t.relname, i.relname, COALESCE(a.attname, '<expression>'), x.indisprimary
FROM pg_index x
JOIN pg_class t ON t.oid = x.indrelid
JOIN pg_class i ON i.oid = x.indexrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = x.indkey[0]
WHERE n.nspname = 'ctrlz'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	usedAllow := map[string]bool{}
	for rows.Next() {
		var table, index, first string
		var primary bool
		if err := rows.Scan(&table, &index, &first, &primary); err != nil {
			return nil, err
		}
		if !fx.IsTenant(table) {
			continue
		}
		key := fx.KeyColumn(table)
		if first == key {
			continue
		}
		a := table + "(" + first + ")"
		if !primary && allow[a] {
			usedAllow[a] = true
			continue
		}
		kind := "index"
		if primary {
			kind = "primary key"
		}
		out = append(out, fmt.Sprintf("%s %s on %s leads with %s, not %s, and is not on the allow-list", kind, index, table, first, key))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for a := range allow {
		if !usedAllow[a] {
			out = append(out, "allow-listed index not found (stale entry): "+a)
		}
	}
	return out, nil
}

// 07 ---------------------------------------------------------------------------

type fkRow struct {
	child, parent string
	ccols, pcols  []string
	del           string
	// deferral is empty for an immediate key, " deferred" for a deferrable key that starts deferred and
	// " deferrable" for one that starts immediate, so a key cannot become deferred without a line in
	// foreign_keys.yaml (P3 2.2 item 7).
	deferral string
	// state is empty for a foreign key that is enforced and validated, and names what is missing
	// otherwise, so a NOT ENFORCED or NOT VALID key is a different string from the one in
	// foreign_keys.yaml and the diff reports it (db-r13-3).
	state string
}

func (f fkRow) String() string {
	return fmt.Sprintf("%s(%s) -> %s(%s) %s%s%s", f.child, strings.Join(f.ccols, ","), f.parent, strings.Join(f.pcols, ","), f.del, f.deferral, f.state)
}

func liveFKs(ctx context.Context, q Querier) ([]fkRow, error) {
	rows, err := q.Query(ctx, `
SELECT cl.relname, pl.relname,
  (SELECT array_agg(a.attname::text ORDER BY k.ord) FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
  (SELECT array_agg(a.attname::text ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ord) JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
  CASE c.confdeltype WHEN 'a' THEN 'no_action' WHEN 'r' THEN 'restrict' WHEN 'c' THEN 'cascade' WHEN 'n' THEN 'set_null' WHEN 'd' THEN 'set_default' END
   || COALESCE('(' || (SELECT string_agg(a.attname, ',') FROM unnest(c.confdelsetcols) k(attnum) JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum) || ')', ''),
  CASE WHEN NOT c.condeferrable THEN '' WHEN c.condeferred THEN ' deferred' ELSE ' deferrable' END,
  CASE WHEN c.conenforced THEN '' ELSE ' NOT ENFORCED' END || CASE WHEN c.convalidated THEN '' ELSE ' NOT VALID' END
FROM pg_constraint c
JOIN pg_class cl ON cl.oid = c.conrelid
JOIN pg_class pl ON pl.oid = c.confrelid
WHERE c.contype = 'f' AND c.connamespace = 'ctrlz'::regnamespace`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fkRow
	for rows.Next() {
		var f fkRow
		if err := rows.Scan(&f.child, &f.parent, &f.ccols, &f.pcols, &f.del, &f.deferral, &f.state); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func checkForeignKeys(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	fks, err := liveFKs(ctx, q)
	if err != nil {
		return nil, err
	}
	var got []string
	var out []string
	for _, f := range fks {
		got = append(got, f.String())
		childTenant, parentTenant := fx.IsTenant(f.child), fx.IsTenant(f.parent)
		switch {
		case childTenant && f.parent == "tenants":
			// The tenant row is keyed by id.
			if len(f.ccols) != 1 || f.ccols[0] != "tenant_id" || len(f.pcols) != 1 || f.pcols[0] != "id" {
				out = append(out, "foreign key to tenants must be (tenant_id) -> (id): "+f.String())
			}
		case childTenant && parentTenant:
			// Composite, with tenant_id at the same position on both sides.
			ok := false
			for i := range f.ccols {
				if f.ccols[i] == "tenant_id" && i < len(f.pcols) && f.pcols[i] == "tenant_id" {
					ok = true
				}
			}
			if !ok || len(f.ccols) < 2 {
				out = append(out, "foreign key between tenant tables must carry tenant_id on both sides at the same position: "+f.String())
			}
		case !childTenant && (parentTenant || f.parent == "tenants"):
			out = append(out, "foreign key from a global table to a tenant table: "+f.String())
		}
	}
	sort.Strings(got)
	want := append([]string{}, fx.ForeignKeys.ForeignKeys...)
	return append(out, diff("foreign_keys.yaml", want, got)...), nil
}

// 08 ---------------------------------------------------------------------------

func checkRoles(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit, COALESCE(rolconfig, '{}')
FROM pg_roles WHERE rolname LIKE 'ctrlz\_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	var names []string
	for rows.Next() {
		var n string
		var super, bypass, createrole, createdb, login, repl bool
		var connLimit int
		var config []string
		if err := rows.Scan(&n, &super, &bypass, &createrole, &createdb, &login, &repl, &connLimit, &config); err != nil {
			return nil, err
		}
		names = append(names, n)
		exp, ok := fx.Roles.Roles[n]
		if !ok {
			continue // reported by the diff below
		}
		if super || bypass || createrole || createdb || repl {
			out = append(out, fmt.Sprintf("%s has a forbidden attribute: super=%v bypassrls=%v createrole=%v createdb=%v replication=%v", n, super, bypass, createrole, createdb, repl))
		}
		if login != exp.Login {
			out = append(out, fmt.Sprintf("%s: rolcanlogin=%v, want %v", n, login, exp.Login))
		}
		// The bounds on a stuck transaction, a runaway query and the pool live
		// in these two, and losing them fails nothing else.
		if connLimit != exp.ConnLimit {
			out = append(out, fmt.Sprintf("%s: rolconnlimit=%d, want %d", n, connLimit, exp.ConnLimit))
		}
		var wantConfig []string
		for k, v := range exp.Settings {
			wantConfig = append(wantConfig, k+"="+v)
		}
		out = append(out, diff(n+" role defaults (rolconfig)", wantConfig, config)...)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var want []string
	for n := range fx.Roles.Roles {
		want = append(want, n)
	}
	sort.Strings(names)
	out = append(out, diff("ctrlz roles", want, names)...)

	got, err := strs(ctx, q, `
SELECT format('%s|%s|%s|%s|%s', pg_get_userbyid(m.roleid), pg_get_userbyid(m.member), m.inherit_option, m.set_option, m.admin_option)
FROM pg_auth_members m
WHERE pg_get_userbyid(m.roleid) LIKE 'ctrlz\_%' OR pg_get_userbyid(m.member) LIKE 'ctrlz\_%'`)
	if err != nil {
		return nil, err
	}
	var wantM []string
	for _, m := range fx.Roles.Memberships {
		wantM = append(wantM, fmt.Sprintf("%s|%s|%v|%v|%v", m.Role, m.Member, boolPG(m.Inherit), boolPG(m.Set), boolPG(m.Admin)))
	}
	out = append(out, diff("pg_auth_members", wantM, got)...)
	// What a login role gets BESIDE its own row of pg_roles (db-r11-3): the settings pg_roles hides
	// and the parameter privileges no ACL check reads.
	more, err := roleDefaultsBesideRolconfig(ctx, q, fx)
	if err != nil {
		return nil, err
	}
	out = append(out, more...)
	params, err := parameterPrivileges(ctx, q)
	if err != nil {
		return nil, err
	}
	return append(out, params...), nil
}

// roleDefaultsBesideRolconfig reads pg_db_role_setting in full. pg_roles.rolconfig shows only the
// rows with no database (ALTER ROLE r SET ...), and Postgres applies the others as well: a row for
// a role in one database comes BEFORE the role-wide line (so `ALTER ROLE ctrlz_tenant IN DATABASE
// ctrlz SET statement_timeout = 0` removes the bound while rolconfig still reads 60s), and a row
// with no role (ALTER DATABASE SET, ALTER ROLE ALL SET) reaches every login. Nothing a ctrlz role
// gets that way is declared, so any row for one in a single database fails, and the rows with no
// role are compared with roles.yaml (database_defaults, cluster_defaults), both empty.
func roleDefaultsBesideRolconfig(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT COALESCE(r.rolname, ''), rs.setdatabase = 0, rs.setrole = 0, COALESCE(d.datname, ''), d.datname = current_database(), s
FROM pg_db_role_setting rs
LEFT JOIN pg_roles r ON r.oid = rs.setrole
LEFT JOIN pg_database d ON d.oid = rs.setdatabase
CROSS JOIN LATERAL unnest(rs.setconfig) AS s
WHERE rs.setrole = 0 OR r.rolname LIKE 'ctrlz\_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out, gotDB, gotCluster []string
	for rows.Next() {
		var role, db, setting string
		var allDBs, allRoles bool
		var thisDB *bool
		if err := rows.Scan(&role, &allDBs, &allRoles, &db, &thisDB, &setting); err != nil {
			return nil, err
		}
		switch {
		case allRoles && allDBs:
			gotCluster = append(gotCluster, setting)
		case allRoles && thisDB != nil && *thisDB:
			gotDB = append(gotDB, setting)
		case allRoles:
			// ALTER DATABASE SET of another database of the cluster: not ours to judge.
		case !allDBs:
			out = append(out, fmt.Sprintf("%s has a setting for one database (%s: %s) that pg_roles.rolconfig does not show", role, db, setting))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out = append(out, diff("ALTER DATABASE SET (database_defaults)", settingList(fx.Roles.DatabaseDefaults), gotDB)...)
	return append(out, diff("ALTER ROLE ALL SET (cluster_defaults)", settingList(fx.Roles.ClusterDefaults), gotCluster)...), nil
}

func settingList(m map[string]string) []string {
	var out []string
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	return out
}

// parameterPrivileges fails for any privilege on a configuration parameter (GRANT SET or ALTER
// SYSTEM ON PARAMETER, Postgres 15 and later) that a ctrlz role holds, directly, through PUBLIC or
// through a role it is a member of. Check 12 asks has_table_privilege and has_column_privilege, which
// say nothing of parameters, and `SET LOCAL session_replication_role = replica` is what a parameter
// privilege lets a login role do: it skips every trigger that is not ENABLE ALWAYS, which is the
// premise of each "for every writer" guard. MEMBER and not USAGE, as in the row policies (sms-r9-8):
// a membership that does not inherit can still SET ROLE.
func parameterPrivileges(ctx context.Context, q Querier) ([]string, error) {
	got, err := strs(ctx, q, `
SELECT format('%s holds %s on parameter %s%s', r.rolname, a.privilege_type, p.parname,
              CASE WHEN a.grantee = 0 THEN ' through PUBLIC'
                   WHEN a.grantee = r.oid THEN ''
                   ELSE ' through ' || pg_get_userbyid(a.grantee) END)
FROM pg_parameter_acl p
CROSS JOIN LATERAL aclexplode(p.paracl) AS a
JOIN pg_roles r ON r.rolname LIKE 'ctrlz\_%'
 AND CASE WHEN a.grantee = 0 THEN true ELSE pg_has_role(r.oid, a.grantee, 'MEMBER') END`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, g := range got {
		out = append(out, "parameter privilege: "+g)
	}
	return out, nil
}

// boolPG prints a bool the way format('%s', bool) does.
func boolPG(b bool) string {
	if b {
		return "t"
	}
	return "f"
}

// 09 ---------------------------------------------------------------------------

func checkOwners(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	var out []string
	// The owners come from roles.yaml, the one source of them: the same file, and the same question
	// (reachcheck.WrongOwners), that reachcheck.JudgeBootstrapState asks on every start (db-r17-11, db-r17-15).
	// A file that names none fails here too.
	if fx.Roles.DatabaseOwner == "" || len(fx.Roles.SchemaOwners) == 0 {
		out = append(out, "roles.yaml must name database_owner and schema_owners")
	}
	// The database.
	dbOwner, err := strs(ctx, q, `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()`)
	if err != nil {
		return nil, err
	}
	if len(dbOwner) != 1 || dbOwner[0] != fx.Roles.DatabaseOwner {
		out = append(out, fmt.Sprintf("the database is owned by %v, roles.yaml says %s", dbOwner, fx.Roles.DatabaseOwner))
	}
	// Every object of every kind of every listed schema belongs to the owner of its schema.
	bad, err := reachcheck.WrongOwnersWith(ctx, reachcheck.QueryFunc(func(ctx context.Context, sql string, args ...any) (reachcheck.Rows, error) {
		return q.Query(ctx, sql, args...)
	}), fx.Roles.SchemaOwners, fx.Roles.FunctionOwners)
	if err != nil {
		return nil, err
	}
	for _, b := range bad {
		out = append(out, fmt.Sprintf("wrong owner: %s %s.%s owned by %s, schema_owners says %s", b.Kind, b.Schema, b.Name, b.Owner, b.Want))
	}
	// Schemas.
	var schemas []string
	for s := range fx.Roles.SchemaOwners {
		schemas = append(schemas, s)
	}
	got, err := strs(ctx, q, `SELECT format('%s|%s', nspname, pg_get_userbyid(nspowner)) FROM pg_namespace WHERE nspname = ANY($1::text[])`, schemas)
	if err != nil {
		return nil, err
	}
	var want []string
	for s, o := range fx.Roles.SchemaOwners {
		want = append(want, s+"|"+o)
	}
	out = append(out, diff("schema owners", want, got)...)
	// ctrlz_backfill owns nothing, anywhere.
	owned, err := strs(ctx, q, `
SELECT 'relation ' || relname FROM pg_class WHERE pg_get_userbyid(relowner) = 'ctrlz_backfill'
UNION ALL SELECT 'function ' || proname FROM pg_proc WHERE pg_get_userbyid(proowner) = 'ctrlz_backfill'
UNION ALL SELECT 'schema ' || nspname FROM pg_namespace WHERE pg_get_userbyid(nspowner) = 'ctrlz_backfill'
UNION ALL SELECT 'type ' || typname FROM pg_type WHERE pg_get_userbyid(typowner) = 'ctrlz_backfill'
UNION ALL SELECT 'database ' || datname FROM pg_database WHERE pg_get_userbyid(datdba) = 'ctrlz_backfill'`)
	if err != nil {
		return nil, err
	}
	for _, o := range owned {
		out = append(out, "ctrlz_backfill owns "+o)
	}
	return out, nil
}

// 10 ---------------------------------------------------------------------------

// ScopedPolicyFindings is the second half of the construction of db-r18-1: ctrlz_scoped meets no policy but
// tenant_isolation. It reads pg_policy as the server applies it (a policy that names no role applies to PUBLIC,
// so ctrlz_scoped too), and reports every policy that applies to the role and is not named tenant_isolation, a
// RESTRICTIVE policy included, and every role attribute that lets it past row-level security.
func ScopedPolicyFindings(ctx context.Context, q Querier) ([]string, error) {
	out, err := strs(ctx, q, `
SELECT format('policy %s on %s applies to ctrlz_scoped and is not tenant_isolation', p.polname, c.relname)
FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
WHERE p.polname <> 'tenant_isolation'
  AND (0 = ANY (p.polroles) OR (SELECT oid FROM pg_roles WHERE rolname = 'ctrlz_scoped') = ANY (p.polroles))`)
	if err != nil {
		return nil, err
	}
	attrs, err := strs(ctx, q, `
SELECT format('ctrlz_scoped has %s', a.what)
FROM pg_roles r CROSS JOIN LATERAL (VALUES (r.rolbypassrls, 'BYPASSRLS'), (r.rolsuper, 'SUPERUSER'), (r.rolcanlogin, 'LOGIN'), (r.rolcreaterole, 'CREATEROLE')) AS a(on_, what)
WHERE r.rolname = 'ctrlz_scoped' AND a.on_`)
	if err != nil {
		return nil, err
	}
	return append(out, attrs...), nil
}

func sdKey(name, args string) string { return fmt.Sprintf("%s(%s)", name, args) }

func checkSecurityDefiner(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	// Every SECURITY DEFINER function in the database, anywhere.
	got, err := strs(ctx, q, `
SELECT format('%s.%s(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		return nil, err
	}
	var want []string
	for _, f := range fx.Functions.SecurityDefiner {
		want = append(want, "ctrlz_fn."+sdKey(f.Name, f.Args))
	}
	out := diff("SECURITY DEFINER functions", want, got)

	// Schema ctrlz_fn holds nothing else.
	all, err := strs(ctx, q, `
SELECT format('ctrlz_fn.%s(%s)', p.proname, pg_get_function_identity_arguments(p.oid))
FROM pg_proc p WHERE p.pronamespace = 'ctrlz_fn'::regnamespace`)
	if err != nil {
		return nil, err
	}
	out = append(out, diff("objects in ctrlz_fn", want, all)...)
	other, err := strs(ctx, q, `
SELECT c.relname FROM pg_class c WHERE c.relnamespace = 'ctrlz_fn'::regnamespace
UNION ALL SELECT t.typname FROM pg_type t WHERE t.typnamespace = 'ctrlz_fn'::regnamespace AND t.typtype <> 'c' AND t.typelem = 0`)
	if err != nil {
		return nil, err
	}
	for _, o := range other {
		out = append(out, "ctrlz_fn holds a non-function object: "+o)
	}

	// No definer body runs dynamic SQL (db-r18-5, D64 lint-residual-shapes): lockrank, the reach and trail
	// checks and every lint read STATIC bodies, so a statement built at run time is a write none of them sees.
	ex, err := DefinerDynamicSQL(ctx, q)
	if err != nil {
		return nil, err
	}
	out = append(out, ex...)
	sp, err := ScopedPolicyFindings(ctx, q)
	if err != nil {
		return nil, err
	}
	out = append(out, sp...)

	// Per function: owner, search_path, result, ACL, body.
	for _, f := range fx.Functions.SecurityDefiner {
		rows, err := q.Query(ctx, `
SELECT pg_get_userbyid(p.proowner), COALESCE(p.proconfig::text, '<none>'), pg_get_function_result(p.oid), p.prosrc,
  COALESCE((SELECT array_agg(CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END ORDER BY 1)
            FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
            WHERE a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner), '{}')
FROM pg_proc p
WHERE p.pronamespace = 'ctrlz_fn'::regnamespace AND p.proname = $1 AND pg_get_function_identity_arguments(p.oid) = $2`, f.Name, f.Args)
		if err != nil {
			return nil, err
		}
		found := false
		for rows.Next() {
			found = true
			var owner, conf, result, src string
			var exec []string
			if err := rows.Scan(&owner, &conf, &result, &src, &exec); err != nil {
				rows.Close()
				return nil, err
			}
			id := sdKey(f.Name, f.Args)
			// db-r18-1: who a definer function runs as is not a default. ctrlz_scoped (no policy but
			// tenant_isolation) is the owner of every function that acts for the tenant of the call, and ctrlz_auth
			// (whose policies see every tenant) is the closed list, each with its reason. A function that says
			// neither, a reason on a scoped one, and a scoped function that is not about a tenant all fail.
			wantOwner := "ctrlz_scoped"
			switch f.Owner {
			case "auth":
				wantOwner = "ctrlz_auth"
				if strings.TrimSpace(f.AuthOwnerReason) == "" {
					out = append(out, fmt.Sprintf("%s: owner: auth has no auth_owner_reason; a function owned by ctrlz_auth, whose policies see every tenant, says why it needs that", id))
				}
			case "scoped":
				if f.AuthOwnerReason != "" {
					out = append(out, fmt.Sprintf("%s: owner: scoped has an auth_owner_reason", id))
				}
				if f.Isolation != "tenant" {
					out = append(out, fmt.Sprintf("%s: owner: scoped but isolation is %q; a scoped function acts for the tenant of the call (isolation: tenant)", id, f.Isolation))
				}
			default:
				out = append(out, fmt.Sprintf("%s: functions.yaml says owner %q, want auth or scoped", id, f.Owner))
			}
			if owner != wantOwner {
				out = append(out, fmt.Sprintf("%s: owner is %s, functions.yaml says %s", id, owner, wantOwner))
			}
			if conf != `{"search_path=pg_catalog, pg_temp"}` {
				out = append(out, fmt.Sprintf("%s: proconfig is %s, want search_path=pg_catalog, pg_temp", id, conf))
			}
			if result != f.Returns {
				out = append(out, fmt.Sprintf("%s: returns %s, want %s", id, result, f.Returns))
			}
			var wantExec []string
			for _, r := range f.Execute {
				wantExec = append(wantExec, role(r))
			}
			sort.Strings(exec)
			out = append(out, diff(id+" EXECUTE", wantExec, exec)...)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if !found {
			out = append(out, "missing function "+sdKey(f.Name, f.Args))
		}
	}
	return out, nil
}

// 11 ---------------------------------------------------------------------------

func checkHelpers(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	got, err := strs(ctx, q, `
SELECT format('%s(%s) %s', p.proname, pg_get_function_identity_arguments(p.oid), pg_get_function_result(p.oid))
FROM pg_proc p
WHERE p.pronamespace = 'ctrlz'::regnamespace AND NOT p.prosecdef
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')`)
	if err != nil {
		return nil, err
	}
	var want []string
	for _, h := range fx.Functions.Helpers {
		want = append(want, fmt.Sprintf("%s(%s) %s", h.Name, h.Args, h.Returns))
	}
	out := diff("functions in ctrlz", want, got)
	// The triggers that guard a delete. An updated_at trigger is not one of
	// them. The list is read WHATEVER the trigger's state is (db-r14-2): filtering on
	// tgenabled = 'O' made an unlisted trigger that is ENABLE ALWAYS or ENABLE REPLICA
	// invisible, and pg_get_triggerdef does not carry the state, so the definitions
	// cannot show it. The state is judged on its own just below.
	liveTriggers, err := strs(ctx, q, `
SELECT pg_get_triggerdef(t.oid)
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND NOT t.tgisinternal
  AND t.tgfoid <> 'ctrlz.touch_updated_at()'::regprocedure
  AND t.tgfoid NOT IN (SELECT p.oid FROM pg_proc p WHERE p.proname = 'credential_gen_bump' AND p.pronamespace = 'ctrlz'::regnamespace)`)
	if err != nil {
		return nil, err
	}
	out = append(out, diff("triggers on ctrlz tables", fx.Functions.Triggers, liveTriggers)...)
	// Every non-internal trigger of ctrlz is 'O' (origin: fires for ordinary sessions, skipped
	// under session_replication_role = replica). 'D' is as good as a missing trigger, and 'A' and
	// 'R' are a different promise from the one the guards were written for: an unlisted trigger
	// that fires under replica mode would run a guarded write the allow lists do not know of.
	// ENABLE ALWAYS on the guards is a decision for a reviewer (rules.md role-reach, round 11:
	// not adopted), so it is a finding here and not an allowed state. The exempt updated_at and
	// credential_gen_bump triggers are held to the same state.
	notOrigin, err := strs(ctx, q, `
SELECT format('trigger %s on %s is %s, want enabled for origin sessions only (O)', t.tgname, c.relname,
              CASE t.tgenabled WHEN 'D' THEN 'disabled (D)' WHEN 'A' THEN 'ENABLE ALWAYS (A)' WHEN 'R' THEN 'ENABLE REPLICA (R)' ELSE t.tgenabled::text END)
FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND NOT t.tgisinternal AND t.tgenabled <> 'O'`)
	if err != nil {
		return nil, err
	}
	out = append(out, notOrigin...)
	// ctrlz_ext holds only extension members.
	loose, err := strs(ctx, q, `
SELECT p.proname FROM pg_proc p
WHERE p.pronamespace = 'ctrlz_ext'::regnamespace
  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')`)
	if err != nil {
		return nil, err
	}
	for _, l := range loose {
		out = append(out, "ctrlz_ext holds a function that is not part of an extension: "+l)
	}
	return out, nil
}

// 12 ---------------------------------------------------------------------------

// privSet collects what pg_class and pg_attribute say, as Priv strings. Only
// SELECT, INSERT, UPDATE and DELETE are ever expected, so any other privilege
// type (TRUNCATE, REFERENCES, TRIGGER, MAINTAIN) shows up as unexpected.
func livePrivs(ctx context.Context, q Querier) ([]string, error) {
	tbl, err := strs(ctx, q, `
SELECT format('%s|%s|%s|*', c.relname, CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END, x.privilege_type)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault((CASE c.relkind WHEN 'S' THEN 's' ELSE 'r' END)::"char", c.relowner))) x
WHERE n.nspname = 'ctrlz' AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f') AND x.grantee <> c.relowner`)
	if err != nil {
		return nil, err
	}
	col, err := strs(ctx, q, `
SELECT format('%s|%s|%s|%s', c.relname, CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END, x.privilege_type, a.attname)
FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(a.attacl) x
WHERE n.nspname = 'ctrlz' AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL AND x.grantee <> c.relowner`)
	if err != nil {
		return nil, err
	}
	return append(tbl, col...), nil
}

func expectedPrivs(ctx context.Context, q Querier, fx *Fixtures) ([]string, []string, error) {
	cols, err := liveColumns(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	known := map[string]bool{}
	for _, r := range allRoles() {
		known[r] = true
	}
	var out, problems []string
	tables := make([]string, 0, len(fx.Grants.Tables))
	for t := range fx.Grants.Tables {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		if _, ok := cols[t]; !ok {
			problems = append(problems, "grants.yaml lists a table that does not exist: "+t)
			continue
		}
		for short, spec := range fx.Grants.Tables[t] {
			if !known[short] {
				problems = append(problems, fmt.Sprintf("grants.yaml: %s: unknown role %q", t, short))
				continue
			}
			ps, err := ParsePrivs(t, role(short), spec, columnNames(cols[t]))
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			for _, p := range ps {
				out = append(out, p.String())
			}
		}
	}
	for v, roles := range fx.Grants.Views {
		for _, r := range roles {
			out = append(out, Priv{v, role(r), "SELECT", "*"}.String())
		}
	}
	sort.Strings(out)
	return out, problems, nil
}

func checkGrants(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	want, out, err := expectedPrivs(ctx, q, fx)
	if err != nil {
		return nil, err
	}
	got, err := livePrivs(ctx, q)
	if err != nil {
		return nil, err
	}
	out = append(out, diff("table and column privileges", want, got)...)

	// Schemas.
	gotS, err := strs(ctx, q, `
SELECT format('%s|%s|%s', n.nspname, CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END, x.privilege_type)
FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) x
WHERE n.nspname IN ('public', 'ctrlz', 'ctrlz_fn', 'ctrlz_ext', 'river') AND x.grantee <> n.nspowner`)
	if err != nil {
		return nil, err
	}
	var wantS []string
	for s, g := range fx.Grants.Schemas {
		for _, r := range g.Usage {
			wantS = append(wantS, fmt.Sprintf("%s|%s|USAGE", s, role(r)))
		}
	}
	out = append(out, diff("schema privileges", wantS, gotS)...)

	// The database.
	gotD, err := strs(ctx, q, `
SELECT format('%s|%s', CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END, x.privilege_type)
FROM pg_database d CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) x
WHERE d.datname = current_database() AND x.grantee <> d.datdba`)
	if err != nil {
		return nil, err
	}
	var wantD []string
	for _, r := range fx.Grants.Database.Connect {
		wantD = append(wantD, role(r)+"|CONNECT")
	}
	out = append(out, diff("database privileges", wantD, gotD)...)

	// Functions: SECURITY DEFINER ones are checked by 10 in detail, and the
	// helpers here. PUBLIC must hold nothing on any function.
	gotF, err := strs(ctx, q, `
SELECT format('%s.%s|%s', n.nspname, p.proname, CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END)
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) x
WHERE n.nspname IN ('ctrlz', 'ctrlz_fn') AND x.grantee <> p.proowner AND x.privilege_type = 'EXECUTE'`)
	if err != nil {
		return nil, err
	}
	var wantF []string
	for _, r := range fx.Grants.CurrentTenantIDExecute {
		wantF = append(wantF, "ctrlz.current_tenant_id|"+role(r))
	}
	for _, f := range fx.Functions.SecurityDefiner {
		for _, r := range f.Execute {
			wantF = append(wantF, "ctrlz_fn."+f.Name+"|"+role(r))
		}
	}
	for _, h := range fx.Functions.Helpers {
		for _, r := range h.Execute {
			wantF = append(wantF, "ctrlz."+h.Name+"|"+role(r))
		}
	}
	return append(out, diff("function EXECUTE", wantF, gotF)...), nil
}

// 13 ---------------------------------------------------------------------------

func checkDefaultACL(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	got, err := strs(ctx, q, `
SELECT format('%s|%s|%s|%s', pg_get_userbyid(d.defaclrole), COALESCE(n.nspname, ''), d.defaclobjtype, d.defaclacl::text)
FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace`)
	if err != nil {
		return nil, err
	}
	var want []string
	for _, d := range fx.Grants.DefaultACL {
		want = append(want, fmt.Sprintf("%s|%s|%s|%s", d.Role, d.Schema, d.ObjType, d.ACL))
	}
	return diff("pg_default_acl", want, got), nil
}

// 14 ---------------------------------------------------------------------------

func checkViews(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	got, err := strs(ctx, q, `
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'ctrlz' AND c.relkind = 'v'`)
	if err != nil {
		return nil, err
	}
	out := diff("views.yaml", fx.Views.Views, got)
	noInvoker, err := strs(ctx, q, `
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'ctrlz' AND c.relkind = 'v' AND NOT COALESCE('security_invoker=true' = ANY (c.reloptions), false)`)
	if err != nil {
		return nil, err
	}
	for _, v := range noInvoker {
		out = append(out, "view without security_invoker=true: "+v)
	}
	mat, err := strs(ctx, q, `
SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'ctrlz' AND c.relkind = 'm'`)
	if err != nil {
		return nil, err
	}
	for _, m := range mat {
		out = append(out, "materialized view (ignores RLS): "+m)
	}
	// grants.yaml and views.yaml must agree.
	var inGrants []string
	for v := range fx.Grants.Views {
		inGrants = append(inGrants, v)
	}
	sort.Strings(inGrants)
	want := append([]string{}, fx.Views.Views...)
	sort.Strings(want)
	return append(out, diff("grants.yaml views against views.yaml", want, inGrants)...), nil
}

// 15 ---------------------------------------------------------------------------

func checkPublicEmpty(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	objs, err := strs(ctx, q, `
SELECT 'relation ' || relname FROM pg_class WHERE relnamespace = 'public'::regnamespace
UNION ALL SELECT 'function ' || proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace
UNION ALL SELECT 'type ' || typname FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typtype <> 'c'`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, o := range objs {
		out = append(out, "public holds an object: "+o)
	}
	acl, err := strs(ctx, q, `
SELECT CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END || ' ' || x.privilege_type
FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) x
WHERE n.nspname = 'public'`)
	if err != nil {
		return nil, err
	}
	for _, a := range acl {
		out = append(out, "public schema privilege: "+a)
	}
	return out, nil
}

// 16 ---------------------------------------------------------------------------

func checkExtensions(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	got, err := strs(ctx, q, `SELECT extname FROM pg_extension`)
	if err != nil {
		return nil, err
	}
	return diff("pg_extension", fx.Roles.Extensions, got), nil
}

// 17 ---------------------------------------------------------------------------

func checkNamedConstraints(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	var out []string
	for _, c := range fx.Tables.NamedConstraints {
		var def string
		var enforced, validated bool
		err := q.QueryRow(ctx, `
SELECT pg_get_constraintdef(oid), conenforced, convalidated FROM pg_constraint
WHERE conname = $1 AND conrelid = (quote_ident('ctrlz') || '.' || quote_ident($2))::regclass`, c.Name, c.Table).Scan(&def, &enforced, &validated)
		if err != nil {
			out = append(out, fmt.Sprintf("constraint %s on %s is missing", c.Name, c.Table))
			continue
		}
		// The text of a constraint that is switched off still contains its expression, with a
		// suffix, so the substring below cannot tell it from a live one (db-r13-3).
		if !enforced || !validated {
			out = append(out, fmt.Sprintf("constraint %s on %s is not enforced and validated: %s", c.Name, c.Table, def))
			continue
		}
		if !strings.Contains(def, c.Contains) {
			out = append(out, fmt.Sprintf("constraint %s on %s is %q, want it to contain %q", c.Name, c.Table, def, c.Contains))
		}
	}
	return out, nil
}

// 18 ---------------------------------------------------------------------------

func checkForbiddenColumns(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	bad, err := strs(ctx, q, `
SELECT c.relname || '.' || a.attname
FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname IN ('ctrlz', 'river') AND a.attnum > 0 AND NOT a.attisdropped
  AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND (a.attname ~* 'email' OR a.attname ~* 'ai_malware')`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, b := range bad {
		out = append(out, "forbidden column (phone is the identity, D23; AI Malware is removed, D5): "+b)
	}
	return out, nil
}

// 19 ---------------------------------------------------------------------------

func checkTenantWriteDenied(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	bad, err := strs(ctx, q, `
SELECT c.relname || '.' || a.attname || ' ' || p.priv
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN (VALUES ('INSERT'), ('UPDATE')) AS p(priv)
WHERE n.nspname = 'ctrlz' AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
  AND a.attname IN ('pair_override_node_a', 'pair_override_node_b', 'admin_hold', 'first_query_at', 'last_query_at')
  AND has_column_privilege('ctrlz_tenant', c.oid, a.attnum, p.priv)`)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, b := range bad {
		out = append(out, "ctrlz_tenant can write (D30): "+b)
	}
	return out, nil
}

// 20 ---------------------------------------------------------------------------

func checkRiver(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	var out []string
	for _, r := range []string{"tenant", "hub", "compiler", "admin", "auth", "backfill", "worker", "keytool", "scoped"} {
		var usage, create bool
		if err := q.QueryRow(ctx, `SELECT has_schema_privilege($1, 'river', 'USAGE'), has_schema_privilege($1, 'river', 'CREATE')`, role(r)).Scan(&usage, &create); err != nil {
			return nil, err
		}
		if r == "worker" {
			if !usage {
				out = append(out, "ctrlz_worker has no USAGE on river")
			}
		} else if usage {
			out = append(out, role(r)+" has USAGE on river")
		}
		if create {
			out = append(out, role(r)+" has CREATE on river")
		}
	}
	// Tables River will create inherit the worker-only default. Anything
	// already there must grant nobody else.
	others, err := strs(ctx, q, `
SELECT format('%s|%s', c.relname, CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) x
WHERE n.nspname = 'river' AND c.relkind IN ('r', 'p', 'v', 'S') AND x.grantee <> c.relowner
  AND pg_get_userbyid(x.grantee) <> 'ctrlz_worker'`)
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		out = append(out, "river object granted beyond the worker: "+o)
	}
	return out, nil
}

// 21 ---------------------------------------------------------------------------

// checkLockRanks holds the functions of the database to the lock order of
// package lockrank (P1 auth review, round 5; spec 4.4).
//
//   - Every table of ctrlz has a rank and every rank names a table.
//   - Each function's entry in functions.yaml is exactly what its body takes,
//     in order, so Go can apply it when it calls the function.
//   - The body takes its locks in rank order.
//   - No body locks users or admin_users with FOR UPDATE or FOR SHARE.
//
// The bodies are read from the live database, not from the migration files, so
// the last CREATE OR REPLACE is the one judged.
func checkLockRanks(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	out := diff("tables in the lock order", fx.AllTables(), lockrank.Tables())
	inert, err := checkInertKeyReach(ctx, q)
	if err != nil {
		return nil, err
	}
	out = append(out, inert...)
	rows, err := q.Query(ctx, `
SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosrc, n.nspname
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('ctrlz', 'ctrlz_fn') AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('plpgsql', 'sql'))ORDER BY 4, 1, 2`)
	if err != nil {
		return nil, err
	}
	type fn struct{ name, args, src, schema string }
	var fns []fn
	for rows.Next() {
		var f fn
		if err := rows.Scan(&f.name, &f.args, &f.src, &f.schema); err != nil {
			rows.Close()
			return nil, err
		}
		fns = append(fns, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	declared := map[string]*[]string{}
	purge := map[string]string{}
	for _, f := range fx.Functions.SecurityDefiner {
		declared["ctrlz_fn."+sdKey(f.Name, f.Args)] = f.Ranks
		purge["ctrlz_fn."+sdKey(f.Name, f.Args)] = f.InertDelete
	}
	unique, err := inertUniqueCols(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, h := range fx.Functions.Helpers {
		declared["ctrlz."+sdKey(h.Name, h.Args)] = h.Ranks
	}
	seen := map[string]bool{}
	for _, f := range fns {
		id := f.schema + "." + sdKey(f.name, f.args)
		seen[id] = true
		// Judged whether or not functions.yaml lists the function: a function nobody declared is the
		// one most likely to write a column nobody looked at (checks 10 and 11 report it as well).
		out = append(out, inertBodyFindings(id, f.src, purge[id], unique)...)
		want, listed := declared[id]
		if !listed {
			continue // check 10 and 11 report a function that is not listed
		}
		touches, err := lockrank.Analyze(f.src)
		if err != nil {
			out = append(out, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		got := lockrank.Declare(touches)
		switch {
		case want == nil:
			out = append(out, fmt.Sprintf("%s: functions.yaml has no ranks entry; its body takes %v", id, got))
		case strings.Join(*want, ",") != strings.Join(got, ","):
			out = append(out, fmt.Sprintf("%s: ranks in functions.yaml are %v, the body takes %v", id, *want, got))
		}
		var st lockrank.State
		if err := st.Acquire(touches); err != nil {
			out = append(out, fmt.Sprintf("%s: %v", id, err))
		}
		for _, t := range touches {
			if (t.Clause == "update" || t.Clause == "share") && (t.Table == "users" || t.Table == "admin_users" || lockrank.Inert(t.Table)) {
				out = append(out, fmt.Sprintf("%s: FOR %s on %s; only FOR NO KEY UPDATE and FOR KEY SHARE are allowed there", id, strings.ToUpper(t.Clause), t.Table))
			}
		}
	}
	for id := range declared {
		if !seen[id] {
			out = append(out, "functions.yaml lists "+id+" but the database has no such SQL or plpgsql function")
		}
	}
	sort.Strings(out)
	return out, nil
}

// checkInertKeyReach holds the premise of lockrank.Inert to the live grants (db-r8-1). A key
// share on an inert table is ignored because no statement of the system takes a lock on it that
// conflicts with FOR KEY SHARE, and that was written down as "it has no unique column that
// changes", a fact about the code that nothing checked: ctrlz_admin held UPDATE (username) on
// admin_users, a plain UNIQUE column, and an UPDATE that changes a unique-index column takes a
// FOR UPDATE strength tuple lock, which conflicts with the key share every admin_sessions insert
// takes through its foreign key. No statement did it, so there was no deadlock, and the
// statement guard would have classified the first one as an ordinary write.
//
// The premise is a property of the roles, so it is read from them: for every table lockrank
// calls inert, no login role (the table owner apart, as in check 22) may hold UPDATE on any
// column of a unique index, the primary key included (a column set that way is a key column to
// Postgres whatever the index is for; a partial unique index counts, to fail closed), nor DELETE
// on the table. A column or a role added tomorrow is judged the day it exists.
//
// Every role counts, not only LOGIN roles (db-r9-5): the SECURITY DEFINER functions of ctrlz_fn
// are owned by ctrlz_auth, which is NOLOGIN, and run with its privileges for whichever login role
// holds EXECUTE, so ctrlz_auth and ctrlz_backfill are the roles that write most. Superusers, the
// predefined pg_* roles (they hold every privilege implicitly and are not ours to revoke) and the
// owner of the table are the only exemptions. The bodies of the functions are judged in
// checkInertBodies, because a grant is only half of the reach.
func checkInertKeyReach(ctx context.Context, q Querier) ([]string, error) {
	var inert []string
	for _, t := range lockrank.Tables() {
		if lockrank.InertByRoles(t) {
			inert = append(inert, t)
		}
	}
	var out []string
	rows, err := q.Query(ctx, `
SELECT DISTINCT r.rolname, c.relname, a.attname
FROM pg_roles r
CROSS JOIN pg_class c
JOIN pg_index i ON i.indrelid = c.oid AND i.indisunique
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey) AND a.attnum > 0 AND NOT a.attisdropped
WHERE NOT r.rolsuper AND r.rolname !~ '^pg_'
  AND c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r', 'p') AND c.relname = ANY ($1)
  AND pg_get_userbyid(c.relowner) <> r.rolname
  AND has_column_privilege(r.oid, c.oid, a.attnum, 'UPDATE')
ORDER BY 1, 2, 3`, inert)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r, t, c string
		if err := rows.Scan(&r, &t, &c); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, fmt.Sprintf("lock order: %s can UPDATE %s.%s, a column of a unique index of a table the lock order calls inert; that statement takes a FOR UPDATE strength lock that conflicts with the key share of every child insert (revoke it, or give the table a rank)", r, t, c))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `
SELECT r.rolname, c.relname
FROM pg_roles r CROSS JOIN pg_class c
WHERE NOT r.rolsuper AND r.rolname !~ '^pg_'
  AND c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r', 'p') AND c.relname = ANY ($1)
  AND pg_get_userbyid(c.relowner) <> r.rolname
  AND has_table_privilege(r.oid, c.oid, 'DELETE')
ORDER BY 1, 2`, inert)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r, t string
		if err := rows.Scan(&r, &t); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, fmt.Sprintf("lock order: %s can DELETE from %s, a table the lock order calls inert; a delete takes a FOR UPDATE strength lock on the row", r, t))
	}
	rows.Close()
	return out, rows.Err()
}

// inertUniqueCols returns, for each inert table, the columns of any unique index (the primary
// key and a partial unique index included, to fail closed).
func inertUniqueCols(ctx context.Context, q Querier) (map[string]map[string]bool, error) {
	var inert []string
	for _, t := range lockrank.Tables() {
		if lockrank.InertByRoles(t) {
			inert = append(inert, t)
		}
	}
	rows, err := q.Query(ctx, `
SELECT DISTINCT c.relname, a.attname
FROM pg_class c
JOIN pg_index i ON i.indrelid = c.oid AND i.indisunique
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY (i.indkey) AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r', 'p') AND c.relname = ANY ($1)`, inert)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]bool{}
	for _, t := range inert {
		out[t] = map[string]bool{}
	}
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			return nil, err
		}
		out[t][c] = true
	}
	return out, rows.Err()
}

// inertBodyFindings judges one function body against the premise of lockrank.Inert, the half of
// check 21 that the grants cannot see (db-r9-5): a definer function writes with the privileges of
// its owner, and the owner's grants are only as narrow as the body is. A body that DELETEs from an
// inert table, or UPDATEs a column of a unique index of one, takes the FOR UPDATE strength lock
// the statement guard ignores on the grounds that nobody does, and the wait cycle with the key
// share of every child insert is back. A delete is allowed only for a function whose
// functions.yaml entry says `inert_delete` (the purge of a deleting tenant, a job of its own);
// the unique-column update has no exception.
func inertBodyFindings(id, src, purgeReason string, unique map[string]map[string]bool) []string {
	var out []string
	ts, err := lockrank.Targets(src)
	if err != nil {
		return []string{fmt.Sprintf("%s: the body cannot be read for its writes (%v), so check 21 cannot judge it against the inert-table premise", id, err)}
	}
	deletes := false
	for _, t := range ts {
		if t.Verb == lockrank.VerbDelete && lockrank.InertByRoles(t.Table) {
			deletes = true
			if purgeReason == "" {
				out = append(out, fmt.Sprintf("%s: DELETE FROM %s, a table the lock order calls inert; a delete takes a FOR UPDATE strength lock that conflicts with the key share of every child insert (declare inert_delete with the reason in functions.yaml if it is the purge of a deleting tenant)", id, t.Table))
			}
		}
	}
	if purgeReason != "" && !deletes {
		out = append(out, fmt.Sprintf("%s: functions.yaml says inert_delete, but the body deletes from no inert table; remove the note", id))
	}
	sets, err := lockrank.SetColumns(src)
	if err != nil {
		return append(out, fmt.Sprintf("%s: the SET lists of the body cannot be read (%v), so check 21 cannot judge it against the inert-table premise", id, err))
	}
	for _, w := range sets {
		u, inert := unique[w.Table]
		if !inert {
			continue
		}
		for _, c := range w.Cols {
			if u[c] {
				out = append(out, fmt.Sprintf("%s: UPDATE of %s.%s, a column of a unique index of a table the lock order calls inert; that statement takes a FOR UPDATE strength lock that conflicts with the key share of every child insert", id, w.Table, c))
			}
		}
	}
	return out
}

// executeWord is the plpgsql statement that runs a string as SQL. EXECUTE is a reserved word of the language,
// so it has no other spelling in a body; a match inside a comment or a literal is refused too (fail closed:
// the text of a definer body has no reason to say it).
var executeWord = regexp.MustCompile(`(?i)\bexecute\b`)

// DefinerDynamicSQL is the catalog check behind "a definer body is static" (db-r18-5). It reads EVERY function
// that runs with the rights of its owner (prosecdef), whatever schema it is in and whether or not the allow
// list names it, every function of schema ctrlz_fn, and every function owned by ctrlz_auth, and reports each
// one that is not LANGUAGE sql or plpgsql (a language this check cannot read) or whose body runs a string as
// SQL. It judges the text of the body only: a function of another family that runs a string (query_to_xml) is
// the Go lint's and the PUBLIC revokes' business, and a definer function cannot reach one that is revoked.
func DefinerDynamicSQL(ctx context.Context, q Querier) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT format('%s.%s(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)), l.lanname, p.prosrc
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE p.prokind = 'f' AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND (p.prosecdef OR n.nspname = 'ctrlz_fn' OR pg_get_userbyid(p.proowner) IN ('ctrlz_auth', 'ctrlz_scoped'))
ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, lang, src string
		if err := rows.Scan(&id, &lang, &src); err != nil {
			return nil, err
		}
		if lang != "sql" && lang != "plpgsql" {
			out = append(out, fmt.Sprintf("%s: language %s, which the checks cannot read (a definer function is sql or plpgsql)", id, lang))
			continue
		}
		if executeWord.MatchString(src) {
			out = append(out, fmt.Sprintf("%s: body contains EXECUTE (dynamic SQL): a definer body is static, so the lock order, reach and trail checks can read what it writes", id))
		}
	}
	return out, rows.Err()
}
