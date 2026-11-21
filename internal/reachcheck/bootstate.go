package reachcheck

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// JudgeBootstrapState asks, on every start, the rest of what the superuser bootstrap (10-cluster.sql
// and 20-database.sql) sets once and nothing asked again (P1 auth review round 16, db-r16-24; the
// role attributes and defaults are JudgeRoleBounds, db-r16-5). Catalog checks 08 and 12 ask them of a
// fresh CI cluster; a restored dump, a database whose bootstrap was run in part, or one an operator
// changed keeps the state it was left in, and the migrate step started anyway.
//
// Contract. It reads the catalog only and judges five things, each against roles.yaml (the one source
// of the names) and never a list kept here:
//
//   - the database: PUBLIC holds no privilege on it (the default ACL gives PUBLIC CONNECT and TEMP,
//     and 20-database.sql revokes it), and the only other grantees are the login roles of roles.yaml
//     with CONNECT and nothing else. A login role without CONNECT is hygiene, not a hole (the
//     service fails to connect, loudly), so it is not a Security finding;
//   - the public schema: no ACL entry at all, for PUBLIC and for pg_database_owner, whose implicit
//     rights would otherwise let the migrator create objects there;
//   - the memberships: pg_auth_members rows that name a ctrlz role on either side are exactly the ones
//     roles.yaml lists, with the inherit, set and admin options as listed (a ctrlz role that is a
//     member of pg_read_all_data, or the migrator inheriting ctrlz_auth, is a hole);
//   - the OWNERS (db-r17-11: the first form asked the owners of the schemas only; db-r17-15: the second
//     asked relations and functions through maps of their own): the database, the schemas, and every
//     object of every kind in a schema of schema_owners, which belongs to that schema's owner
//     (WrongOwners). An owner holds every right on the object implicitly, whatever the ACL says, and the
//     ACL questions above never see it: a database owned by a service role can create schemas and TEMP
//     tables, lock every service out with ALTER DATABASE and revoke CONNECT from the others. A roles.yaml
//     that names no owner for the database or no schema owner is itself a finding, so a file that
//     forgets a line fails closed.
//
// It also asks one server setting, because the watchdog's promise rests on it (db-r17-7): the watchdog
// ends BACKENDS, and a prepared transaction (PREPARE TRANSACTION) belongs to no backend, so a login role
// that could prepare one would leave its row locks where no sweep can end them. max_prepared_transactions
// must be 0 (the default, pinned in postgresql.conf and in the Compose lint); any other value, from a
// profile's -c flag or a changed default, is a Security finding.
//
// It does not judge the privileges on the ctrlz tables, columns and functions (catalog checks 09 to
// 13 against grants.yaml: those files are CI's) or the other schemas of the cluster. A database or
// role that does not exist yet is skipped, as in JudgeRoleBounds.
//
// The repair of the database and schema findings is RepairDatabase; membership and owner findings name
// the statement in their own text, because no idempotent bootstrap file can take a membership away.
func JudgeBootstrapState(ctx context.Context, q Querier, spec RolesFile) ([]Finding, error) {
	var out []Finding
	secure := func(repair, format string, a ...any) {
		out = append(out, Finding{Text: "bootstrap state: " + fmt.Sprintf(format, a...), Security: true, Repair: repair})
	}
	logins := map[string]bool{}
	for n, r := range spec.Roles {
		if r.Login {
			logins[n] = true
		}
	}

	// The database.
	rows, err := q.Query(ctx, qDatabaseACL)
	if err != nil {
		return nil, err
	}
	have := map[string]map[string]bool{}
	for rows.Next() {
		var grantee, priv string
		if err := rows.Scan(&grantee, &priv); err != nil {
			rows.Close()
			return nil, err
		}
		if have[grantee] == nil {
			have[grantee] = map[string]bool{}
		}
		have[grantee][priv] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	grantees := sortedKeys(have)
	for _, g := range grantees {
		privs := sortedKeys(have[g])
		switch {
		case g == "PUBLIC":
			secure(RepairDatabase, "PUBLIC holds %s on the database", strings.Join(privs, ", "))
		case logins[g]:
			for _, p := range privs {
				if p != "CONNECT" {
					secure(RepairDatabase, "%s holds %s on the database, roles.yaml gives a login role CONNECT only", g, p)
				}
			}
		default:
			secure(RepairDatabase, "%s holds %s on the database and is not a login role of roles.yaml", g, strings.Join(privs, ", "))
		}
	}
	existing, err := rolesNamed(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, n := range sortedKeys(logins) {
		if existing[n] && !have[n]["CONNECT"] {
			out = append(out, Finding{Text: fmt.Sprintf("bootstrap state: %s has no CONNECT on the database", n), Repair: RepairDatabase})
		}
	}

	// The public schema: nothing at all.
	rows, err = q.Query(ctx, qPublicSchemaACL)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var grantee, priv string
		if err := rows.Scan(&grantee, &priv); err != nil {
			rows.Close()
			return nil, err
		}
		secure(RepairDatabase, "%s holds %s on schema public, which must hold no ACL entry", grantee, priv)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The memberships of the ctrlz roles.
	rows, err = q.Query(ctx, qMemberships)
	if err != nil {
		return nil, err
	}
	live := map[Membership]bool{}
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.Role, &m.Member, &m.Inherit, &m.Set, &m.Admin); err != nil {
			rows.Close()
			return nil, err
		}
		live[m] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	want := map[Membership]bool{}
	for _, m := range spec.Memberships {
		want[m] = true
	}
	var extra, missing []string
	for m := range live {
		if !want[m] {
			extra = append(extra, fmt.Sprintf("role %s has member %s (inherit %v, set %v, admin %v); as the superuser run `REVOKE %s FROM %s`, or list it in roles.yaml", m.Role, m.Member, m.Inherit, m.Set, m.Admin, quoteIdent(m.Role), quoteIdent(m.Member)))
		}
	}
	for m := range want {
		if !live[m] && existing[m.Role] && existing[m.Member] {
			missing = append(missing, fmt.Sprintf("role %s lacks member %s with inherit %v, set %v, admin %v as roles.yaml says", m.Role, m.Member, m.Inherit, m.Set, m.Admin))
		}
	}
	sort.Strings(extra)
	sort.Strings(missing)
	for _, e := range extra {
		secure("", "membership: %s", e)
	}
	for _, m := range missing {
		// A lost membership removes a right the migrator needs (SET ROLE ctrlz_auth); the migration that
		// needs it fails loudly, so this is not a hole.
		out = append(out, Finding{Text: "bootstrap state: membership: " + m})
	}

	// The owners of the ctrlz schemas.
	rows, err = q.Query(ctx, qSchemaOwners, sortedKeys(spec.SchemaOwners))
	if err != nil {
		return nil, err
	}
	owners := map[string]string{}
	for rows.Next() {
		var s, o string
		if err := rows.Scan(&s, &o); err != nil {
			rows.Close()
			return nil, err
		}
		owners[s] = o
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, s := range sortedKeys(spec.SchemaOwners) {
		if o, ok := owners[s]; ok && o != spec.SchemaOwners[s] {
			secure("", "schema %s is owned by %s, roles.yaml says %s; as the superuser run `ALTER SCHEMA %s OWNER TO %s`", s, o, spec.SchemaOwners[s], quoteIdent(s), quoteIdent(spec.SchemaOwners[s]))
		}
	}

	// Prepared transactions are off.
	rows, err = q.Query(ctx, qPreparedTransactionsSetting)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return nil, err
		}
		if n != 0 {
			secure("", "max_prepared_transactions is %d: a prepared transaction belongs to no backend, so the watchdog cannot end the locks it keeps; set max_prepared_transactions = 0 in postgresql.conf and remove any -c flag that raises it", n)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The owner of the database, of the relations and of the functions.
	var dbName, dbOwner string
	rows, err = q.Query(ctx, qDatabaseOwner)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		if err := rows.Scan(&dbName, &dbOwner); err != nil {
			rows.Close()
			return nil, err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch {
	case spec.DatabaseOwner == "":
		secure("", "roles.yaml names no database_owner, so the owner of the database is not judged")
	case dbOwner != "" && dbOwner != spec.DatabaseOwner:
		secure("", "the database is owned by %s, roles.yaml says %s; as the superuser run `ALTER DATABASE %s OWNER TO %s`", dbOwner, spec.DatabaseOwner, quoteIdent(dbName), quoteIdent(spec.DatabaseOwner))
	}
	// Every object of every listed schema (db-r17-15; see WrongOwners). A roles.yaml that lists no schema owner
	// asks nothing, so that is itself a finding.
	if len(spec.SchemaOwners) == 0 {
		secure("", "roles.yaml names no schema_owners, so the owners of the objects of the ctrlz schemas are not judged")
	} else {
		bad, err := WrongOwners(ctx, q, spec.SchemaOwners)
		if err != nil {
			return nil, err
		}
		if len(bad) > 0 {
			// The text names the first object and the count, and no more: a restored dump can have a
			// thousand, and the statement is the same for each.
			f := bad[0]
			secure("", "%d object(s) of the ctrlz schemas are not owned as roles.yaml says (schema_owners), first %s %s.%s owned by %s; as the superuser run `ALTER <kind> %s.%s OWNER TO %s` for each, or `REASSIGN OWNED BY %s TO %s` when that role owns nothing else", len(bad), f.Kind, f.Schema, f.Name, f.Owner, quoteIdent(f.Schema), quoteIdent(f.Name), quoteIdent(f.Want), quoteIdent(f.Owner), quoteIdent(f.Want))
		}
	}
	return out, nil
}

// RepairDatabase is the file that closes the database and public-schema findings. It is idempotent
// (REVOKE and GRANT only).
const RepairDatabase = "bootstrap/20-database.sql"

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// quoteIdent quotes a role or schema name for the statement a finding prints.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func rolesNamed(ctx context.Context, q Querier) (map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolname LIKE 'ctrlz\_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}

// The default ACL of a database (datacl NULL) is what acldefault gives: the owner everything and PUBLIC
// CONNECT and TEMP, so a database nobody revoked from is read as open.
const qDatabaseACL = `
SELECT CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END, x.privilege_type
FROM pg_database d CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) x
WHERE d.datname = current_database() AND x.grantee <> d.datdba`

const qPublicSchemaACL = `
SELECT CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END, x.privilege_type
FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) x
WHERE n.nspname = 'public'`

const qMemberships = `
SELECT r.rolname, m.rolname, a.inherit_option, a.set_option, a.admin_option
FROM pg_auth_members a
JOIN pg_roles r ON r.oid = a.roleid
JOIN pg_roles m ON m.oid = a.member
WHERE r.rolname LIKE 'ctrlz\_%' OR m.rolname LIKE 'ctrlz\_%'`

const qPreparedTransactionsSetting = `SELECT pg_catalog.current_setting('max_prepared_transactions')::int`

const qDatabaseOwner = `
SELECT d.datname, pg_get_userbyid(d.datdba) FROM pg_database d WHERE d.datname = current_database()`

const qSchemaOwners = `
SELECT n.nspname, pg_get_userbyid(n.nspowner) FROM pg_namespace n WHERE n.nspname = ANY($1::text[])`
