package reachcheck

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Membership is one expected pg_auth_members row (roles.yaml).
type Membership struct {
	Role    string `yaml:"role"`
	Member  string `yaml:"member"`
	Inherit bool   `yaml:"inherit"`
	Set     bool   `yaml:"set"`
	Admin   bool   `yaml:"admin"`
}

// RoleSpec is the expected state of one role: its attributes, its connection limit and its
// role-wide defaults (pg_roles.rolconfig, as name to value). The numbers are those of the TEST
// profile; a real install takes them from its Compose profile, so the production judgement below
// compares the SHAPE (every key present, no bound zero) and catalog check 08 compares the values.
type RoleSpec struct {
	Login     bool              `yaml:"login"`
	ConnLimit int               `yaml:"conn_limit"`
	Settings  map[string]string `yaml:"settings"`
}

// RolesFile is roles.yaml.
type RolesFile struct {
	Roles        map[string]RoleSpec `yaml:"roles"`
	Memberships  []Membership        `yaml:"memberships"`
	SchemaOwners map[string]string   `yaml:"schema_owners"`
	Extensions   []string            `yaml:"extensions"`
	// DatabaseDefaults and ClusterDefaults are what ALTER DATABASE SET and ALTER ROLE ALL SET
	// hold (pg_db_role_setting rows with no role), both empty by design (db-r11-3).
	DatabaseDefaults map[string]string `yaml:"database_defaults"`
	ClusterDefaults  map[string]string `yaml:"cluster_defaults"`
}

// EmbeddedRoles reads roles.yaml from the copy inside the binary.
func EmbeddedRoles() (RolesFile, error) {
	var r RolesFile
	err := decodeStrict("roles.yaml", &r)
	return r, err
}

// RepairRoles is the file that sets the bounds again. It is idempotent (ALTER ROLE only), so a
// person can run it on an installed database, which 10-cluster.sql (CREATE ROLE) cannot be.
const RepairRoles = "bootstrap/15-role-bounds.sql"

// boundNumber reads the number of a setting such as '60s', '120 s', '0', '1.5min'.
var boundNumber = regexp.MustCompile(`^\s*([0-9]*\.?[0-9]+)\s*[a-zA-Z]*\s*$`)

// JudgeRoleBounds is the standing question of what the SUPERUSER bootstrap sets once and nothing asked
// again (db-r16-5): the attributes, the connection limit and the role defaults (search_path and the
// four timeouts) of every ctrlz role of roles.yaml that exists. Catalog check 08 asks the same of a
// fresh CI cluster with the values of the test profile; this is the part of it that holds for any
// profile, so the migrate step of every start can ask it of an installed database:
//
//   - no role is a superuser, bypasses RLS, creates roles or databases, or replicates, and each
//     login role logs in and each non-login role does not;
//   - a login role has a positive connection limit;
//   - rolconfig holds exactly the keys roles.yaml lists, with search_path as listed and every other
//     value a duration above zero (0 disables the bound, which is how a role removes its own: an
//     ordinary role may ALTER ROLE itself SET statement_timeout = 0);
//   - no ctrlz role has a setting for one database (pg_roles does not show it, Postgres applies it
//     first), and ALTER DATABASE SET and ALTER ROLE ALL SET hold what roles.yaml says.
//
// Every finding is a Security one: a lost bound is a hole, and the repair is RepairRoles.
func JudgeRoleBounds(ctx context.Context, q Querier, spec RolesFile) ([]Finding, error) {
	rows, err := q.Query(ctx, qRoleBounds)
	if err != nil {
		return nil, err
	}
	type live struct {
		super, bypass, createrole, createdb, login, repl bool
		limit                                            int
		config                                           []string
	}
	got := map[string]live{}
	for rows.Next() {
		var n string
		var l live
		if err := rows.Scan(&n, &l.super, &l.bypass, &l.createrole, &l.createdb, &l.login, &l.repl, &l.limit, &l.config); err != nil {
			rows.Close()
			return nil, err
		}
		got[n] = l
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []Finding
	add := func(format string, a ...any) {
		out = append(out, Finding{Text: fmt.Sprintf("role bounds: "+format, a...), Security: true, Repair: RepairRoles})
	}
	names := make([]string, 0, len(spec.Roles))
	for n := range spec.Roles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		exp := spec.Roles[n]
		l, ok := got[n]
		if !ok {
			continue // a role the database predates; catalog check 08 says it is missing
		}
		if l.super || l.bypass || l.createrole || l.createdb || l.repl {
			add("%s has a forbidden attribute (superuser, bypassrls, createrole, createdb or replication)", n)
		}
		if l.login != exp.Login {
			add("%s: rolcanlogin is %v, roles.yaml says %v", n, l.login, exp.Login)
		}
		if exp.Login && l.limit < 1 {
			add("%s has no connection limit (rolconnlimit %d)", n, l.limit)
		}
		have := map[string]string{}
		for _, kv := range l.config {
			k, v, _ := strings.Cut(kv, "=")
			have[k] = v
		}
		keys := make([]string, 0, len(exp.Settings))
		for k := range exp.Settings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v, set := have[k]
			switch {
			case !set:
				add("%s has no role default for %s", n, k)
			case k == "search_path" && v != exp.Settings[k]:
				add("%s: search_path is not what roles.yaml says", n)
			case k != "search_path" && !positive(v):
				add("%s: %s is %q, a bound must be above zero", n, k, v)
			}
		}
		var extra []string
		for k := range have {
			if _, listed := exp.Settings[k]; !listed {
				extra = append(extra, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			add("%s has a role default roles.yaml does not list: %s", n, k)
		}
	}

	// What Postgres applies beside rolconfig (db-r11-3).
	rows, err = q.Query(ctx, qRoleSettingsBeside)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var db, cluster []string
	for rows.Next() {
		var role, setting string
		var allRoles, allDBs, thisDB bool
		if err := rows.Scan(&role, &allDBs, &allRoles, &thisDB, &setting); err != nil {
			return nil, err
		}
		switch {
		case allRoles && allDBs:
			cluster = append(cluster, setting)
		case allRoles && thisDB:
			db = append(db, setting)
		case allRoles:
			// ALTER DATABASE SET of another database of the cluster: not ours to judge.
		case !allDBs:
			add("%s has a setting for one database that pg_roles.rolconfig does not show", role)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, c := range []struct {
		what string
		got  []string
		want map[string]string
	}{{"ALTER DATABASE SET", db, spec.DatabaseDefaults}, {"ALTER ROLE ALL SET", cluster, spec.ClusterDefaults}} {
		want := map[string]bool{}
		for k, v := range c.want {
			want[k+"="+v] = true
		}
		sort.Strings(c.got)
		for _, s := range c.got {
			if !want[s] {
				k, _, _ := strings.Cut(s, "=")
				add("%s holds %s, which roles.yaml does not list", c.what, k)
			}
		}
	}
	return out, nil
}

// positive reports whether a duration setting is above zero. A value it cannot read is not positive:
// the server accepted it, so it is a form this judgement does not know, and a bound nobody can read is
// not one to rely on.
func positive(v string) bool {
	m := boundNumber.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	return err == nil && f > 0
}

// DecodeRoles reads a roles.yaml text, for tests that plant one.
func DecodeRoles(b []byte) (RolesFile, error) {
	var r RolesFile
	err := yaml.Unmarshal(b, &r)
	return r, err
}

const qRoleBounds = `
SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit, COALESCE(rolconfig, '{}'::text[])
FROM pg_roles WHERE rolname LIKE 'ctrlz\_%'`

const qRoleSettingsBeside = `
SELECT COALESCE(r.rolname, ''), rs.setdatabase = 0, rs.setrole = 0, COALESCE(d.datname = current_database(), false), s
FROM pg_db_role_setting rs
LEFT JOIN pg_roles r ON r.oid = rs.setrole
LEFT JOIN pg_database d ON d.oid = rs.setdatabase
CROSS JOIN LATERAL unnest(rs.setconfig) AS s
WHERE rs.setrole = 0 OR r.rolname LIKE 'ctrlz\_%'`
