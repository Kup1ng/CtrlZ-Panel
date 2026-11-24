// Package reachcheck judges what the ctrlz login roles may do in pg_catalog without a grant on
// anything of ours (P1 auth review rounds 14 and 15, rule role-reach, topic 2).
//
// Postgres leaves a set of functions and views open to PUBLIC that either hold SHARED SERVER STATE
// (the advisory locks: one session's lock stops every other) or SHOW what other sessions do with no
// privilege on the tables they do it to (the statistics, the lock views, the sizes, the WAL
// position). migrations/catalog/catalog_reach.yaml lists those families and the roles that may hold
// each privilege; this package asks the live ACLs. It is a production package, not a test helper,
// because two callers need the same judgement: catalog check 30 in CI, and the migrate step of every
// start (internal/migrate CheckReach). The bootstrap that does the REVOKE is a superuser step that
// runs once, on an empty data directory, so an installed database, a restored dump or a cluster
// upgraded to a Postgres that adds a function under a matched name would otherwise stay open with
// every migration green (db-r15-2, db-r15-8).
package reachcheck

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	catalogfixtures "github.com/Kup1ng/CtrlZ-Panel/migrations/catalog"
)

// Rows is the part of a result set the judgement reads; pgx.Rows has it.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
	Err() error
}

// Querier is what the judgement needs. It names no driver type, because database access belongs in
// internal/store and the two callers that may hold a connection (internal/migrate and the catalog
// tests) wrap theirs in a QueryFunc.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// QueryFunc makes a Querier of a function, which is how a caller that holds a pgx connection or
// transaction passes it in: func(ctx, sql, args...) (reachcheck.Rows, error) { return c.Query(ctx, sql, args...) }.
type QueryFunc func(ctx context.Context, sql string, args ...any) (Rows, error)

// Query calls the function.
func (f QueryFunc) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	return f(ctx, sql, args...)
}

// Family is one family of pg_catalog objects that PUBLIC can use by default and that either hold
// shared server state or show what other sessions do (catalog_reach.yaml).
type Family struct {
	Family  string              `yaml:"family"`
	Like    []string            `yaml:"like"`
	Names   []string            `yaml:"names"`
	Why     string              `yaml:"why"`
	Execute map[string][]string `yaml:"execute"`
	Select  map[string][]string `yaml:"select"`
}

// File is catalog_reach.yaml.
type File struct {
	Functions []Family `yaml:"functions"`
	Relations []Family `yaml:"relations"`
}

// Finding is one thing the judgement reports. Security says the live database lets a role or PUBLIC
// do something the files forbid (a privilege nobody named, a bound a role may not lose). The other
// findings are about the FILES or about a grant the bootstrap should have given back: a name that
// matches no object any more, a family with no member, a role named for a privilege it lacks. CI
// reads them all (catalog check 30) because a person can fix the file the same day; the migrate step
// of a production start refuses only on Security, because the stack must not stay down for a
// condition that is harmless and that no re-run of a bootstrap file can repair (db-r16-6).
type Finding struct {
	Text     string
	Security bool
	// Repair names the file that closes the finding ("" when the text says what to do).
	Repair string
}

// Texts returns the text of each finding.
func Texts(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Text)
	}
	return out
}

// SecurityOnly keeps the findings that describe a hole.
func SecurityOnly(fs []Finding) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Security {
			out = append(out, f)
		}
	}
	return out
}

// decodeStrict reads one embedded fixture and refuses a key it does not know: a mistyped key
// ('lke:' for 'like:') would otherwise leave a family with no pattern, which matches nothing, which
// is judged clean (db-r16-11).
func decodeStrict(name string, into any) error {
	b, err := catalogfixtures.FS.ReadFile(name)
	if err != nil {
		return err
	}
	return decodeStrictBytes(name, b, into)
}

func decodeStrictBytes(name string, b []byte, into any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("reachcheck: %s: %w", name, err)
	}
	return nil
}

// ParseFile reads a catalog_reach.yaml text with the same strictness as the embedded copy.
func ParseFile(b []byte) (File, error) {
	var f File
	err := decodeStrictBytes("catalog_reach.yaml", b, &f)
	return f, err
}

// Embedded reads catalog_reach.yaml and the role names of roles.yaml from the copy inside the
// binary, so the migrate container needs no file next to it.
func Embedded() (File, []string, error) {
	var f File
	if err := decodeStrict("catalog_reach.yaml", &f); err != nil {
		return f, nil, err
	}
	r, err := EmbeddedRoles()
	if err != nil {
		return f, nil, err
	}
	roles := make([]string, 0, len(r.Roles))
	for n := range r.Roles {
		roles = append(roles, n)
	}
	sort.Strings(roles)
	return f, roles, nil
}

// Existing keeps the roles that exist in the cluster. has_function_privilege raises for a role that
// does not, and an installed database may predate a role (ctrlz_keytool, 0017); the roles check
// of the catalog tests, not this judgement, says a role is missing.
func Existing(ctx context.Context, q Querier, roles []string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT r FROM unnest($1::text[]) r WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) ORDER BY 1`, roles)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Judge is check 30 (db-r14-3, db-r14-4). For every object that matches a family, each of roles
// (full role names) holds the privilege if and only if the entry names it, and PUBLIC holds it never.
// An entry that matches nothing is reported too, so the list cannot collect names a Postgres release
// dropped, and so is a family that matches no object at all (a mistyped pattern). Default deny: a role
// added later is judged by the same query, and a function added by a later Postgres under a matched
// name is judged without a line being written.
func Judge(ctx context.Context, q Querier, f File, roles []string) ([]Finding, error) {
	var out []Finding
	for _, fam := range f.Functions {
		objs, err := objects(ctx, q, fam, "f", roles)
		if err != nil {
			return nil, err
		}
		out = append(out, judge(fam, "function", "EXECUTE", fam.Execute, objs, roles)...)
	}
	for _, fam := range f.Relations {
		objs, err := objects(ctx, q, fam, "r", roles)
		if err != nil {
			return nil, err
		}
		out = append(out, judge(fam, "relation", "SELECT", fam.Select, objs, roles)...)
	}
	return out, nil
}

// Role is the full name of a short role name of the entries ("auth" is ctrlz_auth).
func Role(short string) string { return "ctrlz_" + short }

type object struct {
	name    string // the key of the entry: name(args) for a function, the relation name otherwise
	public  bool   // PUBLIC holds the privilege in the ACL
	holders []string
}

// objects lists the pg_catalog objects of a family and, for each, which of the roles hold the
// privilege by any route (has_*_privilege follows memberships). It is one query per family: the check
// runs once for every mutation of TestMutations and cannot afford a round trip per object and role.
// kind is "f" for functions and "r" for relations (tables, views and materialized views). PUBLIC is read
// from the ACL itself, because has_*_privilege takes a role and PUBLIC is not one.
func objects(ctx context.Context, q Querier, fam Family, kind string, roles []string) ([]object, error) {
	like := fam.Like
	if like == nil {
		like = []string{}
	}
	names := fam.Names
	if names == nil {
		names = []string{}
	}
	// Two constant statements, so the SQL lint can read them (a statement chosen at run time is a
	// variable, which it refuses in every package it does not exempt).
	var rows Rows
	var err error
	if kind == "f" {
		rows, err = q.Query(ctx, qFunctions, like, names, roles)
	} else {
		rows, err = q.Query(ctx, qRelations, like, names, roles)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []object
	for rows.Next() {
		var o object
		if err := rows.Scan(&o.name, &o.public, &o.holders); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func judge(fam Family, noun, priv string, allowed map[string][]string, objs []object, roles []string) []Finding {
	const repair = "bootstrap/20-database.sql"
	var out []Finding
	if len(objs) == 0 {
		out = append(out, Finding{Text: fmt.Sprintf("catalog reach (%s): the family matches no %s of pg_catalog (a mistyped pattern judges nothing)", fam.Family, noun)})
	}
	seen := map[string]bool{}
	for _, o := range objs {
		seen[o.name] = true
		if o.public {
			out = append(out, Finding{Text: fmt.Sprintf("catalog reach (%s): PUBLIC holds %s on pg_catalog %s %s", fam.Family, priv, noun, o.name), Security: true, Repair: repair})
		}
		may := map[string]bool{}
		for _, r := range allowed[o.name] {
			may[Role(r)] = true
		}
		has := map[string]bool{}
		for _, r := range o.holders {
			has[r] = true
		}
		for _, r := range roles {
			switch {
			case has[r] && !may[r]:
				out = append(out, Finding{Text: fmt.Sprintf("catalog reach (%s): %s holds %s on pg_catalog %s %s, not in catalog_reach.yaml", fam.Family, r, priv, noun, o.name), Security: true, Repair: repair})
			case !has[r] && may[r]:
				out = append(out, Finding{Text: fmt.Sprintf("catalog reach (%s): %s is named for %s on pg_catalog %s %s and does not hold it (the bootstrap does not grant it back)", fam.Family, r, priv, noun, o.name), Repair: repair})
			}
		}
	}
	var stale []string
	for name := range allowed {
		if !seen[name] {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	for _, name := range stale {
		out = append(out, Finding{Text: fmt.Sprintf("catalog reach (%s): %s is named in catalog_reach.yaml and matches no object of pg_catalog", fam.Family, name)})
	}
	// The entries name short role names of roles.yaml, and a name that is not one grants nothing.
	known := make(map[string]bool, len(roles))
	for _, r := range roles {
		known[r] = true
	}
	var names []string
	for name := range allowed {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, r := range allowed[name] {
			if !known[Role(r)] {
				out = append(out, Finding{Text: fmt.Sprintf("catalog reach (%s): %s names %q, which is not a role of roles.yaml", fam.Family, name, r)})
			}
		}
	}
	return out
}

const qFunctions = `
SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')',
       EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE'),
       ARRAY(SELECT r FROM unnest($3::text[]) r WHERE has_function_privilege(r, p.oid, 'EXECUTE') ORDER BY r)
FROM pg_proc p
WHERE p.pronamespace = 'pg_catalog'::regnamespace AND (p.proname LIKE ANY ($1::text[]) OR p.proname = ANY ($2::text[]))
ORDER BY 1`

const qRelations = `
SELECT c.relname,
       EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a WHERE a.grantee = 0 AND a.privilege_type = 'SELECT'),
       ARRAY(SELECT r FROM unnest($3::text[]) r WHERE has_table_privilege(r, c.oid, 'SELECT') ORDER BY r)
FROM pg_class c
WHERE c.relnamespace = 'pg_catalog'::regnamespace AND c.relkind IN ('r', 'v', 'm') AND (c.relname LIKE ANY ($1::text[]) OR c.relname = ANY ($2::text[]))
ORDER BY 1`
