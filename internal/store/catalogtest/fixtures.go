// Package catalogtest holds the catalog tests of docs/specs/postgres-schema.md
// section 12: they read pg_catalog and compare it with the expected state in
// migrations/catalog, in both directions, so an extra object fails as surely
// as a missing one. The two-tenant behaviour tests live here too.
//
// The checks are plain functions that return a list of violations. The Go
// tests run them against the migrated database and expect an empty list. The
// mutation test breaks the database on purpose and expects a non-empty list,
// which is how the suite proves that it can fail.
package catalogtest

import (
	"bytes"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/internal/clockrule"

	catalogfixtures "github.com/Kup1ng/CtrlZ-Panel/migrations/catalog"
)

// NamedConstraint is a constraint the spec names (test 17).
type NamedConstraint struct {
	Table    string `yaml:"table"`
	Name     string `yaml:"name"`
	Contains string `yaml:"contains"`
}

// TablesFile is tables.yaml.
type TablesFile struct {
	TenantKeyExceptions []string          `yaml:"tenant_key_exceptions"`
	Tenant              []string          `yaml:"tenant"`
	Global              []string          `yaml:"global"`
	ValueColumns        []string          `yaml:"value_columns"`
	GlobalRLS           []string          `yaml:"global_rls"`
	NonLeadingIndexes   []string          `yaml:"non_leading_indexes"`
	NamedConstraints    []NamedConstraint `yaml:"named_constraints"`
	// NaNExempt lists the numeric columns that may accept NaN, each with the reason (check 27).
	NaNExempt []NaNExempt `yaml:"nan_exempt"`
}

// Policy is one row of policies.yaml.
type Policy struct {
	Table     string  `yaml:"table"`
	Name      string  `yaml:"name"`
	Cmd       string  `yaml:"cmd"`
	Role      string  `yaml:"role"`
	Qual      *string `yaml:"qual"`
	WithCheck *string `yaml:"with_check"`
	// Restrictive marks an AS RESTRICTIVE policy, which narrows what the
	// permissive ones allow. Left out, the policy is PERMISSIVE.
	Restrictive bool `yaml:"restrictive"`
}

// PoliciesFile is policies.yaml.
type PoliciesFile struct {
	Named []Policy `yaml:"named"`
}

// SchemaGrant is one schema in grants.yaml.
type SchemaGrant struct {
	Owner string   `yaml:"owner"`
	Usage []string `yaml:"usage"`
}

// DefaultACL is one pg_default_acl row.
type DefaultACL struct {
	Role    string `yaml:"role"`
	Schema  string `yaml:"schema"`
	ObjType string `yaml:"objtype"`
	ACL     string `yaml:"acl"`
}

// GrantsFile is grants.yaml.
type GrantsFile struct {
	// Tables maps table to short role name to the privilege notation.
	Tables                 map[string]map[string]string `yaml:"tables"`
	Views                  map[string][]string          `yaml:"views"`
	Schemas                map[string]SchemaGrant       `yaml:"schemas"`
	Database               struct{ Connect []string }   `yaml:"database"`
	CurrentTenantIDExecute []string                     `yaml:"current_tenant_id_execute"`
	DefaultACL             []DefaultACL                 `yaml:"default_acl"`
}

// SDFunction is one allow-listed SECURITY DEFINER function.
type SDFunction struct {
	Name    string   `yaml:"name"`
	Args    string   `yaml:"args"`
	Returns string   `yaml:"returns"`
	Execute []string `yaml:"execute"`
	// Ranks is the order in which the body takes row locks, as lockrank.Declare
	// writes it. A pointer so that a function with no entry at all (nil) differs
	// from one that declares it takes none ([]).
	Ranks *[]string `yaml:"ranks"`
	// Trail lists the trail tables (guarded.yaml) the function inserts into in the
	// same call; NoTrail says why a function that writes a guarded table leaves none.
	// Check 23 requires one of them for every function that writes a guarded table.
	Trail   []string `yaml:"trail"`
	NoTrail string   `yaml:"no_trail"`
	// InertDelete says why a function deletes from a table the lock order calls inert (tenants,
	// admin_users): such a delete takes a lock that the statement guard ignores (db-r9-5), so the
	// one function that may do it, the purge of a deleting tenant, declares it. Check 21 refuses
	// a delete without it and a note without a delete.
	InertDelete string `yaml:"inert_delete"`
	// Isolation is the kind of two-tenant fixture the function needs (see functions.yaml): tenant, key,
	// create or none. IsolationReason says why for create and none.
	Isolation       string `yaml:"isolation"`
	IsolationReason string `yaml:"isolation_reason"`
}

// Helper is a non-SECURITY-DEFINER function in ctrlz.
type Helper struct {
	Name    string    `yaml:"name"`
	Args    string    `yaml:"args"`
	Returns string    `yaml:"returns"`
	Ranks   *[]string `yaml:"ranks"`
	// Execute lists the roles (short names) that hold EXECUTE on a helper that is not a
	// trigger function. A helper without a list is executed by no login role.
	Execute []string `yaml:"execute"`
}

// FunctionsFile is functions.yaml.
type FunctionsFile struct {
	SecurityDefiner []SDFunction `yaml:"security_definer"`
	Helpers         []Helper     `yaml:"helpers"`
	// Triggers are the definitions (pg_get_triggerdef) of the triggers on ctrlz
	// tables other than the updated_at ones, which the table macro makes.
	Triggers []string `yaml:"triggers"`
}

// Membership is one expected pg_auth_members row.
type Membership struct {
	Role    string `yaml:"role"`
	Member  string `yaml:"member"`
	Inherit bool   `yaml:"inherit"`
	Set     bool   `yaml:"set"`
	Admin   bool   `yaml:"admin"`
}

// RoleSpec is the expected state of one role: its attributes, its connection
// limit and its role-wide defaults (pg_roles.rolconfig, as name to value).
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

// Fixtures is everything under migrations/catalog.
type Fixtures struct {
	Tables      TablesFile
	Policies    PoliciesFile
	Grants      GrantsFile
	Functions   FunctionsFile
	Views       struct{ Views []string }
	Roles       RolesFile
	Guarded     GuardedFile
	Clocks      *clockrule.Registry
	Reach       CatalogReachFile
	ForeignKeys struct {
		ForeignKeys []string `yaml:"foreign_keys"`
	}
}

func decode(name string, into any) error {
	b, err := fs.ReadFile(catalogfixtures.FS, name)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	// An unknown key is a typo that would silently weaken a test.
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// Load reads and validates the fixture files.
func Load() (*Fixtures, error) {
	fx := &Fixtures{}
	for name, into := range map[string]any{
		"tables.yaml":        &fx.Tables,
		"policies.yaml":      &fx.Policies,
		"grants.yaml":        &fx.Grants,
		"functions.yaml":     &fx.Functions,
		"views.yaml":         &fx.Views,
		"roles.yaml":         &fx.Roles,
		"guarded.yaml":       &fx.Guarded,
		"foreign_keys.yaml":  &fx.ForeignKeys,
		"catalog_reach.yaml": &fx.Reach,
	} {
		if err := decode(name, into); err != nil {
			return nil, err
		}
	}
	var err error
	if fx.Clocks, err = clockrule.Load(); err != nil {
		return nil, err
	}
	// A table cannot be both kinds, or listed twice.
	seen := map[string]string{}
	for kind, list := range map[string][]string{"tenant": fx.Tables.Tenant, "global": fx.Tables.Global} {
		for _, t := range list {
			if prev, dup := seen[t]; dup {
				return nil, fmt.Errorf("tables.yaml: %s is listed as %s and %s", t, prev, kind)
			}
			seen[t] = kind
		}
	}
	return fx, nil
}

// AllTables returns every listed table, sorted.
func (fx *Fixtures) AllTables() []string {
	out := append(append([]string{}, fx.Tables.Tenant...), fx.Tables.Global...)
	sort.Strings(out)
	return out
}

// IsTenant reports whether t is a tenant table.
func (fx *Fixtures) IsTenant(t string) bool {
	for _, x := range fx.Tables.Tenant {
		if x == t {
			return true
		}
	}
	return false
}

// KeyColumn is the tenant key column of a tenant table: tenant_id, or id for
// tenants.
func (fx *Fixtures) KeyColumn(t string) string {
	for _, x := range fx.Tables.TenantKeyExceptions {
		if x == t {
			return "id"
		}
	}
	return "tenant_id"
}

// Priv is one privilege on one object, at table level (Col is "*") or for one
// column.
type Priv struct {
	Table string
	Role  string
	Kind  string // SELECT, INSERT, UPDATE, DELETE
	Col   string
}

func (p Priv) String() string { return fmt.Sprintf("%s|%s|%s|%s", p.Table, p.Role, p.Kind, p.Col) }

// ParsePrivs expands the grant notation for one table and role against its
// live column list.
func ParsePrivs(table, role, spec string, columns []string) ([]Priv, error) {
	var out []Priv
	rest := strings.TrimSpace(spec)
	for rest != "" {
		letter := rest[0]
		var kind string
		switch letter {
		case 'S':
			kind = "SELECT"
		case 'I':
			kind = "INSERT"
		case 'U':
			kind = "UPDATE"
		case 'D':
			kind = "DELETE"
		default:
			return nil, fmt.Errorf("grants.yaml: %s %s: unexpected %q in %q", table, role, string(letter), spec)
		}
		rest = rest[1:]
		args, hasArgs := "", false
		if strings.HasPrefix(rest, "(") {
			end := strings.Index(rest, ")")
			if end < 0 {
				return nil, fmt.Errorf("grants.yaml: %s %s: unclosed parenthesis in %q", table, role, spec)
			}
			args, hasArgs = rest[1:end], true
			rest = rest[end+1:]
		}
		rest = strings.TrimSpace(rest)
		if !hasArgs {
			out = append(out, Priv{table, role, kind, "*"})
			continue
		}
		var cols []string
		if strings.HasPrefix(args, "-") {
			skip := map[string]bool{}
			for _, c := range strings.Split(args[1:], "-") {
				skip[c] = true
			}
			for _, c := range columns {
				if !skip[c] {
					cols = append(cols, c)
				}
			}
			for c := range skip {
				if !contains(columns, c) {
					return nil, fmt.Errorf("grants.yaml: %s %s: %q is not a column", table, role, c)
				}
			}
		} else {
			for _, c := range strings.Split(args, ",") {
				c = strings.TrimSpace(c)
				if !contains(columns, c) {
					return nil, fmt.Errorf("grants.yaml: %s %s: %q is not a column", table, role, c)
				}
				cols = append(cols, c)
			}
		}
		for _, c := range cols {
			out = append(out, Priv{table, role, kind, c})
		}
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
