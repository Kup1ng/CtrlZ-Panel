package catalogtest

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Kup1ng/CtrlZ-Panel/internal/lockrank"
)

// ColumnSet is a list of column names, or the single scalar "*" meaning every
// guarded column of the table.
type ColumnSet []string

// UnmarshalYAML accepts "*" or a list.
func (c *ColumnSet) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != "*" {
			return fmt.Errorf("guarded.yaml: line %d: a column set is a list or \"*\", not %q", n.Line, n.Value)
		}
		*c = ColumnSet{"*"}
		return nil
	}
	var l []string
	if err := n.Decode(&l); err != nil {
		return err
	}
	*c = l
	return nil
}

func (c ColumnSet) all() bool { return len(c) == 1 && c[0] == "*" }

// GuardedWrite is one table of guarded.yaml's write section.
type GuardedWrite struct {
	Free     []string             `yaml:"free"`
	Declared map[string]ColumnSet `yaml:"declared"`
}

// GuardedTrail is one trail table of guarded.yaml.
type GuardedTrail struct {
	Update map[string][]string `yaml:"update"`
	Delete map[string]string   `yaml:"delete"`
}

// GuardedCredentialGen is one table of guarded.yaml's credential_gen section: the credential
// columns (the trigger's arguments) and, for every other guarded column, why a change to it
// leaves what a past verification proved alone.
type GuardedCredentialGen struct {
	Columns []string          `yaml:"columns"`
	Other   map[string]string `yaml:"other"`
}

// OpenColumns is the free-form columns of one table that are not credentials, with the reason.
type OpenColumns struct {
	Why string `yaml:"why"`
	// NoPersonal says why none of the columns is about a person: not a phone, an address, a device
	// or network name, a place, nor text a person wrote about themselves. `Why` answers the
	// credential question only, and one sentence copied across tables made the personal question
	// invisible (db-r8-2); a table with such a column moves it to `personal` instead.
	NoPersonal string   `yaml:"no_personal"`
	Columns    []string `yaml:"columns"`
}

// GuardedFile is guarded.yaml (rule role-reach).
type GuardedFile struct {
	Owners []string                       `yaml:"owners"`
	Write  map[string]GuardedWrite        `yaml:"write"`
	Read   map[string]map[string][]string `yaml:"read"`
	Trail  map[string]GuardedTrail        `yaml:"trail"`
	// CredentialGen classifies every guarded column of the tables that carry a
	// credential_gen counter (rule credential-generation, check 25).
	CredentialGen map[string]GuardedCredentialGen `yaml:"credential_gen"`
	// Secrets are the guarded-read columns of tables outside the auth set, in the shape of
	// Read. They are kept apart only so that adding a table here does not add it to the
	// clock registry, which covers the tables whose time decides an authentication step.
	Secrets map[string]map[string][]string `yaml:"secrets"`
	// Open decides every column of a free-form type (text, bytea, jsonb, arrays) whose name
	// does not look secret: it holds a name, a setting, a status or a closed vocabulary and no
	// credential. A free-form column in none of Read, Secrets, ReadOpen and Open fails check 22,
	// so the decision is made the day the column is added, whatever it is called (db-r6-3).
	Open map[string]OpenColumns `yaml:"open"`
	// Personal is the personal-data class (db-r7-5): the columns that record a phone number, an
	// address or a user agent, and so which person did what from where, plus any other column a
	// person puts there (otp_challenges.trusted). It has the shape of Read and is judged the same
	// way (a SELECT by a role that is not declared fails, and a declared reader that no longer
	// holds it fails), with the difference that the decision is made by NAME across the whole
	// schema and every type: a column named like a phone, an address or a user agent that is in
	// neither Personal nor PersonalOpen fails check 22.
	Personal map[string]map[string][]string `yaml:"personal"`
	// PersonalOpen lists the personal-looking columns that any role holding the table may read,
	// with the reason (an address of a node the operator owns is not a person's).
	PersonalOpen map[string]map[string]string `yaml:"personal_open"`
	// ReadOpen lists the columns whose NAME looks secret (secretName) and that any role
	// may read, with the reason. A column that looks secret and is in neither Read, Secrets
	// nor ReadOpen fails check 22, so every such column's readers are a reviewed list.
	ReadOpen map[string]map[string]string `yaml:"read_open"`
	// Delete maps every write-guarded table to the roles that may DELETE its rows, directly
	// or through the ON DELETE CASCADE of a parent, each with the reason. An empty map is
	// "nobody". TRUNCATE is refused to every role on every table of the schema.
	Delete map[string]map[string]string `yaml:"delete"`
	// RowBound names, for a declared reader of a table with row-level security, the row predicate
	// that bounds its reach: what a privilege cannot say (checkRowBound).
	RowBound map[string]map[string]string `yaml:"row_bound"`
	// AllRows says, for a declared reader of a secret or personal column of a global table that
	// has no row_bound entry, why it needs every row of the table (check 22). It is the answer the
	// rule demands instead of silence: a reader whose own statements need only some rows is a
	// reader to bound with a policy (db-r9-3).
	AllRows map[string]map[string]string `yaml:"all_rows"`
}

// What the check calls secret is decided in two layers, and both fail closed (db-r5-8, then
// db-r6-3 and db-r6-10, which found the name test alone failing open for accept_token,
// refresh_token, api_key, private_key, otp_seed, key, code, nonce and others):
//
//  1. NAME. A column whose name looks like a credential (secretName: a sealed value, a hash, a
//     key, a token, a code, a seed, a salt, a nonce, a secret, a password, a PEM, a resolver id)
//     must be decided in `read`, `secrets` or `read_open`.
//  2. TYPE. A column of a free-form type (freeForm: text, bytea, jsonb, an array, anything that
//     is not a fixed-width number, time, flag, address or id) can hold anything, whatever it is
//     called, so one that is not a name hit must be listed under `open` with the table's reason.
//     A new free-form column therefore fails until a person decides it. The fixed-width types
//     cannot hold a credential and are not asked (totp_last_step is a bigint, not a secret).
//
// uuid columns are judged by name only: they are ids and keys of rows, and a token stored as a
// uuid is caught by its name.
var secretNameParts = regexp.MustCompile(`(_ct|_hash|_key|_token|_code|_secret|_seed|_salt|_nonce|_pem|_mac|_sig|_pass|_pin)$|secret|token|seed|salt|passw|passphrase|kek|credential|resolver_id|^(payload|password|key|code|pin|nonce|mac|sig|pem|otp|pass)$`)

// plainType lists the fixed-width types: counters, times, flags, addresses and ranges. Most cannot
// hold a credential, so their names are not judged (password_changed_at is a time, password_ok a
// flag); the integer types are the exception, see numericType.
func plainType(typ string) bool {
	switch typ {
	case "timestamp with time zone", "timestamp without time zone", "boolean", "integer", "bigint", "smallint",
		"numeric", "date", "interval", "int4range", "inet", "cidr", "macaddr":
		return true
	}
	return strings.HasPrefix(typ, "numeric(")
}

// numericType says whether a fixed-width column can hold a credential: a 6 digit OTP, a PIN or a
// numeric recovery code fits an integer, a bigint or a numeric (db-r7-5). The rule says a column
// added tomorrow fails until a person decides it, whatever it is called, and that has to include
// these; only the types that cannot hold a code (times, flags, addresses, ranges) are exempt.
func numericType(typ string) bool {
	switch typ {
	case "integer", "bigint", "smallint", "numeric":
		return true
	}
	return strings.HasPrefix(typ, "numeric(")
}

// secretName says whether the column must be decided by its name: every type that can hold a
// credential, the numeric ones included.
func secretName(c column) bool {
	return (!plainType(c.Type) || numericType(c.Type)) && secretNameParts.MatchString(c.Name)
}

// personalNameParts is the name test of the personal-data class: the columns that say which
// person, which phone, which address, which network and which device asked for something. It
// applies to EVERY type that can hold a value, a numeric one included. The name test is only one
// of two layers: an address-typed column is personal whatever it is called (addressType), and
// every free-form column that is not named here is asked again under `open` (db-r8-2).
var personalNameParts = regexp.MustCompile(`phone|msisdn|e164|email|user_agent|cidr|(^|_)(ips?|city|isp|asn|hostname|qname|addr|address|mac)$`)

// addressType says whether the column's TYPE is a network or hardware address, or an array of
// them. It is decided by type because a name test fails open: a `remote_addr inet` or a `peer
// cidr` added tomorrow was named like nothing and was asked by neither layer (db-r8-2).
func addressType(typ string) bool {
	typ = strings.TrimSuffix(typ, "[]")
	switch typ {
	case "inet", "cidr", "macaddr", "macaddr8":
		return true
	}
	return false
}

// personalName says whether the column must be decided as personal data: an address by its type,
// anything else by a name like a phone, an e-mail, a user agent or a place. A flag or a time
// named like one (expose_ip, phone_verified_at) records no value, so it is not asked. A NUMERIC
// column is asked: a phone number fits a bigint, and the round 7 secret test learned the same
// lesson (db-r7-5), so a counter or a limit named like a phone or an address gets a line under
// personal_open that says it is one (db-r8-2).
func personalName(c column) bool {
	if addressType(c.Type) {
		return true
	}
	switch c.Type {
	case "boolean", "timestamp with time zone", "timestamp without time zone", "date", "interval":
		return false
	}
	return personalNameParts.MatchString(c.Name)
}

// freeForm says whether the column's type can hold anything (and so must be decided whatever
// its name is): not a plain type and not a uuid.
func freeForm(c column) bool { return !plainType(c.Type) && c.Type != "uuid" }

// loginRoles returns every role that can log in and is not a superuser. It reads
// pg_roles rather than a list, so a role added by a later migration, by hand or by
// an extension is judged from the day it exists.
func loginRoles(ctx context.Context, q Querier) ([]string, error) {
	return strs(ctx, q, `SELECT rolname FROM pg_roles WHERE rolcanlogin AND NOT rolsuper`)
}

func short(r string) string { return strings.TrimPrefix(r, "ctrlz_") }

// CheckRoleReach is catalog check 22, the enforcement of rule role-reach. For every
// LOGIN role (not a superuser, not a table owner declared in guarded.yaml) it asks
// Postgres, with has_column_privilege and has_table_privilege so that table-level
// grants, column grants, PUBLIC and role membership are all counted, whether the role
// can
//
//   - INSERT or UPDATE a column of a write-guarded table that is not `free`;
//   - SELECT a guarded-read column;
//   - UPDATE, DELETE or TRUNCATE a row of a trail table;
//
// and reports each one that guarded.yaml does not declare. A declared reach that the
// role no longer holds is reported too, so the allow list stays exactly what is
// granted. A failure of this check is a defect of the rule or of guarded.yaml, never
// a reason to add a case to the check.
func CheckRoleReach(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	g := fx.Guarded
	cols, err := liveColumns(ctx, q)
	if err != nil {
		return nil, err
	}
	roles, err := loginRoles(ctx, q)
	if err != nil {
		return nil, err
	}
	owner := map[string]bool{}
	for _, o := range g.Owners {
		owner["ctrlz_"+o] = true
	}
	var out []string
	for _, o := range g.Owners {
		var isOwner bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_class WHERE relnamespace = 'ctrlz'::regnamespace AND relkind IN ('r','p') AND pg_get_userbyid(relowner) = $1)`, "ctrlz_"+o).Scan(&isOwner); err != nil {
			return nil, err
		}
		if !isOwner {
			out = append(out, "guarded.yaml: owners lists ctrlz_"+o+", which owns no table; the exemption is for the owner only")
		}
	}
	// One query for every column privilege of every login role on the guarded
	// tables (about twenty seconds of round trips when asked one by one).
	tables := map[string]bool{}
	for t := range g.Write {
		tables[t] = true
	}
	for t := range g.Read {
		tables[t] = true
	}
	for t := range g.Secrets {
		tables[t] = true
	}
	for t := range g.Personal {
		tables[t] = true
	}
	for t := range g.Trail {
		tables[t] = true
	}
	// Read and Secrets are one list: the second only keeps its tables out of the clock
	// registry. A column named in both is a mistake.
	readSpec := map[string]map[string][]string{}
	for t, m := range g.Read {
		readSpec[t] = map[string][]string{}
		for c, rs := range m {
			readSpec[t][c] = rs
		}
	}
	for t, m := range g.Secrets {
		if readSpec[t] == nil {
			readSpec[t] = map[string][]string{}
		}
		for c, rs := range m {
			if _, dup := readSpec[t][c]; dup {
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s is in both read and secrets", t, c))
			}
			readSpec[t][c] = rs
		}
	}
	for t, m := range g.Personal {
		if readSpec[t] == nil {
			readSpec[t] = map[string][]string{}
		}
		for c, rs := range m {
			if _, dup := readSpec[t][c]; dup {
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s is in personal and in read or secrets", t, c))
			}
			readSpec[t][c] = rs
		}
	}
	held, err := columnPrivileges(ctx, q, tables)
	if err != nil {
		return nil, err
	}
	has := func(role, table, col, kind string) (bool, error) { return held[role+"|"+table+"|"+col+"|"+kind], nil }
	tableHeld, err := tablePrivileges(ctx, q, tables)
	if err != nil {
		return nil, err
	}
	hasTable := func(role, table, kind string) (bool, error) { return tableHeld[role+"|"+table+"|"+kind], nil }
	known := func(table string) bool { _, ok := cols[table]; return ok }
	colOf := func(table, col string) bool {
		for _, c := range cols[table] {
			if c.Name == col {
				return true
			}
		}
		return false
	}

	// Write-guarded columns.
	for _, table := range sortedKeys(g.Write) {
		w := g.Write[table]
		if !known(table) {
			out = append(out, "guarded.yaml: write lists a table that does not exist: "+table)
			continue
		}
		free := map[string]bool{}
		for _, c := range w.Free {
			if !colOf(table, c) {
				out = append(out, fmt.Sprintf("guarded.yaml: write.%s.free: %q is not a column", table, c))
			}
			free[c] = true
		}
		for r := range w.Declared {
			if !contains(allRoles(), r) {
				out = append(out, fmt.Sprintf("guarded.yaml: write.%s.declared: unknown role %q", table, r))
			}
		}
		declaredHeld := map[string]map[string]bool{} // role -> column -> declared and held
		for _, r := range roles {
			if owner[r] {
				continue
			}
			decl := w.Declared[short(r)]
			declaredHeld[r] = map[string]bool{}
			for _, c := range cols[table] {
				if free[c.Name] {
					continue
				}
				var kinds []string
				for _, kind := range []string{"INSERT", "UPDATE"} {
					ok, err := has(r, table, c.Name, kind)
					if err != nil {
						return nil, err
					}
					if ok {
						kinds = append(kinds, kind)
					}
				}
				if len(kinds) == 0 {
					continue
				}
				if decl.all() || contains(decl, c.Name) {
					declaredHeld[r][c.Name] = true
					continue
				}
				out = append(out, fmt.Sprintf("role reach: %s can %s %s.%s; guarded.yaml does not declare it (use a function in ctrlz_fn)", r, strings.Join(kinds, "+"), table, c.Name))
			}
		}
		for rs, decl := range w.Declared {
			r := role(rs)
			if decl.all() {
				if len(declaredHeld[r]) == 0 {
					out = append(out, fmt.Sprintf("guarded.yaml: write.%s.declared.%s is \"*\" but the role holds nothing on the table; remove it", table, rs))
				}
				continue
			}
			for _, c := range decl {
				switch {
				case !colOf(table, c):
					out = append(out, fmt.Sprintf("guarded.yaml: write.%s.declared.%s: %q is not a column", table, rs, c))
				case free[c]:
					out = append(out, fmt.Sprintf("guarded.yaml: write.%s.declared.%s: %q is free already", table, rs, c))
				case !declaredHeld[r][c]:
					out = append(out, fmt.Sprintf("guarded.yaml: write.%s.declared.%s declares %q, which the role no longer holds; remove it", table, rs, c))
				}
			}
		}
	}

	// Guarded-read columns.
	for _, table := range sortedKeys(readSpec) {
		if !known(table) {
			out = append(out, "guarded.yaml: read lists a table that does not exist: "+table)
			continue
		}
		for _, col := range sortedKeys(readSpec[table]) {
			if !colOf(table, col) {
				out = append(out, fmt.Sprintf("guarded.yaml: read.%s: %q is not a column", table, col))
				continue
			}
			declared := readSpec[table][col]
			heldBy := map[string]bool{}
			for _, r := range roles {
				if owner[r] {
					continue
				}
				ok, err := has(r, table, col, "SELECT")
				if err != nil {
					return nil, err
				}
				if !ok {
					continue
				}
				heldBy[short(r)] = true
				if !contains(declared, short(r)) {
					out = append(out, fmt.Sprintf("role reach: %s can SELECT %s.%s; guarded.yaml does not declare it (use a function in ctrlz_fn)", r, table, col))
				}
			}
			for _, d := range declared {
				if !heldBy[d] {
					out = append(out, fmt.Sprintf("guarded.yaml: read.%s.%s declares %s, which no longer holds it; remove it", table, col, d))
				}
			}
		}
	}

	// A reach on a table with row-level security is a reach to the rows the policy shows, and a
	// privilege cannot say which those are. Each declared reader of such a table names the row
	// predicate that bounds it, and the predicate must be what the role's one policy says
	// (sms-r8-3, sms-r8-7: the sender holds SELECT on sms_counters.key, which is a raw phone or
	// address, and sees only the global rows because of a policy this check reads).
	rlsMore, err := checkRowBound(ctx, q, g, fx.Tables.Global, fx.Tables.GlobalRLS, readSpec, owner)
	if err != nil {
		return nil, err
	}
	out = append(out, rlsMore...)

	// Trail tables.
	for _, table := range sortedKeys(g.Trail) {
		tr := g.Trail[table]
		if !known(table) {
			out = append(out, "guarded.yaml: trail lists a table that does not exist: "+table)
			continue
		}
		for _, r := range roles {
			if owner[r] {
				continue
			}
			var upd []string
			for _, c := range cols[table] {
				ok, err := has(r, table, c.Name, "UPDATE")
				if err != nil {
					return nil, err
				}
				if ok {
					upd = append(upd, c.Name)
				}
			}
			sort.Strings(upd)
			want := append([]string{}, tr.Update[short(r)]...)
			sort.Strings(want)
			if strings.Join(upd, ",") != strings.Join(want, ",") {
				out = append(out, fmt.Sprintf("role reach: %s can UPDATE trail table %s on (%s); guarded.yaml declares (%s)", r, table, strings.Join(upd, ", "), strings.Join(want, ", ")))
			}
			trunc, err := hasTable(r, table, "TRUNCATE")
			if err != nil {
				return nil, err
			}
			if trunc {
				out = append(out, fmt.Sprintf("role reach: %s can TRUNCATE trail table %s", r, table))
			}
			del, err := hasTable(r, table, "DELETE")
			if err != nil {
				return nil, err
			}
			pol, declared := tr.Delete[short(r)]
			switch {
			case del && !declared:
				out = append(out, fmt.Sprintf("role reach: %s can DELETE from trail table %s; guarded.yaml declares no age-bounded policy for it", r, table))
			case del && declared:
				var n int
				if err := q.QueryRow(ctx, `
SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relname = $1 AND p.polname = $2
  AND NOT p.polpermissive AND p.polcmd IN ('d', '*')
  AND EXISTS (SELECT 1 FROM unnest(p.polroles) x WHERE x = (SELECT oid FROM pg_roles WHERE rolname = $3))`, table, pol, r).Scan(&n); err != nil {
					return nil, err
				}
				if n != 1 {
					out = append(out, fmt.Sprintf("role reach: %s can DELETE from trail table %s and no RESTRICTIVE DELETE policy %q bounds it for that role", r, table, pol))
				}
			case !del && declared:
				out = append(out, fmt.Sprintf("guarded.yaml: trail.%s.delete declares %s, which no longer holds DELETE; remove it", table, short(r)))
			}
		}
	}
	more, err := checkDeleteReach(ctx, q, g, roles, owner, known)
	if err != nil {
		return nil, err
	}
	out = append(out, more...)
	out = append(out, checkSecretNames(g, cols)...)
	sort.Strings(out)
	return out, nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writtenTables returns the ctrlz tables a function body inserts into, updates or
// deletes from, by verb. It is read by the lexer that the lock order uses (lockrank.Targets),
// not by a pattern of its own: a regular expression missed UPDATE ONLY, MERGE, quoted and
// spaced names, a comment between the verb and the table, and the case of the name, so check
// 21 and check 23 could disagree about one body (db-r6-2). A body whose writes cannot be
// read is an error and the check refuses it; it is never read as writing nothing.
func writtenTables(src string) (insert, other map[string]bool, err error) {
	ts, err := lockrank.Targets(src)
	if err != nil {
		return nil, nil, err
	}
	insert, other = map[string]bool{}, map[string]bool{}
	for _, t := range ts {
		if t.Verb == lockrank.VerbInsert {
			insert[t.Table] = true
		} else {
			other[t.Table] = true
		}
	}
	return insert, other, nil
}

// roleOfPrefix maps the name prefix of a function in ctrlz_fn to the one login role
// it belongs to. A function named for a service is for that service alone.
func roleOfPrefix() map[string]string {
	return map[string]string{"worker_": "worker", "keytool_": "keytool", "admin_": "admin"}
}

// CheckGuardedFunctions is catalog check 23, the second half of rule role-reach: a
// guarded column is changed by a function, and the function leaves the evidence.
// For every SECURITY DEFINER function read from the live database:
//
//   - one whose body writes a write-guarded table, or updates or deletes a trail
//     table (guarded.yaml), must say in
//     functions.yaml either `trail`, the trail tables it inserts into in the same
//     call (the body is checked for the INSERT), or `no_trail` with the reason there
//     is nothing to record or who records it;
//   - one that writes no guarded table must say neither, so the notes cannot go stale;
//   - one named worker_, keytool_ or admin_ is executable by that one role and no
//     other, and so is every function that has a `trail`.
func CheckGuardedFunctions(ctx context.Context, q Querier, fx *Fixtures) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT p.proname, pg_get_function_identity_arguments(p.oid), p.prosrc
FROM pg_proc p WHERE p.pronamespace = 'ctrlz_fn'::regnamespace AND p.prolang IN (SELECT oid FROM pg_language WHERE lanname IN ('plpgsql', 'sql'))`)
	if err != nil {
		return nil, err
	}
	src := map[string]string{}
	for rows.Next() {
		var name, args, body string
		if err := rows.Scan(&name, &args, &body); err != nil {
			rows.Close()
			return nil, err
		}
		src[sdKey(name, args)] = body
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	g := fx.Guarded
	var out []string
	for _, f := range fx.Functions.SecurityDefiner {
		body, ok := src[sdKey(f.Name, f.Args)]
		if !ok {
			continue // check 10 reports a function that is not in the database
		}
		insert, other, err := writtenTables(body)
		if err != nil {
			out = append(out, fmt.Sprintf("function %s(%s): the body cannot be read for its writes (%v), so check 23 cannot judge it", f.Name, f.Args, err))
			continue
		}
		var guarded []string
		for t := range g.Write {
			if insert[t] || other[t] {
				guarded = append(guarded, t)
			}
		}
		// Appending to a trail table is what a trail is; changing or removing its rows
		// is a guarded write.
		for t := range g.Trail {
			if other[t] {
				guarded = append(guarded, t)
			}
		}
		sort.Strings(guarded)
		id := f.Name + "(" + f.Args + ")"
		switch {
		case len(guarded) > 0 && len(f.Trail) == 0 && f.NoTrail == "":
			out = append(out, fmt.Sprintf("function %s writes guarded %s and functions.yaml says neither trail nor no_trail", id, strings.Join(guarded, ", ")))
		case len(f.Trail) > 0 && f.NoTrail != "":
			out = append(out, fmt.Sprintf("function %s has both trail and no_trail", id))
		case len(guarded) == 0 && (len(f.Trail) > 0 || f.NoTrail != ""):
			out = append(out, fmt.Sprintf("function %s writes no guarded table but functions.yaml gives it trail or no_trail; remove it", id))
		}
		if f.NoTrail != "" && len(f.NoTrail) < 20 {
			out = append(out, fmt.Sprintf("function %s: no_trail is not a reason", id))
		}
		for _, t := range f.Trail {
			if _, isTrail := g.Trail[t]; !isTrail {
				out = append(out, fmt.Sprintf("function %s: trail names %s, which is not a trail table in guarded.yaml", id, t))
			} else if !insert[t] {
				out = append(out, fmt.Sprintf("function %s: trail names %s but the body does not insert into it", id, t))
			}
		}
		for prefix, r := range roleOfPrefix() {
			if strings.HasPrefix(f.Name, prefix) && !(len(f.Execute) == 1 && f.Execute[0] == r) {
				out = append(out, fmt.Sprintf("function %s is named for %s and must be executable by that role alone, not %v", id, r, f.Execute))
			}
		}
		if len(f.Trail) > 0 && len(f.Execute) != 1 {
			out = append(out, fmt.Sprintf("function %s has a trail and must be executable by exactly one role, not %v", id, f.Execute))
		}
	}
	sort.Strings(out)
	return out, nil
}

// GoldenRoles are the roles that have a committed grant listing. Every role of
// roles.yaml except the migrator, which owns the tables and holds everything.
func GoldenRoles(fx *Fixtures) []string {
	var out []string
	for r := range fx.Roles.Roles {
		if r != "ctrlz_migrator" {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// RoleGrantList returns everything one role can do to the ctrlz schemas, one line
// each and sorted: the table and column privileges (columns collapsed into a list),
// USAGE on schemas, EXECUTE on every function it can call by any route (a direct
// grant, PUBLIC or a membership), and every policy that applies to it. The test
// compares it with a golden file per role, so a change to what any role can do is a
// diff somebody reads (R5, rule role-reach). Check 12 compares the same privileges
// with grants.yaml; the golden adds the functions and policies and shows the effect,
// not the intent.
func RoleGrantList(ctx context.Context, q Querier, rolname string) ([]string, error) {
	live, err := livePrivs(ctx, q)
	if err != nil {
		return nil, err
	}
	type key struct{ table, kind string }
	whole := map[key]bool{}
	cols := map[key][]string{}
	for _, l := range live {
		p := strings.Split(l, "|")
		if p[1] != rolname {
			continue
		}
		k := key{p[0], p[2]}
		if p[3] == "*" {
			whole[k] = true
		} else {
			cols[k] = append(cols[k], p[3])
		}
	}
	var out []string
	for k := range whole {
		out = append(out, fmt.Sprintf("table %s %s", k.table, k.kind))
	}
	for k, c := range cols {
		sort.Strings(c)
		out = append(out, fmt.Sprintf("table %s %s (%s)", k.table, k.kind, strings.Join(c, ", ")))
	}
	schemas, err := strs(ctx, q, `
SELECT 'schema ' || n.nspname || ' ' || p
FROM pg_namespace n CROSS JOIN LATERAL unnest(ARRAY['USAGE', 'CREATE']) p
WHERE n.nspname IN ('public', 'ctrlz', 'ctrlz_fn', 'ctrlz_ext', 'river') AND has_schema_privilege($1, n.oid, p)`, rolname)
	if err != nil {
		return nil, err
	}
	fns, err := strs(ctx, q, `
SELECT 'execute ' || n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname IN ('ctrlz', 'ctrlz_fn') AND has_function_privilege($1, p.oid, 'EXECUTE')`, rolname)
	if err != nil {
		return nil, err
	}
	pols, err := strs(ctx, q, `
SELECT format('policy %s %s %s %s using=%s check=%s', p.tablename, p.policyname, p.cmd, p.permissive, COALESCE(p.qual, '-'), COALESCE(p.with_check, '-'))
FROM pg_policies p WHERE p.schemaname = 'ctrlz' AND ($1 = ANY (p.roles::text[]) OR 'public' = ANY (p.roles::text[]))`, rolname)
	if err != nil {
		return nil, err
	}
	out = append(out, schemas...)
	out = append(out, fns...)
	out = append(out, pols...)
	sort.Strings(out)
	return out, nil
}

// columnPrivileges returns "role|table|column|KIND" for every INSERT, UPDATE and
// SELECT that a login role (not a superuser) holds on a column of the tables, by any
// route: has_column_privilege counts table grants, column grants, PUBLIC and
// inherited membership alike.
func columnPrivileges(ctx context.Context, q Querier, tables map[string]bool) (map[string]bool, error) {
	var names []string
	for t := range tables {
		names = append(names, t)
	}
	rows, err := q.Query(ctx, `
SELECT r.rolname, c.relname, a.attname, k.kind
FROM pg_roles r
CROSS JOIN pg_class c
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('SELECT')) AS k(kind)
WHERE r.rolcanlogin AND NOT r.rolsuper AND c.relnamespace = 'ctrlz'::regnamespace
  AND c.relkind IN ('r', 'p') AND c.relname = ANY ($1)
  AND has_column_privilege(r.oid, c.oid, a.attnum, k.kind)`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var r, t, c, k string
		if err := rows.Scan(&r, &t, &c, &k); err != nil {
			return nil, err
		}
		out[r+"|"+t+"|"+c+"|"+k] = true
	}
	return out, rows.Err()
}

// tablePrivileges is the same for DELETE and TRUNCATE at table level.
func tablePrivileges(ctx context.Context, q Querier, tables map[string]bool) (map[string]bool, error) {
	var names []string
	for t := range tables {
		names = append(names, t)
	}
	rows, err := q.Query(ctx, `
SELECT r.rolname, c.relname, k.kind
FROM pg_roles r CROSS JOIN pg_class c CROSS JOIN (VALUES ('DELETE'), ('TRUNCATE')) AS k(kind)
WHERE r.rolcanlogin AND NOT r.rolsuper AND c.relnamespace = 'ctrlz'::regnamespace
  AND c.relkind IN ('r', 'p') AND c.relname = ANY ($1)
  AND has_table_privilege(r.oid, c.oid, k.kind)`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var r, t, k string
		if err := rows.Scan(&r, &t, &k); err != nil {
			return nil, err
		}
		out[r+"|"+t+"|"+k] = true
	}
	return out, rows.Err()
}

// checkRowBound judges the reach of a declared reader on a table whose row-level security is on.
// For every table in readSpec with RLS on, every declared reader that is not an owner must be in
// guarded.yaml row_bound with the predicate of the one permissive policy that covers its SELECT,
// compared with the live pg_policies qual; a row_bound entry for a table without RLS, for a role
// that is not a declared reader, or whose predicate is not the policy's, fails. The behavioural
// proof (seed rows outside the predicate, read as the role, count nothing) is
// TestTheWorkerRoleSeesTheGlobalCounterRowsOnly, which a new entry needs a case in.
func checkRowBound(ctx context.Context, q Querier, g GuardedFile, global, globalRLS []string, readSpec map[string]map[string][]string, owner map[string]bool) ([]string, error) {
	rls := map[string]bool{}
	rows, err := q.Query(ctx, `SELECT c.relname, c.relrowsecurity FROM pg_class c WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relkind IN ('r', 'p')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var on bool
		if err := rows.Scan(&t, &on); err != nil {
			rows.Close()
			return nil, err
		}
		rls[t] = on
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []string
	declaredReaders := map[string]map[string]bool{}
	for t, cols := range readSpec {
		for _, rs := range cols {
			for _, r := range rs {
				if declaredReaders[t] == nil {
					declaredReaders[t] = map[string]bool{}
				}
				declaredReaders[t][r] = true
			}
		}
	}
	// Tenant tables have row-level security as their isolation (tenant_isolation, checks 02 and 05);
	// the tables whose RLS bounds what a service may read are the ones tables.yaml lists under global_rls.
	inGlobalRLS := map[string]bool{}
	for _, t := range globalRLS {
		inGlobalRLS[t] = true
	}
	for _, t := range sortedKeys(declaredReaders) {
		if !rls[t] || !inGlobalRLS[t] {
			continue
		}
		for _, r := range sortedKeys(declaredReaders[t]) {
			if owner["ctrlz_"+r] {
				continue
			}
			if _, ok := g.RowBound[t][r]; !ok {
				out = append(out, fmt.Sprintf("role reach: %s reads %s, which has row-level security on, and guarded.yaml row_bound names no predicate for it", r, t))
			}
		}
	}
	// A declared reader of a column of a table sees every row of it unless something bounds it,
	// and a privilege cannot say which rows. The question "which rows?" is asked of every pair
	// whose reach is not already the one tenant_isolation gives (db-r9-3: the sender reached every
	// decoy phone of otp_challenges for a round because the table was never asked):
	//   - every declared reader of a GLOBAL table, and
	//   - every declared reader of a TENANT table to which a permissive policy other than
	//     tenant_isolation applies (written to it, to PUBLIC or to a role it is a member of). Such
	//     a policy (USING (true) for the admin console, the hub's index) lifts the tenant bound
	//     for that role, and tenant_isolation never bounded a service role anyway: it can open
	//     WithTenant for any tenant, so the policy bounds a bug and not a reader (db-r10-2: the
	//     question skipped every tenant table on the premise that tenant_isolation answers it, and
	//     admin_read on users showed every tenant's phone number with no reason written down).
	// Either row_bound names the predicate the policy states, or all_rows says why this reader
	// needs every row.
	isGlobal := map[string]bool{}
	for _, t := range global {
		isGlobal[t] = true
	}
	asked := map[string]map[string]bool{}
	for _, t := range sortedKeys(declaredReaders) {
		if !isGlobal[t] && !rls[t] {
			continue
		}
		for _, r := range sortedKeys(declaredReaders[t]) {
			if owner["ctrlz_"+r] {
				continue
			}
			if !isGlobal[t] {
				quals, err := policyQuals(ctx, q, t, r, true)
				if err != nil {
					return nil, err
				}
				if len(quals) == 0 {
					continue
				}
			}
			if asked[t] == nil {
				asked[t] = map[string]bool{}
			}
			asked[t][r] = true
			_, bound := g.RowBound[t][r]
			reason, all := g.AllRows[t][r]
			kind := "a global table"
			if !isGlobal[t] {
				kind = "a tenant table that a policy other than tenant_isolation shows it in full"
			}
			switch {
			case bound && all:
				out = append(out, fmt.Sprintf("guarded.yaml: %s.%s is in row_bound and in all_rows; a reader is bounded or sees every row, not both", t, r))
			case !bound && !all:
				out = append(out, fmt.Sprintf("role reach: %s reads a secret or personal column of %s, %s, and guarded.yaml names neither row_bound (a policy that shows it only the rows it needs) nor all_rows (why it needs every row)", r, t, kind))
			case all && strings.TrimSpace(reason) == "":
				out = append(out, fmt.Sprintf("guarded.yaml: all_rows.%s.%s gives no reason", t, r))
			}
		}
	}
	for _, t := range sortedKeys(g.AllRows) {
		for _, r := range sortedKeys(g.AllRows[t]) {
			switch {
			case !declaredReaders[t][r]:
				out = append(out, fmt.Sprintf("guarded.yaml: all_rows.%s.%s: the role is no declared reader of a secret or personal column of the table; remove it", t, r))
			case !asked[t][r]:
				out = append(out, fmt.Sprintf("guarded.yaml: all_rows.%s.%s: no policy besides tenant_isolation shows this role the table's rows, so tenant_isolation answers which rows; remove it", t, r))
			}
		}
	}
	for _, t := range sortedKeys(g.RowBound) {
		for _, r := range sortedKeys(g.RowBound[t]) {
			switch {
			case !rls[t]:
				out = append(out, fmt.Sprintf("guarded.yaml: row_bound.%s.%s: the table has no row-level security", t, r))
				continue
			case !declaredReaders[t][r]:
				out = append(out, fmt.Sprintf("guarded.yaml: row_bound.%s.%s: the role is no declared reader of the table; remove it", t, r))
				continue
			case !isGlobal[t] && !asked[t][r]:
				out = append(out, fmt.Sprintf("guarded.yaml: row_bound.%s.%s: no policy besides tenant_isolation shows this role the table's rows, so tenant_isolation answers which rows; remove it", t, r))
				continue
			}
			// On a tenant table the predicate is what the named policies say; tenant_isolation
			// is not a bound of the reader (it is the isolation of whoever opens WithTenant).
			quals, err := policyQuals(ctx, q, t, r, !isGlobal[t])
			if err != nil {
				return nil, err
			}
			norm := func(s string) string {
				return strings.Join(strings.Fields(strings.NewReplacer("(", "", ")", "", "::text", "").Replace(s)), " ")
			}
			if len(quals) != 1 || norm(quals[0]) != norm(g.RowBound[t][r]) {
				out = append(out, fmt.Sprintf("role reach: row_bound.%s.%s says %q and the role's SELECT policies on the table say %q", t, r, g.RowBound[t][r], quals))
			}
		}
	}
	return out, nil
}

// policyQuals returns the USING predicates of the permissive policies that cover a SELECT by the
// role. Postgres applies to a role the policies written TO it, those with no TO clause
// (polroles = {0}, PUBLIC) and those of every role it is a member of, and ORs the permissive
// ones. Matching the role's own oid only left a PUBLIC policy and a membership grant (GRANT
// ctrlz_auth TO ctrlz_worker, whose policy is USING (true)) out of the row half of the rule,
// which the privilege half had already learned (sms-r9-8). exceptTenantIsolation leaves out the
// policy that every tenant table carries, to ask what ELSE lifts the tenant bound (db-r10-2).
func policyQuals(ctx context.Context, q Querier, table, role string, exceptTenantIsolation bool) ([]string, error) {
	rows, err := q.Query(ctx, `
SELECT COALESCE(pg_get_expr(p.polqual, p.polrelid), '<null>') FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
WHERE c.relnamespace = 'ctrlz'::regnamespace AND c.relname = $1 AND p.polpermissive AND p.polcmd IN ('r', '*')
  AND NOT ($3 AND p.polname = 'tenant_isolation')
  AND EXISTS (SELECT 1 FROM unnest(p.polroles) x WHERE CASE WHEN x = 0 THEN true ELSE pg_has_role($2::name, x, 'MEMBER') END)
ORDER BY p.polname`, table, "ctrlz_"+role, exceptTenantIsolation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var quals []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		quals = append(quals, s)
	}
	return quals, rows.Err()
}
