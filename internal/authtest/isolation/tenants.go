package isolation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// Tenants is the database side of the harness for the two seeded tenants of authtest: put
// both back to the same baseline, fingerprint what each owns, and say whether two of them
// are in the same state. Both services use it, so "A's snapshot did not move" means the
// same thing for the tenant API and the admin API.
//
// The test database opens a connection per call and a case that makes forty of them is slow
// on a loaded machine, so each of the three is one statement.
type Tenants struct {
	Env *authtest.Env
	T   *testing.T
	// Phones lists the numbers that tie global rows (codes, invites) to the tenant. It is
	// called every time, since a fixture may move the tenant to a new one.
	Phones func(w Who) []string

	cols     map[string]string
	saved    [2]map[string]string
	rowCols  map[string]string    // the writable columns of each content table
	rowSaved [2]map[string]string // the rows of each content table the seed gave one tenant, as a JSON array
	digested []string
	idTables []string
}

// ids returns the seed of one tenant.
func (s *Tenants) ids(w Who) catalogtest.SeedIDs {
	if w == A {
		return s.Env.A
	}
	return s.Env.B
}

// restoreTables are the tables whose seed row a call may change in place, with the key
// column. They are saved once and put back with the same statement, whatever the columns
// are, so a column added later is restored too.
func restoreTables() []struct{ table, key string } {
	return []struct{ table, key string }{{"users", "tenant_id"}, {"tenants", "id"}, {"tenant_entitlements", "tenant_id"}}
}

// contentTables are the tables of the profile routes (P2): a case adds profiles, rules, keys, jobs and outbox rows that the
// next case must not find, and the seed also gives each tenant a row of every one of them (a locked profile, a queued job)
// that the cases read. They are put back to what the seed made, row for row, the way restoreTables puts back a row in place.
func contentTables() []string {
	return []string{"profiles", "profile_options", "profile_filters", "profile_services", "rule_folders", "rules", "block_pages",
		"idempotency_keys", "batch_jobs", "policy_outbox", "job_outbox"}
}

// resetTables are emptied for the tenant between two cases: everything a route creates.
// Order matters for the foreign keys.
func resetTables() []string {
	return []string{
		"refresh_tokens", "sessions", "webauthn_credentials", "phone_change_requests", "recovery_codes",
		"notifications", "announcement_reads", "tenant_audit_log",
	}
}

// digestSkip are the tables a service role can write that hold a tenant_id and are still not digested, each with the
// reason. It is empty on purpose: a table that holds the rows of a tenant is read, and a reason to leave one out is
// a decision somebody writes down here (tenant-r18-11).
func digestSkip() map[string]string { return map[string]string{} }

// Tables a service can write that name no tenant in any column cannot be read by a digest keyed on the tenant, and are
// not in the list: auth_throttle is the one, keyed by an HMAC of the subject under a server secret, so the tenant is
// not in the row; its isolation is the key (internal/auth/throttle) and the abuse tests of internal/budget.

// digestTables are the tables the services write that hold the rows of a tenant. They are READ FROM THE DATABASE, not
// listed (tenant-r18-11): every base table of the ctrlz schema with a tenant_id column that some login role of a
// service can write (INSERT, UPDATE or DELETE on the table, or INSERT or UPDATE on a column). A list typed here
// stopped at the eleven tables the first routes wrote, so a route added later that wrote the rows of tenant A in
// another table (idempotency keys, an IP claim, a profile) was compared against nothing, and the harness stayed
// green for it. The source is the catalog the grants golden files pin, and it does not depend on the code of any
// route. A table that has no tenant_id cannot be read by a digest keyed on the tenant; the comment above says which
// one it is (auth_throttle) and where its isolation is tested. A table that has one and is still left out is listed in
// digestSkip with the reason.
func (s *Tenants) digestTables() []string {
	if s.digested != nil {
		return s.digested
	}
	var names []string
	rows := s.list(`SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'ctrlz' AND c.relkind IN ('r', 'p')
		  AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND a.attnum > 0 AND NOT a.attisdropped)
		  AND EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname LIKE 'ctrlz_%' AND r.rolname NOT IN ('ctrlz_migrator', 'ctrlz_backfill')
		        AND (has_table_privilege(r.oid, c.oid, 'INSERT,UPDATE,DELETE') OR has_any_column_privilege(r.oid, c.oid, 'INSERT,UPDATE')))
		ORDER BY 1`)
	for _, r := range rows {
		if _, skip := digestSkip()[r]; !skip {
			names = append(names, r)
		}
	}
	if len(names) < 11 {
		s.T.Fatalf("the catalog gave only %d tables with a tenant_id that a service can write (%v): the query reads nothing real", len(names), names)
	}
	s.digested = names
	return names
}

// list runs a query that returns one text column and gives the column back as a list.
func (s *Tenants) list(sql string) []string {
	var out []string
	s.Env.Scan(s.T, `SELECT coalesce(array_agg(q.v), '{}'::text[]) FROM (`+sql+`) q(v)`, nil, &out)
	return out
}

// OwnIDs returns the uuid primary key of every row the tenant owns in the digested tables, as text. A route that answers
// B must never carry one of them, whatever fixture noted or forgot to note; the harness reads them from the same
// catalog as the digest, so a row of A in a table added tomorrow is looked for in B's answers the day it exists.
func (s *Tenants) OwnIDs(w Who) []string {
	tl := Lit(s.ids(w).Tenant.String())
	if s.idTables == nil {
		s.idTables = s.list(`SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'ctrlz' AND c.relname = ANY(` + LitList(s.digestTables()) + `)
			  AND EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'id' AND a.atttypid = 'uuid'::regtype AND a.attnum > 0 AND NOT a.attisdropped) ORDER BY 1`)
	}
	if len(s.idTables) == 0 {
		return nil
	}
	// One statement for every table, so a case does not pay one connection per table.
	var parts []string
	for _, tbl := range s.idTables {
		parts = append(parts, fmt.Sprintf(`SELECT id::text FROM ctrlz.%s WHERE tenant_id = %s`, tbl, tl))
	}
	return s.list(strings.Join(parts, " UNION ALL "))
}

// Lit quotes a value that comes from the harness itself (an id, a phone) as an SQL literal.
func Lit(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// LitList quotes a list of such values as a text array.
func LitList(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = Lit(s)
	}
	return "ARRAY[" + strings.Join(q, ", ") + "]::text[]"
}

// Reset returns one tenant to the state of the seed: no sessions, passkeys, pending changes,
// tickets, codes or announcements, and the user, tenant and entitlement rows as they were the
// first time this was called. before is SQL that runs first (the global rows a case clears).
func (s *Tenants) Reset(w Who, before string) {
	t := s.T
	id := s.ids(w)
	if s.cols == nil {
		s.cols = map[string]string{}
		for _, rt := range restoreTables() {
			var cols string
			s.Env.Scan(t, `SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) FROM information_schema.columns
				WHERE table_schema = 'ctrlz' AND table_name = $1 AND is_generated = 'NEVER' AND column_name NOT IN ('id', 'tenant_id')`,
				[]any{rt.table}, &cols)
			s.cols[rt.table] = cols
		}
	}
	if s.saved[w] == nil {
		s.saved[w] = map[string]string{}
		for _, rt := range restoreTables() {
			var js string
			s.Env.Scan(t, fmt.Sprintf(`SELECT to_jsonb(x)::text FROM ctrlz.%s x WHERE %s = $1`, rt.table, rt.key), []any{id.Tenant}, &js)
			s.saved[w][rt.table] = js
		}
	}
	if s.rowCols == nil {
		s.rowCols = map[string]string{}
		for _, tbl := range contentTables() {
			var cols string
			s.Env.Scan(t, `SELECT string_agg(quote_ident(column_name), ', ' ORDER BY ordinal_position) FROM information_schema.columns
				WHERE table_schema = 'ctrlz' AND table_name = $1 AND is_generated = 'NEVER'`, []any{tbl}, &cols)
			s.rowCols[tbl] = cols
		}
	}
	if s.rowSaved[w] == nil {
		s.rowSaved[w] = map[string]string{}
		for _, tbl := range contentTables() {
			var js string
			s.Env.Scan(t, fmt.Sprintf(`SELECT coalesce(jsonb_agg(to_jsonb(x)), '[]'::jsonb)::text FROM ctrlz.%s x WHERE tenant_id = $1`, tbl), []any{id.Tenant}, &js)
			s.rowSaved[w][tbl] = js
		}
	}
	tl := Lit(id.Tenant.String())
	var sql strings.Builder
	sql.WriteString(before)
	for _, tbl := range resetTables() {
		fmt.Fprintf(&sql, `DELETE FROM ctrlz.%s WHERE tenant_id = %s;`, tbl, tl)
	}
	fmt.Fprintf(&sql, `DELETE FROM ctrlz.auth_tickets WHERE subject_tenant = %[1]s; DELETE FROM ctrlz.announcements WHERE tenant_id = %[1]s;
		DELETE FROM ctrlz.otp_challenges WHERE phone_e164 = ANY(%[2]s);`, tl, LitList(s.Phones(w)))
	for _, rt := range restoreTables() {
		cols := s.cols[rt.table]
		fmt.Fprintf(&sql, `UPDATE ctrlz.%[1]s x SET (%[2]s) = (SELECT %[2]s FROM jsonb_populate_record(NULL::ctrlz.%[1]s, $j$%[4]s$j$::jsonb)) WHERE x.%[3]s = %[5]s;`,
			rt.table, cols, rt.key, s.saved[w][rt.table], tl)
	}
	// The content tables reference one another and the seed rows reference them: with the foreign key and touch triggers off
	// (the superuser may), every table is emptied and refilled in any order and the rows come back exactly as they were.
	sql.WriteString(`SET LOCAL session_replication_role = replica;`)
	for _, tbl := range contentTables() {
		fmt.Fprintf(&sql, `DELETE FROM ctrlz.%[1]s WHERE tenant_id = %[2]s;
			INSERT INTO ctrlz.%[1]s (%[3]s) SELECT %[3]s FROM jsonb_populate_recordset(NULL::ctrlz.%[1]s, $j$%[4]s$j$::jsonb);`,
			tbl, tl, s.rowCols[tbl], s.rowSaved[w][tbl])
	}
	s.Env.Exec(t, sql.String())
}

func rowsDigest(table, where string) string {
	return fmt.Sprintf(`(SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.%s x WHERE %s)`, table, where)
}

// Digest fingerprints every row the tenant owns in the tables the services write, one entry
// per table, and the rows that belong to it through its phones and its subject columns: the
// login and reset codes, the tickets, the invites addressed to it, the announcements for it.
func (s *Tenants) Digest(w Who) map[string]string {
	id := s.ids(w)
	tl := Lit(id.Tenant.String())
	ph := LitList(s.Phones(w))
	var parts []string
	for _, tbl := range s.digestTables() {
		parts = append(parts, Lit(tbl), rowsDigest(tbl, "tenant_id = "+tl))
	}
	parts = append(parts,
		Lit("tenants"), rowsDigest("tenants", "id = "+tl),
		Lit("otp_challenges"), rowsDigest("otp_challenges", "phone_e164 = ANY("+ph+")"),
		Lit("invites"), rowsDigest("invites", "phone_e164 = ANY("+ph+")"),
		Lit("auth_tickets"), rowsDigest("auth_tickets", "subject_tenant = "+tl),
		Lit("announcements"), rowsDigest("announcements", "tenant_id = "+tl))
	var js string
	s.Env.Scan(s.T, "SELECT jsonb_build_object("+strings.Join(parts, ", ")+")::text", nil, &js)
	out := map[string]string{}
	if err := json.Unmarshal([]byte(js), &out); err != nil {
		s.T.Fatal(err)
	}
	return out
}

// Shape is what "the same state" means for two tenants: how many rows each owns in every
// table of the digest, and the flags of the user row. It is a count, not a digest, since the
// ids differ; two tenants that were treated alike have the same one.
func (s *Tenants) Shape(w Who) string {
	id := s.ids(w)
	tl, ph := Lit(id.Tenant.String()), LitList(s.Phones(w))
	var parts []string
	for _, tbl := range s.digestTables() {
		parts = append(parts, fmt.Sprintf(`'%[1]s=' || (SELECT count(*) FROM ctrlz.%[1]s WHERE tenant_id = %[2]s)`, tbl, tl))
	}
	parts = append(parts,
		`'user=' || (SELECT concat_ws(',', (totp_enabled_at IS NOT NULL)::text, (totp_pending_at IS NOT NULL)::text, enforce_passkey::text, must_reset::text,
			(phone_verified_at IS NOT NULL)::text, (passkey_review_at IS NOT NULL)::text, (password_hash IS NOT NULL)::text, locale)
			FROM ctrlz.users WHERE id = `+Lit(id.User.String())+`)`,
		`'otp=' || (SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = ANY(`+ph+`))`,
		`'invites=' || (SELECT count(*) FROM ctrlz.invites WHERE phone_e164 = ANY(`+ph+`))`,
		`'tickets=' || (SELECT count(*) FROM ctrlz.auth_tickets WHERE subject_tenant = `+tl+`)`,
		`'announcements=' || (SELECT count(*) FROM ctrlz.announcements WHERE tenant_id = `+tl+`)`)
	var out string
	s.Env.Scan(s.T, "SELECT concat_ws(' ', "+strings.Join(parts, ", ")+")", nil, &out)
	return out
}
