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

	cols  map[string]string
	saved [2]map[string]string
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

// resetTables are emptied for the tenant between two cases: everything a route creates.
// Order matters for the foreign keys.
func resetTables() []string {
	return []string{
		"refresh_tokens", "sessions", "webauthn_credentials", "phone_change_requests", "recovery_codes",
		"notifications", "announcement_reads", "tenant_audit_log",
	}
}

// digestTables are the tables the services write, keyed by tenant_id.
func digestTables() []string {
	return []string{"users", "sessions", "refresh_tokens", "webauthn_credentials", "phone_change_requests", "notifications",
		"announcement_reads", "recovery_codes", "api_tokens", "tenant_audit_log", "tenant_entitlements"}
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
	for _, tbl := range digestTables() {
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
	for _, tbl := range digestTables() {
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
