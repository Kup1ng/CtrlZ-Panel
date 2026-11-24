package catalogtest_test

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// The effect of a function call on the caller's own rows, checked in both directions.
const (
	fxChanges   = "changes"   // B's digest must differ afterwards
	fxReads     = "reads"     // B's digest must be what it was
	fxElsewhere = "elsewhere" // a tenant nobody has yet is made; neither digest moves
)

// fnFix is the two-tenant fixture of one SECURITY DEFINER function (rule
// isolation-success-coverage). arrange runs for A and then for B, so A holds the very state B's
// call acts on. call is the SELECT; args gets the tenant of the setting (caller) and the tenant
// whose ids go in (subject): the success call is B with B's ids, the cross call is B's setting
// with A's ids, and a function that acts on an id alone has nothing but its tenant predicate to
// refuse that.
type fnFix struct {
	arrange func(f *fnCtx, s catalogtest.SeedIDs)
	call    string
	args    func(caller, subject catalogtest.SeedIDs) []any
	own     string // the rows the success call answers, as fnCtx.summary prints them
	cross   string // the rows the cross call answers; "*" accepts any answer
	noCross bool   // the function takes no id: the tenant setting is its only selector
	effect  string
}

// fnCtx is the transaction a case runs in. It is rolled back, so no case leaves a trace.
type fnCtx struct {
	h    *harness
	tx   pgx.Tx
	ids  map[string]uuid.UUID
	repl *strings.Replacer
}

func (f *fnCtx) exec(sql string, args ...any) {
	f.h.t.Helper()
	if _, err := f.tx.Exec(f.h.ctx, sql, args...); err != nil {
		f.h.t.Fatalf("arrange: %v\n%s", err, sql)
	}
}

// id is a fixed identifier per name and tenant, made on first use, so arrange and call agree.
func (f *fnCtx) id(name string, s catalogtest.SeedIDs) uuid.UUID {
	key := fmt.Sprintf("%s/%d", name, s.Index)
	if f.ids[key] == uuid.Nil {
		f.ids[key] = uuid.Must(uuid.NewV7())
	}
	return f.ids[key]
}

// extraPhone and newPhone are numbers only the fixtures use: an invite's, and a phone change's.
func extraPhone(s catalogtest.SeedIDs) string { return fmt.Sprintf("+98912220000%d", s.Index) }
func newPhone(s catalogtest.SeedIDs) string   { return fmt.Sprintf("+98913111100%d", s.Index) }

func (f *fnCtx) phones(s catalogtest.SeedIDs) []string {
	return []string{s.Phone, extraPhone(s), newPhone(s)}
}

// summary prints the rows a call answered, with the ids of A and B named, so an expectation
// reads "(B.tenant)" and cannot be satisfied by A's row.
func (f *fnCtx) summary(rows pgx.Rows) string {
	var out strings.Builder
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			f.h.t.Fatal(err)
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			switch x := v.(type) {
			case nil:
				parts[i] = "null"
			case [16]byte:
				parts[i] = f.repl.Replace(uuid.UUID(x).String())
			case []byte:
				parts[i] = "bytes"
			default:
				parts[i] = f.repl.Replace(fmt.Sprint(x))
			}
		}
		out.WriteString("(" + strings.Join(parts, ",") + ")")
	}
	if err := rows.Err(); err != nil {
		f.h.t.Fatalf("call: %v", err)
	}
	return out.String()
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// tokenOf is the SQL that turns a name into the 32 bytes of a ticket hash.
func ticketHash(prefix string) string {
	return fmt.Sprintf("sha256(convert_to('%s-' || $1::text, 'UTF8'))", prefix)
}

func (h *harness) fnFixtures() map[string]fnFix {
	byTenant := func(s, _ catalogtest.SeedIDs) []any { return nil }
	user := func(_, s catalogtest.SeedIDs) []any { return []any{s.User} }
	// oneTime puts the user in the state of an admin-issued one-time password.
	oneTime := func(f *fnCtx, s catalogtest.SeedIDs) {
		f.exec(`DELETE FROM ctrlz.webauthn_credentials WHERE tenant_id = $1`, s.Tenant)
		f.exec(`UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, s.User)
	}
	rpInForce := func(f *fnCtx, s catalogtest.SeedIDs) {
		f.exec(`UPDATE ctrlz.webauthn_config SET rp_id = 'rp.test'`)
	}
	ticket := func(f *fnCtx, s catalogtest.SeedIDs) {
		f.exec(`INSERT INTO ctrlz.auth_tickets (token_hash, kind, subject_tenant, subject_user, expires_at)
			VALUES (sha256(convert_to('tk-' || $3::text, 'UTF8')), 'mfa', $1, $2, now() + interval '5 minutes')`, s.Tenant, s.User, s.Tenant)
	}
	ticketArgs := func(_, s catalogtest.SeedIDs) []any { return []any{s.Tenant} }
	tenantOf := func(sql string, arg func(s catalogtest.SeedIDs) any) fnFix {
		return fnFix{call: sql, args: func(_, s catalogtest.SeedIDs) []any { return []any{arg(s)} }, own: "(B.tenant)", noCross: true, effect: fxReads}
	}
	// otp plants a consumed or open OTP challenge for the tenant's own phone.
	otp := func(consumed bool, purpose, phone func(s catalogtest.SeedIDs) string, name string) func(f *fnCtx, s catalogtest.SeedIDs) {
		return func(f *fnCtx, s catalogtest.SeedIDs) {
			f.exec(`INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at)
				VALUES ($1, $2, $3, '\x01', now() + interval '5 minutes', CASE WHEN $4::boolean THEN now() END)`,
				f.id(name, s), phone(s), purpose(s), consumed)
		}
	}
	own := func(s catalogtest.SeedIDs) string { return s.Phone }
	login := func(catalogtest.SeedIDs) string { return "login" }

	return map[string]fnFix{
		"admin_one_time_state": {arrange: oneTime, call: `SELECT cred_state, no_second_factor, tenant_status FROM ctrlz_fn.admin_one_time_state($1)`,
			args: user, own: "(one_time_live,true,active)", cross: "", effect: fxReads},
		"admin_reissue_one_time_password": {arrange: oneTime, call: `SELECT outcome FROM ctrlz_fn.admin_reissue_one_time_password($1, 'argon2id$new')`,
			args: user, own: "(ok)", cross: "(not_found)", effect: fxChanges},
		"admin_revoke_user_sessions": {call: `SELECT ctrlz_fn.admin_revoke_user_sessions($1)`,
			args: user, own: "(1)", cross: "(0)", effect: fxChanges},
		"announcements_for_tenant": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`INSERT INTO ctrlz.announcements (audience, tenant_id, body) VALUES ('tenant', $1, 'ann-' || $2::text)`, s.Tenant, s.Tenant)
			},
			call: `SELECT body FROM ctrlz_fn.announcements_for_tenant() ORDER BY body`, args: byTenant,
			own: "(ann-B.tenant)(hello)", noCross: true, effect: fxReads},
		"auth_phone_change_complete": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`DELETE FROM ctrlz.phone_change_requests WHERE tenant_id = $1`, s.Tenant)
				f.exec(`INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at) VALUES
					($1, $3, 'phone_old', '\x01', now() + interval '5 minutes', now()), ($2, $4, 'phone_new', '\x01', now() + interval '5 minutes', now())`,
					f.id("old", s), f.id("new", s), s.Phone, newPhone(s))
				f.exec(`INSERT INTO ctrlz.phone_change_requests (tenant_id, id, user_id, new_phone_e164, old_otp_id, new_otp_id, expires_at)
					VALUES ($1, $2, $3, $4, $5, $6, now() + interval '10 minutes')`,
					s.Tenant, f.id("req", s), s.User, newPhone(s), f.id("old", s), f.id("new", s))
			},
			call: `SELECT outcome FROM ctrlz_fn.auth_phone_change_complete($1)`,
			args: nil, // the request id is made by arrange, see argsWithIDs
			own:  "(ok)", cross: "(invalid)", effect: fxChanges},
		"auth_phone_mark_verified": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`UPDATE ctrlz.users SET phone_verified_at = NULL WHERE id = $1`, s.User)
				otp(true, login, own, "otp")(f, s)
			},
			call: `SELECT outcome FROM ctrlz_fn.auth_phone_mark_verified($1, $2)`,
			args: nil, // per case, see argsWithIDs
			own:  "(ok)", cross: "(invalid)", effect: fxChanges},
		"auth_tickets_revoke": {arrange: ticket, call: `SELECT 'done' FROM ctrlz_fn.auth_tickets_revoke($1)`, args: user,
			own: "(done)", cross: "*", effect: fxChanges},
		"auth_totp_seed": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`UPDATE ctrlz.users SET totp_secret_ct = '\x435a01000100' WHERE id = $1`, s.User)
			},
			call: `SELECT octet_length(totp_secret_ct) FROM ctrlz_fn.auth_totp_seed($1, $2)`,
			args: func(_, s catalogtest.SeedIDs) []any { return []any{s.User, s.Tenant} }, own: "(6)", cross: "", effect: fxReads},
		"auth_user_flags":   {call: `SELECT has_password FROM ctrlz_fn.auth_user_flags($1)`, args: user, own: "(true)", cross: "", effect: fxReads},
		"endpoint_pair_ips": {call: `SELECT endpoint_id FROM ctrlz_fn.endpoint_pair_ips()`, args: byTenant, own: "(B.endpoint)", noCross: true, effect: fxReads},
		"ip_claim_check": {call: `SELECT outcome FROM ctrlz_fn.ip_claim_check($1)`,
			args: func(_, s catalogtest.SeedIDs) []any { return []any{pfx(s.Prefix)} }, own: "(own)", cross: "(unavailable)", effect: fxReads},
		"ip_claim_open_challenge": {call: `SELECT length(label) FROM ctrlz_fn.ip_claim_open_challenge($1)`,
			args: func(_, s catalogtest.SeedIDs) []any { return []any{s.Claim} }, own: "(26)", cross: "", effect: fxChanges},
		"ip_claim_release": {call: `SELECT outcome FROM ctrlz_fn.ip_claim_release($1)`,
			args: func(_, s catalogtest.SeedIDs) []any { return []any{s.Claim} }, own: "(released)", cross: "(not_found)", effect: fxChanges},
		"ip_claim_request": {call: `SELECT outcome FROM ctrlz_fn.ip_claim_request($1, $2, 'manual')`,
			args: func(caller, s catalogtest.SeedIDs) []any {
				return []any{s.Endpoint, pfx(fmt.Sprintf("203.0.113.%d/32", caller.Index))}
			}, own: "(active)", cross: "(not_found)", effect: fxChanges},
		"ip_claim_take": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				host := strings.TrimSuffix(s.Prefix, "/32")
				f.exec(`UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = $2::inet, observed_protocol = 'tcp' WHERE claim_id = $1`, s.Claim, host)
			},
			call: `SELECT outcome FROM ctrlz_fn.ip_claim_take($1, NULL::text, gen_random_uuid())`,
			args: func(_, s catalogtest.SeedIDs) []any { return []any{s.Claim} }, own: "(active)", cross: "(not_found)", effect: fxChanges},
		"keytool_totp_declare_lost": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`UPDATE ctrlz.users SET totp_secret_ct = '\x435a010001aabb', totp_enabled_at = now() WHERE id = $1`, s.User)
			},
			// The tool passes the user ids and ciphertexts it proved lost (admin-r13-3), so the function takes an id
			// and needs the cross call: B's setting with A's user must clear nothing.
			call: `SELECT ctrlz_fn.keytool_totp_declare_lost(1, ARRAY[$1]::uuid[], ARRAY['\x435a010001aabb'::bytea])`, args: user, own: "(1)", cross: "(0)", effect: fxChanges},
		"keytool_totp_replace": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`UPDATE ctrlz.users SET totp_secret_ct = '\x0102030405' WHERE id = $1`, s.User)
			},
			call: `SELECT ctrlz_fn.keytool_totp_replace($1, '\x0102030405'::bytea, '\x0a0b0c0d'::bytea)`, args: user, own: "(true)", cross: "(false)", effect: fxChanges},
		"tenant_set_password": {call: `SELECT ctrlz_fn.tenant_set_password($1, 'argon2id$new')`, args: user, own: "(true)", cross: "(false)", effect: fxChanges},
		"worker_enforce_clear_without_live": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				rpInForce(f, s)
				f.exec(`UPDATE ctrlz.users SET enforce_passkey = true WHERE id = $1`, s.User)
			},
			call: `SELECT ctrlz_fn.worker_enforce_clear_without_live('rp.test')`, args: byTenant, own: "(1)", noCross: true, effect: fxChanges},
		"worker_passkeys_mark_stale": {arrange: rpInForce, call: `SELECT user_id FROM ctrlz_fn.worker_passkeys_mark_stale('rp.test')`, args: byTenant,
			own: "(B.user)", noCross: true, effect: fxChanges},
		"worker_sweep_pending_totp": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`UPDATE ctrlz.users SET totp_secret_ct = '\x0102030405', totp_pending_at = now() - interval '1 hour' WHERE id = $1`, s.User)
			},
			call: `SELECT ctrlz_fn.worker_sweep_pending_totp(100)`, args: byTenant, own: "(1)", noCross: true, effect: fxChanges},

		"auth_download_by_hash":      tenantOf(`SELECT tenant_id FROM ctrlz_fn.auth_download_by_hash(convert_to($1, 'UTF8'))`, func(s catalogtest.SeedIDs) any { return s.Download }),
		"auth_passkey_by_credential": tenantOf(`SELECT tenant_id FROM ctrlz_fn.auth_passkey_by_credential(convert_to($1, 'UTF8'))`, func(s catalogtest.SeedIDs) any { return s.Passkey }),
		"auth_refresh_by_hash":       tenantOf(`SELECT tenant_id FROM ctrlz_fn.auth_refresh_by_hash(convert_to($1, 'UTF8'))`, func(s catalogtest.SeedIDs) any { return s.Refresh }),
		"auth_session_by_hash":       tenantOf(`SELECT tenant_id FROM ctrlz_fn.auth_session_by_hash(convert_to($1, 'UTF8'))`, func(s catalogtest.SeedIDs) any { return s.Session }),
		"auth_share_by_hash":         tenantOf(`SELECT tenant_id FROM ctrlz_fn.auth_share_by_hash(convert_to($1, 'UTF8'))`, func(s catalogtest.SeedIDs) any { return s.Share }),
		"auth_token_by_hash":         tenantOf(`SELECT tenant_id FROM ctrlz_fn.auth_token_by_hash(convert_to($1, 'UTF8'))`, func(s catalogtest.SeedIDs) any { return s.APIToken }),
		"auth_user_by_phone":         tenantOf(`SELECT tenant_id FROM ctrlz_fn.auth_user_by_phone($1)`, func(s catalogtest.SeedIDs) any { return s.Phone }),
		"auth_invite_by_hash": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`INSERT INTO ctrlz.invites (id, token_hash, phone_e164, expires_at) VALUES ($1, convert_to('inv-' || $2::text, 'UTF8'), $3, now() + interval '1 day')`,
					f.id("inv", s), s.Tenant, extraPhone(s))
			},
			call: `SELECT phone_e164 FROM ctrlz_fn.auth_invite_by_hash(convert_to('inv-' || $1::text, 'UTF8'))`, args: ticketArgs,
			own: "(" + extraPhone(catalogtest.SeedIDs{Index: 2}) + ")", noCross: true, effect: fxReads},
		"auth_otp_check": {arrange: otp(false, login, own, "otp"), call: `SELECT outcome FROM ctrlz_fn.auth_otp_check($1, $2, 'login', '\x01'::bytea)`,
			args: nil, own: "(ok)", cross: "(invalid)", effect: fxReads},
		"auth_otp_consume": {arrange: otp(false, login, own, "otp"), call: `SELECT outcome FROM ctrlz_fn.auth_otp_consume($1, $2, 'login', '\x01'::bytea)`,
			args: nil, own: "(ok)", cross: "(invalid)", effect: fxChanges},
		"auth_otp_issue": {call: `SELECT allowed FROM ctrlz_fn.auth_otp_issue($1, 'login', '\x01'::bytea, '\x02'::bytea, '198.51.100.7'::inet, false)`,
			args: func(caller, _ catalogtest.SeedIDs) []any { return []any{caller.Phone} }, own: "(true)", noCross: true, effect: fxChanges},
		"auth_ticket_peek": {arrange: ticket, call: `SELECT subject_tenant FROM ctrlz_fn.auth_ticket_peek(` + ticketHash("tk") + `, 'mfa')`,
			args: ticketArgs, own: "(B.tenant)", noCross: true, effect: fxChanges},
		"auth_ticket_take": {arrange: ticket, call: `SELECT subject_tenant FROM ctrlz_fn.auth_ticket_take(` + ticketHash("tk") + `, 'mfa')`,
			args: ticketArgs, own: "(B.tenant)", noCross: true, effect: fxChanges},
		"auth_ticket_put": {call: `SELECT id IS NOT NULL FROM ctrlz_fn.auth_ticket_put(sha256(convert_to('put-' || $3::text, 'UTF8')), 'mfa', $1::uuid, $2::uuid, false, 'password', NULL::bytea, 60, 1::bigint)`,
			args: func(_, s catalogtest.SeedIDs) []any { return []any{s.Tenant, s.User, s.Tenant} }, own: "(true)", noCross: true, effect: fxChanges},

		"admin_create_user": {call: `SELECT tenant_id IS NOT NULL FROM ctrlz_fn.admin_create_user($1, 'argon2id$new', 'fa')`,
			args: func(_, _ catalogtest.SeedIDs) []any { return []any{"+989123334444"} }, own: "(true)", noCross: true, effect: fxElsewhere},
		"auth_register_user": {
			arrange: func(f *fnCtx, s catalogtest.SeedIDs) {
				f.exec(`INSERT INTO ctrlz.invites (id, token_hash, phone_e164, expires_at) VALUES ($1, convert_to('inv-' || $2::text, 'UTF8'), $3, now() + interval '1 day')`,
					f.id("inv", s), s.Tenant, extraPhone(s))
				otp(true, func(catalogtest.SeedIDs) string { return "invite" }, extraPhone, "otp")(f, s)
			},
			call: `SELECT tenant_id IS NOT NULL FROM ctrlz_fn.auth_register_user($1, 'argon2id$new', 'fa', $2, $3)`,
			args: nil, own: "(true)", cross: "", effect: fxChanges},
	}
}

// argsWithIDs gives the functions whose arguments are ids made by arrange (a request, a
// challenge, an invite) their arguments. The id is per tenant and per case, so the table above
// cannot hold it.
func (f *fnCtx) argsWithIDs(fn string, caller, subject catalogtest.SeedIDs) ([]any, bool) {
	switch fn {
	case "auth_phone_change_complete":
		return []any{f.id("req", subject)}, true
	case "auth_phone_mark_verified":
		return []any{subject.User, f.id("otp", subject)}, true
	case "auth_otp_check", "auth_otp_consume":
		// The challenge is the subject's; the phone is the caller's, which is what a request
		// from B names.
		return []any{f.id("otp", subject), caller.Phone}, true
	case "auth_register_user":
		return []any{extraPhone(caller), f.id("inv", subject), f.id("otp", subject)}, true
	}
	return nil, false
}
