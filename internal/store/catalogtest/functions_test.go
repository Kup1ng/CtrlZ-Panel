package catalogtest_test

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// returnColumns reads the column names out of "TABLE(a uuid, b text)".
func returnColumns(returns string) []string {
	inner := strings.TrimSuffix(strings.TrimPrefix(returns, "TABLE("), ")")
	var out []string
	for _, part := range strings.Split(inner, ", ") {
		out = append(out, strings.Fields(part)[0])
	}
	return out
}

// TestSecurityDefinerFunctions is spec test 24. Every function in the
// allow-list is called as ctrlz_tenant with its exact key, and must return one
// row with exactly the columns listed in functions.yaml; with a wrong key it
// must return nothing. Functions that act for the tenant of the transaction
// are called with no tenant too.
func TestSecurityDefinerFunctions(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	fx := h.fx
	a, b := h.A, h.B

	// One global invite for the invite lookup.
	inviteID := uuid.Must(uuid.NewV7())
	if _, err := h.super.Exec(h.ctx, `INSERT INTO ctrlz.invites (id, token_hash, phone_e164, expires_at) VALUES ($1, convert_to('invite-token', 'UTF8'), '+989121110000', now() + interval '1 day')`, inviteID); err != nil {
		t.Fatal(err)
	}
	bytesOf := func(s string) []byte { return []byte(s) }
	miss := bytesOf("no-such-token")
	otherUUID := uuid.Must(uuid.NewV7())

	type tcase struct {
		fn      string
		hit     []any
		miss    []any
		guc     *string // setting for the exact-key call; nil leaves it unset
		wantKey string  // a column that must hold the expected tenant, optional
	}
	aStr := a.Tenant.String()
	cases := []tcase{
		{fn: "auth_user_by_phone", hit: []any{a.Phone}, miss: []any{"+989999999999"}},
		{fn: "auth_totp_seed", hit: []any{a.User, a.Tenant}, miss: []any{a.User, b.Tenant}, guc: &aStr},
		{fn: "auth_session_by_hash", hit: []any{bytesOf(a.Session)}, miss: []any{miss}},
		{fn: "auth_token_by_hash", hit: []any{bytesOf(a.APIToken)}, miss: []any{miss}},
		{fn: "auth_refresh_by_hash", hit: []any{bytesOf(a.Refresh)}, miss: []any{miss}},
		{fn: "auth_invite_by_hash", hit: []any{bytesOf("invite-token")}, miss: []any{miss}},
		{fn: "auth_passkey_by_credential", hit: []any{bytesOf(a.Passkey)}, miss: []any{miss}},
		{fn: "auth_share_by_hash", hit: []any{bytesOf(a.Share)}, miss: []any{miss}},
		{fn: "auth_download_by_hash", hit: []any{bytesOf(a.Download)}, miss: []any{miss}},
		{fn: "endpoint_pair_ips", guc: &aStr},
		{fn: "announcements_for_tenant", guc: &aStr},
		{fn: "ip_claim_check", hit: []any{netip.MustParsePrefix("203.0.113.0/24")}, guc: &aStr},
		{fn: "ip_claim_release", hit: []any{a.Claim}, guc: &aStr, miss: []any{otherUUID}},
		// No row at all for a claim that is not the caller's.
		{fn: "ip_claim_open_challenge", hit: []any{a.Claim}, guc: &aStr, miss: []any{otherUUID}},
		{fn: "ip_claim_take", hit: []any{a.Claim, nil, otherUUID}, guc: &aStr, miss: []any{otherUUID, nil, otherUUID}},
		{fn: "ip_claim_request", hit: []any{a.Endpoint, netip.MustParsePrefix("203.0.113.0/24"), "manual"}, guc: &aStr, miss: []any{otherUUID, netip.MustParsePrefix("203.0.113.0/24"), "manual"}},
	}

	byName := map[string]catalogtest.SDFunction{}
	for _, f := range fx.Functions.SecurityDefiner {
		byName[f.Name] = f
	}
	covered := map[string]bool{}

	run := func(fn string, args []any, guc *string) (cols []string, rows int, err error) {
		ph := make([]string, len(args))
		for i := range args {
			ph[i] = fmt.Sprintf("$%d", i+1)
		}
		h.inTx(h.super, "tenant", guc, func(tx pgx.Tx) {
			r, qerr := tx.Query(h.ctx, fmt.Sprintf("SELECT * FROM ctrlz_fn.%s(%s)", fn, strings.Join(ph, ", ")), args...)
			if qerr != nil {
				err = qerr
				return
			}
			for _, fd := range r.FieldDescriptions() {
				cols = append(cols, fd.Name)
			}
			for r.Next() {
				rows++
			}
			err = r.Err()
		})
		return
	}

	for _, c := range cases {
		covered[c.fn] = true
		f, ok := byName[c.fn]
		if !ok {
			t.Errorf("%s is not in functions.yaml", c.fn)
			continue
		}
		t.Run(c.fn, func(t *testing.T) {
			cols, rows, err := run(c.fn, c.hit, c.guc)
			if err != nil {
				t.Fatalf("exact key: %v", err)
			}
			if rows != 1 {
				t.Errorf("exact key returned %d rows, want 1", rows)
			}
			want := returnColumns(f.Returns)
			if strings.Join(cols, ",") != strings.Join(want, ",") {
				t.Errorf("columns are %v, want %v", cols, want)
			}
			if c.miss != nil {
				_, rows, err := run(c.fn, c.miss, c.guc)
				if err != nil {
					t.Fatalf("wrong key: %v", err)
				}
				if c.fn == "ip_claim_request" {
					// Reports not_found as a row, creating nothing.
					if rows != 1 {
						t.Errorf("wrong endpoint returned %d rows, want 1 (not_found)", rows)
					}
				} else if c.fn == "ip_claim_release" || c.fn == "ip_claim_take" {
					if rows != 1 {
						t.Errorf("wrong claim returned %d rows, want one not_found outcome", rows)
					}
				} else if rows != 0 {
					t.Errorf("wrong key returned %d rows, want 0", rows)
				}
			}
			// Functions that act for the tenant of the transaction return
			// nothing at all when there is none.
			if c.guc != nil {
				_, rows, err := run(c.fn, c.hit, nil)
				if err != nil {
					t.Fatalf("no tenant: %v", err)
				}
				if rows != 0 {
					t.Errorf("with no tenant set the function returned %d rows, want 0", rows)
				}
				other := uuid.Must(uuid.NewV7()).String()
				_, rows, err = run(c.fn, c.hit, &other)
				if err != nil {
					t.Fatalf("foreign tenant: %v", err)
				}
				if c.fn == "ip_claim_check" || c.fn == "announcements_for_tenant" {
					if rows != 1 {
						t.Errorf("a tenant with no claims got %d rows from ip_claim_check, want 1", rows)
					}
				} else if c.fn == "ip_claim_request" || c.fn == "ip_claim_release" || c.fn == "ip_claim_take" {
					if rows != 1 { // not_found for someone else's endpoint or claim
						t.Errorf("a foreign tenant got %d rows, want a single not_found", rows)
					}
				} else if rows != 0 {
					t.Errorf("a foreign tenant got %d rows, want 0", rows)
				}
			}
		})
	}

	// endpoint_pair_ips returns the caller's pair only: A has one endpoint, so
	// one row, with the two node addresses, and never B's endpoint.
	t.Run("endpoint_pair_ips content", func(t *testing.T) {
		h.inTx(h.super, "tenant", &aStr, func(tx pgx.Tx) {
			var ep uuid.UUID
			var p, f netip.Addr
			if err := tx.QueryRow(h.ctx, "SELECT endpoint_id, primary_dns_ip, fallback_dns_ip FROM ctrlz_fn.endpoint_pair_ips()").Scan(&ep, &p, &f); err != nil {
				t.Fatal(err)
			}
			if ep != a.Endpoint || p.String() != "192.0.2.1" || f.String() != "192.0.2.2" {
				t.Errorf("got %s %s %s", ep, p, f)
			}
		})
	})

	// The remaining functions change state and are exercised in their own
	// tests below: registration and OTP.
	// The P1 functions (migration 0011) are exercised in auth_test.go, tests 29
	// to 39, in test 42 (admin_reissue_one_time_password), and in the store package tests.
	// The five transitions of the one-time-state rule (admin_account_*, tenant_set_password) are
	// driven from every credential state by internal/store TestCredentialStateEdges and
	// TestUserCredentialStateEdges.
	// audit_lock takes no tenant and returns nothing: its behaviour (refused for every role but
	// ctrlz_admin, takes the advisory lock, drops it at commit) is in review_r14_reach_test.go.
	covered["audit_lock"] = true
	// profile_tenant_lock answers whether it took the tenant's profile-creation lock: TestFunctionIsolation calls it with B's tenant
	// (true) and with no tenant (false, nothing locked), and the max_profiles driver of internal/store TestCapsRaceHarness
	// shows that the lock serialises racing creators.
	covered["profile_tenant_lock"] = true

	// keytool_audit_key_event writes one row of the admin chain for the key tool: its refusals are in
	// review_r18_admin_test.go (TestTheKeyToolCanWriteTwoKindsOfAuditRowAndNothingElse), and the chain it writes is
	// verified with the Go verifier by internal/admincli TestKeyStatusAndRekey (admin-r18-6, -7).
	covered["keytool_audit_key_event"] = true
	// tenant_notice_sms queues the SMS of a security notice (question 19): its two-tenant call is the fixture of
	// TestFunctionIsolation, its refusals are in internal/api TestASecurityNoticeQueuesOneSMSToTheAccountPhone, and its
	// cap is raced by internal/store TestCapsRaceHarness (entry notice.sms).
	covered["tenant_notice_sms"] = true
	for _, name := range []string{"auth_register_user", "auth_otp_issue", "auth_otp_consume", "auth_otp_check", "admin_create_user", "admin_one_time_state", "admin_reissue_one_time_password", "admin_throttle_hit", "admin_throttle_refund",
		"admin_throttle_reset", "admin_account_bootstrap", "admin_account_reset", "admin_account_set_password", "admin_account_totp_enable", "tenant_set_password", "keytool_totp_declare_lost", "worker_passkeys_mark_stale", "worker_enforce_clear_without_live", "worker_sweep_throttle", "worker_sweep_tickets", "worker_sweep_pending_totp", "worker_sweep_sms_deliveries", "worker_sweep_sms_counters", "worker_sweep_otp_challenges", "keytool_totp_replace", "admin_totp_replace", "admin_revoke_user_sessions", "admin_sms_stats", "auth_phone_change_complete", "auth_phone_mark_verified", "auth_public_config", "auth_throttle_hit",
		"auth_throttle_refund", "auth_throttle_reset", "auth_ticket_peek", "auth_ticket_put", "auth_ticket_take", "auth_tickets_revoke", "auth_user_flags"} {
		covered[name] = true
	}
	for _, f := range fx.Functions.SecurityDefiner {
		if !covered[f.Name] {
			t.Errorf("function %s has no behaviour test; add a case", f.Name)
		}
	}
}

// otpRow inserts an OTP challenge as the superuser (the tx is switched back to
// the tenant role afterwards by the caller) and returns its id. consumedAgo is
// how long ago it was consumed; nil leaves it unconsumed.
func otpRow(h *harness, tx pgx.Tx, phone, purpose string, consumedAgo *time.Duration) uuid.UUID {
	h.t.Helper()
	id := uuid.Must(uuid.NewV7())
	var consumed any
	if consumedAgo != nil {
		consumed = time.Now().Add(-*consumedAgo)
	}
	if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
		h.t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at)
VALUES ($1, $2, $3, '\x01', now() + interval '5 minutes', $4)`, id, phone, purpose, consumed); err != nil {
		h.t.Fatal(err)
	}
	if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
		h.t.Fatal(err)
	}
	return id
}

func TestRegisterUser(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	call := func(tx pgx.Tx, phone string, invite *uuid.UUID, otp *uuid.UUID) (rows int, tenant uuid.UUID) {
		r, err := tx.Query(h.ctx, "SELECT tenant_id, user_id FROM ctrlz_fn.auth_register_user($1, 'hash', 'fa', $2, $3)", phone, invite, otp)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		for r.Next() {
			var u uuid.UUID
			if err := r.Scan(&tenant, &u); err != nil {
				t.Fatal(err)
			}
			rows++
		}
		return
	}
	setMode := func(tx pgx.Tx, mode string) {
		if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, "UPDATE ctrlz.system_settings SET registration_mode = $1", mode); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
	}
	ago := func(d time.Duration) *time.Duration { return &d }
	h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
		const phone = "+989125550001"
		// Closed: refused even with a good OTP, and nothing is created.
		good := otpRow(h, tx, phone, "signup", ago(time.Minute))
		if rows, _ := call(tx, phone, nil, &good); rows != 0 {
			t.Errorf("closed registration created a user")
		}

		setMode(tx, "open")
		// Review F07: a number nobody verified cannot be registered. Each of
		// these used to succeed in open mode, because registration took no OTP.
		other := otpRow(h, tx, "+989125559999", "signup", ago(time.Minute))
		wrongPurpose := otpRow(h, tx, phone, "login", ago(time.Minute))
		unconsumed := otpRow(h, tx, phone, "signup", nil)
		stale := otpRow(h, tx, phone, "signup", ago(11*time.Minute))
		for name, otp := range map[string]*uuid.UUID{"no OTP": nil, "an unknown OTP": ptr(uuid.Must(uuid.NewV7())),
			"an OTP for another phone": &other, "an OTP for another purpose": &wrongPurpose,
			"an OTP that was never consumed": &unconsumed, "an OTP consumed too long ago": &stale} {
			if rows, _ := call(tx, phone, nil, otp); rows != 0 {
				t.Errorf("registration with %s was accepted", name)
			}
		}
		// A signup OTP does not register through the invite route either.
		if rows, _ := call(tx, phone, ptr(uuid.Must(uuid.NewV7())), &good); rows != 0 {
			t.Errorf("a signup OTP was accepted for an invite registration")
		}

		// The right OTP: created once, verified, and the same phone is then
		// refused the same way.
		rows, tenant := call(tx, phone, nil, &good)
		if rows != 1 || tenant == uuid.Nil {
			t.Fatalf("open registration returned %d rows", rows)
		}
		if rows, _ := call(tx, phone, nil, &good); rows != 0 {
			t.Errorf("a taken phone was registered twice")
		}
		// The new tenant has its owner, verified, and its entitlements row.
		if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{
			"SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND role = 'owner' AND phone_verified_at IS NOT NULL",
			"SELECT count(*) FROM ctrlz.tenant_entitlements WHERE tenant_id = $1",
			"SELECT count(*) FROM ctrlz.tenants WHERE id = $1",
		} {
			if n, err := count(h.ctx, tx, q, tenant); err != nil || n != 1 {
				t.Errorf("%s: %d rows, err %v", q, n, err)
			}
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}

		// Invite: works in closed mode, once, only for its own phone, and only
		// with an OTP of purpose invite for that phone.
		setMode(tx, "closed")
		inv := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.invites (id, token_hash, phone_e164, expires_at) VALUES ($1, '\x0102', '+989125550002', now() + interval '1 day')`, inv); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
		inv3 := otpRow(h, tx, "+989125550003", "invite", ago(time.Minute))
		inv2 := otpRow(h, tx, "+989125550002", "invite", ago(time.Minute))
		signup2 := otpRow(h, tx, "+989125550002", "signup", ago(time.Minute))
		if rows, _ := call(tx, "+989125550003", &inv, &inv3); rows != 0 {
			t.Errorf("an invite for another phone was accepted")
		}
		if rows, _ := call(tx, "+989125550002", &inv, &signup2); rows != 0 {
			t.Errorf("an invite registration with a signup OTP was accepted")
		}
		if rows, _ := call(tx, "+989125550002", &inv, nil); rows != 0 {
			t.Errorf("an invite registration without an OTP was accepted")
		}
		if rows, _ := call(tx, "+989125550002", &inv, &inv2); rows != 1 {
			t.Errorf("a valid invite was refused in closed mode")
		}
		if rows, _ := call(tx, "+989125550002", &inv, &inv2); rows != 0 {
			t.Errorf("an invite was used twice")
		}
	})
}

func ptr[T any](v T) *T { return &v }

func TestOTP(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
		// The resend cooldown is a minute and this test runs in one transaction
		// with a frozen now(), so issueFrom ages the earlier challenges first;
		// issueRaw does not, and is for the cooldown itself.
		var rewind func()
		issueRaw := func(phone, purpose, ip string) (uuid.UUID, bool) {
			var id *uuid.UUID
			var ok bool
			var ipArg any
			if ip != "" {
				ipArg = ip
			}
			if err := tx.QueryRow(h.ctx, "SELECT id, allowed FROM ctrlz_fn.auth_otp_issue($1, $2, '\\x0a0b', '\\x0c'::bytea, $3::inet, false)", phone, purpose, ipArg).Scan(&id, &ok); err != nil {
				t.Fatal(err)
			}
			if id == nil {
				return uuid.Nil, ok
			}
			return *id, ok
		}
		issueFrom := func(phone, purpose, ip string) (uuid.UUID, bool) {
			t.Helper()
			rewind()
			return issueRaw(phone, purpose, ip)
		}
		rewind = func() {
			if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(h.ctx, "UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '5 minutes' WHERE created_at > now() - interval '5 minutes'"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
				t.Fatal(err)
			}
		}
		issue := func(phone string) (uuid.UUID, bool) { return issueFrom(phone, "login", "198.51.100.7") }
		consumeAs := func(id uuid.UUID, phone, purpose, hash string) string {
			var out string
			if err := tx.QueryRow(h.ctx, "SELECT outcome FROM ctrlz_fn.auth_otp_consume($1, $2, $3, $4::bytea)", id, phone, purpose, hash).Scan(&out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		const p1 = "+989127770001"
		consume := func(id uuid.UUID, hash string) string { return consumeAs(id, p1, "login", hash) }
		counter := func(scope, key string) int {
			t.Helper()
			if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant") }()
			var n int
			err := tx.QueryRow(h.ctx, "SELECT COALESCE((SELECT count FROM ctrlz.sms_counters WHERE scope = $1 AND key = $2), 0)", scope, key).Scan(&n)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}

		id, ok := issue(p1)
		if !ok || id == uuid.Nil {
			t.Fatalf("first OTP was not issued")
		}
		if got := consume(id, `\x0a0c`); got != "invalid" {
			t.Errorf("wrong code: %s", got)
		}
		// Review F07: the right code is still refused for another phone or
		// purpose, with the generic outcome, and spends no try.
		if got := consumeAs(id, "+989127770009", "login", `\x0a0b`); got != "invalid" {
			t.Errorf("right code, other phone: %s", got)
		}
		if got := consumeAs(id, p1, "reset", `\x0a0b`); got != "invalid" {
			t.Errorf("right code, other purpose: %s", got)
		}
		if got := consume(id, `\x0a0b`); got != "ok" {
			t.Errorf("right code: %s", got)
		}
		if got := consume(id, `\x0a0b`); got != "consumed" {
			t.Errorf("reused code: %s", got)
		}
		if got := consume(uuid.Must(uuid.NewV7()), `\x0a0b`); got != "invalid" {
			t.Errorf("unknown challenge: %s", got)
		}
		// Five tries, then locked even for the right code. Mismatched
		// phone/purpose calls do not count, so a stranger who knows the id
		// cannot lock it.
		id2, _ := issue(p1)
		for i := 0; i < 20; i++ {
			consumeAs(id2, "+989127770009", "login", `\x0000`)
		}
		for i := 0; i < 5; i++ {
			consume(id2, `\x0000`)
		}
		if got := consume(id2, `\x0a0b`); got != "locked" {
			t.Errorf("after five wrong tries: %s", got)
		}

		// auth_otp_check (0018, primitives-r4-3) answers like consume but leaves a right
		// code alone: any number of checks, then the consume still works. A wrong code
		// spends a try, and the binding to phone and purpose is the same.
		const right, wrongHash = `\x0a0b`, `\x0000`
		checkOf := func(id uuid.UUID, phone, purpose, hash string) string {
			var out string
			if err := tx.QueryRow(h.ctx, "SELECT outcome FROM ctrlz_fn.auth_otp_check($1, $2, $3, $4::bytea)", id, phone, purpose, hash).Scan(&out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		const p3 = "+989127770003"
		id3, ok3 := issue(p3)
		if !ok3 {
			t.Fatal("challenge for the check test was not issued")
		}
		for i := 0; i < 8; i++ {
			if got := checkOf(id3, p3, "login", right); got != "ok" {
				t.Errorf("check %d of the right code: %s", i, got)
			}
		}
		if got := checkOf(id3, "+989127770009", "login", right); got != "invalid" {
			t.Errorf("check, other phone: %s", got)
		}
		if got := checkOf(id3, p3, "reset", right); got != "invalid" {
			t.Errorf("check, other purpose: %s", got)
		}
		// Eight checks of the right code spent no try, so the consume still works.
		if got := consumeAs(id3, p3, "login", right); got != "ok" {
			t.Errorf("consume after eight checks: %s", got)
		}
		if got := checkOf(id3, p3, "login", right); got != "consumed" {
			t.Errorf("check after consume: %s", got)
		}
		p4 := "+989127770004"
		id4, ok4 := issue(p4)
		if !ok4 {
			t.Fatal("second challenge for the check test was not issued")
		}
		for i := 0; i < 5; i++ {
			if got := checkOf(id4, p4, "login", wrongHash); got != "invalid" {
				t.Errorf("wrong check %d: %s", i, got)
			}
		}
		if got := checkOf(id4, p4, "login", right); got != "locked" {
			t.Errorf("check after five wrong tries: %s", got)
		}
		if got := consumeAs(id4, p4, "login", right); got != "locked" {
			t.Errorf("consume after five wrong checks: %s", got)
		}

		// The per-phone cap counts messages sent: five a day, the sixth is
		// refused and stores nothing.
		// They come from different networks: one network may send three to one
		// phone, and the phone's five are for the whole world.
		for i := 0; i < 3; i++ { // two issued above, three more reach five
			if _, ok := issueFrom(p1, "login", fmt.Sprintf("198.51.%d.7", 101+i)); !ok {
				t.Fatalf("attempt %d should still be allowed", i+3)
			}
		}
		const sixth = "198.51.104.7"
		globalBefore := counter("global", "all")
		ipBefore := counter("ip", sixth)
		if id, ok := issueFrom(p1, "login", sixth); ok || id != uuid.Nil {
			t.Errorf("sixth attempt in a day was allowed")
		}
		if n := counter("phone", p1); n != 5 {
			t.Errorf("phone counter is %d, want 5 (a refused attempt does not count)", n)
		}
		// Review F03: the refused attempt did not move the global or the IP
		// counter either. Before, each one raised the global counter, so one
		// client could burn the 5000-a-day cap for everybody.
		for i := 0; i < 50; i++ {
			issueFrom(p1, "login", sixth)
		}
		if g := counter("global", "all"); g != globalBefore {
			t.Errorf("refused attempts moved the global counter from %d to %d", globalBefore, g)
		}
		if n := counter("ip", sixth); n != ipBefore {
			t.Errorf("refused attempts moved the IP counter from %d to %d", ipBefore, n)
		}
		if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		if n, _ := count(h.ctx, tx, "SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = $1", p1); n != 5 {
			t.Errorf("%d challenges stored, want 5 (refused attempts store none)", n)
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}

		// L1-F03: one source cannot spend a phone's whole quota. Three a day per
		// (phone, network), counted on messages sent; the phone itself keeps
		// two more for everyone else.
		const victim = "+989127770101"
		for i := 0; i < 3; i++ {
			if _, ok := issueFrom(victim, "login", fmt.Sprintf("198.51.200.%d", i+1)); !ok {
				t.Fatalf("send %d from one network to one phone should be allowed", i+1)
			}
		}
		if _, ok := issueFrom(victim, "login", "198.51.200.77"); ok {
			t.Error("a fourth send from one /24 to one phone was allowed")
		}
		if n := counter("phone", victim); n != 3 {
			t.Errorf("the phone counter is %d after a refusal by the sub-cap, want 3", n)
		}
		if n := counter("phone_net", victim+"|198.51.200.0/24"); n != 3 {
			t.Errorf("the (phone, network) counter is %d, want 3", n)
		}
		if _, ok := issueFrom(victim, "login", "198.51.201.1"); !ok {
			t.Error("another network could not reach the phone's remaining quota")
		}
		if _, ok := issueFrom("+989127770102", "login", "198.51.200.5"); !ok {
			t.Error("the sub-cap on one phone refused another phone from the same network")
		}
		if _, ok := issueFrom(victim, "login", "2001:db8:aa:1::1"); !ok {
			t.Error("an IPv6 source could not reach the phone's last message")
		}
		if _, ok := issueFrom(victim, "login", "2001:db8:aa:1::2"); ok {
			t.Error("the phone's cap of five was exceeded")
		}

		// L1-F03: one message per (phone, purpose) per minute, counted on
		// messages sent.
		const cool = "+989127770103"
		if _, ok := issueFrom(cool, "login", "198.51.210.1"); !ok {
			t.Fatal("first send refused")
		}
		phoneBefore, globalBefore2 := counter("phone", cool), counter("global", "all")
		if _, ok := issueRaw(cool, "login", "198.51.211.1"); ok {
			t.Error("a second send inside the cooldown was allowed")
		}
		if counter("phone", cool) != phoneBefore || counter("global", "all") != globalBefore2 {
			t.Error("a send refused by the cooldown moved a counter")
		}
		if _, ok := issueRaw(cool, "reset", "198.51.211.1"); !ok {
			t.Error("the cooldown is per purpose, but another purpose was refused")
		}
		if _, ok := issueFrom(cool, "login", "198.51.212.1"); !ok {
			t.Error("a send after the cooldown was refused")
		}

		// Per IP address: 20 sends a day from one IPv4 host. The phones differ
		// so only the IP cap can refuse; the 21st is refused, and the phone it
		// asked for was not charged.
		for i := 0; i < 20; i++ {
			if _, ok := issueFrom(fmt.Sprintf("+98912888%04d", i), "login", "203.0.113.50"); !ok {
				t.Fatalf("send %d from one IP should be allowed", i+1)
			}
		}
		if _, ok := issueFrom("+989128889999", "login", "203.0.113.50"); ok {
			t.Error("the 21st send from one IP was allowed")
		}
		if n := counter("phone", "+989128889999"); n != 0 {
			t.Errorf("the phone of a request refused by the IP cap was charged %d", n)
		}
		// The same client written as an IPv4-mapped IPv6 address is the same
		// client.
		if _, ok := issueFrom("+989128889998", "login", "::ffff:203.0.113.50"); ok {
			t.Error("an IPv4-mapped spelling got a fresh IP budget")
		}

		// IPv6 keys on the /64: rotating the low 64 bits buys nothing.
		for i := 0; i < 20; i++ {
			if _, ok := issueFrom(fmt.Sprintf("+98912777%04d", i+10), "login", fmt.Sprintf("2001:db8:1:2::%x", i+1)); !ok {
				t.Fatalf("send %d from one /64 should be allowed", i+1)
			}
		}
		if _, ok := issueFrom("+989127779999", "login", "2001:db8:1:2:ffff::1"); ok {
			t.Error("the 21st send from one /64 was allowed")
		}
		if _, ok := issueFrom("+989127779998", "login", "2001:db8:1:3::1"); !ok {
			t.Error("a different /64 shares the budget of the first")
		}

		// A /24 of IPv4 addresses has a looser shared budget (100): 20 hosts
		// of 20 sends each would be 400.
		sent := 0
		for host := 1; host <= 10 && sent < 101; host++ {
			for i := 0; i < 20 && sent < 101; i++ {
				if _, ok := issueFrom(fmt.Sprintf("+98913%02d%05d", host, i), "login", fmt.Sprintf("192.0.2.%d", host)); !ok {
					break
				}
				sent++
			}
		}
		if sent != 100 {
			t.Errorf("one /24 sent %d messages, want exactly 100", sent)
		}

		// No address, no message: there is no shared "unknown" bucket.
		if _, ok := issueFrom("+989129990001", "login", ""); ok {
			t.Error("a request with no IP was allowed")
		}
		if n := counter("ip", "unknown"); n != 0 {
			t.Errorf("an 'unknown' IP bucket exists with %d", n)
		}

		// Input the table would reject is refused up front, with no error (an
		// error would put the row, code hash included, into the server log).
		if _, ok := issueFrom("0912 not a phone", "login", "198.51.100.9"); ok {
			t.Error("an unnormalised phone was accepted")
		}
		if _, ok := issueFrom("+989129990002", "frobnicate", "198.51.100.9"); ok {
			t.Error("an unknown purpose was accepted")
		}

		// The global cap is a hard stop for everybody, and refused requests
		// leave it where it is.
		if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
			t.Fatal(err)
		}
		day := "(now() AT TIME ZONE 'Asia/Tehran')::date"
		if _, err := tx.Exec(h.ctx, "UPDATE ctrlz.sms_counters SET count = 5000 WHERE scope = 'global' AND key = 'all' AND day = "+day); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
			t.Fatal(err)
		}
		if _, ok := issueFrom("+989129990003", "login", "198.51.100.77"); ok {
			t.Error("a send above the global cap was allowed")
		}
		if g := counter("global", "all"); g != 5000 {
			t.Errorf("global counter %d after a refused send", g)
		}
		if n := counter("phone", "+989129990003"); n != 0 {
			t.Errorf("a send refused by the global cap charged its phone: %d", n)
		}
	})
}

// TestMigratorSeesNothing is spec test 25. The migrator owns the tables and
// has no policy, so under FORCE RLS it reads nothing and writes nothing. That
// is also what makes a backfill silently touch zero rows, which the migration
// pattern of section 11 turns into a failure by declaring the expected count.
func TestMigratorSeesNothing(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	conn, err := h.db.Conn(h.ctx, "ctrlz_migrator")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(h.ctx)
	for _, tbl := range h.fx.Tables.Tenant {
		var n int
		if err := conn.QueryRow(h.ctx, "SELECT count(*) FROM "+ident(tbl)).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tbl, err)
		}
		if n != 0 {
			t.Errorf("the migrator sees %d rows in %s", n, tbl)
		}
	}
	if _, err := conn.Exec(h.ctx, "INSERT INTO ctrlz.tenants (id) VALUES (gen_random_uuid())"); !isRLSViolation(err) {
		t.Errorf("the migrator inserted a tenant: %v", err)
	}

	// The backfill pattern: iterate the tenants as ctrlz_backfill, set the
	// setting per tenant, update, and check the total against the declared count.
	backfill := func(set bool) error {
		tx, err := conn.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(h.ctx)
		for _, stmt := range []string{
			"GRANT SELECT ON ctrlz.tenants TO ctrlz_backfill",
			"GRANT SELECT, UPDATE ON ctrlz.users TO ctrlz_backfill",
			"SET LOCAL ROLE ctrlz_backfill",
		} {
			if _, err := tx.Exec(h.ctx, stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		setting := "PERFORM pg_catalog.set_config('ctrlz.tenant_id', t.id::text, true);"
		if !set {
			setting = ""
		}
		_, err = tx.Exec(h.ctx, strings.Replace(`
DO $$
DECLARE t record; n integer; total integer := 0; expected integer := 2;
BEGIN
  FOR t IN SELECT id FROM ctrlz.tenants LOOP
    /*SETTING*/
    UPDATE ctrlz.users SET locale = locale;
    GET DIAGNOSTICS n = ROW_COUNT;
    total := total + n;
  END LOOP;
  IF total <> expected THEN
    RAISE EXCEPTION 'backfill touched % rows, expected %', total, expected;
  END IF;
END $$`, "/*SETTING*/", setting, 1))
		return err
	}
	if err := backfill(true); err != nil {
		t.Errorf("a backfill that sets the tenant per tenant failed: %v", err)
	}
	err = backfill(false)
	if err == nil || !strings.Contains(err.Error(), "backfill touched 0 rows, expected 2") {
		t.Errorf("a backfill without the setting must fail on the row count, got: %v", err)
	}
}
