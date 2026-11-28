package catalogtest_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// Spec tests 29 to 39 (docs/specs/p1-auth.md section 16.5): what migration 0011
// added. They go in the catalog test package because they act as the database
// roles and read the tables as the superuser, the way the other behaviour tests
// of this package do.

// denied runs one statement as a role and reports whether Postgres refused it
// for lack of a privilege (SQLSTATE 42501).
func (h *harness) denied(role string, guc *string, sql string, args ...any) bool {
	h.t.Helper()
	refused := false
	h.inTx(h.super, role, guc, func(tx pgx.Tx) {
		_, err := tx.Exec(h.ctx, sql, args...)
		if pe := pgErr(err); pe != nil && pe.Code == "42501" {
			refused = true
		} else if err != nil {
			h.t.Fatalf("%s: expected success or a permission error, got %v", sql, err)
		}
	})
	return refused
}

// asSuper runs fn on the superuser level inside a tx that is currently a service
// role, and returns to the role.
func asSuper(h *harness, tx pgx.Tx, role string, fn func()) {
	h.t.Helper()
	if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
		h.t.Fatal(err)
	}
	fn()
	if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_"+role); err != nil {
		h.t.Fatal(err)
	}
}

// Test 29: the tenant role reads the phone columns and cannot write them, and
// cannot finish a phone change request.
func TestTenantCannotWritePhone(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a := h.A.Tenant.String()
	for _, sql := range []string{
		"UPDATE ctrlz.users SET phone_e164 = '+989129990000' WHERE tenant_id = '" + a + "'",
		"UPDATE ctrlz.users SET phone_verified_at = now() WHERE tenant_id = '" + a + "'",
		"UPDATE ctrlz.phone_change_requests SET completed_at = now() WHERE tenant_id = '" + a + "'",
		"UPDATE ctrlz.phone_change_requests SET expires_at = now() + interval '1 day' WHERE tenant_id = '" + a + "'",
	} {
		if !h.denied("tenant", &a, sql) {
			t.Errorf("the tenant role was allowed: %s", sql)
		}
	}
	h.inTx(h.super, "tenant", &a, func(tx pgx.Tx) {
		for _, q := range []string{"SELECT phone_e164, phone_verified_at FROM ctrlz.users", "SELECT id FROM ctrlz.phone_change_requests"} {
			if n, err := count(h.ctx, tx, "SELECT count(*) FROM ("+q+") x"); err != nil || n != 1 {
				t.Errorf("%s: %d rows, err %v", q, n, err)
			}
		}
	})
}

// Test 30: the tenant role has no privilege of any kind on the tables that only
// ctrlz_fn, the admin or the worker may touch.
func TestTenantHasNoReachToAuthTables(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	for _, tbl := range []string{"auth_tickets", "auth_throttle", "admin_jobs", "sms_outbox", "sms_deliveries", "sms_provider_templates", "sms_gateways"} {
		var cols, whole bool
		if err := h.super.QueryRow(h.ctx, `SELECT has_any_column_privilege('ctrlz_tenant', $1::regclass, 'SELECT, INSERT, UPDATE, REFERENCES'),
  has_table_privilege('ctrlz_tenant', $1::regclass, 'DELETE, TRUNCATE, TRIGGER')`, "ctrlz."+tbl).Scan(&cols, &whole); err != nil {
			t.Fatal(err)
		}
		if cols || whole {
			t.Errorf("ctrlz_tenant has a privilege on %s (column or table level: %v %v)", tbl, cols, whole)
		}
	}
}

// Test 31: the admin's functions, and the separation of the two throttle pairs.
func TestAdminFunctionsAndThrottleSeparation(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	rows, err := h.super.Query(h.ctx, `SELECT p.proname FROM pg_proc p
WHERE p.pronamespace = 'ctrlz_fn'::regnamespace AND has_function_privilege('ctrlz_admin', p.oid, 'EXECUTE') ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	rows.Close()
	// auth_tickets_revoke is here for the re-issue of a one-time password
	// (T-536): it acts on the tenant of the setting WithTenant made. audit_lock is
	// here because the admin role no longer calls pg_advisory_xact_lock itself
	// (db-r14-3); TestNoLoginRoleHoldsTheAuditChainOrWatchesOthers drives it. node_pairs_lock and node_upstreams_lock are the
	// same for the two node constraint triggers, and node_taken_claims is the admin's review of a node's reports (P4 0100).
	want := []string{"admin_account_bootstrap", "admin_account_reset", "admin_account_set_password", "admin_account_totp_enable", "admin_create_user", "admin_one_time_state", "admin_reissue_one_time_password", "admin_revoke_user_sessions", "admin_sms_stats", "admin_throttle_hit", "admin_throttle_refund", "admin_throttle_reset", "admin_totp_replace", "audit_lock", "auth_tickets_revoke", "node_pairs_lock", "node_taken_claims", "node_upstreams_lock"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("ctrlz_admin can execute %v, want %v", got, want)
	}
	for _, fn := range []string{"admin_throttle_hit", "admin_throttle_refund", "admin_throttle_reset", "admin_create_user"} {
		var ok bool
		if err := h.super.QueryRow(h.ctx, `SELECT has_function_privilege('ctrlz_tenant', p.oid, 'EXECUTE') FROM pg_proc p
WHERE p.pronamespace = 'ctrlz_fn'::regnamespace AND p.proname = $1`, fn).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("ctrlz_tenant can execute %s", fn)
		}
	}

	key := "decode(repeat('ab', 32), 'hex')"
	userScopes := []string{"login_phone_net", "login_phone", "login_net", "login_net48", "totp_user", "reauth_user", "otp_verify_net", "invite_net", "profile_unlock", "profile_lock_tenant"}
	adminScopes := []string{"admin_login", "admin_login_user", "admin_login_net", "admin_totp"}
	// One transaction, so the rows the calls write can be read back; it is
	// rolled back at the end. The role changes inside it.
	h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
		setRole := func(role string) {
			if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_"+role); err != nil {
				t.Fatal(err)
			}
		}
		hit := func(role, fn, scope string) (allowed bool) {
			setRole(role)
			if err := tx.QueryRow(h.ctx, fmt.Sprintf("SELECT allowed FROM ctrlz_fn.%s($1, %s, 5, 900)", fn, key), scope).Scan(&allowed); err != nil {
				t.Fatalf("%s(%s): %v", fn, scope, err)
			}
			return
		}
		for _, s := range adminScopes {
			if hit("tenant", "auth_throttle_hit", s) {
				t.Errorf("auth_throttle_hit accepted the admin scope %s", s)
			}
			if !hit("admin", "admin_throttle_hit", s) {
				t.Errorf("admin_throttle_hit refused its own scope %s", s)
			}
		}
		for _, s := range userScopes {
			if hit("admin", "admin_throttle_hit", s) {
				t.Errorf("admin_throttle_hit accepted the user scope %s", s)
			}
			if !hit("tenant", "auth_throttle_hit", s) {
				t.Errorf("auth_throttle_hit refused its own scope %s", s)
			}
		}
		rowCount := func(where string) (n int) {
			asSuper(h, tx, "tenant", func() {
				if err := tx.QueryRow(h.ctx, "SELECT coalesce(sum(count), 0) FROM ctrlz.auth_throttle WHERE "+where).Scan(&n); err != nil {
					t.Fatal(err)
				}
			})
			return
		}
		// Rows exist only for the accepted pairs, one hit each.
		if n := rowCount("key = " + key); n != len(userScopes)+len(adminScopes) {
			t.Errorf("total hits recorded: %d, want %d", n, len(userScopes)+len(adminScopes))
		}
		// The user reset cannot clear an admin key (count stays), the admin reset can.
		setRole("tenant")
		if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.auth_throttle_reset('admin_login', "+key+")"); err != nil {
			t.Fatal(err)
		}
		if n := rowCount("key = " + key + " AND scope = 'admin_login'"); n != 1 {
			t.Errorf("the user reset touched an admin key: count %d", n)
		}
		setRole("admin")
		if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.admin_throttle_reset('admin_login', NULL)"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.admin_throttle_reset('login_net', "+key+")"); err != nil {
			t.Fatal(err)
		}
		if n := rowCount("key = " + key + " AND scope = 'admin_login'"); n != 0 {
			t.Errorf("the admin reset left count %d", n)
		}
		if n := rowCount("key = " + key + " AND scope = 'login_net'"); n != 1 {
			t.Errorf("the admin reset cleared a user key: %d", n)
		}
		// The limit works: the sixth hit inside the window is refused, with a wait.
		setRole("tenant")
		var allowed bool
		var retry int
		for i := 0; i < 6; i++ {
			if err := tx.QueryRow(h.ctx, "SELECT allowed, retry_after_s FROM ctrlz_fn.auth_throttle_hit('totp_user', decode(repeat('cd', 32), 'hex'), 5, 900)").Scan(&allowed, &retry); err != nil {
				t.Fatal(err)
			}
		}
		if allowed || retry < 1 || retry > 900 {
			t.Errorf("sixth hit: allowed %v, retry %d", allowed, retry)
		}
		// A key that is not 32 bytes is refused, not stored.
		if err := tx.QueryRow(h.ctx, "SELECT allowed FROM ctrlz_fn.auth_throttle_hit('totp_user', '\\x01', 5, 900)").Scan(&allowed); err != nil || allowed {
			t.Errorf("short key: allowed %v err %v", allowed, err)
		}
	})
}

// TestThrottleRefundScopeAllowLists is db-r7-2. The two refund functions (0027, 0031) each carry
// the scopes they may touch, and the reset and hit tests above never call them: delete the scope
// line from admin_throttle_refund, or add admin_totp to it, and every other test stays green.
// Each refund gives an attempt back on its own role's refundable scopes with the live epoch and
// on nothing else: not a scope of the other role (the tenant role holds no business with the
// admin counters whose key it might learn), not admin_totp (a code is always examined, so the
// five-guess limit never gets an attempt back), and not an epoch other than the one the hit
// returned.
func TestThrottleRefundScopeAllowLists(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	key := "decode(repeat('ef', 32), 'hex')"
	type scope struct{ name, role, hit, refund string }
	var scopes []scope
	for _, s := range []string{"login_phone_net", "login_phone", "login_net", "login_net48", "totp_user", "reauth_user", "otp_verify_net", "invite_net", "profile_unlock", "profile_lock_tenant"} {
		scopes = append(scopes, scope{s, "tenant", "auth_throttle_hit", "auth_throttle_refund"})
	}
	for _, s := range []string{"admin_login", "admin_login_user", "admin_login_net", "admin_totp"} {
		scopes = append(scopes, scope{s, "admin", "admin_throttle_hit", "admin_throttle_refund"})
	}
	// Scopes whose attempt does no work when the Argon2 gate is busy, and so may be given back.
	refundable := map[string]bool{"admin_totp": false}
	h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
		setRole := func(role string) {
			if _, err := tx.Exec(h.ctx, "RESET ROLE"); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_"+role); err != nil {
				t.Fatal(err)
			}
		}
		count := func(s scope) (n int) {
			asSuper(h, tx, s.role, func() {
				if err := tx.QueryRow(h.ctx, "SELECT count FROM ctrlz.auth_throttle WHERE scope = $1 AND key = "+key, s.name).Scan(&n); err != nil {
					t.Fatal(err)
				}
			})
			return
		}
		epochs := map[string]int64{}
		for _, s := range scopes {
			setRole(s.role)
			var epoch int64
			if err := tx.QueryRow(h.ctx, fmt.Sprintf("SELECT window_epoch FROM ctrlz_fn.%s($1, %s, 5, 900)", s.hit, key), s.name).Scan(&epoch); err != nil {
				t.Fatalf("%s(%s): %v", s.hit, s.name, err)
			}
			epochs[s.name] = epoch
		}
		refund := func(role, fn, name string, epoch int64) {
			t.Helper()
			setRole(role)
			if _, err := tx.Exec(h.ctx, fmt.Sprintf("SELECT ctrlz_fn.%s($1, %s, 900, $2)", fn, key), name, epoch); err != nil {
				t.Fatalf("%s(%s): %v", fn, name, err)
			}
		}
		for _, s := range scopes {
			other, otherFn := "admin", "admin_throttle_refund"
			if s.role == "admin" {
				other, otherFn = "tenant", "auth_throttle_refund"
			}
			// Another role's refund, with the right epoch.
			refund(other, otherFn, s.name, epochs[s.name])
			if n := count(s); n != 1 {
				t.Errorf("%s of ctrlz_%s gave back an attempt on %s: count %d", otherFn, other, s.name, n)
			}
			// Its own, with an epoch that is not the one the hit returned.
			for _, e := range []int64{epochs[s.name] + 1, epochs[s.name] - 1} {
				refund(s.role, s.refund, s.name, e)
				if n := count(s); n != 1 {
					t.Errorf("%s accepted epoch %d (the line is at %d) on %s: count %d", s.refund, e, epochs[s.name], s.name, n)
				}
			}
		}
		// The control: the refund works where it is meant to, so the no-ops above are the lists
		// and not a call that never reaches the row.
		for _, s := range scopes {
			want := 0
			if ok, listed := refundable[s.name]; listed && !ok {
				want = 1 // admin_totp
			}
			refund(s.role, s.refund, s.name, epochs[s.name])
			if n := count(s); n != want {
				t.Errorf("%s on %s with the live epoch: count %d, want %d", s.refund, s.name, n, want)
			}
		}
	})
}

// counterRows reads today's sms_counters rows as "scope|key=count".
func counterRows(h *harness, tx pgx.Tx, role string) map[string]int {
	h.t.Helper()
	out := map[string]int{}
	asSuper(h, tx, role, func() {
		rows, err := tx.Query(h.ctx, `SELECT scope, key, count FROM ctrlz.sms_counters WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date`)
		if err != nil {
			h.t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var s, k string
			var c int
			if err := rows.Scan(&s, &k, &c); err != nil {
				h.t.Fatal(err)
			}
			out[s+"|"+k] = c
		}
	})
	return out
}

func wantKeys(keys []sms.CounterKey) map[string]int {
	out := map[string]int{}
	for _, k := range keys {
		out[k.Scope+"|"+k.Key] = 1
	}
	return out
}

func sameCounters(got, want map[string]int) string {
	var g, w []string
	for k, v := range got {
		g = append(g, fmt.Sprintf("%s=%d", k, v))
	}
	for k, v := range want {
		w = append(w, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, ",") == strings.Join(w, ",") {
		return ""
	}
	return fmt.Sprintf("counters are\n  %v\nwant\n  %v", g, w)
}

// Test 32: auth_otp_issue. The decoy, the caps, the soft breaker, the key of a
// known device, the /48 key, and the keys internal/sms builds for the refund.
func TestOTPIssueModes(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	issue := func(tx pgx.Tx, phone, ip string, decoy, trusted bool) (allowed bool) {
		var delivery any
		if !decoy {
			delivery = []byte{0x0a}
		}
		var id *uuid.UUID
		if err := tx.QueryRow(h.ctx, "SELECT id, allowed FROM ctrlz_fn.auth_otp_issue($1, 'login', '\\x0a0b', $2, $3::inet, $4)",
			phone, delivery, ip, trusted).Scan(&id, &allowed); err != nil {
			t.Fatal(err)
		}
		if allowed != (id != nil) {
			t.Errorf("allowed %v with id %v", allowed, id)
		}
		return
	}
	setSettings := func(tx pgx.Tx, set string) {
		asSuper(h, tx, "tenant", func() {
			if _, err := tx.Exec(h.ctx, "UPDATE ctrlz.system_settings SET "+set); err != nil {
				t.Fatal(err)
			}
		})
	}
	setGlobal := func(tx pgx.Tx, n int) {
		asSuper(h, tx, "tenant", func() {
			if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', LEAST($1::int, 1))`, n); err != nil {
				t.Fatal(err)
			}
			// A new row starts at zero or one (migration 0040); the cap tests need it higher, which
			// is an increase and always allowed.
			if _, err := tx.Exec(h.ctx, `UPDATE ctrlz.sms_counters SET count = $1 WHERE scope = 'global' AND key = 'all' AND day = (now() AT TIME ZONE 'Asia/Tehran')::date AND count < $1`, n); err != nil {
				t.Fatal(err)
			}
		})
	}

	// The keys each case wrote equal the keys sms.OTPCounterKeys lists.
	cases := []struct {
		name           string
		phone, ip      string
		decoy, trusted bool
	}{
		{"real, IPv4", "+989125550101", "198.51.100.7", false, false},
		{"decoy, IPv4", "+989125550102", "198.51.100.8", true, false},
		{"real, known device", "+989125550103", "198.51.100.9", false, true},
		{"real, IPv6", "+989125550104", "2001:db8:1:2:3:4:5:6", false, false},
		{"decoy, IPv6", "+989125550105", "2001:db8:aaaa:bbbb::1", true, false},
		{"real, IPv4-mapped IPv6", "+989125550106", "::ffff:198.51.100.77", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
				if !issue(tx, c.phone, c.ip, c.decoy, c.trusted) {
					t.Fatal("refused")
				}
				addr := netip.MustParseAddr(c.ip).Unmap()
				got := counterRows(h, tx, "tenant")
				// The global count is sixteen shard rows since 0055 (db-r18-2); the keys of the request are
				// compared with the shards folded into the one world-wide counter.
				for k, n := range got {
					if strings.HasPrefix(k, "global|all:") {
						got["global|all"] += n
						delete(got, k)
					}
				}
				if c.decoy {
					// A decoy probes and locks a shard of the global count like a real request and adds nothing
					// to it (0052, 0055, tenant-r16-11): a row may exist, at zero, and counts nothing.
					if n, ok := got["global|all"]; ok && n == 0 {
						delete(got, "global|all")
					}
				}
				if msg := sameCounters(got, wantKeys(sms.OTPCounterKeys(c.phone, addr, c.trusted, c.decoy))); msg != "" {
					t.Error(msg)
				}
				var trusted bool
				asSuper(h, tx, "tenant", func() {
					if err := tx.QueryRow(h.ctx, "SELECT trusted FROM ctrlz.otp_challenges WHERE phone_e164 = $1", c.phone).Scan(&trusted); err != nil {
						t.Fatal(err)
					}
				})
				if trusted != c.trusted {
					t.Errorf("stored trusted %v, want %v", trusted, c.trusted)
				}
			})
		})
	}

	t.Run("a decoy leaves the global counter alone", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			issue(tx, "+989125550111", "198.51.100.20", true, false)
			if n := counterRows(h, tx, "tenant")["global|all"]; n != 0 {
				t.Errorf("a decoy bumped the global counter to %d", n)
			}
		})
	})

	t.Run("a full global cap refuses a decoy and a real request alike, moving nothing", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			setSettings(tx, "otp_cap_global = 3")
			setGlobal(tx, 3)
			before := counterRows(h, tx, "tenant")
			for i, decoy := range []bool{true, false} {
				for _, trusted := range []bool{false, true} {
					if issue(tx, fmt.Sprintf("+98912555012%d", i), "198.51.100.30", decoy, trusted) {
						t.Errorf("decoy=%v trusted=%v passed a full cap", decoy, trusted)
					}
				}
			}
			if msg := sameCounters(counterRows(h, tx, "tenant"), before); msg != "" {
				t.Errorf("a refusal moved a counter: %s", msg)
			}
		})
	})

	t.Run("the money cap refuses both too", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			setSettings(tx, "sms_cost_cap_daily = 100")
			asSuper(h, tx, "tenant", func() {
				if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.sms_counters (day, scope, key, count, cost) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 1, 100)`); err != nil {
					t.Fatal(err)
				}
			})
			for _, decoy := range []bool{true, false} {
				if issue(tx, "+989125550131", "198.51.100.31", decoy, true) {
					t.Errorf("decoy=%v passed the money cap", decoy)
				}
			}
		})
	})

	t.Run("under the soft limit a known device passes and a stranger does not", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			setSettings(tx, "otp_cap_global = 10, otp_soft_pct = 80")
			setGlobal(tx, 8)
			if issue(tx, "+989125550141", "198.51.100.41", false, false) {
				t.Error("an unknown device passed the soft limit")
			}
			if issue(tx, "+989125550142", "198.51.100.42", true, false) {
				t.Error("a decoy from an unknown device passed the soft limit")
			}
			if !issue(tx, "+989125550143", "198.51.100.43", false, true) {
				t.Error("a known device was refused under the hard cap")
			}
		})
	})

	t.Run("a known device is not held back by a spent shared phone cap", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			setSettings(tx, "otp_cap_phone_net = 1, otp_cap_phone = 1, otp_cooldown_s = 10")
			phone := "+989125550151"
			if !issue(tx, phone, "198.51.100.51", false, false) {
				t.Fatal("first request refused")
			}
			// A stranger from another network has spent nothing of the shared
			// keys but the phone key, which is now full.
			asSuper(h, tx, "tenant", func() {
				if _, err := tx.Exec(h.ctx, "UPDATE ctrlz.otp_challenges SET created_at = now() - interval '1 hour' WHERE phone_e164 = $1", phone); err != nil {
					t.Fatal(err)
				}
			})
			if issue(tx, phone, "203.0.113.51", false, false) {
				t.Error("a stranger passed a full phone cap")
			}
			if !issue(tx, phone, "203.0.113.52", false, true) {
				t.Error("the owner's known device was refused")
			}
		})
	})

	t.Run("an IPv6 /48 is capped across its /64s", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			setSettings(tx, "otp_cap_net48 = 2")
			if !issue(tx, "+989125550161", "2001:db8:5:1::1", false, false) || !issue(tx, "+989125550162", "2001:db8:5:2::1", false, false) {
				t.Fatal("refused under the cap")
			}
			if issue(tx, "+989125550163", "2001:db8:5:3::1", false, false) {
				t.Error("a third /64 of one /48 passed a cap of 2")
			}
		})
	})

	t.Run("the cooldown still serialises one phone and purpose", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			if !issue(tx, "+989125550171", "198.51.100.71", false, false) {
				t.Fatal("first refused")
			}
			if issue(tx, "+989125550171", "198.51.100.72", false, false) {
				t.Error("a second request inside the cooldown passed")
			}
		})
	})
}

// Test 33: auth_phone_change_complete.
func TestPhoneChangeComplete(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aGUC, bGUC := a.Tenant.String(), b.Tenant.String()
	const newPhone = "+989127770001"

	type req struct{ id, oldOTP, newOTP uuid.UUID }
	// newReq makes a request of tenant A made `age` ago, expiring in `ttl`.
	newReq := func(tx pgx.Tx, to string, age, ttl time.Duration) req {
		r := req{uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())}
		asSuper(h, tx, "tenant", func() {
			if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.phone_change_requests (tenant_id, id, user_id, new_phone_e164, old_otp_id, new_otp_id, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, now() - $7::interval, now() + $8::interval)`,
				a.Tenant, r.id, a.User, to, r.oldOTP, r.newOTP, fmt.Sprintf("%d milliseconds", age.Milliseconds()), fmt.Sprintf("%d milliseconds", ttl.Milliseconds())); err != nil {
				t.Fatal(err)
			}
		})
		return r
	}
	otp := func(tx pgx.Tx, id uuid.UUID, phone, purpose string, consumedAgo time.Duration) {
		asSuper(h, tx, "tenant", func() {
			// The tenant stamp is what auth_otp_issue writes for an account's codes (question 15): the function under test
			// reads the challenge as ctrlz_scoped, which sees only the rows of the tenant of the setting.
			if _, err := tx.Exec(h.ctx, `INSERT INTO ctrlz.otp_challenges (id, phone_e164, purpose, code_hash, expires_at, consumed_at, tenant_id)
VALUES ($1, $2, $3, '\x01', now() + interval '5 minutes', now() - $4::interval, $5)`, id, phone, purpose, fmt.Sprintf("%d milliseconds", consumedAgo.Milliseconds()), a.Tenant); err != nil {
				t.Fatal(err)
			}
		})
	}
	complete := func(tx pgx.Tx, id uuid.UUID) (outcome string, rows int) {
		r, err := tx.Query(h.ctx, "SELECT outcome FROM ctrlz_fn.auth_phone_change_complete($1)", id)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		for r.Next() {
			if err := r.Scan(&outcome); err != nil {
				t.Fatal(err)
			}
			rows++
		}
		return
	}
	state := func(tx pgx.Tx, id uuid.UUID) (phone string, completed bool) {
		asSuper(h, tx, "tenant", func() {
			if err := tx.QueryRow(h.ctx, "SELECT phone_e164 FROM ctrlz.users WHERE id = $1", a.User).Scan(&phone); err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRow(h.ctx, "SELECT completed_at IS NOT NULL FROM ctrlz.phone_change_requests WHERE id = $1", id).Scan(&completed); err != nil {
				t.Fatal(err)
			}
		})
		return
	}
	min := time.Minute
	ok := func(name string, mk func(tx pgx.Tx) req, guc *string, want string) {
		t.Run(name, func(t *testing.T) {
			h.inTx(h.super, "tenant", guc, func(tx pgx.Tx) {
				r := mk(tx)
				got, rows := complete(tx, r.id)
				if want == "" {
					if rows != 0 {
						t.Errorf("returned a row (%q), want none", got)
					}
				} else if got != want {
					t.Errorf("outcome %q, want %q", got, want)
				}
				phone, done := state(tx, r.id)
				if want != "ok" && (phone != a.Phone || done) {
					t.Errorf("a refusal changed state: phone %s completed %v", phone, done)
				}
				if want == "ok" {
					if phone != newPhone || !done {
						t.Errorf("success left phone %s completed %v", phone, done)
					}
					if again, _ := complete(tx, r.id); again != "invalid" {
						t.Errorf("a second completion gave %q", again)
					}
				}
			})
		})
	}
	good := func(tx pgx.Tx) req {
		r := newReq(tx, newPhone, 2*min, 3*min)
		otp(tx, r.oldOTP, a.Phone, "phone_old", min)
		otp(tx, r.newOTP, newPhone, "phone_new", min)
		return r
	}
	ok("no setting gives no row", good, nil, "")
	ok("a request of another tenant", good, &bGUC, "invalid")
	ok("both codes valid", good, &aGUC, "ok")
	ok("no code consumed", func(tx pgx.Tx) req { return newReq(tx, newPhone, 2*min, 3*min) }, &aGUC, "invalid")
	ok("a code of another purpose", func(tx pgx.Tx) req {
		r := newReq(tx, newPhone, 2*min, 3*min)
		otp(tx, r.oldOTP, a.Phone, "phone_old", min)
		otp(tx, r.newOTP, newPhone, "login", min)
		return r
	}, &aGUC, "invalid")
	ok("a code for the wrong number", func(tx pgx.Tx) req {
		r := newReq(tx, newPhone, 2*min, 3*min)
		otp(tx, r.oldOTP, a.Phone, "phone_old", min)
		otp(tx, r.newOTP, "+989127770002", "phone_new", min)
		return r
	}, &aGUC, "invalid")
	ok("a code consumed before the request was made", func(tx pgx.Tx) req {
		r := newReq(tx, newPhone, 2*min, 3*min)
		otp(tx, r.oldOTP, a.Phone, "phone_old", 3*min)
		otp(tx, r.newOTP, newPhone, "phone_new", min)
		return r
	}, &aGUC, "invalid")
	ok("a code consumed more than ten minutes ago", func(tx pgx.Tx) req {
		r := newReq(tx, newPhone, 14*min, 1*min)
		otp(tx, r.oldOTP, a.Phone, "phone_old", 11*min)
		otp(tx, r.newOTP, newPhone, "phone_new", min)
		return r
	}, &aGUC, "invalid")
	ok("an expired request", func(tx pgx.Tx) req {
		r := newReq(tx, newPhone, 6*min, -1*min)
		otp(tx, r.oldOTP, a.Phone, "phone_old", 2*min)
		otp(tx, r.newOTP, newPhone, "phone_new", 2*min)
		return r
	}, &aGUC, "invalid")
	ok("a number that belongs to someone else", func(tx pgx.Tx) req {
		r := newReq(tx, b.Phone, 2*min, 3*min)
		otp(tx, r.oldOTP, a.Phone, "phone_old", min)
		otp(tx, r.newOTP, b.Phone, "phone_new", min)
		return r
	}, &aGUC, "unavailable")
}

// Test 34: a ticket is single use under a race, tickets_revoke is scoped to the
// user and the tenant, and a ticket can be read five times.
func TestTicketsRaceRevokeAndAttempts(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	a, b := h.A, h.B
	aGUC, bGUC := a.Tenant.String(), b.Tenant.String()
	put := func(hexByte string, kind string, tenant, user uuid.UUID) {
		t.Helper()
		if _, err := h.super.Exec(h.ctx, `INSERT INTO ctrlz.auth_tickets (token_hash, kind, subject_tenant, subject_user, expires_at)
VALUES (decode(repeat($1, 32), 'hex'), $2, $3, $4, now() + interval '5 minutes')`, hexByte, kind, tenant, user); err != nil {
			t.Fatal(err)
		}
	}
	consumed := func(hexByte string) (c bool) {
		if err := h.super.QueryRow(h.ctx, "SELECT consumed_at IS NOT NULL FROM ctrlz.auth_tickets WHERE token_hash = decode(repeat($1, 32), 'hex')", hexByte).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return
	}

	t.Run("two connections take one ticket, one row", func(t *testing.T) {
		put("11", "mfa", a.Tenant, a.User)
		conn2 := h.fresh()
		tx1, err := h.super.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx1.Rollback(context.Background())
		tx2, err := conn2.Begin(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx2.Rollback(context.Background())
		for _, tx := range []pgx.Tx{tx1, tx2} {
			if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_tenant"); err != nil {
				t.Fatal(err)
			}
		}
		take := func(tx pgx.Tx) int {
			rows, err := tx.Query(h.ctx, "SELECT subject_user FROM ctrlz_fn.auth_ticket_take(decode(repeat('11', 32), 'hex'), 'mfa')")
			if err != nil {
				t.Error(err)
				return -1
			}
			defer rows.Close()
			n := 0
			for rows.Next() {
				n++
			}
			return n
		}
		if n := take(tx1); n != 1 {
			t.Fatalf("the first take returned %d rows", n)
		}
		var wg sync.WaitGroup
		var second int
		wg.Add(1)
		go func() { defer wg.Done(); second = take(tx2) }()
		awaitLockWaiters(t, h.ctx, h.fresh(), 1) // the second UPDATE is parked on the row lock
		if err := tx1.Commit(h.ctx); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if second != 0 {
			t.Errorf("the second take returned %d rows after the first committed", second)
		}
		// Later takes find nothing, and a wrong kind never matches.
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			if n := take(tx); n != 0 {
				t.Errorf("a consumed ticket was taken again (%d rows)", n)
			}
		})
	})

	t.Run("a ticket of another kind is not taken", func(t *testing.T) {
		put("12", "mfa", a.Tenant, a.User)
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			if n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz_fn.auth_ticket_take(decode(repeat('12', 32), 'hex'), 'reset')"); err != nil || n != 0 {
				t.Errorf("wrong kind: %d rows, err %v", n, err)
			}
			if n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz_fn.auth_ticket_take(decode(repeat('12', 32), 'hex'), 'mfa')"); err != nil || n != 1 {
				t.Errorf("right kind: %d rows, err %v", n, err)
			}
		})
	})

	t.Run("peek spends an attempt and stops after five", func(t *testing.T) {
		put("13", "mfa", a.Tenant, a.User)
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			for i := 1; i <= 7; i++ {
				n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz_fn.auth_ticket_peek(decode(repeat('13', 32), 'hex'), 'mfa')")
				if err != nil {
					t.Fatal(err)
				}
				if want := map[bool]int{true: 1, false: 0}[i <= 5]; n != want {
					t.Errorf("peek %d returned %d rows, want %d", i, n, want)
				}
			}
		})
	})

	t.Run("tickets_revoke closes the user's mfa and reset tickets in the caller's tenant only", func(t *testing.T) {
		put("21", "mfa", a.Tenant, a.User)
		put("22", "reset", a.Tenant, a.User)
		put("23", "passkey_login", a.Tenant, a.User) // another kind
		put("24", "mfa", b.Tenant, b.User)           // another user and tenant
		otherUser := uuid.Must(uuid.NewV7())
		put("25", "mfa", a.Tenant, otherUser) // another user of the same tenant
		// B's setting naming A's user changes nothing of A's.
		h.inTx(h.super, "tenant", &bGUC, func(tx pgx.Tx) {
			if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.auth_tickets_revoke($1)", a.User); err != nil {
				t.Fatal(err)
			}
			asSuper(h, tx, "tenant", func() {
				for _, k := range []string{"21", "22"} {
					if consumed(k) {
						t.Errorf("tenant B closed tenant A's ticket %s", k)
					}
				}
			})
		})
		// No setting changes nothing either.
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.auth_tickets_revoke($1)", a.User); err != nil {
				t.Fatal(err)
			}
			asSuper(h, tx, "tenant", func() {
				if consumed("21") {
					t.Error("a call with no tenant closed a ticket")
				}
			})
		})
		h.inTx(h.super, "tenant", &aGUC, func(tx pgx.Tx) {
			if _, err := tx.Exec(h.ctx, "SELECT ctrlz_fn.auth_tickets_revoke($1)", a.User); err != nil {
				t.Fatal(err)
			}
			asSuper(h, tx, "tenant", func() {
				for k, want := range map[string]bool{"21": true, "22": true, "23": false, "24": false, "25": false} {
					if consumed(k) != want {
						t.Errorf("ticket %s consumed=%v, want %v", k, !want, want)
					}
				}
			})
		})
	})

	t.Run("a ticket lives at most ten minutes", func(t *testing.T) {
		h.inTx(h.super, "tenant", nil, func(tx pgx.Tx) {
			if n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz_fn.auth_ticket_put(decode(repeat('31', 32), 'hex'), 'mfa', NULL, NULL, false, NULL, NULL, 99999, NULL)"); err != nil || n != 1 {
				t.Fatalf("put: %d rows, err %v", n, err)
			}
			asSuper(h, tx, "tenant", func() {
				var secs float64
				if err := tx.QueryRow(h.ctx, "SELECT extract(epoch FROM expires_at - created_at) FROM ctrlz.auth_tickets WHERE token_hash = decode(repeat('31', 32), 'hex')").Scan(&secs); err != nil || secs > 600 {
					t.Errorf("ticket lifetime %v seconds, err %v", secs, err)
				}
			})
		})
	})
}

// Test 35: the tenant role cannot create a user the admin way.
func TestTenantCannotCallAdminCreateUser(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	if !h.denied("tenant", nil, "SELECT * FROM ctrlz_fn.admin_create_user('+989121119999', 'hash', 'fa')") {
		t.Error("ctrlz_tenant ran admin_create_user")
	}
	// The admin can, and the result is as the spec says.
	h.inTx(h.super, "admin", nil, func(tx pgx.Tx) {
		var tenant, user uuid.UUID
		if err := tx.QueryRow(h.ctx, "SELECT tenant_id, user_id FROM ctrlz_fn.admin_create_user('+989121119999', 'hash', 'en')").Scan(&tenant, &user); err != nil {
			t.Fatal(err)
		}
		asSuper(h, tx, "admin", func() {
			var mustReset bool
			var verified *time.Time
			var expires time.Time
			var locale string
			if err := tx.QueryRow(h.ctx, "SELECT must_reset, phone_verified_at, password_expires_at, locale FROM ctrlz.users WHERE id = $1", user).Scan(&mustReset, &verified, &expires, &locale); err != nil {
				t.Fatal(err)
			}
			if !mustReset || verified != nil || locale != "en" || time.Until(expires) < 71*time.Hour || time.Until(expires) > 73*time.Hour {
				t.Errorf("created user: must_reset %v verified %v expires %v locale %s", mustReset, verified, expires, locale)
			}
			if n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz.tenant_entitlements WHERE tenant_id = $1", tenant); err != nil || n != 1 {
				t.Errorf("entitlements row: %d err %v", n, err)
			}
		})
		// A taken phone is an empty result, and creates nothing.
		if n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz_fn.admin_create_user($1, 'hash', 'fa')", h.A.Phone); err != nil || n != 0 {
			t.Errorf("taken phone: %d rows, err %v", n, err)
		}
	})
}

// Test 36: the delivery log keeps no phone number and no text.
func TestDeliveryLogHasNoPhoneOrText(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	rows, err := h.super.Query(h.ctx, `SELECT attname FROM pg_attribute
WHERE attrelid = 'ctrlz.sms_deliveries'::regclass AND attnum > 0 AND NOT attisdropped
  AND (attname ILIKE '%phone%' OR attname ILIKE '%text%' OR attname ILIKE '%body%' OR attname ILIKE '%mobile%' OR attname ILIKE '%number%')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		t.Errorf("sms_deliveries has the column %s", n)
	}
}

// declaredLostCT is a sealed-looking seed whose header names the key: "CZ", format
// version 1, the key number in two bytes, then filler. The function reads only the
// header (it cannot open the seed), so this is what it sees in the column.
func declaredLostCT(key int) string {
	return fmt.Sprintf(`decode('435a01%04x' || repeat('00', 40), 'hex')`, key)
}

// Test 38: `ctrlz declare-lost user_totp` runs as ctrlz_keytool under a tenant
// setting and reaches that tenant only, clears only seeds sealed under the named
// key, and leaves a notice and an audit row behind in the same statement (review
// round 3, db-r3-1 and db-r3-5). ctrlz_admin and ctrlz_worker cannot call it.
func TestDeclareLostRunsAsKeytool(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	// A's user is sealed under key 1, B's under key 1 too, so a wrong tenant would show.
	for _, ids := range []struct{ tenant, user uuid.UUID }{{h.A.Tenant, h.A.User}, {h.B.Tenant, h.B.User}} {
		if _, err := h.super.Exec(h.ctx, `UPDATE ctrlz.users SET totp_secret_ct = `+declaredLostCT(1)+`, totp_enabled_at = now(), totp_last_step = 7 WHERE tenant_id = $1 AND id = $2`, ids.tenant, ids.user); err != nil {
			t.Fatal(err)
		}
	}
	aGUC := h.A.Tenant.String()
	counts := func(tx pgx.Tx, tenant uuid.UUID) (notices, audits int) {
		var err error
		asSuper(h, tx, "keytool", func() {
			if notices, err = count(h.ctx, tx, "SELECT count(*) FROM ctrlz.notifications WHERE kind = 'totp_lost' AND tenant_id = '"+tenant.String()+"'"); err != nil {
				t.Fatal(err)
			}
			if audits, err = count(h.ctx, tx, "SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = 'totp.declared_lost' AND params->>'key_number' = '1' AND tenant_id = '"+tenant.String()+"'"); err != nil {
				t.Fatal(err)
			}
		})
		return
	}
	// The function takes the seeds the tool proved lost (round 13, admin-r13-3): the user ids and the
	// ciphertexts it read. The ciphertext here is the one planted above, so it is rebuilt from the key.
	seedOf := func(key int) []byte {
		b, err := hex.DecodeString(fmt.Sprintf("435a01%04x", key) + strings.Repeat("00", 40))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	callWith := func(tx pgx.Tx, key any, users []uuid.UUID, cts [][]byte) int {
		var n int
		if err := tx.QueryRow(h.ctx, "SELECT ctrlz_fn.keytool_totp_declare_lost($1, $2, $3)", key, users, cts).Scan(&n); err != nil {
			t.Fatalf("declare-lost(%v): %v", key, err)
		}
		return n
	}
	call := func(tx pgx.Tx, key any) int {
		return callWith(tx, key, []uuid.UUID{h.A.User}, [][]byte{seedOf(1)})
	}
	h.inTx(h.super, "keytool", nil, func(tx pgx.Tx) {
		if n := call(tx, 1); n != 0 {
			t.Errorf("without a tenant setting: cleared %d, want 0", n)
		}
	})
	h.inTx(h.super, "keytool", &aGUC, func(tx pgx.Tx) {
		// A key number that no seed names clears nothing and writes nothing: after a
		// rotation to key 2, "--key-number 1" is the only number that names these seeds.
		for _, key := range []any{2, 0, 65536, nil} {
			if n := call(tx, key); n != 0 {
				t.Errorf("key %v: cleared %d, want 0", key, n)
			}
		}
		if notices, audits := counts(tx, h.A.Tenant); notices != 0 || audits != 0 {
			t.Errorf("a call that cleared nothing left %d notices and %d audit rows", notices, audits)
		}
		// The decision is the caller's list, never the number (admin-r13-3): a seed that is not
		// listed, a listed one whose ciphertext is not what the row holds (it was enrolled again
		// meanwhile), a list of unequal lengths, an empty one, and another tenant's user all clear
		// nothing, although every one of those rows names key 1.
		other := seedOf(1)
		other[len(other)-1] = 1
		for name, c := range map[string]struct {
			users []uuid.UUID
			cts   [][]byte
		}{
			"nothing listed":          {nil, nil},
			"a changed ciphertext":    {[]uuid.UUID{h.A.User}, [][]byte{other}},
			"unequal lists":           {[]uuid.UUID{h.A.User, h.A.User}, [][]byte{seedOf(1)}},
			"another tenant's user":   {[]uuid.UUID{h.B.User}, [][]byte{seedOf(1)}},
			"the number is not named": {[]uuid.UUID{h.A.User}, [][]byte{seedOf(2)}},
		} {
			if n := callWith(tx, 1, c.users, c.cts); n != 0 {
				t.Errorf("%s: cleared %d, want 0", name, n)
			}
		}
		if n := call(tx, 1); n != 1 {
			t.Fatalf("declare-lost: cleared %d, want 1", n)
		}
		// A second call finds nothing left to clear, and adds nothing.
		if n := call(tx, 1); n != 0 {
			t.Fatalf("declare-lost again: cleared %d, want 0", n)
		}
		if notices, audits := counts(tx, h.A.Tenant); notices != 1 || audits != 1 {
			t.Errorf("tenant A: %d notices and %d audit rows, want 1 and 1", notices, audits)
		}
		if notices, audits := counts(tx, h.B.Tenant); notices != 0 || audits != 0 {
			t.Errorf("tenant B was written to: %d notices, %d audit rows", notices, audits)
		}
		asSuper(h, tx, "keytool", func() {
			for _, c := range []struct {
				name    string
				user    uuid.UUID
				cleared bool
			}{{"A", h.A.User, true}, {"B", h.B.User, false}} {
				var secret []byte
				var enabled *time.Time
				var step *int64
				if err := tx.QueryRow(h.ctx, "SELECT totp_secret_ct, totp_enabled_at, totp_last_step FROM ctrlz.users WHERE id = $1", c.user).Scan(&secret, &enabled, &step); err != nil {
					t.Fatal(err)
				}
				if got := secret == nil && enabled == nil && step == nil; got != c.cleared {
					t.Errorf("tenant %s: cleared=%v, want %v", c.name, got, c.cleared)
				}
			}
			// Recovery codes are hashes that need no key; they stay (8.5).
			if n, err := count(h.ctx, tx, "SELECT count(*) FROM ctrlz.recovery_codes"); err != nil || n != 2 {
				t.Errorf("recovery codes: %d err %v, want both tenants' codes to stay", n, err)
			}
		})
	})
}

// Test 39: auth_user_flags answers for the caller's tenant only.
func TestUserFlags(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	aGUC, bGUC := h.A.Tenant.String(), h.B.Tenant.String()
	if _, err := h.super.Exec(h.ctx, "UPDATE ctrlz.users SET password_hash = NULL WHERE id = $1", h.B.User); err != nil {
		t.Fatal(err)
	}
	flags := func(guc *string, user uuid.UUID) (rows int, has bool) {
		h.inTx(h.super, "tenant", guc, func(tx pgx.Tx) {
			r, err := tx.Query(h.ctx, "SELECT has_password FROM ctrlz_fn.auth_user_flags($1)", user)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			for r.Next() {
				rows++
				if err := r.Scan(&has); err != nil {
					t.Fatal(err)
				}
			}
		})
		return
	}
	if rows, has := flags(&aGUC, h.A.User); rows != 1 || !has {
		t.Errorf("A's own flags: %d rows, has_password %v", rows, has)
	}
	if rows, has := flags(&bGUC, h.B.User); rows != 1 || has {
		t.Errorf("B's own flags: %d rows, has_password %v (B has no password)", rows, has)
	}
	if rows, _ := flags(nil, h.A.User); rows != 0 {
		t.Errorf("no setting returned %d rows", rows)
	}
	if rows, _ := flags(&bGUC, h.A.User); rows != 0 {
		t.Errorf("tenant B read A's user: %d rows", rows)
	}
}

// TestAdminBootstrapRefusesAnythingButSerializable is db-r7-1. "Only while there is no admin"
// is INSERT ... WHERE NOT EXISTS, which two READ COMMITTED calls both pass (neither sees the
// other's uncommitted row). The caller was told to run it Serializable and nothing checked, so
// the function refuses the other levels itself: a caller that drops the option fails on its
// first call and never produces a second admin. Two sessions run it concurrently at READ
// COMMITTED and at REPEATABLE READ, none inserts; at SERIALIZABLE exactly one of two overlapping
// calls commits an admin.
func TestAdminBootstrapRefusesAnythingButSerializable(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	adminCount := func(q catalogtest.Querier) (n int) {
		t.Helper()
		if err := q.QueryRow(h.ctx, `SELECT count(*) FROM ctrlz.admin_users`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return
	}
	// The seed made one admin; an empty table is what bootstrap is for.
	h.exec(`DELETE FROM ctrlz.admin_users`)
	call := func(tx pgx.Tx, name string) (id *uuid.UUID, err error) {
		err = tx.QueryRow(h.ctx, `SELECT ctrlz_fn.admin_account_bootstrap($1, 'hash')`, name).Scan(&id)
		return
	}
	// Two sessions, both open before either calls, as the role the console runs as.
	open := func(iso pgx.TxIsoLevel) (pgx.Tx, func()) {
		t.Helper()
		conn := h.fresh()
		tx, err := conn.BeginTx(h.ctx, pgx.TxOptions{IsoLevel: iso})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(h.ctx, "SET LOCAL ROLE ctrlz_admin"); err != nil {
			t.Fatal(err)
		}
		return tx, func() { _ = tx.Rollback(context.Background()) }
	}
	for _, iso := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead} {
		t.Run(string(iso), func(t *testing.T) {
			t1, done1 := open(iso)
			defer done1()
			t2, done2 := open(iso)
			defer done2()
			for i, tx := range []pgx.Tx{t1, t2} {
				if _, err := call(tx, fmt.Sprintf("boot%d", i)); err == nil {
					t.Errorf("session %d: the bootstrap ran at %s", i, iso)
				} else if pe := pgErr(err); pe == nil || pe.Code != "25000" {
					t.Errorf("session %d: want SQLSTATE 25000, got %v", i, err)
				}
			}
		})
	}
	if n := adminCount(h.super); n != 0 {
		t.Fatalf("a refused bootstrap left %d admins", n)
	}

	// Serializable: one wins, and the other either sees the winner (NULL) or is told to retry
	// (40001), never a second admin.
	t1, done1 := open(pgx.Serializable)
	defer done1()
	t2, done2 := open(pgx.Serializable)
	defer done2()
	id1, err := call(t1, "boot1")
	if err != nil || id1 == nil {
		t.Fatalf("the first serializable bootstrap: %v %v", id1, err)
	}
	id2, err2 := call(t2, "boot2")
	committed := 0
	if err2 == nil && id2 != nil {
		if err := t2.Commit(h.ctx); err == nil {
			committed++
		} else if pe := pgErr(err); pe == nil || pe.Code != "40001" {
			t.Fatalf("commit of the second: %v", err)
		}
	} else if err2 != nil {
		if pe := pgErr(err2); pe == nil || pe.Code != "40001" {
			t.Fatalf("the second serializable bootstrap: %v", err2)
		}
	}
	if err := t1.Commit(h.ctx); err == nil {
		committed++
	} else if pe := pgErr(err); pe == nil || pe.Code != "40001" {
		t.Fatalf("commit of the first: %v", err)
	}
	if n := adminCount(h.super); committed > 1 || n != committed {
		t.Fatalf("%d bootstraps committed and %d admins exist; want at most one of each", committed, n)
	}
}
