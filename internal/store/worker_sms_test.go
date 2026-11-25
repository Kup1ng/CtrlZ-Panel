package store_test

import (
	"bytes"
	"crypto/sha256"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

func TestWorkerDrainsOTPsAndRefunds(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	ip := netip.MustParseAddr("198.51.100.77")
	// The seed made an OTP with a sealed code and a decoy; this test counts its own.
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.otp_challenges"); err != nil {
		t.Fatal(err)
	}

	realRow, err := tenant.Auth().OTPIssue(f.ctx, "+989121110031", "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !realRow.Allowed {
		t.Fatal(realRow, err)
	}
	decoy, err := tenant.Auth().OTPIssue(f.ctx, "+989121110032", "login", []byte{1}, nil, ip, false)
	if err != nil || !decoy.Allowed {
		t.Fatal(decoy, err)
	}
	counter := func(scope, key string) int {
		var n int
		// The global count is sixteen shard rows since 0055 (db-r18-2): the counter of the world is their sum.
		_ = super.QueryRow(f.ctx, "SELECT COALESCE(sum(count), 0) FROM ctrlz.sms_counters WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date AND scope = $1 AND (key = $2 OR ($1 = 'global' AND $2 = 'all' AND key LIKE 'all:%'))", scope, key).Scan(&n)
		return n
	}
	if counter("global", "all") != 1 || counter("phone", "+989121110031") != 1 || counter("phone", "+989121110032") != 1 {
		t.Fatal("the counters are not what the issue should have written")
	}

	// The claim returns the real row only, once; a second claim finds it held.
	var claimed []store.OTPDelivery
	f.global(t, worker, func(g store.GlobalTx) {
		var err error
		if claimed, err = g.OTPClaim(10, 3); err != nil {
			t.Fatal(err)
		}
	})
	if len(claimed) != 1 || claimed[0].ID != realRow.ID || claimed[0].Attempts != 1 || string(claimed[0].DeliveryCT) != "sealed" ||
		claimed[0].Phone != "+989121110031" || claimed[0].CreatedAt.IsZero() {
		t.Fatalf("claim: %+v", claimed)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if again, _ := g.OTPClaim(10, 3); len(again) != 0 {
			t.Errorf("a row held by a claim was claimed again: %+v", again)
		}
	})
	// The claim lapses; the next pass counts a second attempt.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() - interval '1 second' WHERE id = $1", realRow.ID); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		again, _ := g.OTPClaim(10, 3)
		if len(again) != 1 || again[0].Attempts != 2 {
			t.Errorf("second pass: %+v", again)
		}
	})

	// A terminal failure: clear the code, log the attempt, refund the world-wide slot.
	keys := sms.OTPCounterKeys("+989121110031", ip, false, false)
	f.global(t, worker, func(g store.GlobalTx) {
		if cleared, err := g.OTPDeliveryClear(realRow.ID); err != nil || !cleared.Yes() {
			t.Fatalf("clear: %v %v", cleared, err)
		}
		// The second clear is not the one that finished the row: it must say so, so
		// the caller does not refund twice.
		if cleared, err := g.OTPDeliveryClear(realRow.ID); err != nil || cleared.Yes() {
			t.Fatalf("a second clear reported success: %v %v", cleared, err)
		}
		if err := g.DeliveryRecord(store.SMSDelivery{Source: "otp", SourceID: realRow.ID, Provider: "sms_ir", TemplateKey: "otp", Outcome: "unreachable", LatencyMS: 6000}); err != nil {
			t.Fatal(err)
		}
		if err := g.CountersRefund(claimed[0].CreatedAt); err != nil {
			t.Fatal(err)
		}
		// A second refund does not go below zero.
		if err := g.CountersRefund(claimed[0].CreatedAt); err != nil {
			t.Fatal(err)
		}
	})
	// Only the global key goes back; every key the issue wrote for a phone stays spent (sms-r6-1).
	for _, k := range keys {
		want := 1 // the real row and the decoy share the address, so an ip key reads 2
		switch k.Scope {
		case "global":
			want = 0
		case "ip":
			want = 2
		}
		if n := counter(k.Scope, k.Key); n != want {
			t.Errorf("%s %s is %d after the refund, want %d", k.Scope, k.Key, n, want)
		}
	}
	if counter("phone", "+989121110032") != 1 {
		t.Error("the refund of one phone touched another")
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if rows, _ := g.OTPClaim(10, 3); len(rows) != 0 {
			t.Errorf("a cleared row was claimed: %+v", rows)
		}
	})

	// An OTP that expired unsent is cleared and refunded by the sweep.
	late, err := tenant.Auth().OTPIssue(f.ctx, "+989121110033", "login", []byte{1}, []byte("sealed"), ip, true)
	if err != nil || !late.Allowed {
		t.Fatal(late, err)
	}
	if counter("phone", "+989121110033|trusted") != 1 {
		t.Fatal("the known device key was not written")
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 second' WHERE id = $1", late.ID); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		n, err := g.OTPExpireUndelivered()
		if err != nil || n != 1 {
			t.Fatalf("OTPExpireUndelivered: %d %v", n, err)
		}
	})
	if counter("global", "all") != 0 || counter("phone", "+989121110033|trusted") != 1 {
		t.Error("the expired row gave back more or less than the global slot")
	}
	var ct []byte
	if err := super.QueryRow(f.ctx, "SELECT delivery_ct FROM ctrlz.otp_challenges WHERE id = $1", late.ID).Scan(&ct); err != nil || ct != nil {
		t.Errorf("the sealed code of an expired row stayed: %v %v", ct, err)
	}

	// Cost: the money counter, and the cap that reads it.
	f.global(t, worker, func(g store.GlobalTx) {
		if w, _ := g.OutboxRetryGate(); !w.Yes() {
			t.Error("a cap that is not set was reached")
		}
	})
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 1500"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if err := g.CountersAddCost("1000.5"); err != nil {
			t.Fatal(err)
		}
		if w, _ := g.OutboxRetryGate(); !w.Yes() {
			t.Error("the cap was reached at 1000.5 of 1500")
		}
		if err := g.CountersAddCost("600"); err != nil {
			t.Fatal(err)
		}
		if w, _ := g.OutboxRetryGate(); w.Yes() {
			t.Error("the cap was not reached at 1600.5 of 1500")
		}
	})
	// And auth_otp_issue honours the money counter the worker wrote.
	if r, _ := tenant.Auth().OTPIssue(f.ctx, "+989121110034", "login", []byte{1}, []byte("x"), netip.MustParseAddr("198.51.100.80"), true); r.Allowed {
		t.Error("an OTP passed the money cap")
	}
}

func TestWorkerOutboxGatewaysAndAlerts(t *testing.T) {
	f := newFixture(t)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)

	// The seed queued an outbox row and made a noop gateway; start from nothing.
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.sms_outbox"); err != nil {
		t.Fatal(err)
	}
	var gw, sentID, failedID uuid.UUID
	f.global(t, admin, func(g store.GlobalTx) {
		var err error
		if gw, err = g.SMSGatewayEnsure(uuid.New(), "sms_ir"); err != nil {
			t.Fatal(err)
		}
		if ok, _ := activate(g, gw, "sms_ir", []byte("sealed"), "1234"); !ok {
			t.Fatal("credentials")
		}
		if ok, err := g.SMSRoutingSet("sms_ir", ""); err != nil || !ok {
			t.Fatal(ok, err)
		}
	})
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	f.global(t, admin, func(g store.GlobalTx) {
		for i, id := range ids {
			if err := g.SMSOutboxInsert(store.NewOutbox{ID: id, Kind: "test", Phone: "+98912111004" + string(rune('0'+i)), TemplateKey: "otp", Locale: "fa", ParamsCT: []byte("ct")}); err != nil {
				t.Fatal(err)
			}
		}
	})
	// The worker sees the gateway with its sealed credentials; the admin's view
	// has no credentials field at all.
	f.global(t, worker, func(g store.GlobalTx) {
		gws, err := g.WorkerGateways()
		// The routed gateway, and the seed's noop row, which is listed because it
		// needs no credentials (a test send may pin it).
		if err != nil || len(gws) != 2 {
			t.Fatalf("WorkerGateways: %+v %v", gws, err)
		}
		var routed *store.WorkerGateway
		for i := range gws {
			if gws[i].Role == "primary" {
				routed = &gws[i]
			}
		}
		if routed == nil || string(routed.CredentialsCT) != "sealed" {
			t.Fatalf("WorkerGateways: %+v", gws)
		}
		items, err := g.OutboxClaim(2)
		if err != nil || len(items) != 2 || items[0].Attempts != 1 || string(items[0].ParamsCT) != "ct" || items[0].GatewayID != uuid.Nil {
			t.Fatalf("OutboxClaim: %+v %v", items, err)
		}
		if again, _ := g.OutboxClaim(5); len(again) != 1 {
			t.Errorf("the claimed rows were claimed again: %d", len(again))
		}
		sentID, failedID = items[0].ID, items[1].ID
		if ok, _ := g.OutboxFinish(items[0].ID, "sent", nil); !ok.Yes() {
			t.Error("finish sent")
		}
		if ok, _ := g.OutboxFinish(items[0].ID, "failed", word("x")); ok.Yes() {
			t.Error("a finished message was finished again")
		}
		if ok, _ := g.OutboxFinish(items[1].ID, "failed", word("cap")); !ok.Yes() {
			t.Error("finish failed")
		}
	})
	var left []byte
	var state string
	for _, id := range []uuid.UUID{sentID, failedID} {
		if err := super.QueryRow(f.ctx, "SELECT state, params_ct FROM ctrlz.sms_outbox WHERE id = $1", id).Scan(&state, &left); err != nil || left != nil {
			t.Errorf("params_ct of %s stayed after the end: %v %v", id, left, err)
		}
	}
	// The admin reads the state and nothing else.
	f.global(t, admin, func(g store.GlobalTx) {
		if st, ok, _ := g.SMSOutboxStatus(failedID); !ok || st.State != "failed" || st.LastError != "cap" {
			t.Errorf("status: %+v %v", st, ok)
		}
	})
	// The outbox cap, the stale rule.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.system_settings SET sms_outbox_cap_daily = 2, sms_cost_cap_daily = NULL"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		for i, want := range []bool{true, true, false, false} {
			if ok, err := g.OutboxFirstGate(); err != nil || ok.Yes() != want {
				t.Errorf("bump %d: %v %v", i, ok, err)
			}
		}
	})
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.system_settings SET sms_outbox_cap_daily = 0"); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, "TRUNCATE ctrlz.sms_counters"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if ok, _ := g.OutboxFirstGate(); ok.Yes() {
			t.Error("a cap of zero let a message through")
		}
	})
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.sms_outbox SET created_at = now() - interval '2 hours', claimed_until = NULL WHERE state = 'pending'"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OutboxFailStaleBatch(1000); err != nil || n != 1 {
			t.Errorf("OutboxFailStale: %d %v", n, err)
		}
	})

	// The breaker: three transient failures open it, doubling, and a success closes it.
	var breaker *time.Time
	read := func() int {
		var n int
		if err := super.QueryRow(f.ctx, "SELECT consecutive_failures, breaker_open_until FROM ctrlz.sms_gateways WHERE id = $1", gw).Scan(&n, &breaker); err != nil {
			t.Fatal(err)
		}
		return n
	}
	f.global(t, worker, func(g store.GlobalTx) {
		for i := 0; i < 2; i++ {
			if _, err := g.GatewayFailed(gw, word("transient 503"), true); err != nil {
				t.Fatal(err)
			}
		}
	})
	if read() != 2 || breaker != nil {
		t.Errorf("after two failures: %v", breaker)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if _, err := g.GatewayFailed(gw, word("credit 102"), false); err != nil { // does not count
			t.Fatal(err)
		}
		if _, err := g.GatewayFailed(gw, word("transient 503"), true); err != nil {
			t.Fatal(err)
		}
	})
	if read() != 3 || breaker == nil || time.Until(*breaker) < 50*time.Second || time.Until(*breaker) > 70*time.Second {
		t.Errorf("after three: %v", breaker)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		for i := 0; i < 20; i++ {
			_, _ = g.GatewayFailed(gw, word("transient 503"), true)
		}
	})
	if read(); breaker == nil || time.Until(*breaker) > 15*time.Minute+time.Second {
		t.Errorf("the breaker passed 15 minutes: %v", breaker)
	}
	// The public flag does not follow the breaker (sms-r18-2): only a real row reaches a gateway, so a
	// flag that fell with the breaker would say whether a request left a real row.
	if cfg, _ := f.db.Store(f.ctx, t, store.RoleTenant).Auth().PublicConfig(f.ctx); !cfg.SMSAvailable {
		t.Error("sms_available fell with an open breaker, which tells a phone with an account from one without")
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if err := g.GatewayOK(gw); err != nil {
			t.Fatal(err)
		}
	})
	if read() != 0 || breaker != nil {
		t.Error("a success did not close the breaker")
	}
	if cfg, _ := f.db.Store(f.ctx, t, store.RoleTenant).Auth().PublicConfig(f.ctx); !cfg.SMSAvailable {
		t.Error("sms_available is false with a configured gateway")
	}

	// Alerts: one open alert per kind and key; an ack lets the next failure alert.
	f.global(t, worker, func(g store.GlobalTx) {
		for i, want := range []bool{true, false, false} {
			if ok, err := g.AlertOnce("warning", "sms_gateway", key("sms_ir"), mustParams(sms.GatewayAlert{Provider: sms.ProviderSMSIR, Class: sms.Auth, Code: sms.CodeUnknown})); err != nil || ok != want {
				t.Errorf("alert %d: %v %v", i, ok, err)
			}
		}
		if ok, _ := g.AlertOnce("warning", "sms_gateway", key("melipayamak"), closed.Params{}); !ok {
			t.Error("another gateway's alert was swallowed")
		}
	})
	var aid uuid.UUID
	f.global(t, admin, func(g store.GlobalTx) {
		rows, err := g.AlertsPage(uuid.Nil, 10)
		if err != nil || len(rows) != 2 {
			t.Fatalf("AlertsPage: %d %v", len(rows), err)
		}
		if !strings.Contains(string(rows[0].Params), `"key"`) {
			t.Errorf("params: %s", rows[0].Params)
		}
		aid = rows[0].ID
		if kind, ok, _ := g.AlertAck(aid); !ok || kind != "sms_gateway" {
			t.Errorf("ack: %q %v", kind, ok)
		}
		if _, ok, _ := g.AlertAck(aid); ok {
			t.Error("acked twice")
		}
	})
	f.global(t, worker, func(g store.GlobalTx) {
		if ok, _ := g.AlertOnce("warning", "sms_gateway", key("sms_ir"), closed.Params{}); !ok {
			if ok2, _ := g.AlertOnce("warning", "sms_gateway", key("melipayamak"), closed.Params{}); !ok2 {
				t.Error("an acked alert did not let the next one through")
			}
		}
	})
	f.global(t, admin, func(g store.GlobalTx) {
		rows, _ := g.AlertsPage(uuid.Nil, 10)
		if len(rows) != 3 || rows[2].ResolvedAt == nil {
			t.Errorf("alerts after the ack: %d rows, last resolved %v", len(rows), rows[len(rows)-1].ResolvedAt)
		}
	})
}

// TestSweepsRunAsTheWorker is spec test 37: each sweep's DELETE, with its real
// WHERE clause, runs as ctrlz_worker (the column grants are enough), removes
// what is old, keeps what is not, and under a tenant setting touches that
// tenant only.
func TestSweepsRunAsTheWorker(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := super.Exec(f.ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := super.QueryRow(f.ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Global rows: one old and one young of each.
	exec(`INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, expires_at, created_at) VALUES
 ('+989121110051', 'login', '\x01', now() - interval '25 hours', now() - interval '25 hours'),
 ('+989121110052', 'login', '\x01', now() + interval '5 minutes', now())`)
	exec(`INSERT INTO ctrlz.auth_tickets (token_hash, kind, expires_at, created_at) VALUES
 (decode(repeat('41', 32), 'hex'), 'mfa', now() - interval '1 minute', now() - interval '6 minutes'),
 (decode(repeat('42', 32), 'hex'), 'mfa', now() + interval '5 minutes', now())`)
	exec(`INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES
 ('login_net', decode(repeat('43', 32), 'hex'), now() - interval '2 days', 3),
 ('login_net', decode(repeat('44', 32), 'hex'), now(), 3)`)
	exec(`INSERT INTO ctrlz.sms_deliveries (source, source_id, provider, template_key, outcome, created_at) VALUES
 ('otp', gen_random_uuid(), 'noop', 'otp', 'accepted', now() - interval '91 days'),
 ('otp', gen_random_uuid(), 'noop', 'otp', 'accepted', now())`)
	exec(`INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, state, created_at) VALUES
 ('test', '+989121110053', 'otp', 'fa', 'sent', now() - interval '31 days'),
 ('test', '+989121110054', 'otp', 'fa', 'pending', now())`)
	exec(testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES
 ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'phone', '+989121110055', 1),
 ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'ip', '198.51.100.1', 1),
 ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'global', 'all', 9),
 ((now() AT TIME ZONE 'Asia/Tehran')::date, 'phone', '+989121110056', 1)`))
	exec(`INSERT INTO ctrlz.invites (token_hash, phone_e164, expires_at) VALUES
 ('\x0a01', '+989121110057', now() - interval '91 days'),
 ('\x0a02', '+989121110058', now() + interval '1 day')`)

	var c store.SweepCounts
	for _, step := range store.SweepSteps() {
		var n int
		f.global(t, worker, func(g store.GlobalTx) {
			var err error
			if n, err = g.SweepGlobalBatch(step, 1000); err != nil {
				t.Fatal(err)
			}
		})
		switch step {
		case store.SweepOTP:
			c.OTP = n
		case store.SweepTickets:
			c.Tickets = n
		case store.SweepThrottle:
			c.Throttle = n
		case store.SweepDeliveries:
			c.Deliveries = n
		case store.SweepOutbox:
			c.Outbox = n
		case store.SweepCounters:
			c.Counters = n
		case store.SweepInvites:
			c.Invites = n
		}
	}
	if c.OTP != 1 || c.Tickets != 1 || c.Throttle != 1 || c.Deliveries != 1 || c.Outbox != 1 || c.Counters != 2 || c.Invites != 1 {
		t.Errorf("deleted %+v", c)
	}
	// The seed adds an OTP and a decoy of its own (both young), and a ticket,
	// a throttle row, a delivery and an outbox row.
	for q, want := range map[string]int{
		"SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = '+989121110052'":               1,
		"SELECT count(*) FROM ctrlz.auth_tickets WHERE token_hash = decode(repeat('42', 32), 'hex')": 1,
		"SELECT count(*) FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'":             1, // kept for the statistics
		"SELECT count(*) FROM ctrlz.sms_counters WHERE scope = 'phone'":                              1,
		"SELECT count(*) FROM ctrlz.invites WHERE phone_e164 = '+989121110058'":                      1,
	} {
		if got := count(q); got != want {
			t.Errorf("%s: %d, want %d", q, got, want)
		}
	}

	// Tenant rows, for both tenants: old sessions, refresh tokens, phone changes,
	// audit rows and a pending TOTP secret.
	for _, ids := range []struct {
		tenant, user uuid.UUID
	}{{f.A.Tenant, f.A.User}, {f.B.Tenant, f.B.User}} {
		exec(`INSERT INTO ctrlz.sessions (tenant_id, user_id, token_hash, idle_expires_at, absolute_expires_at, last_seen_at)
VALUES ($1, $2, convert_to(gen_random_uuid()::text, 'UTF8'), now() - interval '3 days', now() - interval '2 days', now())`, ids.tenant, ids.user)
		exec(`INSERT INTO ctrlz.refresh_tokens (tenant_id, user_id, session_id, family_id, token_hash, expires_at)
SELECT $1, $2, id, gen_random_uuid(), convert_to(gen_random_uuid()::text, 'UTF8'), now() - interval '2 days' FROM ctrlz.sessions WHERE tenant_id = $1 AND absolute_expires_at < now() LIMIT 1`, ids.tenant, ids.user)
		exec(`INSERT INTO ctrlz.phone_change_requests (tenant_id, user_id, new_phone_e164, old_otp_id, new_otp_id, created_at, expires_at)
VALUES ($1, $2, '+989139990000', gen_random_uuid(), gen_random_uuid(), now() - interval '2 days 10 minutes', now() - interval '2 days')`, ids.tenant, ids.user)
		exec(`INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, at) VALUES ($1, $2, 'old', now() - interval '400 days')`, ids.tenant, ids.user)
		exec(`UPDATE ctrlz.users SET totp_secret_ct = '\x01', totp_pending_at = now() - interval '16 minutes' WHERE id = $1`, ids.user)
	}
	var tc store.TenantSweepCounts
	if err := worker.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		for _, step := range store.TenantSweepSteps() {
			// Each step is its own transaction in the sweep (worker/sweep); one here only
			// to count them.
			tx.ForgetLocks()
			n, err := tx.SweepTenantBatch(step, 1000, time.Now())
			if err != nil {
				return err
			}
			switch step {
			case store.TenantSweepSessions:
				tc.Sessions = n
			case store.TenantSweepRefresh:
				tc.Refresh = n
			case store.TenantSweepPhone:
				tc.PhoneChanges = n
			case store.TenantSweepAudit:
				tc.Audit = n
			case store.TenantSweepPendingTOTP:
				tc.PendingTOTP = n
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The refresh token goes with its session (ON DELETE CASCADE), so the sweep
	// of refresh tokens finds none of its own.
	if tc.Sessions != 1 || tc.Refresh != 0 || tc.PhoneChanges != 1 || tc.Audit != 1 || tc.PendingTOTP != 1 {
		t.Errorf("tenant A sweep: %+v", tc)
	}
	// Tenant B is as it was: its old rows are still there, and its seeded rows are
	// too (the seed's young session, request and audit row).
	for q, want := range map[string]int{
		"SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1":                              2,
		"SELECT count(*) FROM ctrlz.refresh_tokens WHERE tenant_id = $1":                        2,
		"SELECT count(*) FROM ctrlz.phone_change_requests WHERE tenant_id = $1":                 2,
		"SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1":                      2,
		"SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND totp_pending_at IS NOT NULL": 1,
	} {
		if got := count(q, f.B.Tenant); got != want {
			t.Errorf("tenant B untouched? %s: %d, want %d", q, got, want)
		}
		wantA := want - 1
		if strings.Contains(q, "totp_pending") {
			wantA = 0
		}
		if got := count(q, f.A.Tenant); got != wantA {
			t.Errorf("tenant A after its sweep: %s: %d, want %d", q, got, wantA)
		}
	}
}

func TestWorkerPerTenantJobs(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)

	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.admin_jobs"); err != nil { // the seed queued one
		t.Fatal(err)
	}
	// TenantIDs pages in id order.
	f.global(t, worker, func(g store.GlobalTx) {
		p1, err := g.TenantIDs(uuid.Nil, 1)
		if err != nil || len(p1) != 1 {
			t.Fatalf("page 1: %v %v", p1, err)
		}
		p2, _ := g.TenantIDs(p1[0], 5)
		if len(p2) != 1 || p2[0] == p1[0] {
			t.Errorf("page 2: %v", p2)
		}
		if p3, _ := g.TenantIDs(p2[0], 5); len(p3) != 0 {
			t.Errorf("page 3: %v", p3)
		}
	})

	// The RP ID job: stale marking and Enforce, for one tenant at a time. Both act for the
	// RP ID in force only (migration 0017), so the configuration says which that is.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.webauthn_config SET rp_id = 'panel.localhost'"); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET enforce_passkey = true"); err != nil {
		t.Fatal(err)
	}
	var users []uuid.UUID
	if err := worker.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		var err error
		n, err := tx.EnforceClearWithoutLive("panel.localhost")
		if n != 1 {
			t.Errorf("Enforce cleared for %d users", n)
		}
		if users, err = tx.PasskeysMarkStale("panel.localhost"); err != nil {
			return err
		}
		if again, _ := tx.PasskeysMarkStale("panel.localhost"); len(again) != 0 {
			t.Errorf("a second run marked %v again", again)
		}
		if err := tx.NotificationAdd("passkey_stale", "warning", []byte(`{}`)); err != nil {
			t.Error(err)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0] != f.A.User {
		t.Errorf("stale users: %v", users)
	}
	var staleB, enforceA, enforceB int
	_ = super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.webauthn_credentials WHERE tenant_id = $1 AND stale_at IS NOT NULL", f.B.Tenant).Scan(&staleB)
	_ = super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND enforce_passkey", f.A.Tenant).Scan(&enforceA)
	_ = super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.users WHERE tenant_id = $1 AND enforce_passkey", f.B.Tenant).Scan(&enforceB)
	if staleB != 0 || enforceA != 0 || enforceB != 1 {
		t.Errorf("tenant B's credentials stale %d; Enforce A %d, B %d (want 0, 0, 1)", staleB, enforceA, enforceB)
	}

	// Key rotation runs as the key tool, not as the worker, which has no grant on the seeds
	// (db-r4-3). The seed is swapped only when it is what we read.
	keytool := f.db.Store(f.ctx, t, store.RoleKeytool)
	if err := worker.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.TOTPSecrets()
		return err
	}); err == nil {
		t.Error("the worker role read the sealed TOTP seeds")
	}
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.users SET totp_secret_ct = convert_to('old-' || tenant_id::text, 'UTF8')"); err != nil {
		t.Fatal(err)
	}
	if err := keytool.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		secrets, err := tx.TOTPSecrets()
		if err != nil || len(secrets) != 1 || secrets[0].User != f.A.User {
			t.Fatalf("TOTPSecrets: %+v %v", secrets, err)
		}
		if ok, _ := tx.TOTPSecretReplace(f.A.User, []byte("not the value"), []byte("x")); ok {
			t.Error("a seed that changed was overwritten")
		}
		if ok, err := tx.TOTPSecretReplace(f.A.User, secrets[0].CT, []byte("new-A")); err != nil || !ok {
			t.Error(ok, err)
		}
		if ok, _ := tx.TOTPSecretReplace(f.B.User, []byte("old-"+f.B.Tenant.String()), []byte("hijack")); ok {
			t.Error("tenant B's seed was replaced from tenant A's transaction")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var b string
	_ = super.QueryRow(f.ctx, "SELECT convert_from(totp_secret_ct, 'UTF8') FROM ctrlz.users WHERE id = $1", f.B.User).Scan(&b)
	if b != "old-"+f.B.Tenant.String() {
		t.Errorf("tenant B's seed is %q", b)
	}

	// Admin jobs: start, progress, finish.
	var job uuid.UUID
	f.global(t, f.db.Store(f.ctx, t, store.RoleAdmin), func(g store.GlobalTx) {
		var err error
		if job, err = g.AdminJobInsert("webauthn_rp_change", []byte(`{"rp_id":"panel.localhost"}`), uuid.Nil); err != nil {
			t.Fatal(err)
		}
	})
	f.global(t, worker, func(g store.GlobalTx) {
		jobs, err := g.AdminJobsActive()
		if err != nil || len(jobs) != 1 || jobs[0].ID != job || jobs[0].State != "queued" {
			t.Fatalf("AdminJobsActive: %+v %v", jobs, err)
		}
		if ok, err := g.AdminJobStart(job); err != nil || !ok.Yes() {
			t.Fatalf("start: %v %v", ok, err)
		}
		if err := g.AdminJobProgress(job, []byte(`{"tenants":1}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := g.AdminJobFinish(job, "done", nil); err != nil {
			t.Fatal(err)
		}
		if jobs, _ := g.AdminJobsActive(); len(jobs) != 0 {
			t.Errorf("a finished job is still active: %+v", jobs)
		}
		// A finished job cannot be started again from an old job list, and a
		// tenant transaction cannot hold it (sms-r2-12).
		if ok, err := g.AdminJobStart(job); err != nil || ok.Yes() {
			t.Errorf("a finished job started again: %v %v", ok, err)
		}
	})
	if err := worker.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if held, err := tx.AdminJobHold(job); err != nil || held {
			t.Errorf("hold on a finished job: %v %v", held, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var progress string
	_ = super.QueryRow(f.ctx, "SELECT progress::text FROM ctrlz.admin_jobs WHERE id = $1", job).Scan(&progress)
	if !strings.Contains(progress, "tenants") {
		t.Errorf("progress %s", progress)
	}
}

// A record transaction that fails on every pass must not let the provider accept
// the same code again and again (review sms-r1-4), and the sweep must not touch a
// row a worker is sending (sms-r1-13).
func TestOTPClaimCeilingEndsAnExhaustedRowOnceAndTheSweepSkipsLiveClaims(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	ip := netip.MustParseAddr("198.51.100.78")
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.otp_challenges"); err != nil {
		t.Fatal(err)
	}
	row, err := tenant.Auth().OTPIssue(f.ctx, "+989121110061", "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !row.Allowed {
		t.Fatal(row, err)
	}
	globalCount := func() int {
		var n int
		if err := super.QueryRow(f.ctx, "SELECT COALESCE((SELECT sum(count) FROM ctrlz.sms_counters WHERE scope = 'global' AND (key = 'all' OR key LIKE 'all:%') AND day = (now() AT TIME ZONE 'Asia/Tehran')::date), 0)").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	phoneCount := func() int {
		var n int
		if err := super.QueryRow(f.ctx, "SELECT COALESCE((SELECT count FROM ctrlz.sms_counters WHERE scope = 'phone' AND key = '+989121110061'), 0)").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	for i := 1; i <= 3; i++ {
		f.global(t, worker, func(g store.GlobalTx) {
			got, err := g.OTPClaim(5, 3)
			if err != nil || len(got) != 1 || got[0].Attempts != i {
				t.Fatalf("claim %d: %+v %v", i, got, err)
			}
		})
		if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() - interval '1 second'"); err != nil {
			t.Fatal(err)
		}
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if got, _ := g.OTPClaim(5, 3); len(got) != 0 {
			t.Errorf("a row that used its three claims was claimed again: %+v", got)
		}
	})
	// While a claim is live, neither end path touches the row.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() + interval '10 seconds', expires_at = now() - interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OTPExpireUndelivered(); err != nil || n != 0 {
			t.Errorf("the sweep took a row a worker is sending: %d %v", n, err)
		}
		if n, err := g.OTPEndExhausted(3); err != nil || n != 0 {
			t.Errorf("the exhausted pass took a row a worker is sending: %d %v", n, err)
		}
	})
	if phoneCount() != 1 {
		t.Fatalf("phone counter %d before the end", phoneCount())
	}
	// The claim lapses: the exhausted pass ends it and refunds once; a second
	// pass and the expiry sweep find nothing to refund again.
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() - interval '2 minutes', expires_at = now() + interval '3 minutes'"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OTPEndExhausted(3); err != nil || n != 1 {
			t.Fatalf("OTPEndExhausted: %d %v", n, err)
		}
		if n, _ := g.OTPEndExhausted(3); n != 0 {
			t.Errorf("the exhausted row was ended twice: %d", n)
		}
		if n, _ := g.OTPExpireUndelivered(); n != 0 {
			t.Errorf("the expiry sweep refunded an ended row: %d", n)
		}
	})
	// The global slot went back once; the phone's stays spent.
	if phoneCount() != 1 || globalCount() != 0 {
		t.Errorf("phone counter %d (want 1), global %d (want 0) after the refund", phoneCount(), globalCount())
	}
}

func TestOutboxClaimCeilingAndFailStale(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.sms_outbox"); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct, attempts)
VALUES ('test', '+989121110062', 'otp', 'fa', '\x01', $1) RETURNING id`, store.OutboxMaxAttempts).Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if got, _ := g.OutboxClaim(5); len(got) != 0 {
			t.Errorf("a message past the ceiling was claimed: %+v", got)
		}
	})
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.sms_outbox SET claimed_until = now() + interval '10 seconds'"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, _ := g.OutboxFailStaleBatch(1000); n != 0 {
			t.Errorf("a message under a live claim was ended: %d", n)
		}
	})
	if _, err := super.Exec(f.ctx, "UPDATE ctrlz.sms_outbox SET claimed_until = NULL"); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OutboxFailStaleBatch(1000); err != nil || n != 1 {
			t.Fatalf("OutboxFailStale: %d %v", n, err)
		}
	})
	var state, last string
	var ct []byte
	if err := super.QueryRow(f.ctx, "SELECT state, last_error, params_ct FROM ctrlz.sms_outbox WHERE id = $1", id).Scan(&state, &last, &ct); err != nil ||
		state != "failed" || last != "attempts" || ct != nil {
		t.Errorf("after the ceiling: %s %s %v %v", state, last, ct, err)
	}
}

// Review round 3 (db-r3-2): a message that is older than an hour but is claimed
// again right now is being sent. The sweep must wait for the claim to lapse, or
// it ends the row as failed while the provider accepts the message and the finish
// that follows matches nothing (a double send after the admin re-sends the invite).
func TestOutboxFailStaleWaitsForALiveClaimPastTheHour(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.sms_outbox"); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct, attempts, created_at, claimed_until)
VALUES ('test', '+989121110063', 'otp', 'fa', '\x01', 3, now() - interval '61 minutes', now() + interval '10 seconds') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if n, err := g.OutboxFailStaleBatch(1000); err != nil || n != 0 {
			t.Fatalf("a message under a live claim, past the hour, was ended: %d %v", n, err)
		}
		// The send then finishes and the row is sent, not failed.
		if ok, err := g.OutboxFinish(id, "sent", nil); err != nil || !ok.Yes() {
			t.Fatalf("OutboxFinish after the sweep: %v %v", ok, err)
		}
	})
	var state string
	var ct []byte
	if err := super.QueryRow(f.ctx, "SELECT state, params_ct FROM ctrlz.sms_outbox WHERE id = $1", id).Scan(&state, &ct); err != nil || state != "sent" {
		t.Fatalf("state %q err %v", state, err)
	}

	// With the claim gone, the same age ends the row as a timeout.
	if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct, attempts, created_at)
VALUES ('test', '+989121110064', 'otp', 'fa', '\x01', 3, now() - interval '61 minutes') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		// The claim query leaves it alone too, so a message that is retried until the
		// hour is up does not hold the sweep off for ever.
		if got, _ := g.OutboxClaim(5); len(got) != 0 {
			t.Errorf("a message past the hour was claimed: %+v", got)
		}
		if n, err := g.OutboxFailStaleBatch(1000); err != nil || n != 1 {
			t.Fatalf("an unclaimed message past the hour: %d %v", n, err)
		}
	})
	var last string
	if err := super.QueryRow(f.ctx, "SELECT state, last_error FROM ctrlz.sms_outbox WHERE id = $1", id).Scan(&state, &last); err != nil || state != "failed" || last != "timeout" {
		t.Errorf("after the hour: %s %s %v", state, last, err)
	}
}

// The sweep deletes in bounded batches (review sms-r1-1): a limit of 10 on 25
// old rows takes three calls, and the young row stays.
func TestSweepGlobalBatchIsBounded(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, "DELETE FROM ctrlz.auth_tickets"); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.auth_tickets (token_hash, kind, expires_at, created_at)
SELECT decode(lpad(to_hex(n), 64, '0'), 'hex'), 'mfa', now() - interval '1 minute', now() - interval '6 minutes' FROM generate_series(1, 25) n`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.auth_tickets (token_hash, kind, expires_at) VALUES (decode(repeat('ff', 32), 'hex'), 'mfa', now() + interval '5 minutes')`); err != nil {
		t.Fatal(err)
	}
	var got []int
	for i := 0; i < 3; i++ {
		f.global(t, worker, func(g store.GlobalTx) {
			n, err := g.SweepGlobalBatch(store.SweepTickets, 10)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, n)
		})
	}
	if got[0] != 10 || got[1] != 10 || got[2] != 5 {
		t.Errorf("batches: %v, want 10 10 5", got)
	}
	var left int
	if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.auth_tickets").Scan(&left); err != nil || left != 1 {
		t.Errorf("rows left %d (%v), want the young one", left, err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if _, err := g.SweepGlobalBatch(store.SweepStep(99), 10); err == nil {
			t.Error("an unknown step was accepted")
		}
	})
}

// The hold of a refused login is two columns that bind to the credentials they were made for
// (sms-r12-3). A hold lands only on the sum of the ciphertext the row has now; a release lifts only
// the hold that was made for the sum it carries; saving credentials through the admin path clears
// it; and the worker reads it back.
func TestGatewayHoldBindsToTheSealedCredentials(t *testing.T) {
	f := newFixture(t)
	admin := f.db.Store(f.ctx, t, store.RoleAdmin)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	var gw uuid.UUID
	f.global(t, admin, func(g store.GlobalTx) {
		var err error
		if gw, err = g.SMSGatewayEnsure(uuid.New(), "sms_ir"); err != nil {
			t.Fatal(err)
		}
		if ok, _ := activate(g, gw, "sms_ir", []byte("sealed-1"), "1234"); !ok {
			t.Fatal("credentials")
		}
	})
	sum := func(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
	code := sms.StatusOf(sms.StatusCode("10"))
	read := func() (held bool, ctSum []byte, c string) {
		var hc *string
		f.global(t, worker, func(g store.GlobalTx) {
			gws, err := g.WorkerGateways()
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range gws {
				if w.ID == gw {
					ctSum, hc = w.HeldCTSum, w.HeldCode
				}
			}
		})
		if hc != nil {
			c = *hc
		}
		return hc != nil, ctSum, c
	}
	hold := func(s string) (won bool) {
		f.global(t, worker, func(g store.GlobalTx) {
			w, err := g.GatewayHold(gw, sum(s), code)
			if err != nil {
				t.Fatal(err)
			}
			won = w.Yes()
		})
		return won
	}
	release := func(s string) (won bool) {
		f.global(t, worker, func(g store.GlobalTx) {
			w, err := g.GatewayRelease(gw, sum(s))
			if err != nil {
				t.Fatal(err)
			}
			won = w.Yes()
		})
		return won
	}

	if hold("sealed-0") {
		t.Fatal("a hold for credentials the row does not have landed")
	}
	if h, _, _ := read(); h {
		t.Fatal("a lost hold left a mark")
	}
	if !hold("sealed-1") {
		t.Fatal("a hold for the current credentials was refused")
	}
	if h, got, c := read(); !h || !bytes.Equal(got, sum("sealed-1")) || c != "10" {
		t.Fatalf("hold read back: %v %x %q", h, got, c)
	}
	if release("sealed-0") {
		t.Fatal("a release for other credentials lifted the hold")
	}
	if h, _, _ := read(); !h {
		t.Fatal("the hold was lost to a release of other credentials")
	}
	if !release("sealed-1") {
		t.Fatal("a release for the held credentials was refused")
	}
	if h, _, _ := read(); h {
		t.Fatal("the hold is still there after its release")
	}

	// The admin path ends a hold: new credentials clear it, and a hold read for other credentials
	// is not the row's.
	if !hold("sealed-1") {
		t.Fatal("hold")
	}
	f.global(t, admin, func(g store.GlobalTx) {
		if ok, _ := activate(g, gw, "sms_ir", []byte("sealed-2"), "1234"); !ok {
			t.Fatal("credentials")
		}
	})
	if h, _, _ := read(); h {
		t.Fatal("saving credentials did not clear the hold")
	}
	// The worker cannot write a code outside the closed alphabet.
	if err := worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := g.GatewayHold(gw, sum("sealed-2"), word("x y"))
		return err
	}); err == nil {
		t.Error("a code outside the alphabet was stored")
	}
}
