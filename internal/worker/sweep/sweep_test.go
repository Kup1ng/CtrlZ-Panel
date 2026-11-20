package sweep_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/sweep"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

var ip = netip.MustParseAddr("198.51.100.7")

type rig struct {
	t     *testing.T
	env   *authtest.Env
	otp   *otp.Service
	sweep *sweep.Sweeper
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	env.ResetSMS(t)
	ring, err := keyring.NewEphemeral(keyring.DomainAuthMAC, keyring.DomainOTPDelivery)
	if err != nil {
		t.Fatal(err)
	}
	wring, _ := keyring.NewEphemeral(keyring.DomainSMSCred)
	env.AddGateway(t, wring, authtest.Gateway{Provider: "noop", Role: "primary"})
	tenant := env.Tenant(t)
	o, err := otp.New(tenant.Auth(), ring, func(ctx context.Context) (store.PublicConfig, error) { return tenant.Auth().PublicConfig(ctx) },
		otp.WithCodeSource(func() (secret.String, error) { return secret.New("012345"), nil }))
	if err != nil {
		t.Fatal(err)
	}
	s, err := sweep.New(sweep.Config{Store: env.Worker(t), Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Page: 1})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, env: env, otp: o, sweep: s}
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.env.DB.Scan(r.env.Ctx, sql, args, &n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *rig) counter(scope, key string) int {
	return r.count(`SELECT COALESCE((SELECT count FROM ctrlz.sms_counters WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date
	  AND scope = $1 AND key = $2), 0)`, scope, key)
}

func (r *rig) request(phone string) uuid.UUID {
	r.t.Helper()
	ch, err := r.otp.Request(r.env.Ctx, otp.Request{Phone: phone, Purpose: otp.Login, Locale: "fa", IP: ip})
	if err != nil {
		r.t.Fatal(err)
	}
	return ch.ID
}

func TestFastRefundsOTPsThatExpiredUnsent(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A.Phone, r.env.B.Phone
	unknown := "+989129990000"
	expiredA, expiredB := r.request(a), r.request(b)
	decoy := r.request(unknown)
	// A third known phone's code was delivered (the worker cleared it) and one is
	// still fresh and waiting.
	r.env.Exec(t, `INSERT INTO ctrlz.tenants (id) VALUES ('00000000-0000-7000-8000-0000000000aa')`)
	r.env.Exec(t, `INSERT INTO ctrlz.users (tenant_id, id, phone_e164) VALUES ('00000000-0000-7000-8000-0000000000aa', '00000000-0000-7000-8000-0000000000ab', '+989128880001')`)
	r.env.Exec(t, `INSERT INTO ctrlz.tenants (id) VALUES ('00000000-0000-7000-8000-0000000000ac')`)
	r.env.Exec(t, `INSERT INTO ctrlz.users (tenant_id, id, phone_e164) VALUES ('00000000-0000-7000-8000-0000000000ac', '00000000-0000-7000-8000-0000000000ad', '+989128880002')`)
	delivered := r.request("+989128880001")
	fresh := r.request("+989128880002")
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET delivery_ct = NULL WHERE id = $1`, delivered)

	// The worker was down while two codes ran out.
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET `+testpg.OTPExpiredUnsentSet+`
	  WHERE id = ANY ($1)`, []uuid.UUID{expiredA, expiredB, decoy})
	if r.counter("phone", a) != 1 || r.counter("global", "all") != 4 {
		t.Fatalf("counters before: phone %d, global %d", r.counter("phone", a), r.counter("global", "all"))
	}

	res, err := r.sweep.Fast(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExpiredOTP != 2 {
		t.Fatalf("expired %d, want the two real codes (the decoy has nothing to clear)", res.ExpiredOTP)
	}
	// The two real rows gave back the global key and nothing else (sms-r5-7): every
	// other key a decoy also bumped, and a decoy is never ended, so a real row's per-phone
	// and per-network counters must end where a decoy's do. The delivered and the fresh
	// rows keep theirs, global included.
	for _, p := range []string{a, b, unknown} {
		if r.counter("phone", p) != 1 {
			t.Errorf("phone %s counter %d, want 1: an expired row must leave what a decoy leaves", p, r.counter("phone", p))
		}
	}
	if r.counter("phone", "+989128880001") != 1 || r.counter("phone", "+989128880002") != 1 {
		t.Error("the delivered or the fresh row was refunded")
	}
	if r.counter("global", "all") != 2 {
		t.Errorf("global %d, want 2 (delivered and fresh)", r.counter("global", "all"))
	}
	if r.counter("ip", ip.String()) != 5 {
		t.Errorf("ip counter %d, want 5: five requests, none refunded", r.counter("ip", ip.String()))
	}
	// The sealed code of the two is gone; the fresh one waits.
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id = ANY ($1) AND delivery_ct IS NOT NULL`, []uuid.UUID{expiredA, expiredB}) != 0 {
		t.Error("an expired code kept its sealed payload")
	}
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND delivery_ct IS NOT NULL`, fresh) != 1 {
		t.Error("the fresh code was cleared")
	}
	// Once only.
	if res, err = r.sweep.Fast(r.env.Ctx); err != nil || res.ExpiredOTP != 0 {
		t.Errorf("second pass: %+v %v", res, err)
	}
	if r.counter("global", "all") != 2 {
		t.Error("a second pass refunded again")
	}
}

func TestFastEndsStaleOutboxMessages(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct, created_at) VALUES
	  ('invite', '+989121112233', 'invite', 'fa', '\x01', now() - interval '61 minutes'),
	  ('invite', '+989121112244', 'invite', 'fa', '\x01', now() - interval '5 minutes')`)
	res, err := r.sweep.Fast(r.env.Ctx)
	if err != nil || res.StaleOutbox != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE state = 'failed' AND last_error = 'timeout' AND params_ct IS NULL`) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE state = 'pending' AND params_ct IS NOT NULL`) != 1 {
		t.Error("the stale message was not ended, or the fresh one was")
	}
}

func TestSlowDeletesWhatOutlivedItsUse(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	ex := func(sql string, args ...any) { r.env.Exec(t, sql, args...) }

	// Tenant A: everything expired. Tenant B: the same kinds of row, all live.
	ex(`UPDATE ctrlz.sessions SET idle_expires_at = now() - interval '3 days', absolute_expires_at = now() - interval '2 days' WHERE tenant_id = $1`, a.Tenant)
	ex(`UPDATE ctrlz.refresh_tokens SET expires_at = now() - interval '2 days', created_at = now() - interval '3 days' WHERE tenant_id = $1`, a.Tenant)
	ex(`UPDATE ctrlz.phone_change_requests SET expires_at = now() - interval '2 days', created_at = now() - interval '2 days 5 minutes' WHERE tenant_id = $1`, a.Tenant)
	ex(`INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, at) VALUES ($1, $2, 'old', now() - interval '400 days'), ($3, $4, 'old', now() - interval '400 days')`,
		a.Tenant, a.User, b.Tenant, b.User)
	ex(`UPDATE ctrlz.users SET totp_secret_ct = '\x01', totp_pending_at = now() - interval '20 minutes' WHERE id = $1`, a.User)
	ex(`UPDATE ctrlz.users SET totp_secret_ct = '\x01', totp_pending_at = now() - interval '5 minutes' WHERE id = $1`, b.User)

	// Global rows.
	ex(`UPDATE ctrlz.auth_tickets SET expires_at = now() - interval '1 minute', created_at = now() - interval '10 minutes'`)
	ex(`INSERT INTO ctrlz.auth_tickets (token_hash, kind, expires_at) VALUES (decode(repeat('03', 32), 'hex'), 'passkey_login', now() + interval '5 minutes')`)
	ex(`UPDATE ctrlz.auth_throttle SET window_start = now() - interval '2 days'`)
	ex(`INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES ('login_net', decode(repeat('04', 32), 'hex'), now(), 1)`)
	ex(`INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, expires_at, ip, created_at) VALUES
	  ('+989120000071', 'login', '\x01', now() - interval '25 hours', '198.51.100.9', now() - interval '25 hours 5 minutes'),
	  ('+989120000072', 'login', '\x01', now() + interval '5 minutes', '198.51.100.9', now())`)
	ex(`INSERT INTO ctrlz.sms_deliveries (source, source_id, provider, template_key, outcome, created_at) VALUES
	  ('otp', gen_random_uuid(), 'noop', 'otp', 'accepted', now() - interval '91 days'),
	  ('otp', gen_random_uuid(), 'noop', 'otp', 'accepted', now() - interval '10 days')`)
	ex(`INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, state, created_at) VALUES
	  ('invite', '+989121112233', 'invite', 'fa', 'sent', now() - interval '31 days'),
	  ('invite', '+989121112244', 'invite', 'fa', 'sent', now() - interval '3 days')`)
	ex(testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES
	  ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'phone', '+989120000073', 2),
	  ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'phone_net', '+989120000073|198.51.100.0/24', 2),
	  ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'ip', '198.51.100.9', 2),
	  ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'global', 'all', 7),
	  ((now() AT TIME ZONE 'Asia/Tehran')::date, 'phone', '+989120000074', 1)`))
	ex(`INSERT INTO ctrlz.invites (token_hash, phone_e164, expires_at) VALUES
	  (decode(repeat('0c', 32), 'hex'), '+989120000075', now() - interval '91 days'),
	  (decode(repeat('0d', 32), 'hex'), '+989120000076', now() - interval '1 day')`)

	res, err := r.sweep.Slow(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tenants != 2 {
		t.Errorf("swept %d tenants, want 2 (page size 1 forces two reads)", res.Tenants)
	}

	// Tenant A's expired rows are gone. B's live rows are all still there.
	check := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("%s: %d, want %d", name, got, want)
		}
	}
	check("A sessions", r.count(`SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1`, a.Tenant), 0)
	check("B sessions", r.count(`SELECT count(*) FROM ctrlz.sessions WHERE tenant_id = $1`, b.Tenant), 1)
	check("A refresh", r.count(`SELECT count(*) FROM ctrlz.refresh_tokens WHERE tenant_id = $1`, a.Tenant), 0)
	check("B refresh", r.count(`SELECT count(*) FROM ctrlz.refresh_tokens WHERE tenant_id = $1`, b.Tenant), 1)
	check("A phone changes", r.count(`SELECT count(*) FROM ctrlz.phone_change_requests WHERE tenant_id = $1`, a.Tenant), 0)
	check("B phone changes", r.count(`SELECT count(*) FROM ctrlz.phone_change_requests WHERE tenant_id = $1`, b.Tenant), 1)
	check("A old audit", r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'old'`, a.Tenant), 0)
	check("B old audit", r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'old'`, b.Tenant), 0)
	check("A audit kept", r.count(`SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1`, a.Tenant), 1)
	check("A pending totp", r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_secret_ct IS NULL AND totp_pending_at IS NULL`, a.User), 1)
	check("B pending totp", r.count(`SELECT count(*) FROM ctrlz.users WHERE id = $1 AND totp_secret_ct IS NOT NULL`, b.User), 1)

	check("expired tickets", r.count(`SELECT count(*) FROM ctrlz.auth_tickets`), 1)
	check("old throttle", r.count(`SELECT count(*) FROM ctrlz.auth_throttle`), 1)
	check("old otp rows", r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 IN ('+989120000071', '+989120000072')`), 1)
	check("old deliveries", r.count(`SELECT count(*) FROM ctrlz.sms_deliveries`), 1)
	check("old outbox", r.count(`SELECT count(*) FROM ctrlz.sms_outbox`), 1)
	check("old invites", r.count(`SELECT count(*) FROM ctrlz.invites`), 1)
	// Counters: phone, network and address keys over two days old go (they hold raw
	// numbers); the global row stays for /sms/stats; today's stays.
	check("old counters", r.count(`SELECT count(*) FROM ctrlz.sms_counters WHERE day < (now() AT TIME ZONE 'Asia/Tehran')::date - 2`), 1)
	check("global counter kept", r.count(`SELECT count(*) FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all' AND count = 7`), 1)
	check("today's counter kept", r.count(`SELECT count(*) FROM ctrlz.sms_counters WHERE key = '+989120000074'`), 1)

	// Idempotent.
	res2, err := r.sweep.Slow(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Global != (store.SweepCounts{}) || res2.Tenant != (store.TenantSweepCounts{}) {
		t.Errorf("a second sweep deleted again: %+v", res2)
	}
}

func TestRunSweepsOnItsOwnAndStops(t *testing.T) {
	env := authtest.New(t, cluster)
	env.ResetSMS(t)
	s, err := sweep.New(sweep.Config{Store: env.Worker(t), Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Fast: 50 * time.Millisecond, Slow: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	env.Exec(t, `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, created_at) VALUES ('invite', '+989121112233', 'invite', 'fa', now() - interval '2 hours')`)
	ctx, cancel := context.WithCancel(env.Ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	var n int
	for time.Now().Before(deadline) {
		_ = env.DB.Scan(env.Ctx, `SELECT count(*) FROM ctrlz.sms_outbox WHERE state = 'failed'`, nil, &n)
		if n == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n != 1 {
		t.Error("the running sweeper did not end the stale message")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestNewNeedsStoreAndLog(t *testing.T) {
	if _, err := sweep.New(sweep.Config{}); err == nil {
		t.Error("built without a store")
	}
}

func (r *rig) sweeper(c sweep.Config) *sweep.Sweeper {
	r.t.Helper()
	c.Store, c.Log = r.env.Worker(r.t), slog.New(slog.NewJSONHandler(io.Discard, nil))
	s, err := sweep.New(c)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// A backlog is worked off in bounded batches over several runs (review sms-r1-1):
// with a batch of 10 and 2 batches per run, 35 expired tickets take two runs.
func TestSlowDrainsABacklogInBoundedBatches(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `DELETE FROM ctrlz.auth_tickets`)
	r.env.Exec(t, `INSERT INTO ctrlz.auth_tickets (token_hash, kind, expires_at, created_at)
SELECT decode(lpad(to_hex(n), 64, '0'), 'hex'), 'mfa', now() - interval '1 minute', now() - interval '6 minutes' FROM generate_series(1, 35) n`)
	s := r.sweeper(sweep.Config{Batch: 10, MaxBatches: 2})
	for i, want := range []struct{ deleted, left int }{{20, 15}, {15, 0}} {
		res, err := s.Slow(r.env.Ctx)
		if err != nil {
			t.Fatal(err)
		}
		if res.Global.Tickets != want.deleted {
			t.Errorf("run %d deleted %d tickets, want %d", i+1, res.Global.Tickets, want.deleted)
		}
		if got := r.count(`SELECT count(*) FROM ctrlz.auth_tickets`); got != want.left {
			t.Errorf("run %d left %d tickets, want %d", i+1, got, want.left)
		}
	}
}

// One table that cannot be swept (here the worker lost its EXECUTE right on
// the throttle sweep function, as a stuck lock or a timeout would) must not undo or block the
// others (review sms-r1-1, sms-r1-16). Before the fix all seven deletes shared
// one transaction and the failure rolled the other six back.
func TestSlowOneFailingTableStopsNoOtherTable(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `DELETE FROM ctrlz.auth_tickets`)
	r.env.Exec(t, `INSERT INTO ctrlz.auth_tickets (token_hash, kind, expires_at, created_at) VALUES
 (decode(repeat('41', 32), 'hex'), 'mfa', now() - interval '1 minute', now() - interval '6 minutes')`)
	r.env.Exec(t, `INSERT INTO ctrlz.auth_throttle (scope, key, window_start, count) VALUES ('login_net', decode(repeat('43', 32), 'hex'), now() - interval '2 days', 3)`)
	r.env.Exec(t, testpg.PlantCounters(`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date - 3, 'phone', '+989121110077', 1)`))
	r.env.Exec(t, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, expires_at, created_at) VALUES ('+989121110078', 'login', '\x01', now() - interval '25 hours', now() - interval '25 hours')`)
	r.env.Exec(t, `REVOKE EXECUTE ON FUNCTION ctrlz_fn.worker_sweep_throttle(integer) FROM ctrlz_worker`)

	res, err := r.sweeper(sweep.Config{}).Slow(r.env.Ctx)
	if err == nil {
		t.Fatal("a table that could not be swept was reported as swept")
	}
	if !errors.Is(err, store.ErrPermission) {
		t.Errorf("the failure is not the refused grant: %v", err)
	}
	if res.Global.Tickets != 1 || res.Global.OTP != 1 || res.Global.Counters < 1 {
		t.Errorf("the other tables were held back: %+v", res.Global)
	}
	if r.count(`SELECT count(*) FROM ctrlz.auth_tickets WHERE token_hash = decode(repeat('41', 32), 'hex')`) != 0 ||
		r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE phone_e164 = '+989121110078'`) != 0 ||
		r.count(`SELECT count(*) FROM ctrlz.sms_counters WHERE key = '+989121110077'`) != 0 {
		t.Error("the deletes of the healthy tables were rolled back")
	}
	if r.count(`SELECT count(*) FROM ctrlz.auth_throttle WHERE key = decode(repeat('43', 32), 'hex')`) != 1 {
		t.Error("the unsweepable table lost its row")
	}
}

// The fast sweep runs on its own goroutine, so a slow sweep that is stuck does not
// hold back the refund of an expired OTP (review sms-r1-2). The slow sweep is
// stuck here on a table another session holds locked.
func TestFastIsNotHeldBackByAStuckSlowSweep(t *testing.T) {
	r := newRig(t)
	super, err := r.env.DB.Super(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(context.Background())
	if _, err := super.Exec(r.env.Ctx, `BEGIN`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = super.Exec(context.Background(), `ROLLBACK`) }()
	if _, err := super.Exec(r.env.Ctx, `LOCK TABLE ctrlz.auth_tickets IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	s := r.sweeper(sweep.Config{Fast: 50 * time.Millisecond, Slow: time.Hour})
	ctx, cancel := context.WithCancel(r.env.Ctx)
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(300 * time.Millisecond) // the first slow run is now waiting on the lock

	phone := r.env.A.Phone
	id := r.request(phone)
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 second' WHERE id = $1`, id)
	deadline := time.Now().Add(3 * time.Second)
	for r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND delivery_ct IS NOT NULL`, id) != 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if r.count(`SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND delivery_ct IS NOT NULL`, id) != 0 {
		t.Error("an expired unsent OTP was not closed while the slow sweep was stuck")
	}
	if r.counter("global", "all") != 0 {
		t.Error("the expired OTP was not refunded while the slow sweep was stuck")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}
