package store_test

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// One probe round is one escalation step, however many rows of the pass fail at
// once (review sms-r2-1). The router checks the breaker against its snapshot
// before the call, so when a pause ends, up to Concurrency rows reach the
// gateway together. If each failure escalated, a gateway that had just opened
// its breaker for 60 seconds would jump to 15 minutes in one round.
func TestGatewayFailuresInOneRoundEscalateOnce(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	var gw uuid.UUID
	if _, err := super.Exec(f.ctx, `DELETE FROM ctrlz.sms_gateways`); err != nil {
		t.Fatal(err)
	}
	if err := super.QueryRow(f.ctx, `INSERT INTO ctrlz.sms_gateways (provider, role) VALUES ('sms_ir', 'primary') RETURNING id`).Scan(&gw); err != nil {
		t.Fatal(err)
	}
	fail := func(n int) {
		t.Helper()
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
					_, err := g.GatewayFailed(gw, word("transient:http_500"), true)
					return err
				}); err != nil {
					t.Errorf("GatewayFailed: %v", err)
				}
			}()
		}
		wg.Wait()
	}
	state := func() (int, time.Duration) {
		t.Helper()
		var n int
		var secs *float64
		if err := super.QueryRow(f.ctx, `SELECT consecutive_failures, extract(epoch FROM breaker_open_until - now())::float8 FROM ctrlz.sms_gateways WHERE id = $1`, gw).Scan(&n, &secs); err != nil {
			t.Fatal(err)
		}
		if secs == nil {
			return n, 0
		}
		return n, time.Duration(*secs * float64(time.Second))
	}
	expire := func() {
		t.Helper()
		if _, err := super.Exec(f.ctx, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() - interval '1 second' WHERE id = $1`, gw); err != nil {
			t.Fatal(err)
		}
	}
	within := func(d, want time.Duration) bool { return d > want-10*time.Second && d <= want+time.Second }

	// First opening: four concurrent failures on a closed gateway are three
	// counted failures and a 60 second pause, not 120.
	fail(4)
	if n, d := state(); n != 3 || !within(d, 60*time.Second) {
		t.Fatalf("first opening: %d failures, pause %v, want 3 and 60 s", n, d)
	}
	// The pause ends and a pass of four rows probes the gateway, all four fail:
	// one step (120 s), not four (the cap of 15 minutes).
	expire()
	fail(4)
	if n, d := state(); n != 4 || !within(d, 120*time.Second) {
		t.Fatalf("first probe round: %d failures, pause %v, want 4 and 120 s", n, d)
	}
	// And again, one step each round, up to the cap of 15 minutes.
	for i, round := range []time.Duration{240 * time.Second, 480 * time.Second, 900 * time.Second, 900 * time.Second} {
		expire()
		fail(4)
		if n, d := state(); n != 5+i || !within(d, round) {
			t.Fatalf("probe round %d: %d failures, pause %v, want %v", i+2, n, d, round)
		}
	}
	// A failure that does not count never moves the breaker, open or not.
	expire()
	before, _ := state()
	if err := worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := g.GatewayFailed(gw, word("config:no_template"), false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n, d := state(); n != before || d > 0 {
		t.Errorf("an uncounted failure changed the breaker: %d %v", n, d)
	}
}

// A cap of 0 means "stop all spending". auth_otp_issue refuses at 0 >= 0 even
// when no cost row exists yet, and the worker's check must too, or the first
// outbox message of the Tehran day passes (sms-r2-6).
func TestCostCapOfZeroBindsBeforeTheFirstCostRow(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, `TRUNCATE ctrlz.sms_counters`); err != nil {
		t.Fatal(err)
	}
	reached := func() bool {
		var b bool
		f.global(t, worker, func(g store.GlobalTx) {
			gate, err := g.OutboxRetryGate()
			if err != nil {
				t.Fatal(err)
			}
			b = !gate.Yes()
		})
		return b
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 0`); err != nil {
		t.Fatal(err)
	}
	if !reached() {
		t.Error("a cap of 0 let the first message of the day through")
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 100`); err != nil {
		t.Fatal(err)
	}
	if reached() {
		t.Error("a cap of 100 was reached with nothing spent")
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = NULL`); err != nil {
		t.Fatal(err)
	}
	if reached() {
		t.Error("no cap, yet reached")
	}
}

// The worker clears a row it finished, but a row the user has consumed is not
// refundable: the code reached them (sms-r2-8).
func TestOTPDeliveryClearOfAConsumedRowIsNotRefundable(t *testing.T) {
	f := newFixture(t)
	tenant := f.db.Store(f.ctx, t, store.RoleTenant)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	ip := netip.MustParseAddr("198.51.100.78")
	row, err := tenant.Auth().OTPIssue(f.ctx, "+989121110041", "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !row.Allowed {
		t.Fatal(row, err)
	}
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.otp_challenges SET consumed_at = now() WHERE id = $1`, row.ID); err != nil {
		t.Fatal(err)
	}
	f.global(t, worker, func(g store.GlobalTx) {
		if ok, err := g.OTPDeliveryClear(row.ID); err != nil || ok.Yes() {
			t.Errorf("clear of a consumed row: refundable %v, %v", ok, err)
		}
	})
	var sealed bool
	if err := super.QueryRow(f.ctx, `SELECT delivery_ct IS NOT NULL FROM ctrlz.otp_challenges WHERE id = $1`, row.ID).Scan(&sealed); err != nil || sealed {
		t.Errorf("the consumed row still holds its code (%v, %v)", sealed, err)
	}
}

// The fast OTP sweep ends a bounded batch per call, in its own transaction, so a
// backlog after a long outage cannot hold row locks on the shared counters for as
// long as it takes to refund thousands of rows (sms-r2-4).
func TestOTPExpireUndeliveredEndsABoundedBatch(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	if _, err := super.Exec(f.ctx, `DELETE FROM ctrlz.otp_challenges`); err != nil {
		t.Fatal(err)
	}
	total := store.OTPEndBatch + 50
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, created_at, ip)
SELECT '+9891211' || lpad(n::text, 5, '0'), 'login', '\x01', '\x02', now() - interval '1 minute', now() - interval '6 minutes', '198.51.100.9'
FROM generate_series(1, $1) n`, total); err != nil {
		t.Fatal(err)
	}
	// Ten of them were consumed: cleared, never refunded.
	if _, err := super.Exec(f.ctx, `UPDATE ctrlz.otp_challenges SET consumed_at = now() - interval '4 minutes' WHERE id IN (SELECT id FROM ctrlz.otp_challenges ORDER BY created_at, id LIMIT 10)`); err != nil {
		t.Fatal(err)
	}
	var refunded, calls int
	for more := true; more && calls < 10; calls++ {
		f.global(t, worker, func(g store.GlobalTx) {
			var n int
			var err error
			if n, more, err = g.OTPExpireUndeliveredBatch(); err != nil {
				t.Fatal(err)
			}
			if n > store.OTPEndBatch {
				t.Errorf("one call refunded %d rows, over the batch of %d", n, store.OTPEndBatch)
			}
			refunded += n
		})
	}
	if calls != 2 {
		t.Errorf("%d calls for %d rows with a batch of %d, want 2", calls, total, store.OTPEndBatch)
	}
	if refunded != total-10 {
		t.Errorf("refunded %d, want %d (the consumed ones are cleared, not refunded)", refunded, total-10)
	}
	var left int
	if err := super.QueryRow(f.ctx, `SELECT count(*) FROM ctrlz.otp_challenges WHERE delivery_ct IS NOT NULL`).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d rows still hold a code (%v)", left, err)
	}
}

// The tenant sweep deletes in bounded batches, one transaction each, and only in
// the tenant it was called for (sms-r2-4, and the two-tenant rule).
func TestSweepTenantBatchIsBoundedAndTenantScoped(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	for _, ids := range []struct{ tenant, user uuid.UUID }{{f.A.Tenant, f.A.User}, {f.B.Tenant, f.B.User}} {
		if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, at)
SELECT $1, $2, 'old', now() - interval '400 days' FROM generate_series(1, 25)`, ids.tenant, ids.user); err != nil {
			t.Fatal(err)
		}
	}
	count := func(tenant uuid.UUID) int {
		var n int
		if err := super.QueryRow(f.ctx, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'old'`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	var got []int
	for i := 0; i < 3; i++ {
		f.inTenant(t, worker, f.A.Tenant, func(tx store.Tx) {
			n, err := tx.SweepTenantBatch(store.TenantSweepAudit, 10, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, n)
		})
	}
	if got[0] != 10 || got[1] != 10 || got[2] != 5 {
		t.Errorf("batches: %v, want 10 10 5", got)
	}
	if count(f.A.Tenant) != 0 || count(f.B.Tenant) != 25 {
		t.Errorf("A has %d old rows, B has %d, want 0 and 25", count(f.A.Tenant), count(f.B.Tenant))
	}
	f.inTenant(t, worker, f.A.Tenant, func(tx store.Tx) {
		if _, err := tx.SweepTenantBatch(store.TenantSweepStep(99), 10, time.Now()); err == nil {
			t.Error("an unknown step was accepted")
		}
		if _, err := tx.SweepTenantBatch(store.TenantSweepAudit, 0, time.Now()); err == nil {
			t.Error("a batch of 0 was accepted")
		}
	})
}
