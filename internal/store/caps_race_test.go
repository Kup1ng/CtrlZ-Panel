package store_test

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The race harness of rule caps-and-endings (P1 auth review, round 5; spec 18.2, 18.3;
// internal/caps).
//
// Every entry of the registry has a driver here that runs N spenders at once, released
// together by a barrier, against the real database, and checks the cap and that at most
// one refund or charge happened per row. A cap or an ending that is decided in two
// statements, or whose answer a caller ignores, loses a race here even if every
// sequential test passes. An entry with no driver fails, and so does a driver with no
// entry, so a new cap cannot be added without being raced.
//
// The drivers are small on purpose: set the limit low, start more spenders than it
// allows, count the wins, and read the row the spenders fought over.

// spenders is how many actors race. It is above every limit the drivers set.
const spenders = 8

// race runs fn(0..n-1) at the same moment: every goroutine waits on the barrier. A
// start barrier alone is not enough for a statement inside a transaction: the
// goroutines open their connections one after the other and the first can finish before
// the last has begun, so the race is never run. hold is a second barrier for the
// moment just before the critical statement: a spender that calls it inside its
// transaction waits there until every spender is inside its own, then all go. It
// passes at once for a spender that comes late (a retry) and gives up after ten
// seconds, so a spender that failed earlier cannot hang the test.
func race(n int, fn func(i int, hold func())) {
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	hold := newBarrier(n, 10*time.Second)
	for i := 0; i < n; i++ {
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			fn(i, hold)
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
}

// newBarrier returns a function that blocks until n callers have arrived or the timeout
// has passed, and lets later callers through at once.
func newBarrier(n int, timeout time.Duration) func() {
	inside := make(chan struct{})
	var arrived atomic.Int32
	return func() {
		if int(arrived.Add(1)) == n {
			close(inside)
		}
		select {
		case <-inside:
		case <-time.After(timeout):
		}
	}
}

// warm opens the lookup connections of the tenant store, which the Auth() calls use and
// no transaction of the harness holds, so that the spenders find them open.
func (e *raceEnv) warm(t *testing.T) {
	t.Helper()
	race(spenders, func(int, func()) {
		if _, err := e.tenant.Auth().PublicConfig(e.ctx); err != nil {
			t.Errorf("warm: %v", err)
		}
	})
}

// raceEnv is one fixture with a store per role, each with a pool wide enough for every
// spender to hold a connection at once (the default pool is 4, which would serialise
// the race).
type raceEnv struct {
	*fixture
	super                 *pgx.Conn
	tenant, worker, admin *store.Store
}

func newRaceEnv(t *testing.T) *raceEnv {
	t.Helper()
	f := newFixture(t)
	open := func(role store.Role) *store.Store {
		cfg := f.db.StoreConfig(role)
		cfg.MaxConns = 10
		s, err := store.Open(f.ctx, cfg)
		if err != nil {
			t.Fatalf("open store as %s: %v", role, err)
		}
		t.Cleanup(s.Close)
		return s
	}
	return &raceEnv{fixture: f, super: f.superConn(t), tenant: open(store.RoleTenant), worker: open(store.RoleWorker), admin: open(store.RoleAdmin)}
}

func (e *raceEnv) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.super.Exec(e.ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *raceEnv) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.super.QueryRow(e.ctx, sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// global runs fn in a global transaction of the store and records an error.
func (e *raceEnv) globalErr(s *store.Store, fn func(g store.GlobalTx) error) error {
	return s.WithGlobal(e.ctx, store.TxOpts{}, fn)
}

// wins counts how many of n racing spenders won, and fails the test on an error.
func wins(t *testing.T, n int, spend func(i int, hold func()) (bool, error)) int {
	t.Helper()
	var won atomic.Int32
	var mu sync.Mutex
	var errs []error
	race(n, func(i int, hold func()) {
		ok, err := spend(i, hold)
		if err != nil {
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
			return
		}
		if ok {
			won.Add(1)
		}
	})
	for _, err := range errs {
		t.Errorf("a spender failed: %v", err)
	}
	return int(won.Load())
}

// ---------------------------------------------------------------------------
// The OTP caps: the per-key counters of auth_otp_issue.

var otpPurposes = []string{"login", "signup", "invite", "reset", "phone_old", "phone_new"}

// otpCapRace sets every OTP cap high except column, which it sets to 3, runs
// spenders that share only that key, and checks that exactly 3 got a code and that a
// refusal left nothing behind on any key.
func otpCapRace(column string, n int, spend func(e *raceEnv, i int) (store.OTPIssued, error)) func(*testing.T, *raceEnv) {
	return func(t *testing.T, e *raceEnv) {
		e.warm(t)
		e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
		e.exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 1000, otp_cap_phone_net = 1000, otp_cap_ip = 1000, otp_cap_net24 = 1000,
  otp_cap_phone_trusted = 1000, otp_cap_net48 = 1000, otp_cap_global = 1000, otp_soft_pct = 100, sms_cost_cap_daily = NULL`)
		e.exec(t, fmt.Sprintf(`UPDATE ctrlz.system_settings SET %s = 3`, column))
		got := wins(t, n, func(i int, _ func()) (bool, error) {
			r, err := spend(e, i)
			return r.Allowed, err
		})
		if got != 3 {
			t.Errorf("%s: %d codes were issued, want exactly 3", column, got)
		}
		if rows := e.count(t, `SELECT count(*) FROM ctrlz.otp_challenges`); rows != 3 {
			t.Errorf("%s: %d challenge rows, want 3", column, rows)
		}
		// A refused request rolls its counters back: the largest counter is the cap.
		if top := e.count(t, `SELECT COALESCE(max(count), 0) FROM ctrlz.sms_counters WHERE scope <> 'global'`); top > 3 {
			t.Errorf("%s: a counter reached %d", column, top)
		}
	}
}

// otpGlobalCapRace is otpCapRace for the global cap, which is not exact since 0055 (db-r18-2, caps.Entry.Slack of
// otp.global): the count is the sum of sixteen shard rows read without a lock, so spenders that all read it
// below the cap before the first commits each add one. What it proves is what the slack declares: nobody is
// is refused below the cap, every code issued is counted once, the excess never passes the spenders in flight,
// and once the burst has committed the cap holds exactly, so a second wave as wide as the first is refused
// whole. That second wave is what bounds the excess (db-r18-19): a count that is at most the number of
// spenders is true by construction, and a cap that let each of the sixteen shards reach it alone would pass
// a first wave and accept the second.
func otpGlobalCapRace(n int, spend func(e *raceEnv, i int) (store.OTPIssued, error)) func(*testing.T, *raceEnv) {
	return func(t *testing.T, e *raceEnv) {
		e.warm(t)
		e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
		e.exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 1000, otp_cap_phone_net = 1000, otp_cap_ip = 1000, otp_cap_net24 = 1000,
  otp_cap_phone_trusted = 1000, otp_cap_net48 = 1000, otp_cap_global = 3, otp_soft_pct = 100, sms_cost_cap_daily = NULL`)
		got := wins(t, n, func(i int, _ func()) (bool, error) {
			r, err := spend(e, i)
			return r.Allowed, err
		})
		if got < 3 {
			t.Errorf("otp_cap_global: %d codes were issued by %d spenders, want at least the cap (3): nobody is refused below it", got, n)
		}
		if rows := e.count(t, `SELECT count(*) FROM ctrlz.otp_challenges`); rows != got {
			t.Errorf("otp_cap_global: %d challenge rows for %d codes", rows, got)
		}
		if sum := e.count(t, `SELECT COALESCE(sum(count), 0) FROM ctrlz.sms_counters WHERE scope = 'global' AND (key = 'all' OR key LIKE 'all:%')`); sum != got {
			t.Errorf("otp_cap_global: the shards add up to %d for %d codes", sum, got)
		}
		second := wins(t, n, func(i int, _ func()) (bool, error) {
			r, err := spend(e, n+i)
			return r.Allowed, err
		})
		if second != 0 {
			t.Errorf("otp_cap_global: %d requests of a second wave were allowed after a first wave of %d committed: the cap must hold exactly once the sum is visible", second, got)
		}
	}
}

func otpIssue(e *raceEnv, phone, purpose string, ip netip.Addr, trusted bool) (store.OTPIssued, error) {
	return e.tenant.Auth().OTPIssue(e.ctx, phone, purpose, []byte{1}, []byte("sealed"), ip, trusted)
}

func phoneN(i int) string { return fmt.Sprintf("+98912111%04d", i) }

// ---------------------------------------------------------------------------

// capDrivers maps each registry entry to the race that proves it.
func capDrivers() map[string]func(*testing.T, *raceEnv) {
	ip := netip.MustParseAddr("198.51.100.7")
	return map[string]func(*testing.T, *raceEnv){
		"otp.phone": otpCapRace("otp_cap_phone", len(otpPurposes), func(e *raceEnv, i int) (store.OTPIssued, error) {
			return otpIssue(e, phoneN(1), otpPurposes[i], netip.MustParseAddr(fmt.Sprintf("198.51.%d.9", 100+i)), false)
		}),
		"otp.phone_net": otpCapRace("otp_cap_phone_net", len(otpPurposes), func(e *raceEnv, i int) (store.OTPIssued, error) {
			return otpIssue(e, phoneN(2), otpPurposes[i], ip, false)
		}),
		"otp.phone_trusted": otpCapRace("otp_cap_phone_trusted", len(otpPurposes), func(e *raceEnv, i int) (store.OTPIssued, error) {
			return otpIssue(e, phoneN(3), otpPurposes[i], ip, true)
		}),
		"otp.ip": otpCapRace("otp_cap_ip", spenders, func(e *raceEnv, i int) (store.OTPIssued, error) {
			return otpIssue(e, phoneN(10+i), "login", ip, false)
		}),
		"otp.net24": otpCapRace("otp_cap_net24", spenders, func(e *raceEnv, i int) (store.OTPIssued, error) {
			return otpIssue(e, phoneN(20+i), "login", netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", 10+i)), false)
		}),
		"otp.net48": otpCapRace("otp_cap_net48", spenders, func(e *raceEnv, i int) (store.OTPIssued, error) {
			return otpIssue(e, phoneN(30+i), "login", netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%d::1", 10+i)), false)
		}),
		"otp.global": otpGlobalCapRace(spenders, func(e *raceEnv, i int) (store.OTPIssued, error) {
			// Known devices pass the soft breaker, so the hard stop is what decides.
			return otpIssue(e, phoneN(40+i), "login", netip.MustParseAddr(fmt.Sprintf("203.0.%d.1", 113+i)), true)
		}),
		"otp.cooldown":         driveOTPCooldown,
		"ip_claims.per_tenant": driveIPClaims,
		"outbox.daily":         driveOutboxDaily,
		"cost.daily":           driveCostDaily,
		"cost.needs_price":     driveCostNeedsPrice,
		"passkeys.per_user":    drivePasskeys,
		"sessions.per_user":    driveSessions,
		"totp.step.user":       driveTOTPUser,
		"totp.step.admin":      driveTOTPAdmin,
		"recovery.code":        driveRecovery,
		"ticket.take":          driveTicket,
		"ticket.spend":         driveTicketSpend,
		"otp.consume":          driveOTPConsume,
		"otp.claim":            driveOTPClaim,
		"outbox.claim":         driveOutboxClaim,
		"otp.ending":           driveOTPEnding,
		"outbox.ending":        driveOutboxEnding,
		"breaker.step":         driveBreaker,
		"gateway.hold":         driveGatewayHold,
		"gateway.unusable":     driveGatewayUnusable,
		"admin_job.run":        driveAdminJob,
	}
}

func TestCapsRaceHarness(t *testing.T) {
	drivers := capDrivers()
	for name, d := range p3Drivers() {
		drivers[name] = d
	}
	for name, d := range p2Drivers() {
		drivers[name] = d
	}
	known := map[string]bool{}
	for _, e := range caps.Entries() {
		known[e.Name] = true
		if drivers[e.Name] == nil {
			t.Errorf("registry entry %s has no race driver; a cap nobody raced is the next finding", e.Name)
		}
	}
	var names []string
	for name := range drivers {
		names = append(names, name)
		if !known[name] {
			t.Errorf("driver %s has no registry entry", name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if !known[name] {
			continue
		}
		t.Run(name, func(t *testing.T) {
			drivers[name](t, newRaceEnv(t))
		})
	}
}

// ---------------------------------------------------------------------------
// The outbox gates.

// driveIPClaims: of the requests that race for claims of one tenant that already holds its seeded claim,
// exactly the room under max_ip_claims is granted. The count is compared by hand in ip_claim_request (not
// with ctrlz.cap_reached: it counts rows, under the tenant's advisory lock), so it is the driver that
// proves the lock, and the registry lists it as the limit the lint cannot compare for itself
// (sms-r16-28).
func driveIPClaims(t *testing.T, e *raceEnv) {
	e.exec(t, `UPDATE ctrlz.system_settings SET registration_mode = 'open'`)
	e.exec(t, `UPDATE ctrlz.plans SET max_ip_claims = 4`)
	e.exec(t, `DELETE FROM ctrlz.tenant_entitlements WHERE tenant_id = $1`, e.A.Tenant)
	held := e.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state <> 'released'`, e.A.Tenant)
	want := 4 - held
	got := wins(t, spenders, func(i int, _ func()) (bool, error) {
		var granted bool
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			r, err := tx.IPClaimRequest(e.A.Endpoint, netip.MustParsePrefix(fmt.Sprintf("203.0.113.%d/32", 100+i)), "manual")
			granted = r.Outcome == "pending_proof"
			return err
		})
		return granted, err
	})
	if got != want {
		t.Errorf("%d claims were granted to a tenant with room for %d under max_ip_claims", got, want)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state <> 'released'`, e.A.Tenant); n != 4 {
		t.Errorf("the tenant holds %d claims, want exactly the limit of 4", n)
	}
}

// driveOTPCooldown: of the issue calls that race for one phone and purpose inside one cooldown window,
// exactly one sends. The window is compared with the timestamp of a challenge the winner inserts, so the
// order comes from the advisory lock of the phone that the issue takes first (migration 0055; before it
// the lock of the one global counter row did the same), and a regression that lost that order would let
// a burst through (sms-r16-28).
func driveOTPCooldown(t *testing.T, e *raceEnv) {
	e.warm(t)
	e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
	e.exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 1000, otp_cap_phone_net = 1000, otp_cap_ip = 1000, otp_cap_net24 = 1000,
  otp_cap_phone_trusted = 1000, otp_cap_net48 = 1000, otp_cap_global = 1000, otp_soft_pct = 100, sms_cost_cap_daily = NULL, otp_cooldown_s = 60`)
	ip := netip.MustParseAddr("198.51.100.61")
	got := wins(t, spenders, func(int, func()) (bool, error) {
		r, err := otpIssue(e, phoneN(61), "login", ip, false)
		return r.Allowed, err
	})
	if got != 1 {
		t.Errorf("%d codes were issued for one phone and purpose inside one cooldown, want exactly 1", got)
	}
	if rows := e.count(t, `SELECT count(*) FROM ctrlz.otp_challenges`); rows != 1 {
		t.Errorf("%d challenge rows, want 1", rows)
	}
}

func driveOutboxDaily(t *testing.T, e *raceEnv) {
	e.exec(t, `UPDATE ctrlz.system_settings SET sms_outbox_cap_daily = 3, sms_cost_cap_daily = NULL`)
	e.exec(t, `TRUNCATE ctrlz.sms_counters`)
	got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) { hold(); w, err = g.OutboxFirstGate(); return err })
		return w.Yes(), err
	})
	if got != 3 {
		t.Errorf("%d messages passed the daily count of 3", got)
	}
	if n := e.count(t, `SELECT count FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'outbox' AND day = (now() AT TIME ZONE 'Asia/Tehran')::date`); n != 3 {
		t.Errorf("the counter reads %d, want 3", n)
	}
	// A cap of 0 refuses the first message, a day with no row yet included.
	e.exec(t, `UPDATE ctrlz.system_settings SET sms_outbox_cap_daily = 0`)
	e.exec(t, `TRUNCATE ctrlz.sms_counters`)
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) { hold(); w, err = g.OutboxFirstGate(); return err })
		return w.Yes(), err
	}); got != 0 {
		t.Errorf("%d messages passed a daily count of 0", got)
	}
}

// driveCostDaily: the money cap is compared by the same expression everywhere, and a
// gate refuses once the day has spent the cap. The price is added after the provider
// accepts, so spenders that passed the gate before the cap was reached still add theirs:
// the excess is bounded by the spenders in flight (caps.Entry.Slack), and it must be
// bounded, which a gate that never refuses would not be.
func driveCostDaily(t *testing.T, e *raceEnv) {
	const price, rounds = 10, 5
	e.exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = 30, sms_outbox_cap_daily = 1000`)
	e.exec(t, `TRUNCATE ctrlz.sms_counters`)
	// A real OTP waiting in the queue: it passed the issue before the day spent its cap, and the
	// claim must not take it once the cap is reached (sms-r16-9).
	e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
	if row, err := e.tenant.Auth().OTPIssue(e.ctx, phoneN(53), "login", []byte{1}, []byte("sealed"), netip.MustParseAddr("198.51.100.53"), false); err != nil || !row.Allowed {
		t.Fatal(row, err)
	}
	var passed atomic.Int32
	wins(t, spenders, func(_ int, hold func()) (bool, error) {
		for r := 0; r < rounds; r++ {
			err := e.globalErr(e.worker, func(g store.GlobalTx) error {
				hold()
				w, err := g.OutboxRetryGate()
				if err != nil {
					return err
				}
				if !w.Yes() {
					return nil
				}
				passed.Add(1)
				return g.CountersAddCost(fmt.Sprint(price))
			})
			if err != nil {
				return false, err
			}
		}
		return true, nil
	})
	var spent float64
	if err := e.super.QueryRow(e.ctx, `SELECT cost::float8 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all'`).Scan(&spent); err != nil {
		t.Fatal(err)
	}
	if spent < 30 || spent > 30+(spenders-1)*price {
		t.Errorf("the day spent %v against a cap of 30 with %d spenders in flight", spent, spenders)
	}
	if int(passed.Load()) >= spenders*rounds {
		t.Errorf("the gate never refused: %d of %d passed", passed.Load(), spenders*rounds)
	}
	// Once the cap is reached every gate, first claim or retry, refuses.
	for _, first := range []bool{true, false} {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
			if first {
				w, err = g.OutboxFirstGate()
			} else {
				w, err = g.OutboxRetryGate()
			}
			return err
		})
		if err != nil || w.Yes() {
			t.Errorf("a gate (first=%v) passed after the day spent its cap: %v", first, err)
		}
	}
	// The claim of an OTP is a gate of the same cap: the queued row is not taken, whatever number of
	// workers ask, and is taken again once the day has room (the cap lifted).
	var claimed atomic.Int32
	race(spenders, func(_ int, hold func()) {
		err := e.globalErr(e.worker, func(g store.GlobalTx) error {
			hold()
			rows, err := g.OTPClaim(5, 3)
			claimed.Add(int32(len(rows)))
			return err
		})
		if err != nil {
			t.Errorf("OTPClaim: %v", err)
		}
	})
	if claimed.Load() != 0 {
		t.Errorf("%d claims took a queued OTP after the day spent its money cap", claimed.Load())
	}
	e.exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = NULL`)
	var after int
	if err := e.globalErr(e.worker, func(g store.GlobalTx) error {
		rows, err := g.OTPClaim(5, 3)
		after = len(rows)
		return err
	}); err != nil || after != 1 {
		t.Errorf("with the cap lifted the queued OTP was claimed %d times (%v), want once", after, err)
	}
}

// ---------------------------------------------------------------------------

func drivePasskeys(t *testing.T, e *raceEnv) {
	// settle keeps every spender's transaction open until all of them have run the
	// statement: a count read under READ COMMITTED sees only rows committed when the
	// statement starts, so without the lock of PasskeyAdd every spender counts 19 and
	// writes. With the lock the others are waiting for it and cannot arrive, so the
	// barrier gives up after a short time and the winner commits.
	settle := func() {}
	add := func(label string, tenant uuid.UUID, user uuid.UUID, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			_, _, w, err = tx.PasskeyAdd(store.Credential{UserID: user, CredentialID: []byte(label), PublicKey: []byte("pk"), RPID: "example.test"}, caps.MaxPasskeys)
			settle()
			return err
		})
		return w.Yes(), err
	}
	have := e.count(t, `SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1`, e.A.User)
	for i := have; i < caps.MaxPasskeys-1; i++ {
		if ok, err := add(fmt.Sprintf("fill-%d", i), e.A.Tenant, e.A.User, func() {}); err != nil || !ok {
			t.Fatalf("filling to %d: %v %v", caps.MaxPasskeys-1, ok, err)
		}
	}
	settle = newBarrier(spenders, 400*time.Millisecond)
	if got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		return add(fmt.Sprintf("last-%d", i), e.A.Tenant, e.A.User, hold)
	}); got != 1 {
		t.Errorf("%d credentials were added into the last slot", got)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.webauthn_credentials WHERE user_id = $1`, e.A.User); n != caps.MaxPasskeys {
		t.Errorf("the user holds %d credentials, want %d", n, caps.MaxPasskeys)
	}
	if n := e.count(t, `SELECT count(DISTINCT name) FROM ctrlz.webauthn_credentials WHERE user_id = $1 AND name LIKE 'Passkey %'`, e.A.User); n != caps.MaxPasskeys-have {
		t.Errorf("%d distinct default names for %d new credentials", n, caps.MaxPasskeys-have)
	}
	settle = func() {}
	if got := wins(t, spenders, func(i int, hold func()) (bool, error) {
		return add(fmt.Sprintf("over-%d", i), e.A.Tenant, e.A.User, hold)
	}); got != 0 {
		t.Errorf("%d credentials were added past the cap", got)
	}
	// Tenant B holds the same cap on its own and is not counted against A's.
	if ok, err := add("b-first", e.B.Tenant, e.B.User, func() {}); err != nil || !ok {
		t.Errorf("tenant B was refused its own first slot: %v %v", ok, err)
	}
	// A user of another tenant is not a slot in this one.
	if ok, err := add("cross", e.B.Tenant, e.A.User, func() {}); err != nil || ok {
		t.Errorf("tenant B added a credential to tenant A's user: %v %v", ok, err)
	}
}

func driveTOTPUser(t *testing.T, e *raceEnv) {
	e.exec(t, `UPDATE ctrlz.users SET totp_last_step = NULL`)
	step := func(tenant, user uuid.UUID, n int64, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, tenant, store.TxOpts{}, func(tx store.Tx) (err error) { hold(); w, err = tx.TOTPStepAccept(user, n); return err })
		return w.Yes(), err
	}
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) { return step(e.A.Tenant, e.A.User, 100, hold) }); got != 1 {
		t.Errorf("%d requests spent the same TOTP step", got)
	}
	// Steps that rise at once: the last one in order wins the column, none goes back.
	wins(t, spenders, func(i int, hold func()) (bool, error) { return step(e.A.Tenant, e.A.User, int64(101+i), hold) })
	if n := e.count(t, `SELECT totp_last_step FROM ctrlz.users WHERE id = $1`, e.A.User); n != 100+spenders {
		t.Errorf("the step went back: %d", n)
	}
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) { return step(e.A.Tenant, e.A.User, 100, hold) }); got != 0 {
		t.Errorf("%d requests spent an old step", got)
	}
	// Tenant B's user has its own step.
	if ok, err := step(e.B.Tenant, e.B.User, 100, func() {}); err != nil || !ok {
		t.Errorf("tenant B's step was spent by tenant A: %v %v", ok, err)
	}
}

func driveTOTPAdmin(t *testing.T, e *raceEnv) {
	var admin uuid.UUID
	if err := e.super.QueryRow(e.ctx, `SELECT id FROM ctrlz.admin_users LIMIT 1`).Scan(&admin); err != nil {
		if err := e.admin.WithGlobal(e.ctx, store.TxOpts{Isolation: store.Serializable}, func(g store.GlobalTx) (err error) {
			admin, _, err = g.AdminBootstrap("racer", secret.New("h"))
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	e.exec(t, `UPDATE ctrlz.admin_users SET totp_last_step = NULL`)
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.admin, func(g store.GlobalTx) (err error) { hold(); w, err = g.AdminTOTPStepAccept(admin, 77); return err })
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d requests spent the same admin TOTP step", got)
	}
}

func driveRecovery(t *testing.T, e *raceEnv) {
	h := hash("race-code")
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if _, err := tx.UserKeyShare(e.A.User); err != nil {
			return err
		}
		return tx.RecoveryCodesReplace(e.A.User, [][]byte{h})
	}); err != nil {
		t.Fatal(err)
	}
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
			hold()
			// The routes lock the user first; a key share is the weakest lock that
			// satisfies the lock order and still lets the spenders run together.
			if _, err = tx.UserKeyShare(e.A.User); err != nil {
				return err
			}
			w, err = tx.RecoveryCodeUse(e.A.User, h)
			return err
		})
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d requests spent the same recovery code", got)
	}
	// Tenant B cannot spend A's code.
	if err := e.tenant.WithTenant(e.ctx, e.B.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if _, err := tx.UserKeyShare(e.A.User); err != nil {
			return err
		}
		w, err := tx.RecoveryCodeUse(e.A.User, h)
		if w.Yes() {
			t.Error("tenant B spent tenant A's recovery code")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func driveTicket(t *testing.T, e *raceEnv) {
	h := sha32(201)
	if _, ok, err := e.tenant.Auth().TicketPut(e.ctx, store.NewTicket{TokenHash: h, Kind: store.TicketReset, Tenant: e.A.Tenant, User: e.A.User, TTL: 5 * time.Minute}); err != nil || !ok {
		t.Fatalf("TicketPut: %v %v", ok, err)
	}
	e.warm(t)
	if got := wins(t, spenders, func(int, func()) (bool, error) {
		_, w, err := e.tenant.Auth().TicketTake(e.ctx, h, store.TicketReset)
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d requests took the same ticket", got)
	}
}

func driveOTPConsume(t *testing.T, e *raceEnv) {
	e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
	code := []byte("the-code-hash")
	row, err := e.tenant.Auth().OTPIssue(e.ctx, phoneN(50), "login", code, []byte("sealed"), netip.MustParseAddr("198.51.100.50"), false)
	if err != nil || !row.Allowed {
		t.Fatal(row, err)
	}
	e.warm(t)
	var ok atomic.Int32
	race(spenders, func(int, func()) {
		out, err := e.tenant.Auth().OTPConsume(e.ctx, row.ID, phoneN(50), "login", code)
		if err != nil {
			t.Errorf("OTPConsume: %v", err)
		}
		if out == "ok" {
			ok.Add(1)
		}
	})
	if ok.Load() != 1 {
		t.Errorf("%d requests consumed the same code", ok.Load())
	}
}

// driveOTPClaim: one worker takes a row per lease, and no row is taken past its ceiling.
func driveOTPClaim(t *testing.T, e *raceEnv) {
	e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
	row, err := e.tenant.Auth().OTPIssue(e.ctx, phoneN(51), "login", []byte{1}, []byte("sealed"), netip.MustParseAddr("198.51.100.51"), false)
	if err != nil || !row.Allowed {
		t.Fatal(row, err)
	}
	const ceiling = 3
	claim := func() int {
		var n atomic.Int32
		race(spenders, func(_ int, hold func()) {
			err := e.globalErr(e.worker, func(g store.GlobalTx) error {
				hold()
				rows, err := g.OTPClaim(5, ceiling)
				n.Add(int32(len(rows)))
				return err
			})
			if err != nil {
				t.Errorf("OTPClaim: %v", err)
			}
		})
		return int(n.Load())
	}
	for attempt := 1; attempt <= ceiling; attempt++ {
		if got := claim(); got != 1 {
			t.Errorf("claim %d: %d workers took the row", attempt, got)
		}
		e.exec(t, `UPDATE ctrlz.otp_challenges SET delivery_claimed_until = now() - interval '1 second'`)
	}
	if got := claim(); got != 0 {
		t.Errorf("a row past its ceiling of %d claims was taken %d times", ceiling, got)
	}
}

func driveOutboxClaim(t *testing.T, e *raceEnv) {
	e.exec(t, `DELETE FROM ctrlz.sms_outbox`)
	id := uuid.New()
	if err := e.globalErr(e.admin, func(g store.GlobalTx) error {
		return g.SMSOutboxInsert(store.NewOutbox{ID: id, Kind: "invite", Phone: phoneN(52), TemplateKey: "invite", Locale: "fa", ParamsCT: []byte("ct")})
	}); err != nil {
		t.Fatal(err)
	}
	e.exec(t, `UPDATE ctrlz.sms_outbox SET attempts = $1`, store.OutboxMaxAttempts-1)
	claim := func() int {
		var n atomic.Int32
		race(spenders, func(_ int, hold func()) {
			err := e.globalErr(e.worker, func(g store.GlobalTx) error {
				hold()
				rows, err := g.OutboxClaim(5)
				n.Add(int32(len(rows)))
				return err
			})
			if err != nil {
				t.Errorf("OutboxClaim: %v", err)
			}
		})
		return int(n.Load())
	}
	if got := claim(); got != 1 {
		t.Errorf("%d workers took the last claim", got)
	}
	e.exec(t, `UPDATE ctrlz.sms_outbox SET claimed_until = now() - interval '1 second'`)
	if got := claim(); got != 0 {
		t.Errorf("a message past %d claims was taken %d times", store.OutboxMaxAttempts, got)
	}
	if n := e.count(t, `SELECT attempts FROM ctrlz.sms_outbox WHERE id = $1`, id); n != store.OutboxMaxAttempts {
		t.Errorf("attempts reads %d, want %d", n, store.OutboxMaxAttempts)
	}
}

// driveOTPEnding: one expired row that three kinds of actor all end (the worker's finish,
// the fast sweep, the exhausted pass), while a second row of the same phone keeps one
// slot on every shared counter. A double refund would take that slot too, and the
// counters, which never go below zero, would hide it unless the second row holds one.
func driveOTPEnding(t *testing.T, e *raceEnv) {
	e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
	ip := netip.MustParseAddr("198.51.100.60")
	phone := phoneN(60)
	a, err := e.tenant.Auth().OTPIssue(e.ctx, phone, "login", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !a.Allowed {
		t.Fatal(a, err)
	}
	b, err := e.tenant.Auth().OTPIssue(e.ctx, phone, "signup", []byte{1}, []byte("sealed"), ip, false)
	if err != nil || !b.Allowed {
		t.Fatal(b, err)
	}
	// Row a is the one every actor wants: expired, out of claims, no live claim.
	e.exec(t, `UPDATE ctrlz.otp_challenges SET expires_at = now() - interval '1 second', delivery_attempts = 3, delivery_claimed_until = NULL, created_at = created_at - interval '1 minute' WHERE id = $1`, a.ID)
	var refunds atomic.Int32
	race(spenders, func(i int, hold func()) {
		err := e.globalErr(e.worker, func(g store.GlobalTx) error {
			hold()
			switch i % 3 {
			case 0: // the worker's finish
				w, err := g.OTPDeliveryClear(a.ID)
				if err != nil {
					return err
				}
				if w.Yes() {
					refunds.Add(1)
					return g.CountersRefund(time.Now())
				}
			case 1: // the fast sweep
				n, _, err := g.OTPExpireUndeliveredBatch()
				refunds.Add(int32(n))
				return err
			default: // the pass that closes rows out of claims
				n, err := g.OTPEndExhausted(3)
				refunds.Add(int32(n))
				return err
			}
			return nil
		})
		if err != nil {
			t.Errorf("an ending failed: %v", err)
		}
	})
	if refunds.Load() != 1 {
		t.Errorf("%d actors refunded the same row", refunds.Load())
	}
	// Only the global slot goes back. The phone and the network stay spent for both rows (2): a
	// refund of them would leave a real row's counters below a decoy's (sms-r6-1), and a second
	// refund of the global slot would take the other row's (it reads 0 instead of 1).
	for _, c := range []struct {
		scope, key string
		want       int
	}{{"phone", phone, 2}, {"global", "all", 1}, {"ip", "198.51.100.0/24", 2}} {
		// The world-wide count is the sum of its sixteen shards (db-r18-2), any other key is its own row.
		if n := e.count(t, `SELECT COALESCE(sum(count), 0) FROM ctrlz.sms_counters WHERE scope = $1 AND (key = $2 OR ($1 = 'global' AND $2 = 'all' AND key LIKE 'all:%')) AND day = (now() AT TIME ZONE 'Asia/Tehran')::date`, c.scope, c.key); n != c.want {
			t.Errorf("%s %s reads %d after one row of two ended, want %d", c.scope, c.key, n, c.want)
		}
	}
	if e.count(t, `SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND delivery_ct IS NULL`, a.ID) != 1 {
		t.Error("the ended row still holds its code")
	}
	if e.count(t, `SELECT count(*) FROM ctrlz.otp_challenges WHERE id = $1 AND delivery_ct IS NOT NULL`, b.ID) != 1 {
		t.Error("the other row lost its code")
	}
}

func driveOutboxEnding(t *testing.T, e *raceEnv) {
	e.exec(t, `DELETE FROM ctrlz.sms_outbox`)
	id := uuid.New()
	if err := e.globalErr(e.admin, func(g store.GlobalTx) error {
		return g.SMSOutboxInsert(store.NewOutbox{ID: id, Kind: "invite", Phone: phoneN(70), TemplateKey: "invite", Locale: "fa", ParamsCT: []byte("ct")})
	}); err != nil {
		t.Fatal(err)
	}
	// Old enough for the stale sweep, with no live claim.
	e.exec(t, `UPDATE ctrlz.sms_outbox SET created_at = now() - interval '2 hours', claimed_until = NULL`)
	var mu sync.Mutex
	var enders []string
	race(spenders, func(i int, hold func()) {
		err := e.globalErr(e.worker, func(g store.GlobalTx) error {
			hold()
			switch i % 3 {
			case 0:
				w, err := g.OutboxFinish(id, "sent", nil)
				if w.Yes() {
					mu.Lock()
					enders = append(enders, "sent")
					mu.Unlock()
				}
				return err
			case 1:
				w, err := g.OutboxFinish(id, "failed", word("x"))
				if w.Yes() {
					mu.Lock()
					enders = append(enders, "failed")
					mu.Unlock()
				}
				return err
			}
			n, err := g.OutboxFailStaleBatch(1000)
			if n > 0 {
				mu.Lock()
				enders = append(enders, "stale")
				mu.Unlock()
			}
			return err
		})
		if err != nil {
			t.Errorf("an ending failed: %v", err)
		}
	})
	if len(enders) != 1 {
		t.Fatalf("%d actors ended the same message: %v", len(enders), enders)
	}
	var state, lastError string
	var sentAt *time.Time
	if err := e.super.QueryRow(e.ctx, `SELECT state, COALESCE(last_error, ''), sent_at FROM ctrlz.sms_outbox WHERE id = $1`, id).Scan(&state, &lastError, &sentAt); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{"sent": {"sent", ""}, "failed": {"failed", "x"}, "stale": {"failed", "timeout"}}[enders[0]]
	if state != want[0] || lastError != want[1] || (state == "sent") != (sentAt != nil) {
		t.Errorf("the row reads %s/%q (sent_at %v) but %s ended it", state, lastError, sentAt, enders[0])
	}
}

func driveBreaker(t *testing.T, e *raceEnv) {
	var gw uuid.UUID
	e.exec(t, `DELETE FROM ctrlz.sms_gateways`)
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.sms_gateways (provider, role, consecutive_failures) VALUES ('sms_ir', 'primary', 2) RETURNING id`).Scan(&gw); err != nil {
		t.Fatal(err)
	}
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
			hold()
			w, err = g.GatewayFailed(gw, word("transient:http_500"), true)
			return err
		})
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d failures of one round each stepped the breaker", got)
	}
	var n int
	var open float64
	if err := e.super.QueryRow(e.ctx, `SELECT consecutive_failures, extract(epoch FROM breaker_open_until - now())::float8 FROM ctrlz.sms_gateways WHERE id = $1`, gw).Scan(&n, &open); err != nil {
		t.Fatal(err)
	}
	if n != 3 || open < 45 || open > 65 {
		t.Errorf("after one round the breaker reads %d failures, open for %.0fs; want 3 and about 60", n, open)
	}
	// A failure that does not count toward the breaker never steps it.
	var w store.Won
	if err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
		w, err = g.GatewayFailed(gw, word("config:no_template"), false)
		return err
	}); err != nil || w.Yes() {
		t.Errorf("an uncounted failure stepped the breaker: %v", err)
	}
}

func driveAdminJob(t *testing.T, e *raceEnv) {
	var job uuid.UUID
	if err := e.globalErr(e.admin, func(g store.GlobalTx) (err error) {
		job, err = g.AdminJobInsert("webauthn_rp_change", []byte(`{"rp_id":"panel.localhost"}`), uuid.Nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Starts and two kinds of finish at once. Starting a job that is still active is
	// allowed to repeat (a job is safe to run again); finishing it is not.
	var mu sync.Mutex
	var finishers []string
	race(spenders, func(i int, hold func()) {
		err := e.globalErr(e.worker, func(g store.GlobalTx) error {
			hold()
			if i%4 == 0 {
				_, err := g.AdminJobStart(job)
				return err
			}
			state := "done"
			if i%2 == 0 {
				state = "failed"
			}
			w, err := g.AdminJobFinish(job, state, nil)
			if w.Yes() {
				mu.Lock()
				finishers = append(finishers, state)
				mu.Unlock()
			}
			return err
		})
		if err != nil {
			t.Errorf("a job call failed: %v", err)
		}
	})
	if len(finishers) != 1 {
		t.Fatalf("%d workers finished the same job: %v", len(finishers), finishers)
	}
	if st := e.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE id = $1 AND state = $2`, job, finishers[0]); st != 1 {
		t.Errorf("the job's state is not the winner's (%s)", finishers[0])
	}
	// A job that is finished cannot be started from an old list.
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) { hold(); w, err = g.AdminJobStart(job); return err })
		return w.Yes(), err
	}); got != 0 {
		t.Errorf("a finished job was started %d times", got)
	}
}

// driveTicketSpend: a sealed passkey ceremony has no row until it is used, and of several
// finishes that carry the same ticket exactly one records it.
func driveTicketSpend(t *testing.T, e *raceEnv) {
	h := sha32(202)
	e.warm(t)
	if got := wins(t, spenders, func(int, func()) (bool, error) {
		w, err := e.tenant.Auth().TicketSpend(e.ctx, h, 5*time.Minute)
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d requests spent the same ceremony ticket", got)
	}
}

// driveCostNeedsPrice: a money cap and a routed gateway without a price must never be committed
// together (round 6, admin-r6-3). Two writers each write one table, then ask the invariant, and
// neither commits before the other has asked, so without the settings row lock inside
// SMSPriceMissingUnderCap each sees the other's old state and both commit. With it the second
// asker waits for the first's commit and is refused. The two writers are the limits writer and,
// in turn, a price removal and an unpriced gateway being routed.
func driveCostNeedsPrice(t *testing.T, e *raceEnv) {
	for name, b := range map[string]func(g store.GlobalTx) error{
		"price removal": func(g store.GlobalTx) error {
			_, err := g.SMSGatewaySetCost(uuid.MustParse("00000000-0000-7000-8000-0000000000a1"), nil)
			return err
		},
		"routing": func(g store.GlobalTx) error {
			failed, err := g.SMSRoutingSetNamed("", "sms_ir")
			if err == nil && failed != "" {
				err = fmt.Errorf("routing refused: %s", failed)
			}
			return err
		},
	} {
		e.exec(t, `DELETE FROM ctrlz.sms_gateways`)
		e.exec(t, `UPDATE ctrlz.system_settings SET sms_cost_cap_daily = NULL`)
		e.exec(t, `INSERT INTO ctrlz.sms_gateways (id, provider, role, credentials_ct, cost_per_message)
  VALUES ('00000000-0000-7000-8000-0000000000a1', 'melipayamak', 'primary', '\x01', 95),
         ('00000000-0000-7000-8000-0000000000a2', 'sms_ir', 'disabled', '\x01', NULL)`)
		var limits store.SMSLimits
		if err := e.globalErr(e.admin, func(g store.GlobalTx) (err error) { limits, err = g.SMSLimitsGet(); return }); err != nil {
			t.Fatal(err)
		}
		dailyCap := "250000"
		limits.CostCapDaily = &dailyCap

		aWrote, bWrote, aAsked, bAsked := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		wait := func(ch chan struct{}, limit time.Duration) {
			select {
			case <-ch:
			case <-time.After(limit):
			}
		}
		refused := func(g store.GlobalTx) error {
			missing, err := g.SMSPriceMissingUnderCap()
			if err == nil && missing {
				err = errPriceRequired
			}
			return err
		}
		errA, errB := make(chan error, 1), make(chan error, 1)
		go func() {
			errA <- e.globalErr(e.admin, func(g store.GlobalTx) error {
				if err := g.SMSLimitsSet(limits); err != nil {
					return err
				}
				close(aWrote)
				wait(bWrote, 20*time.Second)
				err := refused(g)
				close(aAsked)
				wait(bAsked, 2*time.Second) // with the lock the other writer is waiting for this commit
				return err
			})
		}()
		go func() {
			errB <- e.globalErr(e.admin, func(g store.GlobalTx) error {
				wait(aWrote, 20*time.Second)
				if err := b(g); err != nil {
					return err
				}
				close(bWrote)
				err := refused(g)
				close(bAsked)
				wait(aAsked, 20*time.Second)
				return err
			})
		}()
		ea, eb := <-errA, <-errB
		if ea != nil && eb != nil {
			t.Fatalf("%s: both writers were refused (%v, %v): the race was lost and shows nothing", name, ea, eb)
		}
		bad := e.count(t, `SELECT count(*) FROM ctrlz.sms_gateways g, ctrlz.system_settings s
WHERE s.sms_cost_cap_daily IS NOT NULL AND g.role IN ('primary', 'fallback') AND (g.cost_per_message IS NULL OR g.cost_per_message = 0)`)
		if bad > 0 {
			t.Errorf("%s: a money cap is armed and %d routed gateway(s) have no price (a: %v, b: %v)", name, bad, ea, eb)
		}
	}
}

var errPriceRequired = fmt.Errorf("price required")

// driveGatewayHold: the calls in flight that all met one refusal put one hold between them, a hold
// for credentials the row no longer has is never put, and of the workers that all saw the accepted
// test send one lifts the hold (sms-r12-3).
func driveGatewayHold(t *testing.T, e *raceEnv) {
	var gw uuid.UUID
	e.exec(t, `DELETE FROM ctrlz.sms_gateways`)
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.sms_gateways (provider, role, credentials_ct) VALUES ('sms_ir', 'primary', '\x0102') RETURNING id`).Scan(&gw); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte{1, 2})
	stale := sha256.Sum256([]byte{9})
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
			hold()
			w, err = g.GatewayHold(gw, sum[:], word("10"))
			return err
		})
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d refusals of one gateway each put the hold", got)
	}
	var w store.Won
	if err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
		w, err = g.GatewayRelease(gw, stale[:])
		return err
	}); err != nil || w.Yes() {
		t.Errorf("a release for other credentials lifted the hold: %v", err)
	}
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
			hold()
			w, err = g.GatewayRelease(gw, sum[:])
			return err
		})
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d accepted test sends each lifted the hold", got)
	}
	if err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
		w, err = g.GatewayHold(gw, stale[:], word("10"))
		return err
	}); err != nil || w.Yes() {
		t.Errorf("a hold for credentials the row does not have was put: %v", err)
	}
}

// driveGatewayUnusable races the worker's judgement that no sender can be built (sms-r15-1): of
// several workers that judged the same credentials one writes it, a judgement for other credentials
// is never written, and of several that all built the gateway one takes it back.
func driveGatewayUnusable(t *testing.T, e *raceEnv) {
	var gw uuid.UUID
	e.exec(t, `DELETE FROM ctrlz.sms_gateways`)
	if err := e.super.QueryRow(e.ctx, `INSERT INTO ctrlz.sms_gateways (provider, role, credentials_ct) VALUES ('sms_ir', 'primary', '\x0102') RETURNING id`).Scan(&gw); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte{1, 2})
	stale := sha256.Sum256([]byte{9})
	var w store.Won
	if err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
		w, err = g.GatewayUnusable(gw, stale[:])
		return err
	}); err != nil || w.Yes() {
		t.Errorf("a judgement for credentials the row does not have was written: %v", err)
	}
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
			hold()
			w, err = g.GatewayUnusable(gw, sum[:])
			return err
		})
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d workers each wrote the judgement of one gateway", got)
	}
	if err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
		w, err = g.GatewayUsable(gw, stale[:])
		return err
	}); err != nil || w.Yes() {
		t.Errorf("a stale build took back a judgement about other credentials (sms-r16-2): %v", err)
	}
	if got := wins(t, spenders, func(_ int, hold func()) (bool, error) {
		var w store.Won
		err := e.globalErr(e.worker, func(g store.GlobalTx) (err error) {
			hold()
			w, err = g.GatewayUsable(gw, sum[:])
			return err
		})
		return w.Yes(), err
	}); got != 1 {
		t.Errorf("%d workers each took the judgement back", got)
	}
}

// driveSessions races the cap on live sessions per account (tenant-r18-2): spenders that each insert a session
// and then trim, all inside their transactions at the moment the first trims, so each trim is blind to the rows
// the others have not committed. The user row lock the trim takes is what makes the last committer count them
// all: the account ends at exactly the cap, the newest sessions survive, the refresh tokens of the ended ones
// end with them, and another tenant's sessions are not counted against A.
func driveSessions(t *testing.T, e *raceEnv) {
	live := func(user uuid.UUID) int {
		return e.count(t, `SELECT count(*) FROM ctrlz.sessions WHERE user_id = $1 AND revoked_at IS NULL`, user)
	}
	open := func(tenant, user uuid.UUID, label string, hold func()) error {
		return e.tenant.WithTenant(e.ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
			now := time.Now()
			id, err := tx.SessionCreate(store.NewSession{UserID: user, TokenHash: []byte(label), IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(2 * time.Hour), AuthMethod: "password", At: now})
			if err != nil {
				return err
			}
			if _, err := tx.RefreshCreate(store.NewRefresh{SessionID: id, UserID: user, FamilyID: uuid.New(), TokenHash: []byte("r-" + label), ExpiresAt: now.Add(time.Hour)}); err != nil {
				return err
			}
			hold()
			_, err = tx.SessionsTrim(user, caps.MaxSessions, now)
			return err
		})
	}
	for i := live(e.A.User); i < caps.MaxSessions-3; i++ {
		if err := open(e.A.Tenant, e.A.User, fmt.Sprintf("fill-%d", i), func() {}); err != nil {
			t.Fatalf("filling: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := open(e.B.Tenant, e.B.User, fmt.Sprintf("b-%d", i), func() {}); err != nil {
			t.Fatalf("tenant B: %v", err)
		}
	}
	bLive := live(e.B.User)
	race(spenders, func(i int, hold func()) {
		if err := open(e.A.Tenant, e.A.User, fmt.Sprintf("race-%d", i), hold); err != nil {
			t.Errorf("spender %d: %v", i, err)
		}
	})
	if n := live(e.A.User); n != caps.MaxSessions {
		t.Errorf("the account holds %d live sessions after %d racing logins, want exactly the cap %d", n, spenders, caps.MaxSessions)
	}
	if n := e.count(t, `SELECT count(*) FROM ctrlz.refresh_tokens r JOIN ctrlz.sessions s ON s.id = r.session_id
		WHERE s.user_id = $1 AND s.revoked_at IS NOT NULL AND r.revoked_at IS NULL`, e.A.User); n != 0 {
		t.Errorf("%d refresh tokens of ended sessions are still live", n)
	}
	if n := live(e.B.User); n != bLive {
		t.Errorf("tenant B holds %d live sessions, had %d: a trim of A touched B", n, bLive)
	}
	// Another tenant's user is not trimmed through A's tenant.
	if err := e.tenant.WithTenant(e.ctx, e.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		ended, err := tx.SessionsTrim(e.B.User, 1, time.Now())
		if len(ended) != 0 {
			t.Errorf("tenant A trimmed %d sessions of a user of tenant B", len(ended))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n := live(e.B.User); n != bLive {
		t.Errorf("tenant B lost sessions to a trim from tenant A: %d, had %d", n, bLive)
	}
}
