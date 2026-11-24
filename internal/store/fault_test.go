package store_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// The fault tests of the Full review tier: what the store does when the
// database misbehaves, against a real Postgres. A tenant-scoped transaction
// that dies, a server that restarts under an open pool, a pool with no free
// connection, and a connection that stops answering. In each, the caller gets
// an error rather than a hang or a wrong answer, nothing commits that should
// not, and the next request still runs for the right tenant.

const insertFaultKey = `INSERT INTO ctrlz.idempotency_keys (tenant_id, key, route, request_hash, expires_at)
VALUES ($1, $2, '/fault', '\x01', now() + interval '1 day')`

func faultKeys(t *testing.T, f *fixture) int {
	t.Helper()
	super, err := f.db.Super(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(f.ctx)
	var n int
	if err := super.QueryRow(f.ctx, "SELECT count(*) FROM ctrlz.idempotency_keys WHERE route = '/fault'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestBackendTerminatedMidTransaction: the server kills the session in the
// middle of a WithTenant transaction, as an admin or the OOM killer would. The
// caller gets an error, the write made before the kill is not there, and the
// next WithTenant on the same pool, which has one connection and so must make a
// new one, runs for its own tenant with no setting left behind.
func TestBackendTerminatedMidTransaction(t *testing.T) {
	for _, useAfterKill := range []bool{false, true} {
		name := "commit after the kill"
		if useAfterKill {
			name = "statement after the kill"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			s := oneConn(t, f, store.RoleTenant)
			super, err := f.db.Super(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer super.Close(f.ctx)

			err = s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
				if _, err := tx.DB().Exec(tx.Context(), insertFaultKey, tx.TenantID(), "fault-kill"); err != nil {
					return err
				}
				var pid int
				if err := tx.DB().QueryRow(tx.Context(), "SELECT pg_backend_pid()").Scan(&pid); err != nil {
					return err
				}
				if _, err := super.Exec(f.ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
					return err
				}
				// Wait until the backend is really gone.
				for i := 0; i < 100; i++ {
					var n int
					if err := super.QueryRow(f.ctx, "SELECT count(*) FROM pg_stat_activity WHERE pid = $1", pid).Scan(&n); err != nil {
						return err
					}
					if n == 0 {
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
				if useAfterKill {
					_, err := tx.DB().Exec(tx.Context(), insertFaultKey, tx.TenantID(), "fault-after")
					return err
				}
				return nil // the commit meets the dead connection
			})
			if err == nil {
				t.Fatal("a transaction whose backend was terminated reported success")
			}
			if !errors.Is(err, store.ErrConnection) {
				t.Errorf("got %v, want a connection error", err)
			}
			if n := faultKeys(t, f); n != 0 {
				t.Errorf("%d rows of the killed transaction were committed", n)
			}

			// The next transaction, for the other tenant, on the same one-connection pool.
			var setting string
			var foreign int
			if err := s.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
				if err := tx.DB().QueryRow(tx.Context(), readTenantSetting).Scan(&setting); err != nil {
					return err
				}
				return tx.DB().QueryRow(tx.Context(), "SELECT count(*) FROM ctrlz.idempotency_keys WHERE tenant_id <> $1", f.B.Tenant).Scan(&foreign)
			}); err != nil {
				t.Fatalf("the next transaction: %v", err)
			}
			if setting != f.B.Tenant.String() {
				t.Errorf("the next transaction runs for %q, want tenant B %s", setting, f.B.Tenant)
			}
			if foreign != 0 {
				t.Errorf("the next transaction sees %d rows of another tenant", foreign)
			}
			if left, err := s.RawTenantSetting(f.ctx); err != nil || left != "" {
				t.Errorf("the connection carries tenant setting %q after the transaction (%v)", left, err)
			}
		})
	}
}

// TestPoolRecoversWhenPostgresRestarts stops the server under an open pool
// holding several connections, then starts it again. While it is down a caller
// with a deadline gets an error and not a hang. Once it is back the same Store,
// with no process restart, serves again, and the stale connections are purged
// instead of failing one request each for ever.
func TestPoolRecoversWhenPostgresRestarts(t *testing.T) {
	f := newFixture(t)
	c := testpg.Need(t, cluster)
	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 4
	cfg.ConnectTimeout = 2 * time.Second
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	// Fill the pool: four transactions open at once need four connections.
	var wg sync.WaitGroup
	ready := make(chan struct{})
	release := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
				ready <- struct{}{}
				<-release
				return nil
			})
		}()
	}
	for i := 0; i < 4; i++ {
		<-ready
	}
	close(release)
	wg.Wait()

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := c.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	t.Cleanup(func() {
		if !restarted { // never leave the cluster down for the tests that follow
			_ = c.StartPostgres(context.Background())
		}
	})

	// Down: an error within the deadline, not a hang.
	downCtx, downCancel := context.WithTimeout(f.ctx, 3*time.Second)
	start := time.Now()
	err = s.WithTenant(downCtx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(store.Tx) error { return nil })
	downCancel()
	if err == nil {
		t.Fatal("a transaction succeeded while the server was down")
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("a call with a 3 second deadline took %v while the server was down", d)
	}

	if err := c.StartPostgres(stopCtx); err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	restarted = true

	// Back: the same Store recovers. Wait for the first success, allowing only
	// connection-class failures on the way, then require a clean run, which
	// proves that every dead connection has been dropped.
	deadline := time.Now().Add(60 * time.Second)
	streak := 0
	for streak < 10 {
		if time.Now().After(deadline) {
			t.Fatalf("the pool did not recover within a minute (streak %d)", streak)
		}
		callCtx, callCancel := context.WithTimeout(f.ctx, 5*time.Second)
		var seen string
		err := s.WithTenant(callCtx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			return tx.DB().QueryRow(tx.Context(), readTenantSetting).Scan(&seen)
		})
		callCancel()
		switch {
		case err == nil:
			if seen != f.A.Tenant.String() {
				t.Fatalf("after the restart the transaction runs for %q, want %s", seen, f.A.Tenant)
			}
			streak++
		case errors.Is(err, store.ErrConnection), errors.Is(err, context.DeadlineExceeded):
			streak = 0
			time.Sleep(200 * time.Millisecond)
		default:
			t.Fatalf("an unexpected kind of error while recovering: %v", err)
		}
	}
	// And the data is still there: the restart was a clean stop.
	if n := count(t, s, f, "SELECT count(*) FROM ctrlz.idempotency_keys"); n < 1 {
		t.Errorf("tenant A lost its rows over the restart: %d", n)
	}
}

func count(t *testing.T, s *store.Store, f *fixture, sql string) (n int) {
	t.Helper()
	if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		return tx.DB().QueryRow(tx.Context(), sql).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestPoolExhaustionHonoursTheDeadline: every connection is busy, so a new
// caller waits for one. With a deadline it gets a context error, in time; it
// does not hang, and the pool serves again once a connection is back.
func TestPoolExhaustionHonoursTheDeadline(t *testing.T) {
	f := newFixture(t)
	s := oneConn(t, f, store.RoleTenant)

	hold := make(chan struct{})
	held := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(store.Tx) error {
			close(held)
			<-hold
			return nil
		})
	}()
	<-held

	ctx, cancel := context.WithTimeout(f.ctx, 400*time.Millisecond)
	defer cancel()
	called := false
	start := time.Now()
	err := s.WithTenant(ctx, f.B.Tenant, store.TxOpts{ReadOnly: true}, func(store.Tx) error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("got %v, want the deadline", err)
	}
	if called {
		t.Error("the callback ran without a connection")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the call took %v against a 400 ms deadline", d)
	}
	// A cancelled context behaves the same.
	cctx, ccancel := context.WithCancel(f.ctx)
	ccancel()
	if err := s.WithTenant(cctx, f.B.Tenant, store.TxOpts{}, func(store.Tx) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context: %v", err)
	}

	close(hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := s.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{ReadOnly: true}, func(store.Tx) error { return nil }); err != nil {
		t.Errorf("the pool did not serve again: %v", err)
	}
}

// blackhole is a TCP proxy in front of Postgres that can be told to swallow
// everything from then on: the connection stays open and nothing answers, the
// way a dead route or a frozen server looks to the client.
type blackhole struct {
	ln     net.Listener
	target string
	frozen atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func newBlackhole(t *testing.T, target string) *blackhole {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{ln: ln, target: target}
	t.Cleanup(func() {
		ln.Close()
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, c := range b.conns {
			c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", b.target)
			if err != nil {
				c.Close()
				continue
			}
			b.mu.Lock()
			b.conns = append(b.conns, c, up)
			b.mu.Unlock()
			go b.pipe(up, c)
			go b.pipe(c, up)
		}
	}()
	return b
}

func (b *blackhole) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !b.frozen.Load() {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil { // io.EOF or a closed socket: either way this direction is over
			return
		}
	}
}

func (b *blackhole) hostPort() (string, uint16) {
	h, p, _ := net.SplitHostPort(b.ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, uint16(n)
}

// TestRollbackOnABlackholedConnectionReturns (review L2-F21): the callback
// fails while the connection to the server has gone silent. The rollback can
// never be answered, so it must give up at its timeout and let the caller go;
// before, it waited for ever and held the pool slot, and a small pool drained.
func TestRollbackOnABlackholedConnectionReturns(t *testing.T) {
	f := newFixture(t)
	host, port := f.db.Addr()
	bh := newBlackhole(t, net.JoinHostPort(host, strconv.Itoa(int(port))))
	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 1
	cfg.Host, cfg.Port = bh.hostPort()
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)

	appErr := errors.New("the handler failed")
	result := make(chan error, 1)
	var took time.Duration
	go func() {
		start := time.Now()
		err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, err := tx.DB().Exec(tx.Context(), insertFaultKey, tx.TenantID(), "fault-blackhole"); err != nil {
				return err
			}
			bh.frozen.Store(true) // from here on nothing comes back
			return appErr
		})
		took = time.Since(start)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, appErr) {
			t.Errorf("got %v, want the handler's own error", err)
		}
		if took < store.RollbackTimeout-time.Second || took > store.RollbackTimeout+5*time.Second {
			t.Errorf("the call took %v; the rollback should give up after about %v", took, store.RollbackTimeout)
		}
	case <-time.After(store.RollbackTimeout + 30*time.Second):
		t.Fatal("WithTenant is still waiting for the rollback of a connection that will never answer")
	}
	if n := faultKeys(t, f); n != 0 {
		t.Errorf("%d rows of the abandoned transaction were committed", n)
	}

	// The slot is free again: with the proxy open once more the pool opens a
	// new connection and serves.
	bh.frozen.Store(false)
	if err := s.WithTenant(f.ctx, f.B.Tenant, store.TxOpts{ReadOnly: true}, func(store.Tx) error { return nil }); err != nil {
		t.Errorf("the pool did not recover after the abandoned rollback: %v", err)
	}
}

// TestDriverErrorsCarryNoArgument (review L2-F15), against the real driver: an
// argument pgx cannot encode, and a value it cannot scan, come back from the
// callback's own DB() calls without the value.
func TestDriverErrorsCarryNoArgument(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	const canary = "CANARY-123456"
	check := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: no error", name)
			return
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("%s: the canary reached the error text: %q", name, err)
		}
		if !errors.Is(err, store.ErrDriver) {
			t.Errorf("%s: %v is not ErrDriver", name, err)
		}
	}
	check("encode", s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		_, err := tx.DB().Exec(tx.Context(), "SELECT $1::text", map[string]string{"otp": canary})
		return err
	}))
	check("scan a QueryRow", s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		var n int
		return tx.DB().QueryRow(tx.Context(), "SELECT $1::text", canary).Scan(&n)
	}))
	check("scan Rows", s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		rows, err := tx.DB().Query(tx.Context(), "SELECT $1::text", canary)
		if err != nil {
			return err
		}
		defer rows.Close()
		var n int
		for rows.Next() {
			if err := rows.Scan(&n); err != nil {
				return err
			}
		}
		return rows.Err()
	}))
}

// TestRowsFromDBHaveNoConnection (review L1-F09): the rows DB().Query returns
// are pgx.Rows, so generated code keeps working, but Conn() gives nothing to
// hold on to.
func TestRowsFromDBHaveNoConnection(t *testing.T) {
	f := newFixture(t)
	s := f.db.Store(f.ctx, t, store.RoleTenant)
	err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		rows, err := tx.DB().Query(tx.Context(), "SELECT g FROM generate_series(1, 3) AS g")
		if err != nil {
			return err
		}
		if rows.Conn() != nil {
			t.Error("rows.Conn() returned the raw connection")
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[int32])
		if err != nil || len(got) != 3 || got[2] != 3 {
			t.Errorf("CollectRows through the wrapper: %v %v", got, err)
		}
		type row struct{ G int32 }
		rows, err = tx.DB().Query(tx.Context(), "SELECT g FROM generate_series(1, 2) AS g")
		if err != nil {
			return err
		}
		structs, err := pgx.CollectRows(rows, pgx.RowToStructByName[row])
		if err != nil || len(structs) != 2 {
			t.Errorf("RowToStructByName through the wrapper: %v %v", structs, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Review round 3, db-r3-3. Every Auth() and Admin() call is a single statement on the
// pool, outside any transaction. If the acquire deadline were dropped from one(), or
// connections stayed dead after a restart, the tests above (they drive WithTenant and
// WithGlobal) would still pass. These two show the single-statement calls' own failure
// behaviour on the one pool.

// TestAuthCallExhaustionHonoursTheAcquireTimeout: with every connection busy, an
// Auth() call fails with the deadline in about the acquire timeout, and does not wait
// for the caller's own (much longer) deadline. Calls queue for a free connection
// instead of failing while there is one.
func TestAuthCallExhaustionHonoursTheAcquireTimeout(t *testing.T) {
	f := newFixture(t)

	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 2
	cfg.AcquireTimeout = 500 * time.Millisecond
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, _, err := s.Auth().UserByPhone(f.ctx, "+989121110099"); err != nil {
		t.Fatalf("a lookup on an idle pool: %v", err)
	}
	release, err := s.HoldConns(f.ctx, 2) // the whole pool
	if err != nil {
		t.Fatal(err)
	}
	callCtx, cancel := context.WithTimeout(f.ctx, time.Minute)
	defer cancel()
	start := time.Now()
	_, _, err = s.Auth().UserByPhone(callCtx, "+989121110099")
	took := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a lookup on an exhausted pool returned %v, want the deadline", err)
	}
	if took > 10*time.Second {
		t.Errorf("the lookup took %v against a 500 ms acquire timeout", took)
	}
	release()
	if _, _, err := s.Auth().UserByPhone(f.ctx, "+989121110099"); err != nil {
		t.Errorf("the pool did not serve again once connections came back: %v", err)
	}

	// With one of three connections held, three calls at once queue on the other two and
	// all succeed; none fails for want of a connection.
	acfg := f.db.StoreConfig(store.RoleAdmin)
	acfg.MaxConns = 3
	acfg.AcquireTimeout = 10 * time.Second
	a, err := store.Open(f.ctx, acfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	arelease, err := a.HoldConns(f.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer arelease()
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := a.Admin().ThrottleHit(f.ctx, "admin_login", sha32(byte(100+i)), 5, 15*time.Minute)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("a queued admin lookup failed: %v", err)
		}
	}
}

// TestAuthCallsRecoverWhenPostgresRestarts: after the server stops and starts,
// Auth() and Admin() calls on the same Stores, with their warm connections, work again and do not fail one request per stale connection for ever.
func TestAuthCallsRecoverWhenPostgresRestarts(t *testing.T) {
	f := newFixture(t)
	c := testpg.Need(t, cluster)
	cfg := f.db.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 4
	cfg.ConnectTimeout = 2 * time.Second
	s, err := store.Open(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	acfg := f.db.StoreConfig(store.RoleAdmin)
	acfg.MaxConns = 3
	acfg.ConnectTimeout = 2 * time.Second
	a, err := store.Open(f.ctx, acfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)

	// Warm the pools: all their connections are open before the stop.
	for _, st := range []*store.Store{s, a} {
		n := 4
		if st == a {
			n = 3
		}
		rel, err := st.HoldConns(f.ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	tenantCall := func(ctx context.Context) error {
		_, _, err := s.Auth().UserByPhone(ctx, "+989121110099")
		return err
	}
	adminCall := func(ctx context.Context) error {
		_, err := a.Admin().ThrottleHit(ctx, "admin_login", sha32(77), 1000, 15*time.Minute)
		return err
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := c.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	t.Cleanup(func() {
		if !restarted {
			_ = c.StartPostgres(context.Background())
		}
	})
	for name, call := range map[string]func(context.Context) error{"Auth": tenantCall, "Admin": adminCall} {
		downCtx, downCancel := context.WithTimeout(f.ctx, 3*time.Second)
		start := time.Now()
		err := call(downCtx)
		downCancel()
		if err == nil {
			t.Errorf("%s: a lookup succeeded while the server was down", name)
		}
		if d := time.Since(start); d > 15*time.Second {
			t.Errorf("%s: a lookup with a 3 second deadline took %v while the server was down", name, d)
		}
	}
	if err := c.StartPostgres(stopCtx); err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	restarted = true

	for name, call := range map[string]func(context.Context) error{"Auth": tenantCall, "Admin": adminCall} {
		deadline := time.Now().Add(60 * time.Second)
		streak := 0
		for streak < 10 {
			if time.Now().After(deadline) {
				t.Fatalf("%s: the pool did not recover within a minute (streak %d)", name, streak)
			}
			callCtx, callCancel := context.WithTimeout(f.ctx, 5*time.Second)
			err := call(callCtx)
			callCancel()
			switch {
			case err == nil:
				streak++
			case errors.Is(err, store.ErrConnection), errors.Is(err, context.DeadlineExceeded):
				streak = 0
				time.Sleep(200 * time.Millisecond)
			default:
				t.Fatalf("%s: an unexpected kind of error while recovering: %v", name, err)
			}
		}
	}
}

// TestStatementTimeoutAnswersRetry runs a real statement past a short
// statement_timeout, the way the roles' 60 s limit would stop a query behind a lock
// queue, and expects the retry class the HTTP layer answers with 503. Before the
// fix the database's 57014 had no class and became a 500 (db-r5-3). The next
// transaction on the same one-connection pool must still run.
func TestStatementTimeoutAnswersRetry(t *testing.T) {
	f := newFixture(t)
	s := oneConn(t, f, store.RoleTenant)
	err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if _, err := tx.DB().Exec(tx.Context(), "SET LOCAL statement_timeout = '50ms'"); err != nil {
			return err
		}
		_, err := tx.DB().Exec(tx.Context(), "SELECT pg_sleep(5)")
		return err
	})
	if !errors.Is(err, store.ErrRetry) {
		t.Fatalf("a statement past statement_timeout returned %v, want ErrRetry", err)
	}
	if herr := httpx.FromError(err); herr.Status != 503 {
		t.Errorf("the HTTP layer answers %d, want 503", herr.Status)
	}
	if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		var one int
		return tx.DB().QueryRow(tx.Context(), "SELECT 1").Scan(&one)
	}); err != nil {
		t.Errorf("the next transaction after the timeout: %v", err)
	}
}

// TestIdleInTransactionTimeoutAnswersConnectionLost holds a transaction open past a short
// idle_in_transaction_session_timeout, the way a hung Valkey or SMS call inside a transaction
// would past the roles' 120 s, and expects the class the HTTP layer answers with 503. The
// server closes the connection with FATAL 25P03, which had no class and became a 500 with a
// WARN (db-r6-1). The next transaction on the same one-connection pool must still run.
func TestIdleInTransactionTimeoutAnswersConnectionLost(t *testing.T) {
	f := newFixture(t)
	s := oneConn(t, f, store.RoleTenant)
	err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		if _, err := tx.DB().Exec(tx.Context(), "SET LOCAL idle_in_transaction_session_timeout = '200ms'"); err != nil {
			return err
		}
		time.Sleep(1500 * time.Millisecond) // the stalled call between two statements
		var one int
		return tx.DB().QueryRow(tx.Context(), "SELECT 1").Scan(&one)
	})
	if !errors.Is(err, store.ErrConnection) {
		t.Fatalf("a transaction killed by idle_in_transaction_session_timeout returned %v, want ErrConnection", err)
	}
	if herr := httpx.FromError(err); herr.Status != 503 {
		t.Errorf("the HTTP layer answers %d, want 503", herr.Status)
	}
	if err := s.WithTenant(f.ctx, f.A.Tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
		var one int
		return tx.DB().QueryRow(tx.Context(), "SELECT 1").Scan(&one)
	}); err != nil {
		t.Errorf("the next transaction after the timeout: %v", err)
	}
}
