package store_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The behaviour of the sharded global count (P1 auth review round 18, db-r18-2 and db-r18-12). The point of
// the sixteen shard rows is that requests no longer queue on one counter row, so what is tested is that point
// and not the text of the function: the digest of caps.LimitFunctions trips on any edit of auth_otp_issue
// and is re-blessed with it, so it cannot be the test of this property.

// shardKey is the closed set of keys the issue function may write for the global count.
var shardKey = regexp.MustCompile(`^all(:([1-9]|1[0-5]))?$`)

func (e *raceEnv) openOTPCaps(t *testing.T) {
	t.Helper()
	e.exec(t, `DELETE FROM ctrlz.otp_challenges`)
	e.exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 1000, otp_cap_phone_net = 1000, otp_cap_ip = 1000, otp_cap_net24 = 1000,
  otp_cap_phone_trusted = 1000, otp_cap_net48 = 1000, otp_cap_global = 100000, otp_soft_pct = 100, sms_cost_cap_daily = NULL`)
	e.exec(t, `TRUNCATE ctrlz.sms_counters`)
}

// TestTheGlobalCountSpreadsOverItsShards: real requests write more than one shard row, only shard rows of the
// closed key set, and the shards add up to the number of codes issued. A function that counted on one row
// ('all' only) fails the first check; one that invented keys fails the second; one that lost a count fails the
// third.
func TestTheGlobalCountSpreadsOverItsShards(t *testing.T) {
	e := newRaceEnv(t)
	e.warm(t)
	e.openOTPCaps(t)
	const requests = 200
	for i := 0; i < requests; i++ {
		// Known devices pass the soft breaker and share no per-address key, so only the shard differs.
		r, err := otpIssue(e, phoneN(i), "login", netip.MustParseAddr(fmt.Sprintf("198.18.%d.%d", i/250, 1+i%250)), true)
		if err != nil || !r.Allowed {
			t.Fatalf("request %d: %+v %v", i, r, err)
		}
	}
	rows, err := e.super.Query(e.ctx, `SELECT key, count FROM ctrlz.sms_counters WHERE scope = 'global' AND (key = 'all' OR key LIKE 'all:%')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	shards, sum := 0, 0
	for rows.Next() {
		var key string
		var n int
		if err := rows.Scan(&key, &n); err != nil {
			t.Fatal(err)
		}
		if !shardKey.MatchString(key) {
			t.Errorf("the global count has a row with the key %q, which is not one of the sixteen shards", key)
		}
		shards++
		sum += n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// 200 draws of 16 shards leave fewer than 8 distinct ones with a probability far below 1e-20.
	if shards < 8 {
		t.Errorf("%d requests wrote %d shard rows of the global count, want them spread over many: the count is on one row again", requests, shards)
	}
	if sum != requests {
		t.Errorf("the shards add up to %d for %d codes", sum, requests)
	}
}

// TestAHeldShardLeavesTheOtherRequestsRunning: another session holds the row lock of one shard, and the
// requests that did not pick that shard (fifteen of sixteen) are neither delayed nor refused. With a single
// counter row every request waits for the holder and none finishes inside the deadline.
func TestAHeldShardLeavesTheOtherRequestsRunning(t *testing.T) {
	e := newRaceEnv(t)
	e.warm(t)
	e.openOTPCaps(t)
	e.exec(t, `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 0)`)
	holder := e.fixture.superConn(t)
	tx, err := holder.Begin(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(e.ctx) }()
	if _, err := tx.Exec(e.ctx, `SELECT 1 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = 'all' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}

	const requests = 64
	var done atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
			defer cancel()
			r, err := e.tenant.Auth().OTPIssue(ctx, phoneN(500+i), "login", []byte{1}, []byte("sealed"),
				netip.MustParseAddr(fmt.Sprintf("198.19.%d.1", i)), true) // one /24 each: a shared net row would queue the others behind a request that waits
			if err == nil && r.Allowed {
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	// Each request picks the held shard with probability 1/16: about 4 of 64 wait, so at least 40 finishing is
	// far inside the noise, and a single counter row lets none through.
	if got := done.Load(); got < 40 {
		t.Errorf("%d of %d requests finished while one shard was held, want nearly all: the requests queue on one row", got, requests)
	}
}

// TestARefundTakesAShardNobodyHoldsAndNeverWaits pins what qCountersRefund does with sixteen shards
// (db-r18-18): it gives the slot back to the first shard with a count that nobody is writing, and when every
// shard with a count is held it gives nothing back, at once and without an error. That last case is a limit
// that stays until the owner decides it (Plan.md, round 18: the alternative is a column on the challenge row
// that names the shard it counted on); the test says what it is so a change of it is a decision and not a
// side effect.
func TestARefundTakesAShardNobodyHoldsAndNeverWaits(t *testing.T) {
	e := newRaceEnv(t)
	e.exec(t, `TRUNCATE ctrlz.sms_counters`)
	e.exec(t, `INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES
	  ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 1),
	  ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all:3', 1)`)
	hold := func(keys ...string) func() {
		conn := e.fixture.superConn(t)
		tx, err := conn.Begin(e.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range keys {
			if _, err := tx.Exec(e.ctx, `SELECT 1 FROM ctrlz.sms_counters WHERE scope = 'global' AND key = $1 FOR UPDATE`, k); err != nil {
				t.Fatal(err)
			}
		}
		return func() { _ = tx.Rollback(e.ctx) }
	}
	counts := func() string {
		var s string
		if err := e.super.QueryRow(e.ctx, `SELECT string_agg(key || '=' || count, ',' ORDER BY key) FROM ctrlz.sms_counters WHERE scope = 'global'`).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	refund := func() time.Duration {
		start := time.Now()
		if err := e.globalErr(e.worker, func(g store.GlobalTx) error { return g.CountersRefund(time.Now()) }); err != nil {
			t.Fatalf("a refund returned an error: %v", err)
		}
		return time.Since(start)
	}

	release := hold("all")
	refund()
	release()
	if got := counts(); got != "all=1,all:3=0" {
		t.Errorf("with the first shard held the refund must take the next one with a count: %s", got)
	}

	e.exec(t, `UPDATE ctrlz.sms_counters SET count = 1`)
	release = hold("all", "all:3")
	took := refund()
	release()
	if got := counts(); got != "all=1,all:3=1" {
		t.Errorf("with every shard that has a count held the refund is skipped (the limit the owner has not decided): %s", got)
	}
	if took > 2*time.Second {
		t.Errorf("a skipped refund waited %v: it must never wait", took)
	}
}
