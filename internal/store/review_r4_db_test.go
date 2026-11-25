package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// TestCountersRefundTouchesTheGlobalRowOnly is db-r4-5 as it stands after the refund
// became the global key alone (sms-r6-1). auth_otp_issue bumps the counters narrow to wide
// (an address, its network, the phone, then the world) and holds every row to the end of
// its transaction. Round 4 locked a refund's rows in the same order so that the two could
// not deadlock; now the refund names one row, the world's, which issue takes last, so there
// is no order left to get wrong. The test holds the narrower rows the way an issue does and
// shows the refund neither waits for them nor moves them.
func TestCountersRefundTouchesTheGlobalRowOnly(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	issue := f.superConn(t)
	day := `(now() AT TIME ZONE 'Asia/Tehran')::date`
	for _, q := range []string{
		`TRUNCATE ctrlz.sms_counters`,
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + day + `, 'global', 'all', 5)`,
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + day + `, 'ip', '203.0.113.9', 5)`,
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + day + `, 'ip', '203.0.113.0/24', 5)`,
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + day + `, 'phone_net', '+989121112233|203.0.113.0/24', 5)`,
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES (` + day + `, 'phone', '+989121112233', 5)`,
	} {
		if _, err := super.Exec(f.ctx, testpg.PlantCounters(q)); err != nil {
			t.Fatal(err)
		}
	}
	for round := 0; round < 3; round++ {
		tx, err := issue.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(f.ctx, `SELECT 1 FROM ctrlz.sms_counters WHERE scope <> 'global' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		// A refund that touched any of the rows the issue side holds would wait here until
		// the timeout, and fail.
		err = worker.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error { return g.CountersRefund(time.Now()) })
		cancel()
		if err != nil {
			t.Fatalf("round %d: the refund waited for a row it has no business with: %v", round, err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	var global, host, net, phoneNet, phone int
	if err := super.QueryRow(f.ctx, `SELECT
  (SELECT count FROM ctrlz.sms_counters WHERE scope = 'global'),
  (SELECT count FROM ctrlz.sms_counters WHERE key = '203.0.113.9'),
  (SELECT count FROM ctrlz.sms_counters WHERE key = '203.0.113.0/24'),
  (SELECT count FROM ctrlz.sms_counters WHERE scope = 'phone_net'),
  (SELECT count FROM ctrlz.sms_counters WHERE scope = 'phone')`).Scan(&global, &host, &net, &phoneNet, &phone); err != nil {
		t.Fatal(err)
	}
	if global != 2 || host != 5 || net != 5 || phoneNet != 5 || phone != 5 {
		t.Errorf("counters after three refunds: global %d (want 2), host %d, net %d, phone_net %d, phone %d (want 5 each: a refund never gives them back)", global, host, net, phoneNet, phone)
	}
}

// TestCountersRefundBatchFloorsAtZeroAndKeepsDays: a batch that refunds the same key
// more often than it was counted stops at zero, and each message is refunded on its
// own Tehran day.
func TestCountersRefundBatchFloorsAtZeroAndKeepsDays(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	for _, q := range []string{
		`TRUNCATE ctrlz.sms_counters`,
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date, 'global', 'all', 2)`,
		`INSERT INTO ctrlz.sms_counters (day, scope, key, count) VALUES ((now() AT TIME ZONE 'Asia/Tehran')::date - 1, 'global', 'all', 3)`,
	} {
		if _, err := super.Exec(f.ctx, testpg.PlantCounters(q)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	err := worker.WithGlobal(f.ctx, store.TxOpts{}, func(gt store.GlobalTx) error {
		// three against a count of two, then one a day earlier
		return gt.CountersRefundAll([]time.Time{now, now, now, now.Add(-24 * time.Hour)})
	})
	if err != nil {
		t.Fatal(err)
	}
	var today, yesterday int
	if err := super.QueryRow(f.ctx, `SELECT
  (SELECT count FROM ctrlz.sms_counters WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date),
  (SELECT count FROM ctrlz.sms_counters WHERE day = (now() AT TIME ZONE 'Asia/Tehran')::date - 1)`).Scan(&today, &yesterday); err != nil {
		t.Fatal(err)
	}
	if today != 0 || yesterday != 2 {
		t.Errorf("today %d (want 0), yesterday %d (want 2)", today, yesterday)
	}
}
