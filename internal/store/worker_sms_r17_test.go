package store_test

import (
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// sms-r17-22: the fix of sms-r17-4 rests on the claim that a claim takes at most its limit of rows, and the
// only tests were lints over the SQL text. The property itself is run here: a backlog far larger than the
// limit, several workers claiming at the same time and skipping what another holds, and the count of rows
// each call returns, per call and in all, and that no row is handed to two of them.
func TestAClaimNeverTakesMoreRowsThanItsLimit(t *testing.T) {
	f := newFixture(t)
	worker := f.db.Store(f.ctx, t, store.RoleWorker)
	super := f.superConn(t)
	const backlog, limit, workers = 40, 4, 5
	if _, err := super.Exec(f.ctx, `DELETE FROM ctrlz.otp_challenges`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `DELETE FROM ctrlz.sms_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, created_at, ip)
SELECT '+9891211' || lpad(n::text, 5, '0'), 'login', '\x01', '\x02', now() + interval '5 minutes', now() - make_interval(secs => n), '198.51.100.9'
FROM generate_series(1, $1) n`, backlog); err != nil {
		t.Fatal(err)
	}
	if _, err := super.Exec(f.ctx, `INSERT INTO ctrlz.sms_outbox (id, kind, phone_e164, template_key, locale, params_ct)
SELECT gen_random_uuid(), 'test', '+9891212' || lpad(n::text, 5, '0'), 'otp', 'fa', '\x01'
FROM generate_series(1, $1) n`, backlog); err != nil {
		t.Fatal(err)
	}

	type kind struct {
		name  string
		claim func(g store.GlobalTx) ([]uuid.UUID, error)
	}
	kinds := []kind{
		{"otp", func(g store.GlobalTx) ([]uuid.UUID, error) {
			rows, err := g.OTPClaim(limit, 3)
			var ids []uuid.UUID
			for _, r := range rows {
				ids = append(ids, r.ID)
			}
			return ids, err
		}},
		{"outbox", func(g store.GlobalTx) ([]uuid.UUID, error) {
			rows, err := g.OutboxClaim(limit)
			var ids []uuid.UUID
			for _, r := range rows {
				ids = append(ids, r.ID)
			}
			return ids, err
		}},
	}
	for _, k := range kinds {
		taken := map[uuid.UUID]bool{}
		var mu sync.Mutex
		// Rounds of concurrent claims until the backlog is gone; a round that takes nothing ends it.
		for round := 0; round < backlog; round++ {
			var wg sync.WaitGroup
			var got int
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := worker.WithGlobal(f.ctx, store.TxOpts{}, func(g store.GlobalTx) error {
						ids, err := k.claim(g)
						if err != nil {
							return err
						}
						if len(ids) > limit {
							t.Errorf("%s: one claim took %d rows, over its limit of %d", k.name, len(ids), limit)
						}
						mu.Lock()
						defer mu.Unlock()
						for _, id := range ids {
							if taken[id] {
								t.Errorf("%s: row %s was handed to two claims", k.name, id)
							}
							taken[id] = true
						}
						got += len(ids)
						return nil
					})
					if err != nil {
						t.Errorf("%s: %v", k.name, err)
					}
				}()
			}
			wg.Wait()
			if got > workers*limit {
				t.Errorf("%s: %d workers took %d rows in one round, over %d", k.name, workers, got, workers*limit)
			}
			if got == 0 {
				break
			}
		}
		if len(taken) != backlog {
			t.Errorf("%s: %d of %d rows were claimed in the end", k.name, len(taken), backlog)
		}
	}
}
