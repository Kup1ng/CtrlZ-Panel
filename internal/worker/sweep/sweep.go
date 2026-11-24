// Package sweep is the worker's housekeeping (spec 9.5): what outlived its use is
// deleted, and what was owed back is given back.
//
// Two cadences, because the work differs:
//
//   - Fast (30 seconds): OTPs that expired before any gateway took them are
//     closed and their counters refunded, and outbox messages retried for an hour
//     are ended. A worker outage then costs the phone no cap and the invite no
//     endless retry, and the refund is not held back for ten minutes.
//   - Slow (10 minutes): expired tickets, throttle windows, OTP rows over a day
//     old, delivery and outbox history, per-phone and per-network counters, old
//     invites, and for each tenant its expired sessions, refresh tokens, phone
//     change requests, old audit rows and unconfirmed TOTP secrets.
//
// The two run on their own goroutines, so a slow walk over the tenants never
// holds back a refund. Every statement is idempotent and bounded: the global
// deletes go in batches, each in its own transaction, so a backlog is worked off
// over several runs and one failing table stops no other. Two workers sweeping at
// once do the same work twice and no harm. Correctness never rests on
// a sweep having run: expiry is checked where a row is read.
package sweep

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sweepbatch"
)

// Config builds a Sweeper.
type Config struct {
	Store *store.Store // opened as ctrlz_worker
	Log   *slog.Logger
	// Fast and Slow are the two cadences; the defaults are 30 s and 10 min.
	Fast, Slow time.Duration
	// Page is how many tenants one read returns; default 100.
	Page int
	// Batch is how many rows one DELETE of the global sweep may remove (default
	// 5000), and MaxBatches how many batches one table gets in one run (default
	// 200). A backlog is then worked off over several runs, and no statement runs
	// long enough to meet the worker's statement_timeout.
	Batch, MaxBatches int
}

// Sweeper runs the sweeps.
type Sweeper struct {
	db                *store.Store
	log               *slog.Logger
	fast              time.Duration
	slow              time.Duration
	page              int
	batch, maxBatches int
}

// New returns a Sweeper.
func New(c Config) (*Sweeper, error) {
	if c.Store == nil || c.Log == nil {
		return nil, errors.New("sweep: store and log are required")
	}
	s := &Sweeper{db: c.Store, log: c.Log, fast: c.Fast, slow: c.Slow, page: c.Page}
	if s.fast <= 0 {
		s.fast = 30 * time.Second
	}
	if s.slow <= 0 {
		s.slow = 10 * time.Minute
	}
	if s.page <= 0 {
		s.page = 100
	}
	s.batch, s.maxBatches = c.Batch, c.MaxBatches
	if s.batch <= 0 {
		s.batch = 5000
	}
	if s.maxBatches <= 0 {
		s.maxBatches = 200
	}
	return s, nil
}

// Run sweeps until ctx ends. Each cadence has its own goroutine, and each runs
// once at start, so a worker that was down for a while catches up at once. They
// are apart because the slow sweep walks every tenant and can take minutes: on
// one goroutine it would hold back the fast tick, and an OTP that expired unsent
// would stay unrefunded for as long. The two safego.Go calls are written out, one
// per cadence, because internal/lint TestBoundedSweeps reads them: a goroutine that
// reached both would put the slow walk back in front of the fast refund.
func (s *Sweeper) Run(ctx context.Context) error {
	s.log.Info("sweep started")
	var wg sync.WaitGroup
	wg.Add(2)
	safego.Go(s.log, sweepFast, func() {
		defer wg.Done()
		s.every(ctx, sweepFast, s.fast, func(ctx context.Context) error { _, err := s.Fast(ctx); return err })
	})
	safego.Go(s.log, sweepSlow, func() {
		defer wg.Done()
		s.every(ctx, sweepSlow, s.slow, func(ctx context.Context) error { _, err := s.Slow(ctx); return err })
	})
	wg.Wait()
	return nil
}

// every runs one cadence: once now, then at each tick, until ctx ends.
func (s *Sweeper) every(ctx context.Context, kind sweepKind, interval time.Duration, run func(context.Context) error) {
	s.logResult(ctx, kind, func() error { return run(ctx) })
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.logResult(ctx, kind, func() error { return run(ctx) })
		}
	}
}

// plan is the bound of one sweep run: the batch size and how many batches.
func (s *Sweeper) plan() sweepbatch.Plan {
	return sweepbatch.Plan{Size: s.batch, Max: s.maxBatches}
}

// sweepKind names a sweep for the log: a closed type, so a log line can carry it.
type sweepKind string

const (
	sweepFast sweepKind = "fast"
	sweepSlow sweepKind = "slow"
)

// Valid reports membership.
func (k sweepKind) Valid() bool { return k == sweepFast || k == sweepSlow }

func (s *Sweeper) logResult(ctx context.Context, kind sweepKind, f func() error) {
	// One run keeps its own panic: the loop goes on at its next tick, and the process does not end under
	// the rows another unit of the worker holds in flight (sms-r17-17).
	defer safego.Keep(s.log, kind)
	if err := f(); err != nil && ctx.Err() == nil {
		// The joined error holds store errors, which are already sanitised.
		s.log.Warn("sweep failed", logattr.Enum("sweep", kind), logattr.Enum("error_class", errClass(err)))
	}
}

func errClass(err error) logattr.ErrClass {
	switch {
	case errors.Is(err, store.ErrConnection):
		return logattr.ErrConnection
	case errors.Is(err, store.ErrRetry):
		return logattr.ErrRetry
	case errors.Is(err, context.DeadlineExceeded):
		return logattr.ErrTimeout
	}
	return logattr.ErrOther
}

// FastResult says what the fast sweep did.
type FastResult struct {
	ExpiredOTP  int // OTPs closed unsent and refunded
	StaleOutbox int // outbox messages ended after an hour
}

// Fast closes unsent OTPs and ends stale outbox messages. The two steps run in
// their own transactions: the refund of an OTP must commit with its clear, and
// the outbox step has nothing to do with it.
func (s *Sweeper) Fast(ctx context.Context) (FastResult, error) {
	var r FastResult
	var errs []error
	// After a long worker outage thousands of codes may wait. Each batch ends a
	// bounded number in its own transaction, so the row locks on the shared
	// global and network counters are held for a batch and not for the backlog,
	// and auth_otp_issue is not left waiting on them (sms-r2-4).
	var err error
	r.ExpiredOTP, err = sweepbatch.Drain(ctx, s.plan(), func(ctx context.Context, _ int) (n int, more bool, err error) {
		err = s.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
			// The refund is the world-wide key and nothing else, written in the store's
			// statement, so an expired real row leaves the counters a decoy leaves
			// (sms-r5-7, rule known-unknown-oracle).
			n, more, err = g.OTPExpireUndeliveredBatch()
			return err
		})
		return n, more, err
	})
	if err != nil {
		errs = append(errs, err)
	}
	// The outbox step has nothing to do with the refund above, so a failure of one
	// leaves the other to run.
	r.StaleOutbox, err = sweepbatch.Drain(ctx, s.plan(), func(ctx context.Context, size int) (n int, more bool, err error) {
		err = s.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
			n, err = g.OutboxFailStaleBatch(size)
			return err
		})
		return n, n >= size, err
	})
	if err != nil {
		errs = append(errs, err)
	}
	if r.ExpiredOTP > 0 || r.StaleOutbox > 0 {
		s.log.Info("sweep fast", logattr.Int("expired_otp", r.ExpiredOTP), logattr.Int("stale_outbox", r.StaleOutbox))
	}
	return r, errors.Join(errs...)
}

// SlowResult says what the slow sweep deleted.
type SlowResult struct {
	Global  store.SweepCounts
	Tenants int
	Tenant  store.TenantSweepCounts // summed over the tenants
}

// Slow deletes expired rows, global first and then one transaction per tenant.
// A failure in one table or one tenant is recorded and the next still runs.
//
// Each global table is deleted in bounded batches, each batch in its own
// transaction (store.SweepGlobalBatch). One statement over millions of rows
// would meet the worker's statement_timeout, roll back, and meet it again on
// every run, and a lock wait on one table must not undo the deletes of the
// others.
func (s *Sweeper) Slow(ctx context.Context) (SlowResult, error) {
	var r SlowResult
	var errs []error
	for _, step := range store.SweepSteps() {
		n, err := s.sweepStep(ctx, step)
		if err != nil {
			errs = append(errs, err)
		}
		switch step {
		case store.SweepOTP:
			r.Global.OTP = n
		case store.SweepTickets:
			r.Global.Tickets = n
		case store.SweepThrottle:
			r.Global.Throttle = n
		case store.SweepDeliveries:
			r.Global.Deliveries = n
		case store.SweepOutbox:
			r.Global.Outbox = n
		case store.SweepCounters:
			r.Global.Counters = n
		case store.SweepInvites:
			r.Global.Invites = n
		}
	}

	after := uuid.Nil
	for ctx.Err() == nil {
		var ids []uuid.UUID
		if err := s.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			ids, err = g.TenantIDs(after, s.page)
			return err
		}); err != nil {
			errs = append(errs, err)
			break
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			c, err := s.sweepTenant(ctx, id)
			if err != nil {
				errs = append(errs, err)
			} else {
				r.Tenants++
			}
			r.Tenant.Sessions += c.Sessions
			r.Tenant.Refresh += c.Refresh
			r.Tenant.PhoneChanges += c.PhoneChanges
			r.Tenant.Audit += c.Audit
			r.Tenant.PendingTOTP += c.PendingTOTP
		}
		after = ids[len(ids)-1]
		if len(ids) < s.page {
			break
		}
	}
	return r, errors.Join(errs...)
}

// sweepStep empties one global table in batches, at most maxBatches of them. It
// returns what it deleted, also when a later batch failed.
func (s *Sweeper) sweepStep(ctx context.Context, step store.SweepStep) (int, error) {
	return sweepbatch.Drain(ctx, s.plan(), func(ctx context.Context, size int) (n int, more bool, err error) {
		err = s.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
			n, err = g.SweepGlobalBatch(step, size)
			return err
		})
		return n, n >= size, err
	})
}

// sweepTenant runs the tenant steps. Each step is its own batched loop, and each
// batch its own transaction: a tenant with a backlog in one table (a year of
// audit rows after a long outage) meets statement_timeout on that batch alone.
// It cannot roll back the clear of a pending TOTP secret or the other tables,
// and a failing step is recorded while the next still runs (sms-r2-4).
func (s *Sweeper) sweepTenant(ctx context.Context, tenant uuid.UUID) (store.TenantSweepCounts, error) {
	var c store.TenantSweepCounts
	var errs []error
	for _, step := range store.TenantSweepSteps() {
		total, err := sweepbatch.Drain(ctx, s.plan(), func(ctx context.Context, size int) (n int, more bool, err error) {
			err = s.db.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
				n, err = tx.SweepTenantBatch(step, size, appclock.Now())
				return err
			})
			return n, n >= size, err
		})
		if err != nil {
			errs = append(errs, err)
		}
		switch step {
		case store.TenantSweepSessions:
			c.Sessions = total
		case store.TenantSweepRefresh:
			c.Refresh = total
		case store.TenantSweepPhone:
			c.PhoneChanges = total
		case store.TenantSweepAudit:
			c.Audit = total
		case store.TenantSweepPendingTOTP:
			c.PendingTOTP = total
		}
	}
	return c, errors.Join(errs...)
}
