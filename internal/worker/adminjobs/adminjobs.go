// Package adminjobs runs the jobs the admin service queues in admin_jobs: work
// that spans tenants and so cannot run inside the admin's own request (spec 7.4,
// 11.2, 11.5).
//
// The runner polls the table. A job is queued by an admin transaction that also
// writes its audit row, so there is nothing to wake on that a 5 second poll does
// not cover, and a job that was queued while the worker was down simply waits.
//
// Every handler is safe to run again from the start. A worker that dies mid-job
// leaves it running, the next poll picks it up, and the tenants already done find
// nothing left to change. That is why a job needs no cursor: progress is for the
// operator to read, not for the handler to resume from.
//
// Correctness never rests on a job having run. For the RP ID change the login
// path already refuses a credential of another RP ID (7.4 step 3), and for the
// registration switch a sweep reads the current mode (11.5).
package adminjobs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Job kinds (the CHECK of admin_jobs.kind).
const (
	KindRegistrationTransition = "registration_transition"
	KindWebauthnRPChange       = "webauthn_rp_change"
)

// Report stores the progress of the running job. Handlers call it as they go.
type Report func(progress any)

// Handler runs one job. The returned value is the final progress. An error means
// the run failed; the runner decides whether to try again.
type Handler func(ctx context.Context, job store.AdminJob, report Report) (final any, err error)

// Config builds a Runner.
type Config struct {
	Store *store.Store // opened as ctrlz_worker
	Log   *slog.Logger
	Poll  time.Duration // default 5 s
	// MaxFailures is how many failed runs end a job as failed; default 5.
	MaxFailures int
	// Backoff is the pause before each retry of a failed job: the first entry
	// after the first failure, and the last one for every failure after that.
	// Default 5 s, 30 s, 2 min, 10 min. A job that walks every tenant must not be
	// given up for good because the database blinked for half a minute, so five
	// failures now span about 12 minutes and not 25 seconds.
	Backoff []time.Duration
	// Now is the clock; tests replace it.
	Now func() time.Time
	// Page is the number of tenants read at a time; default 100.
	Page int
	// Handlers adds or replaces handlers by kind. A later work package fills the
	// real ones in without touching the runner.
	Handlers map[string]Handler
	// BeforeStart and AfterPage are test seams: they let a test play the part of
	// a second worker or an admin at the two moments where a job can go stale,
	// between reading the job list and starting a job, and between two pages of
	// tenants. Nothing in production sets them.
	BeforeStart func(store.AdminJob)
	AfterPage   func(tenantsDone int)
	// SweepBudget bounds the tenants one periodic registration sweep walks; default 50,000. A test seam as well: the next run
	// resumes after the last tenant of the one before.
	SweepBudget int
}

// Runner polls admin_jobs and runs what it finds.
type Runner struct {
	db       *store.Store
	log      *slog.Logger
	poll     time.Duration
	maxFail  int
	page     int
	handlers map[string]Handler
	backoff  []time.Duration
	now      func() time.Time
	failures map[uuid.UUID]failure
	holder   string // this worker's name in the lease of the periodic sweep

	// sweepBudget and sweepAfter are the periodic sweep's bound and where the last bounded run stopped (Nil when it ended the list). They
	// live in memory like failures: a restarted worker starts at the first tenant, which costs one repeated slice, and a worker that
	// holds the lease takes up from where it left off, so every tenant is reached within a few runs.
	sweepBudget int
	sweepMu     sync.Mutex
	sweepAfter  uuid.UUID

	beforeStart func(store.AdminJob)
	afterPage   func(int)
}

// failure is what the runner remembers of a job that failed. It lives in memory
// only: a restarted worker starts the count again, which can only make a job
// more patient.
type failure struct {
	count int
	retry time.Time // not before this instant
}

// New returns a Runner with the P1 handlers installed.
func New(c Config) (*Runner, error) {
	if c.Store == nil || c.Log == nil {
		return nil, errors.New("adminjobs: store and log are required")
	}
	r := &Runner{db: c.Store, log: c.Log, poll: c.Poll, maxFail: c.MaxFailures, page: c.Page, failures: map[uuid.UUID]failure{}, holder: sweepHolder(), backoff: c.Backoff, now: c.Now,
		beforeStart: c.BeforeStart, afterPage: c.AfterPage, sweepBudget: c.SweepBudget}
	if r.poll <= 0 {
		r.poll = 5 * time.Second
	}
	if r.maxFail < 1 {
		r.maxFail = 5
	}
	if r.sweepBudget < 1 {
		r.sweepBudget = sweepTenantBudget
	}
	if r.page < 1 {
		r.page = 100
	}
	if len(r.backoff) == 0 {
		r.backoff = []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute}
	}
	if r.now == nil {
		r.now = time.Now
	}
	r.handlers = map[string]Handler{
		KindRegistrationTransition: r.registrationTransition,
		KindWebauthnRPChange:       r.webauthnRPChange,
	}
	for k, h := range c.Handlers {
		r.handlers[k] = h
	}
	return r, nil
}

// Run polls until ctx ends.
func (r *Runner) Run(ctx context.Context) error {
	tick := time.NewTicker(r.poll)
	defer tick.Stop()
	// The registration sweep has its own cadence and its own goroutine: it walks every tenant and must not hold back the poll
	// for jobs (P3 spec 4.4).
	done := make(chan struct{})
	safego.Go(r.log, unitSweep, func() {
		defer close(done)
		sweep := time.NewTicker(SweepEvery)
		defer sweep.Stop()
		for {
			r.runSweepOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-sweep.C:
			}
		}
	})
	defer func() { <-done }()
	for {
		r.pass(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// pass is one poll. It keeps its own panic (a handler met a row shape it did not expect): the job stays
// running as a crash leaves it, the next poll resumes it (every handler is safe to run again), and the process
// does not end under the SMS rows that another unit of the worker holds in flight (sms-r17-17).
func (r *Runner) pass(ctx context.Context) {
	defer safego.Keep(r.log, unitPass)
	if n, err := r.RunOnce(ctx); err != nil && ctx.Err() == nil {
		r.log.Warn("admin jobs failed", logattr.Enum("error_class", errClass(err)))
	} else if n > 0 {
		r.log.Info("admin jobs ran", logattr.Int("count", n))
	}
}

// logUnit names the unit that kept a panic: a closed type so a log line can carry it.
type logUnit string

const (
	unitPass    logUnit = "pass"
	unitHandler logUnit = "handler"
	unitSweep   logUnit = "sweep"
)

// Valid reports membership.
func (u logUnit) Valid() bool { return u == unitPass || u == unitHandler || u == unitSweep }

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

// RunOnce runs every queued or running job once, one after the other, and
// returns how many it ran. Jobs are sequential on purpose: they all walk the
// tenants, and two walking at once would only compete for the same rows.
func (r *Runner) RunOnce(ctx context.Context) (int, error) {
	var jobs []store.AdminJob
	if err := r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
		jobs, err = g.AdminJobsActive()
		return err
	}); err != nil {
		return 0, err
	}
	var errs []error
	ran := 0
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		if f, ok := r.failures[j.ID]; ok && r.now().Before(f.retry) {
			continue // backing off after a failure
		}
		ran++
		if err := r.run(ctx, j); err != nil {
			errs = append(errs, err)
		}
	}
	return ran, errors.Join(errs...)
}

func (r *Runner) run(ctx context.Context, j store.AdminJob) error {
	h, ok := r.handlers[j.Kind]
	if !ok {
		return r.finish(ctx, j.ID, "failed", map[string]string{"error": "unknown_kind"})
	}
	// The job list was read earlier. Another worker may have finished the job
	// since, and a replacement may be queued under new parameters: running the
	// old handler then would undo the new job's work (sms-r2-12).
	if r.beforeStart != nil {
		r.beforeStart(j)
	}
	var started store.Won
	if err := r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		started, err = g.AdminJobStart(j.ID)
		return err
	}); err != nil {
		return err
	}
	if !started.Yes() {
		delete(r.failures, j.ID)
		return nil
	}
	report := func(p any) {
		b, err := json.Marshal(p)
		if err != nil {
			return
		}
		// Progress is for the operator. A failure to store it must not stop the job.
		_ = r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error { return g.AdminJobProgress(j.ID, b) })
	}
	// A handler that panics is a failed run like any other (sms-r18-5): the panic is kept by safego.Run,
	// which returns after the handler has unwound (a transaction it held has rolled back), and the
	// failure is counted below, takes the backoff and ends the job as failed after maxFail runs. Kept
	// at pass() alone it unwound the whole RunOnce loop before the count, so the same job came first
	// again on every poll with no backoff and every job behind it never ran.
	var final any
	var err error
	if safego.Run(r.log, unitHandler, func() { final, err = h(ctx, j, report) }) {
		final, err = nil, errHandlerPanicked
	}
	if errors.Is(err, errSuperseded) {
		// Someone else finished the job while this run walked the tenants. What
		// this run did before it noticed was done under the job's own parameters
		// and is safe to have done; nothing is left for it to finish.
		delete(r.failures, j.ID)
		return nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err() // shutting down; the job stays running and is picked up again
		}
		f := r.failures[j.ID]
		f.count++
		if errors.Is(err, errBadParams) || f.count >= r.maxFail {
			delete(r.failures, j.ID)
			return errors.Join(err, r.finish(ctx, j.ID, "failed", map[string]string{"error": failureCode(err)}))
		}
		step := f.count - 1
		if step >= len(r.backoff) {
			step = len(r.backoff) - 1
		}
		f.retry = r.now().Add(r.backoff[step])
		r.failures[j.ID] = f
		return err // left running: a later poll runs it again, after the backoff
	}
	delete(r.failures, j.ID)
	return r.finish(ctx, j.ID, "done", final)
}

// failureCode is the fixed text kept in the job's progress: a class, never an
// error message.
func failureCode(err error) string {
	switch {
	case errors.Is(err, errBadParams):
		return "bad_params"
	case errors.Is(err, errHandlerPanicked):
		return "panic"
	case errors.Is(err, store.ErrConnection):
		return "connection"
	}
	return "error"
}

func (r *Runner) finish(ctx context.Context, id uuid.UUID, state string, progress any) error {
	b, err := json.Marshal(progress)
	if err != nil {
		b = []byte("{}")
	}
	return r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		ended, err := g.AdminJobFinish(id, state, b)
		if err != nil {
			return err
		}
		if !ended.Yes() {
			// Another worker finished the job first and its state stands. A job id is not a
			// secret; nothing else is logged.
			r.log.Info("admin job was already finished", logattr.ID("job", id))
		}
		return nil
	})
}

// errSuperseded means the job was finished by another worker while this one
// ran it. It is not a failure and is not counted as one.
var errSuperseded = errors.New("adminjobs: job already finished")

// errHandlerPanicked is what a run reports when its handler panicked: a failure to count and retry,
// not a bad job (the handler is written to be run again, so the job may still succeed).
var errHandlerPanicked = errors.New("adminjobs: handler panicked")

// errBadParams is a job whose parameters cannot be read. Running it again would
// not help, so it ends as failed at once.
var errBadParams = errors.New("adminjobs: bad parameters")

// forEachTenant pages through the tenants and runs fn in one transaction each,
// reporting after every page. A tenant that fails stops the walk with the error:
// the job is left running and the whole walk runs again, which is safe.
func (r *Runner) forEachTenant(ctx context.Context, fn func(store.Tx) error, after func(done int)) error {
	_, _, err := r.forEachTenantWith(ctx, store.TxOpts{}, walk{}, fn, after)
	return err
}

// walk shapes one pass over the tenants.
type walk struct {
	// After is the tenant the pass starts after (Nil for the first).
	After uuid.UUID
	// Bound is the most tenants the pass runs (0 for none).
	Bound int
	// SkipRetry lets a tenant whose transaction lost a race or a lock (store.ErrRetry) be passed over, so one tenant that keeps
	// failing does not stop every tenant after it in id order. The pass still ends with that error once it has walked what it
	// should, so a job that must reach every tenant is not reported as done and runs again.
	SkipRetry bool
}

// forEachTenantWith is forEachTenant with the options of each tenant's transaction (the sweep gives them one batch id) and the
// shape of w. It returns the last tenant it ran, and more when it stopped at its bound with tenants left: the caller keeps last
// and starts there next time, so a bound never leaves the same tenants for every run.
func (r *Runner) forEachTenantWith(ctx context.Context, opts store.TxOpts, w walk, fn func(store.Tx) error, after func(done int)) (last uuid.UUID, more bool, err error) {
	cursor := w.After
	last = w.After
	done := 0
	var retried error
	for {
		var ids []uuid.UUID
		if err := r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			ids, err = g.TenantIDs(cursor, r.page)
			return err
		}); err != nil {
			return last, false, err
		}
		if len(ids) == 0 {
			return last, false, retried
		}
		for _, id := range ids {
			if err := r.db.WithTenant(ctx, id, opts, fn); err != nil {
				if !w.SkipRetry || !errors.Is(err, store.ErrRetry) || ctx.Err() != nil {
					return last, false, err
				}
				if retried == nil {
					retried = err
				}
			}
			last = id
			done++
			if w.Bound > 0 && done >= w.Bound {
				after(done)
				return last, true, retried
			}
		}
		after(done)
		if r.afterPage != nil {
			r.afterPage(done)
		}
		cursor = ids[len(ids)-1]
	}
}

// ---------------------------------------------------------------------------
// webauthn_rp_change (7.4 step 4)

type rpParams struct {
	RPID string `json:"rp_id"`
}

// RPProgress is the progress of an RP ID change.
type RPProgress struct {
	Tenants  int `json:"tenants"`
	Users    int `json:"users_notified"`
	Enforced int `json:"enforce_cleared"`
}

// webauthnRPChange marks the credentials of another RP ID stale, turns Enforce
// Passkey off for users left without a live credential, and tells each affected
// user. In each tenant all three happen in one transaction.
//
// Why a retry notifies nobody twice: only a credential that was live changes
// state, and the notification is written for the users PasskeysMarkStale
// returns, which is empty on the second pass.
func (r *Runner) webauthnRPChange(ctx context.Context, j store.AdminJob, report Report) (any, error) {
	var p rpParams
	if err := json.Unmarshal(j.Params, &p); err != nil || p.RPID == "" {
		return nil, errBadParams
	}
	var prog RPProgress
	err := r.forEachTenant(ctx, func(tx store.Tx) error {
		// The job's rp_id is only right while the job is the active one: it is
		// the RP ID in force, because the admin API sets the configuration and
		// queues the job together and refuses a second change while one is
		// active. A worker that is still walking after another finished this
		// job would otherwise mark the credentials of the NEXT RP ID stale, and
		// they could not be revived. The share lock on the job row, held to the
		// end of this transaction, keeps the job from being finished and
		// replaced underneath it (sms-r2-12, sms-r2-3).
		held, err := tx.AdminJobHold(j.ID)
		if err != nil {
			return err
		}
		if !held {
			return errSuperseded
		}
		// Users first, then their credentials (internal/lockrank: users are the first
		// rank). The order costs nothing: a credential counts as live only with this
		// RP ID, stale or not, so clearing Enforce Passkey does not wait for the marking.
		cleared, err := tx.EnforceClearWithoutLive(p.RPID)
		if err != nil {
			return err
		}
		users, err := tx.PasskeysMarkStale(p.RPID)
		if err != nil {
			return err
		}
		for _, u := range users {
			// The notification names the user by id in its params. A tenant has
			// one owner today, and the row is the tenant's, so it shows on the
			// Account page of whoever signs in.
			if err := tx.NotificationAdd("passkey_stale", "warning", mustJSON(map[string]string{"user_id": u.String()})); err != nil {
				return err
			}
		}
		prog.Users += len(users)
		prog.Enforced += int(cleared)
		return nil
	}, func(done int) {
		prog.Tenants = done
		report(prog)
	})
	if err != nil {
		return nil, err
	}
	return prog, nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
