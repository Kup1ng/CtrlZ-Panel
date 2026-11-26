// Package periodic is the worker's clock-driven jobs of P4 (docs/specs/p4-nodes.md 8, package J2): the DDNS pass, the purge of
// expired rules, the sweep of the free DNS counters, the schedule horizon mark, the expiry of node enrolments, and the pruning
// of the config log with the collection of blobs.
//
// How they are scheduled. Each job has its own goroutine and its own period, so a slow one (the DDNS pass over every tenant)
// never holds back a quick one (the enrolment expiry, every minute), and a job that fails raises an alert and waits for its next
// period without touching the others. One worker at a time runs a job: it takes a lease named after the job (ctrlz.leases, the
// table the compiler and the registration sweep use), and renews it on each run; a worker that dies loses it when it runs out.
// Every job is a function of the database state and is safe to run twice, so the lease saves work and is not what keeps the
// data right. A daily job holds the same short lease while it runs, renewed from a goroutine, and takes it until the end of the
// UTC day only once it has returned without an error: so a second tick of the same worker and a restart of another do not run
// it again the same day, and a worker that dies in the middle of a run (a deploy, a crash) leaves a lease that ends in minutes,
// not one that shuts the job out until midnight (J12-r3-1).
package periodic

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sweepbatch"
)

// Job names a job: for the lease, the log and the alert. A closed type, so a log line and an alert can carry it.
type Job string

// The jobs.
const (
	JobDDNS        Job = "ddns"
	JobEnrollments Job = "enrollments"
	JobRules       Job = "expired_rules"
	JobCounters    Job = "free_counters"
	JobHorizon     Job = "schedule_horizon"
	JobPrune       Job = "log_pruning"
)

// Valid reports membership.
func (j Job) Valid() bool {
	switch j {
	case JobDDNS, JobEnrollments, JobRules, JobCounters, JobHorizon, JobPrune:
		return true
	}
	return false
}

// String is the name.
func (j Job) String() string { return string(j) }

// Reason is why a job raises an alert: a closed set, because an alert's params reach the admin page.
type Reason string

// The reasons.
const (
	ReasonJobFailed  Reason = "job_failed"        // a job returned an error
	ReasonDDNSInject Reason = "ddns_injected"     // a DDNS host answered with the block page address some networks inject
	ReasonDDNSMany   Reason = "ddns_too_many"     // a DDNS host answered with more public addresses than the cap
	ReasonDDNSStale  Reason = "ddns_lookup_stale" // a DDNS host has had no usable answer for 24 hours
	ReasonGCHeld     Reason = "blob_gc_held"      // an active node has held back the collection of blobs for a day
)

// Valid reports membership.
func (r Reason) Valid() bool {
	switch r {
	case ReasonJobFailed, ReasonDDNSInject, ReasonDDNSMany, ReasonDDNSStale, ReasonGCHeld:
		return true
	}
	return false
}

// String is the text of the reason.
func (r Reason) String() string { return string(r) }

// AlertKind is the kind of every alert of this package.
const AlertKind = "periodic"

type jobAlert struct {
	Reason Reason `json:"reason"`
	Job    Job    `json:"job"`
}

type hostAlert struct {
	Reason   Reason    `json:"reason"`
	Tenant   uuid.UUID `json:"tenant_id"`
	Endpoint uuid.UUID `json:"endpoint_id"`
	Host     uuid.UUID `json:"host_id"`
}

type nodeAlert struct {
	Reason Reason    `json:"reason"`
	Node   uuid.UUID `json:"node_id"`
}

// ClaimBudget charges the `ip-claim` class (P3 4.5) of a tenant for one ip_claim_request the DDNS pass is about to make.
type ClaimBudget interface {
	// Allow says whether the tenant may make one more claim request now, and charges it.
	Allow(ctx context.Context, tenant uuid.UUID) (bool, error)
}

// Blobs is the artifact store the pruning deletes files from (the volume the compiler writes, 6.5).
type Blobs interface {
	// Delete removes the file of a hash; a file that is not there is not an error.
	Delete(hash []byte) error
}

// Config builds a Runner.
type Config struct {
	Store *store.Store // opened as ctrlz_worker
	Log   *slog.Logger
	// Resolver answers the DDNS lookups. Nil disables the DDNS job.
	Resolver Resolver
	// Claims charges ip-claim. Nil lets every request through (a test).
	Claims ClaimBudget
	// Blobs is the artifact store. Nil leaves the blob rows alone (a worker with no artifact volume has no compiler).
	Blobs Blobs
	// Page is how many tenants one read returns (default 100); Batch is the rows of one bounded delete (default 1000).
	Page, Batch int
	// Holder names this worker in the leases; default a random id.
	Holder string
}

// Runner runs the jobs.
type Runner struct {
	db       *store.Store
	log      *slog.Logger
	resolver Resolver
	claims   ClaimBudget
	blobs    Blobs
	page     int
	batch    int
	holder   string
	// tenantBudget is ddnsTenantBudget; a field so that a test can shorten it.
	tenantBudget time.Duration

	mu        sync.Mutex
	ddnsAfter uuid.UUID               // where the next DDNS pass resumes after a pass that ran out of time
	ddnsStart map[uuid.UUID]int       // per tenant: the host the next pass starts its lookups at, after a budget that ran out
	heldSince map[uuid.UUID]time.Time // the first pass that found an active node holding blob collection back
	doneDay   map[Job]string          // the UTC day a daily job last ran here

	// afterTenant is a hook of tests, called after each tenant a walk finished.
	afterTenant func(done int)

	// lease and alert are what attempt asks of the database; fields so that a test of the schedule needs none.
	lease func(ctx context.Context, name string, secs int) (bool, error)
	alert func(ctx context.Context, j Job)
}

// New returns a Runner.
func New(c Config) (*Runner, error) {
	if c.Store == nil || c.Log == nil {
		return nil, errors.New("periodic: store and log are required")
	}
	r := &Runner{
		db: c.Store, log: c.Log, resolver: c.Resolver, claims: c.Claims, blobs: c.Blobs, page: c.Page, batch: c.Batch, holder: c.Holder,
		heldSince: map[uuid.UUID]time.Time{}, doneDay: map[Job]string{}, ddnsStart: map[uuid.UUID]int{},
		tenantBudget: ddnsTenantBudget,
	}
	if r.page <= 0 {
		r.page = 100
	}
	if r.batch <= 0 {
		r.batch = 1000
	}
	if r.holder == "" {
		r.holder = uuid.NewString()
	}
	r.lease = r.leaseTake
	r.alert = r.alertJob
	return r, nil
}

// spec is the schedule of one job.
type spec struct {
	job    Job
	every  time.Duration // the period; a daily job is tried every tick and runs once a UTC day
	budget time.Duration // how long one run may take, below the period for the others
	daily  bool
	run    func(context.Context) error
}

func (r *Runner) specs() []spec {
	out := []spec{
		{job: JobEnrollments, every: time.Minute, budget: 50 * time.Second, run: r.Enrollments},
		{job: JobPrune, every: time.Hour, budget: 50 * time.Minute, run: r.Prune},
		{job: JobRules, every: 10 * time.Minute, budget: 6 * time.Hour, daily: true, run: r.ExpiredRules},
		{job: JobCounters, every: 10 * time.Minute, budget: time.Hour, daily: true, run: r.FreeCounters},
		{job: JobHorizon, every: 10 * time.Minute, budget: 6 * time.Hour, daily: true, run: r.Horizon},
	}
	if r.resolver != nil {
		out = append(out, spec{job: JobDDNS, every: 5 * time.Minute, budget: 4*time.Minute + 30*time.Second, run: r.DDNS})
	}
	return out
}

// Run runs every job on its schedule until ctx ends.
func (r *Runner) Run(ctx context.Context) error {
	r.log.Info("periodic jobs started")
	var wg sync.WaitGroup
	for _, s := range r.specs() {
		wg.Add(1)
		safego.Go(r.log, s.job, func() {
			defer wg.Done()
			r.loop(ctx, s)
		})
	}
	wg.Wait()
	return nil
}

func (r *Runner) loop(ctx context.Context, s spec) {
	r.attempt(ctx, s)
	t := time.NewTicker(s.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.attempt(ctx, s)
		}
	}
}

// attempt takes the lease and, when it wins, runs the job once. A panic of the job ends that run and nothing else.
func (r *Runner) attempt(ctx context.Context, s spec) {
	defer safego.Keep(r.log, s.job)
	now := appclock.Now().UTC()
	day := now.Format("2006-01-02")
	if s.daily {
		r.mu.Lock()
		done := r.doneDay[s.job] == day
		r.mu.Unlock()
		if done {
			return
		}
	}
	// Twice the period, for every job: a run that ends without a clean return, or a worker that dies, frees the job for
	// another worker after that long, and the same worker renews it on its next tick.
	secs := int(2 * s.every / time.Second)
	name := "p4_" + s.job.String()
	if ok, err := r.lease(ctx, name, secs); err != nil {
		if ctx.Err() == nil {
			r.log.Warn("periodic lease failed", logattr.Enum("job", s.job), logattr.Enum("error_class", errClass(err)))
		}
		return
	} else if !ok {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, s.budget)
	defer cancel()
	stop := func() {}
	if s.daily {
		// A daily run may last hours, far past the lease, so it is renewed while it runs; a lease that was lost (another
		// worker holds it now) ends the run.
		stop = r.keepLease(rctx, cancel, s, name, secs)
	}
	err := s.run(rctx)
	stop() // before the day's lease below, so that no late renewal shortens it
	if err != nil {
		if ctx.Err() == nil {
			r.log.Warn("periodic job failed", logattr.Enum("job", s.job), logattr.Enum("error_class", errClass(err)))
			r.alert(ctx, s.job)
		}
		return
	}
	if s.daily {
		r.mu.Lock()
		r.doneDay[s.job] = day
		r.mu.Unlock()
		// Done for the day: hold the lease until its end so that no other worker runs the job again today. Without it the
		// others would run it once more, which is safe and only costs the work.
		// The remainder is measured from the end of the run, not its start: a run of hours would otherwise take a lease that is
		// already over. A run that crossed midnight has no lease to take, since its day is gone (J12-r4-2).
		done := appclock.Now().UTC()
		if done.Format("2006-01-02") != day {
			return
		}
		end := int(done.Truncate(24*time.Hour).Add(24*time.Hour).Sub(done)/time.Second) + 1
		if _, err := r.lease(ctx, name, end); err != nil && ctx.Err() == nil {
			r.log.Warn("periodic lease failed", logattr.Enum("job", s.job), logattr.Enum("error_class", errClass(err)))
		}
	}
}

// keepLease renews the lease of a running daily job twice a period and cancels the run when it finds the lease gone. It returns
// the function that stops it and waits for it to end.
func (r *Runner) keepLease(ctx context.Context, cancel context.CancelFunc, s spec, name string, secs int) (stop func()) {
	kctx, end := context.WithCancel(ctx)
	done := make(chan struct{})
	safego.Go(r.log, s.job, func() {
		defer close(done)
		t := time.NewTicker(s.every / 2)
		defer t.Stop()
		for {
			select {
			case <-kctx.Done():
				return
			case <-t.C:
				ok, err := r.lease(kctx, name, secs)
				if err != nil {
					// A database that does not answer for a moment: the run goes on, the lease has half its time left.
					if kctx.Err() == nil {
						r.log.Warn("periodic lease renewal failed", logattr.Enum("job", s.job), logattr.Enum("error_class", errClass(err)))
					}
					continue
				}
				if !ok && kctx.Err() == nil {
					r.log.Warn("periodic lease lost", logattr.Enum("job", s.job))
					cancel()
					return
				}
			}
		}
	})
	return func() { end(); <-done }
}

func (r *Runner) leaseTake(ctx context.Context, name string, secs int) (ok bool, err error) {
	err = r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		ok, err = g.LeaseTake(name, r.holder, secs)
		return err
	})
	return ok, err
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

// alertJob raises the alert of a failed job, open once until an admin acknowledges it.
func (r *Runner) alertJob(ctx context.Context, j Job) {
	params, err := closed.NewParams(jobAlert{Reason: ReasonJobFailed, Job: j})
	if err != nil {
		return
	}
	r.raise(ctx, "warning", closed.NewKey(ReasonJobFailed, j), params)
}

func (r *Runner) raise(ctx context.Context, severity string, key closed.Key, params closed.Params) {
	if err := r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := g.AlertOnce(severity, AlertKind, key, params)
		return err
	}); err != nil && ctx.Err() == nil {
		r.log.Warn("periodic alert failed", logattr.Enum("error_class", errClass(err)))
	}
}

// RunJob runs one job now, without the lease and the schedule. It is what the tests and an operator's one-off call use.
func (r *Runner) RunJob(ctx context.Context, j Job) error {
	for _, s := range r.specs() {
		if s.job == j {
			return s.run(ctx)
		}
	}
	return errors.New("periodic: no such job")
}

// drain runs one bounded statement in its own transactions until it handles fewer rows than a batch.
func (r *Runner) drain(ctx context.Context, step func(g store.GlobalTx, limit int) (int, error)) (int, error) {
	return sweepbatch.Drain(ctx, sweepbatch.Plan{Size: r.batch, Max: 200}, func(ctx context.Context, size int) (n int, more bool, err error) {
		err = r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
			n, err = step(g, size)
			return err
		})
		return n, n >= size, err
	})
}

// walkTenants calls fn for each tenant after the given one, in pages. A tenant whose fn failed does not stop the walk: the
// errors are joined and the next tenant goes on. It stops early, and says so, when ctx ends or fn says there is no time left
// for another tenant; the tenant it stopped in is not counted as handled and not as failed. last is the last tenant it
// handled, where a later walk can resume.
func (r *Runner) walkTenants(ctx context.Context, after uuid.UUID, fn func(context.Context, uuid.UUID) error) (last uuid.UUID, complete bool, err error) {
	var errs []error
	done := 0
	for ctx.Err() == nil {
		var ids []uuid.UUID
		if e := r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			ids, err = g.TenantIDs(after, r.page)
			return err
		}); e != nil {
			return after, false, errors.Join(append(errs, e)...)
		}
		if len(ids) == 0 {
			return uuid.Nil, true, errors.Join(errs...)
		}
		for _, id := range ids {
			if ctx.Err() != nil {
				return after, false, errors.Join(errs...)
			}
			if e := fn(ctx, id); e != nil {
				// A tenant the pass ran out of time in is not done and did not fail: it is where the next pass begins, and
				// the job has not failed for doing what it was built to do (J12-r3-5).
				if ctx.Err() != nil || errors.Is(e, errOutOfTime) {
					return after, false, errors.Join(errs...)
				}
				errs = append(errs, e)
			}
			after = id
			done++
			if r.afterTenant != nil {
				r.afterTenant(done)
			}
		}
		if len(ids) < r.page {
			return uuid.Nil, true, errors.Join(errs...)
		}
	}
	return after, false, errors.Join(errs...)
}
