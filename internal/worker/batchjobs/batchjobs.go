// Package batchjobs is the worker's runner of the batch jobs of P2 (docs/specs/p2-profiles.md 3.5): the drain that turns
// the job_outbox rows the api wrote into River jobs, the River handler that runs a job through the same code as the routes,
// and the sweep of the rows River can no longer end.
//
// The handler enters WithTenant for each of its transactions in turn, never nested (RULES rule 14). A job's tenant is the
// column of the outbox row, carried into River as metadata and never read from the args, which hold only the job id: a row
// that names another tenant's job finds nothing under RLS.
package batchjobs

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Args are the arguments of a River job: the job id and nothing else (RULES rule 10: River keeps them in its own table).
type Args struct {
	JobID string `json:"job_id"`
}

// Kind is the River kind of a batch job.
func (Args) Kind() string { return "batch_job" }

// The numbers of the runner (D31, provisional).
const (
	// JobTimeout is how long one run of a job may take before River stops it.
	JobTimeout = 10 * time.Minute
	// RescueAfter is the stuck-job bound of River: above the timeout, so a live job is never run twice at once.
	RescueAfter = 15 * time.Minute
	// StaleAfter is the age after which the sweep ends a row River can no longer end.
	StaleAfter = 15 * time.Minute
	// FinishedKeep is how long finished jobs and idempotency keys are kept.
	FinishedKeep = 24 * time.Hour
	// drainBatch is how many outbox rows one drain transaction takes.
	drainBatch = 50
	// sweepBatch bounds each delete of the sweep (RULES rule 16).
	sweepBatch = 500
)

// riverAttempts is River's max attempts for a job: three attempts run the work and a fourth only marks the job failed.
const riverAttempts = profiles.JobAttempts + 1

// Config builds a Runner.
type Config struct {
	Store *store.Store // opened as ctrlz_worker
	Env   *profiles.Env
	Log   *slog.Logger
	// Poll is how often the outbox is drained and River fetches (default one second), Sweep how often the sweep runs
	// (default one minute).
	Poll, Sweep time.Duration
	Now         appclock.Func
}

// Runner runs the jobs.
type Runner struct {
	cfg    Config
	client *river.Client[store.RiverTx]
}

// workerImpl is the River worker of the batch jobs.
type workerImpl struct {
	river.WorkerDefaults[Args]
	run *profiles.JobRunner
}

// errTransient is what River stores for a run that failed in a way a later attempt may mend: a closed string, so River's
// errors column and its log hold no free text (RULES rule 10).
var errTransient = errors.New("transient")

type meta struct {
	Tenant string `json:"tenant_id"`
}

// Work runs one delivery of a job. A refusal ends the job as failed with no retry; only a transient error is retried, and
// the fourth delivery only marks the job failed with job_attempts_exhausted.
func (w *workerImpl) Work(ctx context.Context, job *river.Job[Args]) error {
	var m meta
	if err := json.Unmarshal(job.Metadata, &m); err != nil {
		return river.JobCancel(errors.New("bad_metadata"))
	}
	tenant, err1 := uuid.Parse(m.Tenant)
	id, err2 := uuid.Parse(job.Args.JobID)
	if err1 != nil || err2 != nil {
		return river.JobCancel(errors.New("bad_args"))
	}
	if job.Attempt > profiles.JobAttempts {
		if err := w.run.Exhausted(ctx, tenant, id); err != nil {
			return errTransient
		}
		return river.JobCancel(errors.New("job_attempts_exhausted"))
	}
	if err := w.run.Run(ctx, tenant, id); err != nil {
		return errTransient
	}
	return nil
}

// neverSchedule is a periodic schedule that never fires.
type neverSchedule struct{}

func (neverSchedule) Next(time.Time) time.Time { return time.Time{} }

// New builds the runner and its River client. River runs poll-only: nothing in this module listens or notifies (rule 31).
func New(cfg Config) (*Runner, error) {
	if cfg.Store == nil || cfg.Env == nil || cfg.Log == nil {
		return nil, errors.New("batchjobs: Store, Env and Log are required")
	}
	if cfg.Poll <= 0 {
		cfg.Poll = time.Second
	}
	if cfg.Sweep <= 0 {
		cfg.Sweep = time.Minute
	}
	drv, err := cfg.Store.RiverDriver()
	if err != nil {
		return nil, err
	}
	jr := &profiles.JobRunner{Env: cfg.Env, Store: cfg.Store}
	workers := river.NewWorkers()
	river.AddWorker(workers, &workerImpl{run: jr})
	client, err := river.NewClient(drv, riverConfig(cfg, workers))
	if err != nil {
		return nil, err
	}
	return &Runner{cfg: cfg, client: client}, nil
}

// Drain turns outbox rows into River jobs, one transaction per batch: the rows are deleted and each River job is inserted
// in the same transaction, so a failed insert puts the rows back. It returns how many it moved.
func (r *Runner) Drain(ctx context.Context) (int, error) {
	moved := 0
	for {
		n := 0
		err := r.cfg.Store.WithGlobal(ctx, store.TxOpts{}, func(tx store.GlobalTx) error {
			rows, err := tx.JobOutboxTake(drainBatch)
			if err != nil {
				return err
			}
			for _, row := range rows {
				md, _ := json.Marshal(meta{Tenant: row.Tenant.String()})
				if err := tx.RiverInsert(func(p store.RiverTx) error {
					_, err := r.client.InsertTx(tx.Context(), p, Args{JobID: row.JobID}, &river.InsertOpts{MaxAttempts: riverAttempts, Metadata: md})
					return err
				}); err != nil {
					return err
				}
			}
			n = len(rows)
			return nil
		})
		if err != nil {
			return moved, err
		}
		moved += n
		if n < drainBatch {
			return moved, nil
		}
	}
}

// step names the closed place a failure of the runner is logged at.
type step string

// Valid reports membership, so the name can be logged.
func (s step) Valid() bool { return s == stepTenant }

const (
	stepTenant step = "tenant"
)

// Sweep ends what River can no longer end and deletes what outlived its use, tenants in pages and one WithTenant for
// each (PS 10): a queued or running row older than StaleAfter with neither an outbox row nor a River job in a non-final
// state is marked failed with job_attempts_exhausted, so the tenant's slot is always freed; finished jobs and idempotency
// keys older than a day are deleted in bounded batches.
func (r *Runner) Sweep(ctx context.Context) error {
	now := appclock.Or(r.cfg.Now)()
	var after uuid.UUID
	for {
		var ids []uuid.UUID
		err := r.cfg.Store.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(tx store.GlobalTx) (e error) {
			ids, e = tx.TenantIDs(after, 100)
			return e
		})
		if err != nil {
			return err
		}
		for _, t := range ids {
			if err := r.sweepTenant(ctx, t, now); err != nil {
				r.cfg.Log.Warn("job sweep failed for a tenant", logattr.Enum("step", stepTenant))
			}
			after = t
		}
		if len(ids) < 100 {
			return nil
		}
	}
}

func (r *Runner) sweepTenant(ctx context.Context, tenant uuid.UUID, now time.Time) error {
	var stale []uuid.UUID
	if err := r.cfg.Store.WithTenant(ctx, tenant, store.TxOpts{ReadOnly: true}, func(tx store.Tx) (e error) {
		stale, e = tx.JobStale(now.Add(-StaleAfter), sweepBatch)
		return e
	}); err != nil {
		return err
	}
	if len(stale) > 0 {
		dead, err := r.withoutLiveRiverJob(ctx, stale)
		if err != nil {
			return err
		}
		if len(dead) > 0 {
			if err := r.cfg.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
				_, e := tx.JobEndStale(dead)
				return e
			}); err != nil {
				return err
			}
		}
	}
	return r.cfg.Store.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
		// In the order of the lock registry: idempotency_keys (rank 50) before batch_jobs (rank 710).
		if _, err := tx.IdempotencyPurge(now, sweepBatch); err != nil {
			return err
		}
		_, err := tx.JobsPurge(now.Add(-FinishedKeep), sweepBatch)
		return err
	})
}

// liveStates are the River states in which a job can still run or be run again.
func liveStates() []rivertype.JobState {
	return []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRetryable, rivertype.JobStateRunning, rivertype.JobStateScheduled}
}

// withoutLiveRiverJob keeps the ids that no River job in a non-final state names. It asks River about each id on its
// own and never lists the live jobs of every tenant in one page: a page of 10,000 cut the list at the 10,001st live job,
// and a queued row whose job lay past the cut was failed while River still held the job (p2-B3-r12-1). A stale row is the
// rare case (a job older than StaleAfter with no outbox row), so one small query for each is the cheap way to be exact.
func (r *Runner) withoutLiveRiverJob(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	var dead []uuid.UUID
	for _, id := range ids {
		res, err := r.client.JobList(ctx, river.NewJobListParams().Kinds(Args{}.Kind()).States(liveStates()...).
			Where("args->>'job_id' = @job_id", river.NamedArgs{"job_id": id.String()}).First(1))
		if err != nil {
			return nil, err
		}
		if len(res.Jobs) == 0 {
			dead = append(dead, id)
		}
	}
	return dead, nil
}

// loopName names a background loop of the runner for safego and the log.
type loopName string

const (
	loopDrain loopName = "drain"
	loopSweep loopName = "sweep"
)

// Valid reports membership: the two loops of the runner.
func (n loopName) Valid() bool { return n == loopDrain || n == loopSweep }

// Run starts River, then drains and sweeps until ctx ends. It returns when both loops and the client have stopped.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.client.Start(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	loop := func(name loopName, every time.Duration, f func(context.Context) error) {
		wg.Add(1)
		safego.Go(r.cfg.Log, name, func() {
			defer wg.Done()
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				r.pass(ctx, name, f)
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		})
	}
	loop(loopDrain, r.cfg.Poll, func(ctx context.Context) error { _, err := r.Drain(ctx); return err })
	loop(loopSweep, r.cfg.Sweep, r.Sweep)
	<-ctx.Done()
	wg.Wait()
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return r.client.Stop(stop)
}

// pass runs one pass of a loop and keeps its panic, so a panic costs that pass and the loop goes on at its next tick: a
// loop that ended on a panic would leave a worker that looks healthy to Compose and does nothing (the worker role's rule,
// internal/safego). Every unit of the runner is written to be run again from a crash: a drain row is deleted only after
// River holds the job, and a sweep is idempotent.
func (r *Runner) pass(ctx context.Context, name loopName, f func(context.Context) error) {
	defer safego.Keep(r.cfg.Log, name)
	if err := f(ctx); err != nil && ctx.Err() == nil {
		r.cfg.Log.Warn("batch job loop failed", logattr.Enum("loop", name))
	}
}

// riverConfig is the configuration the runner gives River, in one place so a test can read the two bounds that must keep
// their order: a run is stopped at JobTimeout and River rescues a job it thinks stuck only after RescueAfter, which is
// later, so a live job slowed to just under its timeout is never run a second time at once (spec 3.5, 10.5).
func riverConfig(cfg Config, workers *river.Workers) *river.Config {
	return &river.Config{
		Schema:               "river",
		PollOnly:             true,
		FetchPollInterval:    cfg.Poll,
		JobTimeout:           JobTimeout,
		RescueStuckJobsAfter: RescueAfter,
		Queues:               map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 2}},
		Workers:              workers,
		Logger:               cfg.Log,
		// The reindexer needs the owner of the river tables, which the worker is not.
		ReindexerSchedule: neverSchedule{},
	}
}
