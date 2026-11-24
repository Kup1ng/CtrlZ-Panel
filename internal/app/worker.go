package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/senders"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/adminjobs"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/batchjobs"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/sweep"
)

// startWorker starts the three background loops of the worker role (spec 9.5,
// 7.4, 11.2): the SMS sender, the sweeps and the admin job runner. They share
// the worker's store and run until ctx ends. The returned function waits for
// them, bounded by wait, so a shutdown does not hang on a gateway call.
//
// A loop that fails to build stops the process: a worker that cannot send SMS or
// sweep is worse than one that is not running, because Compose would see it as
// healthy.
func startWorker(ctx context.Context, cfg Config, rt *Runtime, st *store.Store, log *slog.Logger) (func(wait time.Duration), error) {
	if rt.Keys == nil {
		return nil, errors.New("worker: no key ring")
	}
	source := smssend.NewSource(st, rt.Keys, senders.Env{Name: string(cfg.Env), NoopFile: cfg.NoopSMSFile}, log)
	sender, err := smssend.New(smssend.Config{Store: st, Router: sms.NewRouter(source, classify.Routing{}, sms.WithLog(log)), Keys: rt.Keys, Log: log})
	if err != nil {
		return nil, err
	}
	sweeper, err := sweep.New(sweep.Config{Store: st, Log: log})
	if err != nil {
		return nil, err
	}
	jobs, err := adminjobs.New(adminjobs.Config{Store: st, Log: log})
	if err != nil {
		return nil, err
	}

	// The batch jobs of P2 (spec 3.5): the drain of job_outbox into River, the handler and the job sweep. The jobs run the code of
	// the routes, so the location catalog is the one the api reads.
	batch, err := batchjobs.New(batchjobs.Config{Store: st, Env: &profiles.Env{Catalog: locations.Store{}}, Log: log})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for name, run := range map[workerLoop]func(context.Context) error{
		loopSMS: sender.Run, loopSweep: sweeper.Run, loopAdminJobs: jobs.Run, loopBatchJobs: batch.Run,
	} {
		wg.Add(1)
		safego.Go(log, name, func() {
			// A panic of a loop ends nothing else: the loops share a process with the rows of the SMS queue
			// that a provider has accepted and that are not yet recorded (sms-r17-17).
			defer wg.Done()
			if err := run(ctx); err != nil && ctx.Err() == nil {
				log.Error("worker loop stopped", logattr.Enum("loop", name))
			}
		})
	}
	log.Info("worker loops started")
	return func(wait time.Duration) {
		cancel()
		done := make(chan struct{})
		safego.Go(log, loopStop, func() { wg.Wait(); close(done) })
		select {
		case <-done:
		case <-time.After(wait):
			log.Warn("worker loops did not stop in time")
		}
	}, nil
}

// workerLoop names a background loop for the log: a closed type, so a log line can
// carry it (rule closed-values-in-logs).
type workerLoop string

const (
	loopSMS       workerLoop = "sms"
	loopSweep     workerLoop = "sweep"
	loopAdminJobs workerLoop = "admin_jobs"
	loopBatchJobs workerLoop = "batch_jobs"
	loopStop      workerLoop = "stop" // the goroutine that waits for the loops at shutdown
)

// Valid reports membership.
func (l workerLoop) Valid() bool {
	return l == loopSMS || l == loopSweep || l == loopAdminJobs || l == loopBatchJobs || l == loopStop
}
