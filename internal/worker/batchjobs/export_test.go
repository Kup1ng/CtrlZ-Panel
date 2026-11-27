package batchjobs

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
)

// WorkDelivery runs the River handler for one delivery of a job, as River would, so a test can reach the branches a
// real queue only meets after failures (the fourth delivery, a transient error).
func (r *Runner) WorkDelivery(ctx context.Context, tenant, jobID string, attempt int) error {
	w := &workerImpl{run: &profiles.JobRunner{Env: r.cfg.Env, Store: r.cfg.Store}}
	md, _ := json.Marshal(meta{Tenant: tenant})
	return w.Work(ctx, &river.Job[Args]{JobRow: &rivertype.JobRow{Attempt: attempt, Metadata: md}, Args: Args{JobID: jobID}})
}

// IsCancel reports whether err is River's cancel of a job (the end of a job with no retry).
func IsCancel(err error) bool {
	var c *rivertype.JobCancelError
	return errors.As(err, &c)
}

// RiverBounds is what the runner really gives River: the bound that stops a run and the one after which River rescues a job.
func RiverBounds(cfg Config) (timeout, rescue time.Duration) {
	c := riverConfig(cfg, river.NewWorkers())
	return c.JobTimeout, c.RescueStuckJobsAfter
}

// ReindexerPlan is what the runner gives River's reindexer: when it would run next after now, and the indexes it would reindex.
func ReindexerPlan(cfg Config, now time.Time) (next time.Time, indexes []string, indexesSet bool) {
	c := riverConfig(cfg, river.NewWorkers())
	return c.ReindexerSchedule.Next(now), c.ReindexerIndexNames, c.ReindexerIndexNames != nil
}
