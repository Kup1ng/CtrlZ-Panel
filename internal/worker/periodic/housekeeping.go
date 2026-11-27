package periodic

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sweepbatch"
)

// Enrollments is the expiry of node enrolments (4.2, 8): every minute, an enrolment nobody finished becomes expired, and
// enrolments that are over are deleted a week after their expiry. The two steps are independent, so a failure of one leaves the
// other to run.
func (r *Runner) Enrollments(ctx context.Context) error {
	expired, err1 := r.drain(ctx, func(g store.GlobalTx, limit int) (int, error) { return g.EnrollmentsExpire(limit) })
	deleted, err2 := r.drain(ctx, func(g store.GlobalTx, limit int) (int, error) { return g.EnrollmentsDelete(limit) })
	if expired+deleted > 0 {
		r.log.Info("enrolments swept", logattr.Int("expired", expired), logattr.Int("deleted", deleted))
	}
	return errors.Join(err1, err2)
}

// FreeCounters deletes the free DNS counters and the dedupe rows of their batches after 30 days (PS 5).
func (r *Runner) FreeCounters(ctx context.Context) error {
	return r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, _, err := g.FreeCountersSweep()
		return err
	})
}

// ruleProfilesPerBatch is how many profiles one batch of the purge names; a batch deletes at most Batch rules of them.
const ruleProfilesPerBatch = 50

// ExpiredRules deletes the rules past their expiry (T-185), tenant by tenant, a thousand at a time. It is a system writer of
// the profile tables: it takes no profile lock and writes no outbox row, since an expired rule is inert on the node already,
// and it steps the version of every profile it deleted from in the same transaction, so the rule count of the profile list
// is not served stale (P2 3.1). Each batch is its own transaction, so a tenant with a backlog meets the statement timeout on
// one batch and not on the whole purge.
func (r *Runner) ExpiredRules(ctx context.Context) error {
	_, complete, err := r.walkTenants(ctx, uuid.Nil, func(ctx context.Context, tenant uuid.UUID) error {
		_, err := sweepbatch.Drain(ctx, sweepbatch.Plan{Size: r.batch, Max: 200}, func(ctx context.Context, size int) (n int, more bool, err error) {
			// A batch names at most ruleProfilesPerBatch profiles, so a full page of profiles means more may wait behind it even when
			// the rules it deleted are fewer than size: the drain goes on while either is full.
			fullPage := false
			err = r.db.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
				n, fullPage = 0, false
				now := appclock.Now()
				profiles, err := tx.ExpiredRuleProfiles(now, ruleProfilesPerBatch)
				if err != nil || len(profiles) == 0 {
					return err
				}
				fullPage = len(profiles) == ruleProfilesPerBatch
				// The profile rows first, in id order, then their rules: the order every profile write of the module takes.
				if err := tx.ProfilesBumpVersion(profiles); err != nil {
					return err
				}
				n, err = tx.ExpiredRulesDelete(profiles, now, size)
				return err
			})
			return n, n >= size || fullPage, err
		})
		return err
	})
	return unfinished(ctx, complete, err)
}

// unfinished makes a walk that stopped for time an error. A daily job counts as done for the day when it returns nil, and the
// walk no longer reports the tenant it was cut off in (J12-r3-5), so a run that ended early must say so itself.
func unfinished(ctx context.Context, complete bool, err error) error {
	if err == nil && !complete {
		return ctx.Err()
	}
	return err
}

// Horizon marks endpoint_set for every tenant that has a schedule, once a day. The compiler writes the offset transitions of an
// Endpoint's zone 400 days ahead of the day it compiles (D31), and writes a record again only when a transition enters the
// horizon, so a daily mark costs a diff and keeps the coverage at 399 days or more, well beyond the 60-day margin the spec asks
// for. The worker cannot read an Endpoint's zone (it holds no grant on schedule_timezone), so it cannot tell a zone that has
// transitions from one that has none: it marks every tenant that has a window, and the compile of a zone with none changes nothing.
func (r *Runner) Horizon(ctx context.Context) error {
	_, complete, err := r.walkTenants(ctx, uuid.Nil, func(ctx context.Context, tenant uuid.UUID) error {
		return r.db.WithTenant(ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
			has, err := tx.HasScheduleWindows()
			if err != nil || !has {
				return err
			}
			return store.MarkDirty(tx, store.AggregateEndpointSet, tenant)
		})
	})
	return unfinished(ctx, complete, err)
}
