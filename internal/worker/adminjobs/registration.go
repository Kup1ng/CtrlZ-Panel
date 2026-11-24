package adminjobs

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The registration sweep (P3 spec 4.4, AUTH 11.5, T-269): what the registration mode does to the Plain DNS claims that were
// never proven. Moving to `open` gives each unproven active claim its one grace (suspends it at once when it already had it)
// and suspends a claim whose grace ended; any other mode puts a claim in grace back to active. A suspended claim stays until an
// admin clears it.
//
// Correctness never rests on the job: the sweep reads the mode in force, inside each tenant's transaction, and runs again every
// ten minutes under a lease, so a crash, a missed job or a worker that was down leaves nothing wrong for long. Every statement
// is bounded and idempotent, one transaction per tenant, so two workers at once do the same work twice and no harm.

const (
	// SweepEvery is the cadence of the periodic sweep.
	SweepEvery = 10 * time.Minute
	// sweepLease is how long a worker holds the lease of the periodic sweep: a worker that died leaves it for the next to take.
	sweepLease = 9 * time.Minute
	// sweepTenantBudget bounds the tenants one periodic run walks; the next run starts after the last one this run reached (and
	// wraps at the end of the list), so no tenant waits for ever behind the first sweepTenantBudget ids. A job walks them all.
	sweepTenantBudget = 50000
	// leaseName is the row of ctrlz.leases the periodic sweep holds.
	leaseName = "registration_sweep"
)

// Notification kinds the sweep writes to the tenant (AUTH 13).
const (
	notifyGrace     = "ip_grace_started"
	notifySuspended = "ip_suspended"
)

// RegistrationProgress is the progress of a registration transition, and the result of one sweep run.
type RegistrationProgress struct {
	Tenants int `json:"tenants"`
	// Claims counts the active claims still unproven when the walk met each tenant (what P1 reported, and what the impact page
	// counts before the move).
	Claims    int `json:"claims"`
	Graced    int `json:"graced"`
	Suspended int `json:"suspended"`
	Restored  int `json:"restored"`
}

// registrationTransition is the handler of the job.
func (r *Runner) registrationTransition(ctx context.Context, j store.AdminJob, report Report) (any, error) {
	prog, err := r.sweepClaims(ctx, j.ID, report)
	if err != nil {
		return nil, err
	}
	return prog, nil
}

// SweepClaims runs the sweep once, with no job behind it.
func (r *Runner) SweepClaims(ctx context.Context) (RegistrationProgress, error) {
	return r.sweepClaims(ctx, uuid.Nil, func(any) {})
}

// sweepClaims walks the tenants, one transaction each, all of them in one batch (so the compiler emits one config entry for
// the run). job is the admin job that asked, or Nil: a run for a job stops when another change has superseded it.
func (r *Runner) sweepClaims(ctx context.Context, job uuid.UUID, report Report) (RegistrationProgress, error) {
	var prog RegistrationProgress
	batch, err := uuid.NewV7()
	if err != nil {
		return prog, err
	}
	w := walk{SkipRetry: true}
	if job == uuid.Nil {
		// The periodic sweep is bounded and resumes where the last one stopped. A job is not: it ends as done only when it has
		// walked every tenant (it ends the walk with the error of a tenant it had to pass over, and then runs again).
		// The mutex guards the place only, never the walk: two runs at once repeat idempotent work and do no harm.
		r.sweepMu.Lock()
		w.After, w.Bound = r.sweepAfter, r.sweepBudget
		r.sweepMu.Unlock()
	}
	last, more, err := r.forEachTenantWith(ctx, store.TxOpts{Batch: batch}, w, func(tx store.Tx) error {
		if job != uuid.Nil {
			held, err := tx.AdminJobHold(job)
			if err != nil {
				return err
			}
			if !held {
				return errSuperseded
			}
		}
		mode, grace, err := tx.RegistrationForSweep()
		if err != nil {
			return err
		}
		var res store.ClaimSweep
		if mode == "open" {
			res, err = tx.ClaimsSweepOpen(grace)
		} else {
			res, err = tx.ClaimsSweepClosed()
		}
		if err != nil {
			return err
		}
		n, err := tx.UnprovenClaims()
		if err != nil {
			return err
		}
		prog.Claims += n
		prog.Graced += res.Graced
		prog.Suspended += res.Suspended
		prog.Restored += res.Restored
		if res.Graced > 0 {
			if err := tx.NotificationAdd(notifyGrace, "warning", mustJSON(map[string]int{"count": res.Graced, "grace_days": grace})); err != nil {
				return err
			}
		}
		if res.Suspended > 0 {
			if err := tx.NotificationAdd(notifySuspended, "critical", mustJSON(map[string]int{"count": res.Suspended})); err != nil {
				return err
			}
			// A suspended claim leaves the set the nodes serve (spec 4.1); a grace or a restore changes no record.
			return store.MarkDirty(tx, store.AggregateEndpointSet, tx.TenantID())
		}
		return nil
	}, func(done int) {
		prog.Tenants = done
		report(prog)
	})
	if job == uuid.Nil && (err == nil || errors.Is(err, store.ErrRetry)) {
		// A pass that stopped at its bound is resumed after its last tenant; one that reached the end of the list starts over.
		// A walk that ended in an error other than a passed-over tenant leaves the place as it was.
		next := uuid.Nil
		if more {
			next = last
		}
		r.sweepMu.Lock()
		r.sweepAfter = next
		r.sweepMu.Unlock()
	}
	return prog, err
}

// sweepHolder names this worker in the lease. It is made once per Runner from a random id, so two workers never share a holder
// and a restarted one does not inherit its predecessor's lease.
func sweepHolder() string {
	id, err := uuid.NewRandom()
	if err != nil {
		return "worker"
	}
	return id.String()
}

// runSweepOnce takes the lease and, when it wins, sweeps. A worker that does not win does nothing: another is sweeping.
func (r *Runner) runSweepOnce(ctx context.Context) {
	defer safego.Keep(r.log, unitSweep)
	var ok bool
	if err := r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		ok, err = g.LeaseTake(leaseName, r.holder, int(sweepLease.Seconds()))
		return err
	}); err != nil {
		// Not winning the lease is silent, but a lease that cannot be read is not: the sweep keeps open registration correct when a
		// job was missed, and a broken grant or statement would otherwise stop it with nothing in the log.
		if ctx.Err() == nil {
			r.log.Warn("registration sweep lease failed", logattr.Enum("error_class", errClass(err)))
		}
		return
	} else if !ok {
		return
	}
	if _, err := r.SweepClaims(ctx); err != nil && ctx.Err() == nil {
		r.log.Warn("registration sweep failed", logattr.Enum("error_class", errClass(err)))
	}
}
