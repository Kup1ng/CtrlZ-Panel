package periodic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/closed"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Log pruning and blob collection (T-083, docs/specs/p4-nodes.md 6.5 and 8). The compiler keeps the two latest snapshots; a node
// that is behind the older one starts from GetSnapshot, so the log below it is no node's to ask for. A blob the latest state
// does not bind carries gc_after_seq, the seq of the entry that unbound it, and may go once no node can still need it: every
// active node has applied past it, and the kept snapshots no longer name it (they are at or above it).
//
// The rows go first and each file after its row, all inside one transaction that holds the log lock of the compiler
// (ctrlz_fn.config_log_lock, PS 10) until it commits, so a re-bind never interleaves with a delete: the compiler takes the same
// lock to bind a hash again, so it meets either the row and its file or neither. A file is never removed after the lock is
// released, which would leave a row the compiler had just bound with no file behind it. The compiler must write the file
// again under the lock when it finds it missing, and not only stat it (docs/specs/p4-nodes.md 6.5).

// holdAlertAfter is how long an active node may hold the collection back before an alert.
const holdAlertAfter = 24 * time.Hour

// Prune runs one pass.
func (r *Runner) Prune(ctx context.Context) error {
	var floor uint64
	var haveFloor bool
	var applied []store.NodeApplied
	if err := r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
		if floor, haveFloor, err = g.PruneFloor(); err != nil || !haveFloor {
			return err
		}
		applied, err = g.ActiveApplied()
		return err
	}); err != nil {
		return err
	}
	if !haveFloor {
		return nil // no snapshot yet: nothing is known to be unneeded
	}

	var errs []error
	// The log, a batch at a time, each under the lock.
	logRows, err := r.drain(ctx, func(g store.GlobalTx, limit int) (int, error) {
		if err := g.ConfigLogLock(); err != nil {
			return 0, err
		}
		return g.ConfigLogPrune(floor, limit)
	})
	if err != nil {
		errs = append(errs, err)
	}

	// The blobs. The lowest applied_seq of the active nodes is read inside each batch's transaction, after the lock, so the
	// batch judges the nodes as they are when it deletes.
	if r.blobs != nil {
		blobs, err := r.collect(ctx, floor)
		if err != nil {
			errs = append(errs, err)
		}
		if blobs > 0 || logRows > 0 {
			r.log.Info("log pruned", logattr.Int("log_rows", logRows), logattr.Int("blobs", blobs))
		}
		if err := r.alertHolders(ctx, floor, applied); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// fileGroup is how many files are unlinked between two checks that the transaction holding the log lock is still alive.
const fileGroup = 50

// collect removes the collectable blobs in batches under the lock: each file, then its row, before the batch commits. The files
// go in groups with a statement between them, because the lock is only as good as the transaction that holds it: a failover,
// or the transaction timeout on a stalled volume, rolls the rows back and frees the lock, and a loop that went on unlinking
// then would remove files of hashes the compiler has bound again meanwhile (J12-r2-7). A file that will not go keeps its row
// and the pass goes on past it (the next batch starts after it), so one stuck file blocks nothing else (J12-r3-2); the pass
// still ends with an error, which raises the job's alert, and the row is tried again next pass. A batch whose commit fails after
// its files went leaves rows that are still collectable and files that are gone, which is harmless: the next pass deletes the
// rows (a file that is not there is not an error), and the compiler writes a missing file again under the lock when it binds
// the hash (6.5).
func (r *Runner) collect(ctx context.Context, floor uint64) (int, error) {
	total := 0
	var after []byte
	var failed []error
	for ctx.Err() == nil {
		var res store.CollectResult
		if err := r.db.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
			res = store.CollectResult{}
			if err := g.ConfigLogLock(); err != nil {
				return err
			}
			nodes, err := g.ActiveApplied()
			if err != nil {
				return err
			}
			var min *uint64
			for i := range nodes {
				if min == nil || nodes[i].Seq < *min {
					v := nodes[i].Seq
					min = &v
				}
			}
			n := 0
			res, err = g.ArtifactsCollect(floor, min, after, r.batch, func(hash []byte) error {
				if n > 0 && n%fileGroup == 0 {
					if err := ctx.Err(); err != nil {
						return fmt.Errorf("%w: %w", store.ErrCollectStop, err)
					}
					// Taking the lock again costs nothing while this transaction holds it, and fails once it does not.
					if err := g.ConfigLogLock(); err != nil {
						return fmt.Errorf("%w: %w", store.ErrCollectStop, err)
					}
				}
				n++
				if err := r.blobs.Delete(hash); err != nil {
					return fmt.Errorf("periodic: a blob file would not go: %w", err)
				}
				return nil
			})
			return err
		}); err != nil {
			return total, errors.Join(append(failed, err)...)
		}
		total += res.Removed
		if res.Failed != nil {
			failed = append(failed, res.Failed)
		}
		if res.Scanned < r.batch {
			return total, errors.Join(failed...)
		}
		after = res.Last
	}
	return total, errors.Join(append(failed, ctx.Err())...)
}

// alertHolders raises the alert of an active node that has held the collection of blobs back for a day. The log has no
// time of its own the worker may read, so the first pass that finds the node holding is remembered in memory: a restart of the
// worker, or a change of the worker that holds the lease, starts the day over, and the alert is late by at most that.
func (r *Runner) alertHolders(ctx context.Context, floor uint64, applied []store.NodeApplied) error {
	var waiting uint64
	var any bool
	if err := r.db.WithGlobal(ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
		waiting, any, err = g.ArtifactsWaitingUpTo(floor)
		return err
	}); err != nil {
		return err
	}
	now := appclock.Now()
	holding := map[uuid.UUID]bool{}
	if any {
		for _, n := range applied {
			if n.Seq <= waiting {
				holding[n.Node] = true
			}
		}
	}
	r.mu.Lock()
	var late []uuid.UUID
	for id := range holding {
		first, seen := r.heldSince[id]
		if !seen {
			r.heldSince[id] = now
			continue
		}
		if now.Sub(first) >= holdAlertAfter {
			late = append(late, id)
		}
	}
	for id := range r.heldSince {
		if !holding[id] {
			delete(r.heldSince, id)
		}
	}
	r.mu.Unlock()
	for _, id := range late {
		params, err := closed.NewParams(nodeAlert{Reason: ReasonGCHeld, Node: id})
		if err != nil {
			continue
		}
		r.raise(ctx, "warning", closed.NewKey(ReasonGCHeld, closed.ID(id)), params)
	}
	return nil
}
