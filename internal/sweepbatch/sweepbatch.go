// Package sweepbatch is the one loop every retention and expiry sweep runs through
// (P1 auth review, rule bounded-sweeps; spec 9.5, 10.4).
//
// A sweep that deletes or ends everything past its limit in one statement meets the
// database's statement_timeout on the day it has a backlog, rolls back, and meets it
// again on every run; when several sweeps share a transaction, one timeout also undoes
// the others. So a sweep is a series of batches bounded by primary key, each in a
// transaction of its own, and a backlog is worked off over several runs. The loop lives
// here, once, so that no sweep can be written with a different idea of when to stop.
//
// The callback opens its own transaction (WithGlobal or WithTenant) and runs one
// ...Batch method of the store in it. internal/lint TestBoundedSweeps fails for a batch
// method called anywhere else, and for a DELETE or bulk UPDATE that has no LIMIT.
package sweepbatch

import "context"

// Plan bounds one run of one sweep.
type Plan struct {
	// Size is the most rows one batch may handle; it is the LIMIT of the statement.
	Size int
	// Max is the most batches one run may take, so that a table with an endless
	// backlog cannot hold the sweeper from its other tables.
	Max int
}

// Drain calls batch until a batch comes back short, Max batches have run, ctx ends or a
// batch fails. batch returns how many rows it handled and whether it was full (more
// waits), and must run in a transaction of its own. Drain returns the sum of the rows
// handled, also when a later batch failed, and the error of that batch.
func Drain(ctx context.Context, p Plan, batch func(ctx context.Context, size int) (handled int, full bool, err error)) (int, error) {
	total := 0
	for i := 0; i < p.Max && ctx.Err() == nil; i++ {
		n, full, err := batch(ctx, p.Size)
		total += n
		if err != nil {
			return total, err
		}
		if !full {
			break
		}
	}
	return total, nil
}
