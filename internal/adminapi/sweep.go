package adminapi

import (
	"context"
	"log/slog"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sweepbatch"
)

// SweepEvery is how often the admin service deletes expired admin sessions
// (spec 10.4): the worker has no grant on admin_sessions, so the service that
// owns the table cleans it. An hourly delete of rows a day past their limit is
// slack enough that no live session is ever touched.
const SweepEvery = time.Hour

// The bound of one pass, the same shape as the worker's sweeps (rule bounded-sweeps):
// a backlog is worked off over several passes and no batch outruns statement_timeout.
const (
	sweepBatchSize  = 5000
	sweepMaxBatches = 200
)

// RunSweep deletes expired admin sessions now and then every interval, until ctx
// ends. A failed pass is logged by class only and tried again at the next tick:
// nothing depends on a pass succeeding, since expired rows are already refused
// by the session lookup.
func RunSweep(ctx context.Context, st *store.Store, log *slog.Logger, interval time.Duration) {
	pass := func() {
		n, err := sweepbatch.Drain(ctx, sweepbatch.Plan{Size: sweepBatchSize, Max: sweepMaxBatches},
			func(ctx context.Context, size int) (n int, more bool, err error) {
				err = st.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
					n, err = g.AdminSessionsDeleteExpiredBatch(appclock.Now(), size)
					return err
				})
				return n, n >= size, err
			})
		if n > 0 {
			log.Info("admin sessions swept", logattr.Int("deleted", n))
		}
		if err != nil && ctx.Err() == nil {
			log.Warn("admin session sweep failed")
		}
	}
	pass()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}
