package smssend

import (
	"context"
	"errors"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

const (
	// recordTries is how many times a record transaction is attempted when the database
	// answers with a condition that a repeat can cure: three retries after the first run.
	recordTries = 4
	// defaultRecordRetryPause is the pause before the first retry; it doubles each time
	// (100 ms, 200 ms, 400 ms), which is under a second in all and well inside recordBudget.
	defaultRecordRetryPause = 100 * time.Millisecond
)

// recordTx runs a record transaction (the ending of a claimed row, with the gateways, the
// counters and the delivery log that go with it) and runs it again when the database says a
// repeat may succeed: ErrRetry (a lock timeout, a deadlock, a serialization loss) or
// ErrConnection (a restart, a failover, a pooled connection that died).
//
// Store.run runs its function once and nothing above it retried, so one transient error at
// the wrong moment lost the record of a send the provider had already accepted: the code
// stayed sealed, the claim lapsed and the next claim sent it again, billed again, with its
// price never added to the money counter (sms-r9-5). The record is what is retried, never
// the send, and the time is the caller's context: the detached one of an accepted send has
// recordBudget, a record after a stop only the shutdown budget, and a retry never outlives it.
//
// The closures are safe to run again because the earlier run rolled back and every ending in
// them is gated by a Won, so a row that was ended by someone else in between is not ended
// twice. One case is not exact: a connection lost during the COMMIT may have committed, and
// the repeat then finds its Won lost, so it writes the delivery row and the breaker step a
// second time, and an accept adds its price again, an OTP's (settleOTP charges whoever
// cleared the row, because a row ended by an expiry still had its message billed) and an
// outbox message's alike (sms-r10-3). Each of these over-counts, the safe direction for a
// cap, and the cause is rarer than the failure this retry removes.
//
// A row is not ended by a sweep in the pause between two runs: the exhausted pass, the
// expiry and the stale-outbox sweep take a row only store.RecordBudget after its lease
// lapsed, which is longer than this loop can run (sms-r10-5).
func (w *Worker) recordTx(ctx context.Context, fn func(store.GlobalTx) error) error {
	return retryRecord(ctx, w.retryPause, func() error { return w.db.WithGlobal(ctx, store.TxOpts{}, fn) })
}

// retryRecord is the loop of recordTx on its own, so that its three decisions can be tested
// without a database (sms-r10-2): which errors are worth a repeat (ErrRetry and ErrConnection,
// wrapped or not, and nothing else), how many runs there are (recordTries), and that a pause ends
// when the context does. A failure that is neither retryable nor the last run is returned as it
// came, never wrapped, so the callers' error classes still read it.
func retryRecord(ctx context.Context, pause time.Duration, run func() error) error {
	var err error
	for try := 0; try < recordTries; try++ {
		if err = run(); err == nil {
			return nil
		}
		if !errors.Is(err, store.ErrRetry) && !errors.Is(err, store.ErrConnection) {
			return err
		}
		if try == recordTries-1 {
			break
		}
		t := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
		pause *= 2
	}
	return err
}
