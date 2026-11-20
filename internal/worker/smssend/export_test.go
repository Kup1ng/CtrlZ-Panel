package smssend

import (
	"context"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Exports for the external tests: the arithmetic that bounds a send by its claim lease, and the
// shortest budget a record gets once the worker was told to stop.

func LeaseMargin() time.Duration                           { return leaseMargin }
func SendBudgetWithin(b, left time.Duration) time.Duration { return sendBudgetWithin(b, left) }
func ShutdownRecordBudget() time.Duration                  { return shutdownRecordBudget }

// RetryRecord and RecordTries expose the loop that runs the record transactions, so the decisions
// in it (which errors repeat, how many runs, the stop during a pause) are tested without a database.
func RetryRecord(ctx context.Context, pause time.Duration, run func() error) error {
	return retryRecord(ctx, pause, run)
}
func RecordTries() int { return recordTries }

func DefaultRecordRetryPause() time.Duration { return defaultRecordRetryPause }

// KeepSnapshotFresh is one pass's refresh of the router snapshot, so a test can time it.
func KeepSnapshotFresh(ctx context.Context, w *Worker) { w.keepSnapshotFresh(ctx) }

// SnapshotPollWait is the bound of that wait.
func SnapshotPollWait() time.Duration { return snapshotPollWait }

// UsableMarks runs the snapshot decision over gateway rows with no database and counts the writes that
// would take a judgement back.
func (s *Source) UsableMarks(gws []store.WorkerGateway) int {
	_, marks := s.snapshot(gws, nil)
	n := 0
	for _, m := range marks {
		if m.usable {
			n++
		}
	}
	return n
}
