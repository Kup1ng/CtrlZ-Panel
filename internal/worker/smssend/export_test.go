package smssend

import (
	"context"
	"time"
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
