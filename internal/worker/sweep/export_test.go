package sweep

import (
	"context"
	"log/slog"
)

// KeptRun is one run of a cadence as the loop makes it (logResult), over a Sweeper that has only a log, so
// a test can make the run panic without a database (sms-r17-17).
func KeptRun(ctx context.Context, log *slog.Logger, fast bool, f func() error) {
	kind := sweepSlow
	if fast {
		kind = sweepFast
	}
	(&Sweeper{log: log}).logResult(ctx, kind, f)
}
