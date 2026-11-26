package adminjobs

import (
	"context"
	"log/slog"
)

// KeptPass is one poll of the loop over a Runner that has a log and no store: reading the job list then
// panics, which is the failure the test needs, with no database (sms-r17-17).
func KeptPass(ctx context.Context, log *slog.Logger) { (&Runner{log: log}).pass(ctx) }
