package sweep_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/panicguard"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/sweep"
)

// sms-r17-17: a panic in a sweep run (a row shape the code did not expect) ended the process, which also
// ended the rows of the SMS queue that a provider had accepted and the worker had not yet recorded. A run
// now keeps its panic, and the loop goes on at its next tick.
func TestAPanicInOneSweepRunStaysWithThatRun(t *testing.T) {
	for _, fast := range []bool{true, false} {
		var buf bytes.Buffer
		log := slog.New(slog.NewJSONHandler(&buf, nil))
		escaped := func() (out bool) {
			defer func() { out = recover() != nil }() // the test's own, so a missing guard fails this test and does not end the binary
			sweep.KeptRun(context.Background(), log, fast, func() error { panic("canary-panic-value 987654") })
			return false
		}()
		if escaped {
			t.Fatalf("fast=%v: the panic left the sweep run", fast)
		}
		got := buf.String()
		if strings.Count(got, panicguard.Msg) != 1 {
			t.Errorf("fast=%v: the panic was not logged once: %s", fast, got)
		}
		if strings.Contains(got, "canary-panic-value") || strings.Contains(got, "987654") {
			t.Errorf("fast=%v: the value of the panic reached the log: %s", fast, got)
		}
	}
}
