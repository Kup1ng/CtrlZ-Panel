package adminjobs_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/adminjobs"
)

// sms-r18-5: a handler that panicked was kept at pass(), which unwound the whole RunOnce loop before the
// failure was counted. The job stayed running with no failure record and no backoff, came first again on
// every poll and panicked again for ever, and every job behind it in the list never ran. A panic is a failed
// run now: it is counted, takes the backoff, ends the job as failed after MaxFailures runs, and the jobs
// behind it run in the same pass.
func TestAPanickingHandlerIsAFailedRunAndDoesNotCutTheLoop(t *testing.T) {
	var logs bytes.Buffer
	panicked, behind := 0, 0
	now := time.Now()
	r := newRig(t, adminjobs.Config{})
	// The rig's own logger discards; this runner's reads what the guard says.
	runner, err := adminjobs.New(adminjobs.Config{Store: r.env.Worker(t), Log: slog.New(slog.NewJSONHandler(&logs, nil)), Page: 1,
		MaxFailures: 3, Backoff: []time.Duration{time.Second}, Now: func() time.Time { return now }, Handlers: map[string]adminjobs.Handler{
			adminjobs.KindWebauthnRPChange: func(context.Context, store.AdminJob, adminjobs.Report) (any, error) {
				panicked++
				panic("canary-job-panic 987654")
			},
			adminjobs.KindRegistrationTransition: func(context.Context, store.AdminJob, adminjobs.Report) (any, error) {
				behind++
				return map[string]any{"ok": true}, nil
			},
		}})
	if err != nil {
		t.Fatal(err)
	}
	// The panicking job is older, so the list returns it first.
	bad := r.queue(adminjobs.KindWebauthnRPChange, map[string]string{"rp_id": "new.test"})
	good := r.queue(adminjobs.KindRegistrationTransition, map[string]any{})

	for i := 1; i <= 2; i++ {
		if _, err := runner.RunOnce(r.env.Ctx); err == nil {
			t.Fatalf("run %d: a panicking handler returned no error", i)
		}
		if state, _ := r.job(bad); state != "running" {
			t.Fatalf("after failure %d the panicking job is %s: it is left to be retried until MaxFailures", i, state)
		}
		now = now.Add(2 * time.Second) // past the backoff
	}
	if _, err := runner.RunOnce(r.env.Ctx); err == nil {
		t.Fatal("the third run reported no error")
	}
	state, p := r.job(bad)
	if state != "failed" || p["error"] != "panic" || panicked != 3 {
		t.Errorf("the panicking job is %s %v after %d runs, want failed with error panic after 3", state, p, panicked)
	}
	// The job behind it ran in the first pass and was done at once; it never waited for the other.
	if state, _ := r.job(good); state != "done" || behind != 1 {
		t.Errorf("the job behind the panicking one is %s after %d runs, want done after 1", state, behind)
	}
	if strings.Count(logs.String(), safego.Msg) != 3 || strings.Contains(logs.String(), "canary-job-panic") || strings.Contains(logs.String(), "987654") {
		t.Errorf("the log did not say each panic once without its value: %s", logs.String())
	}
	// A failed job no longer runs.
	if n, _ := runner.RunOnce(r.env.Ctx); n != 0 {
		t.Errorf("a failed job ran again: %d", n)
	}
}
