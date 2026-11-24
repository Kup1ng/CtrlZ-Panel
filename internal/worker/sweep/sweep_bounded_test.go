package sweep_test

import (
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/sweep"
)

// The fast sweep ends stale outbox messages in bounded batches too, and a message whose
// claim is live is left to the worker that holds it.
func TestFastEndsStaleOutboxInBatchesAndSparesALiveClaim(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `INSERT INTO ctrlz.sms_outbox (kind, phone_e164, template_key, locale, params_ct, created_at)
SELECT 'invite', '+98912666' || lpad(g::text, 4, '0'), 'invite', 'fa', '\x01', now() - interval '2 hours' FROM generate_series(1, 7) g`)
	r.env.Exec(t, `UPDATE ctrlz.sms_outbox SET claimed_until = now() + interval '1 minute' WHERE phone_e164 = '+989126660001'`)
	s := r.sweeper(sweep.Config{Batch: 2, MaxBatches: 2})
	res, err := s.Fast(r.env.Ctx)
	if err != nil || res.StaleOutbox != 4 {
		t.Fatalf("first run: %+v %v, want 4 ended", res, err)
	}
	res, err = s.Fast(r.env.Ctx)
	if err != nil || res.StaleOutbox != 2 {
		t.Fatalf("second run: %+v %v, want the last 2 ended", res, err)
	}
	if r.count(`SELECT count(*) FROM ctrlz.sms_outbox WHERE state = 'pending' AND phone_e164 = '+989126660001'`) != 1 {
		t.Error("a message with a live claim was ended")
	}
}
