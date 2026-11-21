package smssend_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Review round 13 of the SMS layer and the worker loops (sms-r13-2, sms-r13-4, sms-r13-5).

// sms-r13-2 and sms-r13-5: the hold of a refused login is not written between two gateways. It
// was written by the router on a context of its own with a budget of its own, so a gateway row
// that another transaction held (a record transaction waiting on the hot global counter, a
// snapshot reload) kept the write waiting for seconds, the fallback then found less than the 6.6
// seconds a call needs and was not asked, and a code that had a working fallback stayed sealed
// until the next claim, 20 seconds later. Now the router only marks the attempt and the record
// transaction writes the hold on the row it has locked anyway, so the send never waits for it.
func TestAHoldIsNotWrittenOnTheSendPathSoABusyGatewayRowCostsTheFallbackNothing(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) } // key refused

	// Another transaction holds the primary's row, as a record transaction of another worker does.
	super, err := r.env.DB.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(ctx)
	lock, err := super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			_ = lock.Commit(ctx)
		}
	}
	defer release()
	if _, err := lock.Exec(ctx, `SELECT 1 FROM ctrlz.sms_gateways WHERE id = $1 FOR UPDATE`, r.priID); err != nil {
		t.Fatal(err)
	}

	ch := r.request(r.env.A.Phone)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.w.Drain(ctx)
	}()

	// The fallback is asked while the row is still locked: nothing on the send path waits for it.
	deadline := time.Now().Add(8 * time.Second)
	for r.fb.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if r.pri.count() != 1 || r.fb.count() != 1 {
		t.Fatalf("with the gateway row locked: primary %d calls, fallback %d, want 1 and 1", r.pri.count(), r.fb.count())
	}
	select {
	case <-done:
		t.Fatal("the record did not wait for the locked row, so the test did not lock what the record writes")
	default:
	}
	release()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the drain did not finish after the row was released")
	}
	if r.deliveryCT(ch.ID) {
		t.Error("the code stayed sealed although the fallback accepted it")
	}
	if g := gatewayOf(t, ctx, r.src, r.priID); g.Held == nil {
		t.Error("the refused login was not held once the record could write")
	}
}

// A send whose record is never written holds nothing: the hold is part of the record, so it
// commits or rolls back with the delivery it belongs to.
func TestAHoldRollsBackWithItsRecord(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	rec := r.src.(interface {
		RecordHold(store.GlobalTx, sms.Attempt) error
	})
	g1 := gatewayOf(t, ctx, r.src, r.priID)
	cause := sms.NewError(sms.ProviderSMSIR, sms.Auth, sms.StatusCode("10"))
	errStop := errors.New("stop")
	err := r.worker.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		if err := rec.RecordHold(g, sms.Attempt{Gateway: r.priID, Hold: sms.HoldPlace, Revision: g1.Revision, Err: cause}); err != nil {
			return err
		}
		return errStop
	})
	if err == nil {
		t.Fatal("the transaction was meant to fail")
	}
	if g := gatewayOf(t, ctx, r.src, r.priID); g.Held != nil {
		t.Fatal("a hold survived the rollback of its record")
	}
}

// sms-r13-4: a rekey re-seals the same credentials under the newest key, which changes the
// ciphertext and so its digest. The hold names the digest of the ciphertext the refusal was made
// for, so the re-seal made the hold stop counting and the refused key was asked again by the
// traffic of users, the run of failed logins the hold exists to prevent (Melipayamak -108 blocks
// the panel address and only its support lifts it). The statement of the rekey carries the hold to
// the new ciphertext. A hold for other credentials stays what it was, and a re-seal of a gateway
// that is not held leaves it not held.
func TestARekeyOfAHeldGatewayKeepsItHeld(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 100, otp_cap_phone_net = 100`)
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) } // key refused
	r.request(r.env.A.Phone)
	r.drain()
	if r.pri.count() != 1 || gatewayOf(t, ctx, r.src, r.priID).Held == nil {
		t.Fatalf("the refusal did not hold the gateway: %d calls", r.pri.count())
	}

	// ctrlzctl keys rekey: the same plaintext under a fresh seal, replaced only where the stored
	// ciphertext is still the one that was read.
	rekey := func(id uuid.UUID) {
		t.Helper()
		var sealed []store.SealedGatewayCredentials
		admin := r.env.Admin(t)
		if err := admin.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
			sealed, err = g.SMSCredentialsSealed()
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for _, s := range sealed {
			if s.ID != id {
				continue
			}
			plain, err := sms.OpenCredentials(r.ring, s.ID, s.Provider, s.CT)
			if err != nil {
				t.Fatal(err)
			}
			next, err := sms.SealCredentials(r.ring, s.ID, s.Provider, plain)
			if err != nil {
				t.Fatal(err)
			}
			if string(next) == string(s.CT) {
				t.Fatal("the re-seal did not change the ciphertext, so the test cannot see the defect")
			}
			if err := admin.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
				ok, err := g.SMSCredentialsReplace(s.ID, s.CT, next)
				if err == nil && !ok {
					t.Error("the replace did not match the stored ciphertext")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	rekey(r.priID)
	r.router.Invalidate()
	if gatewayOf(t, ctx, r.src, r.priID).Held == nil {
		t.Fatal("a rekey lifted the hold of a refused login")
	}
	// The traffic of users still does not ask the refused key.
	r.env.Exec(t, `UPDATE ctrlz.otp_challenges SET created_at = created_at - interval '2 minutes'`)
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL`)
	r.router.Invalidate()
	r.request(r.env.A.Phone)
	r.drain()
	if n := r.pri.count(); n != 1 {
		t.Fatalf("after the rekey the refused primary was called %d times in all, want 1", n)
	}

	// A gateway that is not held stays not held through a rekey: the carry-forward moves a hold,
	// it does not invent one.
	rekey(r.fbID)
	if g := gatewayOf(t, ctx, r.src, r.fbID); g.Held != nil {
		t.Fatalf("a rekey held a gateway that was not held: %+v", g.Held)
	}
}
