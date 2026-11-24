package smssend_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// Review round 12 of the SMS layer and the worker loops (sms-r12-2, sms-r12-3, sms-r12-4).

// gatewayOf loads a snapshot from the source and returns one gateway of it.
func gatewayOf(t *testing.T, ctx context.Context, src sms.Source, id uuid.UUID) sms.Gateway {
	t.Helper()
	snap, err := src.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range snap.Gateways {
		if g.ID == id {
			return g
		}
	}
	t.Fatalf("gateway %s is not in the snapshot", id)
	return sms.Gateway{}
}

// A hold names the credentials the refused call used (sms-r12-2). The admin saves a correct key
// while a call made with the old one is in flight, and the call comes back refused: its hold must
// not land on the new, working credentials, or the gateway is passed over until a restart. It is
// refused twice, in memory by the revision of the build and in the database by the sum of the
// sealed credentials, which is what covers a PUT that lands after the build was made and before the
// write. A release of an older revision lifts nothing for the same reason.
func TestAHoldForReplacedCredentialsIsIgnoredAndAStaleReleaseLiftsNothing(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	cause := sms.NewError(sms.ProviderSMSIR, sms.Auth, sms.StatusCode("10"))
	rec := r.src.(interface {
		RecordHold(store.GlobalTx, sms.Attempt) error
	})
	// The write the record transaction makes for an attempt (sms-r13-2): one attempt, one statement.
	write := func(a sms.Attempt) {
		t.Helper()
		if err := r.worker.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error { return rec.RecordHold(g, a) }); err != nil {
			t.Fatal(err)
		}
	}
	hold := func(rev uint64) {
		write(sms.Attempt{Gateway: r.priID, Hold: sms.HoldPlace, Revision: rev, Err: cause})
	}
	lift := func(rev uint64) { write(sms.Attempt{Gateway: r.priID, Hold: sms.HoldLift, Revision: rev}) }
	held := func() int {
		return r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE id = $1 AND held_code IS NOT NULL`, r.priID)
	}

	g1 := gatewayOf(t, ctx, r.src, r.priID)
	r.reseal(r.priID, "sms_ir", `{"api_key":"`+canaryIRKey+`-2"}`)
	g2 := gatewayOf(t, ctx, r.src, r.priID)
	if g1.Revision == g2.Revision {
		t.Fatal("saving credentials did not give the build a new revision")
	}

	// (a) A refusal for the old credentials, coming back after the new ones were loaded.
	hold(g1.Revision)
	if g := gatewayOf(t, ctx, r.src, r.priID); g.Held != nil || held() != 0 {
		t.Fatalf("a hold for replaced credentials landed: held %v, rows %d", g.Held, held())
	}

	// (b) The PUT lands after the last load and before the write: the revision is still the
	// current one of this process, and only the sum in the statement can tell.
	ct, err := sms.SealCredentials(r.ring, r.priID, "sms_ir", secret.NewBytes([]byte(`{"api_key":"`+canaryIRKey+`-3"}`)))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET credentials_ct = $2 WHERE id = $1`, r.priID, ct)
	hold(g2.Revision)
	if held() != 0 {
		t.Fatal("a hold landed on credentials that were saved after the call, in the window the revision cannot see")
	}

	// (c) The current credentials are held, with the refusal the row carries.
	g3 := gatewayOf(t, ctx, r.src, r.priID)
	hold(g3.Revision)
	g := gatewayOf(t, ctx, r.src, r.priID)
	if g.Held == nil || g.Held.Class() != sms.Auth || g.Held.Code != sms.StatusCode("10") || g.Held.Provider != sms.ProviderSMSIR {
		t.Fatalf("the current credentials were not held with their refusal: %+v", g.Held)
	}

	// (d) A release made for an older revision lifts nothing; the current one lifts it.
	lift(g2.Revision)
	if gatewayOf(t, ctx, r.src, r.priID).Held == nil {
		t.Fatal("a release of an older revision lifted the hold")
	}
	lift(g3.Revision)
	if g := gatewayOf(t, ctx, r.src, r.priID); g.Held != nil || held() != 0 {
		t.Fatal("a release of the current revision did not lift the hold")
	}
}

// A hold is one state for every worker (sms-r12-3, sms-r12-4). Two workers share a queue
// (SKIP LOCKED) and a rolling deploy overlaps an old and a new one, so a hold kept in the memory
// of the worker that met the refusal left the other passing the gateway over, stepping the shared
// breaker, and an accepted test send in the first closed it again: the gateway flapped and
// sms_available with it. The hold is in the row now, the other worker reads it at its next load,
// and a test send that either worker runs lifts it for both.
func TestAHoldAndItsLiftingAreSeenByEveryWorker(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `UPDATE ctrlz.system_settings SET otp_cap_phone = 100, otp_cap_phone_net = 100`)
	log := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	src2 := smssend.NewSource(r.worker, r.ring, senderEnv(r.noopFile), log)
	src2.Build = r.build
	router2 := sms.NewRouter(src2, classify.Routing{})
	send2 := func() sms.Outcome {
		t.Helper()
		out, err := router2.Send(r.env.Ctx, sms.Request{To: "+989121112233", Template: "otp", Locale: "fa", Value: secret.New("123456")})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Worker 1 meets the refusal and holds.
	r.pri.reply = func(_ int, w http.ResponseWriter) { irStatus(10)(w) }
	r.request(r.env.A.Phone)
	r.drain()
	if r.pri.count() != 1 {
		t.Fatalf("worker 1 did not meet the refusal: %d calls", r.pri.count())
	}
	// Worker 2 was never refused, and does not ask: it reads the hold from the row.
	out := send2()
	if r.pri.count() != 1 {
		t.Fatalf("worker 2 asked a gateway that worker 1 holds: %d calls", r.pri.count())
	}
	if a := out.Attempts[0]; a.Gateway != r.priID || !a.Local || a.Err == nil {
		t.Fatalf("worker 2 did not pass the held primary over locally: %+v", a)
	}

	// The operator repairs the account at the provider and sends a test send. Worker 1 runs it
	// and the provider accepts.
	r.pri.reply = func(_ int, w http.ResponseWriter) { irOK(w) }
	r.queue("test", "otp", "+989121112233", r.priID, "123456")
	r.drain()
	if r.pri.count() != 2 {
		t.Fatalf("the test send did not reach the provider: %d calls", r.pri.count())
	}
	r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = NULL, consecutive_failures = 0`)

	// Worker 2 carries a routed send through the primary again, with no restart.
	router2.Invalidate()
	out = send2()
	if _, ok := out.Accepted(); !ok || r.pri.count() != 3 {
		t.Fatalf("worker 2 still passes the repaired gateway over: %d calls", r.pri.count())
	}
}
