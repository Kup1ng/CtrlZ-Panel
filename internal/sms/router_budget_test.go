package sms_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/smshttp"
)

// Review round 8 (sms-r8-5): the router never starts a provider call that the deadline of the
// send cannot finish. A call cut by the deadline while the provider had already taken the
// message was dropped (no delivery row, no price, the code sent again by the next claim), and a
// primary that hung never reached its breaker.

// hangingSender answers after d, or when its context ends, with the transient timeout the real
// drivers give for a call that ran out of time.
type hangingSender struct {
	provider string
	d        time.Duration
	calls    atomic.Int32
}

func (h *hangingSender) Provider() string { return h.provider }
func (h *hangingSender) Send(ctx context.Context, _ sms.Message, _ sms.ProviderTemplate) (sms.Result, error) {
	h.calls.Add(1)
	select {
	case <-time.After(h.d):
		return sms.Result{ProviderID: sms.ParseField(h.provider + "-1")}, nil
	case <-ctx.Done():
		return sms.Result{}, sms.NewError(sms.ParseProvider(h.provider), sms.Transient, sms.CodeTimeout)
	}
}
func (h *hangingSender) Balance(context.Context) (sms.Field, error) { return sms.ParseField("1"), nil }

func budgetRouter(t *testing.T, call time.Duration, pri, fb sms.Sender) *sms.Router {
	t.Helper()
	p := sms.Gateway{ID: uuid.New(), Provider: "sms_ir", Role: "primary", Sender: pri}
	f := sms.Gateway{ID: uuid.New(), Provider: "melipayamak", Role: "fallback", Sender: fb}
	tpls := map[sms.TemplateRef]sms.ProviderTemplate{}
	for _, g := range []sms.Gateway{p, f} {
		tpls[sms.TemplateRef{Gateway: g.ID, Key: "otp", Locale: "fa"}] = sms.ProviderTemplate{ID: "100", ParamNames: []string{"CODE"}}
	}
	src := &fakeSource{snap: sms.Snapshot{Gateways: []sms.Gateway{p, f}, Templates: tpls}}
	return sms.NewRouter(src, classify.Routing{}, sms.WithCallTimeout(call))
}

func TestARouterStartsNoCallThatItsDeadlineCannotFinish(t *testing.T) {
	pri, fb := &hangingSender{provider: "sms_ir", d: 0}, &hangingSender{provider: "melipayamak", d: 0}
	r := budgetRouter(t, 400*time.Millisecond, pri, fb)

	// Less than one call left: nothing is asked, and the caller is told why.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	out, err := r.Send(ctx, req)
	if !errors.Is(err, sms.ErrNoTime) {
		t.Fatalf("err = %v, want ErrNoTime", err)
	}
	if pri.calls.Load()+fb.calls.Load() != 0 {
		t.Errorf("a call was started with %v left for a call of 400 ms", 300*time.Millisecond)
	}
	if len(out.Attempts) != 0 || out.Skipped != 2 {
		t.Errorf("attempts %d skipped %d, want 0 and 2: a gateway that was not asked is counted as not asked", len(out.Attempts), out.Skipped)
	}

	// With room for two calls both gateways are asked as usual, and a deadline of the context
	// that is far away is no limit at all.
	pri.d, fb.d = 0, 0
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := r.Send(ctx2, req); err != nil || pri.calls.Load() != 1 {
		t.Errorf("a send with time to spare: %v, %d primary calls", err, pri.calls.Load())
	}
	if _, err := r.Send(context.Background(), req); err != nil {
		t.Errorf("a send with no deadline: %v", err)
	}
}

// With room for one call and not two, the primary that hangs is asked for its whole call and its
// timeout is recorded as an attempt (the breaker counts it); the fallback is not started.
func TestAHangingPrimaryIsRecordedAndTheFallbackIsNotStartedWithoutTime(t *testing.T) {
	pri, fb := &hangingSender{provider: "sms_ir", d: time.Minute}, &hangingSender{provider: "melipayamak"}
	r := budgetRouter(t, 400*time.Millisecond, pri, fb)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	out, err := r.Send(ctx, req)
	if !errors.Is(err, sms.ErrNoTime) {
		t.Fatalf("err = %v, want ErrNoTime", err)
	}
	if len(out.Attempts) != 1 || out.Attempts[0].Err == nil || out.Attempts[0].Err.Code != sms.CodeTimeout {
		t.Fatalf("the primary's timeout was not recorded as an attempt: %+v", out.Attempts)
	}
	if fb.calls.Load() != 0 || out.Skipped != 1 {
		t.Errorf("fallback calls %d, skipped %d, want 0 and 1", fb.calls.Load(), out.Skipped)
	}
}

// A primary that takes the message after 250 ms is accepted when the call has its own time:
// the accept is in the outcome, never dropped by a deadline that was shorter than the call.
func TestAnAcceptWithinTheCallTimeIsKept(t *testing.T) {
	pri, fb := &hangingSender{provider: "sms_ir", d: 250 * time.Millisecond}, &hangingSender{provider: "melipayamak"}
	r := budgetRouter(t, 400*time.Millisecond, pri, fb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := r.Send(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Accepted(); !ok || fb.calls.Load() != 0 {
		t.Errorf("accepted=%v fallback calls %d", ok, fb.calls.Load())
	}
}

func TestTheDefaultCallNeedCoversTheDriversOwnTimeout(t *testing.T) {
	r := sms.NewRouter(&fakeSource{}, classify.Routing{})
	if r.CallNeed() <= smshttp.TotalTimeout {
		t.Errorf("a call needs %v, the drivers' client timeout is smshttp.TotalTimeout: the router would cut a call its driver is still allowed to make", r.CallNeed())
	}
}
