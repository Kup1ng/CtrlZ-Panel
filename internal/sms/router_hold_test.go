package sms_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
)

// A gateway whose login the provider refused is not probed again by the traffic of users
// (sms-r11-9). Every further call is another failed login with the same credentials, and a provider
// answers a run of those by blocking the panel's address (Melipayamak -108), which only its support
// lifts. The hold itself is kept by the Source (smssend.Source); these tests use one that does the
// same in memory.

// holdSource is a fakeSource that keeps holds, as smssend.Source does: per gateway and revision.
type holdSource struct {
	*fakeSource
	held map[uuid.UUID]*sms.Error
}

func (s *holdSource) Load(ctx context.Context) (sms.Snapshot, error) {
	snap, err := s.fakeSource.Load(ctx)
	out := snap
	out.Gateways = append([]sms.Gateway(nil), snap.Gateways...)
	s.fakeSource.mu.Lock()
	defer s.fakeSource.mu.Unlock()
	for i := range out.Gateways {
		out.Gateways[i].Held = s.held[out.Gateways[i].ID]
		out.Gateways[i].Revision = 1
	}
	return out, err
}

// record does what the worker does with the attempts of a send, in memory: the router only says what
// it saw (Attempt.Hold), and the record of the send writes it (sms-r13-2, sms-r13-5).
func (s *holdSource) record(out sms.Outcome) {
	s.fakeSource.mu.Lock()
	defer s.fakeSource.mu.Unlock()
	for _, a := range out.Attempts {
		if a.Revision != 1 {
			continue
		}
		switch a.Hold {
		case sms.HoldPlace:
			s.held[a.Gateway] = a.Err
		case sms.HoldLift:
			delete(s.held, a.Gateway)
		}
	}
}

// send runs one send through the router and records its outcome like the worker.
func (s *holdSource) send(r *rig, req sms.Request) (sms.Outcome, error) {
	out, err := r.router.Send(context.Background(), req)
	s.record(out)
	r.router.Invalidate()
	return out, err
}

func holdRig(t *testing.T) (*rig, *holdSource) {
	t.Helper()
	r := newRig(t)
	hs := &holdSource{fakeSource: r.src, held: map[uuid.UUID]*sms.Error{}}
	r.router = sms.NewRouter(hs, classify.Routing{}, sms.WithClock(func() time.Time { return *r.now }))
	return r, hs
}

func refused() (sms.Result, error) {
	return sms.Result{}, sms.NewError(sms.ProviderSMSIR, sms.Auth, sms.StatusCode("10"))
}

func TestARefusedLoginIsNotProbedAgainByUsersTraffic(t *testing.T) {
	r, hs := holdRig(t)
	r.pri.reply = func(int) (sms.Result, error) { return refused() }

	// The first send meets the refusal once and falls back.
	out, err := hs.send(r, req)
	if err != nil {
		t.Fatal(err)
	}
	if r.pri.calls != 1 || r.fb.calls != 1 {
		t.Fatalf("first send: primary %d, fallback %d calls", r.pri.calls, r.fb.calls)
	}
	if _, ok := out.Accepted(); !ok {
		t.Fatal("the fallback did not carry the send")
	}
	// Every later send passes the primary over locally: no call, and the attempt is the refusal
	// again, so the worker's breaker step and the alert are the same as for a real answer.
	for i := 0; i < 5; i++ {
		out, err := hs.send(r, req)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := out.Accepted(); !ok {
			t.Fatal("the fallback did not carry the send")
		}
		first := out.Attempts[0]
		if first.Gateway != r.priGW.ID || !first.Local || first.Err == nil || first.Err.Class != sms.Auth || first.Err.Code != sms.StatusCode("10") {
			t.Fatalf("send %d: the held primary left %+v", i, first)
		}
		if classify.ScopeOf(first.Err) != classify.Gateway || !classify.CountsTowardBreaker(first) {
			t.Fatalf("send %d: the held attempt must be a Gateway-scope breaker step", i)
		}
	}
	if r.pri.calls != 1 {
		t.Errorf("the refused primary was called %d times, want 1", r.pri.calls)
	}
}

// The test send is the explicit probe: it ignores the hold, and an accepted one lifts it.
func TestAPinnedSendProbesAHeldGatewayAndAnAcceptLiftsTheHold(t *testing.T) {
	r, hs := holdRig(t)
	refuse := true
	r.pri.reply = func(int) (sms.Result, error) {
		if refuse {
			return refused()
		}
		return sms.Result{ProviderID: sms.ParseField("ok-1")}, nil
	}
	if _, err := hs.send(r, req); err != nil {
		t.Fatal(err)
	}
	pin := req
	pin.Gateway = r.priGW.ID
	out, err := hs.send(r, pin)
	if err != nil || r.pri.calls != 2 {
		t.Fatalf("the pinned send must reach the provider: calls %d, err %v", r.pri.calls, err)
	}
	if a := out.Attempts[0]; a.Local || a.Err == nil || a.Err.Class != sms.Auth {
		t.Fatalf("a refused probe is a real answer: %+v", a)
	}
	if hs.held[r.priGW.ID] == nil {
		t.Fatal("a refused probe lifted the hold")
	}
	// The provider now accepts (the operator whitelisted the address, say).
	refuse = false
	out, err = hs.send(r, pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Accepted(); !ok || r.pri.calls != 3 {
		t.Fatalf("the probe was not accepted: calls %d", r.pri.calls)
	}
	if hs.held[r.priGW.ID] != nil {
		t.Fatal("an accepted probe did not lift the hold")
	}
	if _, err := hs.send(r, req); err != nil || r.pri.calls != 4 {
		t.Fatalf("after the lift the primary carries traffic again: calls %d, err %v", r.pri.calls, err)
	}
}

// Only a refused login holds. A gateway that is down, out of credit or unhappy about a template
// recovers by itself and keeps its breaker and probes.
func TestOnlyARefusedLoginHoldsAGateway(t *testing.T) {
	for name, e := range map[string]*sms.Error{
		"transient":   sms.NewError(sms.ProviderSMSIR, sms.Transient, sms.CodeTimeout),
		"credit":      sms.NewError(sms.ProviderSMSIR, sms.Credit, sms.StatusCode("102")),
		"config":      sms.NewError(sms.ProviderSMSIR, sms.Config, sms.StatusCode("113")),
		"recipient":   sms.NewError(sms.ProviderSMSIR, sms.Recipient, sms.StatusCode("104")),
		"blacklisted": sms.NewError(sms.ProviderSMSIR, sms.Blacklisted, sms.StatusCode("115")),
	} {
		r, hs := holdRig(t)
		r.pri.reply = func(int) (sms.Result, error) { return sms.Result{}, e }
		for i := 0; i < 3; i++ {
			if _, err := hs.send(r, req); err != nil {
				t.Fatal(err)
			}
		}
		if len(hs.held) != 0 || r.pri.calls != 3 {
			t.Errorf("%s: held %d, primary calls %d, want no hold and 3 calls", name, len(hs.held), r.pri.calls)
		}
	}
}

// A send whose attempts are never recorded keeps the old behaviour: every send asks again. It is the control
// of the first test, which would pass for a router that never called the provider at all.
func TestWithoutARecordedHoldARefusedGatewayIsAskedEveryTime(t *testing.T) {
	r := newRig(t)
	r.pri.reply = func(int) (sms.Result, error) { return refused() }
	for i := 0; i < 3; i++ {
		if _, err := r.router.Send(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if r.pri.calls != 3 {
		t.Errorf("primary calls %d, want 3", r.pri.calls)
	}
}

// sms-r12-5: the hold has no timer, so only an answer that proves a refused login may start it.
// A numeric status of the provider's table does. An HTTP 401 or 403 does not, except sms.ir's
// documented 401: a 403 from a provider's edge says nothing about the credentials, and holding
// the gateway on it would take OTP out of service until a restart although the provider
// recovered seconds later. Such an answer stays an Auth failure (the alert, the breaker step) and
// the breaker probes again after its pause.
func TestOnlyAProvenRefusalHoldsAGateway(t *testing.T) {
	for _, c := range []struct {
		name string
		err  *sms.Error
		hold bool
	}{
		{"sms.ir key refused (10)", sms.NewError(sms.ProviderSMSIR, sms.Auth, sms.StatusCode("10")), true},
		{"sms.ir documented 401", sms.NewError(sms.ProviderSMSIR, sms.Auth, sms.HTTPCode(401)), true},
		{"melipayamak -108", sms.NewError(sms.ProviderMelipayamak, sms.Auth, sms.StatusCode("-108")), true},
		{"melipayamak 0", sms.NewError(sms.ProviderMelipayamak, sms.Auth, sms.StatusCode("0")), true},
		{"melipayamak http 403", sms.NewError(sms.ProviderMelipayamak, sms.Auth, sms.HTTPCode(403)), false},
		{"melipayamak http 401", sms.NewError(sms.ProviderMelipayamak, sms.Auth, sms.HTTPCode(401)), false},
		{"sms.ir http 403", sms.NewError(sms.ProviderSMSIR, sms.Auth, sms.HTTPCode(403)), false},
		{"auth with an unlisted word", sms.NewError(sms.ProviderSMSIR, sms.Auth, sms.CodeUnknown), false},
	} {
		r, hs := holdRig(t)
		r.pri.reply = func(int) (sms.Result, error) { return sms.Result{}, c.err }
		for i := 0; i < 3; i++ {
			out, err := hs.send(r, req)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := out.Accepted(); !ok {
				t.Fatalf("%s: the fallback did not carry the send", c.name)
			}
		}
		if held := len(hs.held) == 1; held != c.hold {
			t.Errorf("%s: held %v, want %v", c.name, held, c.hold)
		}
		wantCalls := 3
		if c.hold {
			wantCalls = 1
		}
		if r.pri.calls != wantCalls {
			t.Errorf("%s: primary calls %d, want %d", c.name, r.pri.calls, wantCalls)
		}
	}
}

// sms-r13-2, sms-r13-5: the router writes nothing. A refused login only marks its attempt, with the
// revision of the credentials it was made with, and the record of the send writes the hold, so the
// refusal costs the fallback no time and a write that fails cannot lose the send's own record.
func TestTheRouterOnlyMarksARefusedAttemptAndWritesNoHold(t *testing.T) {
	r, hs := holdRig(t)
	refuse := true
	r.pri.reply = func(int) (sms.Result, error) {
		if refuse {
			return refused()
		}
		return sms.Result{ProviderID: sms.ParseField("ok-1")}, nil
	}
	out, err := r.router.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs.held) != 0 {
		t.Fatal("the router wrote a hold itself")
	}
	if len(out.Attempts) != 2 {
		t.Fatalf("attempts: %d, want the refusal and the fallback's accept", len(out.Attempts))
	}
	if a := out.Attempts[0]; a.Hold != sms.HoldPlace || a.Revision != 1 || a.Gateway != r.priGW.ID {
		t.Errorf("the refused attempt is not marked for a hold: %+v", a)
	}
	if a := out.Attempts[1]; a.Hold != sms.HoldNone {
		t.Errorf("the accepted fallback attempt is marked: %+v", a)
	}

	// A pinned accepted send on a held gateway asks for the lifting, and a pinned refusal on a
	// held gateway asks for nothing (it is already held).
	hs.record(out)
	r.router.Invalidate()
	pin := req
	pin.Gateway = r.priGW.ID
	out, err = r.router.Send(context.Background(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if a := out.Attempts[0]; a.Hold != sms.HoldNone {
		t.Errorf("a refusal on a gateway that is already held asked for a second hold: %+v", a)
	}
	refuse = false
	out, err = r.router.Send(context.Background(), pin)
	if err != nil {
		t.Fatal(err)
	}
	if a := out.Attempts[0]; a.Hold != sms.HoldLift || a.Revision != 1 {
		t.Errorf("an accepted probe of a held gateway does not ask for the lifting: %+v", a)
	}
}
