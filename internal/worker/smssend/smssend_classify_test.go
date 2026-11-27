package smssend_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/smssend"
)

// The database half of the matrix of rule sms-failure-classification (P1 auth review,
// round 5; spec 9.7). internal/sms/classify has the pure matrix over every failure;
// this one runs the real worker over the real tables for a representative failure of
// each scope, one or two routed gateways, and a breaker that is closed or already open,
// and asks what the router may still use (the breaker and the hold) and, since round 18
// (sms-r18-2), that the public sms_available flag did not move.
//
// The expectation is the truth table of 9.7, written here by hand: no routed gateway can
// be used exactly when every one is either already open or failing in a scope that says
// the whole gateway cannot deliver (gateway, ambiguous). A failure about one template,
// one message or one number never closes the router to a gateway, because a breaker is per
// gateway and the other purposes would go with it.

type shape struct {
	name  string
	scope classify.Scope
	// A gateway that cannot be used at all has a Problem and no Sender; every other
	// shape has a Sender that answers err, or a mapping that is wrong or missing.
	problem sms.Code
	err     *sms.Error
	noMap   bool
	params  []string
}

func shapes() []shape {
	e := func(c sms.Class, code sms.Code) *sms.Error { return sms.NewError("sms_ir", c, code) }
	return []shape{
		{name: "key refused", scope: classify.Gateway, err: e(sms.Auth, sms.StatusCode("10"))},
		{name: "credentials unreadable", scope: classify.Gateway, problem: sms.CodeCredentialsUnreadable},
		{name: "timeout", scope: classify.Ambiguous, err: e(sms.Transient, sms.CodeTimeout)},
		{name: "no mapping", scope: classify.Template, noMap: true},
		{name: "template refused", scope: classify.Template, err: e(sms.Config, sms.CodeTemplateID)},
		{name: "value too long", scope: classify.Message, err: e(sms.Config, sms.CodeValueTooLong)},
		{name: "blacklisted", scope: classify.Number, err: e(sms.Blacklisted, sms.StatusCode("10"))},
	}
}

type failingSender struct{ err *sms.Error }

func (failingSender) Provider() string { return "sms_ir" }
func (f failingSender) Send(context.Context, sms.Message, sms.ProviderTemplate) (sms.Result, error) {
	return sms.Result{}, f.err
}
func (failingSender) Balance(context.Context) (sms.Field, error) { return sms.Field{}, nil }

// shapedSource loads the real snapshot and then gives each gateway the failure its
// shape says. The mappings and gateway ids stay the database's.
type shapedSource struct {
	inner  sms.Source
	shapes map[uuid.UUID]shape
}

func (s shapedSource) Load(ctx context.Context) (sms.Snapshot, error) {
	snap, err := s.inner.Load(ctx)
	if err != nil {
		return snap, err
	}
	for i, g := range snap.Gateways {
		sh, ok := s.shapes[g.ID]
		if !ok {
			continue
		}
		snap.Gateways[i].Sender, snap.Gateways[i].Problem = nil, sh.problem
		if sh.problem == sms.CodeNone {
			snap.Gateways[i].Sender = failingSender{sh.err}
		}
		for ref := range snap.Templates {
			if ref.Gateway != g.ID {
				continue
			}
			switch {
			case sh.noMap:
				delete(snap.Templates, ref)
			case sh.params != nil:
				snap.Templates[ref] = sms.ProviderTemplate{ID: "1", ParamNames: sh.params}
			}
		}
	}
	return snap, nil
}

func TestSMSAvailabilityFollowsTheScopeOfTheFailures(t *testing.T) {
	r := newRig(t)
	all := shapes()
	type cell struct {
		primary shape
		fall    *shape // nil: one routed gateway
		fbOpen  bool   // the fallback's breaker is already open
	}
	var cells []cell
	for _, p := range all {
		pp := p
		cells = append(cells, cell{primary: p})
		// The fallbacks: one of each kind of answer that matters beside the primary. The
		// pure matrix in internal/sms/classify has every pair; this is the same table over
		// the real tables, kept short because every cell is three passes of a worker.
		for _, i := range []int{1, 2, 3, 6} {
			ff := all[i]
			cells = append(cells, cell{primary: pp, fall: &ff})
		}
		cells = append(cells, cell{primary: p, fall: &all[0], fbOpen: true})
	}
	for _, c := range cells {
		name := c.primary.name
		if c.fall != nil {
			name += " + " + c.fall.name
			if c.fbOpen {
				name += " (fallback breaker open)"
			}
		}
		r.env.ResetSMS(t)
		priID := r.env.AddGateway(t, r.ring, authtest.Gateway{Provider: "sms_ir", Role: "primary", Credentials: `{"api_key":"` + canaryIRKey + `"}`})
		shapesByID := map[uuid.UUID]shape{priID: c.primary}
		counted := func(s classify.Scope) bool { return s == classify.Gateway || s == classify.Ambiguous }
		wantRoutable := !counted(c.primary.scope)
		if c.fall != nil {
			fbID := r.env.AddGateway(t, r.ring, authtest.Gateway{Provider: "melipayamak", Role: "fallback",
				Credentials: `{"username":"canary-user","password":"` + canaryMeliPW + `"}`})
			shapesByID[fbID] = *c.fall
			if c.fbOpen {
				r.env.Exec(t, `UPDATE ctrlz.sms_gateways SET breaker_open_until = now() + interval '1 hour', consecutive_failures = 3 WHERE id = $1`, fbID)
			}
			// routable while any routed gateway is closed and not failing in a counted scope
			wantRoutable = (!c.fbOpen && !counted(c.fall.scope)) || !counted(c.primary.scope)
		}
		src := shapedSource{inner: smssend.NewSource(r.worker, r.ring, senderEnv(r.noopFile), slog.New(slog.NewJSONHandler(io.Discard, nil))), shapes: shapesByID}
		src.inner.(*smssend.Source).Build = r.build
		w, err := smssend.New(smssend.Config{Store: r.worker, Router: sms.NewRouter(src, classify.Routing{}), Keys: r.ring, Log: slog.New(slog.NewJSONHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		r.request(r.env.A.Phone)
		for i := 0; i < 3; i++ {
			if _, err := w.Drain(r.env.Ctx); err != nil {
				t.Fatalf("%s: drain: %v", name, err)
			}
			r.lapse()
		}
		cfg, err := r.tenant.Auth().PublicConfig(r.env.Ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// The scope of a failure decides what the ROUTER may still use, which is the breaker and the hold:
		// the table of this test. The public flag is configuration alone since round 18 (sms-r18-2) and
		// is the same in every cell, because no send moves it; that it is true here is the property.
		if !cfg.SMSAvailable {
			t.Errorf("%s: sms_available = false: a failed send moved the public flag", name)
		}
		if routable := r.count(`SELECT count(*) FROM ctrlz.sms_gateways WHERE role IN ('primary', 'fallback') AND (breaker_open_until IS NULL OR breaker_open_until <= now()) AND NOT blocked_now`) > 0; routable != wantRoutable {
			t.Errorf("%s: a routed gateway can still be used = %v, want %v", name, routable, wantRoutable)
		}
	}
}
