package classify_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms"
	"github.com/Kup1ng/CtrlZ-Panel/internal/sms/classify"
)

// (a) The exhaustive half of rule sms-failure-classification: every sms.Code has a
// scope. The codes are read from the source of codes.go, so a code added tomorrow is in
// the list tomorrow and this test fails until the table of scope.go names it.

// declaredCodes returns the value of every constant of type Code in codes.go.
func declaredCodes(t *testing.T) []sms.Code {
	t.Helper()
	path := filepath.Join("..", "codes.go")
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []sms.Code
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "Code" {
				continue
			}
			for _, v := range vs.Values {
				lit, ok := v.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, sms.Code(s))
			}
		}
	}
	return out
}

func allClasses() []sms.Class {
	return []sms.Class{0, sms.Transient, sms.Auth, sms.Credit, sms.Config, sms.Recipient, sms.Blacklisted, 99}
}

func TestEverySMSCodeHasAScope(t *testing.T) {
	codes := declaredCodes(t)
	if len(codes) < 25 {
		t.Fatalf("only %d codes read from codes.go; the test is not looking at the table", len(codes))
	}
	for _, c := range codes {
		if c == sms.CodeNone {
			continue // the zero Code is "no problem", not a member
		}
		if !c.Valid() {
			t.Errorf("code %q is declared in codes.go but is not Valid()", c)
		}
		for _, class := range allClasses() {
			s, ok := classify.Of(c, class)
			if !ok {
				t.Errorf("code %q (class %v) has no scope: add a row to classify.Of", c, class)
			}
			if s.String() == "unknown" || !s.Name().Valid() {
				t.Errorf("code %q (class %v) maps to %v, which is not a scope", c, class, s)
			}
		}
	}
	// The two families a driver reads from a provider are not constants, so the source
	// walk does not list them. They take the scope of the class the driver gave them.
	for _, c := range []sms.Code{sms.StatusCode("10"), sms.StatusCode("-1"), sms.StatusCode("104"), sms.HTTPCode(401), sms.HTTPCode(503)} {
		if !c.Valid() {
			t.Fatalf("test code %q is not a member of the table of codes.go", c)
		}
		for _, class := range allClasses() {
			if _, ok := classify.Of(c, class); !ok {
				t.Errorf("provider status %q (class %v) has no scope", c, class)
			}
		}
	}
	// A word that is not a member is in no row, and ScopeOf answers closed for it.
	if _, ok := classify.Of("no_such_code", sms.Config); ok {
		t.Error("a code that is not in the table of codes.go has a scope")
	}
	if got := classify.ScopeOf(&sms.Error{Provider: "sms_ir", Class: sms.Config, Code: "no_such_code"}); got != classify.Ambiguous {
		t.Errorf("an unclassified code is %v, want ambiguous (it must count toward the breaker)", got)
	}
}

// The scope of the codes the router and the senders make on their own does not depend
// on a driver's class. Naming the intent here is what pins the table to the spec: a row
// moved to another scope fails here and in the matrix below.
func TestScopeOfTheFixedCodes(t *testing.T) {
	want := map[sms.Code]classify.Scope{
		sms.CodeNoCredentials: classify.Gateway, sms.CodeBadCredentials: classify.Gateway, sms.CodeNoopInProduction: classify.Gateway,
		sms.CodeUnknownProvider: classify.Gateway, sms.CodeCredentialsUnreadable: classify.Gateway, sms.CodeUnusable: classify.Gateway,
		sms.CodeNoTemplate: classify.Template, sms.CodeParamCount: classify.Template, sms.CodeTemplateID: classify.Template, sms.CodeParamMissing: classify.Template,
		sms.CodeBadMessage: classify.Message, sms.CodeValueTooLong: classify.Message, sms.CodeValueSeparator: classify.Message,
		sms.CodeRequest: classify.Message, sms.CodeEncode: classify.Message,
		sms.CodeNumberFormat: classify.Number,
		sms.CodeTimeout:      classify.Ambiguous, sms.CodeNetwork: classify.Ambiguous, sms.CodeFile: classify.Ambiguous,
		sms.CodeNoGateway: classify.Ambiguous, sms.CodeDriverErr: classify.Ambiguous,
	}
	for c, s := range want {
		for _, class := range allClasses() {
			if got, _ := classify.Of(c, class); got != s {
				t.Errorf("%s with class %v is %v, want %v", c, class, got, s)
			}
		}
	}
	// What the provider said decides the scope of the codes that carry its meaning. Config
	// means a template only for a status number the provider documents; for anything the
	// driver could not place (a redirect, an HTTP status, an unlisted status, an unreadable
	// reply) it is Ambiguous, which counts toward the breaker (sms-r5-4).
	byClass := func(config classify.Scope) map[sms.Class]classify.Scope {
		return map[sms.Class]classify.Scope{
			sms.Transient: classify.Ambiguous, sms.Auth: classify.Gateway, sms.Credit: classify.Gateway,
			sms.Config: config, sms.Recipient: classify.Number, sms.Blacklisted: classify.Number,
			0: classify.Ambiguous, 99: classify.Ambiguous,
		}
	}
	for _, c := range []sms.Code{sms.StatusCode("10"), sms.StatusCode("113"), sms.StatusCode("114"), sms.StatusCode("116"), sms.StatusCode("117"), sms.StatusCode("-2"), sms.StatusCode("-4"), sms.StatusCode("-5"), sms.StatusCode("-10"), sms.StatusCode("7")} {
		for class, s := range byClass(classify.Template) {
			if got, _ := classify.Of(c, class); got != s {
				t.Errorf("%s with class %v is %v, want %v", c, class, got, s)
			}
		}
	}
	// A status about the account's line or plan is Gateway whatever else, when the driver tags it
	// Config (sms-r9-1); the other classes keep their own reading of the number.
	for _, c := range []sms.Code{sms.StatusCode("101"), sms.StatusCode("118"), sms.StatusCode("119"), sms.StatusCode("123"), sms.StatusCode("-3"), sms.StatusCode("-7")} {
		for class, s := range byClass(classify.Gateway) {
			if got, _ := classify.Of(c, class); got != s {
				t.Errorf("%s with class %v is %v, want %v", c, class, got, s)
			}
		}
	}
	for _, c := range []sms.Code{sms.CodeUnknown, sms.CodeRedirect, sms.CodeBadReply, sms.HTTPCode(400), sms.HTTPCode(401), sms.HTTPCode(403), sms.HTTPCode(404), sms.HTTPCode(503)} {
		for class, s := range byClass(classify.Ambiguous) {
			if got, _ := classify.Of(c, class); got != s {
				t.Errorf("%s with class %v is %v, want %v", c, class, got, s)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// (b) The truth table of spec 9.7.

// rep is one way a gateway can fail, labelled with the scope the spec says it has. The
// label is written here, by hand, and never taken from classify, so a row of the table
// that moves fails the matrix.
type rep struct {
	name   string
	scope  classify.Scope
	local  bool       // the gateway is passed over with no network call
	reply  *sms.Error // what the sender answers, for a network failure
	prob   sms.Code   // the Problem of a gateway with no Sender
	tpl    bool       // no mapping for the template
	params []string   // a mapping with this many parameters (nil: the right one)
	final  bool       // the answer ends the send (a refused number)
}

type failing struct{ err *sms.Error }

func (failing) Provider() string { return "sms_ir" }
func (f failing) Send(context.Context, sms.Message, sms.ProviderTemplate) (sms.Result, error) {
	return sms.Result{}, f.err
}
func (failing) Balance(context.Context) (sms.Field, error) { return sms.Field{}, nil }

type fixedSource struct{ snap sms.Snapshot }

func (s fixedSource) Load(context.Context) (sms.Snapshot, error) { return s.snap, nil }

func reps() []rep {
	e := func(class sms.Class, code sms.Code) *sms.Error { return sms.NewError("sms_ir", class, code) }
	return []rep{
		{name: "a refused key", scope: classify.Gateway, reply: e(sms.Auth, sms.StatusCode("10"))},
		{name: "no credit", scope: classify.Gateway, reply: e(sms.Credit, sms.StatusCode("102"))},
		{name: "credentials that do not open", scope: classify.Gateway, local: true, prob: sms.CodeCredentialsUnreadable},
		{name: "no credentials", scope: classify.Gateway, local: true, prob: sms.CodeNoCredentials},
		{name: "a noop row in production", scope: classify.Gateway, local: true, prob: sms.CodeNoopInProduction},
		{name: "an unknown provider", scope: classify.Gateway, local: true, prob: sms.CodeUnknownProvider},
		{name: "a gateway with no stated problem", scope: classify.Gateway, local: true},
		{name: "a timeout", scope: classify.Ambiguous, reply: e(sms.Transient, sms.CodeTimeout)},
		{name: "a 5xx", scope: classify.Ambiguous, reply: e(sms.Transient, sms.HTTPCode(503))},
		{name: "an unreadable reply", scope: classify.Ambiguous, reply: e(sms.Transient, sms.CodeBadReply)},
		{name: "no mapping for the template", scope: classify.Template, local: true, tpl: true},
		{name: "a parameter count that differs", scope: classify.Template, local: true, params: []string{"A", "B"}},
		{name: "a template the provider refuses", scope: classify.Template, reply: e(sms.Config, sms.CodeTemplateID)},
		{name: "a documented status about the template", scope: classify.Template, reply: e(sms.Config, sms.StatusCode("113"))},
		// Statuses about the account's line or plan (sms-r9-1): every template on the gateway
		// fails the same way, so each counts toward the breaker.
		{name: "a sending line that is not active (sms.ir 123)", scope: classify.Gateway, reply: e(sms.Config, sms.StatusCode("123"))},
		{name: "a line that is invalid (sms.ir 101)", scope: classify.Gateway, reply: e(sms.Config, sms.StatusCode("101"))},
		{name: "a message count over the limit (sms.ir 118, read as the account's quota)", scope: classify.Gateway, reply: e(sms.Config, sms.StatusCode("118"))},
		{name: "a plan that must be upgraded (sms.ir 119)", scope: classify.Gateway, reply: e(sms.Config, sms.StatusCode("119"))},
		{name: "a line not defined (Melipayamak -3)", scope: classify.Gateway, reply: e(sms.Config, sms.StatusCode("-3"))},
		{name: "a sender number error (Melipayamak -7)", scope: classify.Gateway, reply: e(sms.Config, sms.StatusCode("-7"))},
		// Answers nothing documents (sms-r5-4): a gateway that answers any of these to every
		// send delivers nothing, so each counts toward the breaker. They were Template, which
		// never opened it and left OTP offered while no code arrived.
		{name: "a status nobody listed", scope: classify.Ambiguous, reply: e(sms.Config, sms.CodeUnknown)},
		{name: "a redirect", scope: classify.Ambiguous, reply: e(sms.Config, sms.CodeRedirect)},
		{name: "a 404 after a path change", scope: classify.Ambiguous, reply: e(sms.Config, sms.HTTPCode(404))},
		{name: "a 403 from a firewall", scope: classify.Ambiguous, reply: e(sms.Config, sms.HTTPCode(403))},
		{name: "a 400 with no readable body", scope: classify.Ambiguous, reply: e(sms.Config, sms.HTTPCode(400))},
		{name: "a value too long", scope: classify.Message, reply: e(sms.Config, sms.CodeValueTooLong)},
		{name: "a request the driver could not build", scope: classify.Message, reply: e(sms.Config, sms.CodeRequest)},
		{name: "a blacklisted number", scope: classify.Number, reply: e(sms.Blacklisted, sms.StatusCode("10"))},
		{name: "a refused number", scope: classify.Number, reply: e(sms.Recipient, sms.CodeNumberFormat), final: true},
	}
}

// counted is the truth table of 9.1 and 9.7 for the breaker: which scopes say that the
// whole gateway cannot deliver.
func counted(s classify.Scope) bool { return s == classify.Gateway || s == classify.Ambiguous }

var now = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// build makes a snapshot of the routed gateways with the given failures. An id in open
// has an open breaker in the snapshot, as the database would report it.
func build(rs []rep, open map[int]bool) (sms.Snapshot, []uuid.UUID) {
	var snap sms.Snapshot
	snap.Templates = map[sms.TemplateRef]sms.ProviderTemplate{}
	var ids []uuid.UUID
	roles := []string{"primary", "fallback"}
	for i, r := range rs {
		id := uuid.New()
		ids = append(ids, id)
		g := sms.Gateway{ID: id, Provider: "sms_ir", Role: roles[i]}
		if r.local && r.scope == classify.Gateway {
			g.Problem = r.prob // no Sender: the gateway cannot be used at all
		} else {
			g.Sender = failing{r.reply}
		}
		if open[i] {
			until := now.Add(time.Minute)
			g.BreakerOpenUntil = &until
		}
		snap.Gateways = append(snap.Gateways, g)
		if !r.tpl {
			names := []string{"Code"}
			if r.params != nil {
				names = r.params
			}
			snap.Templates[sms.TemplateRef{Gateway: id, Key: "otp", Locale: "fa"}] = sms.ProviderTemplate{ID: "1", ParamNames: names}
		}
	}
	return snap, ids
}

func send(t *testing.T, snap sms.Snapshot) sms.Outcome {
	t.Helper()
	router := sms.NewRouter(fixedSource{snap}, classify.Routing{}, sms.WithClock(func() time.Time { return now }))
	out, err := router.Send(context.Background(), sms.Request{To: "+989121234567", Template: "otp", Locale: "fa", Value: secret.New("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMatrix runs a send three times for every pair of failures on two routed gateways
// and for every single failure on one, with each breaker closed or already open, and
// follows the breaker of 9.1 (three counted failures in a row open it, a gateway whose
// breaker is open is skipped and does not move). Then it asks what the login page asks,
// sms_available: at least one routed gateway with a closed breaker. The expectation is
// the spec's: it is false exactly when every routed gateway is either already open or
// failing in a scope that says the whole gateway cannot deliver.
func TestMatrix(t *testing.T) {
	all := reps()
	type cell struct {
		rs   []rep
		open map[int]bool
	}
	var cells []cell
	for _, a := range all {
		for _, o := range []bool{false, true} {
			cells = append(cells, cell{[]rep{a}, map[int]bool{0: o}})
		}
		for _, b := range all {
			for mask := 0; mask < 4; mask++ {
				cells = append(cells, cell{[]rep{a, b}, map[int]bool{0: mask&1 != 0, 1: mask&2 != 0}})
			}
		}
	}
	for _, c := range cells {
		failures := make([]int, len(c.rs))
		open := map[int]bool{}
		for i, o := range c.open {
			open[i] = o
		}
		name := ""
		for i, r := range c.rs {
			name += r.name
			if c.open[i] {
				name += " (breaker open)"
			}
			name += " | "
		}
		for round := 0; round < 3; round++ {
			snap, ids := build(c.rs, open)
			out := send(t, snap)
			for _, a := range out.Attempts {
				for i, id := range ids {
					if id != a.Gateway || !classify.CountsTowardBreaker(a) {
						continue
					}
					failures[i]++
					if failures[i] >= 3 {
						open[i] = true
					}
				}
			}
		}
		// The truth table: the gateways that are still closed are those not already open
		// and not failing in a counted scope. A final refusal on the primary means the
		// fallback is never asked, and the primary's own scope (number) never counts.
		wantAvailable := false
		for i, r := range c.rs {
			if !c.open[i] && !counted(r.scope) {
				wantAvailable = true
			}
		}
		gotAvailable := false
		for i := range c.rs {
			if !open[i] {
				gotAvailable = true
			}
		}
		if gotAvailable != wantAvailable {
			t.Errorf("%s: sms_available = %v, want %v", name, gotAvailable, wantAvailable)
		}
	}
	if len(cells) < 600 {
		t.Fatalf("only %d cells in the matrix", len(cells))
	}
}

// TestNumberRefusedMatrix is the same matrix for the other decision that reads the
// scopes of one send: whether the number itself is refused (9.5). It is true when the
// last answer is a final refusal, or when at least one gateway really answered about the
// number and every other gateway was a local pass about the message or the template;
// never when a routed gateway was skipped behind an open breaker, when one could not be
// used at all, or when one gave a verdict on anything but the number.
func TestNumberRefusedMatrix(t *testing.T) {
	all := reps()
	for _, a := range all {
		for _, b := range all {
			for mask := 0; mask < 4; mask++ {
				open := map[int]bool{0: mask&1 != 0, 1: mask&2 != 0}
				rs := []rep{a, b}
				snap, _ := build(rs, open)
				out := send(t, snap)
				want := wantRefused(rs, open)
				if got := classify.NumberRefused(out); got != want {
					t.Errorf("%s | %s open=%v: NumberRefused = %v, want %v (attempts %d, skipped %d)", a.name, b.name, open, got, want, len(out.Attempts), out.Skipped)
				}
			}
		}
	}
}

// wantRefused writes the 9.5 rule over the labelled failures, walking the routed
// gateways in order as the router does: an open breaker is skipped, and a final refusal
// ends the send.
func wantRefused(rs []rep, open map[int]bool) bool {
	var attempted []rep
	skipped := 0
	for i, r := range rs {
		if open[i] {
			skipped++
			continue
		}
		attempted = append(attempted, r)
		if r.final {
			break
		}
	}
	if n := len(attempted); n > 0 && attempted[n-1].final {
		return true
	}
	if skipped > 0 {
		return false
	}
	asked := 0
	for _, r := range attempted {
		switch {
		case r.local && (r.scope == classify.Template || r.scope == classify.Message):
			continue
		case r.local, r.scope != classify.Number:
			return false
		}
		asked++
	}
	return asked > 0
}

// TestBreakerIsPerGateway: a failure on one gateway does not count toward
// the other's breaker.
func TestBreakerIsPerGateway(t *testing.T) {
	rs := []rep{reps()[0], reps()[7]} // a refused key, then a timeout
	snap, ids := build(rs, nil)
	out := send(t, snap)
	if len(out.Attempts) != 2 {
		t.Fatalf("attempts: %d", len(out.Attempts))
	}
	for i, a := range out.Attempts {
		if a.Gateway != ids[i] || !classify.CountsTowardBreaker(a) {
			t.Errorf("attempt %d on %v: counts = %v", i, a.Gateway, classify.CountsTowardBreaker(a))
		}
	}
}

// TestAlertTable pins the alert severity and key of each scope (9.7, 9.8).
func TestAlertTable(t *testing.T) {
	gwID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	one := func(e *sms.Error, local bool) sms.Outcome {
		return sms.Outcome{Attempts: []sms.Attempt{{Gateway: gwID, Provider: "sms_ir", Local: local, Err: e}}}
	}
	otp := sms.ParseTemplate("otp")
	type want struct {
		sev, key string
	}
	cases := []struct {
		name string
		out  sms.Outcome
		want *want
	}{
		{"a refused key", one(sms.NewError("sms_ir", sms.Auth, sms.StatusCode("10")), false), &want{"critical", gwID.String() + ":auth"}},
		{"no credit", one(sms.NewError("sms_ir", sms.Credit, sms.StatusCode("102")), false), &want{"critical", gwID.String() + ":credit"}},
		{"unreadable credentials", one(sms.NewError("sms_ir", sms.Config, sms.CodeCredentialsUnreadable), true), &want{"critical", gwID.String() + ":config"}},
		{"a timeout", one(sms.NewError("sms_ir", sms.Transient, sms.CodeTimeout), false), nil},
		{"a blacklisted number", one(sms.NewError("sms_ir", sms.Blacklisted, sms.StatusCode("10")), false), nil},
		// One attempt that is about the template, with no other route tried and none
		// skipped, is a template no routed gateway can send.
		{"a missing mapping on the only route", one(sms.NewError("sms_ir", sms.Config, sms.CodeNoTemplate), true), &want{"critical", gwID.String() + ":config:otp:none"}},
	}
	for _, c := range cases {
		got := classify.Alerts(c.out, otp)
		switch {
		case c.want == nil && len(got) != 0:
			t.Errorf("%s: raised %d alerts, want none", c.name, len(got))
		case c.want != nil && (len(got) != 1 || got[0].Severity != c.want.sev || got[0].Key.String() != c.want.key || got[0].Kind != classify.KindGateway):
			t.Errorf("%s: %+v, want %+v", c.name, got, *c.want)
		}
	}
	// A missing mapping on one gateway while the other is skipped is only a warning on
	// its own key; the other route may carry the template.
	skipped := one(sms.NewError("sms_ir", sms.Config, sms.CodeNoTemplate), true)
	skipped.Skipped = 1
	if got := classify.Alerts(skipped, otp); len(got) != 1 || got[0].Severity != "warning" || got[0].Key.String() != gwID.String()+":config:otp" {
		t.Errorf("a missing mapping beside a skipped gateway: %+v", got)
	}
	// A test send is pinned: a missing mapping is the operator's answer, a warning.
	pinned := one(sms.NewError("sms_ir", sms.Config, sms.CodeNoTemplate), true)
	pinned.Pinned = true
	if got := classify.Alerts(pinned, otp); len(got) != 1 || got[0].Severity != "warning" {
		t.Errorf("a pinned test send: %+v", got)
	}
	// sms_down speaks for an outcome that ended on a transient failure and for nothing else.
	if _, ok := classify.Down(one(sms.NewError("sms_ir", sms.Transient, sms.CodeTimeout), false)); !ok {
		t.Error("no sms_down for a timeout")
	}
	if _, ok := classify.Down(sms.Outcome{}); !ok {
		t.Error("no sms_down when no gateway was left to try")
	}
	for _, e := range []*sms.Error{sms.NewError("sms_ir", sms.Auth, sms.StatusCode("10")), sms.NewError("sms_ir", sms.Config, sms.CodeNoTemplate), sms.NewError("sms_ir", sms.Blacklisted, sms.StatusCode("10"))} {
		if _, ok := classify.Down(one(e, false)); ok {
			t.Errorf("sms_down for %v", e)
		}
	}
}

func TestDeliveryOutcome(t *testing.T) {
	for _, c := range []struct {
		e    *sms.Error
		want string
	}{
		{sms.NewError("sms_ir", sms.Transient, sms.CodeTimeout), "unreachable"},
		{sms.NewError("sms_ir", sms.Auth, sms.StatusCode("10")), "rejected"},
		{sms.NewError("sms_ir", sms.Blacklisted, sms.StatusCode("10")), "rejected"},
		{sms.NewError("sms_ir", sms.Config, sms.CodeTemplateID), "rejected"},
	} {
		if got := classify.DeliveryOutcome(sms.Attempt{Err: c.e}); got != c.want {
			t.Errorf("%v: %s, want %s", c.e, got, c.want)
		}
	}
}
