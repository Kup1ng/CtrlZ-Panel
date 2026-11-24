package vectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
)

// EvalCase is one evaluator vector.
type EvalCase struct {
	ID       string                 `json:"id"`
	Why      string                 `json:"why"`
	Endpoint string                 `json:"endpoint"`
	Client   string                 `json:"client"`
	Req      ReqJSON                `json:"req"`
	Upstream map[string]UpstreamRec `json:"upstream"`
	Expect   ExpectJSON             `json:"expect"`
}

type ReqJSON struct {
	QName      string `json:"qname"`
	QType      string `json:"qtype"`
	Now        string `json:"now"`
	Src        string `json:"src"`
	SrcCountry string `json:"src_country"`
	Protocol   string `json:"protocol"`
	CD         bool   `json:"cd"`
	DO         bool   `json:"do"`
	AD         bool   `json:"ad"`
	Isolated   bool   `json:"isolated"`
}

type UpstreamRec struct {
	RCode      string   `json:"rcode"`
	Failed     bool     `json:"failed"`
	Chain      []string `json:"chain"`
	Answer     []string `json:"answer"`
	Authority  []string `json:"authority"`
	Validation string   `json:"validation"`
	ECSScope   uint8    `json:"ecs_scope"`
}

type AnswerJSON struct {
	RCode     string    `json:"rcode"`
	AD        *bool     `json:"ad"`
	Answer    *[]string `json:"answer"`
	Authority *[]string `json:"authority"`
	ECS       *string   `json:"ecs"`
}

// ExpectJSON lists only what a case asserts; a nil field is not checked.
type ExpectJSON struct {
	PreDone      *bool       `json:"pre_done"`
	Deferred     *bool       `json:"deferred"`
	Walk         *bool       `json:"walk"`
	Action       *string     `json:"action"`
	Stage        *string     `json:"stage"`
	Ref          *string     `json:"ref"`
	Slot         *uint8      `json:"slot"`
	Flags        *[]string   `json:"flags"`
	WantGrant    *bool       `json:"want_grant"`
	GrantKind    *uint8      `json:"grant_kind"`
	Widenable    *bool       `json:"widenable"`
	Target       *string     `json:"target"`
	Location     *uint16     `json:"location"`
	Effective    *[]uint16   `json:"effective"`
	DialHost     *string     `json:"dial_host"`
	Hop          *uint8      `json:"hop"`
	TrafficCat   *uint16     `json:"traffic_cat"`
	TableMissing *bool       `json:"table_missing"`
	Lookups      *[]string   `json:"lookups"`
	Answer       *AnswerJSON `json:"answer"`
}

func protoOf(s string) (policy.Protocol, error) {
	switch s {
	case "udp", "":
		return policy.ProtoUDP, nil
	case "tcp":
		return policy.ProtoTCP, nil
	case "doh":
		return policy.ProtoDoH, nil
	case "dot":
		return policy.ProtoDoT, nil
	case "doq":
		return policy.ProtoDoQ, nil
	}
	return 0, fmt.Errorf("protocol %q", s)
}

func validationOf(s string) (policy.Validation, error) {
	switch s {
	case "indeterminate":
		return policy.Indeterminate, nil
	case "secure":
		return policy.Secure, nil
	case "insecure", "":
		return policy.Insecure, nil
	case "bogus":
		return policy.Bogus, nil
	}
	return 0, fmt.Errorf("validation %q", s)
}

func actionText(a policy.Action) string {
	switch a {
	case policy.ActionBlock:
		return "block"
	case policy.ActionBypass:
		return "bypass"
	case policy.ActionRedirect:
		return "redirect"
	}
	return "none"
}

func targetText(k policy.TargetKind) string {
	return [...]string{"none", "location", "auto", "random", "ip", "host"}[k]
}

// upstreamResolver serves the case's canned answers and records every lookup.
type upstreamResolver struct {
	recs       map[string]UpstreamRec
	calls      []string
	unexpected []string
}

var errNoVector = errors.New("vector has no upstream answer for this lookup")

func (u *upstreamResolver) Lookup(_ context.Context, n names.Name, qtype uint16, _ policy.ResolveParams) (*policy.TrueAnswer, error) {
	key := n.String() + "/" + typeName(qtype)
	u.calls = append(u.calls, key)
	rec, ok := u.recs[key]
	if !ok {
		u.unexpected = append(u.unexpected, key)
		return nil, errNoVector
	}
	ta := &policy.TrueAnswer{Failed: rec.Failed, ECSScope: rec.ECSScope}
	var err error
	if rec.RCode == "" {
		rec.RCode = "NOERROR"
	}
	if ta.RCode, err = rcodeFromName(rec.RCode); err != nil {
		return nil, err
	}
	if ta.Validation, err = validationOf(rec.Validation); err != nil {
		return nil, err
	}
	chain := rec.Chain
	if len(chain) == 0 {
		chain = []string{n.String()}
	}
	for _, c := range chain {
		cn, err := names.FromString(c)
		if err != nil {
			return nil, err
		}
		ta.Chain = append(ta.Chain, cn)
	}
	for _, s := range rec.Answer {
		rr, err := ParseRR(s)
		if err != nil {
			return nil, err
		}
		ta.Answer = append(ta.Answer, rr)
	}
	for _, s := range rec.Authority {
		rr, err := ParseRR(s)
		if err != nil {
			return nil, err
		}
		ta.Authority = append(ta.Authority, rr)
	}
	return ta, nil
}

func buildRequest(c *EvalCase) (*Request, *upstreamResolver, error) {
	var in policy.Input
	qn, err := names.FromString(c.Req.QName)
	if err != nil {
		return nil, nil, fmt.Errorf("qname: %w", err)
	}
	in.Name = qn
	if in.QType, err = typeFromName(c.Req.QType); err != nil {
		return nil, nil, err
	}
	if in.Now, err = parseTime(c.Req.Now); err != nil {
		return nil, nil, fmt.Errorf("now: %w", err)
	}
	if c.Req.Src != "" {
		if in.Src, err = netip.ParseAddr(c.Req.Src); err != nil {
			return nil, nil, err
		}
	}
	if cc := c.Req.SrcCountry; cc != "" {
		if len(cc) != 2 {
			return nil, nil, fmt.Errorf("src_country %q", cc)
		}
		in.SrcCountry = [2]byte{cc[0], cc[1]}
	}
	if in.Protocol, err = protoOf(c.Req.Protocol); err != nil {
		return nil, nil, err
	}
	in.CD, in.DO, in.AD = c.Req.CD, c.Req.DO, c.Req.AD
	in.Trace = true
	in.EndpointID = EndpointID(c.Endpoint)
	r := &Request{Input: in, Endpoint: c.Endpoint, Isolated: c.Req.Isolated}
	if c.Client != "" {
		r.ClientHash = identity.ClientHash(c.Client)
	}
	u := &upstreamResolver{recs: c.Upstream}
	r.Resolver = u
	return r, u, nil
}

func runEvaluatorGroup(t *testing.T, g *GroupFile, h Harness) {
	fx, err := LoadFixture(g.Fixture)
	if err != nil {
		t.Fatalf("fixture %s: %v", g.Fixture, err)
	}
	ev, err := h.Prepare(fx)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	var cases []EvalCase
	if err := decodeStrict(g.Cases, &cases); err != nil {
		t.Fatalf("%s: %v", g.Group, err)
	}
	if len(cases) == 0 {
		t.Fatalf("%s has no cases", g.Group)
	}
	seen := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		if seen[c.ID] || c.ID == "" {
			t.Errorf("duplicate or empty case id %q", c.ID)
		}
		seen[c.ID] = true
		if err := vacuous(g.Group, c); err != nil {
			t.Errorf("%s: %v (case: %s)", c.ID, err, c.Why)
		}
		t.Run(c.ID, func(t *testing.T) {
			req, up, err := buildRequest(c)
			if err != nil {
				t.Fatalf("%s: bad case: %v", c.Why, err)
			}
			out, err := ev.Evaluate(context.Background(), req)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			for _, u := range up.unexpected {
				t.Errorf("unexpected lookup %q (case: %s)", u, c.Why)
			}
			check(t, fx, c, out, up)
		})
	}
}

func check(t *testing.T, fx *Fixture, c *EvalCase, out *Outcome, up *upstreamResolver) {
	t.Helper()
	e, f := &c.Expect, &out.Final
	fail := func(field string, got, want any) {
		t.Errorf("%s: %s = %v, want %v\n  case: %s", c.ID, field, got, want, c.Why)
		if len(f.Trace) > 0 {
			var b strings.Builder
			for _, s := range f.Trace {
				fmt.Fprintf(&b, " [L%d %s slot%d hit=%v %s]", s.Level, s.Stage, s.Slot, s.Hit, s.Detail)
			}
			t.Logf("trace:%s", b.String())
		}
	}
	cmp := func(field string, got, want any) {
		if !reflect.DeepEqual(got, want) {
			fail(field, got, want)
		}
	}
	if e.PreDone != nil {
		cmp("pre_done", out.PreDone, *e.PreDone)
	}
	if e.Deferred != nil {
		cmp("deferred", out.Deferred, *e.Deferred)
	}
	if e.Walk != nil {
		cmp("walk", out.Walk, *e.Walk)
	}
	if e.Action != nil {
		cmp("action", actionText(f.Action), *e.Action)
	}
	if e.Stage != nil {
		cmp("stage", f.Stage.String(), *e.Stage)
	}
	if e.Ref != nil {
		cmp("ref", fx.RefText(f.Ref), *e.Ref)
	}
	if e.Slot != nil {
		cmp("slot", f.Slot, *e.Slot)
	}
	if e.Flags != nil {
		cmp("flags", f.Flags.Names(), *e.Flags)
	}
	if e.WantGrant != nil {
		cmp("want_grant", f.WantGrant, *e.WantGrant)
	}
	if e.GrantKind != nil {
		cmp("grant_kind", f.GrantKind, *e.GrantKind)
	}
	if e.Widenable != nil {
		cmp("widenable", f.Widenable, *e.Widenable)
	}
	if e.Target != nil {
		cmp("target", targetText(f.Target), *e.Target)
	}
	if e.Location != nil {
		cmp("location", f.Location, *e.Location)
	}
	if e.Effective != nil {
		got := f.Effective
		if got == nil {
			got = []uint16{}
		}
		cmp("effective", got, *e.Effective)
	}
	if e.DialHost != nil {
		got := ""
		if f.DialHost.Len() > 0 {
			got = f.DialHost.String()
		}
		cmp("dial_host", got, *e.DialHost)
	}
	if e.Hop != nil {
		cmp("hop", f.HopIndex, *e.Hop)
	}
	if e.TrafficCat != nil {
		cmp("traffic_cat", f.TrafficCat, *e.TrafficCat)
	}
	if e.TableMissing != nil {
		cmp("table_missing", f.TableMissing, *e.TableMissing)
	}
	if e.Lookups != nil {
		got := up.calls
		if got == nil {
			got = []string{}
		}
		cmp("lookups", got, *e.Lookups)
	}
	if a := e.Answer; a != nil {
		if a.RCode != "" {
			cmp("answer.rcode", rcodeName(f.Answer.RCode), a.RCode)
		}
		if a.AD != nil {
			cmp("answer.ad", f.Answer.AD, *a.AD)
		}
		norm := func(in []string) []string {
			out := []string{}
			for _, s := range in {
				rr, err := ParseRR(s)
				if err != nil {
					t.Fatalf("%s: expected RR %q: %v", c.ID, s, err)
				}
				out = append(out, FormatRR(rr))
			}
			return out
		}
		render := func(rrs []policy.RR) []string {
			out := []string{}
			for _, rr := range rrs {
				out = append(out, FormatRR(rr))
			}
			return out
		}
		if a.Answer != nil {
			cmp("answer.answer", render(f.Answer.Answer), norm(*a.Answer))
		}
		if a.Authority != nil {
			cmp("answer.authority", render(f.Answer.Authority), norm(*a.Authority))
		}
		if a.ECS != nil {
			got := "none"
			if f.Answer.ECS != nil {
				got = fmt.Sprintf("%s scope %d", f.Answer.ECS.Source, f.Answer.ECS.Scope)
			}
			cmp("answer.ecs", got, *a.ECS)
		}
	}
}

// compile-time check that the JSON types stay decodable by encoding/json.
var _ = json.Marshal

// vacuous rejects a case whose expectation could not fail on a wrong answer.
// Every field of ExpectJSON is optional, and an unset one is not checked, so a
// case that asserts neither an action nor an answer passes whatever the
// evaluator does. In the qtype matrix, which pins the synthesized answers of
// section 7, an empty answer (NODATA or NXDOMAIN) must also assert the
// Authority section, because the SOA there is what makes the negative answer
// cacheable and its TTL is part of the contract.
func vacuous(group string, c *EvalCase) error {
	e := &c.Expect
	if e.Action == nil && e.Answer == nil {
		return errors.New("asserts neither an action nor an answer")
	}
	if group == "qtype-matrix" && e.Answer != nil {
		a := e.Answer
		empty := a.Answer != nil && len(*a.Answer) == 0
		if (empty || a.RCode == "NXDOMAIN") && a.Authority == nil {
			return errors.New("a NODATA or NXDOMAIN cell must assert the Authority SOA and its TTL (section 7)")
		}
	}
	return nil
}
