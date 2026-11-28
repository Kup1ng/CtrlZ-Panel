package policy

import (
	"context"
	"reflect"
	"testing"

	"github.com/Kup1ng/CtrlZ-Shared/names"
)

type oneAnswer struct{ a *TrueAnswer }

func (o oneAnswer) Lookup(context.Context, names.Name, uint16, ResolveParams) (*TrueAnswer, error) {
	return o.a, nil
}

// PostDefault must be the evaluator's own no-profile path and nothing else, so a
// caller of it (soft_disabled, the degraded mode, the free path) cannot drift
// from what a Decide over an empty stack gives (SC 5.1, T-560).
func TestPostDefaultIsDecideOverNoProfile(t *testing.T) {
	n := names.MustString("x.test")
	rr := func(typ uint16, d []byte) RR { return RR{Name: n, Type: typ, Class: ClassIN, TTL: 300, Data: d} }
	answers := map[string]*TrueAnswer{
		"secure": {Chain: []names.Name{n}, Validation: Secure, Answer: []RR{rr(TypeA, []byte{93, 184, 216, 34}), rr(TypeRRSIG, []byte{0xab, 0xcd})}},
		"bogus":  {Chain: []names.Name{n}, Validation: Bogus, Answer: []RR{rr(TypeA, []byte{93, 184, 216, 34})}},
		"failed": {Failed: true, RCode: RCodeServFail},
		// A private address passes: Rebind is an option of a profile.
		"private": {Chain: []names.Name{n}, Answer: []RR{rr(TypeA, []byte{192, 168, 1, 5})}},
	}
	for an, ans := range answers {
		for _, qt := range []uint16{TypeA, TypeAAAA, TypeHTTPS} {
			for _, flags := range []struct{ cd, do, ad bool }{{}, {do: true}, {ad: true}, {cd: true, do: true}} {
				in := &Input{Name: n, QType: qt, Now: 1, CD: flags.cd, DO: flags.do, AD: flags.ad}
				got := PostDefault(in, ans)
				want := Decide(context.Background(), in, NewStack(nil, nil, nil), &Env{}, oneAnswer{ans})
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s qtype %d %+v:\n got  %+v\n want %+v", an, qt, flags, got, want)
				}
				if got.Action != ActionBypass || got.Stage != StageDefault || got.WantGrant {
					t.Errorf("%s: %+v is not Bypass, default, no Grant", an, got)
				}
			}
		}
	}
}

func TestPostDefaultRules(t *testing.T) {
	n := names.MustString("x.test")
	a := RR{Name: n, Type: TypeA, Class: ClassIN, TTL: 300, Data: []byte{1, 2, 3, 4}}
	sig := RR{Name: n, Type: TypeRRSIG, Class: ClassIN, TTL: 300, Data: []byte{1}}
	secure := &TrueAnswer{Chain: []names.Name{n}, Validation: Secure, Answer: []RR{a, sig}}

	// ANY is never resolved: one HINFO, with no answer at all.
	if f := PostDefault(&Input{Name: n, QType: TypeANY}, nil); len(f.Answer.Answer) != 1 || f.Answer.Answer[0].Type != TypeHINFO {
		t.Errorf("ANY: %+v", f.Answer)
	}
	// 5.12: a nil or failed answer is SERVFAIL.
	for _, ta := range []*TrueAnswer{nil, {Failed: true}} {
		if f := PostDefault(&Input{Name: n, QType: TypeA}, ta); f.Answer.RCode != RCodeServFail {
			t.Errorf("failure: %+v", f.Answer)
		}
	}
	// 5.11 with EffectiveCD equal to the client's CD: Bogus is SERVFAIL unless
	// the client sent CD.
	bogus := &TrueAnswer{Chain: []names.Name{n}, Validation: Bogus, Answer: []RR{a}}
	if f := PostDefault(&Input{Name: n, QType: TypeA}, bogus); f.Answer.RCode != RCodeServFail || len(f.Answer.Answer) != 0 {
		t.Errorf("bogus, CD off: %+v", f.Answer)
	}
	if f := PostDefault(&Input{Name: n, QType: TypeA, CD: true}, bogus); f.Answer.RCode != RCodeNoError || len(f.Answer.Answer) != 1 || f.Answer.AD {
		t.Errorf("bogus, CD on: %+v", f.Answer)
	}
	// AD needs a Secure answer, CD clear and DO or AD from the client; the
	// signatures stay only for DO.
	if f := PostDefault(&Input{Name: n, QType: TypeA, DO: true}, secure); !f.Answer.AD || len(f.Answer.Answer) != 2 {
		t.Errorf("secure, DO: %+v", f.Answer)
	}
	if f := PostDefault(&Input{Name: n, QType: TypeA}, secure); f.Answer.AD || len(f.Answer.Answer) != 1 {
		t.Errorf("secure, no DO: %+v", f.Answer)
	}
	if f := PostDefault(&Input{Name: n, QType: TypeA, DO: true, CD: true}, secure); f.Answer.AD {
		t.Errorf("secure, CD: %+v", f.Answer)
	}
}
