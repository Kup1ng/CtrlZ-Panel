package api

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
)

// TestBoundaryFuzz is the end-to-end half of rule boundary-input (P1 auth review
// round 5, rules.md topic 9, spec 18.5; internal/lint TestOpenAPIBoundsEveryInput is
// the document half and internal/authtest/boundary the schema half).
//
// Every operation of api/openapi.yaml gets a baseline request that satisfies its
// schema and then one request per way a client can break a bound, one at a time:
// a NUL, a control, a bidi override, a joiner, invalid UTF-8, a 64 KiB value, a value
// one over its length, an integer outside its range or too large for 64 bits, a list
// or a map one over its size, a key that is not a word, a member of the wrong type, a
// required member missing. Through the real server, over real Postgres, each of them
// must be refused 400 (413 when it is only too large) before any handler, session or
// database work, and none may put a WARN or an ERROR line in the log. The baselines
// must get past the schema check, so a refusal always means the mutated member.
//
// Then each baseline is sent by a client that has already gone (a cancelled request
// context): never a 5xx, since nobody is left to read it and it is not a fault.
func TestBoundaryFuzz(t *testing.T) {
	f := newFrig(t, frigOpts{passkey: true})
	cases, err := boundary.Cases(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	baselines, refused := 0, 0
	for i, c := range cases {
		r := boundary.DoAs(context.Background(), f.h, host, boundary.IP(i), c, boundary.TenantCookie(f.keys, f.ck.now().Add(time.Hour)))
		if v := boundary.Verdict(c, r); v != "" {
			t.Errorf("%s: %s", c.Name, v)
			continue
		}
		if c.Baseline {
			baselines++
		} else {
			refused++
		}
	}
	if baselines < 40 || refused < 2000 {
		t.Errorf("only %d baselines and %d refusals fired: the generator has stopped covering the document", baselines, refused)
	}

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	for i, c := range cases {
		if !c.Baseline {
			continue
		}
		if v := boundary.AbortVerdict(boundary.DoAs(gone, f.h, host, boundary.IP(len(cases)+i), c, boundary.TenantCookie(f.keys, f.ck.now().Add(time.Hour)))); v != "" {
			t.Errorf("%s: %s", c.Name, v)
		}
	}

	if lines := boundary.WarnLines(f.logs.String()); len(lines) > 0 {
		t.Errorf("%d WARN or ERROR lines from client input, first: %s", len(lines), lines[0])
	}
}
