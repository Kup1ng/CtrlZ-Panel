package api

import (
	"context"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
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
	// A heavy operation (P2 spec 6.5: the bulk-write class and a big rule create) checks its body only after its session
	// resolved, its place was taken and its buckets were charged, so a forged cookie is 401 before any schema check: those operations are driven with
	// a live session. The clock moves a minute every few cases (a session's own bucket is 10 a minute) and the limiter is renewed
	// now and then (the tenant's day budget of bulk-write is 200).
	bulk := map[string]bool{}
	ops, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if op.MaxBody > httpx.BulkThreshold || op.Rate == ratelimit.BulkWrite {
			bulk[op.ID] = true
		}
	}
	live := f.makeSession(f.env.A.Tenant, f.env.A.User).jar[session.CookieSession]
	bulkCases := 0
	baselines, refused := 0, 0
	for i, c := range cases {
		cookie := boundary.TenantCookie(f.keys, f.ck.now().Add(time.Hour))
		if bulk[c.Op] {
			bulkCases++
			if bulkCases%8 == 0 {
				f.ck.add(time.Minute)
			}
			if bulkCases%150 == 0 {
				f.setLimiter(ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: f.ck.now}))
			}
			cookie = live
		}
		r := boundary.DoAs(context.Background(), f.h, host, boundary.IP(i), c, cookie)
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
