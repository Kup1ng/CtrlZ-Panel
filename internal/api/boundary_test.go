package api

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/bearer"
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
		// The routes that carry a share or download link value screen it before the schema check (P3 7.1), so a request whose value
		// is not one this service made is the 404 of junk and never reaches the check. Each of their cases carries a value that
		// screens, made for a row that does not exist and used once, so that what a case breaks is the member it names; a case that
		// breaks the value itself is junk and is 404 (or 400 or 413 when the router or the size says so first).
		intact := true
		if kind, ok := linkOps[c.Op]; ok {
			c, intact = f.withLiveLink(t, c, kind)
		}
		r := boundary.DoAs(context.Background(), f.h, host, boundary.IP(i), c, cookie)
		v := boundary.Verdict(c, r)
		if !intact && !c.Baseline && r.Status == 404 {
			v = ""
		}
		if v != "" {
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

// linkOps are the operations that carry a link value, and the kind of value each takes.
var linkOps = map[string]bearer.Kind{
	"openShare": bearer.ShareLink, "createShareAppleProfile": bearer.ShareLink, "downloadAppleProfile": bearer.DownloadLink,
}

// withLiveLink puts a value that screens in place of the sample the generator wrote, in the body or the path. intact says the
// case still carries that value whole, in the member or the path segment of the route: only then does the case reach the schema
// check, and so only then must it be refused by the member it breaks.
func (f *frig) withLiveLink(t *testing.T, c boundary.Case, kind bearer.Kind) (out boundary.Case, intact bool) {
	t.Helper()
	v, err := f.srv.bearer.Mint(kind, uuid.New(), f.ck.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	live := v.Reveal()
	out = c
	if c.Body != nil {
		out.Body = bytes.ReplaceAll(c.Body, []byte(strings.Repeat("a", bearer.Len)), []byte(live))
		var m map[string]json.RawMessage
		var got string
		if json.Unmarshal(out.Body, &m) == nil && json.Unmarshal(m["link"], &got) == nil {
			intact = got == live
		}
		return out, intact
	}
	out.Path = strings.Replace(c.Path, strings.Repeat("A", bearer.Len), live, 1)
	return out, out.Path == "/public/apple-profile/"+live
}
