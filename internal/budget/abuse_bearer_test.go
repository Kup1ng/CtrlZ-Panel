package budget_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// The twins of TestAbuseDeadCookiesBeyondTheSetShareTheirSessionsBudget for the bearer values of P3 (docs/specs/p3-endpoints.md
// 11.5; review round 1 of D6, p3-D6-r1-14). The dead set forgets its oldest mark at its capacity, so a holder of more dead values
// than that who sends them round and round finds each forgotten when it comes back. What bounds the cost then is the class that is
// charged on the row or token the value names, before the lookup and never given back: token-miss for a token, public-link for a
// share or download link, 30 a minute each. A removed charge on either path lets the same holder cost one lookup a request.

// tokenStub is an API token reader whose every value is gone for good: "t-<n>" screens as the token row n, and its lookup (one
// TokenByHash on the pool) is counted and answers 401 with Dead set, as the real reader does for a deleted or revoked token.
type tokenStub struct{ lookups atomic.Int64 }

func (*tokenStub) Screen(cred string) (string, bool) {
	return strings.TrimPrefix(cred, "t-"), strings.HasPrefix(cred, "t-")
}

func (s *tokenStub) Resolve(context.Context, string, apispec.Operation, netip.Addr) (httpx.Resolved, error) {
	s.lookups.Add(1)
	return httpx.Resolved{Dead: true}, httpx.TokenInvalid()
}

func TestAbuseDeadTokensBeyondTheSetShareTheirTokenBudget(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: func() time.Time { return now }})
	adm, err := admission.New(admission.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	op := apispec.Operation{ID: "readThing", Method: "POST", Path: "/c/read-thing", Auth: apispec.Session, Rate: "user-read", Token: "read"}
	tokens := &tokenStub{}
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Limiter: lim, Service: ratelimit.Tenant, Ops: []apispec.Operation{op}, SkipRequestCheck: true,
		Resolver: &stubResolver{}, Tokens: tokens, BaseURL: "/api/v1", DeadCapacity: 8, Admission: adm, Host: httpx.StaticHost("panel.test"),
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	built.Router.With(built.PerOp).Post("/api/v1"+op.Path, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	miss, ok := ratelimit.Lookup(ratelimit.Tenant, ratelimit.TokenMiss)
	if !ok {
		t.Fatal("the tenant service has no token-miss class")
	}
	send := func(i int) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1"+op.Path, nil)
		r.Host = "panel.test"
		r.RemoteAddr = "198.51.100.7:4000"
		r.Header.Set("Authorization", fmt.Sprintf("Bearer t-%d", i))
		w := httptest.NewRecorder()
		built.Router.ServeHTTP(w, r)
		return w.Code
	}
	// Four hundred dead tokens, a set that holds eight, each sent more times than its budget allows in the minute (the clock does
	// not move): each is a lookup until its budget is spent and a refusal after, and no more lookups than the budget are made.
	const tokensN, rounds = 400, 40
	budget := miss.Limits[0].Max
	if rounds <= budget {
		t.Fatalf("%d rounds do not exhaust a budget of %d", rounds, budget)
	}
	for r := 0; r < rounds; r++ {
		for i := 0; i < tokensN; i++ {
			send(i)
		}
	}
	if got, want := tokens.lookups.Load(), int64(tokensN*budget); got != want {
		t.Errorf("%d dead tokens sent %d times caused %d lookups, want exactly the budget of %d each: %d", tokensN, rounds, got, budget, want)
	}
	// A token that is not among them is served its own budget: the others' spending is not its own.
	before := tokens.lookups.Load()
	send(tokensN + 1)
	if tokens.lookups.Load() != before+1 {
		t.Error("a token that had spent nothing was refused before its lookup")
	}
}

func TestAbuseDeadLinksBeyondTheSetShareTheirRowBudget(t *testing.T) {
	h := newHarnessCap(t, ratelimit.Tenant, 8)
	pub, ok := ratelimit.Lookup(ratelimit.Tenant, ratelimit.PublicLink)
	if !ok {
		t.Fatal("the tenant service has no public-link class")
	}
	budget := pub.Limits[0].Max
	const rows, rounds = 400, 40
	if rounds <= budget {
		t.Fatalf("%d rounds do not exhaust a budget of %d", rounds, budget)
	}
	before := h.handled.Load()
	for r := 0; r < rounds; r++ {
		for i := 0; i < rows; i++ {
			h.postLinkDead(ratelimit.PublicLink, away(r*rows+i), fmt.Sprintf("row-%d", i))
		}
	}
	if got, want := h.handled.Load()-before, int64(rows*budget); got != want {
		t.Errorf("%d dead link values sent %d times caused %d lookups, want exactly the budget of %d each: %d", rows, rounds, got, budget, want)
	}
}

// postLinkDead is postLink for a value whose row does not exist: the handler reports the lookup found nothing.
func (h *harness) postLinkDead(class, ip, row string) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/c/"+class, nil)
	r.Host = "panel.test"
	r.RemoteAddr = hostPort(ip) + ":4000"
	r.Header.Set("X-Test-Link", row)
	r.Header.Set("X-Test-Dead", "1")
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w.Code
}
