package budget_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/throttle"
	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The two abuse tests of rule budget-keying, generated for every registered bucket.
//
//	A. Strangers on the same /24 (and the same /64 and /48) fill the buckets that a
//	   network can fill. A request that carries a proof must still pass, and a
//	   subject's own bucket must not have moved.
//	B. A proof (or a subject) that moves to a new network on every request is
//	   refused once its own budget is spent: moving networks buys nothing.
//
// A bucket the generator cannot drive fails the test, so a new bucket needs a driver
// before it can be declared, and a Network bucket that says a proof cannot stand in
// for it (NoProof) is checked to keep that reason and to refuse the proof's help.

// ---------------------------------------------------------------------------
// Throttle scopes, through throttle.Service with a counting fake store.

type counters struct {
	n map[string]int
}

func newCounters() *counters { return &counters{n: map[string]int{}} }

func (c *counters) hit(_ context.Context, scope string, key []byte, max int, _ time.Duration) (store.ThrottleResult, error) {
	k := scope + "|" + string(key)
	c.n[k]++
	if c.n[k] > max {
		return store.ThrottleResult{RetryAfter: time.Minute}, nil
	}
	return store.ThrottleResult{Allowed: true}, nil
}

func (c *counters) reset(_ context.Context, scope string, key []byte) error {
	for k := range c.n {
		if strings.HasPrefix(k, scope+"|") && (key == nil || k == scope+"|"+string(key)) {
			c.n[k] = 0
		}
	}
	return nil
}

func fakeMAC(parts ...[]byte) []byte { return bytes.Join(parts, []byte{0}) }

func newService(svc budget.Service) *throttle.Service {
	c := newCounters()
	return throttle.NewFor(svc, c.hit, c.reset, fakeMAC)
}

// victim is the subject every test acts for.
var victim = throttle.Who{
	Phone: "+989121234567", Username: "root", User: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
	Admin: uuid.MustParse("22222222-2222-2222-2222-222222222222"), Session: uuid.MustParse("55555555-5555-5555-5555-555555555555"), Marker: "marker-of-the-owner",
	Invite: uuid.MustParse("33333333-3333-3333-3333-333333333333"),
}

// at returns who with an address.
func at(w throttle.Who, ip string) throttle.Who {
	w.IP = netip.MustParseAddr(ip)
	return w
}

// stranger i on the victim's network: the same /24, the same /64 for IPv6.
func strangerV4(i int) string { return fmt.Sprintf("203.0.113.%d", 10+i%200) }
func strangerV6(i int) string { return fmt.Sprintf("2001:db8:1:2::%x", i+1) }

// strangerWide is a different /64 of the victim's /48.
func strangerWide(i int) string { return fmt.Sprintf("2001:db8:1:%x::9", i+16) }

// away is a new network on every call: the proof that moves.
func away(i int) string { return fmt.Sprintf("198.51.%d.%d", i%250, 1+i/250) }

// spend charges until the scope refuses, and returns how many were allowed.
func spend(t *testing.T, s *throttle.Service, sc throttle.Scope, who func(i int) throttle.Who) int {
	t.Helper()
	p, ok := throttle.PolicyOf(sc)
	if !ok {
		t.Fatalf("no policy for %s", sc)
	}
	for i := 0; i < p.Max+5; i++ {
		err := s.Charge(context.Background(), sc, who(i))
		if errors.Is(err, throttle.ErrTooMany) {
			return i
		}
		if err != nil {
			t.Fatalf("%s: %v", sc, err)
		}
	}
	t.Fatalf("%s was never refused", sc)
	return 0
}

// proofEntry is how a request that carries a proof of a Network scope is charged: the
// entry point of the route, with the proof. The test fails for a Network scope that
// names a ProofBucket and has no entry here.
func proofEntry(name string) func(s *throttle.Service, ip string, i int) error {
	ctx := context.Background()
	switch name {
	case "invite_net", "invite_net48":
		return func(s *throttle.Service, ip string, _ int) error {
			return s.InviteHit(ctx, netip.MustParseAddr(ip), victim.Invite)
		}
	case "admin_login_net", "admin_login":
		return func(s *throttle.Service, ip string, _ int) error {
			_, err := s.AdminLoginHits(ctx, victim.Username, netip.MustParseAddr(ip), victim.Marker)
			return err
		}
	}
	return nil
}

// noProofEntry is the same route without a proof: it must be the network that counts.
func noProofEntry(name string) func(s *throttle.Service, ip string) error {
	ctx := context.Background()
	switch name {
	case "invite_net", "invite_net48":
		return func(s *throttle.Service, ip string) error { return s.InviteHit(ctx, netip.MustParseAddr(ip), uuid.Nil) }
	case "admin_login_net", "admin_login":
		return func(s *throttle.Service, ip string) error {
			userScope, err := s.AdminLoginHits(ctx, victim.Username, netip.MustParseAddr(ip), "")
			if err == nil {
				err = userScope
			}
			return err
		}
	}
	return nil
}

func TestAbuseAStrangersFillTheNetworkBucketsAndAProofStillPasses(t *testing.T) {
	ctx := context.Background()
	for _, b := range budget.All() {
		if b.Layer != budget.Throttle || !b.HasNetwork() {
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			s := newService(b.Service)
			sc := throttle.Scope(b.Name)

			var variants []func(i int) string
			switch {
			case containsPart(b, budget.PartWide):
				variants = append(variants, strangerWide) // different /64s of one /48
			default:
				variants = append(variants, strangerV4, strangerV6)
			}
			for vi, v := range variants {
				s = newService(b.Service) // fresh counters for each variant
				var who func(i int) throttle.Who
				if b.Narrow {
					// The key holds the subject too. A stranger on the owner's network who
					// guesses at the owner's name spends the owner's pair on that network,
					// which is why it is narrow; strangers on other networks spend nothing of it.
					who = func(i int) throttle.Who { return at(victim, v(i)) }
				} else {
					who = func(i int) throttle.Who { return at(throttle.Who{}, v(i)) }
				}
				got := spend(t, s, sc, who)
				if p, _ := throttle.PolicyOf(sc); got != p.Max {
					t.Fatalf("variant %d: %d strangers allowed, want %d", vi, got, p.Max)
				}
				switch {
				case b.ProofBucket != "":
					entry := proofEntry(b.Name)
					if entry == nil {
						t.Fatalf("no driver for the proof of %s: add one to proofEntry", b.Name)
					}
					// The owner's request carries a proof and comes from the filled network.
					for k := 0; k < 3; k++ {
						if err := entry(s, v(1000+k), k); err != nil {
							t.Fatalf("variant %d: a request with a proof was refused by %s: %v", vi, b.Name, err)
						}
					}
					// The control: the same route without a proof is refused on the network.
					ctl := noProofEntry(b.Name)
					if ctl == nil {
						t.Fatalf("no driver for the route of %s without a proof", b.Name)
					}
					if err := ctl(s, v(2000)); !errors.Is(err, throttle.ErrTooMany) {
						t.Fatalf("variant %d: the stranger control was not refused: %v", vi, err)
					}
				case b.NoProof != "":
					// No proof stands in for the network, so nothing carried with the
					// request can open the bucket: the registry says why.
					if len(b.NoProof) < 40 {
						t.Fatalf("%s: NoProof %q is not a reason", b.Name, b.NoProof)
					}
					if err := s.Charge(ctx, sc, who(3000)); !errors.Is(err, throttle.ErrTooMany) {
						t.Fatalf("variant %d: %v", vi, err)
					}
				}
			}
		})
	}
}

func TestAbuseAStrangersCannotSpendASubjectsBucket(t *testing.T) {
	for _, b := range budget.All() {
		if b.Layer != budget.Throttle || b.Source == budget.Network {
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			s := newService(b.Service)
			sc := throttle.Scope(b.Name)
			// A hundred other subjects (and, on the owner's network, a hundred strangers)
			// spend their own budgets: the owner's pair is untouched.
			p, _ := throttle.PolicyOf(sc)
			for i := 0; i < 100; i++ {
				w := at(throttle.Who{
					Phone: fmt.Sprintf("+98912000%04d", i), Username: fmt.Sprintf("stranger%d", i),
					User: uuid.New(), Admin: uuid.New(), Session: uuid.New(), Marker: fmt.Sprintf("marker-%d", i), Invite: uuid.New(),
				}, strangerV4(i))
				for k := 0; k <= p.Max; k++ {
					_ = s.Charge(context.Background(), sc, w)
				}
			}
			for k := 0; k < p.Max; k++ {
				if err := s.Charge(context.Background(), sc, at(victim, strangerV4(k))); err != nil {
					t.Fatalf("the owner's own budget was spent by others: %v", err)
				}
			}
		})
	}
}

func TestAbuseBAProofThatMovesNetworksIsRefusedAfterItsBudget(t *testing.T) {
	for _, b := range budget.All() {
		if b.Layer != budget.Throttle {
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			s := newService(b.Service)
			sc := throttle.Scope(b.Name)
			p, _ := throttle.PolicyOf(sc)
			switch {
			case b.Source != budget.Network && !b.Narrow:
				// The key holds no network: a new address on every request is the same bucket.
				got := spend(t, s, sc, func(i int) throttle.Who { return at(victim, away(i)) })
				if got != p.Max {
					t.Fatalf("%d allowed while moving, want %d", got, p.Max)
				}
			case b.Narrow:
				// The pair is keyed on the network too, so moving gets a new pair by design,
				// and the budget that follows the subject is the entry point's other scope.
				var entry func(i int) error
				switch b.Name {
				case "login_phone_net":
					entry = func(i int) error {
						return s.LoginHits(context.Background(), victim.Phone, netip.MustParseAddr(away(i)))
					}
				case "admin_login":
					entry = func(i int) error {
						userScope, err := s.AdminLoginHits(context.Background(), victim.Username, netip.MustParseAddr(away(i)), "")
						if err == nil {
							err = userScope // reported separately, and a refusal all the same
						}
						return err
					}
				default:
					t.Fatalf("no driver for the narrow scope %s", b.Name)
				}
				// Moving on every request is refused by the subject-keyed scope of the same
				// entry point, within its own budget and not the network pair's.
				allowed := 0
				for i := 0; i < 200 && entry(i) == nil; i++ {
					allowed++
				}
				want := map[string]throttle.Scope{"login_phone_net": throttle.LoginPhone, "admin_login": throttle.AdminLoginUser}[b.Name]
				if sib, _ := throttle.PolicyOf(want); allowed != sib.Max {
					t.Fatalf("%s moving networks: %d allowed, want the %d of %s", b.Name, allowed, sib.Max, want)
				}
			default:
				// A Network scope: the proof that stands in for it, when there is one, is a
				// bucket of its own that does not move with the network.
				if b.ProofBucket == "" {
					if b.NoProof == "" {
						t.Fatalf("%s has neither a proof bucket nor a reason", b.Name)
					}
					return
				}
				entry := proofEntry(b.Name)
				if entry == nil {
					t.Fatalf("no driver for the proof of %s", b.Name)
				}
				pb, _ := budget.FindScope(b.ProofBucket)
				allowed := 0
				for i := 0; i < pb.Max+5; i++ {
					if err := entry(s, away(i), i); err != nil {
						if !errors.Is(err, throttle.ErrTooMany) {
							t.Fatal(err)
						}
						break
					}
					allowed++
				}
				if allowed != pb.Max {
					t.Fatalf("a proof that moves networks was allowed %d times, want its budget of %d", allowed, pb.Max)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Rate classes, through the real pipeline.

type stubResolver struct{ lookups atomic.Int64 }

func (*stubResolver) CookieName() string { return "sess" }

// Screen accepts "ok-..." cookies, as a tag check would.
func (*stubResolver) Screen(cookie string) (string, string, bool) {
	return cookie, issuerOf(cookie), strings.HasPrefix(cookie, "ok-")
}

// Resolve gives every screened cookie a session of its own. A cookie "ok-live-..." belongs to a
// live session (its lookup token is given back); "ok-dead-..." belongs to one that is gone for
// good (the answer of the real resolvers: 401, and the pipeline remembers the cookie); any other
// "ok-..." is a session that is neither, so every request of it is a lookup of its own.
func (s *stubResolver) Resolve(ctx context.Context, cookie string, _ apispec.Operation) (httpx.Resolved, error) {
	s.lookups.Add(1) // each call is one SessionByHash on the pool
	if strings.HasPrefix(cookie, "ok-dead") {
		return httpx.Resolved{Dead: true}, httpx.SessionExpired()
	}
	// "ok-live-x~3" is the fourth cookie of session "ok-live-x": a rotation changes the cookie and
	// keeps the session, as the real resolvers do.
	live := strings.HasPrefix(cookie, "ok-live")
	res := httpx.Resolved{Ctx: ctx, Live: live}
	if live {
		res.SessionID = strings.SplitN(cookie, "~", 2)[0]
	}
	return res, nil
}

type harness struct {
	h       http.Handler
	limiter *ratelimit.Limiter
	res     *stubResolver
}

func newHarness(t *testing.T, svc ratelimit.Service) *harness { return newHarnessCap(t, svc, 0) }

// newHarnessCap is newHarness with the pipeline's dead set at a given capacity (0 is the default).
func newHarnessCap(t *testing.T, svc ratelimit.Service, deadCap int) *harness {
	t.Helper()
	var ops []apispec.Operation
	for _, c := range ratelimit.Classes(svc) {
		if ratelimit.ChargedByThePipeline(c.Name) {
			continue
		}
		auth := apispec.None
		if c.Key == ratelimit.BySession {
			auth = apispec.Session
		}
		ops = append(ops, apispec.Operation{ID: c.Name, Method: "POST", Path: "/c/" + c.Name, Auth: auth, Rate: c.Name})
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	lim := ratelimit.New(ratelimit.Config{Service: svc, LocalOnly: true, Now: func() time.Time { return now }})
	res := &stubResolver{}
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Limiter: lim, Service: svc, Ops: ops, SkipRequestCheck: true, Resolver: res, BaseURL: "/api/v1", DeadCapacity: deadCap,
		Host: httpx.StaticHost("panel.test"),
		Proof: func(r *http.Request) (string, string, bool) {
			id := r.Header.Get("X-Test-Marker")
			// The account the marker was sealed for; one account unless the test names another.
			subject := r.Header.Get("X-Test-Subject")
			if subject == "" {
				subject = "the-one-account"
			}
			return id, subject, id != ""
		},
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	// A deferred class is answered by its handler (budget.Bucket.Deferred). X-Test-Exempt stands for the one
	// request such a handler lets through (the console one-time password of the admin login).
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// X-Test-Held stands for a handler that found the device marker holds for the account asked about
		// (budget.Bucket.HeldProof): it asks httpx.HeldProofHolds, which charges the marker's buckets and
		// gives the plain token back.
		// X-Test-Invite stands for a handler that read the invite the request carries: "live-N" is a live
		// invite (budget.Bucket.HeldInvite: it asks httpx.InviteProofHolds), anything else is a token that is not live
		// and gets the plain bucket's answer.
		if inv := r.Header.Get("X-Test-Invite"); inv != "" {
			if !strings.HasPrefix(inv, "live-") {
				if e := httpx.DeferredRefusal(r.Context()); e != nil {
					httpx.Write(w, r, e)
					return
				}
			} else if e := httpx.InviteProofHolds(r.Context(), inv); e != nil {
				httpx.Write(w, r, e)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Header.Get("X-Test-Held") != "" {
			if e := httpx.HeldProofHolds(r.Context()); e != nil {
				httpx.Write(w, r, e)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if e := httpx.DeferredRefusal(r.Context()); e != nil && r.Header.Get("X-Test-Exempt") == "" {
			httpx.Write(w, r, e)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	for _, op := range ops {
		built.Router.With(built.PerOp).Post("/api/v1"+op.Path, ok)
	}
	return &harness{h: built.Router, limiter: lim, res: res}
}

// post sends one request from ip. marker and cookie are optional.
func (h *harness) post(class, ip, marker, cookie string) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/c/"+class, nil)
	r.Host = "panel.test"
	r.RemoteAddr = hostPort(ip) + ":4000"
	if marker != "" {
		r.Header.Set("X-Test-Marker", marker)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: "sess", Value: cookie})
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w.Code
}

func hostPort(ip string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]"
	}
	return ip
}

// floodUntilRefused sends requests from strangers until the class refuses one, and
// returns how many were answered before.
func floodUntilRefused(t *testing.T, h *harness, class string, max int, ip func(i int) string) int {
	t.Helper()
	for i := 0; i < max+10; i++ {
		switch code := h.post(class, ip(i), "", ""); code {
		case http.StatusNoContent:
		case http.StatusTooManyRequests:
			return i
		default:
			t.Fatalf("%s from %s: %d", class, ip(i), code)
		}
	}
	t.Fatalf("%s was never refused", class)
	return 0
}

func TestAbuseARateClassesStrangersAndProofs(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, b := range budget.Of(budget.RateClass, budget.Service(svc)) {
			if ratelimit.ChargedByThePipeline(b.Name) {
				continue
			}
			t.Run(string(svc)+"/"+b.Name, func(t *testing.T) {
				h := newHarness(t, svc)
				max := b.Limits[0].Max
				switch b.Source {
				case budget.Network:
					// The /24, then the /64, then (wider factor) the /48, each filled by
					// strangers; then a request with a proof from the filled network.
					for name, ip := range map[string]func(int) string{"v4": strangerV4, "v6": strangerV6} {
						h = newHarness(t, svc)
						if got := floodUntilRefused(t, h, b.Name, max*ratelimit.WideFactor, ip); got != max {
							t.Fatalf("%s: %d strangers answered, want %d", name, got, max)
						}
						code := h.post(b.Name, ip(500), "owner-marker", "")
						switch {
						case b.ProofPart != "" && code != http.StatusNoContent:
							t.Fatalf("%s: a request with a proof got %d from a network that strangers filled", name, code)
						case b.ProofPart == "" && code != http.StatusTooManyRequests:
							t.Fatalf("%s: %s takes no proof and a marker got %d", name, b.Name, code)
						}
					}
					// The /48 bucket: strangers spread over the /64s of one /48 fill it.
					h = newHarness(t, svc)
					got := 0
					for i := 0; i < max*ratelimit.WideFactor+10; i++ {
						if h.post(b.Name, strangerWide(i), "", "") != http.StatusNoContent {
							break
						}
						got++
					}
					if got != max*ratelimit.WideFactor {
						t.Fatalf("/48: %d strangers answered, want %d", got, max*ratelimit.WideFactor)
					}
					if b.ProofPart != "" {
						if code := h.post(b.Name, strangerWide(900), "owner-marker", ""); code != http.StatusNoContent {
							t.Fatalf("/48: a request with a proof got %d", code)
						}
					}
				default:
					// A session class: other sessions on the same network spend their own.
					for i := 0; i < 3*max && i < 400; i++ {
						h.post(b.Name, strangerV4(i), "", fmt.Sprintf("ok-live-stranger-%d", i))
					}
					for i := 0; i < 20; i++ {
						h.post(b.Name, strangerV4(i), "", "ok-live-stranger-0")
					}
					if code := h.post(b.Name, strangerV4(1), "", "ok-live-owner"); code != http.StatusNoContent {
						t.Fatalf("the owner's session got %d after strangers spent theirs", code)
					}
				}
			})
		}
	}
}

func TestAbuseBRateClassesAProofThatMovesNetworks(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, b := range budget.Of(budget.RateClass, budget.Service(svc)) {
			if ratelimit.ChargedByThePipeline(b.Name) {
				continue
			}
			t.Run(string(svc)+"/"+b.Name, func(t *testing.T) {
				h := newHarness(t, svc)
				max := b.Limits[0].Max
				allowed := 0
				for i := 0; i < max+20; i++ {
					var code int
					if b.Source == budget.Network {
						if b.ProofPart == "" {
							// Nothing to move: a request with no proof is the network's by
							// definition, and the registry says why.
							if b.NoProof == "" && b.HeldProof == "" {
								t.Fatalf("%s has no proof and no reason", b.Name)
							}
							return
						}
						code = h.post(b.Name, away(i), "owner-marker", "")
					} else {
						code = h.post(b.Name, away(i), "", "ok-live-owner")
					}
					if code == http.StatusTooManyRequests {
						break
					}
					allowed++
				}
				if allowed != max {
					t.Fatalf("a proof that moved networks was answered %d times, want its budget of %d", allowed, max)
				}
			})
		}
	}
}

// session-lookup is keyed on the cookie: junk costs nothing, a dead cookie spends only
// its own budget, and a cookie that moves networks does not get a fresh one.
func TestAbuseSessionLookup(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		t.Run(string(svc), func(t *testing.T) {
			h := newHarness(t, svc)
			// The roomiest session class, so that only the lookup budget can refuse.
			var session string
			best := 0
			for _, c := range ratelimit.Classes(svc) {
				if c.Key == ratelimit.BySession && c.Name != ratelimit.SessionLookup && c.Limits[0].Max > best {
					session, best = c.Name, c.Limits[0].Max
				}
			}
			before := h.limiter.LocalSize()
			for i := 0; i < 500; i++ {
				if code := h.post(session, strangerV4(i), "", fmt.Sprintf("junk-%d", i)); code != http.StatusUnauthorized {
					t.Fatalf("junk cookie got %d", code)
				}
			}
			if h.limiter.LocalSize() != before {
				t.Fatalf("junk cookies created %d buckets", h.limiter.LocalSize()-before)
			}
			if code := h.post(session, strangerV4(1), "", "ok-live-owner"); code != http.StatusNoContent {
				t.Fatalf("the owner's live session got %d after the junk", code)
			}
			look, _ := ratelimit.Lookup(svc, ratelimit.SessionLookup)
			answered := 0
			for i := 0; i < look.Limits[0].Max+20; i++ {
				if h.post(session, away(i), "", "ok-limbo-a") == http.StatusTooManyRequests {
					break
				}
				answered++
			}
			if answered != look.Limits[0].Max {
				t.Fatalf("a cookie that moved networks was answered %d times, want %d", answered, look.Limits[0].Max)
			}
			// A cookie whose session is gone for good costs one lookup, however often and from
			// wherever it is sent: it is remembered (primitives-r6-5).
			lookupsBefore := h.res.lookups.Load()
			for i := 0; i < look.Limits[0].Max+20; i++ {
				if code := h.post(session, away(i), "", "ok-dead-b"); code != http.StatusUnauthorized {
					t.Fatalf("a dead cookie got %d, want 401", code)
				}
			}
			if got := h.res.lookups.Load() - lookupsBefore; got != 1 {
				t.Fatalf("a dead cookie caused %d lookups, want 1", got)
			}
			if code := h.post(session, strangerV4(1), "", "ok-live-owner"); code != http.StatusNoContent {
				t.Fatalf("a dead cookie spent the owner's lookup budget: %d", code)
			}
		})
	}
}

func containsPart(b budget.Bucket, p budget.Part) bool {
	for _, q := range b.Parts {
		if q == p {
			return true
		}
	}
	return false
}

// A key is never made of an address that is not there. Every bucket that holds a network
// refuses a request with no client address and counts nothing, at the one choke point,
// whatever entry point reached it (rule budget-keying; primitives-r4-1 was found entry
// point by entry point in round 4).
func TestEveryNetworkBucketRefusesAnEmptyAddress(t *testing.T) {
	for _, b := range budget.All() {
		if !b.HasNetwork() {
			continue
		}
		t.Run(b.Layer.String()+"/"+b.Name, func(t *testing.T) {
			switch b.Layer {
			case budget.Throttle:
				c := newCounters()
				s := throttle.NewFor(b.Service, c.hit, c.reset, fakeMAC)
				if err := s.Charge(context.Background(), throttle.Scope(b.Name), victim); err == nil || errors.Is(err, throttle.ErrTooMany) {
					t.Fatalf("a hit with no address: %v", err)
				}
				if len(c.n) != 0 {
					t.Fatalf("a hit with no address counted: %v", c.n)
				}
			case budget.RateClass:
				l := ratelimit.New(ratelimit.Config{Service: ratelimit.Service(b.Service), LocalOnly: true})
				class, _ := ratelimit.Lookup(ratelimit.Service(b.Service), b.Name)
				if _, err := l.Allow(context.Background(), class, ratelimit.Subject{Proof: "a-marker"}); !errors.Is(err, ratelimit.ErrNoSubject) {
					t.Fatalf("a request with a proof and no address: %v", err)
				}
				if l.LocalSize() != 0 {
					t.Fatal("a request with no address created a bucket")
				}
			}
		})
	}
}

// unlock leaves every registered scope of the admin clear (spec 10.1). The scopes it
// clears are walked from the registry, so one that is declared and forgotten fails
// here the day it is declared, not when somebody is locked out. The control is a
// stranger's counter on an exact-key scope of another admin, which unlock must not clear.
func TestUnlockClearsEveryRegisteredAdminScope(t *testing.T) {
	ctx := context.Background()
	c := newCounters()
	s := throttle.NewFor(budget.Admin, c.hit, c.reset, fakeMAC)
	other := throttle.Who{Username: "someone-else", Marker: "marker-of-someone-else", Admin: uuid.MustParse("44444444-4444-4444-4444-444444444444"), Session: uuid.MustParse("66666666-6666-6666-6666-666666666666"), IP: netip.MustParseAddr("203.0.113.9")}

	wholeStores := map[string]bool{}
	for _, b := range budget.Of(budget.Throttle, budget.Admin) {
		if b.HasNetwork() || b.Source == budget.Proof {
			wholeStores[b.StoreScope()] = true
		}
	}
	var scopes []throttle.Scope
	for _, b := range budget.Of(budget.Throttle, budget.Admin) {
		sc := throttle.Scope(b.Name)
		scopes = append(scopes, sc)
		spend(t, s, sc, func(i int) throttle.Who { return at(victim, strangerV4(0)) })
		spend(t, s, sc, func(i int) throttle.Who { return at(other, strangerV4(0)) })
	}
	if err := s.Unlock(ctx, at(victim, strangerV4(0))); err != nil {
		t.Fatal(err)
	}
	for _, sc := range scopes {
		b, _ := budget.FindScope(string(sc))
		if err := s.Charge(ctx, sc, at(victim, strangerV4(0))); err != nil {
			t.Errorf("unlock left %s locked: %v", sc, err)
		}
		// Keys that hold a network or a marker cannot be listed from the console and go
		// as a whole; an exact key (username, admin id) belongs to one admin.
		// A scope stored under the database scope of one that goes as a whole goes with it.
		exact := !b.HasNetwork() && b.Source != budget.Proof && !wholeStores[b.StoreScope()]
		if err := s.Charge(ctx, sc, at(other, strangerV4(0))); exact && !errors.Is(err, throttle.ErrTooMany) {
			t.Errorf("unlock of one admin cleared %s of another: %v", sc, err)
		}
	}
}

// TestAbuseALiveCookieCannotQueueLookups (primitives-r5-7): the route's class is charged
// to the cookie before the lookup and never given back, so one live cookie that is
// flooded from one address costs the pool at most the class's limit in lookups, however
// many requests it sends. Before, the lookup token of a live session was refunded and
// the class was charged only after the lookup: 5000 requests ran 5000 SessionByHash calls
// and 4700 of them were then refused with a 429.
func TestAbuseALiveCookieCannotQueueLookups(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, c := range ratelimit.Classes(svc) {
			if c.Key != ratelimit.BySession || ratelimit.ChargedByThePipeline(c.Name) {
				continue
			}
			t.Run(string(svc)+"/"+c.Name, func(t *testing.T) {
				h := newHarness(t, svc)
				max := c.Limits[0].Max
				ok := 0
				for i := 0; i < max+300; i++ {
					if h.post(c.Name, "203.0.113.7", "", "ok-live-flooded") == http.StatusNoContent {
						ok++
					}
				}
				if got := int(h.res.lookups.Load()); got > max {
					t.Fatalf("one live cookie caused %d lookups in a minute, want at most its class limit %d", got, max)
				}
				if ok != max {
					t.Fatalf("answered %d, want %d", ok, max)
				}
			})
		}
	}
}

// TestAbuseRotatingTheCookieDoesNotRefillASessionClass (tenant-r6-5): a client rotates its
// cookie whenever it likes (reauth, refresh, a new factor), and a class keyed on the cookie
// alone gave every new cookie a new bucket: 25 of 25 reauths in a minute where the class says
// 10. The class is also charged on the session id, which a rotation keeps, so a session that
// takes a new cookie on every request is answered exactly its class's limit. Every session
// class of both services is driven, and the control is another session, which keeps its own.
func TestAbuseRotatingTheCookieDoesNotRefillASessionClass(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, c := range ratelimit.Classes(svc) {
			if c.Key != ratelimit.BySession || ratelimit.ChargedByThePipeline(c.Name) {
				continue
			}
			t.Run(string(svc)+"/"+c.Name, func(t *testing.T) {
				h := newHarness(t, svc)
				max := c.Limits[0].Max
				ok := 0
				for i := 0; i < max+30; i++ {
					if h.post(c.Name, "203.0.113.7", "", fmt.Sprintf("ok-live-rotating~%d", i)) == http.StatusNoContent {
						ok++
					}
				}
				if ok != max {
					t.Fatalf("a session that rotated its cookie on every request was answered %d times, want its limit %d", ok, max)
				}
				if code := h.post(c.Name, "203.0.113.7", "", "ok-live-another~0"); code != http.StatusNoContent {
					t.Fatalf("another session got %d after the first one was refused", code)
				}
			})
		}
	}
}

// TestAbuseDeadCookiesDoNotRefuseLiveOnes is the abuse test of primitives-r6-5, and the rule it
// serves: nothing that is not proof of a live session may refuse one that is. An account holder
// who kept the cookies of his ended sessions floods them from one network FIRST, and then live
// sessions from the same /24 (IPv4) and the same /48 (IPv6) ask: every one must be answered. Round
// 5 charged a network bucket before every lookup, and this test sent the live sessions before the
// flood only, so it never saw 50 of 50 live cookies refused afterwards. The cost a flood of dead
// cookies can impose is one lookup each (they are remembered), and a repeat of the same cookie is
// no lookup at all.
func TestAbuseDeadCookiesDoNotRefuseLiveOnes(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for name, ip := range map[string]func(int) string{"v4": strangerV4, "v6": strangerV6} {
			t.Run(string(svc)+"/"+name, func(t *testing.T) {
				h := newHarness(t, svc)
				// The roomiest session class, so that only the network could refuse.
				var session string
				best := 0
				for _, c := range ratelimit.Classes(svc) {
					if c.Key == ratelimit.BySession && !ratelimit.ChargedByThePipeline(c.Name) && c.Limits[0].Max > best {
						session, best = c.Name, c.Limits[0].Max
					}
				}
				// Two dead cookies replayed 4 times a second for a minute, and 1000 more, each sent
				// several times: far more than any bucket of 240 a minute.
				before := h.res.lookups.Load()
				for i := 0; i < 3000; i++ {
					h.post(session, ip(i), "", fmt.Sprintf("ok-dead-kept-%d", i%1000))
				}
				if got := int(h.res.lookups.Load() - before); got > 1000 {
					t.Fatalf("1000 dead cookies, each sent three times, caused %d lookups, want at most 1000 (one each)", got)
				}
				// Now the live sessions of other tenants behind the same address group.
				for i := 0; i < 200; i++ {
					if code := h.post(session, ip(i), "", fmt.Sprintf("ok-live-nat-%d", i)); code != http.StatusNoContent {
						t.Fatalf("live session %d behind the flooded address group got %d, want 204", i, code)
					}
				}
			})
		}
	}
}

// TestAbuseManyMarkersFromOneNetwork (primitives-r5-8): a marker is free to mint (every
// login issues a new random one), so a source that sends a different marker with every
// request used to get a fresh proof bucket each time and never touched the network's.
// Now a marker's request is also charged to a network bucket of its own at
// ProofNetFactor times the limit: the rotating source meets that ceiling, and the plain
// network bucket that strangers fill is neither used nor emptied by it.
func TestAbuseManyMarkersFromOneNetwork(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, b := range budget.Of(budget.RateClass, budget.Service(svc)) {
			if b.Source != budget.Network || b.ProofPart != budget.PartMarker {
				continue
			}
			for name, ip := range map[string]func(int) string{"v4": strangerV4, "v6": strangerV6} {
				t.Run(string(svc)+"/"+b.Name+"/"+name, func(t *testing.T) {
					h := newHarness(t, svc)
					max := b.Limits[0].Max
					answered := 0
					for i := 0; i < max*ratelimit.ProofNetFactor+50; i++ {
						if h.post(b.Name, ip(i), fmt.Sprintf("minted-%d", i), "") == http.StatusNoContent {
							answered++
						}
					}
					if answered != max*ratelimit.ProofNetFactor {
						t.Fatalf("a source that rotates markers was answered %d times, want the network ceiling of %d", answered, max*ratelimit.ProofNetFactor)
					}
					// Room for the strangers' own bucket is untouched by it.
					plain := 0
					for i := 0; i < max+10; i++ {
						if h.post(b.Name, ip(i), "", "") == http.StatusNoContent {
							plain++
						}
					}
					if plain != max {
						t.Fatalf("requests with no marker got %d of their %d after the markers were refused", plain, max)
					}
				})
			}
		}
	}
}

// postFor is post with a device marker sealed for a named account.
func (h *harness) postFor(class, ip, marker, account string) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/c/"+class, nil)
	r.Host = "panel.test"
	r.RemoteAddr = hostPort(ip) + ":4000"
	r.Header.Set("X-Test-Marker", marker)
	r.Header.Set("X-Test-Subject", account)
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w.Code
}

// TestAbuseMarkersOfOneAccountDoNotRefuseAnother is the second half of primitives-r6-5 (the
// proof-network bucket, "pn"). Round 5 kept one bucket per network for every request that carries
// a marker, so about five markers minted by one account holder's logins filled it, and every
// returning browser of every other tenant behind the same carrier address was refused its login
// and refresh. The bucket is keyed on the network AND the account the marker was sealed for: the
// source that rotates the markers of one account meets that account's ceiling, and a marker of
// another account on the same /24 and /48 still gets its full budget afterwards. The order is the
// one the first version of the abuse test left out: the flood comes first.
func TestAbuseMarkersOfOneAccountDoNotRefuseAnother(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, b := range budget.Of(budget.RateClass, budget.Service(svc)) {
			if b.Source != budget.Network || b.ProofPart != budget.PartMarker {
				continue
			}
			for name, ip := range map[string]func(int) string{"v4": strangerV4, "v6": strangerV6} {
				t.Run(string(svc)+"/"+b.Name+"/"+name, func(t *testing.T) {
					h := newHarness(t, svc)
					max := b.Limits[0].Max
					for i := 0; i < max*ratelimit.ProofNetFactor*3; i++ {
						h.postFor(b.Name, ip(i), fmt.Sprintf("minted-%d", i), "the-attacker")
					}
					if code := h.postFor(b.Name, ip(1), "minted-again", "the-attacker"); code != http.StatusTooManyRequests {
						t.Fatalf("the account that rotates markers is still answered (%d): there is no ceiling", code)
					}
					for i := 0; i < max; i++ {
						if code := h.postFor(b.Name, ip(i), fmt.Sprintf("honest-%d", i), "an-honest-account"); code != http.StatusNoContent {
							t.Fatalf("marker %d of another account behind the same address group got %d after the flood", i, code)
						}
					}
				})
			}
		}
	}
}

// TestAbuseGateServesProofsBeforeStrangers is the abuse test of every gate row (admin-r5-9): the
// slots are held by strangers and a swarm of strangers keeps asking, and a request that carries
// a proof still gets a slot within one hold, while a stranger asking at the same moment is refused
// at once. A row without a lane says why, and the reason is shown; a row with one is driven.
func TestAbuseGateServesProofsBeforeStrangers(t *testing.T) {
	for _, g := range budget.Gates() {
		t.Run(string(g.Service)+"/"+g.Name, func(t *testing.T) {
			switch {
			case len(g.Proofs) == 0 && g.NoLane == "":
				t.Fatal("a gate with no proof lane and no reason")
			case len(g.Proofs) > 0 && g.NoLane != "":
				t.Fatal("a gate with a proof lane and a reason for having none")
			case len(g.Proofs) == 0:
				t.Logf("no lane: %s", g.NoLane)
				return
			}
			for _, p := range g.Proofs {
				if p != budget.PartMarker && p != budget.PartSession {
					t.Errorf("the lane takes %q, which is not a proof a service checks without the gate", p)
				}
			}
			gate := password.NewGate(2, 2*time.Second)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var strangers atomic.Int64
			for i := 0; i < 16; i++ { // more strangers than slots, for ever
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						default:
						}
						if rel, err := gate.Acquire(context.Background()); err == nil {
							strangers.Add(1)
							time.Sleep(4 * time.Millisecond)
							rel()
						}
					}
				}()
			}
			defer func() { close(stop); wg.Wait() }()
			for i := 0; i < 15; i++ {
				// The pressure is asserted before every probe, not slept for (round 16, tenant-r16-19): sixteen
				// strangers on two slots leave most of them in the queue, and a probe asked for while fewer than
				// half wait would run against an idle gate and pass with the lane removed.
				awaitGate(t, gate, "strangers to queue for the slots", func(_, plain int) bool { return plain >= 8 })
				before := strangers.Load()
				rel, err := gate.Acquire(password.Proved(context.Background()))
				if err != nil {
					t.Fatalf("a request with a proof was refused with strangers on the gate: %v", err)
				}
				// Counted in strangers served and not in time: with the lane about two (the slots
				// that were taken as it queued) go first, without it about sixteen.
				if over := strangers.Load() - before; over > 4 {
					t.Errorf("a request with a proof was served after %d strangers: it queued behind them", over)
				}
				rel()
			}
		})
	}
}

// The rows themselves: one per service, no duplicates.
func TestGateRowsAreOnePerService(t *testing.T) {
	seen := map[budget.Service]bool{}
	for _, g := range budget.Gates() {
		if seen[g.Service] {
			t.Errorf("two gates for %s", g.Service)
		}
		seen[g.Service] = true
	}
	if !seen[budget.Tenant] || !seen[budget.Admin] {
		t.Errorf("a service has no gate row: %v", seen)
	}
}

// TestAbuseCOneNetworkStayingPutDoesNotSpendTheSiblingScope is the third abuse test of the rule
// (round 6, admin-r6-4). A Narrow scope exists so that a stranger on the subject's network can
// spend that pair and nothing else; the subject-only scope beside it is what a spread guess is
// bounded by, and every browser without a proof shares it. Test B moves networks on every request;
// this one stays on a single address for far more than a window, at a rate no class would stop,
// and requires that the sibling scope never exceeds the narrow scope's own maximum: a request that
// the narrow pair has already refused must not be charged to the shared scope as well.
func TestAbuseCOneNetworkStayingPutDoesNotSpendTheSiblingScope(t *testing.T) {
	ctx := context.Background()
	entries := map[string]struct {
		sibling throttle.Scope
		hit     func(s *throttle.Service, ip netip.Addr) error
	}{
		"login_phone_net": {throttle.LoginPhone, func(s *throttle.Service, ip netip.Addr) error {
			return s.LoginHits(ctx, victim.Phone, ip)
		}},
		"admin_login": {throttle.AdminLoginUser, func(s *throttle.Service, ip netip.Addr) error {
			refused, err := s.AdminLoginHits(ctx, victim.Username, ip, "")
			if err == nil {
				err = refused
			}
			return err
		}},
	}
	seen := 0
	for _, b := range budget.All() {
		if b.Layer != budget.Throttle || !b.Narrow {
			continue
		}
		seen++
		e, ok := entries[b.Name]
		if !ok {
			t.Fatalf("no stay-on-one-network driver for the narrow scope %s", b.Name)
		}
		t.Run(b.Name, func(t *testing.T) {
			c := newCounters()
			s := throttle.NewFor(b.Service, c.hit, c.reset, fakeMAC)
			ip := netip.MustParseAddr(strangerV4(0))
			refusals := 0
			for i := 0; i < 400; i++ {
				if err := e.hit(s, ip); errors.Is(err, throttle.ErrTooMany) {
					refusals++
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if refusals == 0 {
				t.Fatalf("%s never refused one address that kept going", b.Name)
			}
			sib, _ := budget.FindScope(string(e.sibling))
			spent := 0
			for k, n := range c.n {
				if strings.HasPrefix(k, sib.StoreScope()+"|"+sib.Name+"\x00") {
					spent += n
				}
			}
			if spent > b.Max {
				t.Fatalf("one address spent %s %d times; the pair that is keyed on its network allows %d, and everything after that is refused before the shared scope",
					sib.Name, spent, b.Max)
			}
		})
	}
	if seen == 0 {
		t.Fatal("no narrow scope in the registry")
	}
}

// A lane that serves a proof which can be used again (a session, a device marker) says how it keeps one
// account from holding it: one hash per account at a time (password.ProvedAs), or the reason it does not.
// The behaviour is in internal/auth/password TestAProvedFloodFromOneAccountCannotKeepStrangersOut and in
// internal/api TestOneAccountWithManySessionsCannotStarveStrangers (round 7, tenant-r7-6).
func TestAGateLaneIsBoundedPerAccountOrSaysWhy(t *testing.T) {
	for _, g := range budget.Gates() {
		if len(g.Proofs) == 0 {
			continue
		}
		if g.PerSubject == (g.NoSubject != "") {
			t.Errorf("gate %s/%s has a lane and must say exactly one of PerSubject and NoSubject (PerSubject=%v, NoSubject=%q)", g.Service, g.Name, g.PerSubject, g.NoSubject)
		}
	}
}

// TestAbuseAGateLaneNeverOwnsTheGate is primitives-r7-4, generated for every gate row with a lane.
// The lane orders the waiters; a lane that holders of proofs can keep full for ever refuses every
// request without a proof, in every tenant, with 503 (the proofs are free to use again, and a
// subject bound only stops one account: as many accounts as the gate has slots keep the queue
// non-empty). Here more subjects than slots (or, for a lane that says NoSubject, plain proofs)
// loop hashes the whole time, and requests with no proof must still be served, while the proofs
// keep being served too. The gate sizes are those of the services' defaults.
func TestAbuseAGateLaneNeverOwnsTheGate(t *testing.T) {
	sizes := map[budget.Service]int{budget.Admin: 1, budget.Tenant: 2}
	for _, g := range budget.Gates() {
		if len(g.Proofs) == 0 {
			continue
		}
		slots, ok := sizes[g.Service]
		if !ok {
			t.Fatalf("gate %s/%s has no size in this test", g.Service, g.Name)
		}
		t.Run(string(g.Service)+"/"+g.Name, func(t *testing.T) {
			gate := password.NewGate(slots, 2*time.Second)
			stop := make(chan struct{})
			var wg sync.WaitGroup
			var proofs atomic.Int64
			for subject := 0; subject < slots+3; subject++ {
				for s := 0; s < 10; s++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						ctx := password.Proved(context.Background())
						if g.PerSubject {
							ctx = password.ProvedAs(context.Background(), "subject-"+strconv.Itoa(subject))
						}
						for {
							select {
							case <-stop:
								return
							default:
							}
							rel, err := gate.Acquire(ctx)
							if err != nil {
								time.Sleep(time.Millisecond)
								continue
							}
							proofs.Add(1)
							time.Sleep(3 * time.Millisecond)
							rel()
						}
					}()
				}
			}
			defer func() { close(stop); wg.Wait() }()
			served := 0
			for i := 0; i < 30; i++ {
				// Asked for only while proved requests wait in the lane: the pressure is asserted, and a run that
				// could not build it fails (round 16, tenant-r16-19). A probe served against an empty lane proves nothing.
				awaitGate(t, gate, "proved requests to queue in the lane", func(proved, _ int) bool { return proved >= 1 })
				if rel, err := gate.Acquire(context.Background()); err == nil {
					served++
					rel()
				}
			}
			if served < 15 {
				t.Errorf("requests with no proof were served %d of 30 times while %d subjects held the lane: the lane owns the gate", served, slots+3)
			}
			if proofs.Load() < 30 {
				t.Errorf("the proofs were served %d times: strangers must not push them out", proofs.Load())
			}
		})
	}
}

// issuerOf is the session a stub cookie opens: the text after "@" when the cookie names one
// ("ok-dead-7@s1"), otherwise a session of its own (the cookie without its rotation suffix), so
// the older tests, which never cared, see each cookie as a different session.
func issuerOf(cookie string) string {
	if _, acct, ok := strings.Cut(cookie, "@"); ok {
		return acct
	}
	base, _, _ := strings.Cut(cookie, "~")
	return "sess-" + base
}

// TestAbuseDeadCookiesBeyondTheSetShareTheirSessionsBudget is primitives-r7-6 and tenant-r8-3, for both services. The
// dead set forgets the oldest mark at its capacity, so a holder of more dead cookies than that who
// sends them round and round found each forgotten when it came back and cost a lookup every time,
// bounded by nothing (65,537 distinct dead cookies sent three times were 196,611 lookups against the
// 65,537 the spec claimed). The cost is charged to the session the cookie opens, read from the
// body the tag covers, so no eviction reopens it. Here the set holds eight and one session has four
// hundred dead cookies and sends them round and round from every network it can think of: the lookups
// are bounded by the class's own limit, however many cookies and however many rounds, and a live cookie of
// another session is served throughout. The holder's own session pays the price (declared, spec 14.1). That
// the other session may belong to the SAME account is proved through the real resolver and the real
// session rows by internal/api TestDeadCookiesOfOneSessionCannotRefuseTheOwnersOtherSessions (tenant-r8-3):
// this stub has no accounts, so it can only say that a session's budget is its own.
func TestAbuseDeadCookiesBeyondTheSetShareTheirSessionsBudget(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		t.Run(string(svc), func(t *testing.T) {
			h := newHarnessCap(t, svc, 8)
			miss, ok := ratelimit.Lookup(svc, ratelimit.SessionMiss)
			if !ok {
				t.Fatal("the service has no session-miss class")
			}
			// The roomiest session class, so that only the miss budget and the lookup budgets can refuse.
			var session string
			best := 0
			for _, c := range ratelimit.Classes(svc) {
				if c.Key == ratelimit.BySession && !ratelimit.ChargedByThePipeline(c.Name) && c.Limits[0].Max > best {
					session, best = c.Name, c.Limits[0].Max
				}
			}
			const cookies, rounds = 400, 3
			before := h.res.lookups.Load()
			for r := 0; r < rounds; r++ {
				for i := 0; i < cookies; i++ {
					h.post(session, away(r*cookies+i), "", fmt.Sprintf("ok-dead-%d@s1", i))
				}
			}
			got := h.res.lookups.Load() - before
			if got > int64(miss.Limits[0].Max) {
				t.Errorf("%d dead cookies of one account sent %d times caused %d lookups; its budget is %d", cookies, rounds, got, miss.Limits[0].Max)
			}
			if got < int64(miss.Limits[0].Max) {
				t.Errorf("only %d lookups: the test did not reach the budget (%d), so it proves nothing", got, miss.Limits[0].Max)
			}
			if code := h.post(session, strangerV4(1), "", "ok-live@s2"); code != http.StatusNoContent {
				t.Errorf("the live cookie of another session got %d while s1 spent its budget", code)
			}
		})
	}
}

// awaitGate waits, on a bounded condition and not a sleep, until the gate's queues show the pressure a test
// needs, and fails the test when they never do: a run that could not build its pressure must not pass against an
// idle gate (round 16, tenant-r16-19). The bound is only reached by a hung test.
func awaitGate(t *testing.T, g *password.Gate, what string, cond func(proved, plain int) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if proved, plain := g.Waiting(); cond(proved, plain) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Microsecond)
	}
}
