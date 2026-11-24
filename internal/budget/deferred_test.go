package budget_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/budget"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// A Network rate class that a request with a proof of its own can be let through, and that only the
// handler can recognise, is DEFERRED: the pipeline charges it and hands the refusal over as a value
// (round 7, admin-r7-1). These tests hold the three halves of that rule: what may be deferred, that the
// route asks for the value, and that a flood from the network refuses everyone but the declared request.

func TestOnlyANetworkRateClassIsDeferredAndItSaysWhy(t *testing.T) {
	for _, b := range budget.All() {
		if b.Deferred == "" {
			continue
		}
		if b.Layer != budget.RateClass || b.Source != budget.Network {
			t.Errorf("%s: only a Network rate class is deferred (a scope already returns its refusal as a value)", b.Name)
		}
		if b.HeldProof == "" && b.DeferredGate == "" {
			t.Errorf("%s: say which function tells the declared request from the rest (DeferredGate)", b.Name)
		}
		if b.HeldProof == "" && b.DeferredBound == "" {
			t.Errorf("%s: say which bound a request that passed the gate must take before it reads (DeferredBound)", b.Name)
		}
		if len(b.Deferred) < 40 {
			t.Errorf("%s: Deferred is the reason, say what the handler lets through", b.Name)
		}
	}
	if b, ok := budget.Find(budget.RateClass, budget.Admin, "admin-login"); !ok || b.Deferred == "" {
		t.Error("admin-login must stay deferred: its first login has no marker and the console password must get past a neighbour's flood")
	}
}

// A deferred class that no handler asks for would never refuse anything: the pipeline hands the value
// over and answers nothing. Every operation of such a class must reach httpx.DeferredRefusal.
func TestADeferredClassIsAnsweredByItsHandler(t *testing.T) {
	asked := 0
	for svc, ops := range serviceCharges(t) {
		dir := filepath.Join("..", "api")
		if svc == budget.Admin {
			dir = filepath.Join("..", "adminapi")
		}
		pc := parsePkg(t, dir)
		for _, oc := range ops {
			c, ok := ratelimit.Lookup(ratelimit.Service(svc), oc.op.Rate)
			if !ok || !c.Deferred {
				continue
			}
			if !reachedCalls(pc, capitalize(oc.op.ID))["DeferredRefusal"] {
				t.Errorf("%s uses the deferred class %s and its handler never calls httpx.DeferredRefusal: the class would refuse nobody", oc.op.ID, oc.op.Rate)
				continue
			}
			asked++
		}
	}
	if asked == 0 {
		t.Error("no operation uses a deferred class: the test proves nothing")
	}
}

// The declared exception of the abuse suite (rule budget-keying): strangers on one network fill the class,
// the next stranger is refused by the handler with the class's 429, and the one request the handler lets
// through still gets in from that network.
func TestAbuseADeferredClassRefusesStrangersAndLetsTheDeclaredRequestThrough(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, b := range budget.Of(budget.RateClass, budget.Service(svc)) {
			// A class with HeldProof lets through no declared request of its own: the request it lets through is a
			// marker that holds, driven by TestAbuseAHeldProofStandsInForTheNetworkOnlyWhereItHolds.
			if b.Deferred == "" || b.HeldProof != "" {
				continue
			}
			t.Run(string(svc)+"/"+b.Name, func(t *testing.T) {
				h := newHarness(t, svc)
				max := b.Limits[0].Max
				for i := 0; i < max; i++ {
					if code := h.post(b.Name, strangerV4(i), "", ""); code != http.StatusNoContent {
						t.Fatalf("stranger %d: %d", i, code)
					}
				}
				if code := h.post(b.Name, strangerV4(500), "", ""); code != http.StatusTooManyRequests {
					t.Fatalf("a stranger after the class was full: %d, want 429 from the handler", code)
				}
				r := httptest.NewRequest(http.MethodPost, "/api/v1/c/"+b.Name, nil)
				r.Host = "panel.test"
				r.RemoteAddr = hostPort(strangerV4(501)) + ":4000"
				r.Header.Set("X-Test-Exempt", "console")
				w := httptest.NewRecorder()
				h.h.ServeHTTP(w, r)
				if w.Code != http.StatusNoContent {
					t.Fatalf("the declared request from a network that strangers filled: %d", w.Code)
				}
			})
		}
	}
}

// postHeld is a request carrying a device marker sealed for account, to a route whose handler found that
// the marker holds for the account the request is about (X-Test-Held: it asks httpx.HeldProofHolds).
// With held false the handler finds it does not, and answers what the plain bucket said.
func (h *harness) postHeld(class, ip, marker, account string, held bool) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/c/"+class, nil)
	r.Host = "panel.test"
	r.RemoteAddr = hostPort(ip) + ":4000"
	r.Header.Set("X-Test-Marker", marker)
	r.Header.Set("X-Test-Subject", account)
	if held {
		r.Header.Set("X-Test-Held", "1")
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w.Code
}

// TestAHeldProofClassIsAnsweredByItsHandler: a class with HeldProof is Deferred, and every operation of
// it reaches httpx.HeldProofHolds, or a marker that holds could never take the network's place (and the
// class would refuse the owner on his known device whenever strangers fill the /24).
func TestAHeldProofClassIsAnsweredByItsHandler(t *testing.T) {
	asked := 0
	for svc, ops := range serviceCharges(t) {
		dir := filepath.Join("..", "api")
		if svc == budget.Admin {
			dir = filepath.Join("..", "adminapi")
		}
		pc := parsePkg(t, dir)
		for _, oc := range ops {
			b, ok := budget.Find(budget.RateClass, svc, oc.op.Rate)
			if !ok || b.HeldProof == "" {
				continue
			}
			if !reachedCalls(pc, capitalize(oc.op.ID))["HeldProofHolds"] {
				t.Errorf("%s uses the class %s, which a marker that holds can stand in for, and its handler never calls httpx.HeldProofHolds", oc.op.ID, oc.op.Rate)
				continue
			}
			asked++
		}
	}
	if asked == 0 {
		t.Error("no operation uses a class with HeldProof: the test proves nothing")
	}
}

// TestAbuseAHeldProofStandsInForTheNetworkOnlyWhereItHolds is the abuse test of every HeldProof row
// (tenant-r8-4), flood first. Strangers on one /24 (and /64) fill the plain bucket. Then:
//   - a marker that does not hold for the account asked about gets the plain bucket's answer, however
//     many such markers there are (a marker is free to mint for any account);
//   - a marker that holds gets through on its own buckets, exactly as often as the class's limit says,
//     and is refused after that (the proof carries no more room than the network would have given);
//   - the plain bucket is not spent by it, on a network where it was not already full: the strangers
//     there still have all of theirs afterwards;
//   - a source that rotates held markers of ONE account meets the proof-network ceiling, and a held
//     marker of another account on the same network is still served.
func TestAbuseAHeldProofStandsInForTheNetworkOnlyWhereItHolds(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, b := range budget.Of(budget.RateClass, budget.Service(svc)) {
			if b.HeldProof == "" {
				continue
			}
			for name, ip := range map[string]func(int) string{"v4": strangerV4, "v6": strangerV6} {
				t.Run(string(svc)+"/"+b.Name+"/"+name, func(t *testing.T) {
					max := b.Limits[0].Max

					// The flood first: the plain bucket is full.
					h := newHarness(t, svc)
					if got := floodUntilRefused(t, h, b.Name, max*ratelimit.WideFactor, ip); got != max {
						t.Fatalf("%d strangers answered, want %d", got, max)
					}
					for i := 0; i < max*ratelimit.ProofNetFactor; i++ {
						if code := h.postHeld(b.Name, ip(600+i), fmt.Sprintf("minted-%d", i), "the-attacker", false); code != http.StatusTooManyRequests {
							t.Fatalf("a marker that holds for no account asked about got %d from a network strangers filled", code)
						}
					}
					answered := 0
					for i := 0; i < max+10; i++ {
						if h.postHeld(b.Name, ip(700+i), "owner-marker", "the-owner", true) == http.StatusNoContent {
							answered++
						}
					}
					if answered != max {
						t.Fatalf("a marker that holds got %d answers from a flooded network, want its own %d", answered, max)
					}

					// A network that is not full: a held marker does not spend what strangers have.
					h = newHarness(t, svc)
					for i := 0; i < max; i++ {
						if code := h.postHeld(b.Name, ip(i), "owner-marker", "the-owner", true); code != http.StatusNoContent {
							t.Fatalf("held request %d: %d", i, code)
						}
					}
					if got := floodUntilRefused(t, h, b.Name, max*ratelimit.WideFactor, ip); got != max {
						t.Fatalf("strangers got %d of their %d after a marker that holds was served: it spent the plain bucket", got, max)
					}

					// A source that rotates held markers of one account meets the ceiling; another account is served.
					h = newHarness(t, svc)
					rotated := 0
					for i := 0; i < max*ratelimit.ProofNetFactor+50; i++ {
						if h.postHeld(b.Name, ip(i), fmt.Sprintf("minted-%d", i), "the-attacker", true) == http.StatusNoContent {
							rotated++
						}
					}
					if rotated != max*ratelimit.ProofNetFactor {
						t.Fatalf("a source that rotates held markers was answered %d times, want the ceiling of %d", rotated, max*ratelimit.ProofNetFactor)
					}
					for i := 0; i < max; i++ {
						if code := h.postHeld(b.Name, ip(i), fmt.Sprintf("honest-%d", i), "an-honest-account", true); code != http.StatusNoContent {
							t.Fatalf("a held marker of another account got %d behind the same address group", code)
						}
					}
				})
			}
		}
	}
}

// postInvite is a request with no marker that carries an invite the handler read: live says it is live
// (X-Test-Invite: live-<id>, the handler asks httpx.InviteProofHolds), otherwise it is a token that is not.
func (h *harness) postInvite(class, ip, id string, live bool) int {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/c/"+class, nil)
	r.Host = "panel.test"
	r.RemoteAddr = hostPort(ip) + ":4000"
	if live {
		r.Header.Set("X-Test-Invite", "live-"+id)
	} else {
		r.Header.Set("X-Test-Invite", "junk-"+id)
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w.Code
}

// TestAHeldInviteClassIsAnsweredByItsHandler: a class with HeldInvite is answered by a handler that asks
// httpx.InviteProofHolds, or a live invite could never take the network's place (tenant-r9-1).
func TestAHeldInviteClassIsAnsweredByItsHandler(t *testing.T) {
	asked := 0
	for svc, ops := range serviceCharges(t) {
		dir := filepath.Join("..", "api")
		if svc == budget.Admin {
			dir = filepath.Join("..", "adminapi")
		}
		pc := parsePkg(t, dir)
		for _, oc := range ops {
			b, ok := budget.Find(budget.RateClass, svc, oc.op.Rate)
			if !ok || !b.HeldInvite {
				continue
			}
			if !reachedCalls(pc, capitalize(oc.op.ID))["InviteProofHolds"] {
				t.Errorf("%s uses the class %s, which a live invite can stand in for, and its handler never calls httpx.InviteProofHolds", oc.op.ID, oc.op.Rate)
				continue
			}
			asked++
		}
	}
	if asked == 0 {
		t.Error("no operation uses a class with HeldInvite: the test proves nothing")
	}
}

// TestAbuseALiveInviteStandsInForTheNetwork is the abuse test of every HeldInvite row (tenant-r9-1), flood
// first. Strangers on one /24 (and /64) fill the plain bucket. Then:
//   - tokens that are not live get the plain bucket's answer, however many there are;
//   - a live invite gets through on its own buckets exactly as often as the class's limit says, and is
//     refused after that (the invite carries no more room than the network would have given);
//   - another live invite on the same flooded network is served: invites share nothing;
//   - a network that was not full keeps all of its bucket for strangers after an invite was served;
//   - a source that moves networks with one invite meets the proof-network ceiling.
func TestAbuseALiveInviteStandsInForTheNetwork(t *testing.T) {
	for _, svc := range []ratelimit.Service{ratelimit.Tenant, ratelimit.Admin} {
		for _, b := range budget.Of(budget.RateClass, budget.Service(svc)) {
			if !b.HeldInvite {
				continue
			}
			for name, ip := range map[string]func(int) string{"v4": strangerV4, "v6": strangerV6} {
				t.Run(string(svc)+"/"+b.Name+"/"+name, func(t *testing.T) {
					max := b.Limits[0].Max

					h := newHarness(t, svc)
					if got := floodUntilRefused(t, h, b.Name, max*ratelimit.WideFactor, ip); got != max {
						t.Fatalf("%d strangers answered, want %d", got, max)
					}
					for i := 0; i < 50; i++ {
						if code := h.postInvite(b.Name, ip(600+i), fmt.Sprintf("%d", i), false); code != http.StatusTooManyRequests {
							t.Fatalf("a token that is not live got %d from a network strangers filled", code)
						}
					}
					answered := 0
					for i := 0; i < max+10; i++ {
						if h.postInvite(b.Name, ip(700+i), "one", true) == http.StatusNoContent {
							answered++
						}
					}
					if answered != max {
						t.Fatalf("a live invite got %d answers from a flooded network, want its own %d", answered, max)
					}
					if code := h.postInvite(b.Name, ip(800), "two", true); code != http.StatusNoContent {
						t.Fatalf("another live invite got %d behind the same flooded network", code)
					}

					// A network that is not full: a live invite does not spend what strangers have.
					h = newHarness(t, svc)
					for i := 0; i < max; i++ {
						if code := h.postInvite(b.Name, ip(i), "one", true); code != http.StatusNoContent {
							t.Fatalf("invite request %d: %d", i, code)
						}
					}
					if got := floodUntilRefused(t, h, b.Name, max*ratelimit.WideFactor, ip); got != max {
						t.Fatalf("strangers got %d of their %d after a live invite was served: it spent the plain bucket", got, max)
					}

					// One invite from many networks meets the ceiling of the class.
					h = newHarness(t, svc)
					moved := 0
					for i := 0; i < max*ratelimit.ProofNetFactor+50; i++ {
						if h.postInvite(b.Name, ip(i), "one", true) == http.StatusNoContent {
							moved++
						}
					}
					// The proof's own bucket (the limit) is the ceiling an invite has everywhere.
					if moved != max {
						t.Fatalf("one invite was answered %d times in a minute, want %d", moved, max)
					}
				})
			}
		}
	}
}
