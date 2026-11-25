package api

import (
	"fmt"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/bulkgate"
)

// Review round 3 of package B3 (routes and jobs), one test per finding that changed behaviour.

// TestADisableUntilOfYear1IsInPastNotAbsent: a moment that decodes to the zero time was read as "not sent", so it gave
// /for required alone and was swallowed by a given "for" (p2-B3-r3-1).
func TestADisableUntilOfYear1IsInPastNotAbsent(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	p := a.mustProfile("Disable", "custom")
	path := "/profiles/" + p.ID.String() + "/disabled"
	zero := "0001-01-01T00:00:00Z"
	var fl fieldList
	a.do("PUT", path, map[string]any{"until": zero}).want(422, "validation_failed").json(&fl)
	if !fl.has("/until", "in_past") {
		t.Errorf("until alone: %+v, want /until in_past", fl.Fields)
	}
	fl = fieldList{}
	a.do("PUT", path, map[string]any{"for": "1h", "until": zero}).want(422, "validation_failed").json(&fl)
	if !fl.has("/until", "invalid") {
		t.Errorf("for and until: %+v, want /until invalid", fl.Fields)
	}
}

// TestABusyRuleCreateDoesNotRefillTheDayBudget: POST /profiles/{id}/rules is gated by its body limit but is of the
// user-write class and never pays the bulk-write day budget, so its 503 must not give a token back (p2-B3-r3-3).
func TestABusyRuleCreateDoesNotRefillTheDayBudget(t *testing.T) {
	f := newFrig(t, frigOpts{})
	gate := bulkgate.New(7<<20, 7<<20)
	f.deps.BulkGate = gate
	f.setLimiter(f.deps.Limiter)
	A := f.env.A
	var sessions []*client
	for i := 0; i < 21; i++ {
		sessions = append(sessions, f.makeSession(A.Tenant, A.User))
	}
	p := sessions[20].mustProfile("Busy", "custom")
	bad := map[string]any{"document": b64(`{}`)}
	// Spend the 200 of the day.
	for i := 0; i < 200; i++ {
		sessions[i%20].do("POST", "/profiles:import", bad, idem(fmt.Sprintf("spend-%d", i))).want(422, "validation_failed")
	}
	hold, ok := gate.Acquire(A.Tenant.String(), 7<<20)
	if !ok {
		t.Fatal("the test could not take its own share")
	}
	for i := 0; i < 5; i++ {
		sessions[20].post("/profiles/"+p.ID.String()+"/rules", map[string]any{"patterns": []string{"busy.example"}, "action": "block"}).want(503, "server_busy")
	}
	hold()
	sessions[20].do("POST", "/profiles:import", bad, idem("after-busy")).want(429, "rate_limited")
}
