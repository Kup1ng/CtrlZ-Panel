package api

import "testing"

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
