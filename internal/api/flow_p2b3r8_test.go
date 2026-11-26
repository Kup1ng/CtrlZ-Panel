package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
)

// TestExportsPayTheTenantsDayBudget: the two exports and Duplicate hold the export pool while they build, and a loop of
// exports cost a tenant nothing, so two tenants could keep the pool full (p2-B3-r8-1). Export and Export Rules are of the
// bulk-write class now: 200 a day per tenant, whatever the sessions, and another tenant has its own.
func TestExportsPayTheTenantsDayBudget(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	var sessions []*client
	for i := 0; i < 21; i++ {
		sessions = append(sessions, f.makeSession(A.Tenant, A.User))
	}
	p := sessions[0].mustProfile("Exp", "custom")
	path := "/profiles/" + p.ID.String() + "/export"
	for i := 0; i < 200; i++ {
		sessions[i%20].get(path).want(200, "")
	}
	sessions[20].get(path).want(429, "rate_limited")
	// The folder export shares the budget.
	sessions[20].get("/profiles/"+p.ID.String()+"/folders/00000000-0000-4000-8000-000000000001/export").want(429, "rate_limited")
	// Another tenant has its own budget, and cannot read the first tenant's profile.
	b := f.makeSession(B.Tenant, B.User)
	b.get(path).want(404, "not_found")
}

// TestAPlaceRefusalSpendsNoDayToken: the day token is paid once, after the place, so a refusal for a place that is taken
// spends none of it, however many times a victim's client retries (spec 6.5, Refusals and tokens).
func TestAPlaceRefusalSpendsNoDayToken(t *testing.T) {
	f := newFrig(t, frigOpts{})
	adm := f.withAdmission()
	A := f.env.A
	var sessions []*client
	for i := 0; i < 26; i++ {
		sessions = append(sessions, f.makeSession(A.Tenant, A.User))
	}
	p := sessions[0].mustProfile("Busy", "custom")
	path := "/profiles/" + p.ID.String() + "/export"
	hold, err := adm.Place(A.Tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250; i++ {
		sessions[i%26].get(path).want(503, "server_busy")
	}
	hold()
	f.ck.add(time.Minute) // the per-session bucket of bulk-write: 10 a minute
	// 250 refusals later the tenant still has all of its 200 a day.
	for i := 0; i < 200; i++ {
		sessions[i%20].get(path).want(200, "")
	}
	sessions[20].get(path).want(429, "rate_limited")
}

// TestDocValuesHoldsAMaximalDocument: the cap of the scanner is derived from the schema, not guessed: a legal document of
// the most values the schema allows, every closing delimiter counted, passes it (p2-B3-r8-2).
func TestDocValuesHoldsAMaximalDocument(t *testing.T) {
	v, err := httpx.NewValidator(api.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	budget := v.DocumentValueBudget("ProfileDocument")
	if budget < 0 || int64(profiles.DocValues) <= budget {
		t.Fatalf("DocValues is %d, the schema allows a document of %d values", profiles.DocValues, budget)
	}
	tgt := `{"kind":"location","location":{"country":"US","city":"c","label":"l"},"ipv4":"1.1.1.1","ipv6":"::1","host":"h.example"}`
	rep := func(one string, n int) string {
		return "[" + strings.TrimSuffix(strings.Repeat(one+",", n), ",") + "]"
	}
	rule := fmt.Sprintf(`{"pattern":"a.example","folder":"f1","action":"redirect","target":%s,"enabled":true,"expires_at":"2030-01-01T00:00:00Z","comment":"c"}`, tgt)
	svc := fmt.Sprintf(`{"slug":"a","enabled":true,"action":"redirect","target":%s}`, tgt)
	doc := `{"format":"ctrlz-profile","version":1,"name":"x","kind":"custom","filters":` + rep(`{"id":"a","enabled":true,"mode":"m"}`, 1000) +
		`,"services":` + rep(svc, 5000) + `,"folders":` + rep(fmt.Sprintf(`{"ref":"f1","name":"n","kind":"standard","action":"redirect","target":%s}`, tgt), 500) +
		`,"rules":` + rep(rule, 10000) + `}`
	if f := profiles.ScanJSON([]byte(doc)); f != nil {
		t.Fatalf("a document at the schema's maximum is refused by the scanner: %+v", f)
	}
}
