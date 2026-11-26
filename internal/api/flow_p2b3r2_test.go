package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Review round 2 of package B3 (routes and jobs), one test per finding that changed behaviour.

// TestAnExpiryOfYear1IsInPastNotNoExpiry: a moment that decodes to the zero time was read as "not sent", so a rule asked
// to expire long ago came back permanent (p2-B3-r2-1).
func TestAnExpiryOfYear1IsInPastNotNoExpiry(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	p := a.mustProfile("Expiry", "custom")
	base := "/profiles/" + p.ID.String()
	zero := "0001-01-01T00:00:00Z"
	var fl fieldList
	a.post(base+"/rules", map[string]any{"patterns": []string{"ads.example"}, "action": "block", "expires_at": zero}).want(422, "validation_failed").json(&fl)
	if !fl.has("/expires_at", "in_past") {
		t.Errorf("create: %+v, want /expires_at in_past", fl.Fields)
	}
	// A rule with a real expiry keeps it under a PATCH of year 1, which is refused and clears nothing.
	var made struct {
		Rules []struct {
			ID uuid.UUID `json:"id"`
		} `json:"rules"`
	}
	a.post(base+"/rules", map[string]any{"patterns": []string{"keep.example"}, "action": "block", "expires_in": "1w"}).want(201, "").json(&made)
	rule := base + "/rules/" + made.Rules[0].ID.String()
	a.do("PATCH", rule, map[string]any{"expires_at": zero}).want(422, "validation_failed")
	var n int
	noExpiry := func() int {
		f.env.Scan(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND expires_at IS NULL`, []any{A.Tenant, p.ID}, &n)
		return n
	}
	if got := noExpiry(); got != 0 {
		t.Errorf("%d rules have no expiry after a refused year-1 expiry", got)
	}
	// A group Edit is an item write too.
	r := a.do("POST", base+"/rules:batch", map[string]any{"op": "edit", "ids": []uuid.UUID{made.Rules[0].ID}, "set": map[string]any{"expires_at": zero}}, idem("exp-1"))
	if r.Code == 200 && !strings.Contains(string(r.Body), "failed") && !strings.Contains(string(r.Body), "in_past") {
		t.Errorf("a group edit with a year-1 expiry was accepted: %d %s", r.Code, r.Body)
	}
	if got := noExpiry(); got != 0 {
		t.Errorf("%d rules lost their expiry through a group edit", got)
	}
	// A document keeps a past moment (an export with expired rules imports again): the rule is not permanent.
	doc := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Old","rules":[{"pattern":"old.example","action":"block","expires_at":"` + zero + `"}]}`
	var created struct {
		Profile pProfile `json:"profile"`
	}
	a.do("POST", "/profiles:import", map[string]any{"document": b64(doc)}, idem("exp-2")).want(201, "").json(&created)
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND expires_at IS NULL`, []any{A.Tenant, created.Profile.ID}, &n)
	if n != 0 {
		t.Errorf("an imported rule of year 1 is permanent")
	}
}

// TestServicesBatchDeleteRefusesTheSameSlugTwice: as the set op does (p2-B3-r2-2).
func TestServicesBatchDeleteRefusesTheSameSlugTwice(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	p := a.mustProfile("Svc", "custom")
	var fl fieldList
	a.post("/profiles/"+p.ID.String()+"/services:batch", map[string]any{"op": "delete", "slugs": []string{"example", "example"}}).want(422, "validation_failed").json(&fl)
	if !fl.has("/slugs/1", "duplicate") {
		t.Errorf("fields %+v, want /slugs/1 duplicate", fl.Fields)
	}
}

// TestASelectorAboveALoweredLimitIsRefusedAtOnce: the count at queue time reaches the tenant's own limit, so a limit
// above the job threshold is seen exceeded and the request does not hold the job slot to fail (p2-B3-r2-3).
func TestASelectorAboveALoweredLimitIsRefusedAtOnce(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`)
	p := a.mustProfile("Sel", "custom")
	base := "/profiles/" + p.ID.String()
	seedRules(a, base, 1100)
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = 1050 WHERE tenant_id = $1`, A.Tenant)
	var fl fieldList
	a.do("POST", base+"/rules:batch", map[string]any{"op": "delete", "selector": map[string]any{}}, idem("sel-1")).want(422, "validation_failed").json(&fl)
	if !fl.has("max_rules_per_request", "exceeded") {
		t.Errorf("fields %+v", fl.Fields)
	}
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.batch_jobs WHERE tenant_id = $1`, []any{A.Tenant}, &n)
	if n != 0 {
		t.Errorf("%d jobs queued for a request above the limit", n)
	}
}

// TestUnlockAttemptsThatEndIn409AreAudited: every attempt on an existing profile of the tenant leaves a row (spec 7.2,
// p2-B3-r2-4).
func TestUnlockAttemptsThatEndIn409AreAudited(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	p := a.mustProfile("Unlock", "custom")
	base := "/profiles/" + p.ID.String()
	failed := func() int {
		var n int
		f.env.Scan(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'profile.unlock_failed'`, []any{A.Tenant}, &n)
		return n
	}
	a.post(base+"/unlock", map[string]any{"password": "right-one"}).want(409, "conflict")
	if n := failed(); n != 1 {
		t.Fatalf("an unlock of a profile that is not locked left %d rows, want 1", n)
	}
	// A profile of another tenant leaves nothing in this one's log, and nothing in the other's.
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	b.post(base+"/unlock", map[string]any{"password": "right-one"}).want(404, "not_found")
	if n := failed(); n != 1 {
		t.Fatalf("an unlock of an id that is not the tenant's wrote a row: %d", n)
	}
	var nb int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE tenant_id = $1 AND action = 'profile.unlock_failed'`, []any{f.env.B.Tenant}, &nb)
	if nb != 0 {
		t.Fatalf("tenant B's log holds %d rows of an unlock that found nothing", nb)
	}
}

// TestAJobShowsProfileIDOnlyForTheProfileItMade: profile_id is the new profile of a finished Import or Duplicate, and is
// absent for a rules_batch or an upload job, whose row holds the path profile (p2-B3-r2-5).
func TestAJobShowsProfileIDOnlyForTheProfileItMade(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `DELETE FROM ctrlz.job_outbox`)
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`)
	p := a.mustProfile("Jobs", "custom")
	base := "/profiles/" + p.ID.String()
	seedRules(a, base, 1100)
	var job struct {
		ID        uuid.UUID `json:"id"`
		Kind      string    `json:"kind"`
		ProfileID *string   `json:"profile_id"`
	}
	a.do("POST", base+"/rules:batch", map[string]any{"op": "delete", "selector": map[string]any{}}, idem("job-1")).want(202, "").json(&job)
	if job.Kind != "rules_batch" || job.ProfileID != nil {
		t.Errorf("queued rules_batch job: %+v", job)
	}
	f.env.Exec(t, `UPDATE ctrlz.batch_jobs SET state = 'done' WHERE id = $1`, job.ID)
	job.ProfileID = nil
	a.get("/jobs/"+job.ID.String()).want(200, "").json(&job)
	if job.ProfileID != nil {
		t.Errorf("a done rules_batch job names profile %s", *job.ProfileID)
	}
}

// TestADocumentOfManyBadRulesIsAnsweredWithAtMost100Problems: the check of a document stops at 100 problems and does not
// build the error tree of every rule (p2-B3-r2-6).
func TestADocumentOfManyBadRulesIsAnsweredWithAtMost100Problems(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	rs := make([]string, 5000)
	for i := range rs {
		rs[i] = `{}`
	}
	doc := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Bad","rules":[` + strings.Join(rs, ",") + `]}`
	var fl fieldList
	a.do("POST", "/profiles:import", map[string]any{"document": b64(doc)}, idem("bad-1")).want(422, "validation_failed").json(&fl)
	if len(fl.Fields) != 100 {
		t.Fatalf("%d problems, want 100", len(fl.Fields))
	}
	// In document order: the first rules, each missing its members.
	if !fl.has("/rules/0", "required") || !fl.has("/rules/99", "required") {
		t.Errorf("fields %+v", fl.Fields[:4])
	}
	if fl.has("/rules/100", "required") {
		t.Errorf("a field past the first 100 is answered")
	}
}
