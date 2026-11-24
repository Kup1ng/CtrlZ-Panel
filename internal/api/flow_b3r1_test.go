package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
)

// Review round 1 of package B3 (routes and jobs): what the first round found, as tests that fail without the fix.

// seedRules gives a profile n rules, in requests of 500 so that no request is itself a job.
func seedRules(a *client, base string, n int) {
	a.f.t.Helper()
	for done := 0; done < n; {
		k := min(500, n-done)
		ps := make([]string, k)
		for i := range ps {
			ps[i] = fmt.Sprintf("r%d.example", done+i)
		}
		a.post(base+"/rules", map[string]any{"patterns": ps, "action": "block"}).want(201, "")
		done += k
	}
}

func uuids(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = uuid.NewString()
	}
	return out
}

// TestARulesDocumentHasNoFolderMember: the rules document is the rule item of a profile document without folder (spec 6.3),
// so a rule that names one is an unknown member and not a rule silently put in the folder of the path.
func TestARulesDocumentHasNoFolderMember(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	p := a.mustProfile("Docs", "custom")
	base := "/profiles/" + p.ID.String()
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	a.post(base+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	doc := `{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"a.example","action":"block","folder":"f9"}]}`
	r := a.do("POST", base+"/folders/"+fold.ID.String()+":upload", map[string]any{"document": b64(doc)}, idem("nf-1")).want(422, "validation_failed")
	var fl fieldList
	r.json(&fl)
	found := false
	for _, x := range fl.Fields {
		found = found || x.Code == "unknown_member"
	}
	if !found {
		t.Errorf("fields %+v, want unknown_member", fl.Fields)
	}
}

// TestAJobRequestIsCheckedBeforeItIsQueued: a request above 1,000 items that inline would be a 422 is the same 422 and
// holds no job slot and no daily bulk request (spec 3.4, 3.5).
func TestAJobRequestIsCheckedBeforeItIsQueued(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`) // the fixture queues one job per tenant
	p := a.mustProfile("Jobs", "custom")
	base := "/profiles/" + p.ID.String()
	jobs := func() int {
		var n int
		f.env.Scan(t, `SELECT count(*) FROM ctrlz.batch_jobs WHERE tenant_id = $1`, []any{A.Tenant}, &n)
		return n
	}

	// Op and destination disagree: a copy has no destination. Inline this is /dest_profile_id.
	r := a.do("POST", base+"/rules:batch", map[string]any{"op": "copy", "ids": uuids(1001)}, idem("sh-1")).want(422, "validation_failed")
	var fl fieldList
	r.json(&fl)
	if !fl.has("/dest_profile_id", "invalid") {
		t.Errorf("fields %+v, want /dest_profile_id invalid", fl.Fields)
	}
	// The same id twice.
	ids := uuids(1001)
	ids[1000] = ids[0]
	a.do("POST", base+"/rules:batch", map[string]any{"op": "delete", "ids": ids}, idem("sh-2")).want(422, "validation_failed")
	// A file of 1,001 rules with one bad pattern.
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	a.post(base+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	var rs []string
	for i := 0; i < 1001; i++ {
		pat := fmt.Sprintf("u%d.example", i)
		if i == 700 {
			pat = "bad..name"
		}
		rs = append(rs, fmt.Sprintf(`{"pattern":%q,"action":"block"}`, pat))
	}
	up := `{"format":"ctrlz-rules","version":1,"rules":[` + strings.Join(rs, ",") + `]}`
	r = a.do("POST", base+"/folders/"+fold.ID.String()+":upload", map[string]any{"document": b64(up)}, idem("sh-4")).want(422, "validation_failed")
	r.json(&fl)
	if !fl.has("/rules/700/pattern", "pattern_empty_label") {
		t.Errorf("fields %+v, want /rules/700/pattern", fl.Fields)
	}
	if n := jobs(); n != 0 {
		t.Fatalf("%d jobs queued by requests that were refused", n)
	}

	// A limit of the tenant below the size of the request: refused at once, not queued to fail.
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = 500 WHERE tenant_id = $1`, A.Tenant)
	a.do("POST", base+"/rules:batch", map[string]any{"op": "delete", "ids": uuids(1001)}, idem("lim-1")).want(422, "validation_failed")
	a.do("POST", base+"/folders/"+fold.ID.String()+":upload", map[string]any{"document": b64(up)}, idem("lim-2")).want(422, "validation_failed")
	var big []string
	for i := 0; i < 1001; i++ {
		big = append(big, fmt.Sprintf(`{"pattern":"i%d.example","action":"block"}`, i))
	}
	imp := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Big","rules":[` + strings.Join(big, ",") + `]}`
	a.do("POST", "/profiles:import", map[string]any{"document": b64(imp)}, idem("lim-3")).want(422, "validation_failed")
	if n := jobs(); n != 0 {
		t.Fatalf("%d jobs queued by requests above the tenant's limit", n)
	}
}

// TestACopyFromALockedSourceIsAJobToo: Copy guards the destination only (spec 3.1, 7.3), at 1,001 rules as at 1,000.
func TestACopyFromALockedSourceIsAJobToo(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`) // the fixture queues one job per tenant
	src := a.mustProfile("Src", "custom")
	dst := a.mustProfile("Dst", "custom")
	locked := a.mustProfile("Locked", "custom")
	sb := "/profiles/" + src.ID.String()
	seedRules(a, sb, 1100)
	a.reauthPassword(pwA).want(204, "")
	a.post(sb+"/lock", map[string]any{"password": "p4ssw0rd!"}).want(204, "")
	a.post("/profiles/"+locked.ID.String()+"/lock", map[string]any{"password": "p4ssw0rd!"}).want(204, "")

	copyTo := func(dest uuid.UUID, key string) *resp {
		return a.do("POST", sb+"/rules:batch", map[string]any{"op": "copy", "selector": map[string]any{}, "dest_profile_id": dest.String()}, idem(key))
	}
	copyTo(dst.ID, "cp-1").want(202, "")
	// The destination that is locked is the one that refuses.
	f.env.Exec(t, `UPDATE ctrlz.batch_jobs SET state = 'done' WHERE tenant_id = $1`, A.Tenant)
	copyTo(locked.ID, "cp-2").want(423, "profile_locked")
	// A delete in a locked source still refuses: the source is written.
	f.env.Exec(t, `UPDATE ctrlz.batch_jobs SET state = 'done' WHERE tenant_id = $1`, A.Tenant)
	a.do("POST", sb+"/rules:batch", map[string]any{"op": "delete", "selector": map[string]any{}}, idem("cp-3")).want(423, "profile_locked")
}

// TestADuplicateRetryGetsItsStoredAnswerAfterTheSourceIsDeleted: the answer to a key is what the first request got.
func TestADuplicateRetryGetsItsStoredAnswerAfterTheSourceIsDeleted(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	p := a.mustProfile("Once", "custom")
	base := "/profiles/" + p.ID.String()
	body := map[string]any{"name": "Copy"}
	first := a.do("POST", base+":duplicate", body, idem("dup-r1")).want(201, "")
	a.do("DELETE", base, nil).want(204, "")
	again := a.do("POST", base+":duplicate", body, idem("dup-r1")).want(201, "")
	// The stored answer is jsonb, so its bytes are spaced differently; its content is what the first request got.
	var x, y any
	first.json(&x)
	again.json(&y)
	if fmt.Sprint(x) != fmt.Sprint(y) {
		t.Errorf("the replay differs:\n%s\n%s", first.Body, again.Body)
	}
	// A key that was never used, and one used for another request, are what they were.
	a.do("POST", base+":duplicate", body, idem("dup-r2")).want(404, "not_found")
	a.do("POST", base+":duplicate", map[string]any{"name": "Other"}, idem("dup-r1")).want(409, "idempotency_key_reused")
}

// TestBusyLockAndUnlockDoNotSpendTheThrottle: lock and unlock that the full Argon2 gate turned away looked at no password,
// so they give back the tenant's 20 an hour and the profile's 5 per 15 minutes (spec 7.1, 10.4), as a busy login does.
func TestBusyLockAndUnlockDoNotSpendTheThrottle(t *testing.T) {
	f, release := busyFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	release() // the setup needs the hasher
	p := a.mustProfile("Busy", "custom")
	q := a.mustProfile("Busy2", "custom")
	pb, qb := "/profiles/"+p.ID.String(), "/profiles/"+q.ID.String()
	a.reauthPassword(pwA).want(204, "")
	a.post(pb+"/lock", map[string]any{"password": "p4ssw0rd!"}).want(204, "")
	held, err := f.hasher.Gate().Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	lockTenant, unlock := f.scopeCount("profile_lock_tenant"), f.scopeCount("profile_unlock")
	// A few of each, under the per-session rate of the routes: what a busy answer kept would show in the counts.
	for i := 0; i < 4; i++ {
		a.post(pb+"/unlock", map[string]any{"password": "p4ssw0rd!"}).want(503, "server_busy")
		a.post(qb+"/lock", map[string]any{"password": "p4ssw0rd!"}).want(503, "server_busy")
	}
	if n := f.scopeCount("profile_lock_tenant"); n != lockTenant {
		t.Errorf("profile_lock_tenant counts %d after only busy answers, was %d", n, lockTenant)
	}
	if n := f.scopeCount("profile_unlock"); n != unlock {
		t.Errorf("profile_unlock counts %d after only busy answers, was %d", n, unlock)
	}
}

const (
	canaryLockPW  = "Canary-Lock-Basalt-27182-Sorrel"
	canaryWrongLK = "Canary-Unlock-Wrong-16180-Alder"
)

// TestLockPasswordCanaries: the lock password, a wrong unlock password and the stored hash reach no log, no sink table and
// no answer, through lock, a failed unlock, Export, Duplicate (as a job) and unlock (spec 10.5).
func TestLockPasswordCanaries(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`) // the fixture queues one job per tenant
	p := a.mustProfile("Canary", "custom")
	base := "/profiles/" + p.ID.String()
	seedRules(a, base, 1100)
	a.reauthPassword(pwA).want(204, "")
	a.post(base+"/lock", map[string]any{"password": canaryLockPW, "message": "back soon"}).want(204, "")
	var h []byte
	f.env.Scan(t, `SELECT lock_password_hash FROM ctrlz.profiles WHERE id = $1`, []any{p.ID}, &h)
	if len(h) < 20 {
		t.Fatalf("the stored lock hash is %d bytes", len(h))
	}
	canaries := []string{canaryLockPW, canaryWrongLK, string(h)}
	a.post(base+"/unlock", map[string]any{"password": canaryWrongLK}).want(401, "invalid_credentials")
	answers := [][]byte{
		a.get(base).want(200, "").Body,
		a.get(base+"/export").want(200, "").Body,
		a.do("POST", base+":duplicate", map[string]any{"name": "Job copy"}, idem("can-1")).want(202, "").Body,
		a.get("/profiles").want(200, "").Body,
	}
	a.post(base+"/unlock", map[string]any{"password": canaryLockPW}).want(204, "")
	for _, b := range answers {
		for _, c := range canaries {
			if strings.Contains(string(b), c) {
				t.Errorf("an answer holds a canary: %.80s", b)
			}
		}
	}
	authtest.AssertTextClean(t, "the process log", f.logs.String(), canaries...)
	f.env.AssertSinksClean(t, canaries...)
	f.env.AssertServerLogClean(t, canaries...)
}
