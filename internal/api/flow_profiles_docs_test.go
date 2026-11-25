package api

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
)

// Documents, Upload Folder, the lock bound and the jobs through the routes (spec 6, 7, 3.5, 10.4, 10.5).

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

type fieldList struct {
	Fields []struct{ Name, Code string } `json:"fields"`
}

func (f fieldList) has(name, code string) bool {
	for _, x := range f.Fields {
		if x.Name == name && x.Code == code {
			return true
		}
	}
	return false
}

// TestImportGivesACodeForEveryProblemOfADocument: every code only a document can give, and the schema keywords that map
// to the closed set, each at its pointer, and never an echo of a name from the file (spec 6.2).
func TestImportGivesACodeForEveryProblemOfADocument(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	long := strings.Repeat("n", 65)
	cases := []struct {
		name, doc, pointer, code string
	}{
		{"not json", `{"format":`, "", "json_syntax"},
		{"duplicate key", `{"format":"ctrlz-profile","format":"x"}`, "", "json_syntax"},
		{"too deep", strings.Repeat("[", 9) + strings.Repeat("]", 9), "/0/0/0/0/0/0/0", "json_syntax"},
		{"not an object", `[1]`, "", "type"},
		{"format", `{"format":"other","version":1}`, "/format", "format_unknown"},
		{"version", `{"format":"ctrlz-profile","version":2,"kind":"custom"}`, "/version", "version_unsupported"},
		{"unknown member", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","zz\u0001z":1}`, "", "unknown_member"},
		{"required", `{"format":"ctrlz-profile","version":1,"name":"x"}`, "", "required"},
		{"type", `{"format":"ctrlz-profile","version":1,"name":"x","kind":5}`, "/kind", "type"},
		{"enum", `{"format":"ctrlz-profile","version":1,"name":"x","kind":"nope"}`, "/kind", "invalid"},
		{"too long", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"` + long + `"}`, "/name", "too_long"},
		{"out of range", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","options":{"block_ttl":0}}`, "/options/block_ttl", "out_of_range"},
		{"pattern", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[{"pattern":"bad..name","action":"block"}]}`, "/rules/0/pattern", "pattern_empty_label"},
		{"unknown filter", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","filters":[{"id":"nope"}]}`, "/filters/0/id", "unknown"},
		{"duplicate rule", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[{"pattern":"a.example","action":"block"},{"pattern":"A.example","action":"block"}]}`, "/rules/1/pattern", "duplicate"},
		{"folder ref", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[{"pattern":"a.example","action":"block","folder":"zz"}]}`, "/rules/0/folder", "unknown"},
		{"inherit needs folder", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[{"pattern":"a.example","action":"inherit"}]}`, "/rules/0/action", "needs_folder_action"},
		{"iranian name", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[{"pattern":"shop.ir","action":"redirect","target":{"kind":"host","host":"p.example.net"}}]}`, "/rules/0/pattern", "iranian_name"},
		{"unknown location", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","options":{"default_rule":{"action":"redirect","target":{"kind":"location","location":{"country":"ZZ"}}}}}`, "/options/default_rule/target/location", "unknown"},
		{"ecs host bits", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","options":{"ecs":{"mode":"custom","v4":"10.0.0.1/24"}}}`, "/options/ecs/v4", "invalid"},
		{"branded", `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","options":{"block_response":{"mode":"branded"}}}`, "/options/block_response/mode", "not_available"},
	}
	for i, c := range cases {
		if i%8 == 7 {
			f.ck.add(time.Minute) // the bulk-write bucket: 10 a minute per session
		}
		r := a.do("POST", "/profiles:import", map[string]any{"document": b64(c.doc)}, idem(fmt.Sprintf("codes-%d", i))).want(422, "validation_failed")
		var fl fieldList
		r.json(&fl)
		if !fl.has(c.pointer, c.code) {
			t.Errorf("%s: fields %+v, want %q at %q", c.name, fl.Fields, c.code, c.pointer)
		}
		if strings.Contains(string(r.Body), "zz") && c.name == "unknown member" {
			t.Errorf("an unknown member name was echoed: %s", r.Body)
		}
	}
	// 10,001 rules is the schema's maxItems: a code, not a 5xx. Not base64: the pipeline bounds the file itself.
	a.do("POST", "/profiles:import", map[string]any{"document": "!!!"}, idem("not-base64")).want(400, "bad_request")
	a.do("POST", "/profiles:import", map[string]any{"document": "QQ="}, idem("short-base64")).want(422, "validation_failed")
}

// TestUploadFolderMergesAndNeverDeletes: new keys are created, a key in another folder is a conflict, a repeat is skipped
// in new_only mode and updated in upsert mode (spec 6.3).
func TestUploadFolderMergesAndNeverDeletes(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	p := a.mustProfile("Upload", "custom")
	base := "/profiles/" + p.ID.String()
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	a.post(base+"/folders", map[string]any{"name": "In", "kind": "standard"}).want(201, "").json(&fold)
	a.post(base+"/rules", map[string]any{"patterns": []string{"root.example"}, "action": "block"}).want(201, "")
	up := base + "/folders/" + fold.ID.String() + ":upload"
	doc := `{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"new.example","action":"block"},{"pattern":"root.example","action":"block"}]}`
	var res struct {
		Created, Updated, Skipped, Conflict int
	}
	a.do("POST", up, map[string]any{"document": b64(doc)}, idem("up-1")).want(200, "").json(&res)
	if res.Created != 1 || res.Conflict != 1 {
		t.Fatalf("first upload: %+v", res)
	}
	a.do("POST", up, map[string]any{"document": b64(doc)}, idem("up-2")).want(200, "").json(&res)
	if res.Created != 0 || res.Skipped != 1 || res.Conflict != 1 {
		t.Fatalf("a repeat in new_only mode: %+v", res)
	}
	changed := `{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"new.example","action":"bypass"}]}`
	a.do("POST", up, map[string]any{"document": b64(changed), "mode": "upsert"}, idem("up-3")).want(200, "").json(&res)
	if res.Updated != 1 {
		t.Fatalf("upsert: %+v", res)
	}
	// The same key with another body or another mode is a different request.
	a.do("POST", up, map[string]any{"document": b64(changed), "mode": "new_only"}, idem("up-3")).want(409, "idempotency_key_reused")
	// Export Rules gives what the folder holds, and nothing is deleted by an upload.
	r := a.get(base+"/folders/"+fold.ID.String()+"/export").want(200, "")
	if string(r.Body) != `{"format":"ctrlz-rules","version":1,"rules":[{"pattern":"new.example","action":"bypass","enabled":true}]}` {
		t.Fatalf("export rules: %s", r.Body)
	}
}

// TestTheLockPasswordBound: 6 to 128 code points after NFKC, the same on lock and unlock, and a refused value spends
// nothing and writes no audit row (spec 7.1).
func TestTheLockPasswordBound(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	p := a.mustProfile("Lock", "custom")
	base := "/profiles/" + p.ID.String()
	a.reauthPassword(pwA).want(204, "")
	count := func(q string) int {
		var n int
		f.env.Scan(t, q, nil, &n)
		return n
	}
	throttled := count(`SELECT count(*) FROM ctrlz.auth_throttle`)
	audited := count(`SELECT count(*) FROM ctrlz.tenant_audit_log`)
	for _, c := range []struct{ pw, code string }{
		{"12345", "too_short"}, {strings.Repeat("a", 129), "too_long"}, {strings.Repeat("ﷺ", 8), "too_long"}, {strings.Repeat("ﷺ", 16), "too_long"},
	} {
		var fl fieldList
		a.post(base+"/lock", map[string]any{"password": c.pw}).want(422, "validation_failed").json(&fl)
		if !fl.has("/password", c.code) {
			t.Errorf("lock %d code points: %+v, want %s", len([]rune(c.pw)), fl.Fields, c.code)
		}
		a.post(base+"/unlock", map[string]any{"password": c.pw}).want(422, "validation_failed").json(&fl)
		if !fl.has("/password", c.code) {
			t.Errorf("unlock %d code points: %+v, want %s", len([]rune(c.pw)), fl.Fields, c.code)
		}
	}
	if n := count(`SELECT count(*) FROM ctrlz.auth_throttle`); n != throttled {
		t.Errorf("a refused password spent a throttle: %d rows, had %d", n, throttled)
	}
	if n := count(`SELECT count(*) FROM ctrlz.tenant_audit_log`); n != audited {
		t.Errorf("a refused password wrote an audit row: %d, had %d", n, audited)
	}
	f.ck.add(time.Minute) // the sensitive class: 10 a minute per session
	// 6 and 128 code points are accepted; a lock set in one form of an NFKC pair opens with the other.
	a.post(base+"/lock", map[string]any{"password": "ＡＢＣＤＥＦ"}).want(204, "") // full-width ABCDEF
	a.post(base+"/unlock", map[string]any{"password": "ABCDEF"}).want(204, "")
	a.post(base+"/lock", map[string]any{"password": strings.Repeat("a", 128)}).want(204, "")
	a.post(base+"/unlock", map[string]any{"password": strings.Repeat("a", 128)}).want(204, "")
	f.ck.add(time.Minute)
	// A sixth failure in 15 minutes is 429.
	a.post(base+"/lock", map[string]any{"password": "right-one"}).want(204, "")
	for i := 0; i < 5; i++ {
		a.post(base+"/unlock", map[string]any{"password": "wrong-one"}).want(401, "invalid_credentials")
	}
	a.post(base+"/unlock", map[string]any{"password": "wrong-one"}).want(429, "too_many_attempts")
	a.post(base+"/unlock", map[string]any{"password": "right-one"}).want(429, "too_many_attempts")
	f.ck.add(time.Minute)
	// Another tenant's attempts at the same id land in its own bucket and find no profile.
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	b.post(base+"/unlock", map[string]any{"password": "wrong-one"}).want(404, "not_found")
}

// TestABigRequestIsAJobAndASecondOneWaits: above 1,000 rules the request is a job with its outbox row in the same
// transaction (202), a second is 409 job_running while the first is active, a locked or missing profile is refused before any job
// (spec 3.5).
func TestABigRequestIsAJobAndASecondOneWaits(t *testing.T) {
	f := newFrig(t, frigOpts{})
	f.env.Exec(t, `DELETE FROM ctrlz.job_outbox`)
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`)
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	p := a.mustProfile("Jobs", "custom")
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	base := "/profiles/" + p.ID.String()
	a.post(base+"/folders", map[string]any{"name": "Big", "kind": "standard"}).want(201, "").json(&fold)
	var rules []string
	for i := 0; i < 1001; i++ {
		rules = append(rules, fmt.Sprintf(`{"pattern":"h%d.example.com","action":"block"}`, i))
	}
	doc := `{"format":"ctrlz-rules","version":1,"rules":[` + strings.Join(rules, ",") + `]}`
	up := base + "/folders/" + fold.ID.String() + ":upload"
	var job struct {
		ID    uuid.UUID `json:"id"`
		State string    `json:"state"`
		Total int       `json:"total"`
	}
	a.do("POST", up, map[string]any{"document": b64(doc)}, idem("big-1")).want(202, "").json(&job)
	if job.State != "queued" || job.Total != 1001 {
		t.Fatalf("job %+v", job)
	}
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.job_outbox WHERE tenant_id = $1`, []any{A.Tenant}, &n)
	if n != 1 {
		t.Fatalf("job_outbox rows = %d", n)
	}
	// A replay gives the same job and no second one.
	var again struct{ ID uuid.UUID }
	a.do("POST", up, map[string]any{"document": b64(doc)}, idem("big-1")).want(202, "").json(&again)
	if again.ID != job.ID {
		t.Fatal("a replay queued another job")
	}
	// Another job while this one is active.
	a.do("POST", up, map[string]any{"document": b64(doc)}, idem("big-2")).want(409, "job_running")
	var active struct {
		Job *struct{ ID uuid.UUID } `json:"job"`
	}
	a.get("/jobs/active").want(200, "").json(&active)
	if active.Job == nil || active.Job.ID != job.ID {
		t.Fatalf("active job %+v", active)
	}
	a.get("/jobs/"+job.ID.String()).want(200, "")
	// Another tenant cannot read it.
	f.makeSession(f.env.B.Tenant, f.env.B.User).get("/jobs/"+job.ID.String()).want(404, "not_found")
	// Once it ends there is no active job.
	f.env.Exec(t, `UPDATE ctrlz.batch_jobs SET state = 'done' WHERE id = $1`, job.ID)
	active.Job = nil
	a.get("/jobs/active").want(200, "").json(&active)
	if active.Job != nil {
		t.Fatalf("an ended job is still active: %+v", active)
	}
	// A locked profile is refused before any job is made.
	f.env.Exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = 'h' WHERE id = $1`, p.ID)
	a.do("POST", up, map[string]any{"document": b64(doc)}, idem("big-3")).want(423, "profile_locked")
	a.do("POST", "/profiles/"+uuid.NewString()+"/folders/"+fold.ID.String()+":upload", map[string]any{"document": b64(doc)}, idem("big-4")).want(404, "not_found")
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.batch_jobs WHERE tenant_id = $1 AND state IN ('queued', 'running')`, []any{A.Tenant}, &n)
	if n != 0 {
		t.Fatalf("a refused request left %d active jobs", n)
	}
}

// TestTheTenantsPlaceRefusesWithServerBusyAndReleases: an Import of a tenant whose place is taken is 503 server_busy, a
// refused request holds and charges nothing, and the place is back after the answer (spec 6.5).
func TestTheTenantsPlaceRefusesWithServerBusyAndReleases(t *testing.T) {
	f := newFrig(t, frigOpts{})
	adm := f.withAdmission()
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	hold, err := adm.Place(A.Tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	a.do("POST", "/profiles:import", validBulkDoc(), idem("busy-1")).want(503, "server_busy")
	if places, pool := adm.Held(); places != 1 || pool != 0 {
		t.Fatalf("a refused request changed what is held: %d places, %d bytes", places, pool)
	}
	hold()
	// The retry of the refused request, with its key, is the request that works: nothing was stored for the refusal.
	a.do("POST", "/profiles:import", validBulkDoc(), idem("busy-1")).want(201, "")
	if places, pool := adm.Held(); places != 0 || pool != 0 {
		t.Fatalf("%d places and %d bytes are still held after the answer", places, pool)
	}
}

// TestADocumentOfTooManyRulesIsExceeded: the maxItems of the schema is the code exceeded, and the codes the cases of these
// tests gave are all the codes a document can give (spec 6.2, 10.4).
func TestADocumentOfTooManyRulesIsExceeded(t *testing.T) {
	f := newFrig(t, frigOpts{})
	a := f.makeSession(f.env.A.Tenant, f.env.A.User)
	var b strings.Builder
	b.WriteString(`{"format":"ctrlz-profile","version":1,"kind":"custom","name":"x","rules":[`)
	for i := 0; i < 10001; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"pattern":"a.example","action":"block"}`)
	}
	b.WriteString(`]}`)
	var fl fieldList
	a.do("POST", "/profiles:import", map[string]any{"document": b64(b.String())}, idem("many")).want(422, "validation_failed").json(&fl)
	if !fl.has("/rules", "exceeded") {
		t.Fatalf("fields %+v", fl.Fields)
	}
	for _, code := range profiles.DocumentCodes() {
		if !strings.Contains(documentCodeCases, `"`+code+`"`) {
			t.Errorf("the code %s of a document has no case in TestImportGivesACodeForEveryProblemOfADocument", code)
		}
	}
}

// documentCodeCases is the source of the table of that test, so a code with no case fails.
var documentCodeCases = func() string {
	b, err := os.ReadFile("flow_profiles_docs_test.go")
	if err != nil {
		return ""
	}
	return string(b)
}()

// TestBulkWriteStopsAtTheTenantsDayBudget: 200 bulk requests a day per tenant however many sessions it holds, charged before the
// body is read, and another tenant has its own (spec 8.1).
func TestBulkWriteStopsAtTheTenantsDayBudget(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	// A token bucket refills while the clock moves, so the 200 requests are made inside one minute: 20 sessions of 10 each (a
	// session's own bucket is 10 a minute), and the 201st comes from a session that has used nothing.
	var sessions []*client
	for i := 0; i < 21; i++ {
		sessions = append(sessions, f.makeSession(A.Tenant, A.User))
	}
	bad := map[string]any{"document": b64(`{}`)}
	for i := 0; i < 200; i++ {
		sessions[i%20].do("POST", "/profiles:import", bad, idem(fmt.Sprintf("day-%d", i))).want(422, "validation_failed")
	}
	sessions[20].do("POST", "/profiles:import", bad, idem("day-200")).want(429, "rate_limited")
	f.makeSession(B.Tenant, B.User).do("POST", "/profiles:import", bad, idem("day-b")).want(422, "validation_failed")
}

// TestDuplicateStopsAtTheTenantsDayBudget: Duplicate has the default body limit and so never takes the bulk gate, but it is
// of the bulk-write class and pays the same 200 a day per tenant as Import (spec 8.1).
func TestDuplicateStopsAtTheTenantsDayBudget(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	var sessions []*client
	for i := 0; i < 21; i++ {
		sessions = append(sessions, f.makeSession(A.Tenant, A.User))
	}
	// The source does not exist: the answer is 404, and the budget is charged before the handler runs.
	path := "/profiles/00000000-0000-4000-8000-000000000001:duplicate"
	body := map[string]any{"name": "x"}
	for i := 0; i < 200; i++ {
		sessions[i%20].do("POST", path, body, idem(fmt.Sprintf("dday-%d", i))).want(404, "not_found")
	}
	sessions[20].do("POST", path, body, idem("dday-200")).want(429, "rate_limited")
	f.makeSession(B.Tenant, B.User).do("POST", path, body, idem("dday-b")).want(404, "not_found")
}
