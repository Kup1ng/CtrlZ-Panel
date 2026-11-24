package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The flow and abuse cases of spec 10.4 and 10.5 that the first three packages left open, through the routes.

// TestS3MaxProfilesHoldsUnderRacingCreatesImportsAndDuplicates: with room for three more profiles, twelve requests that each add
// one (create, import and duplicate in turn, from twelve sessions at once) leave exactly three, and every other answer is the
// refusal of the limit or a request to retry, never a fourth profile (spec 3.4, 10.2 S3, T-198).
func TestS3MaxProfilesHoldsUnderRacingCreatesImportsAndDuplicates(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	src := f.fresh(A.Tenant, A.User).mustProfile("Source", "custom")
	var have int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1`, []any{A.Tenant}, &have)
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_profiles = $2 WHERE tenant_id = $1`, A.Tenant, have+3)
	var wg sync.WaitGroup
	codes := make([]int, 12)
	for i := range codes {
		c := f.fresh(A.Tenant, A.User)
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := map[string]string{"Idempotency-Key": fmt.Sprintf("race-%d-%s", i, uuid.NewString()[:8])}
			for attempt := 0; attempt < 20; attempt++ {
				var r *resp
				switch i % 3 {
				case 0:
					r = c.do("POST", "/profiles", map[string]any{"name": fmt.Sprintf("Create %d", i), "kind": "custom"})
				case 1:
					r = c.do("POST", "/profiles:import", map[string]any{"document": b64(fmt.Sprintf(`{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Import %d"}`, i))}, key)
				default:
					r = c.do("POST", "/profiles/"+src.ID.String()+":duplicate", map[string]any{"name": fmt.Sprintf("Duplicate %d", i)}, key)
				}
				codes[i] = r.Code
				if r.Code != 503 {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	created, refused := 0, 0
	for i, code := range codes {
		switch code {
		case 201:
			created++
		case 422:
			refused++
		default:
			t.Errorf("request %d answered %d", i, code)
		}
	}
	var now int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1`, []any{A.Tenant}, &now)
	if now != have+3 || created != 3 || refused != 9 {
		t.Fatalf("the tenant has %d profiles (limit %d), %d requests created one and %d were refused", now, have+3, created, refused)
	}
}

// TestS5ALocationOutsideTheSetThroughTheRoutes: with no location in the set, an item write that needs one is refused and a
// document write keeps it and flags it, a type that needs a destination is created with its Default Rule flagged, and a key
// with no locations row is refused by both (spec 4.2, 10.2 S5, T-129, T-166).
func TestS5ALocationOutsideTheSetThroughTheRoutes(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	// The set is empty: no node has a location.
	f.env.Exec(t, `DELETE FROM ctrlz.location_availability`)
	c := func() *client { return f.fresh(A.Tenant, A.User) }
	p := c().mustProfile("Empty set", "custom")
	base := "/profiles/" + p.ID.String()
	var fl fieldList
	c().post(base+"/rules", map[string]any{"patterns": []string{"vpn.example"}, "action": "redirect", "target": map[string]any{"kind": "auto"}}).want(422, "validation_failed").json(&fl)
	if !fl.has("/target/kind", "no_shared_destination") {
		t.Errorf("Auto on an empty set: fields %+v", fl.Fields)
	}
	c().do("PATCH", base+"/options", map[string]any{"default_rule": map[string]any{"action": "redirect", "target": map[string]any{"kind": "random"}}}).want(422, "validation_failed")
	// A document keeps the same target and flags it; the counter says how many.
	doc := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Flagged","rules":[{"pattern":"vpn.example","action":"redirect","target":{"kind":"auto"}}]}`
	var made struct {
		Flagged int `json:"flagged"`
	}
	c().do("POST", "/profiles:import", map[string]any{"document": b64(doc)}, idem(uuid.NewString())).want(201, "").json(&made)
	if made.Flagged != 1 {
		t.Errorf("an import of an Auto rule on an empty set flagged %d, want 1", made.Flagged)
	}
	// A type with a destination is created with its Default Rule flagged (T-129).
	var vpn struct {
		Flagged int `json:"flagged"`
	}
	c().post("/profiles", map[string]any{"name": "VPN", "kind": "vpn_replacement"}).want(201, "").json(&vpn)
	if vpn.Flagged != 1 {
		t.Errorf("a vpn_replacement profile on an empty set flagged %d, want 1", vpn.Flagged)
	}
	// A key that names no location at all cannot be stored, in a document or on the item route.
	unknown := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Nowhere","rules":[{"pattern":"vpn.example","action":"redirect","target":{"kind":"location","location":{"country":"ZZ"}}}]}`
	c().do("POST", "/profiles:import", map[string]any{"document": b64(unknown)}, idem(uuid.NewString())).want(422, "validation_failed")
	c().post(base+"/rules", map[string]any{"patterns": []string{"vpn2.example"}, "action": "redirect", "target": map[string]any{"kind": "location", "location_id": uuid.NewString()}}).want(422, "validation_failed")
}

// TestServicesBatchAndRulesBatchAtTheirBounds: 2,000 slugs of the longest length pass the schema and 2,001 do not; 10,001 ids
// are a 400, 10,000 are a job of the tenant, and a lower override of the tenant refuses what is above it (spec 3.4, 8.2, 10.4).
func TestServicesBatchAndRulesBatchAtTheirBounds(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.env.Exec(t, `DELETE FROM ctrlz.batch_jobs`)
	p := f.fresh(A.Tenant, A.User).mustProfile("Bounds", "custom")
	base := "/profiles/" + p.ID.String()
	slugs := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%063d", i)[:64-len(fmt.Sprint(i))-1] + "x" + fmt.Sprint(i)
			out[i] = out[i][:min(64, len(out[i]))]
		}
		return out
	}
	for _, s := range slugs(2000) {
		if len(s) > 64 {
			t.Fatalf("slug %q is %d long", s, len(s))
		}
	}
	r := f.fresh(A.Tenant, A.User).post(base+"/services:batch", map[string]any{"op": "delete", "slugs": slugs(2000)})
	if r.Code == 400 || r.Code == 413 {
		t.Errorf("2,000 slugs: %d %s, want the schema to let them through", r.Code, r.Body)
	}
	f.fresh(A.Tenant, A.User).post(base+"/services:batch", map[string]any{"op": "delete", "slugs": slugs(2001)}).want(400, "bad_request")

	f.fresh(A.Tenant, A.User).do("POST", base+"/rules:batch", map[string]any{"op": "delete", "ids": uuids(10001)}, idem("ids-10001")).want(400, "bad_request")
	var job struct {
		State string `json:"state"`
		Total int    `json:"total"`
	}
	f.fresh(A.Tenant, A.User).do("POST", base+"/rules:batch", map[string]any{"op": "delete", "ids": uuids(10000)}, idem("ids-10000")).want(202, "").json(&job)
	if job.State != "queued" || job.Total != 10000 {
		t.Errorf("10,000 ids: %+v, want a queued job of 10,000", job)
	}
	// A lower override of the tenant: 11 ids are above 10.
	f.env.Exec(t, `UPDATE ctrlz.batch_jobs SET state = 'done' WHERE tenant_id = $1`, A.Tenant)
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_request = 10 WHERE tenant_id = $1`, A.Tenant)
	var fl fieldList
	f.fresh(A.Tenant, A.User).do("POST", base+"/rules:batch", map[string]any{"op": "delete", "ids": uuids(11)}, idem("ids-11")).want(422, "validation_failed").json(&fl)
	if !fl.has("max_rules_per_request", "exceeded") {
		t.Errorf("11 ids against a limit of 10: fields %+v", fl.Fields)
	}
}

// TestIranianBypassIsTrueOnARedirectAndFalseOnABlock: a Redirect over an Iranian name, and an inherit under a Redirect Folder Rule
// over one, are shown as acting as Bypass, and a Block over one is not (spec 3.6, 10.4, T-525).
func TestIranianBypassIsTrueOnARedirectAndFalseOnABlock(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("Bypass flags", "custom")
	base := "/profiles/" + p.ID.String()
	var fold struct {
		ID uuid.UUID `json:"id"`
	}
	f.fresh(A.Tenant, A.User).post(base+"/folders", map[string]any{"name": "Over", "kind": "standard", "action": "block"}).want(201, "").json(&fold)
	f.env.Exec(t, `UPDATE ctrlz.rule_folders SET action = 'redirect', target_kind = 'host', target_host = 'proxy.example.net' WHERE id = $1`, fold.ID)
	f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host) VALUES ($1, $2, 'redir.ir', 'domain', 'redirect', 'host', 'proxy.example.net')`, A.Tenant, p.ID)
	f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action) VALUES ($1, $2, $3, 'inherit.ir', 'domain', 'inherit')`, A.Tenant, p.ID, fold.ID)
	f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action) VALUES ($1, $2, 'block.ir', 'domain', 'block')`, A.Tenant, p.ID)
	var page struct {
		Items []struct {
			Pattern       string `json:"pattern"`
			IranianBypass bool   `json:"iranian_bypass"`
		} `json:"items"`
	}
	f.fresh(A.Tenant, A.User).get(base+"/rules").want(200, "").json(&page)
	want := map[string]bool{"redir.ir": true, "inherit.ir": true, "block.ir": false}
	seen := 0
	for _, it := range page.Items {
		if w, ok := want[it.Pattern]; ok {
			seen++
			if it.IranianBypass != w {
				t.Errorf("%s: iranian_bypass %v, want %v", it.Pattern, it.IranianBypass, w)
			}
		}
	}
	if seen != 3 {
		t.Fatalf("the list holds %d of the three rules: %+v", seen, page.Items)
	}
}

// TestWritesOnOneProfileUnderAPoolSmallerThanTheirNumber: while one transaction holds the profile (as a long job does), more
// concurrent writes on it than the pool has connections answer 503 or wait their turn and never anything else in the 5xx
// class, and another tenant's GET /me is answered within 3 seconds throughout (spec 10.5, AUTH 18.3).
func TestWritesOnOneProfileUnderAPoolSmallerThanTheirNumber(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	cfg := f.env.DB.StoreConfig(store.RoleTenant)
	cfg.MaxConns = 4
	cfg.AcquireTimeout = 2 * time.Second
	small, err := store.Open(f.env.Ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	f.deps.Store = small
	sm := session.NewManager(small, session.DefaultPolicy(), f.ck.now)
	if err := sm.WithKeys(f.keys, keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	f.deps.Sessions = sm
	f.setLimiter(f.deps.Limiter)
	p := f.fresh(A.Tenant, A.User).mustProfile("Held", "custom")
	// One transaction takes the guard of the profile and keeps it, as a job does for its whole run.
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- small.WithTenant(f.env.Ctx, A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
			if _, won, err := tx.ProfileGuard(p.ID); err != nil || !won.Yes() {
				close(held)
				return fmt.Errorf("the guard was not won: %v", err)
			}
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	var wg sync.WaitGroup
	codes := make([]int, 16)
	for i := range codes {
		c := f.fresh(A.Tenant, A.User)
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = c.do("PATCH", "/profiles/"+p.ID.String(), map[string]any{"name": fmt.Sprintf("Name %d", i)}).Code
		}()
	}
	other := f.fresh(B.Tenant, B.User)
	start := time.Now()
	r := other.get("/me")
	took := time.Since(start)
	wg.Wait()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for i, code := range codes {
		if code != 503 && code != 200 {
			t.Errorf("write %d answered %d", i, code)
		}
	}
	// The 3 seconds of the spec are the acquire timeout of the store plus the work; the answer may also be the 503 of the full pool.
	if took > 3*time.Second+cfg.AcquireTimeout {
		t.Errorf("another tenant's GET /me took %v while 16 writes queued on one profile", took)
	}
	if r.Code != 200 && r.Code != 503 {
		t.Errorf("another tenant's GET /me answered %d", r.Code)
	}
}

// slowBody is a request body that sends what it has and then waits for release, as a client on a dead link does.
type slowBody struct {
	first   []byte
	sent    bool
	release chan struct{}
}

func (b *slowBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, b.first), nil
	}
	<-b.release
	return 0, io.ErrUnexpectedEOF
}

// TestAStalledBodyHoldsOnlyItsOwnTenantsPlace: an Import whose body stops arriving keeps its tenant's place, so that tenant's
// second Import is 503 server_busy and the tenant's ordinary reads go on, while another tenant's Import and its reads are
// answered at once; when the client leaves, the place is free again (spec 6.5, 10.5).
func TestAStalledBodyHoldsOnlyItsOwnTenantsPlace(t *testing.T) {
	f := newFrig(t, frigOpts{})
	adm := f.withAdmission()
	A, B := f.env.A, f.env.B
	a, b := f.fresh(A.Tenant, A.User), f.fresh(B.Tenant, B.User)
	declared := 1 << 20
	body := &slowBody{first: []byte(`{"document":"`), release: make(chan struct{})}
	req := httptest.NewRequest("POST", "/api/v1/profiles:import", body)
	req.ContentLength = int64(declared)
	req.Host = host
	req.Header.Set("X-Forwarded-For", a.ip)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "stalled-"+uuid.NewString()[:8])
	for _, ck := range a.jar {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	rec := httptest.NewRecorder()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		f.h.ServeHTTP(rec, req)
	}()
	deadline := time.Now().Add(20 * time.Second)
	for {
		if places, _ := adm.Held(); places >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stalled request never took its tenant's place")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The same tenant's second heavy request meets the place; its ordinary read does not.
	f.fresh(A.Tenant, A.User).do("POST", "/profiles:import", validBulkDoc(), idem("second-"+uuid.NewString()[:8])).want(503, "server_busy")
	f.fresh(A.Tenant, A.User).get("/profiles").want(200, "")
	// Another tenant is not held.
	start := time.Now()
	b.do("POST", "/profiles:import", validBulkDoc(), idem("other-"+uuid.NewString()[:8])).want(201, "")
	b.get("/me").want(200, "")
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("another tenant's Import took %v behind a stalled body", took)
	}
	close(body.release)
	select {
	case <-finished:
	case <-time.After(30 * time.Second):
		t.Fatal("the stalled request never ended after its client left")
	}
	if strings.Contains(rec.Body.String(), "panic") {
		t.Errorf("the stalled request ended badly: %s", rec.Body)
	}
	if places, pool := adm.Held(); places != 0 || pool != 0 {
		t.Errorf("%d places and %d bytes are still held after the client left", places, pool)
	}
	f.fresh(A.Tenant, A.User).do("POST", "/profiles:import", validBulkDoc(), idem("after-"+uuid.NewString()[:8])).want(201, "")
}
