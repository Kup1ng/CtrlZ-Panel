package api

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// The input bounds, the hub-written values, the canaries and the claim answers of docs/specs/p3-endpoints.md 11.1, 11.4 and 11.5
// that the flow tests of the packages do not reach: what the API accepts at its limits, what it refuses at one more, and that
// a refusal is a 4xx and never a 5xx.

func refusedAsInput(t *testing.T, what string, got *resp) {
	t.Helper()
	if got.Code != 400 && got.Code != 422 {
		t.Errorf("%s: status %d (%.120q), want 400 or 422", what, got.Code, got.Body)
	}
}

// TestP3InputBounds: a 50-name create, a 100-prefix add and a 500-id batch pass and one more is refused; a comment of 255
// characters passes and one of 256 does not; every type, every Analytics level and each window count at its bound.
func TestP3InputBounds(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	A := f.env.A
	f.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_endpoints = 2000, max_authorized_ips = 2000 WHERE tenant_id = $1`, A.Tenant)
	names := func(n int, prefix string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("%s-%03d", prefix, i)
		}
		return out
	}
	create := func(key string, n int) *resp {
		return r.freshSession().do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": names(n, key), "profile_id": A.Profile.String()}, idem(key))
	}
	create("fifty", 50).want(201, "")
	refusedAsInput(t, "51 names", create("fifty-one", 51))
	if n := f.count(`SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1 AND name LIKE 'fifty-one-%'`, A.Tenant); n != 0 {
		t.Errorf("a refused create of 51 names wrote %d Endpoints", n)
	}

	// 100 prefixes in one add, and a 101st.
	var cidrs []string
	for i := 1; i <= 100; i++ {
		cidrs = append(cidrs, fmt.Sprintf("203.0.113.%d", i))
	}
	ip := "/endpoints/" + r.ep.ID.String() + "/authorized-ips"
	r.freshSession().post(ip, map[string]any{"cidrs": cidrs}).want(201, "")
	refusedAsInput(t, "101 prefixes", r.freshSession().post(ip, map[string]any{"cidrs": append(cidrs, "203.0.114.1")}))

	// 500 ids in one batch pass the bound (none of them is anyone's, so the answer is 404), and 501 do not.
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = uuid.NewString()
	}
	r.freshSession().post("/endpoints:batch", map[string]any{"ids": ids[:500], "op": "delete"}).want(404, "not_found")
	refusedAsInput(t, "501 ids", r.freshSession().post("/endpoints:batch", map[string]any{"ids": ids, "op": "delete"}))

	// A comment of 255 characters and one of 256 (T-221), counted in characters.
	ep := "/endpoints/" + r.ep.ID.String()
	r.freshSession().do("PATCH", ep, map[string]any{"comment": strings.Repeat("ب", 255)}).want(200, "")
	refusedAsInput(t, "a comment of 256 characters", r.freshSession().do("PATCH", ep, map[string]any{"comment": strings.Repeat("ب", 256)}))

	// Each of the types of the catalog creates an Endpoint, and each Analytics level is taken.
	var types struct {
		Types []struct {
			Key string `json:"key"`
		} `json:"types"`
	}
	r.a.get("/endpoint-types").want(200, "").json(&types)
	// The catalogue seed of the tests adds one type of its own (doh_client, position 99, store/catalogtest/seed.go) for the rows it
	// hangs on an Endpoint; the 30 of T-219 are the migration's.
	seeded := 0
	for _, ty := range types.Types {
		if ty.Key != "doh_client" {
			seeded++
		}
	}
	if seeded != 30 {
		t.Errorf("%d Endpoint types besides the test fixture's, want the 30 of T-219", seeded)
	}
	for i, ty := range types.Types {
		r.freshSession().do("POST", "/endpoints", map[string]any{"type": ty.Key, "names": []string{"typed-" + ty.Key},
			"profile_id": A.Profile.String(), "analytics_level": []string{"none", "some", "full"}[i%3]}, idem("typed-"+ty.Key)).want(201, "")
	}
	for _, level := range []string{"none", "some", "full"} {
		var got struct {
			Level string `json:"analytics_level"`
		}
		r.freshSession().do("PATCH", ep, map[string]any{"analytics_level": level}).want(200, "").json(&got)
		if got.Level != level {
			t.Errorf("analytics level %s read back as %s", level, got.Level)
		}
	}

	// 64 windows and a 65th (the grid holds one byte per cell, spec 3.5).
	var windows []map[string]any
	for i := 0; i < 64; i++ {
		windows = append(windows, map[string]any{"start": i * 60, "end": i*60 + 30, "profile_id": A.Profile.String()})
	}
	r.freshSession().do("PUT", ep+"/schedule", map[string]any{"timezone": "Asia/Tehran", "windows": windows}).want(200, "")
	refusedAsInput(t, "65 windows", r.freshSession().do("PUT", ep+"/schedule", map[string]any{"timezone": "Asia/Tehran",
		"windows": append(windows, map[string]any{"start": 64 * 60, "end": 64*60 + 30, "profile_id": A.Profile.String()})}))
	// A zone that is not on the list, and a window off the grid.
	refusedAsInput(t, "a zone off the list", r.freshSession().do("PUT", ep+"/schedule", map[string]any{"timezone": "Mars/Base", "windows": []any{}}))
	refusedAsInput(t, "a window off the grid", r.freshSession().do("PUT", ep+"/schedule", map[string]any{"timezone": "Asia/Tehran",
		"windows": []any{map[string]any{"start": 10, "end": 60, "profile_id": A.Profile.String()}}}))
}

// TestP3TextWithControlsIsRefusedNotFailed: names, aliases, comments, group names and SSIDs with a NUL, a C1 control, U+202E and
// U+200B are refused with a 4xx, and the same request with clean text passes, so the refusal is the text's (RULES 9, 11.5).
func TestP3TextWithControlsIsRefusedNotFailed(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	A := f.env.A
	ep := "/endpoints/" + r.ep.ID.String()
	seq := 0
	routes := map[string]func(text string) *resp{
		"an Endpoint name": func(text string) *resp {
			seq++
			return r.freshSession().do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{text}, "profile_id": A.Profile.String()}, idem(fmt.Sprintf("ctl-%d", seq)))
		},
		"a group name": func(text string) *resp {
			return r.freshSession().post("/endpoint-groups", map[string]any{"name": text})
		},
		"a client alias": func(text string) *resp { return r.freshSession().post(ep+"/clients", map[string]any{"alias": text}) },
		"a comment":      func(text string) *resp { return r.freshSession().do("PATCH", ep, map[string]any{"comment": text}) },
		"an SSID": func(text string) *resp {
			return r.freshSession().post(ep+"/apple-profile", map[string]any{"protocol": "doh", "excluded_ssids": []string{text}})
		},
	}
	for what, send := range routes {
		if got := send("clean text"); got.Code != 200 && got.Code != 201 {
			t.Errorf("%s: clean text answered %d (%.120q)", what, got.Code, got.Body)
			continue
		}
		for _, bad := range []string{"a\x00b", "a\u0085b", "a‮b", "a​b", "\u0007"} {
			refusedAsInput(t, fmt.Sprintf("%s holding %q", what, bad), send(bad))
		}
	}
	// Postgres refuses chr(0) and holds no NUL in a text column at all, so the read-back looks for the other four controls of the list
	// (BEL, NEL, U+202E, U+200B); the NUL is shown refused by the answer above.
	if n := f.count(`SELECT count(*) FROM ctrlz.endpoints WHERE tenant_id = $1 AND name ~ ('[' || chr(7) || chr(133) || chr(8238) || chr(8203) || ']')`, A.Tenant); n != 0 {
		t.Errorf("%d Endpoint names hold a control character", n)
	}
}

// TestAppleRequestAtTheValidateMaximum: 100 domains of 253 bytes of the owner's and 100 common ones (200 expanded), and 50 SSIDs
// of 32 quotes (the longest escaped form), pass both Apple routes and are stored under the params CHECK; one more common domain
// is 422 on /exclude_common (spec 11.5, 7.3).
func TestAppleRequestAtTheValidateMaximum(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	long := func(prefix string, i int) string {
		return fmt.Sprintf("%s%02d", prefix, i) + strings.Repeat("a", 60) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	}
	var common, own, ssids []string
	for i := 0; i < 100; i++ {
		common = append(common, long("c", i))
		own = append(own, long("u", i))
	}
	for i := 0; i < 50; i++ {
		ssids = append(ssids, strings.Repeat(`"`, 30)+fmt.Sprintf("%02d", i))
	}
	if len(common[0]) != 253 {
		t.Fatalf("the test domain is %d bytes", len(common[0]))
	}
	r.seedCommon(common)
	params := map[string]any{"protocol": "dot", "excluded_domains": own, "excluded_ssids": ssids, "exclude_common": true, "prohibit_disablement": true}
	var link pLinkURL
	r.freshSession().post("/endpoints/"+r.ep.ID.String()+"/apple-profile", params).want(201, "").json(&link)
	var size int
	f.env.Scan(t, `SELECT octet_length(params::text) FROM ctrlz.profile_download_tokens WHERE endpoint_id = $1 ORDER BY created_at DESC LIMIT 1`, []any{r.ep.ID}, &size)
	if size < 28000 || size > 65536 {
		t.Errorf("the stored params are %d bytes, want the maximum request of about 28 KB under the 64 KiB CHECK", size)
	}
	body := r.download(valueOf(t, link.URL)).want(200, "").Body
	if !bytes.Contains(body, []byte(common[99])) || !bytes.Contains(body, []byte(own[99])) {
		t.Error("the profile of the maximum request lacks a domain")
	}

	// The same through a share link, which takes the same params without a folder.
	sh := r.share(map[string]any{})
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, sh.URL), "params": params}).want(201, "")

	// One more common domain brings the expanded list to 201.
	r.seedCommon(append(common, long("x", 0)))
	var fl fieldList
	r.freshSession().post("/endpoints/"+r.ep.ID.String()+"/apple-profile", params).want(422, "validation_failed").json(&fl)
	if !fl.has("/exclude_common", "exceeded") {
		t.Errorf("fields %+v, want /exclude_common exceeded", fl.Fields)
	}
}

// TestHubWrittenValuesReachTheEndpoint: Pending turns to Active only through first_query_at, which the hub writes, and the last
// query is the hub's value (T-216 to T-218, spec 11.4).
func TestHubWrittenValuesReachTheEndpoint(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	ep := "/endpoints/" + r.ep.ID.String()
	var got struct {
		Status string     `json:"status"`
		First  *time.Time `json:"first_query_at"`
		Last   *time.Time `json:"last_query_at"`
	}
	r.a.get(ep).want(200, "").json(&got)
	if got.Status != "pending" || got.First != nil || got.Last != nil {
		t.Fatalf("a new Endpoint: %+v", got)
	}
	// No request can make it Active: the schema has no member for it.
	r.a.do("PATCH", ep, map[string]any{"status": "active"}).want(400, "bad_request")
	r.a.do("PATCH", ep, map[string]any{"first_query_at": "2026-11-24T10:00:00Z"}).want(400, "bad_request")
	f.env.Exec(t, `UPDATE ctrlz.endpoints SET first_query_at = '2026-11-24T09:00:00Z', last_query_at = '2026-11-24T10:30:00Z' WHERE id = $1`, r.ep.ID)
	r.a.get(ep).want(200, "").json(&got)
	if got.Status != "active" || got.First == nil || got.Last == nil || !got.Last.Equal(time.Date(2026, 11, 24, 10, 30, 0, 0, time.UTC)) {
		t.Errorf("after the hub's write: %+v", got)
	}
	var page pEndpointPage
	r.a.get("/endpoints?status=active").want(200, "").json(&page)
	if len(page.Items) != 1 || page.Items[0].ID != r.ep.ID {
		t.Errorf("the Active filter lists %+v", page.Items)
	}
}

// TestEndpointSwitchesRoundTrip: each Advanced switch is set and read back, Require Authorized IPs needs a row, and the hidden
// prevent_deactivation round-trips although no screen shows it (T-223 to T-227, T-495).
func TestEndpointSwitchesRoundTrip(t *testing.T) {
	r := newLinkRig(t)
	ep := "/endpoints/" + r.ep.ID.String()
	var got map[string]any
	for _, sw := range []string{"legacy_dns", "authorize_secure_dns", "authorize_ddns", "expose_ip", "prevent_deactivation"} {
		for _, v := range []bool{true, false} {
			r.freshSession().do("PATCH", ep, map[string]any{sw: v}).want(200, "").json(&got)
			if got[sw] != v {
				t.Errorf("%s set to %v reads back as %v", sw, v, got[sw])
			}
			r.freshSession().get(ep).want(200, "").json(&got)
			if got[sw] != v {
				t.Errorf("%s set to %v is %v on the next read", sw, v, got[sw])
			}
		}
	}
	var fl fieldList
	r.freshSession().do("PATCH", ep, map[string]any{"require_authorized_ips": true}).want(422, "validation_failed").json(&fl)
	if !fl.has("/require_authorized_ips", "needs_authorized_ip") {
		t.Errorf("fields %+v, want needs_authorized_ip", fl.Fields)
	}
	r.freshSession().post(ep+"/authorized-ips", map[string]any{"cidrs": []string{"203.0.113.9"}}).want(201, "")
	r.freshSession().do("PATCH", ep, map[string]any{"require_authorized_ips": true}).want(200, "").json(&got)
	if got["require_authorized_ips"] != true {
		t.Errorf("Require Authorized IPs read back as %v", got["require_authorized_ips"])
	}
}

const (
	canaryOwnerPW  = "Canary-Owner-Lock-Spruce-24601-Flint"
	canaryWrongOwn = "Canary-Owner-Wrong-Aspen-13579-Cobalt"
)

// TestP3Canaries (AUTH 18.4, spec 11.5): the DoH token, a share value, a download value, and a lock password right and wrong
// sent through an Endpoint route reach no log, no audit row, no outbox, no job row and no notification.
func TestP3Canaries(t *testing.T) {
	r := newLinkRig(t)
	f := r.f
	A := f.env.A
	var canaries []string

	// The DoH token is the one the view shows: it is the canary, read back from the answer.
	var view struct {
		DohURL string `json:"doh_url"`
		Host   string `json:"host"`
	}
	r.a.get("/endpoints/"+r.ep.ID.String()+"/resolvers").want(200, "").json(&view)
	token := strings.TrimPrefix(view.DohURL, "https://"+view.Host+"/")
	if len(token) != 32 {
		t.Fatalf("the DoH token %q", token)
	}
	canaries = append(canaries, token)
	r.a.get("/endpoints/"+r.ep.ID.String()+"/generators?generator=windows-doh").want(200, "")

	// A share value, opened, and a download value, downloaded, and an Apple link made through the share link.
	sh := r.share(map[string]any{})
	r.open(valueOf(t, sh.URL)).want(200, "")
	var via pLinkURL
	f.client().post("/public/share/apple-profile", map[string]any{"link": valueOf(t, sh.URL), "params": map[string]any{"protocol": "doh"}}).want(201, "").json(&via)
	var dl pLinkURL
	r.apple(map[string]any{"protocol": "dot"}).want(201, "").json(&dl)
	r.download(valueOf(t, dl.URL)).want(200, "")
	r.download(valueOf(t, via.URL)).want(200, "")
	canaries = append(canaries, valueOf(t, sh.URL), valueOf(t, dl.URL), valueOf(t, via.URL))

	// A lock password, wrong and then right, presented through an Endpoint route.
	locked := uuid.Must(uuid.NewV7())
	f.env.Exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) VALUES ($1, $2, 'canary locked')`, A.Tenant, locked)
	var created struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	r.a.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"canary guarded"}, "profile_id": locked.String()}, idem("p3-canary-ep")).want(201, "").json(&created)
	hash, err := f.hasher.Hash(f.env.Ctx, secretString(canaryOwnerPW))
	if err != nil {
		t.Fatal(err)
	}
	f.env.Exec(t, `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = $2 WHERE id = $1`, locked, hash.Reveal())
	guarded := "/endpoints/" + created.Endpoints[0].ID.String()
	r.a.do("PATCH", guarded, map[string]any{"admin_state": "soft_disabled",
		"lock_passwords": []map[string]any{{"profile_id": locked.String(), "password": canaryWrongOwn}}}).want(401, "invalid_credentials")
	r.a.do("PATCH", guarded, map[string]any{"admin_state": "soft_disabled",
		"lock_passwords": []map[string]any{{"profile_id": locked.String(), "password": canaryOwnerPW}}}).want(200, "")
	canaries = append(canaries, canaryOwnerPW, canaryWrongOwn, string(hash.Reveal()))

	authtest.AssertTextClean(t, "the process log", f.logs.String(), canaries...)
	f.env.AssertSinksClean(t, canaries...)
	f.env.AssertServerLogClean(t, canaries...)
}

// B proves an address and A, asking for it afterwards, is refused exactly as B is when A holds it: the answer names nobody, and
// is the same bytes whoever the holder is (D35, spec 11.1).
func TestIPUnavailableIsTheSameWhoeverHoldsTheAddress(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(B.Tenant, B.User)
	aEp, bEp := f.newEndpoint(a, "holder-a"), B.Endpoint.String()

	// hold makes the tenant's claim on the address active, proven and not idle.
	hold := func(c *client, ep, cidr string) pClaim {
		var claim pClaim
		c.post("/endpoints/"+ep+"/ip-claims", map[string]any{"cidr": cidr}).want(201, "").json(&claim)
		c.post("/endpoints/"+ep+"/ip-claims/"+claim.ID.String()+"/challenges", nil).want(201, "")
		f.env.Exec(t, `UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = $2, observed_protocol = 'tcp' WHERE claim_id = $1`, claim.ID, strings.TrimSuffix(cidr, "/32"))
		c.post("/endpoints/"+ep+"/ip-claims/"+claim.ID.String()+":take", map[string]any{}).want(200, "")
		f.env.Exec(t, `UPDATE ctrlz.ip_claims SET last_seen_at = now() WHERE id = $1`, claim.ID)
		return claim
	}
	// ask is the other tenant's take, with evidence of its own from inside the address.
	ask := func(c *client, tenant uuid.UUID, ep, cidr, label string) *resp {
		var theirs pClaim
		c.post("/endpoints/"+ep+"/ip-claims", map[string]any{"cidr": cidr}).want(201, "").json(&theirs)
		if theirs.State != "pending_proof" {
			t.Fatalf("a request over a proven claim started %s", theirs.State)
		}
		f.env.Exec(t, `INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, observed_at, observed_ip, observed_protocol, expires_at)
			VALUES ($1, $2, $3, now(), $4, 'tcp', now() + interval '10 minutes')`, tenant, theirs.ID, label, strings.TrimSuffix(cidr, "/32"))
		return c.post("/endpoints/"+ep+"/ip-claims/"+theirs.ID.String()+":take", map[string]any{})
	}
	hold(a, aEp, "203.0.113.20/32")
	fromB := ask(b, B.Tenant, bEp, "203.0.113.20/32", "bbbbbbbbbbbbbbbbbbbbbbbbbb").want(409, "ip_unavailable")
	hold(b, bEp, "203.0.113.21/32")
	fromA := ask(a, A.Tenant, aEp, "203.0.113.21/32", "aaaaaaaaaaaaaaaaaaaaaaaaaa").want(409, "ip_unavailable")

	if !bytes.Equal(withoutRequestID(fromA.Body), withoutRequestID(fromB.Body)) {
		t.Errorf("the refusal differs by holder: %q and %q", fromA.Body, fromB.Body)
	}

	// The case of the spec: B's refusal when A holds the address is the same bytes as B's refusal when a third tenant C holds one.
	// A comparison of A-holds with B-holds changes the asker and the holder together, so a leak keyed to "the holder is not a third
	// party" would not show (p3-D6-r1-5).
	C := catalogtest.NewSeedIDs(3)
	super, err := f.env.DB.Super(f.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := catalogtest.SeedTenant(f.env.Ctx, super, C); err != nil {
		t.Fatal(err)
	}
	_ = super.Close(f.env.Ctx)
	c := f.makeSession(C.Tenant, C.User)
	var cCreated struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	c.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"holder-c"}, "profile_id": C.Profile.String()}, idem("holder-c")).want(201, "").json(&cCreated)
	hold(c, cCreated.Endpoints[0].ID.String(), "203.0.113.22/32")
	// A label is unique in the table (ip_proof_challenges_label_key), so B's second asker evidence has a label of its own.
	fromBViaC := ask(b, B.Tenant, bEp, "203.0.113.22/32", "bcbcbcbcbcbcbcbcbcbcbcbcbc").want(409, "ip_unavailable")
	if !bytes.Equal(withoutRequestID(fromBViaC.Body), withoutRequestID(fromB.Body)) {
		t.Errorf("B's refusal differs between the holder A and the holder C: %q and %q", fromB.Body, fromBViaC.Body)
	}
	for _, h := range []string{"Content-Type", "Cache-Control", "Retry-After"} {
		if fromBViaC.H.Get(h) != fromB.H.Get(h) {
			t.Errorf("header %s differs between the holders: %q and %q", h, fromB.H.Get(h), fromBViaC.H.Get(h))
		}
	}
	if bytes.Contains(fromBViaC.Body, []byte(C.Tenant.String())) || bytes.Contains(fromBViaC.Body, []byte(A.Tenant.String())) {
		t.Error("the refusal names a tenant")
	}
	for _, h := range []string{"Content-Type", "Cache-Control", "Retry-After"} {
		if fromA.H.Get(h) != fromB.H.Get(h) {
			t.Errorf("header %s differs by holder: %q and %q", h, fromA.H.Get(h), fromB.H.Get(h))
		}
	}
	for _, tenant := range []uuid.UUID{A.Tenant, B.Tenant} {
		if bytes.Contains(fromA.Body, []byte(tenant.String())) || bytes.Contains(fromB.Body, []byte(tenant.String())) {
			t.Error("the refusal names a tenant")
		}
	}
}
