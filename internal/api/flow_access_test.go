package api

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The access routes end to end (docs/specs/p3-endpoints.md 4, 5, 9.2): Authorized IPs with their three rules, Dynamic DNS
// hosts, Plain DNS claims with the proof dialog's calls, and the tenant budget of the claim routes.

type pAuthorized struct {
	ID        uuid.UUID `json:"id"`
	Cidr      string    `json:"cidr"`
	Source    string    `json:"source"`
	IsCurrent bool      `json:"is_current"`
	OptIn     bool      `json:"cleanup_opt_in"`
}

type pAuthorizedPage struct {
	Items      []pAuthorized `json:"items"`
	NextCursor string        `json:"next_cursor"`
}

type pClaim struct {
	ID         uuid.UUID `json:"id"`
	Cidr       string    `json:"cidr"`
	State      string    `json:"state"`
	Source     string    `json:"source"`
	Proven     bool      `json:"proven"`
	NeedsAdmin bool      `json:"needs_admin"`
	Challenge  *struct {
		Label    string `json:"label"`
		Observed bool   `json:"observed"`
	} `json:"challenge"`
}

func (f *frig) newEndpoint(a *client, name string) string {
	f.t.Helper()
	var created struct {
		Endpoints []pEndpoint `json:"endpoints"`
	}
	a.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{name}, "profile_id": f.env.A.Profile.String()},
		idem("access-"+name)).want(201, "").json(&created)
	return created.Endpoints[0].ID.String()
}

func TestAuthorizedIPFlow(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	ep := f.newEndpoint(a, "access")
	base := "/endpoints/" + ep + "/authorized-ips"

	// Rule 3: no row, no Require.
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"require_authorized_ips": true}).want(422, "validation_failed")

	// Add: the client's own address and a /16. A refused prefix refuses all, at its index.
	var added struct {
		Items []pAuthorized `json:"items"`
	}
	a.post(base, map[string]any{"cidrs": []string{"198.18.0.0/15", "1.2.3.4.5"}}).want(422, "validation_failed")
	a.post(base, map[string]any{"cidrs": []string{a.ip, "198.18.0.0/16"}}).want(201, "").json(&added)
	if len(added.Items) != 2 {
		t.Fatalf("%d rows added", len(added.Items))
	}
	a.post(base, map[string]any{"cidrs": []string{"198.18.0.0/16"}}).want(422, "validation_failed")

	// The list marks the row that holds the address of the request, and not for another client.
	var page pAuthorizedPage
	a.get(base).want(200, "").json(&page)
	current := 0
	var mine, wide pAuthorized
	for _, r := range page.Items {
		if r.IsCurrent {
			current++
			mine = r
		} else {
			wide = r
		}
	}
	if current != 1 || mine.Cidr != a.ip+"/32" || wide.Cidr != "198.18.0.0/16" {
		t.Fatalf("list %+v", page.Items)
	}
	var onePage pAuthorizedPage
	a.get(base+"?limit=1").want(200, "").json(&onePage)
	if len(onePage.Items) != 1 || onePage.NextCursor == "" {
		t.Fatalf("first page %+v", onePage)
	}
	var next pAuthorizedPage
	a.get(base+"?limit=1&cursor="+onePage.NextCursor).want(200, "").json(&next)
	if len(next.Items) != 1 || next.Items[0].ID == onePage.Items[0].ID {
		t.Errorf("second page %+v after %+v", next, onePage)
	}
	var found pAuthorizedPage
	a.get(base+"?q=198.18").want(200, "").json(&found)
	if len(found.Items) != 1 || found.Items[0].ID != wide.ID {
		t.Errorf("search %+v", found)
	}

	// Rule 1: the row that holds the caller's address stays.
	a.post(base+":delete", map[string]any{"ids": []string{mine.ID.String()}}).want(422, "validation_failed")
	a.do("PATCH", base+"/"+wide.ID.String(), map[string]any{"cleanup_opt_in": true}).want(200, "")
	var patched pAuthorized
	a.do("PATCH", base+"/"+wide.ID.String(), map[string]any{"cleanup_opt_in": false}).want(200, "").json(&patched)
	if patched.OptIn {
		t.Error("the opt-in did not turn off")
	}

	// Rule 2: with Require on, the last row stays.
	a.do("PATCH", "/endpoints/"+ep, map[string]any{"require_authorized_ips": true}).want(200, "")
	a.post(base+":delete", map[string]any{"ids": []string{wide.ID.String(), mine.ID.String()}}).want(422, "validation_failed")
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1`, []any{uuid.MustParse(ep)}, &n)
	if n != 2 {
		t.Errorf("a refused delete left %d rows", n)
	}
	a.post(base+":delete", map[string]any{"ids": []string{wide.ID.String()}}).want(204, "")

	// Another tenant's Endpoint and rows are 404.
	b.get(base).want(404, "not_found")
	b.post(base, map[string]any{"cidrs": []string{"198.18.0.0/16"}}).want(404, "not_found")
	b.post(base+":delete", map[string]any{"ids": []string{mine.ID.String()}}).want(404, "not_found")
	var bPage pAuthorizedPage
	b.get("/endpoints/"+f.env.B.Endpoint.String()+"/authorized-ips").want(200, "").json(&bPage)
	for _, r := range bPage.Items {
		if r.ID == mine.ID || r.ID == wide.ID {
			t.Error("B lists A's rows")
		}
	}
}

func TestDdnsHostFlow(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	ep := f.newEndpoint(a, "ddns")
	base := "/endpoints/" + ep + "/ddns-hosts"
	type host struct {
		ID       uuid.UUID `json:"id"`
		Hostname string    `json:"hostname"`
		LastIps  []string  `json:"last_ips"`
	}
	var h host
	a.post(base, map[string]any{"hostname": "Home.Example.ORG"}).want(201, "").json(&h)
	if h.Hostname != "home.example.org" || h.LastIps == nil {
		t.Errorf("host %+v", h)
	}
	a.post(base, map[string]any{"hostname": "home.example.org"}).want(422, "validation_failed")
	a.post(base, map[string]any{"hostname": "localhost"}).want(422, "validation_failed")
	var list struct {
		Hosts []host `json:"hosts"`
	}
	a.get(base).want(200, "").json(&list)
	if len(list.Hosts) != 1 {
		t.Errorf("%d hosts", len(list.Hosts))
	}
	// A host that learned rows takes them with it, and its address (the client's) refuses the delete.
	f.env.Exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, ddns_host_id) VALUES ($1, $2, $3::cidr, 'ddns', $4)`,
		A.Tenant, uuid.MustParse(ep), a.ip+"/32", h.ID)
	a.post(base+"/"+h.ID.String()+":delete", map[string]any{}).want(422, "validation_failed")
	f.env.Exec(t, `UPDATE ctrlz.authorized_ips SET cidr = '203.0.113.99/32' WHERE ddns_host_id = $1`, h.ID)
	a.post(base+"/"+h.ID.String()+":delete", map[string]any{}).want(204, "")
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1`, []any{uuid.MustParse(ep)}, &n)
	if n != 0 {
		t.Errorf("%d rows stayed with the host gone", n)
	}
	a.post(base+"/"+h.ID.String()+":delete", map[string]any{}).want(404, "not_found")
	b.get(base).want(404, "not_found")
	b.post(base, map[string]any{"hostname": "x.example.org"}).want(404, "not_found")
}

func TestClaimFlow(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := f.makeSession(A.Tenant, A.User)
	b := f.makeSession(B.Tenant, B.User)
	ep := f.newEndpoint(a, "claims")
	base := "/endpoints/" + ep + "/ip-claims"

	var c pClaim
	a.post(base, map[string]any{"cidr": "203.0.113.7"}).want(201, "").json(&c)
	if c.State != "active" || c.Proven || c.Cidr != "203.0.113.7/32" || c.Source != "manual" || c.NeedsAdmin {
		t.Fatalf("claim %+v", c)
	}
	// Each refusal of the table in 4.3 that needs no evidence.
	a.post(base, map[string]any{"cidr": "203.0.113.7"}).want(422, "validation_failed")
	a.post(base, map[string]any{"cidr": "10.1.2.3"}).want(422, "validation_failed")
	a.post(base, map[string]any{"cidr": "2001:db8::/64"}).want(422, "validation_failed")
	a.post(base, map[string]any{}).want(422, "validation_failed")
	a.post(base, map[string]any{"cidr": "203.0.115.1", "use_my_address": true}).want(422, "validation_failed")
	a.post(base, map[string]any{"cidr": "203.0.115.3/24"}).want(422, "validation_failed")
	// The address the panel saw is a /32 with source browser (4.2).
	var mine pClaim
	a.post(base, map[string]any{"use_my_address": true}).want(201, "").json(&mine)
	if mine.Cidr != a.ip+"/32" || mine.Source != "browser" {
		t.Errorf("use my address: %+v", mine)
	}

	// The proof dialog: a challenge with the values to prove with, the live one shows on the list, a take with no evidence is a
	// 200 that says so, and a take the hub's evidence backs proves the claim.
	var ch struct {
		ID       uuid.UUID `json:"id"`
		Label    string    `json:"label"`
		Commands struct {
			Ready  bool   `json:"ready"`
			Reason string `json:"reason"`
		} `json:"commands"`
	}
	a.post(base+"/"+c.ID.String()+"/challenges", nil).want(201, "").json(&ch)
	if len(ch.Label) != 26 || ch.Commands.Ready || ch.Commands.Reason != "zone_missing" {
		t.Errorf("challenge %+v", ch)
	}
	var list struct {
		Claims []pClaim `json:"claims"`
	}
	a.get(base).want(200, "").json(&list)
	live := false
	for _, x := range list.Claims {
		if x.ID == c.ID && x.Challenge != nil && x.Challenge.Label == ch.Label && !x.Challenge.Observed {
			live = true
		}
	}
	if !live || len(list.Claims) != 2 {
		t.Errorf("list %+v", list.Claims)
	}
	var tk struct {
		Claim   pClaim `json:"claim"`
		Outcome string `json:"outcome"`
	}
	a.post(base+"/"+c.ID.String()+":take", map[string]any{}).want(200, "").json(&tk)
	if tk.Outcome != "no_proof" || tk.Claim.Proven {
		t.Errorf("take without evidence %+v", tk)
	}
	f.env.Exec(t, `UPDATE ctrlz.ip_proof_challenges SET observed_at = now(), observed_ip = '203.0.113.7', observed_protocol = 'tcp' WHERE claim_id = $1`, c.ID)
	a.post(base+"/"+c.ID.String()+":take", map[string]any{}).want(200, "").json(&tk)
	if tk.Claim.State != "active" || !tk.Claim.Proven {
		t.Errorf("take with evidence %+v", tk)
	}

	// Another tenant: 404 on the Endpoint and the claim, and a request for a taken address waits for proof.
	b.get(base).want(404, "not_found")
	b.post(base+"/"+c.ID.String()+"/challenges", nil).want(404, "not_found")
	b.post(base+"/"+c.ID.String()+":release", map[string]any{}).want(404, "not_found")
	bEp := f.env.B.Endpoint.String()
	b.post("/endpoints/"+bEp+"/ip-claims/"+c.ID.String()+":take", map[string]any{}).want(404, "not_found")
	var theirs pClaim
	b.post("/endpoints/"+bEp+"/ip-claims", map[string]any{"cidr": "203.0.113.7"}).want(201, "").json(&theirs)
	if theirs.State != "pending_proof" {
		t.Errorf("B over a proven claim: %+v", theirs)
	}
	// The claim of A is proven and not idle: B's take is the generic refusal, and A's claim stays.
	f.env.Exec(t, `UPDATE ctrlz.ip_claims SET last_seen_at = now() WHERE id = $1`, c.ID)
	f.env.Exec(t, `INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, observed_at, observed_ip, observed_protocol, expires_at)
		VALUES ($1, $2, 'bbbbbbbbbbbbbbbbbbbbbbbbbb', now(), '203.0.113.7', 'tcp', now() + interval '10 minutes')`, B.Tenant, theirs.ID)
	b.post("/endpoints/"+bEp+"/ip-claims/"+theirs.ID.String()+":take", map[string]any{}).want(409, "ip_unavailable")

	// Release: 204, then it is gone, and a second release is 404.
	a.post(base+"/"+c.ID.String()+":release", map[string]any{}).want(204, "")
	a.post(base+"/"+c.ID.String()+":release", map[string]any{}).want(404, "not_found")
	// A suspended claim is not released by its tenant, and gets no challenge.
	f.env.Exec(t, `UPDATE ctrlz.ip_claims SET state = 'suspended' WHERE id = $1`, mine.ID)
	a.post(base+"/"+mine.ID.String()+":release", map[string]any{}).want(409, "ip_suspended")
	a.post(base+"/"+mine.ID.String()+"/challenges", nil).want(409, "ip_suspended")
}

// The tenant's hourly budget of the claim routes (spec 4.5): the thirty-first request of an hour is refused whatever session it
// comes from, and a refused request still counts, so a loop that makes and releases rows is bounded.
func TestClaimRoutesShareOneBudgetPerTenant(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	a := f.makeSession(A.Tenant, A.User)
	a2 := f.makeSession(A.Tenant, A.User)
	ep := f.newEndpoint(a, "budget")
	base := "/endpoints/" + ep + "/ip-claims"
	for i := 0; i < 30; i++ {
		// A reserved address is refused by the function with 422, after the charge.
		c := a
		if i%2 == 1 {
			c = a2
		}
		c.post(base, map[string]any{"cidr": fmt.Sprintf("10.0.0.%d", i+1)}).want(422, "validation_failed")
	}
	a.post(base, map[string]any{"cidr": "10.0.1.1"}).want(429, "rate_limited")
	a2.post(base, map[string]any{"cidr": "10.0.1.2"}).want(429, "rate_limited")
	// Another tenant has its own.
	b := f.makeSession(f.env.B.Tenant, f.env.B.User)
	b.post("/endpoints/"+f.env.B.Endpoint.String()+"/ip-claims", map[string]any{"cidr": "10.0.1.3"}).want(422, "validation_failed")
	// The hour passes.
	f.ck.add(time.Hour + time.Minute)
	a.post(base, map[string]any{"cidr": "10.0.1.4"}).want(422, "validation_failed")
}
