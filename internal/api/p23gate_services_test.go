package api

import (
	"testing"
)

type bypassFlags struct {
	Slug          string `json:"slug"`
	Action        string `json:"action"`
	IranianBypass bool   `json:"iranian_bypass"`
}

// TestIranianBypassOnServicesAndCatalogNames: a Redirect on a service whose catalog row says redirect_allowed is false, and a
// Redirect rule on a name in catalog_no_redirect_domain that is not under .ir, list iranian_bypass true; a Block on either, and a
// Redirect on a service or name the catalog allows, list false; tenant B's rows carry B's own flags and are not in A's list
// (spec 3.6, 10.4, T-525). The rows are planted because a write of such a Redirect is refused (D42): they are the rows a catalog
// update leaves behind. Drop the redirect_allowed lookup of serviceOut and the first service comes back false; drop the action
// test and the Block comes back true.
func TestIranianBypassOnServicesAndCatalogNames(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A, B := f.env.A, f.env.B
	a := func() *client { return f.fresh(A.Tenant, A.User) }
	b := func() *client { return f.fresh(B.Tenant, B.User) }
	p := a().mustProfile("Bypass on services", "custom")
	pb := b().mustProfile("Bypass on services B", "custom")

	plantService := func(tenant, profile any, slug, action string) {
		t.Helper()
		if action == "redirect" {
			f.env.Exec(t, `INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, action, target_kind, target_host) VALUES ($1, $2, $3, 'redirect', 'host', 'proxy.example.net')`, tenant, profile, slug)
			return
		}
		f.env.Exec(t, `INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, action) VALUES ($1, $2, $3, $4)`, tenant, profile, slug, action)
	}
	plantRule := func(tenant, profile any, key, action string) {
		t.Helper()
		if action == "redirect" {
			f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host) VALUES ($1, $2, $3, 'domain', 'redirect', 'host', 'proxy.example.net')`, tenant, profile, key)
			return
		}
		f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action) VALUES ($1, $2, $3, 'domain', $4)`, tenant, profile, key, action)
	}
	plantService(A.Tenant, p.ID, "digikala", "redirect") // redirect_allowed is false
	plantService(A.Tenant, p.ID, "snapp", "block")       // the same service class, but a Block
	plantService(A.Tenant, p.ID, "youtube", "redirect")  // a service that allows a Redirect
	plantRule(A.Tenant, p.ID, "aparat.com", "redirect")  // in catalog_no_redirect_domain, not under .ir
	plantRule(A.Tenant, p.ID, "aparatsport.com", "block")
	plantRule(A.Tenant, p.ID, "plain-example.com", "redirect")
	// Tenant B redirects the same Iranian service on its own profile, and blocks the other.
	plantService(B.Tenant, pb.ID, "digikala", "redirect")
	plantService(B.Tenant, pb.ID, "youtube", "block")

	var list struct {
		Services []bypassFlags `json:"services"`
	}
	a().get("/profiles/"+p.ID.String()+"/services").want(200, "").json(&list)
	want := map[string]bool{"digikala": true, "snapp": false, "youtube": false}
	seen := 0
	for _, s := range list.Services {
		if w, ok := want[s.Slug]; ok {
			seen++
			if s.IranianBypass != w {
				t.Errorf("service %s (%s): iranian_bypass %v, want %v", s.Slug, s.Action, s.IranianBypass, w)
			}
		}
	}
	if seen != len(want) {
		t.Fatalf("the list holds %d of the three planted services: %+v", seen, list.Services)
	}

	var rules struct {
		Items []struct {
			Pattern       string `json:"pattern"`
			IranianBypass bool   `json:"iranian_bypass"`
		} `json:"items"`
	}
	a().get("/profiles/"+p.ID.String()+"/rules").want(200, "").json(&rules)
	wantRules := map[string]bool{"aparat.com": true, "aparatsport.com": false, "plain-example.com": false}
	seen = 0
	for _, r := range rules.Items {
		if w, ok := wantRules[r.Pattern]; ok {
			seen++
			if r.IranianBypass != w {
				t.Errorf("rule %s: iranian_bypass %v, want %v", r.Pattern, r.IranianBypass, w)
			}
		}
	}
	if seen != len(wantRules) {
		t.Fatalf("the list holds %d of the three planted rules: %+v", seen, rules.Items)
	}

	// The write route answers the flag of the row it wrote: a Redirect on a service that allows it is not one.
	var one bypassFlags
	a().do("PUT", "/profiles/"+p.ID.String()+"/services/hulu", map[string]any{"enabled": true, "action": "redirect",
		"target": map[string]any{"kind": "host", "host": "proxy.example.net"}}).want(200, "").json(&one)
	if one.Slug != "hulu" || one.IranianBypass {
		t.Errorf("a Redirect on an allowed service answers %+v", one)
	}

	// Tenant B: its own flags, and A's profile is not found.
	b().get("/profiles/"+pb.ID.String()+"/services").want(200, "").json(&list)
	for _, s := range list.Services {
		switch s.Slug {
		case "digikala":
			if !s.IranianBypass {
				t.Error("tenant B's Redirect on digikala is not flagged")
			}
		case "youtube":
			if s.IranianBypass || s.Action != "block" {
				t.Errorf("tenant B's youtube row: %+v", s)
			}
		case "snapp", "hulu":
			t.Errorf("tenant B lists A's service %s", s.Slug)
		}
	}
	b().get("/profiles/"+p.ID.String()+"/services").want(404, "not_found")
}
