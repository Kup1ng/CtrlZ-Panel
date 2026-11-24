package api

import (
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
)

// The isolation fixtures of the Resolver view, the generators and the links (docs/specs/p3-endpoints.md 11.1, rule
// isolation-success-coverage). They are in a file of their own, as the Endpoint routes' are (isolation_endpoints_test.go).
//
// The three public operations carry a bearer value and no session, and name no row by an id the client chooses (the value is a
// proof its holder owns, and the harness lists no Cross call for it): their cases show that B's value changes B's own rows and
// none of A's. What a value of A reaches is judged by TestLinksOfOneTenantReachOnlyItsEndpoint and the oracle test.

// linkState is what the Arrange of one tenant made.
type linkState struct {
	ep       uuid.UUID
	resolver string
	link     uuid.UUID // a share link of ep
	share    string    // its value
	download string    // the value of an Apple link of ep
	folder   uuid.UUID
}

func (e *isoEnv) linkFixtures() map[string]isolation.Fixture {
	f := e.f
	var st [2]linkState
	seed := func(w isolation.Who) (tenant, profile uuid.UUID) {
		if w == isolation.A {
			return f.env.A.Tenant, f.env.A.Profile
		}
		return f.env.B.Tenant, f.env.B.Profile
	}
	b := func() *tn { return e.n[isolation.B] }
	sess := func() *client { return b().sess }

	// clean puts the Endpoint tables of the tenant back to the seed, as the Endpoint fixtures do: whatever a case made goes, and
	// the cascade takes its links with it.
	clean := func(w isolation.Who) {
		tenant, _ := seed(w)
		for _, sql := range []string{
			`DELETE FROM ctrlz.policy_outbox WHERE tenant_id = $1`,
			`DELETE FROM ctrlz.idempotency_keys WHERE tenant_id = $1`,
			`DELETE FROM ctrlz.endpoint_groups WHERE tenant_id = $1`,
			`DELETE FROM ctrlz.clients WHERE tenant_id = $1 AND source = 'manual'`,
			`DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1`,
		} {
			f.env.Exec(f.t, sql, tenant)
		}
		seeded := f.env.A.Endpoint
		if w == isolation.B {
			seeded = f.env.B.Endpoint
		}
		f.env.Exec(f.t, `DELETE FROM ctrlz.endpoints WHERE tenant_id = $1 AND id <> $2`, tenant, seeded)
	}
	// base is the Arrange every case starts from: a clean tenant, a session, a zone, and an Endpoint made through the route (so its
	// DoH token is sealed under the keys of the api) with a share link and an Apple link, named for the tenant.
	base := func(w isolation.Who) {
		clean(w)
		tenant, profile := seed(w)
		n := e.n[w]
		n.sess = e.session(n, false)
		f.env.Exec(f.t, `UPDATE ctrlz.domain_settings SET dns_zone = 'dns.isolation.example.test'`)
		var created struct {
			Endpoints []pEndpoint `json:"endpoints"`
		}
		r := n.sess.do("POST", "/endpoints", map[string]any{"type": f.endpointType(), "names": []string{"only for tenant " + w.String()}, "profile_id": profile.String()},
			map[string]string{"Idempotency-Key": "iso-links-ep"})
		if r.Code != 201 {
			f.t.Fatalf("an Endpoint for the link fixtures: %d %s", r.Code, r.Body)
		}
		r.json(&created)
		st[w].ep, st[w].resolver = created.Endpoints[0].ID, created.Endpoints[0].ResolverID
		n.note(st[w].ep.String())
		n.note(st[w].resolver)
		var sl pLinkURL
		n.sess.post("/endpoints/"+st[w].ep.String()+"/share-links", map[string]any{}).want(201, "").json(&sl)
		st[w].link, st[w].share = sl.Link.ID, valueOf(f.t, sl.URL)
		var al pLinkURL
		n.sess.post("/endpoints/"+st[w].ep.String()+"/apple-profile", map[string]any{"protocol": "doh"}).want(201, "").json(&al)
		st[w].download = valueOf(f.t, al.URL)
		f.env.Scan(f.t, `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name) VALUES ($1, $2, $3) RETURNING id`, []any{tenant, profile, "folder " + w.String()}, &st[w].folder)
		n.note(st[w].link.String())
		n.note(st[w].share)
		n.note(st[w].download)
	}
	ep := func(w isolation.Who) string { return "/endpoints/" + st[w].ep.String() }
	sees := func() []string { return []string{st[isolation.B].resolver} }
	anon := func() *client { return f.client() }

	return map[string]isolation.Fixture{
		"getEndpointResolvers": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: sees,
			Call:        func() isolation.Result { return result(sess().get(ep(isolation.B) + "/resolvers")) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(ep(isolation.A) + "/resolvers")) }},
		"getEndpointGenerator": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: sees,
			Call:        func() isolation.Result { return result(sess().get(ep(isolation.B) + "/generators/windows-doh")) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(ep(isolation.A) + "/generators/windows-doh")) }},
		"listShareLinks": {Effect: isolation.Shows, Status: 200, Arrange: base,
			Sees:        func() []string { return []string{st[isolation.B].link.String()} },
			Call:        func() isolation.Result { return result(sess().get(ep(isolation.B) + "/share-links")) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(ep(isolation.A) + "/share-links")) }},
		"createShareLink": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(ep(isolation.B)+"/share-links", map[string]any{"client": "kid"}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(ep(isolation.A)+"/share-links", map[string]any{"client": "kid"}))
			}},
		"revokeShareLink": {Effect: isolation.Changes, Status: 204, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("DELETE", ep(isolation.B)+"/share-links/"+st[isolation.B].link.String(), nil))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().do("DELETE", ep(isolation.A)+"/share-links/"+st[isolation.B].link.String(), nil))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:sid": func() isolation.Result {
					return result(sess().do("DELETE", ep(isolation.B)+"/share-links/"+st[isolation.A].link.String(), nil))
				},
			}},
		"createAppleProfile": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(ep(isolation.B)+"/apple-profile", map[string]any{"protocol": "dot", "from_folder_id": st[isolation.B].folder.String()}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(ep(isolation.A)+"/apple-profile", map[string]any{"protocol": "dot", "from_folder_id": st[isolation.B].folder.String()}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:from_folder_id": func() isolation.Result {
					return result(sess().post(ep(isolation.B)+"/apple-profile", map[string]any{"protocol": "dot", "from_folder_id": st[isolation.A].folder.String()}))
				},
			}},
		"openShare": {Effect: isolation.Changes, Status: 200, Arrange: base, Sees: sees,
			Call: func() isolation.Result {
				return result(anon().post("/public/share", map[string]any{"link": st[isolation.B].share}))
			}},
		"createShareAppleProfile": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(anon().post("/public/share/apple-profile", map[string]any{"link": st[isolation.B].share, "params": map[string]any{"protocol": "doh"}}))
			}},
		"downloadAppleProfile": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(anon().get("/public/apple-profile/" + st[isolation.B].download))
			}},
	}
}
