package api

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// The isolation fixtures of the access routes (docs/specs/p3-endpoints.md 11.1, rule isolation-success-coverage): the Dynamic
// DNS hosts, the Authorized IPs and the Plain DNS claims of an Endpoint. For each operation B's call reaches a 2xx while A holds
// the same state, and every place the operation takes a row id has a call that puts A's id there with B's own session and is
// refused 404 with nothing of A's or B's changed.
//
// The rows are named for their tenant (a host, a prefix, a claim address), so what B's answers show is B's and never A's.

// accessState is what the Arrange of one tenant made.
type accessState struct {
	ep    uuid.UUID
	host  uuid.UUID
	auth  uuid.UUID
	auth2 uuid.UUID
	claim uuid.UUID
}

func (e *isoEnv) accessFixtures() map[string]isolation.Fixture {
	f := e.f
	var st [2]accessState
	seed := func(w isolation.Who) catalogtest.SeedIDs {
		if w == isolation.A {
			return f.env.A
		}
		return f.env.B
	}
	b := func() *tn { return e.n[isolation.B] }
	letter := func(w isolation.Who) string { return map[isolation.Who]string{isolation.A: "a", isolation.B: "b"}[w] }
	// The addresses of the tenant: A's are 203.0.113.x and B's 203.0.114.x, so no claim of one overlaps one of the other and no
	// prefix of the rows contains the address a test client comes from (198.51.x.9).
	third := func(w isolation.Who) int { return 113 + int(w) }

	// base is the Arrange every case starts from: the Endpoint tables of the tenant put back to the seed, a session, and one
	// Endpoint with two authorized rows, a DDNS host, an active unproven claim and a challenge that the hub saw.
	base := func(w isolation.Who) {
		s := seed(w)
		for _, sql := range []string{
			`DELETE FROM ctrlz.policy_outbox WHERE tenant_id = $1`,
			`DELETE FROM ctrlz.idempotency_keys WHERE tenant_id = $1`,
			`DELETE FROM ctrlz.endpoint_groups WHERE tenant_id = $1`,
			`DELETE FROM ctrlz.clients WHERE tenant_id = $1 AND source = 'manual'`,
			`DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1`,
		} {
			f.env.Exec(f.t, sql, s.Tenant)
		}
		f.env.Exec(f.t, `DELETE FROM ctrlz.endpoints WHERE tenant_id = $1 AND id <> $2`, s.Tenant, s.Endpoint)
		n := e.n[w]
		n.sess = e.session(n, false)
		id, err := uuid.NewV7()
		if err != nil {
			f.t.Fatal(err)
		}
		rid, err := identity.NewResolverID()
		if err != nil {
			f.t.Fatal(err)
		}
		f.env.Exec(f.t, `INSERT INTO ctrlz.endpoints (tenant_id, id, name, type, resolver_id, profile_id)
			VALUES ($1, $2, $3, (SELECT key FROM ctrlz.endpoint_types ORDER BY position LIMIT 1), $4, $5)`, s.Tenant, id, "access for tenant "+w.String(), rid, s.Profile)
		st[w].ep = id
		t3 := third(w)
		f.env.Scan(f.t, `INSERT INTO ctrlz.endpoint_ddns_hosts (tenant_id, endpoint_id, hostname) VALUES ($1, $2, $3) RETURNING id`,
			[]any{s.Tenant, id, "host-" + letter(w) + ".example.org"}, &st[w].host)
		f.env.Scan(f.t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr) VALUES ($1, $2, $3::cidr) RETURNING id`,
			[]any{s.Tenant, id, fmt.Sprintf("203.0.%d.0/24", t3)}, &st[w].auth)
		f.env.Scan(f.t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr) VALUES ($1, $2, $3::cidr) RETURNING id`,
			[]any{s.Tenant, id, fmt.Sprintf("192.0.%d.0/24", 2+int(w))}, &st[w].auth2)
		f.env.Scan(f.t, `INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source) VALUES ($1, $2, $3::cidr, 'active', 'manual') RETURNING id`,
			[]any{s.Tenant, id, fmt.Sprintf("203.0.%d.200/32", t3)}, &st[w].claim)
		f.env.Exec(f.t, `INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, observed_at, observed_ip, observed_protocol, expires_at)
			VALUES ($1, $2, $3, now(), $4::inet, 'tcp', now() + interval '10 minutes')`, s.Tenant, st[w].claim, "isoproof"+letter(w)+"aaaaaaaaaaaaaaaaa", fmt.Sprintf("203.0.%d.200", t3))
		n.note(fmt.Sprintf("host-%s.example.org", letter(w)))
	}
	pw := func(profile uuid.UUID) map[string]any {
		return map[string]any{"profile_id": profile.String(), "password": "not-the-password"}
	}
	sess := func() *client { return b().sess }
	A := f.env.A
	path := func(w isolation.Who, tail string) string { return fmt.Sprintf("/endpoints/%s%s", st[w].ep, tail) }
	seesHost := func() []string { return []string{"host-b.example.org"} }

	return map[string]isolation.Fixture{
		"listDdnsHosts": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: seesHost,
			Call:        func() isolation.Result { return result(sess().get(path(isolation.B, "/ddns-hosts"))) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(path(isolation.A, "/ddns-hosts"))) }},
		"createDdnsHost": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ddns-hosts"), map[string]any{"hostname": "new-b.example.org"}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.A, "/ddns-hosts"), map[string]any{"hostname": "new-b.example.org"}))
			}},
		"deleteDdnsHost": {Effect: isolation.Changes, Status: 204, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ddns-hosts/"+st[isolation.B].host.String()+":delete"), map[string]any{}))
			},
			CrossStatus: 404,
			// Sorted: body:lock_passwords[].profile_id, path:hid, path:id.
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ddns-hosts/"+st[isolation.B].host.String()+":delete"), map[string]any{"lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:hid": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/ddns-hosts/"+st[isolation.A].host.String()+":delete"), map[string]any{}))
				},
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, "/ddns-hosts/"+st[isolation.B].host.String()+":delete"), map[string]any{}))
				},
			}},
		"listAuthorizedIps": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: func() []string { return []string{"203.0.114.0/24"} },
			Call:        func() isolation.Result { return result(sess().get(path(isolation.B, "/authorized-ips"))) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(path(isolation.A, "/authorized-ips"))) },
			CrossAt: map[string]func() isolation.Result{
				"query:cursor": func() isolation.Result {
					return result(sess().get(path(isolation.B, "/authorized-ips?cursor="+encodeCursor(A.Tenant, f.ck.now(), st[isolation.A].auth))))
				},
			}},
		"addAuthorizedIps": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/authorized-ips"), map[string]any{"cidrs": []string{"203.0.114.77"}}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.A, "/authorized-ips"), map[string]any{"cidrs": []string{"203.0.114.77"}}))
			}},
		"patchAuthorizedIp": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("PATCH", path(isolation.B, "/authorized-ips/"+st[isolation.B].auth.String()), map[string]any{"cleanup_opt_in": true}))
			},
			CrossStatus: 404,
			// Sorted: body:lock_passwords[].profile_id, path:aid, path:id.
			Cross: func() isolation.Result {
				return result(sess().do("PATCH", path(isolation.B, "/authorized-ips/"+st[isolation.B].auth.String()), map[string]any{"cleanup_opt_in": true, "lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:aid": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.B, "/authorized-ips/"+st[isolation.A].auth.String()), map[string]any{"cleanup_opt_in": true}))
				},
				"path:id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.A, "/authorized-ips/"+st[isolation.B].auth.String()), map[string]any{"cleanup_opt_in": true}))
				},
			}},
		"deleteAuthorizedIps": {Effect: isolation.Changes, Status: 204, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/authorized-ips:delete"), map[string]any{"ids": []string{st[isolation.B].auth.String()}}))
			},
			CrossStatus: 404,
			// Sorted: body:ids[], body:lock_passwords[].profile_id, path:id.
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/authorized-ips:delete"), map[string]any{"ids": []string{st[isolation.A].auth.String()}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:lock_passwords[].profile_id": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/authorized-ips:delete"), map[string]any{"ids": []string{st[isolation.B].auth.String()},
						"lock_passwords": []map[string]any{pw(A.Profile)}}))
				},
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, "/authorized-ips:delete"), map[string]any{"ids": []string{st[isolation.B].auth.String()}}))
				},
			}},
		"listIpClaims": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: func() []string { return []string{"203.0.114.200/32"} },
			Call:        func() isolation.Result { return result(sess().get(path(isolation.B, "/ip-claims"))) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(path(isolation.A, "/ip-claims"))) }},
		"requestIpClaim": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ip-claims"), map[string]any{"cidr": "203.0.114.201"}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.A, "/ip-claims"), map[string]any{"cidr": "203.0.114.201"}))
			}},
		"openIpClaimChallenge": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ip-claims/"+st[isolation.B].claim.String()+"/challenges"), nil))
			},
			CrossStatus: 404,
			// Sorted: path:claim_id, path:id.
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ip-claims/"+st[isolation.A].claim.String()+"/challenges"), nil))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, "/ip-claims/"+st[isolation.B].claim.String()+"/challenges"), nil))
				},
			}},
		"takeIpClaim": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ip-claims/"+st[isolation.B].claim.String()+":take"), map[string]any{}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ip-claims/"+st[isolation.A].claim.String()+":take"), map[string]any{}))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, "/ip-claims/"+st[isolation.B].claim.String()+":take"), map[string]any{}))
				},
			}},
		"releaseIpClaim": {Effect: isolation.Changes, Status: 204, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ip-claims/"+st[isolation.B].claim.String()+":release"), map[string]any{}))
			},
			CrossStatus: 404,
			// Sorted: body:lock_passwords[].profile_id, path:claim_id, path:id.
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/ip-claims/"+st[isolation.B].claim.String()+":release"), map[string]any{"lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:claim_id": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/ip-claims/"+st[isolation.A].claim.String()+":release"), map[string]any{}))
				},
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, "/ip-claims/"+st[isolation.B].claim.String()+":release"), map[string]any{}))
				},
			}},
	}
}

// cleanEndpointTables puts the Endpoint tables of the tenant back to the seed's Endpoint alone: the harness resets the tables it
// knows, and an Endpoint case leaves its groups, clients, windows and Endpoints (with the authorized rows, hosts and claims hung on
// them) behind, one side changed by the call and the other not. Both tenants are cleaned the same way, so the next case starts from
// one state whatever it is.
func (e *isoEnv) cleanEndpointTables(w isolation.Who) {
	f := e.f
	s := f.env.A
	if w == isolation.B {
		s = f.env.B
	}
	// One statement each: a statement with parameters is prepared, and a prepared statement is one command.
	for _, sql := range []string{
		`DELETE FROM ctrlz.policy_outbox WHERE tenant_id = $1`,
		`DELETE FROM ctrlz.idempotency_keys WHERE tenant_id = $1`,
		`DELETE FROM ctrlz.endpoint_groups WHERE tenant_id = $1`,
		`DELETE FROM ctrlz.clients WHERE tenant_id = $1 AND source = 'manual'`,
		`DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1`,
	} {
		f.env.Exec(f.t, sql, s.Tenant)
	}
	f.env.Exec(f.t, `DELETE FROM ctrlz.endpoints WHERE tenant_id = $1 AND id <> $2`, s.Tenant, s.Endpoint)
}
