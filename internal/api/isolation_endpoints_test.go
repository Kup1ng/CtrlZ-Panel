package api

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/identity"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// The isolation fixtures of the Endpoint routes (docs/specs/p3-endpoints.md 11.1, rule isolation-success-coverage): for each
// operation, B's call reaches a 2xx while A holds the same state, and every place the operation takes a row id has a call that
// puts A's id there with B's own session and is refused 404 with nothing of A's or B's changed.
//
// The harness resets the tables it knows (sessions, tokens, codes) between two cases and no others, so each Arrange here begins
// by putting the Endpoint tables of its tenant back to the seed, and builds what the case needs with the same statements for
// both tenants, which is what makes A's state B's state.

// epState is what the Arrange of one tenant made.
type epState struct {
	ep, ep2 uuid.UUID
	group   uuid.UUID
	client  uuid.UUID
	window  uuid.UUID
}

func (e *isoEnv) endpointFixtures() map[string]isolation.Fixture {
	f := e.f
	var st [2]epState
	seed := func(w isolation.Who) catalogtest.SeedIDs {
		if w == isolation.A {
			return f.env.A
		}
		return f.env.B
	}
	a := func() *tn { return e.n[isolation.A] }
	b := func() *tn { return e.n[isolation.B] }

	// clean puts the Endpoint tables of the tenant back to the seed: the seeded Endpoint stays, whatever a case made goes.
	clean := func(w isolation.Who) {
		s := seed(w)
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
	mkEndpoint := func(w isolation.Who, name string) uuid.UUID {
		s := seed(w)
		id, err := uuid.NewV7()
		if err != nil {
			f.t.Fatal(err)
		}
		rid, err := identity.NewResolverID()
		if err != nil {
			f.t.Fatal(err)
		}
		f.env.Exec(f.t, `INSERT INTO ctrlz.endpoints (tenant_id, id, name, type, resolver_id, profile_id)
			VALUES ($1, $2, $3, (SELECT key FROM ctrlz.endpoint_types ORDER BY position LIMIT 1), $4, $5)`, s.Tenant, id, name, rid, s.Profile)
		return id
	}
	mkGroup := func(w isolation.Who, name string) uuid.UUID {
		var id uuid.UUID
		f.env.Scan(f.t, `INSERT INTO ctrlz.endpoint_groups (tenant_id, name) VALUES ($1, $2) RETURNING id`, []any{seed(w).Tenant, name}, &id)
		return id
	}
	// base is the Arrange every case starts from: a clean tenant, a session, and one Endpoint, one group, one client and one
	// window of its own, named for the tenant, so what B's answers show is B's and never A's.
	base := func(w isolation.Who) {
		clean(w)
		s := seed(w)
		n := e.n[w]
		n.sess = e.session(n, false)
		label := "only for tenant " + w.String()
		st[w].ep = mkEndpoint(w, label)
		st[w].ep2 = mkEndpoint(w, label+" two")
		st[w].group = mkGroup(w, label)
		f.env.Exec(f.t, `UPDATE ctrlz.endpoints SET group_id = $3 WHERE tenant_id = $1 AND id = $2`, s.Tenant, st[w].ep2, st[w].group)
		f.env.Scan(f.t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, alias, source, is_custom) VALUES ($1, $2, 'kid', $3, 'manual', true) RETURNING id`,
			[]any{s.Tenant, st[w].ep, label}, &st[w].client)
		f.env.Scan(f.t, `INSERT INTO ctrlz.schedule_windows (tenant_id, endpoint_id, minutes, profile_id) VALUES ($1, $2, int4range(60, 120, '[)'), $3) RETURNING id`,
			[]any{s.Tenant, st[w].ep, s.Profile}, &st[w].window)
		n.note(st[w].ep.String())
		n.note(st[w].group.String())
	}
	var typ string
	f.env.Scan(f.t, `SELECT key FROM ctrlz.endpoint_types ORDER BY position LIMIT 1`, nil, &typ)
	sees := func() []string { return []string{"only for tenant B"} }
	sess := func() *client { return b().sess }
	idem := func(key string) map[string]string { return map[string]string{"Idempotency-Key": key} }
	pw := func(profile uuid.UUID) map[string]any {
		return map[string]any{"profile_id": profile.String(), "password": "not-the-password"}
	}
	A, B := f.env.A, f.env.B
	path := func(w isolation.Who, tail string) string { return fmt.Sprintf("/endpoints/%s%s", st[w].ep, tail) }

	return map[string]isolation.Fixture{
		"listEndpointTypes": {Effect: isolation.Shows, Status: 200, Arrange: base,
			Call: func() isolation.Result { return result(sess().get("/endpoint-types")) }},
		"listTimezones": {Effect: isolation.Shows, Status: 200, Arrange: base,
			Call: func() isolation.Result { return result(sess().get("/catalog/timezones")) }},
		"listEndpoints": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: sees,
			Call:        func() isolation.Result { return result(sess().get("/endpoints?sort=name")) },
			CrossStatus: 404,
			// A position and a group of A's, each with B's own session.
			Cross: func() isolation.Result {
				return result(sess().get("/endpoints?cursor=" + encodeListCursor(A.Tenant, false, f.ck.now(), "", st[isolation.A].ep)))
			},
			CrossAt: map[string]func() isolation.Result{
				"query:group": func() isolation.Result {
					return result(sess().get("/endpoints?group=" + st[isolation.A].group.String()))
				},
			}},
		"createEndpoints": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"new one"}, "profile_id": B.Profile.String()}, idem("iso-create")))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"x"}, "profile_id": B.Profile.String(),
					"group_id": st[isolation.A].group.String()}, idem("iso-cross-group")))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:profile2_id": func() isolation.Result {
					return result(sess().do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"x"}, "profile_id": B.Profile.String(),
						"profile2_id": A.Profile2.String()}, idem("iso-cross-p2")))
				},
				"body:profile_id": func() isolation.Result {
					return result(sess().do("POST", "/endpoints", map[string]any{"type": typ, "names": []string{"x"}, "profile_id": A.Profile.String()}, idem("iso-cross-p1")))
				},
			}},
		"exportEndpoints": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: sees,
			Call: func() isolation.Result { return result(sess().get("/endpoints/export")) }},
		"batchEndpoints": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post("/endpoints:batch", map[string]any{"op": "move", "ids": []string{st[isolation.B].ep.String()}, "group_id": st[isolation.B].group.String()}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post("/endpoints:batch", map[string]any{"op": "move", "ids": []string{st[isolation.B].ep.String()}, "group_id": st[isolation.A].group.String()}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:ids[]": func() isolation.Result {
					return result(sess().post("/endpoints:batch", map[string]any{"op": "move", "ids": []string{st[isolation.A].ep.String()}, "group_id": st[isolation.B].group.String()}))
				},
				"body:lock_passwords[].profile_id": func() isolation.Result {
					return result(sess().post("/endpoints:batch", map[string]any{"op": "delete", "ids": []string{st[isolation.B].ep.String()},
						"lock_passwords": []map[string]any{pw(A.Profile)}}))
				},
				"body:set.profile2_id": func() isolation.Result {
					return result(sess().post("/endpoints:batch", map[string]any{"op": "edit", "ids": []string{st[isolation.B].ep.String()},
						"set": map[string]any{"profile2_id": A.Profile2.String()}}))
				},
				"body:set.profile_id": func() isolation.Result {
					return result(sess().post("/endpoints:batch", map[string]any{"op": "edit", "ids": []string{st[isolation.B].ep.String()},
						"set": map[string]any{"profile_id": A.Profile.String()}}))
				},
			}},
		"getEndpoint": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: sees,
			Call:        func() isolation.Result { return result(sess().get(path(isolation.B, ""))) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(path(isolation.A, ""))) }},
		"patchEndpoint": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("PATCH", path(isolation.B, ""), map[string]any{"name": "renamed by B", "comment": "note"}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().do("PATCH", path(isolation.B, ""), map[string]any{"group_id": st[isolation.A].group.String()}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:lock_passwords[].profile_id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.B, ""), map[string]any{"name": "x", "lock_passwords": []map[string]any{pw(A.Profile)}}))
				},
				"body:profile2_id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.B, ""), map[string]any{"profile2_id": A.Profile2.String()}))
				},
				"body:profile_id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.B, ""), map[string]any{"profile_id": A.Profile.String()}))
				},
				"path:id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.A, ""), map[string]any{"name": "x"}))
				},
			}},
		"deleteEndpoint": {Effect: isolation.Changes, Status: 204, Arrange: base,
			Call:        func() isolation.Result { return result(sess().post(path(isolation.B, ":delete"), map[string]any{})) },
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, ":delete"), map[string]any{"lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:id": func() isolation.Result { return result(sess().post(path(isolation.A, ":delete"), map[string]any{})) },
			}},
		"rotateEndpointResolver": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, ":rotate-resolver"), map[string]any{}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, ":rotate-resolver"), map[string]any{"lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, ":rotate-resolver"), map[string]any{}))
				},
			}},
		"getEndpointSchedule": {Effect: isolation.Shows, Status: 200, Arrange: base,
			Call:        func() isolation.Result { return result(sess().get(path(isolation.B, "/schedule"))) },
			CrossStatus: 404,
			Cross:       func() isolation.Result { return result(sess().get(path(isolation.A, "/schedule"))) }},
		"putEndpointSchedule": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("PUT", path(isolation.B, "/schedule"), map[string]any{"timezone": "Asia/Tehran",
					"windows": []map[string]any{{"start": 0, "end": 60, "profile_id": B.Profile.String()}}}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().do("PUT", path(isolation.B, "/schedule"), map[string]any{"timezone": "Asia/Tehran", "windows": []map[string]any{},
					"lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:windows[].id": func() isolation.Result {
					return result(sess().do("PUT", path(isolation.B, "/schedule"), map[string]any{"timezone": "Asia/Tehran",
						"windows": []map[string]any{{"id": st[isolation.A].window.String(), "start": 0, "end": 60, "profile_id": B.Profile.String()}}}))
				},
				"body:windows[].profile2_id": func() isolation.Result {
					return result(sess().do("PUT", path(isolation.B, "/schedule"), map[string]any{"timezone": "Asia/Tehran",
						"windows": []map[string]any{{"start": 0, "end": 60, "profile_id": B.Profile.String(), "profile2_id": A.Profile2.String()}}}))
				},
				"body:windows[].profile_id": func() isolation.Result {
					return result(sess().do("PUT", path(isolation.B, "/schedule"), map[string]any{"timezone": "Asia/Tehran",
						"windows": []map[string]any{{"start": 0, "end": 60, "profile_id": A.Profile.String()}}}))
				},
				"path:id": func() isolation.Result {
					return result(sess().do("PUT", path(isolation.A, "/schedule"), map[string]any{"timezone": "Asia/Tehran", "windows": []map[string]any{}}))
				},
			}},
		"listEndpointGroups": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: sees,
			Call: func() isolation.Result { return result(sess().get("/endpoint-groups")) }},
		"createEndpointGroup": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post("/endpoint-groups", map[string]any{"name": "new group", "endpoint_ids": []string{st[isolation.B].ep.String()}}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post("/endpoint-groups", map[string]any{"name": "x", "endpoint_ids": []string{st[isolation.A].ep.String()}}))
			}},
		"patchEndpointGroup": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("PATCH", "/endpoint-groups/"+st[isolation.B].group.String(), map[string]any{"name": "renamed"}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().do("PATCH", "/endpoint-groups/"+st[isolation.A].group.String(), map[string]any{"name": "renamed"}))
			}},
		"deleteEndpointGroup": {Effect: isolation.Changes, Status: 204, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("DELETE", "/endpoint-groups/"+st[isolation.B].group.String(), nil))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().do("DELETE", "/endpoint-groups/"+st[isolation.A].group.String(), nil))
			}},
		"listClients": {Effect: isolation.Shows, Status: 200, Arrange: base, Sees: sees,
			Call:        func() isolation.Result { return result(sess().get(path(isolation.B, "/clients"))) },
			CrossStatus: 404,
			// First place sorted is path:id.
			Cross: func() isolation.Result { return result(sess().get(path(isolation.A, "/clients"))) },
			CrossAt: map[string]func() isolation.Result{
				"query:cursor": func() isolation.Result {
					return result(sess().get(path(isolation.B, "/clients?cursor="+a().cursorOf(A.Tenant))))
				},
			}},
		"createClient": {Effect: isolation.Changes, Status: 201, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/clients"), map[string]any{"alias": "laptop", "profile_id": B.Profile.String()}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/clients"), map[string]any{"alias": "x", "lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:profile2_id": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/clients"), map[string]any{"alias": "x", "profile_id": B.Profile.String(), "profile2_id": A.Profile2.String()}))
				},
				"body:profile_id": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/clients"), map[string]any{"alias": "x", "profile_id": A.Profile.String()}))
				},
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, "/clients"), map[string]any{"alias": "x"}))
				},
			}},
		"patchClient": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().do("PATCH", path(isolation.B, "/clients/"+st[isolation.B].client.String()), map[string]any{"alias": "renamed", "profile_id": B.Profile.String()}))
			},
			CrossStatus: 404,
			// Sorted: lock_passwords[].profile_id, profile2_id, profile_id, path:cid, path:id.
			Cross: func() isolation.Result {
				return result(sess().do("PATCH", path(isolation.B, "/clients/"+st[isolation.B].client.String()), map[string]any{"alias": "x", "lock_passwords": []map[string]any{pw(A.Profile)}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:profile2_id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.B, "/clients/"+st[isolation.B].client.String()), map[string]any{"profile_id": B.Profile.String(), "profile2_id": A.Profile2.String()}))
				},
				"body:profile_id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.B, "/clients/"+st[isolation.B].client.String()), map[string]any{"profile_id": A.Profile.String()}))
				},
				"path:cid": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.B, "/clients/"+st[isolation.A].client.String()), map[string]any{"alias": "x"}))
				},
				"path:id": func() isolation.Result {
					return result(sess().do("PATCH", path(isolation.A, "/clients/"+st[isolation.B].client.String()), map[string]any{"alias": "x"}))
				},
			}},
		"batchClients": {Effect: isolation.Changes, Status: 200, Arrange: base,
			Call: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/clients:batch"), map[string]any{"op": "edit", "ids": []string{st[isolation.B].client.String()},
					"set": map[string]any{"alias": "bulk", "profile_id": B.Profile.String()}}))
			},
			CrossStatus: 404,
			// Sorted: ids[], lock_passwords[].profile_id, set.profile2_id, set.profile_id, path:id.
			Cross: func() isolation.Result {
				return result(sess().post(path(isolation.B, "/clients:batch"), map[string]any{"op": "delete", "ids": []string{st[isolation.A].client.String()}}))
			},
			CrossAt: map[string]func() isolation.Result{
				"body:lock_passwords[].profile_id": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/clients:batch"), map[string]any{"op": "delete", "ids": []string{st[isolation.B].client.String()},
						"lock_passwords": []map[string]any{pw(A.Profile)}}))
				},
				"body:set.profile2_id": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/clients:batch"), map[string]any{"op": "edit", "ids": []string{st[isolation.B].client.String()},
						"set": map[string]any{"profile_id": B.Profile.String(), "profile2_id": A.Profile2.String()}}))
				},
				"body:set.profile_id": func() isolation.Result {
					return result(sess().post(path(isolation.B, "/clients:batch"), map[string]any{"op": "edit", "ids": []string{st[isolation.B].client.String()},
						"set": map[string]any{"profile_id": A.Profile.String()}}))
				},
				"path:id": func() isolation.Result {
					return result(sess().post(path(isolation.A, "/clients:batch"), map[string]any{"op": "delete", "ids": []string{st[isolation.B].client.String()}}))
				},
			}},
	}
}
