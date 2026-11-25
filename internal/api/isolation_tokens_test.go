package api

import (
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
)

// The isolation fixtures of the API token routes (docs/specs/p3-endpoints.md 6.4, 11.1, rule isolation-success-coverage). Each
// tenant is given a token through the route with a session that holds a live reauth window, so the value and the row are the ones
// a real create leaves, and a statement that lost its tenant or user predicate shows in B's answers or in A's digest.

// tokenState is what the Arrange of one tenant made.
type tokenState struct {
	id    string
	value string
}

// tokenCreated is the answer of POST /api-tokens.
type tokenCreated struct {
	Token struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Kind        string   `json:"kind"`
		TokenPrefix string   `json:"token_prefix"`
		AllowedIPs  []string `json:"allowed_ips"`
		Ended       bool     `json:"ended"`
		ExpiresAt   string   `json:"expires_at"`
		LastUsedAt  *string  `json:"last_used_at"`
		CreatedAt   string   `json:"created_at"`
	} `json:"token"`
	Value string `json:"value"`
}

func (e *isoEnv) tokenFixtures() map[string]isolation.Fixture {
	var st [2]tokenState
	b := func() *tn { return e.n[isolation.B] }

	// made gives the tenant a session with a live reauth window and one token, named for the tenant.
	made := func(w isolation.Who) {
		n := e.n[w]
		n.sess = e.session(n, true)
		var out tokenCreated
		n.sess.post("/api-tokens", map[string]any{"name": "iso " + w.String(), "kind": "write", "allowed_ips": []string{"203.0.113.0/24"}}).want(201, "").json(&out)
		st[w] = tokenState{id: out.Token.ID, value: out.Value}
		n.note(out.Token.ID)
		n.note(out.Value)
	}
	reauthed := func(w isolation.Who) { e.n[w].sess = e.session(e.n[w], true) }

	return map[string]isolation.Fixture{
		"listApiTokens": {Effect: isolation.Shows, Status: 200, Arrange: made,
			Sees: func() []string { return []string{st[isolation.B].id} },
			Call: func() isolation.Result { return result(b().sess.get("/api-tokens")) }},
		"createApiToken": {Effect: isolation.Changes, Status: 201, Arrange: reauthed,
			Call: func() isolation.Result {
				return result(b().sess.post("/api-tokens", map[string]any{"name": "iso new", "kind": "read"}))
			}},
		"patchApiToken": {Effect: isolation.Changes, Status: 200, Arrange: made,
			Call: func() isolation.Result {
				return result(b().sess.do("PATCH", "/api-tokens/"+st[isolation.B].id, map[string]any{"name": "renamed", "allowed_ips": []string{}}))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(b().sess.do("PATCH", "/api-tokens/"+st[isolation.A].id, map[string]any{"name": "renamed", "allowed_ips": []string{}}))
			}},
		"deleteApiToken": {Effect: isolation.Changes, Status: 204, Arrange: made,
			Call: func() isolation.Result {
				return result(b().sess.do("DELETE", "/api-tokens/"+st[isolation.B].id, nil))
			},
			CrossStatus: 404,
			Cross: func() isolation.Result {
				return result(b().sess.do("DELETE", "/api-tokens/"+st[isolation.A].id, nil))
			}},
	}
}
