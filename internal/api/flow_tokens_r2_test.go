package api

import (
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// TestTokenCrossTenant is docs/specs/p3-endpoints.md 11.1, "a token of one tenant never reaches the rows of another on any
// operation" (D69 round 2, p3-D5-r2-1). TestAPITokenPath covers the profile ids only; the Endpoint, client, group, DDNS host,
// authorized address, claim and link operations have their cross-tenant calls in the isolation fixtures, which are written with a
// session. This replays every one of those calls with a write token of tenant B in place of B's session, with A's ids, and asks
// what the harness asks of a session: the refusal the fixture names, and no row of A or B changed.
//
// The fixtures reach B's caller through b().sess, so the token client takes that place after Arrange. An operation whose
// x-ctrlz-token is none is not reachable with a token and is skipped (its refusal is E1's). A call that carries lock_passwords is
// 403 token_not_allowed before any read (3.3), which says nothing of the id, so it must be that refusal and nothing else; the
// calls without it must be exactly the status the session gets.
func TestTokenCrossTenant(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	e := newIsoEnv(f)
	A := f.env.A

	docOps, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	tokenOf := map[string]string{}
	for _, op := range docOps {
		tokenOf[op.ID] = op.Token
	}

	fixtures := map[string]isolation.Fixture{}
	maps.Copy(fixtures, e.endpointFixtures())
	maps.Copy(fixtures, e.accessFixtures())
	maps.Copy(fixtures, e.linkFixtures())
	ids := make([]string, 0, len(fixtures))
	for id := range fixtures {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// One token for the caller, made once: the token-create budget (20 a day) is not for a case each, and a token named ci is the
	// one the Endpoint reset leaves in place. Nothing a reset does ends it.
	value, _ := r.make(r.b, map[string]any{"name": "ci", "kind": "write"})
	caller := r.bearer(value, "")

	// sameExcept is the digest comparison of the harness: the tables a refused call may still change are left out.
	sameExcept := func(before, after map[string]string, skip []string) string {
		var bad []string
		for tbl, d := range before {
			if after[tbl] != d && !slices.Contains(skip, tbl) {
				bad = append(bad, tbl)
			}
		}
		for tbl := range after {
			if _, ok := before[tbl]; !ok && !slices.Contains(skip, tbl) {
				bad = append(bad, tbl)
			}
		}
		sort.Strings(bad)
		return strings.Join(bad, ", ")
	}

	replayed, exact, locked := 0, 0, 0
	seen := map[string]bool{}
	for _, id := range ids {
		fx := fixtures[id]
		if fx.Cross == nil || tokenOf[id] == "none" || tokenOf[id] == "" {
			continue
		}
		replayed++
		seen[id] = true
		t.Run(id, func(t *testing.T) {
			e.reset(isolation.A)
			e.reset(isolation.B)
			fx.Arrange(isolation.A)
			fx.Arrange(isolation.B)
			e.n[isolation.B].sess = caller

			// The first request of a window writes last_used_at of the token (B's row): make it now, so the digests below see a token
			// row that a refused call has no reason to move.
			caller.get("/account/limits").want(200, "")
			a0, b0 := e.db.Digest(isolation.A), e.db.Digest(isolation.B)

			type call struct {
				place  string
				fn     func() isolation.Result
				status int
			}
			calls := []call{{"cross", fx.Cross, fx.CrossStatus}}
			places := make([]string, 0, len(fx.CrossAt))
			for k := range fx.CrossAt {
				places = append(places, k)
			}
			sort.Strings(places)
			for _, k := range places {
				st := fx.CrossStatus
				if s, ok := fx.CrossAtStatus[k]; ok {
					st = s
				}
				calls = append(calls, call{k, fx.CrossAt[k], st})
			}
			for _, c := range calls {
				got := c.fn()
				if caller.lockSent {
					locked++
					if got.Status != 403 || !strings.Contains(string(got.Body), "token_not_allowed") {
						t.Errorf("%s: a token request with lock_passwords answered %d %s, want 403 token_not_allowed", c.place, got.Status, got.Body)
					}
				} else {
					exact++
					if got.Status != c.status {
						t.Errorf("%s: A's id with B's token answered %d %s, want %d", c.place, got.Status, got.Body, c.status)
					}
				}
				for _, leak := range []string{A.Tenant.String(), A.User.String(), "only for tenant A"} {
					if strings.Contains(string(got.Body), leak) {
						t.Errorf("%s: the refusal holds %q, which is A's", c.place, leak)
					}
				}
				if tbl := sameExcept(a0, e.db.Digest(isolation.A), fx.CrossMay); tbl != "" {
					t.Errorf("%s: A's rows in %s changed by B's token on A's id", c.place, tbl)
				}
				if tbl := sameExcept(b0, e.db.Digest(isolation.B), fx.CrossBMay); tbl != "" {
					t.Errorf("%s: B's rows in %s changed by a refused call of its token", c.place, tbl)
				}
				// What a refused call was allowed to change is the baseline of the next.
				a0, b0 = e.db.Digest(isolation.A), e.db.Digest(isolation.B)
			}
		})
	}

	// The replay must not shrink to nothing when a fixture is renamed or an operation stops taking a token: these are operations
	// of each group that take a token and an id, and each must have been replayed.
	for _, id := range []string{"getEndpoint", "patchEndpoint", "batchEndpoints", "patchClient", "batchClients", "patchEndpointGroup",
		"deleteDdnsHost", "patchAuthorizedIp", "deleteAuthorizedIps", "createClient"} {
		if !seen[id] {
			t.Errorf("%s was not replayed with a token", id)
		}
	}
	if exact == 0 || locked == 0 {
		t.Errorf("%d replayed calls of %d operations were judged by status and %d as lock_passwords refusals", exact+locked, replayed, locked)
	}
}
