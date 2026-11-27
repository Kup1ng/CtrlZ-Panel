package api

import (
	"fmt"
	"strings"
	"testing"
	"time"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// Review round 1 of package D5 (p3-D5-r1-1 to -5): the declared limit of 6.3, the canaries of the values, the credential change that
// must end a token mint, and the touch of last_used_at that must never hold a request.

// outsideIP is an address in no allowed list of these tests, one per n, each on a network of its own, so no network-keyed budget
// is shared by two requests.
func (f *frig) outsideIP(n int) string { return fmt.Sprintf("198.%d.%d.9", 18+n/250, n%250+1) }

// makeMany lets tenant A hold many tokens and makes n of them one at a time, as the sensitive class of a session allows.
func (r *tokenRig) makeMany(n int, body func(i int) map[string]any) []string {
	r.f.t.Helper()
	r.f.env.Exec(r.f.t, `UPDATE ctrlz.tenant_entitlements SET max_api_tokens = 100 WHERE tenant_id = $1`, r.f.env.A.Tenant)
	var out []string
	for i := 0; i < n; i++ {
		r.f.ck.add(10 * time.Second)
		r.reauth(r.f.env.A.Tenant, r.f.env.A.User)
		v, _ := r.make(r.a, body(i))
		out = append(out, v)
	}
	return out
}

// p3-D5-r1-1: the declared limit of 6.3 step 4. A flood from outside allowed_ips is 403 and spends the token's own class, so the
// allowed address then gets 429; it spends nothing that is shared. token-tenant (600 a minute for the tenant) is charged after the
// gates, so three flooded tokens (900 requests) leave another token of the same tenant answering 200.
func TestFloodFromOutsideAllowedIPsSpendsOnlyTheTokensOwnClass(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	tokens := r.makeMany(4, func(i int) map[string]any {
		b := map[string]any{"name": fmt.Sprintf("flood %d", i), "kind": "read"}
		if i < 3 {
			b["allowed_ips"] = []string{"203.0.113.0/24"}
		}
		return b
	})
	flooded, bystander := tokens[:3], tokens[3]
	n := 0
	for _, v := range flooded {
		for i := 0; i < 300; i++ {
			n++
			r.bearer(v, f.outsideIP(n)).get("/profiles").want(403, "token_ip_not_allowed")
		}
		// The class of the token is spent: the next one from outside is 429, and so is the allowed address, which is the limit
		// 6.3 declares (the remedy is deleting the token).
		n++
		r.bearer(v, f.outsideIP(n)).get("/profiles").want(429, "")
		r.bearer(v, "203.0.113.9").get("/profiles").want(429, "")
	}
	// What is shared was not spent: the tenant's token-tenant bucket holds 600 and 900 refused requests went by.
	r.bearer(bystander, "203.0.113.9").get("/profiles").want(200, "")
}

// p3-D5-r1-2: every operation that takes a write token writes last_used_at when it was stale. (The bearer on every operation of the
// admin document is TestEveryAdminOperationRefusesABearer in internal/adminapi.)
func TestTokenWalkEveryWriteOperationTouchesLastUsed(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	ops, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	byKey := apispec.Index(ops)
	cases, err := boundary.Cases(apidoc.Tenant())
	if err != nil {
		t.Fatal(err)
	}
	write, row := r.make(r.a, map[string]any{"name": "touch walk", "kind": "write"})
	lastUsed := func() *time.Time {
		var p *time.Time
		f.env.Scan(t, `SELECT last_used_at FROM ctrlz.api_tokens WHERE id = $1`, []any{row.Token.ID}, &p)
		return p
	}
	seen := 0
	for i, c := range cases {
		if !c.Baseline || c.Edge || !strings.HasSuffix(c.Name, "/baseline") {
			continue
		}
		op, ok := byKey[c.Key]
		if !ok || op.Token != "write" {
			continue
		}
		seen++
		f.ck.add(11 * time.Minute) // past TokenTouchEvery, so the value is stale for this request
		cl := r.bearer(write, f.outsideIP(i))
		var body any
		if c.Body != nil {
			body = c.Body
		}
		w := cl.do(c.Method, c.Path, body, c.Header)
		if (w.Code == 401 && w.code() == "token_invalid") || (w.Code == 403 && strings.HasPrefix(w.code(), "token_")) {
			t.Errorf("%s: a write token was refused as a token: %d %s", op.ID, w.Code, w.Body)
			continue
		}
		if got := lastUsed(); got == nil || !got.Equal(f.ck.now().Truncate(time.Microsecond)) {
			t.Errorf("%s: last_used_at is %v after the request, want %v", op.ID, got, f.ck.now())
		}
	}
	if seen == 0 {
		t.Fatal("no operation of the document takes a write token")
	}
}

// p3-D5-r1-3: the value of an API token is a secret.String from creation to the response, and it reaches no log line, audit row or
// other sink of 18.4, whichever way a request with it ends: created, listed, used, refused for its address, its kind or its
// operation, tampered with, revoked, deleted.
func TestAPITokenValueNeverReachesALogOrASink(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	A := f.env.A
	value, row := r.make(r.a, map[string]any{"name": "canary", "kind": "read", "allowed_ips": []string{"203.0.113.0/24"}})
	other, orow := r.make(r.a, map[string]any{"name": "canary two", "kind": "write"})
	tampered := badTag(value)

	r.a.get("/api-tokens").want(200, "")
	r.bearer(value, "203.0.113.5").get("/profiles").want(200, "")
	r.bearer(value, "198.51.100.5").get("/profiles").want(403, "token_ip_not_allowed")
	r.bearer(value, "203.0.113.5").post("/profiles", map[string]any{"name": "x", "kind": "custom"}).want(403, "token_read_only")
	r.bearer(value, "203.0.113.5").get("/account/sessions").want(403, "token_not_allowed")
	r.bearer(value, "203.0.113.5").post("/api-tokens", map[string]any{"name": "by a token", "kind": "write"}).want(403, "token_not_allowed")
	r.bearer(tampered, "").get("/profiles").want(401, "token_invalid")
	r.bearer("ctz_"+strings.Repeat("A", 64), "").get("/profiles").want(401, "token_invalid")
	// A malformed body with a good token, so the refusal of the schema check is read too.
	r.bearer(other, "").do("POST", "/profiles", []byte(`{"name":`)).want(400, "")
	r.reauth(A.Tenant, A.User)
	r.a.do("PATCH", "/api-tokens/"+row.Token.ID, map[string]any{"allowed_ips": []string{"bad"}}).want(422, "validation_failed")
	r.a.do("PATCH", "/api-tokens/"+row.Token.ID, map[string]any{"name": "renamed"}).want(200, "")
	f.env.Exec(t, `UPDATE ctrlz.api_tokens SET revoked_at = $2 WHERE id = $1`, orow.Token.ID, f.ck.now())
	r.bearer(other, "").get("/profiles").want(401, "token_invalid")
	r.a.do("DELETE", "/api-tokens/"+row.Token.ID, nil).want(204, "")
	r.bearer(value, "").get("/profiles").want(401, "token_invalid")

	canaries := []string{value, value[4:], other, other[4:], tampered, tampered[4:]}
	authtest.AssertTextClean(t, "the process log", f.logs.String(), canaries...)
	f.env.AssertSinksClean(t, canaries...)
	f.env.AssertServerLogClean(t, canaries...)
}

// p3-D5-r1-4: a password or phone change made in a session rotates that session and keeps its id, so a create that was resolved
// with the old cookie and waited for the user's row must not mint a token afterwards: the change revoked the tokens that existed,
// and a token made after it would outlive it for a year.
func TestCreateTokenResolvedBeforeACredentialChangeOfTheSameSessionMintsNothing(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	A := f.env.A
	before := f.count(`SELECT count(*) FROM ctrlz.api_tokens WHERE tenant_id = $1`, A.Tenant)

	// What ChangePassword commits, in one transaction that holds the user's row: the credential moves, the acting session gets a
	// new token (same id, revoked_at still NULL), and the user's API tokens are revoked. Only the acting session (the newest one,
	// the one r.a holds) is rotated: the seed gives the user a session of its own, and a hash is unique, so rotating every session
	// of the user to one value is refused by sessions_token_hash_key.
	release := f.holdUpdate(`WITH rot AS (UPDATE ctrlz.sessions SET token_hash = '\x0102030405'::bytea
			WHERE tenant_id = $1::uuid AND id = (SELECT id FROM ctrlz.sessions WHERE user_id = $2::uuid ORDER BY created_at DESC, id DESC LIMIT 1) RETURNING 1),
		rev AS (UPDATE ctrlz.api_tokens SET revoked_at = now() WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND revoked_at IS NULL RETURNING 1)
		UPDATE ctrlz.users SET password_changed_at = now() WHERE tenant_id = $1::uuid AND id = $2::uuid`, A.Tenant, A.User)
	done := make(chan *resp, 1)
	go func() { done <- r.a.post("/api-tokens", map[string]any{"name": "raced", "kind": "write"}) }()
	f.waitBlocked() // the create is parked on the user's row, holding the cookie it was resolved with
	release()
	(<-done).want(401, "session_expired")
	if after := f.count(`SELECT count(*) FROM ctrlz.api_tokens WHERE tenant_id = $1`, A.Tenant); after != before {
		t.Errorf("%d tokens before and %d after a create that lost to a credential change", before, after)
	}

	// Tenant B is untouched by it: its own session still mints.
	r.make(r.b, map[string]any{"name": "b is fine", "kind": "read"})
}

// p3-D5-r1-5: the touch of last_used_at is not in the transaction of the request. A token request never waits for the token's
// row: with the row held by another transaction (a rename, another process's touch) a read and a write of the token are served at
// once, and last_used_at is left for a later request.
func TestTokenRequestsNeverWaitForTheTokenRow(t *testing.T) {
	r := newTokenRig(t)
	f := r.f
	A := f.env.A
	write, row := r.make(r.a, map[string]any{"name": "held", "kind": "write"})

	release := f.holdUpdate(`UPDATE ctrlz.api_tokens SET name = name WHERE id = $1::uuid`, row.Token.ID)
	start := time.Now()
	r.bearer(write, "").get("/profiles").want(200, "")
	r.bearer(write, "").get("/profiles/"+A.Profile.String()).want(200, "")
	r.bearer(write, "").post("/profiles", map[string]any{"name": "while held", "kind": "custom"}).want(201, "")
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("three requests of a token whose row was held took %v", d)
	}
	var p *time.Time
	f.env.Scan(t, `SELECT last_used_at FROM ctrlz.api_tokens WHERE id = $1`, []any{row.Token.ID}, &p)
	if p != nil {
		t.Errorf("last_used_at was written through a held row: %v", p)
	}
	release()

	// Once the row is free and the in-process memory has run out, a request writes it.
	f.ck.add(11 * time.Minute)
	r.bearer(write, "").get("/profiles").want(200, "")
	f.env.Scan(t, `SELECT last_used_at FROM ctrlz.api_tokens WHERE id = $1`, []any{row.Token.ID}, &p)
	if p == nil || !p.Equal(f.ck.now().Truncate(time.Microsecond)) {
		t.Errorf("last_used_at is %v after a request on a free row, want %v", p, f.ck.now())
	}
}
