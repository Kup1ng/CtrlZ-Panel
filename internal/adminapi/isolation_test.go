package adminapi

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	adminapidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/boundary"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest/isolation"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// baselines are the generated requests of api/admin-openapi.yaml that satisfy their
// schemas (internal/authtest/boundary). The gate tests send them, so a request reaches
// the gate under test and not the check of the pipeline in front of it (rule
// boundary-input: a body that breaks its schema is 400 before any session is looked at).
var baselines = sync.OnceValues(func() (map[string]boundary.Case, error) {
	cs, err := boundary.Cases(adminapidoc.Admin())
	if err != nil {
		return nil, err
	}
	out := map[string]boundary.Case{}
	for _, c := range cs {
		if c.Baseline {
			out[c.Op] = c
		}
	}
	return out, nil
})

// sampleRequest returns the path (with its parameters filled with values that parse and
// its query) and the body of the generated baseline of an operation.
func sampleRequest(t *testing.T, op apispec.Operation) (string, any) {
	t.Helper()
	m, err := baselines()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := m[op.ID]
	if !ok {
		t.Fatalf("%s has no generated baseline", op.ID)
	}
	if c.Body == nil {
		return c.Path, nil
	}
	return c.Path, c.Body
}

func adminOps(t *testing.T) []apispec.Operation {
	t.Helper()
	ops, err := apispec.Parse(adminapidoc.Admin(), ratelimit.Admin)
	if err != nil || len(ops) < 30 {
		t.Fatalf("%d operations, %v", len(ops), err)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Key() < ops[j].Key() })
	return ops
}

// TestEveryAdminOperationIsGated is the route test of 18.1 for the admin API:
// with no cookie every non-none operation is 401; in setup only the setup
// routes answer; with a stale TOTP window every admin-fresh one is 403
// totp_fresh_required. The operations come from the document, so a new route is
// caught the moment it is added.
func TestEveryAdminOperationIsGated(t *testing.T) {
	r := newRig(t)
	ops := adminOps(t)
	var logout *apispec.Operation

	// 1. No cookie.
	anon := r.browser()
	for _, op := range ops {
		if op.Auth == apispec.None {
			continue
		}
		p, body := sampleRequest(t, op)
		anon.call(op.Method, p, body).want(401, "session_expired")
	}

	// 2. A setup session: only admin-setup routes get through.
	r.setupAdmin(t, false)
	setup := r.browser()
	setup.login(adminPW, "").want(200, "")
	for i, op := range ops {
		if op.Auth == apispec.None {
			continue
		}
		if op.Path == "/auth/logout" {
			logout = &ops[i]
			continue
		}
		p, body := sampleRequest(t, op)
		res := setup.call(op.Method, p, body)
		if op.Auth == apispec.AdminSetup {
			if res.Code == 401 || res.Code == 403 {
				t.Errorf("%s in setup: %d %s", op.Key(), res.Code, res.Body)
			}
			continue
		}
		res.want(403, "setup_required")
	}

	// 3. A ready session whose TOTP window is stale.
	seed := r.setupAdmin(t, true)
	ready := r.browser()
	ready.mustLogin(seed)
	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() - interval '10 minutes' WHERE revoked_at IS NULL`)
	fresh := 0
	for _, op := range ops {
		if op.Auth == apispec.None || op.Path == "/auth/logout" {
			continue
		}
		p, body := sampleRequest(t, op)
		res := ready.call(op.Method, p, body)
		if op.Auth == apispec.AdminFresh {
			fresh++
			res.want(403, "totp_fresh_required")
			continue
		}
		// A request that satisfies its schema can be refused by its own handler (a wrong code is a
		// 401 totp_invalid); what must not happen is a gate answering.
		if (res.Code == 401 && res.errCode() == "session_expired") || (res.Code == 403 && res.errCode() != "") {
			t.Errorf("%s with a ready session: %d %s", op.Key(), res.Code, res.Body)
		}
	}
	if fresh < 8 {
		t.Fatalf("only %d admin-fresh operations", fresh)
	}
	if logout == nil {
		t.Fatal("no logout operation")
	}
	ready.call(logout.Method, logout.Path, nil).want(204, "")
}

// forbiddenFields are names no admin response may carry (18.1): hashes, sealed
// secrets, tokens, credentials. A list holds none of them, and the few routes that
// show a secret once are named in shownOnce.
func forbiddenFields() []string {
	return []string{
		"password_hash", "totp_secret", "totp_secret_ct", "token", "token_hash", "session", "refresh",
		"credentials_ct", "params_ct", "delivery_ct", "code_hash", "entry_hash", "prev_hash", "api_key", "dns_raw", "query",
		"domain", "queries", "log",
	}
}

// shownOnce are the response fields that carry a one-time value on purpose, each
// on one route, shown once (10.6, 10.7, 11.3, 6.4).
func shownOnce() map[string]string {
	return map[string]string{
		"one_time_password": "UserCreated and OneTimePasswordIssued",
		"code":              "InviteCreated",
		"secret":            "AdminTotpSetup",
		"otpauth_uri":       "AdminTotpSetup",
	}
}

// TestNoAdminResponseCarriesASecret walks the document: the schema of every
// success response, resolved through $ref, has no field from the forbidden list,
// and the only secrets are the shown-once ones on the routes that make them.
func TestNoAdminResponseCarriesASecret(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(adminapidoc.Admin(), &doc); err != nil {
		t.Fatal(err)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	// responseSchemas are the schemas a success response reaches.
	responseSchemas := map[string]bool{}
	var fieldsOf func(node any, seen map[string]bool) []string
	fieldsOf = func(node any, seen map[string]bool) []string {
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		if ref, ok := m["$ref"].(string); ok {
			name := ref[strings.LastIndex(ref, "/")+1:]
			responseSchemas[name] = true
			if seen[name] {
				return nil
			}
			seen[name] = true
			return fieldsOf(schemas[name], seen)
		}
		var out []string
		if props, ok := m["properties"].(map[string]any); ok {
			for name, p := range props {
				out = append(out, name)
				out = append(out, fieldsOf(p, seen)...)
			}
		}
		if items, ok := m["items"]; ok {
			out = append(out, fieldsOf(items, seen)...)
		}
		return out
	}
	forbidden := map[string]bool{}
	for _, f := range forbiddenFields() {
		forbidden[f] = true
	}
	paths := doc["paths"].(map[string]any)
	checked := 0
	for path, item := range paths {
		for method, opAny := range item.(map[string]any) {
			op, ok := opAny.(map[string]any)
			if !ok {
				continue
			}
			resps, _ := op["responses"].(map[string]any)
			for status, rAny := range resps {
				if !strings.HasPrefix(status, "2") {
					continue
				}
				body, _ := rAny.(map[string]any)["content"].(map[string]any)
				js, _ := body["application/json"].(map[string]any)
				if js == nil {
					continue
				}
				for _, f := range fieldsOf(js["schema"], map[string]bool{}) {
					checked++
					if forbidden[f] {
						t.Errorf("%s %s: the %s response has a field %q", strings.ToUpper(method), path, status, f)
					}
				}
			}
		}
	}
	if checked < 100 {
		t.Fatalf("only %d fields walked", checked)
	}
	// The shown-once names exist, and only where the table says.
	for name, where := range shownOnce() {
		found := false
		for schema, s := range schemas {
			if !responseSchemas[schema] {
				continue
			}
			if props, ok := s.(map[string]any)["properties"].(map[string]any); ok && props[name] != nil {
				found = true
				if !strings.Contains(where, schema) {
					t.Errorf("schema %s has the shown-once field %q; expected only %s", schema, name, where)
				}
			}
		}
		if !found {
			t.Errorf("no schema has the shown-once field %q", name)
		}
	}
}

// TestAdminAndPanelRoutesStayApart covers the last rows of 18.1 and 18.5:
// no admin route on the panel host and no panel route on the admin host, and a
// cookie of one never opens the other.
func TestAdminAndPanelRoutesStayApart(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	// Admin-only routes on the panel host, with the admin cookie under both names.
	panel := r.browser()
	panel.jar[session.CookieAdmin] = b.jar[session.CookieAdmin]
	panel.jar[session.CookieSession] = &http.Cookie{Name: session.CookieSession, Value: b.jar[session.CookieAdmin].Value}
	for _, c := range []struct{ method, path string }{
		{"GET", "/users"}, {"POST", "/users"}, {"POST", "/auth/login"}, {"GET", "/audit"},
		{"PUT", "/settings/registration"}, {"POST", "/auth/totp/fresh"}, {"GET", "/sms/gateways"},
	} {
		panel.callOn(r.tenant, panelHost, c.method, c.path, nil).want(404, "not_found")
	}
	// The same-named routes answer 401 with the admin cookie on the panel host.
	panel.callOn(r.tenant, panelHost, "GET", "/me", nil).want(401, "session_expired")
	panel.callOn(r.tenant, panelHost, "POST", "/auth/logout", nil).want(401, "session_expired")
	// Panel routes on the admin host.
	b.callOn(r.h, adminHost, "POST", "/auth/login/password", map[string]any{}).want(404, "not_found")
	b.callOn(r.h, adminHost, "GET", "/account/sessions", nil).want(404, "not_found")
	b.callOn(r.h, adminHost, "GET", "/notifications", nil).want(404, "not_found")
	// The admin session still works at home.
	b.get("/me").want(200, "")
}

// TestStolenAdminCookie is the 18.5 row: a stolen cookie cannot test passwords
// without limit, cannot change the password without the code, and cannot use the
// fresh-only routes.
func TestStolenAdminCookie(t *testing.T) {
	r := newRig(t)
	b, seed := r.admin(t)
	for i := 0; i < 5; i++ {
		b.post("/me/password", map[string]any{"current_password": "wrong-wrong-wrong-" + string(rune('a'+i)), "new_password": adminNewPW}).want(401, "invalid_credentials")
	}
	// The right password cannot get through now either: the scope counted five.
	r.freeStep(t)
	b.post("/me/password", map[string]any{"current_password": adminPW, "new_password": adminNewPW, "totp_code": totpNow(seed)}).want(429, "too_many_attempts")

	// The fresh-only routes the thief most wants, without a fresh code.
	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = NULL`)
	b.post("/sms/gateways/sms_ir/test", map[string]any{"phone": "09125550006", "template": "otp"}).want(403, "totp_fresh_required")
	b.put("/sms/gateways/sms_ir/templates/otp/fa", map[string]any{"provider_template_id": "1", "param_names": []string{"c"}}).want(403, "totp_fresh_required")
	b.put("/sms/gateways/sms_ir", map[string]any{"cost_per_message": "1"}).want(403, "totp_fresh_required")
	b.put("/sms/routing", map[string]any{"primary": "sms_ir"}).want(403, "totp_fresh_required")
	// Round 18 (admin-r18-3, -10): every other state-changing route of the ready admin needs the code too. A copied
	// cookie without the authenticator cannot mint an account bound to somebody else's phone, write the text of
	// every OTP message, or silence an alert and revoke an invite.
	b.post("/users", map[string]any{"phone": "09125550101"}).want(403, "totp_fresh_required")
	b.post("/invites", map[string]any{"phone": "09125550102"}).want(403, "totp_fresh_required")
	b.call("DELETE", "/invites/00000000-0000-7000-8000-000000000001", nil).want(403, "totp_fresh_required")
	b.put("/sms/templates/otp/fa", map[string]any{"body": "your code is {code}"}).want(403, "totp_fresh_required")
	b.post("/alerts/00000000-0000-7000-8000-000000000002/ack", nil).want(403, "totp_fresh_required")
	// A body that satisfies the schema, so the gate and not the check in front of it answers.
	_, limits := sampleRequest(t, apispec.Operation{ID: "putSmsLimits"})
	b.put("/sms/limits", limits).want(403, "totp_fresh_required")
}

// TestAdminThrottleReach is the 18.5 row: neither role's function pair accepts
// the other's scopes, so the api cannot reset an admin key between guesses and
// admin cannot touch the user keys. The functions answer "not allowed" for a
// foreign scope and a reset of one does nothing.
func TestAdminThrottleReach(t *testing.T) {
	r := newRig(t)
	ctx := r.env.Ctx
	key := make([]byte, 32)
	key[0] = 9
	// The api cannot count an admin scope (it is refused, which a caller reads as locked out)...
	if res, err := r.tst.Auth().ThrottleHit(ctx, "admin_login", key, 5, time.Minute); err != nil || res.Allowed {
		t.Errorf("ctrlz_tenant counted an admin scope: %+v %v", res, err)
	}
	// ...and admin cannot count a user scope.
	if res, err := r.adm.Admin().ThrottleHit(ctx, "login_phone", key, 5, time.Minute); err != nil || res.Allowed {
		t.Errorf("ctrlz_admin counted a user scope: %+v %v", res, err)
	}
	// A reset from the wrong side changes nothing: lock an admin key, let the api
	// "reset" it, and it is still locked.
	for i := 0; i < 5; i++ {
		if res, err := r.adm.Admin().ThrottleHit(ctx, "admin_login", key, 5, time.Hour); err != nil || !res.Allowed {
			t.Fatalf("admin hit %d: %+v %v", i, res, err)
		}
	}
	if res, _ := r.adm.Admin().ThrottleHit(ctx, "admin_login", key, 5, time.Hour); res.Allowed {
		t.Fatal("the sixth admin hit was allowed")
	}
	_ = r.tst.Auth().ThrottleReset(ctx, "admin_login", key)
	if res, _ := r.adm.Admin().ThrottleHit(ctx, "admin_login", key, 5, time.Hour); res.Allowed {
		t.Error("the api reset an admin key")
	}
	// The mirror: admin cannot clear a user key.
	for i := 0; i < 5; i++ {
		if res, err := r.tst.Auth().ThrottleHit(ctx, "login_phone", key, 5, time.Hour); err != nil || !res.Allowed {
			t.Fatalf("user hit %d: %+v %v", i, res, err)
		}
	}
	_ = r.adm.Admin().ThrottleReset(ctx, "login_phone", key)
	if res, _ := r.tst.Auth().ThrottleHit(ctx, "login_phone", key, 5, time.Hour); res.Allowed {
		t.Error("admin reset a user key")
	}
}

// TestGatewayRowsNeverHoldCredentials pins the one place a "credentials" field
// is a request field and must not come back in a response (15.2).
func TestGatewayRowsNeverHoldCredentials(t *testing.T) {
	var doc map[string]any
	if err := yaml.Unmarshal(adminapidoc.Admin(), &doc); err != nil {
		t.Fatal(err)
	}
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	row := schemas["SmsGatewayRow"].(map[string]any)["properties"].(map[string]any)
	for name := range row {
		if strings.Contains(name, "credential") || strings.Contains(name, "secret") || strings.Contains(name, "key") {
			t.Errorf("SmsGatewayRow has a field %q", name)
		}
	}
}

// TestIsolation is T-386 and spec 18.1 for the admin API, rule isolation-success-coverage: one
// harness over every operation of api/admin-openapi.yaml. An operation with no success fixture
// fails, so does a fixture whose call is not 2xx, and so does one whose call moves a tenant's
// rows it did not claim to (the two seeded tenants are digested before and after). The two
// routes that act on tenants are the ones whose own tenant's digest must change.
func TestIsolation(t *testing.T) {
	r := newRig(t)
	e := &admIso{r: r}
	e.db = &isolation.Tenants{Env: r.env, T: t, Phones: func(w isolation.Who) []string {
		if w == isolation.A {
			return []string{r.env.A.Phone}
		}
		return []string{r.env.B.Phone}
	}}
	var ops []isolation.Op
	for _, op := range adminOps(t) {
		ops = append(ops, isolation.Op{ID: op.ID, Method: op.Method})
	}
	isolation.Run(t, ops, e.fixtures(), isolation.Hooks{
		Reset:   func(w isolation.Who) { e.db.Reset(w, "") },
		Digest:  e.db.Digest,
		Shape:   e.db.Shape,
		Leaks:   func() []string { return nil },
		ACookie: func() string { return "" },
	})
}
