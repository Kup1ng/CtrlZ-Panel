package httpx_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
)

// P3 6.3: an operation whose x-ctrlz-token is read or write also takes `Authorization: Bearer ctz_<value>`. The rig stands in
// for internal/api: a credential "ctz_<name>" screens as the token <name> when <name> is one of the table, and a lookup answers by
// what the table says about it.
const apiTokenDoc = `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /things:
    get:
      operationId: listThings
      x-ctrlz-auth: session
      x-ctrlz-rate: user-read
      x-ctrlz-token: read
      responses: {"200": {description: ok}}
    post:
      operationId: makeThing
      x-ctrlz-auth: session
      x-ctrlz-rate: user-write
      x-ctrlz-token: write
      requestBody:
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties:
                name: {type: string, maxLength: 16}
      responses: {"200": {description: ok}}
  /secrets:
    get:
      operationId: getSecret
      x-ctrlz-auth: session
      x-ctrlz-rate: user-read
      x-ctrlz-token: none
      responses: {"200": {description: ok}}
  /open:
    get:
      operationId: getOpen
      x-ctrlz-auth: none
      x-ctrlz-rate: public-read
      x-ctrlz-token: none
      responses: {"200": {description: ok}}
`

// apiTokenState is what the rig's lookup knows of one token.
type apiTokenState struct {
	live     bool
	tenant   string
	suspend  bool
	kind     string
	allowed  []netip.Prefix
	resolved atomic.Int32
}

type apiTokenRig struct {
	h       http.Handler
	reached *atomic.Int32
	tokens  map[string]*apiTokenState
	mu      sync.Mutex
	last    struct{ session, tenant string }
}

type fakeAPITokens struct{ rig *apiTokenRig }

// Screen: a credential is "ctz_" and a name; a name that is not in the table fails the tag.
func (f fakeAPITokens) Screen(c string) (string, bool) {
	name, ok := strings.CutPrefix(c, "ctz_")
	if !ok {
		return "", false
	}
	if _, found := f.rig.tokens[name]; !found && !strings.HasPrefix(name, "ghost") {
		return "", false
	}
	return name, true
}

func (f fakeAPITokens) Resolve(ctx context.Context, c string, op apispec.Operation, client netip.Addr) (httpx.Resolved, error) {
	name, _ := strings.CutPrefix(c, "ctz_")
	st := f.rig.tokens[name]
	if st == nil || !st.live {
		return httpx.Resolved{Dead: true}, httpx.TokenInvalid()
	}
	st.resolved.Add(1)
	res := httpx.Resolved{Live: true}
	if st.suspend {
		return res, httpx.New(403, httpx.CodeAccountSuspended)
	}
	if len(st.allowed) > 0 {
		in := false
		for _, p := range st.allowed {
			in = in || p.Contains(client)
		}
		if !in {
			return res, httpx.TokenIPNotAllowed()
		}
	}
	if op.Token == "write" && st.kind != "write" {
		return res, httpx.TokenReadOnly()
	}
	res.SessionID, res.Tenant, res.Ctx = name, st.tenant, ctx
	return res, nil
}

func newAPITokenRig(t *testing.T, withTokens bool) *apiTokenRig {
	t.Helper()
	ops, err := apispec.Parse([]byte(apiTokenDoc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	rig := &apiTokenRig{reached: new(atomic.Int32), tokens: map[string]*apiTokenState{
		"reader":  {live: true, tenant: "tenant-a", kind: "read"},
		"writer":  {live: true, tenant: "tenant-a", kind: "write"},
		"other":   {live: true, tenant: "tenant-b", kind: "write"},
		"revoked": {live: false},
		"limited": {live: true, tenant: "tenant-a", kind: "write", allowed: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		"away":    {live: true, tenant: "tenant-a", kind: "write", suspend: true},
	}}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Service: ratelimit.Tenant, Ops: ops, Doc: []byte(apiTokenDoc), BaseURL: "/api/v1",
		Limiter:  ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: func() time.Time { return now }}),
		Resolver: refusingCookies{}, Host: want,
	}
	if withTokens {
		pl.Tokens = fakeAPITokens{rig}
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.reached.Add(1)
		w.WriteHeader(200)
	})
	built.Router.With(built.PerOp).Get("/v1/things", h)
	built.Router.With(built.PerOp).Post("/v1/things", h)
	built.Router.With(built.PerOp).Get("/v1/secrets", h)
	built.Router.With(built.PerOp).Get("/v1/open", h)
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	rig.h = root
	return rig
}

// refusingCookies is the cookie resolver of a rig that is driven by tokens: a cookie "sess=ok" is a live session, and anything else
// is gone.
type refusingCookies struct{}

func (refusingCookies) CookieName() string { return "sess" }
func (refusingCookies) Screen(c string) (string, string, bool) {
	return "lookup-" + c, "", c != ""
}
func (refusingCookies) Resolve(ctx context.Context, c string, _ apispec.Operation) (httpx.Resolved, error) {
	if c != "ok" {
		return httpx.Resolved{Dead: true}, httpx.SessionExpired()
	}
	return httpx.Resolved{Live: true, SessionID: "session-1", Tenant: "tenant-a", Ctx: ctx}, nil
}

func (rig *apiTokenRig) do(method, path, ip string, headers map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
	r.Host = host
	r.Header.Set("X-Forwarded-For", ip)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	rig.h.ServeHTTP(w, r)
	return w
}

func asBearer(name string) map[string]string {
	return map[string]string{"Authorization": "Bearer ctz_" + name}
}

func TestATokenRunsAnOperationThatTakesOne(t *testing.T) {
	rig := newAPITokenRig(t, true)
	if w := rig.do("GET", "/things", "198.51.100.7", asBearer("reader"), ""); w.Code != 200 {
		t.Errorf("a read token on a read: %d %s", w.Code, w.Body)
	}
	if w := rig.do("POST", "/things", "198.51.100.7", asBearer("writer"), `{"name":"x"}`); w.Code != 200 {
		t.Errorf("a write token on a write: %d %s", w.Code, w.Body)
	}
	if w := rig.do("GET", "/things", "198.51.100.7", map[string]string{"Authorization": "bEaReR ctz_writer"}, ""); w.Code != 200 {
		t.Errorf("the scheme is matched without regard to case: %d", w.Code)
	}
	if rig.reached.Load() != 3 {
		t.Errorf("the handler ran %d times, want 3", rig.reached.Load())
	}
}

func TestATokenIsRefusedWhereTheOperationOrTheTokenSaysSo(t *testing.T) {
	rig := newAPITokenRig(t, true)
	cases := []struct {
		name    string
		method  string
		path    string
		ip      string
		headers map[string]string
		body    string
		status  int
		code    string
	}{
		{"a read token on a write operation", "POST", "/things", "198.51.100.7", asBearer("reader"), `{"name":"x"}`, 403, "token_read_only"},
		{"an operation that takes no token", "GET", "/secrets", "198.51.100.7", asBearer("writer"), "", 403, "token_not_allowed"},
		{"a public operation", "GET", "/open", "198.51.100.7", asBearer("writer"), "", 403, "token_not_allowed"},
		{"a value that does not screen", "GET", "/things", "198.51.100.7", asBearer("nobody"), "", 401, "token_invalid"},
		{"no prefix", "GET", "/things", "198.51.100.7", map[string]string{"Authorization": "Bearer writer"}, "", 401, "token_invalid"},
		{"an empty credential", "GET", "/things", "198.51.100.7", map[string]string{"Authorization": "Bearer "}, "", 401, "token_invalid"},
		{"a revoked token", "GET", "/things", "198.51.100.7", asBearer("revoked"), "", 401, "token_invalid"},
		{"outside allowed_ips", "GET", "/things", "198.51.100.7", asBearer("limited"), "", 403, "token_ip_not_allowed"},
		{"a suspended tenant", "GET", "/things", "198.51.100.7", asBearer("away"), "", 403, "account_suspended"},
		{"a session cookie too", "GET", "/things", "198.51.100.7", map[string]string{"Authorization": "Bearer ctz_writer", "Cookie": "sess=ok"}, "", 400, "bad_request"},
		{"no credential at all", "GET", "/things", "198.51.100.7", nil, "", 401, "session_expired"},
		{"another scheme is no credential", "GET", "/things", "198.51.100.7", map[string]string{"Authorization": "Basic Zm9v"}, "", 401, "session_expired"},
		{"a body the schema refuses", "POST", "/things", "198.51.100.7", asBearer("writer"), `{"nope":1}`, 400, "bad_request"},
	}
	for _, c := range cases {
		w := rig.do(c.method, c.path, c.ip, c.headers, c.body)
		if w.Code != c.status || code(t, w) != c.code {
			t.Errorf("%s: %d %s, want %d %s", c.name, w.Code, w.Body, c.status, c.code)
		}
	}
	if rig.reached.Load() != 0 {
		t.Errorf("the handler ran %d times for a refused request", rig.reached.Load())
	}
	// Inside allowed_ips the same token is served.
	if w := rig.do("GET", "/things", "203.0.113.9", asBearer("limited"), ""); w.Code != 200 {
		t.Errorf("a token from an allowed address: %d %s", w.Code, w.Body)
	}
}

func TestACookieStillWorksAndAnOperationWithoutATokenIsUntouched(t *testing.T) {
	rig := newAPITokenRig(t, true)
	for _, path := range []string{"/things", "/secrets"} {
		if w := rig.do("GET", path, "198.51.100.7", map[string]string{"Cookie": "sess=ok"}, ""); w.Code != 200 {
			t.Errorf("a session on %s: %d %s", path, w.Code, w.Body)
		}
	}
	if w := rig.do("GET", "/open", "198.51.100.7", nil, ""); w.Code != 200 {
		t.Errorf("a public route: %d", w.Code)
	}
}

func TestAServiceWithNoTokenReaderRefusesEveryBearer(t *testing.T) {
	rig := newAPITokenRig(t, false)
	for _, path := range []string{"/things", "/secrets", "/open"} {
		if w := rig.do("GET", path, "198.51.100.7", asBearer("writer"), ""); w.Code != 403 || code(t, w) != "token_not_allowed" {
			t.Errorf("%s: %d %s", path, w.Code, w.Body)
		}
	}
}

// A value that screens is charged to its token class on the token id before any lookup, and never given back; junk charges nothing.
func TestJunkChargesNothingAndALiveTokenSpendsItsOwnClass(t *testing.T) {
	rig := newAPITokenRig(t, true)
	for i := 0; i < 400; i++ {
		if w := rig.do("GET", "/things", "198.51.100.7", asBearer("nobody"), ""); w.Code != 401 {
			t.Fatalf("junk answered %d", w.Code)
		}
	}
	// token-read is 300 a minute per token, and the operation's own class (user-read, 300) is charged on the token too.
	served := 0
	for i := 0; i < 320; i++ {
		if rig.do("GET", "/things", "198.51.100.7", asBearer("reader"), "").Code == 200 {
			served++
		}
	}
	if served != 300 {
		t.Errorf("one token served %d of 320, want 300", served)
	}
	// Another token of the same tenant has a class of its own, and the same token from another network is the same bucket.
	if w := rig.do("GET", "/things", "198.51.100.7", asBearer("writer"), ""); w.Code != 200 {
		t.Errorf("another token: %d", w.Code)
	}
	if w := rig.do("GET", "/things", "203.0.113.50", asBearer("reader"), ""); w.Code != 429 {
		t.Errorf("the same token from another network: %d, want 429", w.Code)
	}
}

// The miss charge goes back for a live token whatever a later gate decides, and stays for a token that is gone: a flood of refusals
// of a live token never spends the budget of a dead one, and the owner of a live token is not locked out by its own refusals.
func TestTheMissChargeIsGivenBackForALiveTokenOnly(t *testing.T) {
	rig := newAPITokenRig(t, true)
	// token-miss is 30 a minute and token-write 60: sixty gate refusals of a live read token pass the miss bucket, which a charge
	// that was not given back would stop at 30 with a 429.
	for i := 0; i < 60; i++ {
		if w := rig.do("POST", "/things", "198.51.100.7", asBearer("reader"), `{"name":"x"}`); w.Code != 403 {
			t.Fatalf("refusal %d answered %d %s", i, w.Code, w.Body)
		}
	}
	// A token with no row is dead: the value joins the dead set and the lookup is not asked again.
	rig.tokens["ghost1"] = &apiTokenState{live: false}
	for i := 0; i < 5; i++ {
		if w := rig.do("GET", "/things", "198.51.100.7", asBearer("ghost1"), ""); w.Code != 401 {
			t.Fatalf("a dead token answered %d", w.Code)
		}
	}
	if n := rig.tokens["ghost1"].resolved.Load(); n != 0 {
		t.Errorf("a token with no row was looked up %d times", n)
	}
}

// token-tenant is the one bound the tokens of a tenant share; another tenant has its own.
func TestTheTokensOfOneTenantShareTheirTenantBound(t *testing.T) {
	rig := newAPITokenRig(t, true)
	// Each of 12 tokens of tenant-a sends 60 requests: 720 in all, and token-tenant is 600 a minute.
	for i := 0; i < 12; i++ {
		rig.tokens["bulk"+string(rune('a'+i))] = &apiTokenState{live: true, tenant: "tenant-a", kind: "read"}
	}
	served := 0
	for i := 0; i < 12; i++ {
		for j := 0; j < 60; j++ {
			if rig.do("GET", "/things", "198.51.100.7", asBearer("bulk"+string(rune('a'+i))), "").Code == 200 {
				served++
			}
		}
	}
	if served != 600 {
		t.Errorf("a tenant's tokens served %d, want 600", served)
	}
	if w := rig.do("GET", "/things", "198.51.100.7", asBearer("other"), ""); w.Code != 200 {
		t.Errorf("another tenant's token: %d", w.Code)
	}
}

func TestAnOperationThatTakesATokenMustHaveASession(t *testing.T) {
	doc := `openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /x:
    get:
      operationId: x
      x-ctrlz-auth: none
      x-ctrlz-rate: public-read
      x-ctrlz-token: read
      responses: {"200": {description: ok}}
`
	ops, err := apispec.Parse([]byte(doc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	pl := &httpx.Pipeline{Log: slog.New(slog.DiscardHandler), Service: ratelimit.Tenant, Ops: ops, Doc: []byte(doc), BaseURL: "/api/v1",
		Limiter: ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true}), Resolver: refusingCookies{}, Host: want}
	if _, err := pl.Build(); err == nil {
		t.Error("an operation with no session that takes a token was built")
	}
}

// heavyTokens answers every credential "ctz_<tenant>-<n>" with a live write token of that tenant, and counts its lookups.
type heavyTokens struct{ lookups atomic.Int32 }

func (h *heavyTokens) Screen(c string) (string, bool) {
	v, ok := strings.CutPrefix(c, "ctz_")
	return v, ok && strings.Contains(v, "-")
}

func (h *heavyTokens) Resolve(ctx context.Context, c string, _ apispec.Operation, _ netip.Addr) (httpx.Resolved, error) {
	h.lookups.Add(1)
	v, _ := strings.CutPrefix(c, "ctz_")
	tenant, _, _ := strings.Cut(v, "-")
	return httpx.Resolved{Ctx: ctx, Live: true, SessionID: v, Tenant: tenant}, nil
}

// A bulk operation by token is a heavy request like one by session (6.5), and its class is charged on the token: ten a minute for
// each token, the lookup repeated inside the slot, and the tenant's day budget shared by every token and session of the tenant.
func TestABulkOperationByTokenIsTenAMinutePerToken(t *testing.T) {
	adm, err := admission.New(admission.Config{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: func() time.Time { return now }})
	tokens := &heavyTokens{}
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Service: ratelimit.Tenant, Ops: ops, Doc: api.Tenant(), BaseURL: "/api/v1",
		Limiter: lim, Resolver: &sessionResolver{}, Host: want, Admission: adm, Tokens: tokens,
		Bearer: func(*http.Request, apispec.Operation) (string, bool) { return "", false },
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	var reached atomic.Int32
	built.Router.With(built.PerOp).Post("/v1/profiles:import", func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	})
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	send := func(token string) int {
		r := httptest.NewRequest("POST", importPath, strings.NewReader(bodyHead+bodyTail))
		r.Host = host
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "k")
		r.Header.Set("Authorization", "Bearer ctz_"+token)
		return serve(root, r).Code
	}
	served := 0
	for i := 0; i < 14; i++ {
		if send("tn-1") == http.StatusCreated {
			served++
		}
	}
	if served != 10 {
		t.Errorf("one token ran %d bulk operations in a minute, want 10", served)
	}
	if got := tokens.lookups.Load(); got < 20 {
		t.Errorf("%d lookups for 10 heavy requests: the work step must resolve the token again", got)
	}
	if send("tn-2") != http.StatusCreated {
		t.Error("another token of the same tenant shared the class of the first")
	}
	if reached.Load() != 11 {
		t.Errorf("the handler ran %d times, want 11", reached.Load())
	}
}
