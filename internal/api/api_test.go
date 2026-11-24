package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	apidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

const host = "panel.example.test"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	env  *authtest.Env
	st   *store.Store
	ck   *clock
	m    *session.Manager
	lim  *ratelimit.Limiter
	h    http.Handler
	logs *strings.Builder
}

func newRig(t *testing.T, valkeyUp bool) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	ck := &clock{t: time.Now().UTC()}
	m := session.NewManager(st, session.DefaultPolicy(), ck.now)
	keys := authtest.APIKeys(t)
	// Tagged like production, so a random cookie is refused before any charge.
	if err := m.WithKeys(keys, keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: valkeyUp, Now: ck.now})
	logs := &strings.Builder{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			io.WriteString(w, `{"status":"ok"}`)
			return
		}
		http.NotFound(w, r)
	})
	h, err := New(Deps{Log: log, Store: st, Sessions: m, Limiter: lim, Keys: keys, Hasher: authtest.FastHasher(t), PanelHost: host, Strict: true, Now: ck.now}, httpx.NewHealth(health))
	if err != nil {
		t.Fatal(err)
	}
	return &rig{env: env, st: st, ck: ck, m: m, lim: lim, h: h, logs: logs}
}

func (r *rig) login(t *testing.T, tenant, user uuid.UUID, remember, restricted bool) session.Issued {
	t.Helper()
	var iss session.Issued
	err := r.st.WithTenant(r.env.Ctx, tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		iss, err = r.m.Create(tx, session.NewSession{User: user, Remember: remember, Restricted: restricted, Method: "password", IP: netip.MustParseAddr("203.0.113.9"), UserAgent: "t"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

type call struct {
	method, path string
	cookies      []*http.Cookie
	hdr          map[string]string
	xff          string
	host         string
	body         string
	peer         string // RemoteAddr; empty keeps the httptest default, which is not loopback
}

func (r *rig) do(t *testing.T, h http.Handler, c call) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
	if c.peer != "" {
		req.RemoteAddr = c.peer
	}
	req.Host = host
	if c.host != "" {
		req.Host = c.host
	}
	xff := c.xff
	if xff == "" {
		xff = "203.0.113.9"
	}
	if xff != "-" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	for k, v := range c.hdr {
		req.Header.Set(k, v)
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func sessionCk(i session.Issued) *http.Cookie {
	return &http.Cookie{Name: session.CookieSession, Value: i.Session.Reveal()}
}
func refreshCk(i session.Issued) *http.Cookie {
	return &http.Cookie{Name: session.CookieRefresh, Value: i.Refresh.Reveal()}
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("not an error body (status %d): %q", w.Code, w.Body.String())
	}
	return b.Code
}

func expect(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status || (code != "" && errCode(t, w) != code) {
		t.Fatalf("got %d %q, want %d %q", w.Code, w.Body.String(), status, code)
	}
}

func (r *rig) setStatus(t *testing.T, tenant uuid.UUID, status string) {
	t.Helper()
	const q = `UPDATE ctrlz.tenants SET status = $2 WHERE id = $1`
	super, err := r.env.DB.Super(r.env.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer super.Close(r.env.Ctx)
	if _, err := super.Exec(r.env.Ctx, q, tenant, status); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------

func TestEveryOperationCarriesBothExtensions(t *testing.T) {
	// Parse fails on a missing or unknown value; the real documents must pass.
	ops, err := apispec.Parse(apidoc.Tenant(), ratelimit.Tenant)
	if err != nil || len(ops) == 0 {
		t.Fatalf("tenant document: %v (%d ops)", err, len(ops))
	}
	for _, op := range ops {
		if op.Auth == "" || op.Rate == "" {
			t.Errorf("%s lacks an extension", op.ID)
		}
	}
	// And the parser really does refuse omissions.
	bad := `paths:
  /x:
    get:
      operationId: x
      x-ctrlz-auth: session
`
	if _, err := apispec.Parse([]byte(bad), ratelimit.Tenant); err == nil {
		t.Fatal("an operation without x-ctrlz-rate must be refused")
	}
}

func TestPublicConfigAndTheHeadersEveryResponseCarries(t *testing.T) {
	r := newRig(t, true)
	w := r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config"})
	expect(t, w, 200, "")
	var cfg struct {
		RegistrationMode string `json:"registration_mode"`
		SMSAvailable     bool   `json:"sms_available"`
		PasskeyEnabled   bool   `json:"passkey_enabled"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil || cfg.RegistrationMode == "" {
		t.Fatalf("body %q: %v", w.Body, err)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-Id") == "" {
		t.Fatalf("headers: %v", w.Header())
	}
	// An unknown route is a JSON 404 inside the pipeline.
	w = r.do(t, r.h, call{method: "GET", path: "/api/v1/nope"})
	expect(t, w, 404, "not_found")
	// A known path with the wrong method is refused too.
	w = r.do(t, r.h, call{method: "DELETE", path: "/api/v1/auth/config"})
	if w.Code != 400 && w.Code != 405 {
		t.Fatalf("wrong method: %d", w.Code)
	}
	// Health is outside the pipeline: no X-Forwarded-For and the container's Host.
	// Only a loopback peer reaches it (admin-r11-4): the container healthcheck does, a neighbour does not.
	w = r.do(t, r.h, call{method: "GET", path: "/healthz", xff: "-", host: "127.0.0.1:8080", peer: "127.0.0.1:40000"})
	expect(t, w, 200, "")
	w = r.do(t, r.h, call{method: "GET", path: "/healthz", xff: "-", host: "127.0.0.1:8080", peer: "10.213.77.5:40000"})
	if w.Code != 404 {
		t.Fatalf("health for a non-loopback peer: %d", w.Code)
	}
}

func TestHostXFFAndCSRFAreEnforcedOnEveryRoute(t *testing.T) {
	r := newRig(t, true)
	expect(t, r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config", host: "evil.test"}), 400, "bad_request")
	expect(t, r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config", xff: "-"}), 400, "bad_request")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", hdr: map[string]string{"Sec-Fetch-Site": "cross-site"}}), 403, "csrf_rejected")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", hdr: map[string]string{"Sec-Fetch-Site": "same-site"}}), 403, "csrf_rejected")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", hdr: map[string]string{"Origin": "https://evil.test"}}), 403, "csrf_rejected")
	// The rightmost X-Forwarded-For is the one that counts: a client-written
	// left part cannot choose its own rate-limit network.
	for i := 0; i < 60; i++ {
		r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config", xff: fmt.Sprintf("10.%d.0.1, 203.0.113.9", i)})
	}
	expect(t, r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config", xff: "198.51.100.77, 203.0.113.9"}), 429, "rate_limited")
}

func TestPublicReadRateLimitIsPerNetworkWithAWideIPv6Bucket(t *testing.T) {
	r := newRig(t, true)
	get := func(xff string) *httptest.ResponseRecorder {
		return r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config", xff: xff})
	}
	for i := 0; i < 60; i++ {
		expect(t, get("203.0.113.9"), 200, "")
	}
	w := get("203.0.113.9")
	expect(t, w, 429, "rate_limited")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	// Same /24, other host: the same bucket.
	expect(t, get("203.0.113.200"), 429, "")
	// Another network is untouched.
	expect(t, get("198.51.100.1"), 200, "")
	// A /48 of IPv6 holds 65,536 /64s; the wide bucket (4x) caps the spread.
	ok := 0
	for i := 0; i < 400; i++ {
		if get(fmt.Sprintf("2001:db8:1:%x::1", i)).Code == 200 {
			ok++
		}
	}
	if ok != 240 {
		t.Fatalf("a /48 spread allowed %d requests, want 240", ok)
	}
}

func TestLogoutEndsOnlyThisSessionAndWritesAnAuditRow(t *testing.T) {
	r := newRig(t, true)
	a1 := r.login(t, r.env.A.Tenant, r.env.A.User, true, false)
	a2 := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	b := r.login(t, r.env.B.Tenant, r.env.B.User, true, false)

	w := r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(a1)}})
	expect(t, w, 204, "")
	cookies := w.Header().Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Fatalf("Set-Cookie: %v", cookies)
	}
	for _, c := range cookies {
		if !strings.Contains(c, "Max-Age=0") || !strings.Contains(c, "Secure") || !strings.Contains(c, "HttpOnly") || strings.Contains(strings.ToLower(c), "domain") {
			t.Errorf("clearing cookie %q", c)
		}
	}
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(a1)}}), 401, "session_expired")
	// The refresh token of the ended session is dead too.
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(a1)}}), 401, "session_expired")
	// Other sessions, of the same user and of the other tenant, are untouched.
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout-all", cookies: []*http.Cookie{sessionCk(b)}, xff: "198.51.100.40"}), 204, "")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(a2)}}), 204, "")

	const q = `SELECT count(*) FROM ctrlz.tenant_audit_log WHERE action = $1`
	count := func(tenant uuid.UUID, action string) (n int) {
		if err := r.st.WithTenant(r.env.Ctx, tenant, store.TxOpts{}, func(tx store.Tx) error {
			return tx.DB().QueryRow(r.env.Ctx, q, action).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(r.env.A.Tenant, "logout") < 2 || count(r.env.B.Tenant, "logout") != 0 || count(r.env.B.Tenant, "logout.all") != 1 {
		t.Fatal("audit rows are not where they belong")
	}
}

func TestLogoutAllEndsEverySessionOfTheUserOnly(t *testing.T) {
	r := newRig(t, true)
	a1 := r.login(t, r.env.A.Tenant, r.env.A.User, true, false)
	a2 := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	b := r.login(t, r.env.B.Tenant, r.env.B.User, true, false)
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout-all", cookies: []*http.Cookie{sessionCk(a1)}}), 204, "")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(a2)}}), 401, "session_expired")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(a2)}}), 401, "session_expired")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(b)}}), 204, "")
}

func TestGatesOnRealRoutes(t *testing.T) {
	r := newRig(t, true)
	// The gate asks the table with the state the user has now (rule one-time-state), so the
	// user is given a live one-time password for the restricted session and a password of
	// their own again after it.
	r.env.Exec(t, `UPDATE ctrlz.users SET must_reset = true, password_expires_at = now() + interval '72 hours' WHERE id = $1`, r.env.A.User)
	restricted := r.login(t, r.env.A.Tenant, r.env.A.User, false, true)
	// session-setup works while restricted; session does not.
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout-all", cookies: []*http.Cookie{sessionCk(restricted)}}), 403, "password_change_required")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(restricted)}}), 204, "")
	r.env.Exec(t, `UPDATE ctrlz.users SET must_reset = false, password_expires_at = NULL WHERE id = $1`, r.env.A.User)

	// Suspended: logout stays open, everything else is 403 account_suspended.
	s1 := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	s2 := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	r.setStatus(t, r.env.A.Tenant, "suspended")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout-all", cookies: []*http.Cookie{sessionCk(s1)}}), 403, "account_suspended")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(s1)}}), 204, "")
	// Deleting reads as an ended session, even for logout.
	r.setStatus(t, r.env.A.Tenant, "deleting")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(s2)}}), 401, "session_expired")

	// No cookie, and a cookie of the wrong name.
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout"}), 401, "session_expired")
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{{Name: "session", Value: "x"}}}), 401, "session_expired")
}

func TestRefreshOverHTTP(t *testing.T) {
	r := newRig(t, true)
	a := r.login(t, r.env.A.Tenant, r.env.A.User, true, false)
	b := r.login(t, r.env.B.Tenant, r.env.B.User, true, false)

	// The browser was restarted: only the refresh cookie remains.
	r.ck.add(3 * time.Hour)
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout-all", cookies: []*http.Cookie{sessionCk(a)}}), 401, "session_expired")
	w := r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(a)}})
	expect(t, w, 204, "")
	got := w.Header().Values("Set-Cookie")
	if len(got) != 2 {
		t.Fatalf("Set-Cookie: %v", got)
	}
	var newSession, newRefresh *http.Cookie
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case session.CookieSession:
			newSession = c
			if c.MaxAge != 0 || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
				t.Errorf("session cookie attributes: %+v", c)
			}
		case session.CookieRefresh:
			newRefresh = c
			if c.MaxAge <= 0 || c.MaxAge > 30*24*3600 || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" {
				t.Errorf("refresh cookie attributes: %+v", c)
			}
		}
	}
	if newSession == nil || newRefresh == nil {
		t.Fatal("both cookies expected")
	}
	// The retry with the new cookie works.
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout-all", cookies: []*http.Cookie{newSession}, xff: "198.51.100.8"}), 204, "")

	// A second tab sends the old refresh cookie inside the grace: 204, no cookies.
	b2 := r.login(t, r.env.A.Tenant, r.env.A.User, true, false)
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(b2)}}), 204, "")
	w = r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(b2)}})
	expect(t, w, 204, "")
	if len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("grace response must carry no cookies: %v", w.Header().Values("Set-Cookie"))
	}
	// Past the grace the old cookie is reuse: 401, cookies cleared.
	r.ck.add(time.Minute)
	w = r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(b2)}})
	expect(t, w, 401, "session_expired")
	if len(w.Header().Values("Set-Cookie")) != 2 {
		t.Fatalf("reuse must clear both cookies: %v", w.Header().Values("Set-Cookie"))
	}
	// B never moved: its refresh token still works (its session cookie is past the
	// 2 h idle limit by the fake clock, like A's).
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(b)}, xff: "198.51.100.9"}), 204, "")
	// No cookie at all.
	expect(t, r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh"}), 401, "session_expired")
}

func TestNoSecretReachesTheLogs(t *testing.T) {
	r := newRig(t, true)
	a := r.login(t, r.env.A.Tenant, r.env.A.User, true, false)
	r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(a)}})
	r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(a)}})
	r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout?token=CANARY-URL", cookies: []*http.Cookie{{Name: session.CookieSession, Value: "CANARY-COOKIE"}}})
	out := r.logs.String()
	for _, c := range []string{a.Session.Reveal(), a.Refresh.Reveal(), "CANARY-URL", "CANARY-COOKIE"} {
		if strings.Contains(out, c) {
			t.Fatalf("log contains a secret: %s", c)
		}
	}
}

// ---------------------------------------------------------------------------
// Synthetic routes for the gates the real document does not use yet.

// TestRateClassRefusalsAreCountedInTheLog is tenant-r18-6 (D64 net-bucket-numbers): the refusals of a rate class are
// counted per class and written at 1, 2, 4, 8, ... with the class, the kind of key it counts on and the count, so
// the numbers of the network buckets can be set from data. The line holds no address, key or cookie.
func TestRateClassRefusalsAreCountedInTheLog(t *testing.T) {
	r := newRig(t, true)
	const peer = "203.0.113.9"
	for i := 0; i < 60+9; i++ {
		r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config", xff: peer})
	}
	var counts []int
	for _, line := range strings.Split(r.logs.String(), "\n") {
		if !strings.Contains(line, "a rate class refused a request") {
			continue
		}
		var rec struct {
			Bucket   string `json:"bucket"`
			KeyKind  string `json:"key_kind"`
			Refusals int    `json:"refusals"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not a JSON line: %q", line)
		}
		if rec.Bucket != "public-read" || rec.KeyKind != "network" {
			t.Errorf("the line names %+v, want the class public-read keyed on the network", rec)
		}
		counts = append(counts, rec.Refusals)
	}
	if fmt.Sprint(counts) != "[1 2 4 8]" {
		t.Errorf("lines for the counts %v after 9 refusals, want [1 2 4 8]", counts)
	}
	for _, leak := range []string{peer, "203.0.113", "X-Forwarded"} {
		if strings.Contains(r.logs.String(), leak) {
			t.Errorf("the log holds %q", leak)
		}
	}
}
