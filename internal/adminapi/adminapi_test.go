package adminapi

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

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	adminapidoc "github.com/Kup1ng/CtrlZ-Panel/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/api"
	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

const (
	adminHost = "admin.example.test"
	panelHost = "panel.example.test"
)

var seedAdmin = uuid.MustParse("00000000-0000-7000-8000-0000000000e1")

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
	t *testing.T
	// codes is the code source of the tenant API of this rig, so that a test can finish a registration.
	codes  *lastCode
	keys   *keyring.Ring
	hasher *password.Hasher
	logs   *syncLog
	deps   Deps
	once   *oneTimeSource
	env    *authtest.Env
	adm    *store.Store
	ck     *clock
	m      *session.Manager
	lim    *ratelimit.Limiter
	h      http.Handler
	tenant http.Handler // the panel's API, to prove the two do not share cookies
	tm     *session.Manager
	tst    *store.Store
}

func newRig(t *testing.T) *rig { return newRigKeys(t, authtest.AdminKeys(t)) }

// newRigKeys is newRig on a given key ring, for a test that shares keys with the worker.
func newRigKeys(t *testing.T, keys *keyring.Ring) *rig { return newRigOn(t, keys, 0) }

// newRigOn is newRigKeys with a pool of maxConns connections for the admin
// store (0 keeps the test default), for the tests that are about how many
// connections a request needs.
func newRigOn(t *testing.T, keys *keyring.Ring, maxConns int32) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	adm := env.Admin(t)
	if maxConns > 0 {
		cfg := env.DB.StoreConfig(store.RoleAdmin)
		cfg.MaxConns = maxConns
		var err error
		if adm, err = store.Open(env.Ctx, cfg); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(adm.Close)
	}
	ck := &clock{t: time.Now().UTC()}
	m := session.NewManager(adm, session.DefaultPolicy(), ck.now)
	if err := m.WithKeys(keys, keyring.DomainAdminMAC); err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.New(ratelimit.Config{Service: ratelimit.Admin, LocalOnly: true, Now: ck.now})
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	hasher, logs, once := authtest.FastHasher(t), &syncLog{}, &oneTimeSource{}
	deps := Deps{Log: slog.New(slog.NewJSONHandler(logs, nil)), Store: adm, Sessions: m, Limiter: lim, AdminHost: adminHost, PanelHost: panelHost, Env: EnvTest, Strict: true,
		Keys: keys, Hasher: hasher, NewOneTime: once.next}
	h, err := New(deps, httpx.NewHealth(health))
	if err != nil {
		t.Fatal(err)
	}
	tst := env.Tenant(t)
	tm := session.NewManager(tst, session.DefaultPolicy(), ck.now)
	tenantKeys := authtest.APIKeys(t)
	if err := tm.WithKeys(tenantKeys, keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	codes := &lastCode{}
	th, err := api.New(api.Deps{
		Log: slog.New(slog.NewJSONHandler(logs, nil)), Store: tst, Sessions: tm,
		Limiter: ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: ck.now}),
		Keys:    tenantKeys, Invites: authtest.InvitesOf(t, keys), Hasher: authtest.FastHasher(t), PanelHost: panelHost, Strict: true, Now: ck.now,
		OTPOptions: []otp.Option{otp.WithCodeSource(codes.next)},
	}, httpx.NewHealth(health))
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, codes: codes, deps: deps, keys: keys, hasher: hasher, logs: logs, once: once, env: env, adm: adm, ck: ck, m: m, lim: lim, h: h, tenant: th, tm: tm, tst: tst}
}

func (r *rig) adminSession(t *testing.T) session.AdminIssued {
	t.Helper()
	var iss session.AdminIssued
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		iss, err = r.m.AdminCreate(g, session.AdminNew{Admin: seedAdmin, IP: netip.MustParseAddr("203.0.113.9"), UserAgent: "t"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return iss
}

// ready enrols TOTP for the seed admin, so its sessions are no longer in setup.
func (r *rig) ready(t *testing.T) {
	t.Helper()
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		if _, ok, err := g.AdminSetPassword(seedAdmin, secret.New("hash")); err != nil || !ok {
			t.Fatalf("password: %v %v", ok, err)
		}
		if ok, err := g.AdminTOTPSetPending(seedAdmin, []byte("sealed-seed")); err != nil || !ok {
			t.Fatalf("pending: %v %v", ok, err)
		}
		if _, ok, err := g.AdminTOTPEnable(seedAdmin, 1); err != nil || !ok {
			t.Fatalf("enable: %v %v", ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (r *rig) do(h http.Handler, method, path, hostName string, cookies []*http.Cookie, xff string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.Host = hostName
	if xff == "" {
		xff = "203.0.113.9"
	}
	req.Header.Set("X-Forwarded-For", xff)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func code(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	return b.Code
}

func expect(t *testing.T, w *httptest.ResponseRecorder, status int, c string) {
	t.Helper()
	if w.Code != status || (c != "" && code(t, w) != c) {
		t.Fatalf("got %d %q, want %d %q", w.Code, w.Body.String(), status, c)
	}
}

func adminCk(i session.AdminIssued) *http.Cookie {
	return &http.Cookie{Name: session.CookieAdmin, Value: i.Token.Reveal()}
}

func TestEveryAdminOperationCarriesBothExtensions(t *testing.T) {
	ops, err := apispec.Parse(adminapidoc.Admin(), ratelimit.Admin)
	if err != nil || len(ops) == 0 {
		t.Fatalf("%v (%d ops)", err, len(ops))
	}
	// The panel's values are not the admin's.
	if _, err := apispec.Parse([]byte("paths:\n  /x:\n    get: {operationId: x, x-ctrlz-auth: session, x-ctrlz-rate: admin-read}\n"), ratelimit.Admin); err == nil {
		t.Fatal("an admin document may not use the tenant auth values")
	}
	if _, err := apispec.Parse([]byte("paths:\n  /x:\n    get: {operationId: x, x-ctrlz-auth: admin, x-ctrlz-rate: user-read}\n"), ratelimit.Admin); err == nil {
		t.Fatal("an admin document may not use the tenant rate classes")
	}
}

func TestAdminLogoutAndTheHostAndCSRFChecks(t *testing.T) {
	r := newRig(t)
	s := r.adminSession(t)
	// The panel host is not the admin host.
	expect(t, r.do(r.h, "POST", "/api/v1/auth/logout", panelHost, []*http.Cookie{adminCk(s)}, "", nil), 400, "bad_request")
	expect(t, r.do(r.h, "POST", "/api/v1/auth/logout", adminHost, []*http.Cookie{adminCk(s)}, "", map[string]string{"Sec-Fetch-Site": "same-site"}), 403, "csrf_rejected")
	// A setup session may log out (admin-setup).
	w := r.do(r.h, "POST", "/api/v1/auth/logout", adminHost, []*http.Cookie{adminCk(s)}, "", nil)
	expect(t, w, 204, "")
	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "Max-Age=0") || !strings.Contains(cookie, "SameSite=Strict") || !strings.Contains(cookie, "Secure") || strings.Contains(strings.ToLower(cookie), "domain") {
		t.Fatalf("clearing cookie: %q", cookie)
	}
	expect(t, r.do(r.h, "POST", "/api/v1/auth/logout", adminHost, []*http.Cookie{adminCk(s)}, "", nil), 401, "session_expired")
	// The logout is in the audit chain.
	var n int
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		rows, err := g.AuditPage(0, "admin.logout", 10)
		n = len(rows)
		return err
	}); err != nil || n != 1 {
		t.Fatalf("admin.logout audit rows: %d %v", n, err)
	}
}

func TestPanelAndAdminCookiesDoNotCrossOver(t *testing.T) {
	r := newRig(t)
	as := r.adminSession(t)
	var ps session.Issued
	if err := r.tst.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		ps, err = r.tm.Create(tx, session.NewSession{User: r.env.A.User, Method: "password", IP: netip.MustParseAddr("203.0.113.9")})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A panel session cookie on the admin host, under the admin cookie's name or
	// its own: 401 either way.
	expect(t, r.do(r.h, "POST", "/api/v1/auth/logout", adminHost, []*http.Cookie{{Name: session.CookieAdmin, Value: ps.Session.Reveal()}}, "", nil), 401, "session_expired")
	expect(t, r.do(r.h, "POST", "/api/v1/auth/logout", adminHost, []*http.Cookie{{Name: session.CookieSession, Value: ps.Session.Reveal()}}, "", nil), 401, "session_expired")
	// An admin session cookie on the panel host: 401 either way.
	expect(t, r.do(r.tenant, "POST", "/api/v1/auth/logout", panelHost, []*http.Cookie{{Name: session.CookieSession, Value: as.Token.Reveal()}}, "", nil), 401, "session_expired")
	expect(t, r.do(r.tenant, "POST", "/api/v1/auth/logout", panelHost, []*http.Cookie{{Name: session.CookieAdmin, Value: as.Token.Reveal()}}, "", nil), 401, "session_expired")
	// No admin route exists on the panel host and no panel route on the admin host.
	expect(t, r.do(r.h, "POST", "/api/v1/auth/logout-all", adminHost, []*http.Cookie{adminCk(as)}, "", nil), 404, "not_found")
	// Both sessions still work on their own side.
	expect(t, r.do(r.tenant, "POST", "/api/v1/auth/logout", panelHost, []*http.Cookie{{Name: session.CookieSession, Value: ps.Session.Reveal()}}, "", nil), 204, "")
	expect(t, r.do(r.h, "POST", "/api/v1/auth/logout", adminHost, []*http.Cookie{adminCk(as)}, "", nil), 204, "")
}

// synth registers routes over a document that holds the admin gates no real
// route of this work package uses.
func (r *rig) synth(t *testing.T) http.Handler {
	t.Helper()
	doc := `paths:
  /t/setup:
    get: {operationId: setup, x-ctrlz-auth: admin-setup, x-ctrlz-rate: admin-read}
  /t/admin:
    get: {operationId: admin, x-ctrlz-auth: admin, x-ctrlz-rate: admin-read}
  /t/fresh:
    post: {operationId: fresh, x-ctrlz-auth: admin-fresh, x-ctrlz-rate: admin-write}
  /t/login:
    post: {operationId: login, x-ctrlz-auth: none, x-ctrlz-rate: admin-login}
`
	ops, err := apispec.Parse([]byte(doc), ratelimit.Admin)
	if err != nil {
		t.Fatal(err)
	}
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Strict: true, Limiter: r.lim, Service: ratelimit.Admin, Ops: ops, SkipRequestCheck: true,
		Resolver: resolver{m: r.m}, BaseURL: "/api/v1", Host: httpx.StaticHost(adminHost),
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{}`) })
	g := built.Router.With(built.PerOp)
	g.Get("/v1/t/setup", ok)
	g.Get("/v1/t/admin", ok)
	g.Post("/v1/t/fresh", ok)
	// The class admin-login is deferred: the route answers its refusal, as the real handler does for everyone but the console password.
	g.Post("/v1/t/login", func(w http.ResponseWriter, r *http.Request) {
		if e := httpx.DeferredRefusal(r.Context()); e != nil {
			httpx.Write(w, r, e)
			return
		}
		io.WriteString(w, `{}`)
	})
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	return root
}

func TestSetupGateAndFreshTOTP(t *testing.T) {
	r := newRig(t)
	h := r.synth(t)
	s := r.adminSession(t)
	cks := []*http.Cookie{adminCk(s)}

	// Before TOTP is enrolled the account is in setup: only admin-setup routes.
	expect(t, r.do(h, "GET", "/api/v1/t/setup", adminHost, cks, "", nil), 200, "")
	expect(t, r.do(h, "GET", "/api/v1/t/admin", adminHost, cks, "", nil), 403, "setup_required")
	expect(t, r.do(h, "POST", "/api/v1/t/fresh", adminHost, cks, "", nil), 403, "setup_required")

	// Enrolled: the same session now passes admin routes, and the setup routes.
	r.ready(t)
	expect(t, r.do(h, "GET", "/api/v1/t/admin", adminHost, cks, "", nil), 200, "")
	expect(t, r.do(h, "GET", "/api/v1/t/setup", adminHost, cks, "", nil), 200, "")
	// admin-fresh needs a TOTP check. The session was made without one.
	expect(t, r.do(h, "POST", "/api/v1/t/fresh", adminHost, cks, "", nil), 403, "totp_fresh_required")

	// A TOTP check opens a five minute window.
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, ok, err := g.AdminSessionFresh(s.SessionID, r.ck.now())
		if !ok {
			t.Fatal("session not found")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expect(t, r.do(h, "POST", "/api/v1/t/fresh", adminHost, cks, "", nil), 200, "")
	r.ck.add(5*time.Minute + time.Second)
	// (the idle limit is 15 minutes, so the session itself is alive)
	expect(t, r.do(h, "POST", "/api/v1/t/fresh", adminHost, cks, "", nil), 403, "totp_fresh_required")
}

func TestAdminSessionLimits(t *testing.T) {
	r := newRig(t)
	h := r.synth(t)
	r.ready(t)
	s := r.adminSession(t)
	cks := []*http.Cookie{adminCk(s)}
	// 15 minutes idle.
	r.ck.add(14 * time.Minute)
	expect(t, r.do(h, "GET", "/api/v1/t/admin", adminHost, cks, "", nil), 200, "")
	// That request slid the limit (touch), so another 14 minutes pass.
	r.ck.add(14 * time.Minute)
	expect(t, r.do(h, "GET", "/api/v1/t/admin", adminHost, cks, "", nil), 200, "")
	r.ck.add(16 * time.Minute)
	expect(t, r.do(h, "GET", "/api/v1/t/admin", adminHost, cks, "", nil), 401, "session_expired")
}

func TestAdminLoginClassIsFivePerMinutePerNetwork(t *testing.T) {
	r := newRig(t)
	h := r.synth(t)
	ok := 0
	for i := 0; i < 8; i++ {
		if r.do(h, "POST", "/api/v1/t/login", adminHost, nil, "198.51.100.7", nil).Code == 200 {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("admin-login allowed %d, want 5", ok)
	}
	if w := r.do(h, "POST", "/api/v1/t/login", adminHost, nil, "198.51.100.200", nil); w.Code != 429 {
		t.Fatalf("same /24: %d", w.Code)
	}
	if w := r.do(h, "POST", "/api/v1/t/login", adminHost, nil, "192.0.2.1", nil); w.Code != 200 {
		t.Fatalf("another network: %d", w.Code)
	}
}

func TestAdminWriteClassIsSixtyPerMinutePerSession(t *testing.T) {
	r := newRig(t)
	h := r.synth(t)
	r.ready(t)
	s := r.adminSession(t)
	if err := r.adm.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, _, err := g.AdminSessionFresh(s.SessionID, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cks := []*http.Cookie{adminCk(s)}
	ok := 0
	for i := 0; i < 70; i++ {
		// Many networks, so only the session-keyed class can refuse.
		if r.do(h, "POST", "/api/v1/t/fresh", adminHost, cks, "198.51.100."+itoa(i+1), nil).Code == 200 {
			ok++
		}
	}
	if ok != 60 {
		t.Fatalf("admin-write allowed %d, want 60", ok)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// lastCode makes the OTP codes of the tenant API of a rig and remembers the last one, which is what the SMS would
// have carried.
type lastCode struct {
	mu   sync.Mutex
	n    int
	code string
}

func (c *lastCode) next() (secret.String, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	c.code = fmt.Sprintf("%06d", 400000+c.n)
	return secret.New(c.code), nil
}

func (c *lastCode) last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}
