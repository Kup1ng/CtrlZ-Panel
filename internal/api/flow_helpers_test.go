package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/afterwork"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/otp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/recovery"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
)

// The passwords of the seeded users. They pass the strength check of 4.3.
const (
	pwA = "Quartz-lantern-Harbor-7391"
	pwB = "Velvet-orbit-Meadow-5528"
)

// codeLog makes the OTP codes of a test predictable and remembers the last one,
// which stands in for the SMS the worker would have sent.
type codeLog struct {
	mu sync.Mutex
	n  int
	// start is the first code minus one; zero means 100000. The canary test sets a
	// value no timestamp is likely to contain.
	start int
	last  string
	hist  []string
}

func (c *codeLog) next() (secret.String, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	first := 100000
	if c.start != 0 {
		first = c.start
	}
	c.last = fmt.Sprintf("%06d", first+c.n)
	c.hist = append(c.hist, c.last)
	return secret.New(c.last), nil
}

// Back is the code issued n requests ago (1 is the last).
func (c *codeLog) Back(n int) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hist[len(c.hist)-n]
}

func (c *codeLog) Last() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// frig is the rig of the flow tests: the full tenant API over real Postgres
// with two seeded tenants, a fake clock, OTP codes the test can read, and an
// Argon2 hasher small enough to be quick.
type frig struct {
	t      *testing.T
	env    *authtest.Env
	st     *store.Store
	ck     *clock
	m      *session.Manager
	h      http.Handler
	hasher *password.Hasher
	keys   *keyring.Ring
	codes  *codeLog
	logs   *strings.Builder
	ipSeq  int
	deps   Deps
	after  *afterwork.Queue // the production queue of work owed after a floor; a test waits on it before it reads the rows
	health httpx.Health
	srv    *Server // the server behind h, for the tests that read a decision off it directly
}

type frigOpts struct {
	passkey bool   // switch Passkey on for the RP ID panel.localhost
	mode    string // registration mode; empty keeps the default (closed)
}

func newFrig(t *testing.T, o frigOpts) *frig {
	t.Helper()
	env := authtest.New(t, cluster)
	st := env.Tenant(t)
	ck := &clock{t: time.Now().UTC()}
	m := session.NewManager(st, session.DefaultPolicy(), ck.now)
	logs := &strings.Builder{}
	f := &frig{t: t, env: env, st: st, ck: ck, m: m, hasher: authtest.FastHasher(t), keys: authtest.APIKeys(t), codes: &codeLog{}, logs: logs}
	if err := m.WithKeys(f.keys, keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	if o.passkey {
		env.Exec(t, `UPDATE ctrlz.webauthn_config SET rp_id = 'panel.localhost', allowed_origins = ARRAY['https://panel.localhost'], enabled = true`)
	}
	if o.mode != "" {
		env.Exec(t, `UPDATE ctrlz.system_settings SET registration_mode = $1`, o.mode)
	}
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"status":"ok"}`) })
	f.deps = Deps{
		Log: slog.New(slog.NewJSONHandler(logs, nil)), Store: st, Sessions: m,
		Limiter: ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: ck.now}),
		Keys:    f.keys, Hasher: f.hasher, PanelHost: host, Strict: true, Now: ck.now,
		OTPOptions: []otp.Option{otp.WithCodeSource(f.codes.next)},
	}
	f.after = afterwork.New(0, 0, 0)
	f.deps.After = f.after
	f.health = httpx.NewHealth(health)
	f.setLimiter(f.deps.Limiter)
	// The seeded users get real passwords; the seed holds a placeholder.
	f.setPassword(env.A.Tenant, env.A.User, pwA)
	f.setPassword(env.B.Tenant, env.B.User, pwB)
	return f
}

// setLimiter rebuilds the handler over the same store, sessions and keys with a
// different rate limiter: the Valkey fault tests swap one for another while the
// database, the users and the issued challenges stay.
func (f *frig) setLimiter(l *ratelimit.Limiter) {
	f.t.Helper()
	d := f.deps
	d.Limiter = l
	h, srv, err := build(d, f.health)
	if err != nil {
		f.t.Fatal(err)
	}
	f.h, f.srv = h, srv
}

func (f *frig) setPassword(tenant, user uuid.UUID, pw string) {
	f.t.Helper()
	h, err := f.hasher.Hash(f.env.Ctx, secret.New(pw))
	if err != nil {
		f.t.Fatal(err)
	}
	f.env.Exec(f.t, `UPDATE ctrlz.users SET password_hash = $3 WHERE tenant_id = $1 AND id = $2`, tenant, user, h.Reveal())
}

// freshIP is an address on a network no earlier call of this test used, so the
// network-keyed rate classes and throttles of one step do not bleed into the next.
func (f *frig) freshIP() string {
	f.ipSeq++
	return fmt.Sprintf("198.51.%d.9", f.ipSeq%250+1)
}

// clearOTP forgets issued challenges and the daily counters, so a test can ask
// for another code for the same phone inside the 60 second cooldown. The
// database clock is real; only this resets it.
func (f *frig) clearOTP() {
	f.t.Helper()
	f.env.Exec(f.t, `DELETE FROM ctrlz.otp_challenges`)
	f.env.Exec(f.t, `TRUNCATE ctrlz.sms_counters`)
}

func (f *frig) clearThrottle() {
	f.t.Helper()
	f.env.Exec(f.t, `DELETE FROM ctrlz.auth_throttle`)
}

// client is a browser: a cookie jar and an address.
type client struct {
	f   *frig
	ip  string
	jar map[string]*http.Cookie
	hdr map[string]string
}

func (f *frig) client() *client {
	return &client{f: f, ip: f.freshIP(), jar: map[string]*http.Cookie{}, hdr: map[string]string{}}
}

// resp is one response.
type resp struct {
	t    *testing.T
	Code int
	Body []byte
	H    http.Header
	Dur  time.Duration
}

func (r *resp) json(v any) {
	r.t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		r.t.Fatalf("not JSON (status %d): %q", r.Code, r.Body)
	}
}

func (r *resp) code() string {
	var b struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.Body, &b)
	return b.Code
}

// want checks the status and, for an error, its code.
func (r *resp) want(status int, code string) *resp {
	r.t.Helper()
	if r.Code != status || (code != "" && r.code() != code) {
		r.t.Fatalf("got %d %q, want %d %q", r.Code, r.Body, status, code)
	}
	return r
}

func (r *resp) cookies() []*http.Cookie { return (&http.Response{Header: r.H}).Cookies() }

func (r *resp) cookie(name string) *http.Cookie {
	for _, c := range r.cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// do sends a request and applies the Set-Cookie headers of the answer to the jar.
func (c *client) do(method, path string, body any, extra ...map[string]string) *resp {
	t := c.f.t
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/v1"+path, rd)
	req.Host = host
	req.Header.Set("X-Forwarded-For", c.ip)
	req.Header.Set("User-Agent", "flow-test")
	if rd != nil {
		// The pipeline checks a body against its schema and takes only JSON (rule boundary-input).
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.hdr {
		req.Header.Set(k, v)
	}
	for _, e := range extra {
		for k, v := range e {
			req.Header.Set(k, v)
		}
	}
	for _, ck := range c.jar {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	w := httptest.NewRecorder()
	start := time.Now()
	c.f.h.ServeHTTP(w, req)
	r := &resp{t: t, Code: w.Code, Body: w.Body.Bytes(), H: w.Header(), Dur: time.Since(start)}
	for _, ck := range r.cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.jar, ck.Name)
		} else {
			c.jar[ck.Name] = ck
		}
	}
	return r
}

func (c *client) get(path string) *resp            { return c.do("GET", path, nil) }
func (c *client) post(path string, body any) *resp { return c.do("POST", path, body) }
func (c *client) postT(path, ticket string, body []byte) *resp {
	return c.do("POST", path, body, map[string]string{"X-Ctrlz-Ticket": ticket})
}

// forget drops one cookie, as a browser restart drops a session cookie.
func (c *client) forget(name string) { delete(c.jar, name) }

// loginPassword signs in and returns the response. It expects 200.
func (c *client) loginPassword(phone, pw string, remember bool) *resp {
	c.f.t.Helper()
	return c.post("/auth/login/password", map[string]any{"phone": phone, "password": pw, "remember_me": remember})
}

func (c *client) mustLogin(phone, pw string) {
	c.f.t.Helper()
	r := c.loginPassword(phone, pw, false).want(200, "")
	var res struct {
		Status string `json:"status"`
	}
	r.json(&res)
	if res.Status != "authenticated" {
		c.f.t.Fatalf("login status = %q", res.Status)
	}
}

func (c *client) reauthPassword(pw string) *resp {
	return c.post("/auth/reauth", map[string]any{"password": pw})
}

// me reads GET /me.
type meBody struct {
	User struct {
		ID          uuid.UUID `json:"id"`
		PhoneMasked string    `json:"phone_masked"`
		HasPassword bool      `json:"has_password"`
		MustReset   bool      `json:"must_reset"`
		Locale      string    `json:"locale"`
		Theme       string    `json:"theme"`
	} `json:"user"`
	Security struct {
		TOTPEnabled           bool    `json:"totp_enabled"`
		RecoveryCodesLeft     int     `json:"recovery_codes_left"`
		Passkeys              int     `json:"passkeys"`
		EnforcePasskey        bool    `json:"enforce_passkey"`
		EnforceLiftAt         *string `json:"enforce_lift_at"`
		PasskeyReviewRequired bool    `json:"passkey_review_required"`
	} `json:"security"`
	Tenant struct {
		ID     uuid.UUID `json:"id"`
		Status string    `json:"status"`
	} `json:"tenant"`
}

func (c *client) me() meBody {
	c.f.t.Helper()
	var m meBody
	c.get("/me").want(200, "").json(&m)
	return m
}

func (f *frig) phoneOf(ids catalogtest.SeedIDs) string { return ids.Phone }

// count reads one number as the superuser.
func (f *frig) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	f.env.Scan(f.t, sql, args, &n)
	return n
}

func secretString(s string) secret.String { return secret.New(s) }

// newRecoveryFixtures makes a set of recovery codes with the production
// generator: the codes to type and the hashes to store.
func newRecoveryFixtures(t *testing.T) ([]string, [][]byte) {
	t.Helper()
	set, err := recovery.NewSet()
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, c := range set.Codes {
		codes = append(codes, c.Reveal())
	}
	return codes, set.Hashes
}

// assertQuiet fails if the process log holds a secret the test used: the
// passwords, every OTP code that was made, and any extra value given (tokens,
// seeds, recovery codes). Spec 18.4: secrets never reach logs.
func (f *frig) assertQuiet(extra ...string) {
	f.t.Helper()
	log := f.logs.String()
	secrets := append([]string{pwA, pwB, "Cobalt-meadow-Falcon-4417", "Marble-Island-Copper-6620"}, extra...)
	f.codes.mu.Lock()
	secrets = append(secrets, f.codes.hist...)
	f.codes.mu.Unlock()
	for _, s := range secrets {
		if s != "" && strings.Contains(log, s) {
			f.t.Errorf("the log holds a secret (%d characters starting %q)", len(s), s[:min(2, len(s))])
		}
	}
}

// cookieValues are the session, refresh and device tokens a client holds.
func (c *client) cookieValues() []string {
	var out []string
	for _, ck := range c.jar {
		out = append(out, ck.Value)
	}
	return out
}
