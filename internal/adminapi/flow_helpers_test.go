package adminapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/totp"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The password of the seeded admin once a test has set it up. It passes the
// strength check of 4.3 with the admin minimum.
const (
	adminPW    = "Granite-lantern-Harbor-4471-quill"
	adminNewPW = "Velvet-orbit-Meadow-5528-ember"
	adminName  = "seed-admin"
)

// oneTimeSource replaces password.NewOneTime in a test: it hands out values the
// test knows, so it can grep the logs for them (18.4) and log in with them.
type oneTimeSource struct {
	mu   sync.Mutex
	n    int
	last string
	all  []string
}

func (o *oneTimeSource) next() (secret.String, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.n++
	o.last = fmt.Sprintf("ONETIMEPASSWORD%09d", o.n)
	o.all = append(o.all, o.last)
	return secret.New(o.last), nil
}

func (o *oneTimeSource) issued() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.all...)
}

// setupAdmin turns the seeded admin into a known account. With ready it has the
// password adminPW and an enrolled authenticator, whose seed it returns; without
// it the account is in setup (must_change_password, no TOTP) with adminPW as its
// one-time password.
func (r *rig) setupAdmin(t *testing.T, ready bool) secret.Bytes {
	t.Helper()
	hash, err := r.hasher.Hash(r.env.Ctx, secret.New(adminPW))
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET username = $2, password_hash = $3, must_change_password = $4,
	  password_expires_at = CASE WHEN $4 THEN now() + interval '24 hours' END,
	  totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = $1`,
		seedAdmin, adminName, hash.Reveal(), !ready)
	if !ready {
		return secret.Bytes{}
	}
	seed, err := totp.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	ct, err := r.keys.Seal(keyring.DomainAdminTOTP, totp.AdminAAD(seedAdmin), seed.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET totp_secret_ct = $2, totp_enabled_at = now() WHERE id = $1`, seedAdmin, ct)
	return seed
}

// freeStep forgets the spent TOTP step, so a test that is not about replay can
// use a code again inside the same 30 seconds.
func (r *rig) freeStep(t *testing.T) {
	t.Helper()
	r.env.Exec(t, `UPDATE ctrlz.admin_users SET totp_last_step = NULL WHERE id = $1`, seedAdmin)
}

// totpNow is the current code for a seed.
func totpNow(seed secret.Bytes) string { return totp.Generate(seed, time.Now()) }

// aresp is one response.
type aresp struct {
	t    *testing.T
	Code int
	Body []byte
	H    http.Header
	Dur  time.Duration
}

func (r *aresp) json(v any) {
	r.t.Helper()
	if err := json.Unmarshal(r.Body, v); err != nil {
		r.t.Fatalf("not JSON (status %d): %q", r.Code, r.Body)
	}
}

func (r *aresp) errCode() string {
	var b struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.Body, &b)
	return b.Code
}

// want checks the status and, for an error, its code.
func (r *aresp) want(status int, c string) *aresp {
	r.t.Helper()
	if r.Code != status || (c != "" && r.errCode() != c) {
		r.t.Fatalf("got %d %q, want %d %q", r.Code, r.Body, status, c)
	}
	return r
}

func (r *aresp) cookie(name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.H}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// browser is an admin browser: a cookie jar and an address.
type browser struct {
	r   *rig
	ip  string
	jar map[string]*http.Cookie
}

var ipSeq struct {
	sync.Mutex
	n int
}

// freshIP is an address on a network no earlier browser of the process used, so
// the network-keyed throttles and rate classes of one test do not bleed into the next.
func freshIP() string {
	ipSeq.Lock()
	defer ipSeq.Unlock()
	ipSeq.n++
	return fmt.Sprintf("198.18.%d.%d", ipSeq.n%250+1, ipSeq.n/250+1)
}

func (r *rig) browser() *browser {
	return &browser{r: r, ip: freshIP(), jar: map[string]*http.Cookie{}}
}

// call sends a request to the admin host.
func (b *browser) call(method, path string, body any, hdr ...map[string]string) *aresp {
	return b.callOn(b.r.h, adminHost, method, path, body, hdr...)
}

func (b *browser) callOn(h http.Handler, host, method, path string, body any, hdr ...map[string]string) *aresp {
	tt := b.tb()
	tt.Helper()
	var rd io.Reader
	switch v := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(v)
	case []byte:
		rd = bytes.NewReader(v)
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			tt.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, "/api/v1"+path, rd)
	req.Host = host
	req.Header.Set("X-Forwarded-For", b.ip)
	req.Header.Set("User-Agent", "admin-flow-test")
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, m := range hdr {
		for k, v := range m {
			req.Header.Set(k, v)
		}
	}
	for _, c := range b.jar {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	w := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(w, req)
	res := &aresp{t: tt, Code: w.Code, Body: w.Body.Bytes(), H: w.Header(), Dur: time.Since(start)}
	for _, c := range (&http.Response{Header: res.H}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.jar, c.Name)
		} else {
			b.jar[c.Name] = c
		}
	}
	return res
}

func (b *browser) get(path string) *aresp            { return b.call("GET", path, nil) }
func (b *browser) post(path string, body any) *aresp { return b.call("POST", path, body) }
func (b *browser) put(path string, body any) *aresp  { return b.call("PUT", path, body) }

func (b *browser) tb() *testing.T { return b.r.t }

// login signs in with the seeded admin. It expects 200 and returns the body.
func (b *browser) login(pw, totpCode string) *aresp {
	body := map[string]any{"username": adminName, "password": pw}
	if totpCode != "" {
		body["totp_code"] = totpCode
	}
	return b.post("/auth/login", body)
}

// mustLogin signs in a ready admin and opens the fresh window with a second code.
func (b *browser) mustLogin(seed secret.Bytes) {
	b.tb().Helper()
	b.r.freeStep(b.tb())
	var res struct {
		State string `json:"state"`
	}
	b.login(adminPW, totpNow(seed)).want(200, "").json(&res)
	if res.State != "ready" {
		b.tb().Fatalf("state = %q", res.State)
	}
}

// fresh opens the five minute window with a code.
func (b *browser) fresh(seed secret.Bytes) {
	b.tb().Helper()
	b.r.freeStep(b.tb())
	b.post("/auth/totp/fresh", map[string]any{"code": totpNow(seed)}).want(200, "")
}

// count reads one number as the superuser.
func (r *rig) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	r.env.Scan(t, sql, args, &n)
	return n
}

// syncLog is a log sink two handlers can share.
type syncLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncLog) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// handler builds another admin handler over the same store, sessions and
// limiter, for a test that changes one dependency (the environment, the hasher).
func (r *rig) handler(t *testing.T, mutate func(*Deps)) http.Handler {
	t.Helper()
	d := r.deps
	mutate(&d)
	h, err := New(d, httpx.NewHealth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// admin sets the seeded admin up as ready and signs a browser in. The login's
// TOTP check opens the fresh window, so the admin-fresh routes work at once.
func (r *rig) admin(t *testing.T) (*browser, secret.Bytes) {
	t.Helper()
	seed := r.setupAdmin(t, true)
	b := r.browser()
	b.mustLogin(seed)
	return b, seed
}

func secretOf(s string) secret.String { return secret.New(s) }

// assertQuiet fails if the process log holds a secret the test used (18.4).
func (r *rig) assertQuiet(t *testing.T, secrets ...string) {
	t.Helper()
	log := r.logs.String()
	for _, s := range append([]string{adminPW, adminNewPW}, secrets...) {
		if s != "" && strings.Contains(log, s) {
			t.Errorf("the log holds a secret (%d characters starting %q)", len(s), s[:min(2, len(s))])
		}
	}
	for _, s := range r.once.issued() {
		if strings.Contains(log, s) {
			t.Error("the log holds a one-time password")
		}
	}
}
