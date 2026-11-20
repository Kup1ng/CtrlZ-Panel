package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/apispec"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// synth builds a pipeline over a small document, so gates that no route of this
// work package uses (reauth, the session-keyed classes, otp-send, the raised body
// limit) run through the same code the real routes do.
func (r *rig) synth(t *testing.T, lim *ratelimit.Limiter) http.Handler {
	t.Helper()
	doc := `paths:
  /t/read:
    get: {operationId: read, x-ctrlz-auth: session, x-ctrlz-rate: user-read}
  /t/sensitive:
    post: {operationId: sensitive, x-ctrlz-auth: reauth, x-ctrlz-rate: sensitive}
  /t/open-otp:
    post: {operationId: openOtp, x-ctrlz-auth: none, x-ctrlz-rate: otp-send}
  /t/big/{id}:
    post: {operationId: big, x-ctrlz-auth: none, x-ctrlz-rate: auth, x-ctrlz-max-body: 65536}
`
	ops, err := apispec.Parse([]byte(doc), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Strict: true, Limiter: lim, Service: ratelimit.Tenant, Ops: ops, SkipRequestCheck: true,
		Resolver: resolver{m: r.m}, BaseURL: "/api/v1", Host: httpx.StaticHost(host),
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n, err := io.Copy(io.Discard, req.Body)
		if err != nil {
			httpx.Write(w, req, httpx.FromError(err))
			return
		}
		fmt.Fprintf(w, `{"read":%d}`, n)
	})
	g := built.Router.With(built.PerOp)
	g.Get("/v1/t/read", ok)
	g.Post("/v1/t/sensitive", ok)
	// otp-send is a deferred class: the pipeline hands over the refusal of a spent bucket and the handler answers it
	// (budget.Bucket.Deferred), as the real route does.
	g.Post("/v1/t/open-otp", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if e := httpx.DeferredRefusal(req.Context()); e != nil {
			httpx.Write(w, req, e)
			return
		}
		ok(w, req)
	}))
	g.Post("/v1/t/big/{id}", ok)
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	return root
}

// reauthed returns a copy of a session whose reauth window is open, rotating it
// the way POST /auth/reauth will.
func (r *rig) reauthed(t *testing.T) session.Issued {
	t.Helper()
	s := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	var out session.Issued
	if err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) (err error) {
		out, err = r.m.Rotate(tx, s.SessionID, store.ReauthSet, false)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRandomCookiesCostNothingAndNeverLockLiveSessionsOut is tenant-r4-4. A
// random cookie fails its tag and is refused 401 before any charge and any
// lookup, so a host that sends them cannot empty a bucket that live sessions
// behind the same carrier NAT share: the junk and the live session come from the
// same IPv4 /24 and from the same IPv6 /48 here. A cookie that was issued here
// and is dead is charged to its own bucket, so replaying it cannot lock anyone
// else out either.
func TestRandomCookiesCostNothingAndNeverLockLiveSessionsOut(t *testing.T) {
	r := newRig(t, true)
	h := r.synth(t, r.lim)
	live := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	get := func(c *http.Cookie, xff string) *httptest.ResponseRecorder {
		var cks []*http.Cookie
		if c != nil {
			cks = []*http.Cookie{c}
		}
		return r.do(t, h, call{method: "GET", path: "/api/v1/t/read", cookies: cks, xff: xff})
	}

	// A live session is never throttled by the lookup class: each lookup gives its
	// token back, so 250 requests pass.
	for i := 0; i < 250; i++ {
		if w := get(sessionCk(live), "192.0.2.50"); w.Code != 200 {
			t.Fatalf("request %d from a live session: %d %s", i, w.Code, w.Body)
		}
	}

	// Junk, well past any per-network budget, from the /24 and the /48 of the live
	// session's users. Every one is a plain 401, and none of them was charged: the
	// limiter holds no bucket for them.
	before := r.lim.LocalSize()
	for i := 0; i < 400; i++ {
		junk := &http.Cookie{Name: session.CookieSession, Value: strings.Repeat("A", 42) + string(rune('A'+i%26))}
		expect(t, get(junk, "198.51.100.5"), 401, "session_expired")
		expect(t, get(junk, "2001:db8:1:1::5"), 401, "session_expired")
	}
	if got := r.lim.LocalSize(); got != before {
		t.Fatalf("random cookies created %d limiter buckets, want none", got-before)
	}
	expect(t, get(sessionCk(live), "198.51.100.77"), 200, "")
	expect(t, get(sessionCk(live), "2001:db8:1:2::9"), 200, "")

	// A dead cookie that carries a valid tag is worth one lookup. The pipeline then remembers
	// it (primitives-r6-5): every later use is a plain 401 with no lookup and no new bucket, however
	// many there are, and the live session beside it on the same /24 and /48 still gets in. Round 5
	// charged the dead cookie's own bucket and the network's, and the network's refused the live
	// ones.
	dead := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	if err := r.st.WithTenant(r.env.Ctx, r.env.A.Tenant, store.TxOpts{}, func(tx store.Tx) error {
		_, err := tx.SessionRevoke(r.env.A.User, dead.SessionID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expect(t, get(sessionCk(dead), "198.51.100.5"), 401, "session_expired") // the one lookup
	known := r.lim.LocalSize()
	for i := 0; i < 400; i++ {
		expect(t, get(sessionCk(dead), "198.51.100.5"), 401, "session_expired")
		expect(t, get(sessionCk(dead), "2001:db8:1:1::5"), 401, "session_expired")
	}
	if got := r.lim.LocalSize(); got != known {
		t.Fatalf("a remembered dead cookie created %d limiter buckets, want none", got-known)
	}
	expect(t, get(sessionCk(live), "198.51.100.77"), 200, "")
	expect(t, get(sessionCk(live), "2001:db8:1:2::9"), 200, "")

	// A request with no cookie costs nothing and is a plain 401.
	expect(t, get(nil, "198.51.100.5"), 401, "session_expired")
}

// TestSessionTokenTagIsKeyed pins the tag itself: a token one byte off is not
// screened in, and a token tagged under another installation's key is not either.
func TestSessionTokenTagIsKeyed(t *testing.T) {
	r := newRig(t, true)
	live := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	tok := live.Session.Reveal()
	if _, _, ok := r.m.Screen(tok); !ok {
		t.Fatal("a token this manager issued is not screened in")
	}
	flipped := []byte(tok)
	flipped[0] ^= 1 // still base64url, still 64 characters
	if _, _, ok := r.m.Screen(string(flipped)); ok {
		t.Fatal("a token with a changed byte passes the tag")
	}
	other := session.NewManager(r.st, session.DefaultPolicy(), r.ck.now)
	if err := other.WithKeys(authtest.APIKeys(t), keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := other.Screen(tok); ok {
		t.Fatal("a token tagged under another key passes the tag")
	}
}

func TestReauthGate(t *testing.T) {
	r := newRig(t, true)
	h := r.synth(t, r.lim)
	plain := r.login(t, r.env.A.Tenant, r.env.A.User, false, false)
	expect(t, r.do(t, h, call{method: "POST", path: "/api/v1/t/sensitive", cookies: []*http.Cookie{sessionCk(plain)}}), 403, "reauth_required")

	fresh := r.reauthed(t)
	expect(t, r.do(t, h, call{method: "POST", path: "/api/v1/t/sensitive", cookies: []*http.Cookie{sessionCk(fresh)}}), 200, "")
	// Ten minutes later the window is closed.
	r.ck.add(10*time.Minute + time.Second)
	expect(t, r.do(t, h, call{method: "POST", path: "/api/v1/t/sensitive", cookies: []*http.Cookie{sessionCk(fresh)}}), 403, "reauth_required")
}

func TestSensitiveClassIsTenPerMinutePerSession(t *testing.T) {
	r := newRig(t, true)
	h := r.synth(t, r.lim)
	s1, s2 := r.reauthed(t), r.reauthed(t)
	count := func(s session.Issued) (ok int) {
		for i := 0; i < 15; i++ {
			// Different networks, so only the session-keyed class can refuse.
			w := r.do(t, h, call{method: "POST", path: "/api/v1/t/sensitive", cookies: []*http.Cookie{sessionCk(s)}, xff: fmt.Sprintf("198.51.100.%d", i+1)})
			switch w.Code {
			case 200:
				ok++
			case 429:
			default:
				t.Fatalf("unexpected %d %s", w.Code, w.Body)
			}
		}
		return ok
	}
	if a, b := count(s1), count(s2); a != 10 || b != 10 {
		t.Fatalf("allowed %d and %d, want 10 each", a, b)
	}
}

func TestOTPSendClassFailsClosedWithoutValkeyAndCountsPerNetwork(t *testing.T) {
	down := newRig(t, false) // no backend and not local-only: Valkey is down
	hd := down.synth(t, down.lim)
	expect(t, down.do(t, hd, call{method: "POST", path: "/api/v1/t/open-otp"}), 503, "sms_unavailable")
	// An open class still works with Valkey down.
	if w := down.do(t, hd, call{method: "POST", path: "/api/v1/t/big/x", body: "{}"}); w.Code != 200 {
		t.Fatalf("an open class with Valkey down: %d %s", w.Code, w.Body)
	}

	up := newRig(t, true)
	hu := up.synth(t, up.lim)
	ok := 0
	for i := 0; i < 8; i++ {
		if up.do(t, hu, call{method: "POST", path: "/api/v1/t/open-otp"}).Code == 200 {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("otp-send allowed %d in a minute, want 5", ok)
	}
}

func TestBodyLimits(t *testing.T) {
	r := newRig(t, true)
	h := r.synth(t, r.lim)
	s := r.reauthed(t)
	body := func(n int) string { return strings.Repeat("a", n) }
	// The default is 16 KiB.
	expect(t, r.do(t, h, call{method: "POST", path: "/api/v1/t/sensitive", cookies: []*http.Cookie{sessionCk(s)}, body: body(16 << 10)}), 200, "")
	expect(t, r.do(t, h, call{method: "POST", path: "/api/v1/t/sensitive", cookies: []*http.Cookie{sessionCk(s)}, body: body(16<<10 + 1)}), 413, "too_large")
	// A route that declares x-ctrlz-max-body takes 64 KiB and not a byte more.
	expect(t, r.do(t, h, call{method: "POST", path: "/api/v1/t/big/x", body: body(64 << 10)}), 200, "")
	expect(t, r.do(t, h, call{method: "POST", path: "/api/v1/t/big/x", body: body(64<<10 + 1), xff: "198.51.100.2"}), 413, "too_large")
}

func TestARouteWithoutADocumentEntryFailsClosed(t *testing.T) {
	r := newRig(t, true)
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Strict: true, Limiter: r.lim, Service: ratelimit.Tenant, Ops: nil, SkipRequestCheck: true,
		Resolver: resolver{m: r.m}, BaseURL: "/api/v1", Host: httpx.StaticHost(host),
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	built.Router.With(built.PerOp).Get("/v1/stray", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "reached") })
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	w := r.do(t, root, call{method: "GET", path: "/api/v1/stray"})
	if w.Code != 500 || strings.Contains(w.Body.String(), "reached") {
		t.Fatalf("an unregistered operation must not be served: %d %s", w.Code, w.Body)
	}
}

func TestPipelineRefusesAClassMismatchAtStartUp(t *testing.T) {
	r := newRig(t, true)
	for name, doc := range map[string]string{
		"unknown class":                `{operationId: a, x-ctrlz-auth: none, x-ctrlz-rate: nope}`,
		"session class on a public op": `{operationId: a, x-ctrlz-auth: none, x-ctrlz-rate: user-read}`,
		"admin auth on the tenant api": `{operationId: a, x-ctrlz-auth: admin, x-ctrlz-rate: auth}`,
	} {
		ops, err := apispec.Parse([]byte("paths:\n  /x:\n    get: "+doc+"\n"), ratelimit.Tenant)
		if err == nil {
			pl := &httpx.Pipeline{Log: slog.New(slog.DiscardHandler), Limiter: r.lim, Service: ratelimit.Tenant, Ops: ops, SkipRequestCheck: true, Resolver: resolver{m: r.m}}
			_, err = pl.Build()
		}
		if err == nil {
			t.Errorf("%s: the mistake must stop the service at start-up", name)
		}
	}
}

// TestDatabaseDownIsA503WithNoDetail covers the fault rows of 18.3: with
// Postgres stopped, a request that needs the database answers 503
// service_unavailable (no panic, no driver text), the cached public
// configuration keeps the host check working, and the service recovers when
// Postgres returns, with no restart.
func TestDatabaseDownIsA503WithNoDetail(t *testing.T) {
	r := newRig(t, true)
	s := r.login(t, r.env.A.Tenant, r.env.A.User, true, false)
	expect(t, r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config"}), 200, "") // warm the cache

	stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := cluster.StopPostgres(stopCtx); err != nil {
		t.Fatalf("stop postgres: %v", err)
	}
	restarted := false
	restart := func() {
		if !restarted {
			restarted = true
			if err := cluster.StartPostgres(context.Background()); err != nil {
				t.Errorf("restart postgres: %v", err)
			}
		}
	}
	t.Cleanup(restart) // never leave the cluster down for the tests that follow

	for _, c := range []call{
		{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(s)}},
		{method: "POST", path: "/api/v1/auth/refresh", cookies: []*http.Cookie{refreshCk(s)}, xff: "198.51.100.3"},
	} {
		w := r.do(t, r.h, c)
		expect(t, w, 503, "service_unavailable")
		for _, leak := range []string{"sqlstate", "pgx", "connect", "refused", "5432"} {
			if strings.Contains(strings.ToLower(w.Body.String()), leak) {
				t.Errorf("the 503 body leaks %q: %s", leak, w.Body)
			}
		}
	}
	// The cached configuration still answers, even after its 30 seconds: the last
	// good value is kept when a refresh fails.
	r.ck.add(2 * time.Minute)
	expect(t, r.do(t, r.h, call{method: "GET", path: "/api/v1/auth/config", xff: "198.51.100.77"}), 200, "")

	restart()
	deadline := time.Now().Add(60 * time.Second)
	for {
		w := r.do(t, r.h, call{method: "POST", path: "/api/v1/auth/logout", cookies: []*http.Cookie{sessionCk(s)}, xff: "198.51.100.9"})
		if w.Code == 204 || w.Code == 401 { // 401: the fake clock moved past the idle limit; the database answered
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the service did not recover: %d %s", w.Code, w.Body)
		}
		time.Sleep(time.Second)
	}
}
