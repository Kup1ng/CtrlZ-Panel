package httpx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

const host = "panel.example.test"

func want(context.Context) (string, error) { return host, nil }

func ok() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

func do(h http.Handler, method, target string, hdr map[string]string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, body)
	r.Host = host
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func code(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var b struct {
		Code        string `json:"code"`
		RequestID   string `json:"request_id"`
		RetryAfterS int    `json:"retry_after_s"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("body is not the error JSON: %q", w.Body.String())
	}
	return b.Code
}

func TestRecoverLogsTheTypeAndNothingOfTheRequest(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	h := httpx.Recover(log)(httpx.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("CANARY-PANIC-VALUE " + r.URL.RawQuery + " " + r.Header.Get("Cookie"))
	})))
	w := do(h, "GET", "/x?token=CANARY-QUERY", map[string]string{"Cookie": "s=CANARY-COOKIE"}, nil)
	if w.Code != 500 || code(t, w) != "internal" {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if w.Header().Get("X-Request-Id") == "" || !strings.Contains(w.Body.String(), w.Header().Get("X-Request-Id")) {
		t.Error("the error body must carry the request id")
	}
	out := buf.String()
	for _, c := range []string{"CANARY-PANIC-VALUE", "CANARY-QUERY", "CANARY-COOKIE"} {
		if strings.Contains(out, c) {
			t.Errorf("log contains %s", c)
		}
	}
	if !strings.Contains(out, "panic_type") || !strings.Contains(out, "string") {
		t.Errorf("log must name the panic type: %s", out)
	}
}

func TestRecoverPassesAbortHandlerThrough(t *testing.T) {
	h := httpx.Recover(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Fatal("ErrAbortHandler must propagate")
		}
	}()
	do(h, "GET", "/", nil, nil)
}

func TestRequestIDIsRandomAndIgnoresTheClient(t *testing.T) {
	h := httpx.RequestID(ok())
	a := do(h, "GET", "/", map[string]string{"X-Request-Id": "evil"}, nil).Header().Get("X-Request-Id")
	b := do(h, "GET", "/", nil, nil).Header().Get("X-Request-Id")
	if a == "" || a == "evil" || a == b {
		t.Fatalf("ids %q %q", a, b)
	}
}

func TestNoStore(t *testing.T) {
	if got := do(httpx.NoStore(ok()), "GET", "/", nil, nil).Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestBodyLimit(t *testing.T) {
	read := func(n int, raise int64) error {
		var err error
		h := httpx.BodyLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if raise > 0 {
				httpx.SetBodyLimit(r, raise)
			}
			_, err = io.ReadAll(r.Body)
		}))
		do(h, "POST", "/", nil, bytes.NewReader(make([]byte, n)))
		return err
	}
	if err := read(httpx.DefaultBodyLimit, 0); err != nil {
		t.Fatalf("exactly the limit must pass: %v", err)
	}
	var mbe *http.MaxBytesError
	if err := read(httpx.DefaultBodyLimit+1, 0); !errors.As(err, &mbe) {
		t.Fatalf("one byte over: %v", err)
	}
	if err := read(1<<20, 0); !errors.As(err, &mbe) {
		t.Fatalf("1 MiB: %v", err)
	}
	if err := read(64<<10, 64<<10); err != nil {
		t.Fatalf("a raised limit of 64 KiB must take 64 KiB: %v", err)
	}
	if err := read(64<<10+1, 64<<10); !errors.As(err, &mbe) {
		t.Fatalf("raised limit, one over: %v", err)
	}
	if got := httpx.FromError(&http.MaxBytesError{Limit: 1}); got.Status != 413 || got.Code != "too_large" {
		t.Fatalf("MaxBytesError maps to %+v", got)
	}
}

func TestClientIP(t *testing.T) {
	var got netip.Addr
	h := httpx.ClientIP(true, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = httpx.ClientIPFrom(r.Context())
		w.WriteHeader(204)
	}))
	cases := []struct {
		name string
		xff  []string
		want string
		code int
	}{
		{"single", []string{"203.0.113.9"}, "203.0.113.9", 204},
		{"rightmost wins, client values are ignored", []string{"1.1.1.1, 2.2.2.2, 203.0.113.9"}, "203.0.113.9", 204},
		{"last line wins", []string{"1.1.1.1", "198.51.100.4"}, "198.51.100.4", 204},
		{"v4 mapped is unmapped", []string{"::ffff:203.0.113.9"}, "203.0.113.9", 204},
		{"v6", []string{"2001:db8::1"}, "2001:db8::1", 204},
		{"zone is dropped", []string{"fe80::1%eth0"}, "fe80::1", 204},
		{"absent is refused in production", nil, "", 400},
		{"junk is refused", []string{"not-an-ip"}, "", 400},
		{"empty last value is refused", []string{"1.1.1.1,"}, "", 400},
	}
	for _, c := range cases {
		got = netip.Addr{}
		r := httptest.NewRequest("GET", "/", nil)
		for _, x := range c.xff {
			r.Header.Add("X-Forwarded-For", x)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.code || (c.want != "" && got.String() != c.want) {
			t.Errorf("%s: code %d addr %s, want %d %s", c.name, w.Code, got, c.code, c.want)
		}
	}

	// Outside production a request without the header uses the peer.
	lax := httpx.ClientIP(false, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = httpx.ClientIPFrom(r.Context())
	}))
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.7:4444"
	lax.ServeHTTP(httptest.NewRecorder(), r)
	if got.String() != "192.0.2.7" {
		t.Errorf("non-strict peer = %s", got)
	}
}

func TestHostCheck(t *testing.T) {
	h := httpx.HostCheck(want)(ok())
	for hostHdr, wantCode := range map[string]int{
		host: 204, "PANEL.example.test": 204, host + ":8443": 204, host + ".": 204,
		"admin.example.test": 400, "evil.test": 400, host + ".evil.test": 400, "": 400,
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = hostHdr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != wantCode {
			t.Errorf("Host %q = %d, want %d", hostHdr, w.Code, wantCode)
		}
	}
	// A configured port must match.
	withPort := httpx.HostCheck(httpx.StaticHost("localhost:8080"))(ok())
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "localhost:9090"
	w := httptest.NewRecorder()
	withPort.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Errorf("wrong port = %d", w.Code)
	}
	// An unknown own host refuses everything.
	none := httpx.HostCheck(httpx.StaticHost(""))(ok())
	if w := do(none, "GET", "/", nil, nil); w.Code != 400 {
		t.Errorf("empty configured host = %d", w.Code)
	}
}

func TestCSRF(t *testing.T) {
	h := httpx.CSRF(want)(ok())
	post := func(hdr map[string]string) int { return do(h, "POST", "/", hdr, strings.NewReader("{}")).Code }

	if c := post(nil); c != 204 {
		t.Errorf("no Origin and no Sec-Fetch-Site (curl) = %d", c)
	}
	if c := post(map[string]string{"Sec-Fetch-Site": "same-origin"}); c != 204 {
		t.Errorf("same-origin = %d", c)
	}
	if c := post(map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://" + host}); c != 204 {
		t.Errorf("same-origin with own Origin = %d", c)
	}
	for name, hdr := range map[string]map[string]string{
		"cross-site":          {"Sec-Fetch-Site": "cross-site"},
		"same-site subdomain": {"Sec-Fetch-Site": "same-site"},
		"foreign origin":      {"Origin": "https://evil.test"},
		"null origin":         {"Origin": "null"},
		"foreign origin despite same-origin hint": {"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.test"},
		"origin on a subdomain":                   {"Origin": "https://x." + host},
	} {
		w := do(h, "POST", "/", hdr, strings.NewReader("{}"))
		if w.Code != 403 || code(t, w) != "csrf_rejected" {
			t.Errorf("%s = %d %s", name, w.Code, w.Body)
		}
	}
	// A GET is never refused for these headers.
	if w := do(h, "GET", "/", map[string]string{"Sec-Fetch-Site": "cross-site"}, nil); w.Code != 204 {
		t.Errorf("cross-site GET = %d", w.Code)
	}
	for _, m := range []string{"PUT", "PATCH", "DELETE"} {
		if w := do(h, m, "/", map[string]string{"Sec-Fetch-Site": "cross-site"}, nil); w.Code != 403 {
			t.Errorf("cross-site %s = %d", m, w.Code)
		}
	}
}

func TestFloorWaitsEvenWhenFnFailsAndStopsWhenTheRequestEnds(t *testing.T) {
	var slept time.Duration
	var now time.Time
	tm := password.Timing{
		Now:    func() time.Time { return now },
		Sleep:  func(_ context.Context, d time.Duration) error { slept += d; return nil },
		Jitter: func() time.Duration { return 20 * time.Millisecond },
	}
	boom := errors.New("boom")
	err := httpx.FloorWith(context.Background(), tm, 500*time.Millisecond, func(context.Context) error { return boom })
	if !errors.Is(err, boom) || slept != 520*time.Millisecond {
		t.Fatalf("err %v slept %v", err, slept)
	}

	// The real floor returns promptly when the request context ends.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_ = httpx.Floor(ctx, 5*time.Second, func(context.Context) error { return nil })
	if time.Since(start) > time.Second {
		t.Fatal("a cancelled request must not wait out the floor")
	}
	// And the real floor does wait.
	start = time.Now()
	_ = httpx.Floor(context.Background(), 60*time.Millisecond, func(context.Context) error { return nil })
	if time.Since(start) < 60*time.Millisecond {
		t.Fatal("floor returned early")
	}
}

func TestErrorBodyAndRetryAfter(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	httpx.Write(w, r, httpx.RateLimited(1500*time.Millisecond))
	if w.Code != 429 || w.Header().Get("Retry-After") != "2" {
		t.Fatalf("%d Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	var b map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &b)
	if b["code"] != "rate_limited" || b["retry_after_s"] != float64(2) {
		t.Fatalf("body %v", b)
	}
	// Fields.
	w = httptest.NewRecorder()
	httpx.Write(w, r, httpx.New(422, httpx.CodePasswordWeak).WithFields(httpx.FieldError{Name: "new_password", Code: "too_short"}))
	if !strings.Contains(w.Body.String(), `"fields":[{"name":"new_password","code":"too_short"}]`) {
		t.Fatalf("body %s", w.Body)
	}
}

func TestFromErrorMapsStoreErrorsWithoutEchoingThem(t *testing.T) {
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{store.ErrConflict, 409, "conflict"},
		{fmt.Errorf("wrapped: %w", store.ErrConnection), 503, "service_unavailable"},
		{store.ErrDriver, 500, "internal"},
		{errors.New("password=CANARY"), 500, "internal"},
		{context.DeadlineExceeded, 503, "service_unavailable"},
		{fmt.Errorf("query: %w", context.Canceled), 503, "service_unavailable"},
		{httpx.NotFound(), 404, "not_found"},
		{fmt.Errorf("ctx: %w", httpx.SessionExpired()), 401, "session_expired"},
	}
	for _, c := range cases {
		got := httpx.FromError(c.err)
		if got.Status != c.status || got.Code != c.code {
			t.Errorf("%v -> %d %s, want %d %s", c.err, got.Status, got.Code, c.status, c.code)
		}
	}
}

func TestSetCookieThroughTheOutbox(t *testing.T) {
	h := httpx.Outbox(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpx.SetCookie(r.Context(), &http.Cookie{Name: "a", Value: "1", Path: "/"})
		httpx.SetCookie(r.Context(), &http.Cookie{Name: "b", Value: "2", Path: "/"})
		w.WriteHeader(204)
	}))
	w := do(h, "GET", "/", nil, nil)
	if got := w.Header().Values("Set-Cookie"); len(got) != 2 {
		t.Fatalf("Set-Cookie = %v", got)
	}
}

func TestErrorLogKeepsOnlyTheClass(t *testing.T) {
	var buf bytes.Buffer
	l := httpx.ErrorLog(slog.New(slog.NewJSONHandler(&buf, nil)))
	l.Printf("http: panic serving 10.0.0.2:5555: CANARY-SECRET-VALUE")
	l.Printf("http: panic serving 10.0.0.2:5555: again") // inside the same second: dropped
	out := buf.String()
	if strings.Contains(out, "CANARY") || strings.Contains(out, "10.0.0.2") {
		t.Fatalf("log leaked: %s", out)
	}
	if !strings.Contains(out, `"kind":"panic"`) || strings.Count(out, "\n") != 1 {
		t.Fatalf("log = %s", out)
	}
}

// With a trusted proxy list, only those peers may speak for a client: a request
// from any other container is refused before X-Forwarded-For is read, so a
// compromised neighbour cannot pick a fresh address per request (review round 3,
// admin-r3-13).
func TestClientIPOnlyFromTrustedProxy(t *testing.T) {
	trusted, err := httpx.ParseTrustedProxies("10.213.78.10, 2001:db8::/64")
	if err != nil || len(trusted) != 2 {
		t.Fatalf("parse: %v %v", trusted, err)
	}
	var got netip.Addr
	h := httpx.ClientIP(true, trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = httpx.ClientIPFrom(r.Context())
		w.WriteHeader(204)
	}))
	for _, c := range []struct {
		peer string
		code int
	}{
		{"10.213.78.10:5555", 204},
		{"[2001:db8::7]:5555", 204},
		{"10.213.78.11:5555", 400}, // a neighbour on the same network
		{"10.213.77.5:5555", 400},  // a container on another network
		{"garbage", 400},
		{"", 400},
	} {
		got = netip.Addr{}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.code || (c.code == 204 && got.String() != "203.0.113.9") {
			t.Errorf("peer %q: code %d addr %s, want %d", c.peer, w.Code, got, c.code)
		}
	}
	// Not strict (development, tests): the list is not consulted.
	lax := httpx.ClientIP(false, trusted)(ok())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.7:4444"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()
	lax.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Errorf("non-strict mode refused a peer outside the list: %d", w.Code)
	}
	if _, err := httpx.ParseTrustedProxies("10.0.0.1, not-an-address"); err == nil {
		t.Error("a bad entry was accepted")
	}
}

// TestClientAbortIsNotAServerFailure is tenant-r4-3. A client that drops the
// connection while a database call runs makes the handler return
// context.Canceled with the request context done: that is not a 500, and it must
// not put a WARN line in the log or a 5xx in the count. A Canceled that does not
// come from the request (a shutdown, a derived context) is still a 503 and is
// logged as one.
func TestClientAbortIsNotAServerFailure(t *testing.T) {
	var buf bytes.Buffer
	p := httpx.Pipeline{Log: slog.New(slog.NewJSONHandler(&buf, nil)), Service: ratelimit.Tenant, SkipRequestCheck: true}
	api, err := p.Build()
	if err != nil {
		t.Fatal(err)
	}

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("POST", "/", nil).WithContext(gone)
	w := httptest.NewRecorder()
	api.ResponseError(w, req, fmt.Errorf("store: %w", context.Canceled))
	if w.Code != httpx.StatusClientClosedRequest || w.Body.Len() != 0 {
		t.Errorf("a client abort answered %d %q", w.Code, w.Body.String())
	}
	if buf.Len() != 0 {
		t.Errorf("a client abort was logged: %s", buf.String())
	}

	// The same error with a live request context is the server's own.
	w = httptest.NewRecorder()
	api.ResponseError(w, httptest.NewRequest("POST", "/", nil), context.Canceled)
	if w.Code != 503 || code(t, w) != "service_unavailable" {
		t.Errorf("a server-side cancel answered %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(buf.String(), `"request failed"`) {
		t.Errorf("a server-side cancel was not logged as a failure: %q", buf.String())
	}

	// A real failure on an aborted request is still a failure.
	buf.Reset()
	w = httptest.NewRecorder()
	api.ResponseError(w, req, errors.New("boom"))
	if w.Code != 500 || !strings.Contains(buf.String(), `"request failed"`) {
		t.Errorf("an unrelated error on an aborted request: %d %q", w.Code, buf.String())
	}
}

// TestLoopbackOnlyJudgesThePeerAddress (admin-r11-4) covers the spellings of the peer that a socket
// test cannot produce: IPv6 loopback, an IPv4-mapped loopback, and a peer that is not an address.
func TestLoopbackOnlyJudgesThePeerAddress(t *testing.T) {
	h := httpx.NewHealth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })).Handler()
	for peer, want := range map[string]int{
		"127.0.0.1:5000": 200, "127.9.9.9:1": 200, "[::1]:5000": 200, "[::ffff:127.0.0.1]:5000": 200,
		"10.213.77.5:5000": 404, "[fd00:213:77::5]:1": 404, "[::ffff:10.0.0.1]:1": 404, "0.0.0.0:1": 404,
		"": 404, "pipe": 404, "localhost:80": 404,
	} {
		r := httptest.NewRequest("GET", "/readyz", nil)
		r.RemoteAddr = peer
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("peer %q = %d, want %d", peer, w.Code, want)
		}
	}
}

// TestCanonicalHostIsOneSpelling: the Host gate and the callers that build an origin or a link
// from the configured host share one normaliser (round 13, admin-r13-1).
func TestCanonicalHostIsOneSpelling(t *testing.T) {
	for in, want := range map[string]string{
		"Panel.Example.IR":      "panel.example.ir",
		" panel.example.ir. ":   "panel.example.ir",
		"panel.localhost:8443":  "panel.localhost:8443",
		"Panel.Localhost.:8443": "panel.localhost:8443",
		"[::1]:8443":            "[::1]:8443",
		"":                      "",
	} {
		if got := httpx.CanonicalHost(in); got != want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
	if httpx.HostName("Panel.Localhost.:8443") != "panel.localhost" || httpx.HostName("a.example.ir.") != "a.example.ir" {
		t.Error("HostName keeps a port or a dot")
	}
}

// A host source that cannot tell is a dependency fault: 503 on the Host check and on the Origin check of
// a state-changing request, never 400 (which says the caller is wrong) and never a guess (round 16,
// tenant-r16-5).
func TestAHostSourceThatCannotTellAnswers503(t *testing.T) {
	broken := httpx.HostSource(func(context.Context) (string, error) { return "", cachex.ErrStale })
	w := do(httpx.HostCheck(broken)(ok()), "GET", "/", nil, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Host check with a source that cannot tell = %d, want 503", w.Code)
	}
	post := do(httpx.CSRF(broken)(ok()), "POST", "/", map[string]string{"Origin": "https://" + host}, strings.NewReader("{}"))
	if post.Code != http.StatusServiceUnavailable {
		t.Errorf("Origin check with a source that cannot tell = %d, want 503", post.Code)
	}
}

// TestEveryCacheFailureIsUnavailable: the errors the cache package exports are read from its source, so
// an error added there later is a failure of this test until it is mapped, not a 500 that nobody
// planned. Each maps to 503, directly and wrapped.
func TestEveryCacheFailureIsUnavailable(t *testing.T) {
	known := map[string]error{"ErrStale": cachex.ErrStale, "ErrReset": cachex.ErrReset, "ErrLoadPanicked": cachex.ErrLoadPanicked}
	fset := gotoken.NewFileSet()
	pkgs, err := parser.ParseDir(fset, "../cachex", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != gotoken.VAR {
					continue
				}
				for _, s := range g.Specs {
					for _, n := range s.(*ast.ValueSpec).Names {
						if !strings.HasPrefix(n.Name, "Err") {
							continue
						}
						found++
						e, ok := known[n.Name]
						if !ok {
							t.Errorf("cachex.%s is exported and this test does not map it: add it to FromError", n.Name)
							continue
						}
						for _, got := range []error{e, fmt.Errorf("load: %w", e)} {
							if fe := httpx.FromError(got); fe.Status != http.StatusServiceUnavailable {
								t.Errorf("FromError(%v) = %d, want 503", got, fe.Status)
							}
						}
					}
				}
			}
		}
	}
	if found != len(known) {
		t.Errorf("found %d exported errors in cachex, the table has %d", found, len(known))
	}
}

// TestAHostSourceThatFindsTheCallerGoneAnswers499 is tenant-r17-8. The Host and Origin checks ask a source
// that can fail, and a caller that left while it was asked is the caller's doing: the bare 499, as in the
// handler path, not a 503 that reads as a server fault. The same source error with a live caller is still
// a 503 (the cases of TestAHostSourceThatCannotTellAnswers503 keep that half).
func TestAHostSourceThatFindsTheCallerGoneAnswers499(t *testing.T) {
	// The source wraps whatever the cache returned together with Unavailable, as the tenant host source does.
	gone := httpx.HostSource(func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", fmt.Errorf("the panel host is not known: %w: %w", ctx.Err(), httpx.Unavailable())
	})
	for name, c := range map[string]struct {
		mw     func(http.Handler) http.Handler
		method string
		hdr    map[string]string
	}{
		"host check":   {httpx.HostCheck(gone), "GET", nil},
		"origin check": {httpx.CSRF(gone), "POST", map[string]string{"Origin": "https://" + host}},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := httptest.NewRequest(c.method, "/", strings.NewReader("{}")).WithContext(ctx)
		r.Host = host
		for k, v := range c.hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		c.mw(ok()).ServeHTTP(w, r)
		if w.Code != httpx.StatusClientClosedRequest || w.Body.Len() != 0 {
			t.Errorf("%s with a caller that left = %d with a %d byte body, want a bare 499", name, w.Code, w.Body.Len())
		}
	}
}
