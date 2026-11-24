package httpx_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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

// The path of a heavy request (docs/specs/p2-profiles.md 6.5), through the real pipeline and the real tenant document, with
// a stub in place of the handler and fake connections that block on a channel, so no test waits on a clock.

// sessionResolver is a Resolver whose cookie is "<tenant>-<session>". A revoked session is gone for good.
type sessionResolver struct {
	mu      sync.Mutex
	revoked map[string]bool
	resolve atomic.Int32
}

func (s *sessionResolver) CookieName() string { return "sid" }

func (s *sessionResolver) Screen(cookie string) (string, string, bool) {
	return cookie, cookie, strings.Contains(cookie, "-")
}

func (s *sessionResolver) Resolve(ctx context.Context, cookie string, _ apispec.Operation) (httpx.Resolved, error) {
	s.resolve.Add(1)
	s.mu.Lock()
	gone := s.revoked[cookie]
	s.mu.Unlock()
	if gone {
		return httpx.Resolved{Dead: true}, httpx.SessionExpired()
	}
	tenant, _, _ := strings.Cut(cookie, "-")
	return httpx.Resolved{Ctx: ctx, Live: true, SessionID: cookie, Tenant: tenant}, nil
}

func (s *sessionResolver) revoke(cookie string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked == nil {
		s.revoked = map[string]bool{}
	}
	s.revoked[cookie] = true
}

type heavyRig struct {
	h       http.Handler
	adm     *admission.Admission
	res     *sessionResolver
	lim     *ratelimit.Limiter
	reached atomic.Int32
	// handler is what the stub does; nil answers 201.
	handler http.HandlerFunc
}

const importPath = "/api/v1/profiles:import"

func newHeavyRig(t *testing.T, cfg admission.Config) *heavyRig {
	t.Helper()
	if cfg.Dir == "" {
		cfg.Dir = t.TempDir()
	}
	adm, err := admission.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := apispec.Parse(api.Tenant(), ratelimit.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	rig := &heavyRig{adm: adm, res: &sessionResolver{}}
	rig.lim = ratelimit.New(ratelimit.Config{Service: ratelimit.Tenant, LocalOnly: true, Now: func() time.Time { return now }})
	pl := &httpx.Pipeline{
		Log: slog.New(slog.DiscardHandler), Service: ratelimit.Tenant, Ops: ops, Doc: api.Tenant(), BaseURL: "/api/v1",
		Limiter: rig.lim, Resolver: rig.res, Host: want, Admission: adm,
	}
	built, err := pl.Build()
	if err != nil {
		t.Fatal(err)
	}
	stub := func(w http.ResponseWriter, r *http.Request) {
		rig.reached.Add(1)
		if rig.handler != nil {
			rig.handler(w, r)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}
	built.Router.With(built.PerOp).Post("/v1/profiles:import", stub)
	built.Router.With(built.PerOp).Get("/v1/profiles/{id}/export", stub)
	root := chi.NewRouter()
	root.Mount("/api", built.Router)
	rig.h = root
	return rig
}

// remainingDay counts the tokens of the tenant's day budget that are left, by spending them.
func (g *heavyRig) remainingDay(t *testing.T, tenant string) int {
	t.Helper()
	c, ok := ratelimit.Lookup(ratelimit.Tenant, ratelimit.BulkWriteTenant)
	if !ok {
		t.Fatal("no bulk-write-tenant class")
	}
	n := 0
	for {
		d, err := g.lim.Allow(context.Background(), c, ratelimit.Subject{Tenant: tenant})
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed {
			return n
		}
		n++
	}
}

// stalledBody sends the head of a body, says so on started, and holds the rest until release is closed. fail makes the rest
// an error instead (a connection that broke).
type stalledBody struct {
	head, tail string
	started    chan<- struct{}
	release    <-chan struct{}
	fail       error
	phase      int
	reads      atomic.Int32
}

func (b *stalledBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	switch b.phase {
	case 0:
		b.phase = 1
		return copy(p, b.head), nil
	case 1:
		b.phase = 2
		if b.started != nil {
			b.started <- struct{}{}
		}
		<-b.release
		if b.fail != nil {
			return 0, b.fail
		}
		return copy(p, b.tail), nil
	}
	return 0, io.EOF
}

const (
	bodyHead = `{"document":"`
	bodyTail = `e30="}`
)

func importRequest(cookie, key string, body io.Reader) *http.Request {
	r := httptest.NewRequest("POST", importPath, body)
	r.Host = host
	r.ContentLength = 6 << 20 // what a client that is about to send a big file declares
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	r.AddCookie(&http.Cookie{Name: "sid", Value: cookie})
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// TestTenSlowTenantsRefuseNobody: ten tenants stalled in the middle of a body of 6 MiB hold a place each and no weight, so an
// Import of an eleventh answers (6.5 properties 1 and 2). With the pools before this model eight of them filled 96 MiB at
// 12 MiB each and the eleventh was 503.
func TestTenSlowTenantsRefuseNobody(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	started := make(chan struct{}, 10)
	release := make(chan struct{})
	var wg sync.WaitGroup
	answers := make([]int, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := &stalledBody{head: bodyHead, tail: bodyTail, started: started, release: release}
			answers[i] = serve(rig.h, importRequest("t"+string(rune('a'+i))+"-s", "k-slow", body)).Code
		}()
	}
	for i := 0; i < 10; i++ {
		<-started
	}
	if places, pool := rig.adm.Held(); places != 10 || pool != 0 {
		t.Fatalf("ten stalled bodies hold %d places and %d bytes of work, want 10 and 0", places, pool)
	}
	w := serve(rig.h, importRequest("tz-s", "k-eleventh", strings.NewReader(bodyHead+bodyTail)))
	if w.Code != http.StatusCreated {
		t.Fatalf("the eleventh tenant: %d %s", w.Code, w.Body)
	}
	close(release)
	wg.Wait()
	for i, c := range answers {
		if c != http.StatusCreated {
			t.Errorf("stalled tenant %d answered %d", i, c)
		}
	}
	if places, pool := rig.adm.Held(); places != 0 || pool != 0 {
		t.Fatalf("%d places and %d bytes are still held after the answers", places, pool)
	}
}

// TestATenantHoldsOnePlace: two Imports of one tenant from two sessions, the first stalled. The second is 503 server_busy,
// its body was not read, and the day budget was charged once (6.5 property 1, Refusals and tokens). With the pools before
// this model both were read.
func TestATenantHoldsOnePlace(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		body := &stalledBody{head: bodyHead, tail: bodyTail, started: started, release: release}
		done <- serve(rig.h, importRequest("t1-a", "k-first", body)).Code
	}()
	<-started
	second := &stalledBody{head: bodyHead, tail: bodyTail, release: release}
	w := serve(rig.h, importRequest("t1-b", "k-second", second))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"server_busy"`) {
		t.Fatalf("the second body of one tenant: %d %s", w.Code, w.Body)
	}
	if n := second.reads.Load(); n != 0 {
		t.Fatalf("the refused body was read %d times", n)
	}
	// Another tenant is not touched by it.
	if w := serve(rig.h, importRequest("t2-a", "k-other", strings.NewReader(bodyHead+bodyTail))); w.Code != http.StatusCreated {
		t.Fatalf("another tenant: %d %s", w.Code, w.Body)
	}
	close(release)
	if c := <-done; c != http.StatusCreated {
		t.Fatalf("the first request answered %d", c)
	}
	// The first paid one token, the refusal none, and the other tenant has its own.
	if got := rig.remainingDay(t, "t1"); got != 199 {
		t.Fatalf("the tenant has %d tokens left, want 199: the day budget was charged more or less than once", got)
	}
}

// TestACutBodyIsBadRequestAndKeepsItsToken: a body cut by a broken connection is 400 and its day token stays spent; and
// nothing is held afterwards (6.5 property 3).
func TestACutBodyIsBadRequestAndKeepsItsToken(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	release := make(chan struct{})
	close(release)
	body := &stalledBody{head: bodyHead, tail: bodyTail, release: release, fail: io.ErrUnexpectedEOF}
	w := serve(rig.h, importRequest("t1-a", "k-cut", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a cut body: %d %s", w.Code, w.Body)
	}
	if rig.reached.Load() != 0 {
		t.Fatal("the handler ran on a cut body")
	}
	if got := rig.remainingDay(t, "t1"); got != 199 {
		t.Fatalf("%d tokens left, want 199: a cut body keeps its token spent", got)
	}
	if places, pool := rig.adm.Held(); places != 0 || pool != 0 {
		t.Fatalf("%d places and %d bytes held after a cut body", places, pool)
	}
}

// TestASessionRevokedWhileItsBodyArrivesWritesNothing: the session is resolved again in the slot, so one that was revoked
// between the first and the last byte of the body is refused and the handler never runs (6.5 property 10). With the
// pipeline before this model it resolved before the body and the handler wrote with the old principal.
func TestASessionRevokedWhileItsBodyArrivesWritesNothing(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		body := &stalledBody{head: bodyHead, tail: bodyTail, started: started, release: release}
		done <- serve(rig.h, importRequest("t1-a", "k-revoked", body))
	}()
	<-started
	rig.res.revoke("t1-a")
	close(release)
	w := <-done
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"session_expired"`) {
		t.Fatalf("a session revoked while its body arrived: %d %s", w.Code, w.Body)
	}
	if rig.reached.Load() != 0 {
		t.Fatal("the handler ran with a revoked session")
	}
	if got := rig.res.resolve.Load(); got != 2 {
		t.Fatalf("the session was resolved %d times, want 2 (before the body and in the slot)", got)
	}
}

// blockingWriter is a client that reads nothing: its Write blocks until release is closed.
type blockingWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingWriter) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.ResponseRecorder.Write(p)
}

// TestASlowExportReaderHoldsNoSlot: the answer is in a file and the weight is given back before it is sent, so a client that
// reads nothing holds a place and a connection and no weight, and another tenant's Export is 200 meanwhile (6.5 property 2).
// With the export pool before this model the encoded bytes were held until the client read them.
func TestASlowExportReaderHoldsNoSlot(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	rig.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 1<<20)))
	}
	const path = "/api/v1/profiles/00000000-0000-4000-8000-000000000001/export"
	get := func(cookie string) *http.Request {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		r.AddCookie(&http.Cookie{Name: "sid", Value: cookie})
		return r
	}
	slow := &blockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { rig.h.ServeHTTP(slow, get("t1-a")); close(done) }()
	<-slow.entered
	places, pool := rig.adm.Held()
	if places != 1 || pool != 0 || rig.adm.Free() != admission.Pool {
		t.Fatalf("a client that reads nothing holds %d places and %d bytes of the pool, free %d: it must hold a place and no weight", places, pool, rig.adm.Free())
	}
	if w := serve(rig.h, get("t2-a")); w.Code != http.StatusOK || w.Body.Len() != 1<<20 {
		t.Fatalf("another tenant's export meanwhile: %d, %d bytes", w.Code, w.Body.Len())
	}
	close(slow.release)
	<-done
	if slow.Code != http.StatusOK || slow.Body.Len() != 1<<20 || slow.Header().Get("Content-Length") != "1048576" {
		t.Fatalf("the slow reader got %d with %d bytes and length %q", slow.Code, slow.Body.Len(), slow.Header().Get("Content-Length"))
	}
}

// TestWorkEndsAtItsDeadline: a handler that blocks is ended at the deadline of the work step with 503 service_unavailable,
// and its slot and place are free after it (6.5 property 5). The handler here waits for its context; the Postgres variant,
// a transaction on pg_sleep, ends the same way because every query ends with the context.
func TestWorkEndsAtItsDeadline(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{WorkLimit: 40 * time.Millisecond})
	var sawDeadline atomic.Bool
	rig.handler = func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		sawDeadline.Store(true)
		httpx.Write(w, r, httpx.FromError(r.Context().Err()))
	}
	w := serve(rig.h, importRequest("t1-a", "k-slow-work", strings.NewReader(bodyHead+bodyTail)))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"service_unavailable"`) {
		t.Fatalf("a handler that outlived its deadline: %d %s", w.Code, w.Body)
	}
	if !sawDeadline.Load() {
		t.Fatal("the handler was not ended by its context")
	}
	if places, pool := rig.adm.Held(); places != 0 || pool != 0 {
		t.Fatalf("%d places and %d bytes held after the deadline", places, pool)
	}
}

// TestAFullQueueEndsInServerBusyAndGivesTheTokenBack: a request that waits the whole queue wait is 503 server_busy and its
// day token is given back (6.5, Refusals and tokens).
func TestAFullQueueEndsInServerBusyAndGivesTheTokenBack(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{QueueWait: 40 * time.Millisecond})
	hold, err := rig.adm.Acquire(context.Background(), admission.Pool)
	if err != nil {
		t.Fatal(err)
	}
	w := serve(rig.h, importRequest("t1-a", "k-queued", strings.NewReader(bodyHead+bodyTail)))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"server_busy"`) {
		t.Fatalf("a request that waited out the queue: %d %s", w.Code, w.Body)
	}
	hold()
	if got := rig.remainingDay(t, "t1"); got != 200 {
		t.Fatalf("%d tokens left, want 200: the queue refusal must give its token back", got)
	}
	if rig.reached.Load() != 0 {
		t.Fatal("the handler ran for a request that never got its weight")
	}
}

// TestNoDiskIsServerBusyAndGivesTheTokenBack: a spool file that cannot be made is 503 server_busy and the token comes back.
func TestNoDiskIsServerBusyAndGivesTheTokenBack(t *testing.T) {
	dir := t.TempDir()
	rig := newHeavyRig(t, admission.Config{Dir: dir})
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	w := serve(rig.h, importRequest("t1-a", "k-nodisk", strings.NewReader(bodyHead+bodyTail)))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"server_busy"`) {
		t.Fatalf("a request with no disk: %d %s", w.Code, w.Body)
	}
	if got := rig.remainingDay(t, "t1"); got != 200 {
		t.Fatalf("%d tokens left, want 200", got)
	}
}

// TestAnAnswerTooLargeIsInternal: an answer above the spool's cap is a 500 and not a truncated answer.
func TestAnAnswerTooLargeIsInternal(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	rig.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := []byte(strings.Repeat("x", 1<<20))
		for i := 0; i < 17; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}
	w := serve(rig.h, importRequest("t1-a", "k-big-answer", strings.NewReader(bodyHead+bodyTail)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("an answer of 17 MiB: %d", w.Code)
	}
}

// TestAHeavyBodyIsRefusedByItsLimitBeforeAnyPlace: a declared length over the limit is 413 before a place or a token is taken.
func TestAHeavyBodyIsRefusedByItsLimitBeforeAnyPlace(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{})
	r := importRequest("t1-a", "k-413", strings.NewReader(bodyHead+bodyTail))
	r.ContentLength = 6<<20 + 1
	if w := serve(rig.h, r); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a declared length over the limit: %d", w.Code)
	}
	if got := rig.remainingDay(t, "t1"); got != 200 {
		t.Fatalf("%d tokens left, want 200", got)
	}
}
