package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
	"github.com/Kup1ng/CtrlZ-Panel/internal/httpx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// slowLoader is a database that does not answer: it waits for its context.
type slowLoader struct {
	calls atomic.Int32
	hang  atomic.Bool
	val   store.PublicConfig
}

func (l *slowLoader) load(ctx context.Context) (store.PublicConfig, error) {
	l.calls.Add(1)
	if l.hang.Load() {
		<-ctx.Done()
		return store.PublicConfig{}, errors.New("pool busy")
	}
	return l.val, nil
}

// TestConfigCacheStaleValueNeverQueuesRequests is tenant-r1-2 and -12: after the
// TTL, with a database that does not answer, a burst of requests is answered with
// the last value at once, and the database is tried once, not once per request.
func TestConfigCacheStaleValueNeverQueuesRequests(t *testing.T) {
	ck := &clock{t: time.Now()}
	l := &slowLoader{val: store.PublicConfig{PanelHost: "panel.example.test"}}
	c := newConfigCacheWait(l.load, ck.now, 100*time.Millisecond, slog.New(slog.DiscardHandler))
	if _, err := c.Get(context.Background()); err != nil {
		t.Fatal(err)
	}

	ck.add(configTTL + time.Second)
	l.hang.Store(true)
	var wg sync.WaitGroup
	took := make([]time.Duration, 8)
	for i := range took {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			v, err := c.Get(context.Background())
			took[i] = time.Since(start)
			if err != nil || v.PanelHost != "panel.example.test" {
				t.Errorf("get = %+v, %v; want the stale value", v, err)
			}
		}()
	}
	wg.Wait()
	for i, d := range took {
		if d > time.Second {
			t.Errorf("request %d waited %v for a database that does not answer", i, d)
		}
	}
	// The failure is remembered: further requests do not reach the database
	// until the retry pause is over.
	for c.Loading() {
		time.Sleep(10 * time.Millisecond)
	}
	calls := l.calls.Load()
	for i := 0; i < 20; i++ {
		start := time.Now()
		if _, err := c.Get(context.Background()); err != nil || time.Since(start) > 50*time.Millisecond {
			t.Fatalf("a request after the failure waited or failed: %v", err)
		}
	}
	if l.calls.Load() != calls {
		t.Errorf("the database was tried %d more times inside the retry pause", l.calls.Load()-calls)
	}
	if calls > 2 { // the first load, and one refresh for the whole burst
		t.Errorf("%d database calls for one burst, want 2", calls)
	}

	// After the pause one request tries again, and a good answer replaces the value.
	ck.add(configRetryAfter + time.Second)
	l.hang.Store(false)
	l.val = store.PublicConfig{PanelHost: "new.example.test"}
	if v, _ := c.Get(context.Background()); v.PanelHost != "new.example.test" {
		t.Errorf("after the pause the value is %q", v.PanelHost)
	}
}

// TestConfigCacheColdStartSharesOneLoad: with nothing cached, parallel requests
// wait for one load and all get its error, and the error is remembered.
func TestConfigCacheColdStartSharesOneLoad(t *testing.T) {
	ck := &clock{t: time.Now()}
	l := &slowLoader{}
	l.hang.Store(true)
	c := newConfigCache(l.load, ck.now, slog.New(slog.DiscardHandler))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(ctx); err == nil {
				t.Error("a cold get with a dead database returned no error")
			}
		}()
	}
	wg.Wait()
	if n := l.calls.Load(); n != 1 {
		t.Errorf("%d loads for five parallel cold requests, want 1", n)
	}
}

// The case of tenant-r15-4: an operator closes registration, and from then on every refresh of the
// configuration panics. The cache must say so (one closed line) and must not keep serving "open"
// for ever: past cachex.StalenessOf(cachex.NameAuthConfig).MaxStale it refuses, and the routes that read it answer an error.
func TestAPanickingConfigRefreshIsSaidAndStopsServingAnOldDecision(t *testing.T) {
	var out strings.Builder
	var mu sync.Mutex
	w := writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return out.Write(p) })
	ck := &clock{t: time.Now()}
	var boom atomic.Bool
	load := func(context.Context) (store.PublicConfig, error) {
		if boom.Load() {
			panic("bad row for 09125550001")
		}
		return store.PublicConfig{RegistrationMode: "open"}, nil
	}
	c := newConfigCacheWait(load, ck.now, 100*time.Millisecond, slog.New(slog.NewTextHandler(w, nil)))
	if v, err := c.Get(context.Background()); err != nil || v.RegistrationMode != "open" {
		t.Fatalf("first Get = %+v, %v", v, err)
	}
	boom.Store(true)
	for waited := time.Duration(0); waited < cachex.StalenessOf(cachex.NameAuthConfig).MaxStale-time.Minute; waited += time.Minute {
		ck.add(time.Minute)
		if v, err := c.Get(context.Background()); err != nil || v.RegistrationMode != "open" {
			t.Fatalf("inside the bound Get = %+v, %v, want the last good value", v, err)
		}
		for c.Loading() {
			time.Sleep(2 * time.Millisecond)
		}
	}
	ck.add(2 * time.Minute)
	if _, err := c.Get(context.Background()); !errors.Is(err, cachex.ErrStale) {
		t.Fatalf("past the bound Get error = %v, want ErrStale", err)
	}
	mu.Lock()
	got := out.String()
	mu.Unlock()
	if !strings.Contains(got, "cache load panicked") || !strings.Contains(got, "cache=auth_config") {
		t.Fatalf("the panicking refresh was not said:\n%s", got)
	}
	if strings.Contains(got, "09125550001") || strings.Contains(got, "bad row") {
		t.Fatalf("the panic value reached the log:\n%s", got)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestThePanelHostIsNotGuessedOnceTheConfigurationIsTooOld is tenant-r16-5. The database has one panel host
// and the environment another. While the cache works the database's wins; past MaxStale it answers
// ErrStale and the host source says so (a 503 at the Host check), and does not fall back to the
// environment's name, which would answer 400 to every browser. A cache that never loaded is the same (tenant-r16-18).
func TestThePanelHostIsNotGuessedOnceTheConfigurationIsTooOld(t *testing.T) {
	ck := &clock{t: time.Now()}
	var fail atomic.Bool
	load := func(context.Context) (store.PublicConfig, error) {
		if fail.Load() {
			return store.PublicConfig{}, errors.New("statement timeout")
		}
		return store.PublicConfig{PanelHost: "db.example.test"}, nil
	}
	c := newConfigCacheWait(load, ck.now, 50*time.Millisecond, slog.New(slog.DiscardHandler))
	hs := panelHost(c, "env.example.test")
	if h, err := hs(context.Background()); err != nil || h != "db.example.test" {
		t.Fatalf("working cache: %q, %v", h, err)
	}
	fail.Store(true)
	ck.add(cachex.StalenessOf(cachex.NameAuthConfig).MaxStale + time.Minute)
	h, err := hs(context.Background())
	if !errors.Is(err, cachex.ErrStale) || h != "" {
		t.Fatalf("past the bound the host source answered %q, %v, want an ErrStale and no host", h, err)
	}
	// The same through the pipeline's Host check: 503, not 400.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "db.example.test"
	httpx.HostCheck(hs)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("Host check with a stale configuration = %d, want 503", w.Code)
	}
	// A cache that never loaded cannot tell either (tenant-r16-18): a first load that failed because the database
	// was not up yet and a load that panicked answer 503 through the Host check and the CSRF Origin check, and
	// neither falls back to the environment's host, which would answer 400 whenever the operator's host is another.
	for name, load := range map[string]func(context.Context) (store.PublicConfig, error){
		"a failed first load":  func(context.Context) (store.PublicConfig, error) { return store.PublicConfig{}, errors.New("down") },
		"a load that panicked": func(context.Context) (store.PublicConfig, error) { panic("boom") },
	} {
		cold := panelHost(newConfigCacheWait(load, ck.now, 50*time.Millisecond, slog.New(slog.DiscardHandler)), "env.example.test")
		h, err := cold(context.Background())
		if err == nil || h != "" {
			t.Fatalf("%s on a cold cache answered %q, %v, want no host and an error", name, h, err)
		}
		if got := httpx.FromError(err).Status; got != http.StatusServiceUnavailable {
			t.Fatalf("%s on a cold cache is a %d, want 503", name, got)
		}
		for _, host := range []string{"env.example.test", "db.example.test"} { // the environment's host, and the operator's
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			r.Host = host
			httpx.HostCheck(cold)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s: Host check for %q = %d, want 503 (a 400 is the fallback guessing)", name, host, w.Code)
			}
			w = httptest.NewRecorder()
			r = httptest.NewRequest("POST", "/", nil)
			r.Host = host
			r.Header.Set("Origin", "https://"+host)
			httpx.CSRF(cold, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s: CSRF check for Origin %q = %d, want 503", name, host, w.Code)
			}
		}
	}
	// A caller that went away while the cold load ran is the same: an error, no host.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cold := panelHost(newConfigCacheWait(func(ctx context.Context) (store.PublicConfig, error) {
		<-ctx.Done()
		return store.PublicConfig{}, ctx.Err()
	}, ck.now, 50*time.Millisecond, slog.New(slog.DiscardHandler)), "env.example.test")
	if h, err := cold(ctx); err == nil || h != "" {
		t.Fatalf("a cancelled caller on a cold cache answered %q, %v, want no host and an error", h, err)
	}
	// Through the Host check the status is the caller's own: a caller that left is the bare 499, not a 503
	// that reads as a server fault (tenant-r17-8). The error above is what the check sees.
	for _, c := range []struct {
		mw     func(http.Handler) http.Handler
		method string
	}{{httpx.HostCheck(cold), "GET"}, {httpx.CSRF(cold, true), "POST"}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(c.method, "/", nil).WithContext(ctx)
		r.Host = "db.example.test"
		r.Header.Set("Origin", "https://db.example.test")
		c.mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
		if w.Code != httpx.StatusClientClosedRequest {
			t.Fatalf("a cancelled caller through %s answered %d, want 499", c.method, w.Code)
		}
	}
}
