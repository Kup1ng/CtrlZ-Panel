package api

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/cachex"
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
	c := newConfigCacheWait(l.load, ck.now, 100*time.Millisecond, nil)
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
	time.Sleep(50 * time.Millisecond)
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
	c := newConfigCache(l.load, ck.now, nil)
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
// for ever: past configServeStaleFor it refuses, and the routes that read it answer an error.
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
	for waited := time.Duration(0); waited < configServeStaleFor-time.Minute; waited += time.Minute {
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
