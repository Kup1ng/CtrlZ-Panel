package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/session"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestFaultsDuringAuth covers the Postgres rows of 18.3 for the auth routes: a
// request that needs the database answers 503 service_unavailable with no
// driver text and no secret, the floor is not skipped, and the service recovers
// when Postgres returns.
func TestFaultsDuringAuth(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	f.client().get("/auth/config").want(200, "") // warm the public configuration

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

	clean := func(r *resp) {
		t.Helper()
		body := strings.ToLower(string(r.Body))
		for _, leak := range []string{"sqlstate", "pgx", "connect", "refused", "5432", strings.ToLower(pwA)} {
			if strings.Contains(body, leak) {
				t.Errorf("the 503 body leaks %q: %s", leak, r.Body)
			}
		}
	}

	r := f.client().loginPassword(A.Phone, pwA, false).want(503, "service_unavailable")
	clean(r)
	if r.Dur < 450*time.Millisecond {
		t.Errorf("login answered in %v with the database down; the floor was skipped", r.Dur)
	}
	r = f.client().post("/auth/otp/request", map[string]any{"phone": A.Phone, "purpose": "login"})
	if r.Code != 503 {
		t.Errorf("otp request with the database down: %d %s", r.Code, r.Body)
	}
	clean(r)
	r = f.client().post("/auth/password/reset/complete", map[string]any{"ticket": "junk", "new_password": pwB})
	if r.Code != 503 && r.Code != 401 {
		t.Errorf("reset complete with the database down: %d %s", r.Code, r.Body)
	}
	clean(r)
	// The configuration is cached, so the login page still loads.
	f.ck.add(2 * time.Minute)
	f.client().get("/auth/config").want(200, "")

	restart()
	deadline := time.Now().Add(60 * time.Second)
	for {
		r := f.client().loginPassword(A.Phone, pwA, false)
		if r.Code == 200 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("login did not recover: %d %s", r.Code, r.Body)
		}
		time.Sleep(time.Second)
	}
}

// TestPoolExhaustedIsA503InTime is the "Pool exhausted" row of 18.3: with every
// pooled connection busy, a request answers 503 service_unavailable inside the
// store's acquire timeout instead of waiting until the
// client leaves, and the service works again as soon as a connection is free.
func TestPoolExhaustedIsA503InTime(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	cfg := f.env.DB.StoreConfig(store.RoleTenant)
	// A small pool that the held transactions below fill completely.
	cfg.MaxConns = 4
	cfg.AcquireTimeout = 2 * time.Second
	small, err := store.Open(f.env.Ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	f.deps.Store = small
	sm := session.NewManager(small, session.DefaultPolicy(), f.ck.now)
	if err := sm.WithKeys(f.keys, keyring.DomainAuthMAC); err != nil {
		t.Fatal(err)
	}
	f.deps.Sessions = sm
	f.setLimiter(f.deps.Limiter)

	// A running service has loaded its public configuration. With one pool the load is a
	// statement on the pool like any other, so on a process that never had it, the
	// exhausted pool would also fail that first load, and the cache remembers a failed
	// first load for configRetryAfter: the login after the release would still be refused.
	// (With the second pool the load never met the exhaustion.) Warm it first.
	f.client().mustLogin(A.Phone, pwA)
	f.clearThrottle()

	hold, done := make(chan struct{}), make(chan error, 4)
	for i := 0; i < 4; i++ {
		held := make(chan struct{})
		go func() {
			done <- small.WithTenant(f.env.Ctx, A.Tenant, store.TxOpts{ReadOnly: true}, func(store.Tx) error {
				close(held)
				<-hold
				return nil
			})
		}()
		<-held
	}

	start := time.Now()
	r := f.client().loginPassword(A.Phone, pwA, false).want(503, "service_unavailable")
	if took := time.Since(start); took > 12*time.Second {
		t.Errorf("the 503 took %v with a 2 s acquire timeout (a login makes several store calls, each bounded)", took)
	}
	if strings.Contains(strings.ToLower(string(r.Body)), "pool") || strings.Contains(string(r.Body), pwA) {
		t.Errorf("the 503 body leaks: %s", r.Body)
	}
	close(hold)
	for i := 0; i < 4; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	f.clearThrottle()
	f.client().mustLogin(A.Phone, pwA)
}
