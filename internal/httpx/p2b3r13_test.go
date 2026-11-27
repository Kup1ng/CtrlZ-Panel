package httpx_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/admission"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testwait"
)

// Round 13 of package B3 (p2-B3-r13-1): the rate classes of an ordinary operation count for each session, and one account
// may hold 50 sessions, so nothing but the 16 connections bounded what one tenant's reads could hold at once. The pipeline
// gives each tenant OrdinaryTenant turns; the others wait in a line that holds no connection.

// TestOneTenantsOrdinaryRequestsAreBoundedAndAnotherTenantIsNotBehindThem: three sessions of one tenant against two turns.
// The third waits and is 503 server_busy when its wait ends, with the handler not run for it; a request of another tenant is
// served while the two hold their turns; the turns are free again after the handlers return.
func TestOneTenantsOrdinaryRequestsAreBoundedAndAnotherTenantIsNotBehindThem(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{OrdinaryTenant: 2, OrdinaryWait: 100 * time.Millisecond})
	inside := make(chan struct{}, 4)
	release := make(chan struct{})
	rig.ordinary = func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Cookie"), "sid=t1-") {
			inside <- struct{}{}
			<-release
		}
		w.WriteHeader(http.StatusOK)
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, c := range []string{"t1-a", "t1-b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- serve(rig.h, jobGet(c)).Code
		}()
	}
	<-inside
	<-inside
	before := rig.reached.Load()
	third := serve(rig.h, jobGet("t1-c"))
	if third.Code != http.StatusServiceUnavailable || !strings.Contains(third.Body.String(), `"server_busy"`) {
		t.Fatalf("the third request of a tenant with two turns: %d %s", third.Code, third.Body)
	}
	if third.Header().Get("Retry-After") == "" {
		t.Fatalf("a refusal for want of a turn does not say when to retry")
	}
	if other := serve(rig.h, jobGet("t2-a")); other.Code != http.StatusOK {
		t.Fatalf("another tenant behind the first one's turns: %d %s", other.Code, other.Body)
	}
	if rig.reached.Load() != before {
		t.Fatalf("the handler ran for the refused request")
	}
	close(release)
	wg.Wait()
	for range 2 {
		if c := <-codes; c != http.StatusOK {
			t.Fatalf("a request that held a turn answered %d", c)
		}
	}
	if n := rig.adm.OrdinaryTenants(); n != 0 {
		t.Fatalf("%d tenants still hold ordinary turns after the handlers returned", n)
	}
	if again := serve(rig.h, jobGet("t1-c")); again.Code != http.StatusOK {
		t.Fatalf("a request of the tenant after its turns were given back: %d %s", again.Code, again.Body)
	}
}

// TestAWaitingRequestGetsItsTurnWhenOneIsGivenBack: the line is not a refusal. One turn, a second request waits and runs as
// soon as the first handler returns, well inside the wait.
func TestAWaitingRequestGetsItsTurnWhenOneIsGivenBack(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{OrdinaryTenant: 1, OrdinaryWait: 30 * time.Second})
	inside := make(chan struct{}, 2)
	release := make(chan struct{})
	rig.ordinary = func(w http.ResponseWriter, r *http.Request) {
		inside <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}
	codes := make(chan int, 2)
	go func() { codes <- serve(rig.h, jobGet("t1-a")).Code }()
	<-inside
	go func() { codes <- serve(rig.h, jobGet("t1-b")).Code }()
	testwait.Until(t, 5*time.Second, "the second request is in line", func() bool { return rig.adm.OrdinaryWaiting("t1") == 1 })
	close(release)
	for range 2 {
		if c := testwait.Receive(t, codes, 5*time.Second, "an answer"); c != http.StatusOK {
			t.Fatalf("answered %d", c)
		}
	}
}

// A client that leaves while it waits for a turn leaves the line.
func TestAClientThatLeavesTheLineIsForgotten(t *testing.T) {
	rig := newHeavyRig(t, admission.Config{OrdinaryTenant: 1, OrdinaryWait: 30 * time.Second})
	inside := make(chan struct{}, 1)
	release := make(chan struct{})
	rig.ordinary = func(w http.ResponseWriter, r *http.Request) {
		inside <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}
	done := make(chan struct{})
	go func() { defer close(done); serve(rig.h, jobGet("t1-a")) }()
	<-inside
	r := jobGet("t1-b")
	ctx, cancel := contextWithCancel(r)
	left := make(chan int, 1)
	go func() { left <- serve(rig.h, r.WithContext(ctx)).Code }()
	testwait.Until(t, 5*time.Second, "the second request is in line", func() bool { return rig.adm.OrdinaryWaiting("t1") == 1 })
	cancel()
	if c := testwait.Receive(t, left, 5*time.Second, "the answer of the client that left"); c != 499 {
		t.Fatalf("a client that left the line: %d, want 499", c)
	}
	testwait.Until(t, 5*time.Second, "the line is empty", func() bool { return rig.adm.OrdinaryWaiting("t1") == 0 })
	close(release)
	<-done
}

func contextWithCancel(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithCancel(r.Context())
}
