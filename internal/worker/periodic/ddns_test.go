package periodic

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// stuckResolver never answers: a lookup ends only when its context does, as a name whose servers are silent would.
type stuckResolver struct {
	mu     sync.Mutex
	asked  []string
	answer map[string][]netip.Addr
}

func (s *stuckResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	s.asked = append(s.asked, host)
	a, ok := s.answer[host]
	s.mu.Unlock()
	if ok {
		return a, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type plainResolver struct{}

func (plainResolver) Lookup(context.Context, string) ([]netip.Addr, error) { return nil, nil }

func newTestRunner(res Resolver, budget time.Duration) *Runner {
	return &Runner{log: slog.New(slog.NewJSONHandler(io.Discard, nil)), resolver: res, tenantBudget: budget,
		ddnsStart: map[uuid.UUID]int{}}
}

// J12-r2-2: the budget bounds a tenant's lookups, and the hosts it cut are skipped, not failed.
func TestLookupAllEndsWithTheBudgetAndSkipsTheHostsItDidNotReach(t *testing.T) {
	work := make([]store.DDNSWork, 10)
	for i := range work {
		work[i].Hostname = string(rune('a'+i)) + ".example.test"
	}
	res := &stuckResolver{answer: map[string][]netip.Addr{}}
	r := newTestRunner(res, 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), r.tenantBudget)
	defer cancel()
	began := time.Now()
	out, next := r.lookupAll(ctx, work, 0)
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("the tenant's lookups took %v, past the budget", took)
	}
	for i, a := range out {
		if !a.skipped {
			t.Errorf("host %d was recorded as asked, but the budget ended it", i)
		}
	}
	if next != 0 {
		t.Errorf("next = %d, want the first host (nothing was answered)", next)
	}
}

// J12-r2-5: the hosts after the cut come first next time, and the ones answered before it are not asked again first.
func TestLookupAllResumesWhereTheBudgetStopped(t *testing.T) {
	work := make([]store.DDNSWork, 8)
	res := &stuckResolver{answer: map[string][]netip.Addr{}}
	for i := range work {
		work[i].Hostname = string(rune('a'+i)) + ".example.test"
	}
	// The first four answer at once; the rest never do.
	for i := 0; i < 4; i++ {
		res.answer[work[i].Hostname] = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
	}
	r := newTestRunner(res, 100*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), r.tenantBudget)
	defer cancel()
	out, next := r.lookupAll(ctx, work, 0)
	for i := 0; i < 4; i++ {
		if out[i].skipped || out[i].err != nil {
			t.Errorf("host %d answered and was not recorded so", i)
		}
	}
	if next != 4 {
		t.Fatalf("next = %d, want 4: the first host the budget did not reach", next)
	}
	// The next pass starts at 4 and wraps: the hosts that answered are the ones left for last.
	res.mu.Lock()
	res.asked = nil
	res.mu.Unlock()
	ctx2, cancel2 := context.WithTimeout(context.Background(), r.tenantBudget)
	defer cancel2()
	r.lookupAll(ctx2, work, next)
	res.mu.Lock()
	defer res.mu.Unlock()
	if len(res.asked) == 0 || res.asked[0][0] < 'e' {
		t.Errorf("the second pass began with %v, want a host from index 4 on", res.asked)
	}
}

// J12-r1-18: a resolver that reads the machine's own sources never lets a tenant tell a panel service name from a missing name.
func TestNoPublicAnswerIsRecordedAsNoAddressForAHostLocalResolver(t *testing.T) {
	if got := noPublicFailure(&netResolver{}); got != store.DDNSEmpty {
		t.Errorf("the host resolver's private-only answer is %q, want %q", got, store.DDNSEmpty)
	}
	if got := noPublicFailure(plainResolver{}); got != store.DDNSNoPublic {
		t.Errorf("a resolver that is not host-local gives %q, want %q", got, store.DDNSNoPublic)
	}
}
