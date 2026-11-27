package endpoints_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/periodic"
)

// answerFunc is a periodic.Resolver over a function.
type answerFunc func(host string) []netip.Addr

func (a answerFunc) Lookup(_ context.Context, host string) ([]netip.Addr, error) { return a(host), nil }

// T-091 (spec 11.1): the DDNS pass against a claim request and a delete of authorized rows on the same Endpoint, at the same
// time. All three take the Endpoint's row first (3.7), so none may end in a deadlock (40P01) or a lock timeout: the pass has no
// error, and the two routes end in a success or a refusal of the write path, which the API answers as a 2xx or a 4xx. The
// rounds change the host's answer each time, so the pass writes and deletes rows while the routes do the same.
func TestDDNSPassAgainstAClaimRequestAndAnAuthorizedDeleteOnTheSameEndpoint(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	ep := f.create(t, A, f.A.Profile, "ddns-busy")[0]
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_ip_claims = 1000, max_authorized_ips = 1000 WHERE tenant_id = $1`, A)
	f.exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true WHERE id = $1`, ep.ID)
	host, err := f.env.CreateDDNSHost(f.ctx, f.st, A, opts, ep.ID, "busy.example.org")
	if err != nil {
		t.Fatal(err)
	}
	round := 0
	var mu sync.Mutex
	res := answerFunc(func(string) []netip.Addr {
		mu.Lock()
		defer mu.Unlock()
		return []netip.Addr{netip.MustParseAddr(fmt.Sprintf("8.8.%d.1", round)), netip.MustParseAddr(fmt.Sprintf("8.8.%d.2", round))}
	})
	runner, err := periodic.New(periodic.Config{
		Store: f.db.Store(f.ctx, t, store.RoleWorker), Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Resolver: res, Page: 1, Batch: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	a := f.auth(A, &fakeVerifier{})
	me := netip.MustParseAddr("198.51.100.250")
	for r := 1; r <= 8; r++ {
		mu.Lock()
		round = r
		mu.Unlock()
		cidrs := []string{fmt.Sprintf("203.0.%d.0/24", r), fmt.Sprintf("203.1.%d.0/24", r), fmt.Sprintf("203.2.%d.0/24", r)}
		rows, err := f.env.AddAuthorized(f.ctx, f.st, A, opts, ep.ID, cidrs, me)
		if err != nil {
			t.Fatalf("round %d: %v", r, err)
		}

		var wg sync.WaitGroup
		var passErr, claimErr, delErr error
		wg.Add(3)
		go func() {
			defer wg.Done()
			passErr = runner.RunJob(f.ctx, periodic.JobDDNS)
		}()
		go func() {
			defer wg.Done()
			ask := fmt.Sprintf("93.184.216.%d/32", 100+r)
			_, claimErr = f.env.RequestClaim(f.ctx, f.st, A, opts, ep.ID, endpoints.ClaimAsk{Cidr: &ask})
		}()
		go func() {
			defer wg.Done()
			ids := make([]uuid.UUID, len(rows))
			for i, row := range rows {
				ids[i] = row.ID
			}
			delErr = f.env.DeleteAuthorized(f.ctx, f.st, A, opts, a, ep.ID, ids, me)
		}()
		wg.Wait()
		if passErr != nil {
			t.Fatalf("round %d: the DDNS pass ended in %v, which would raise the job's alert", r, passErr)
		}
		refusalOrNil(t, "the claim request", claimErr)
		refusalOrNil(t, "the authorized delete", delErr)
		if delErr != nil {
			t.Fatalf("round %d: the delete was refused: %v", r, delErr)
		}
		if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE ddns_host_id = $1 AND cidr IN ($2::cidr, $3::cidr)`, host.ID,
			fmt.Sprintf("8.8.%d.1/32", r), fmt.Sprintf("8.8.%d.2/32", r)); n != 2 {
			t.Fatalf("round %d: the host's two current addresses are %d rows, want 2", r, n)
		}
		if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1 AND cidr = ANY ($2::text[]::cidr[])`, ep.ID, cidrs); n != 0 {
			t.Fatalf("round %d: %d manual rows survived their delete", r, n)
		}
	}
}
