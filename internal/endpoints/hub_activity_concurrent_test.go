package endpoints_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// T-532 (spec 11.5): the hub's real activity write, store.HubActivityWrite as ctrlz_hub, against a delete of clients by selector
// and a manual client create on the same Endpoint. T-531 uses a SQL stand-in for the hub; this one runs the statement the hub
// runs, so a change in its lock order (clients in id order, then the Endpoints in id order, 3.7) is what it would catch. The
// hub tries a write again up to three times when it loses a lock race (ErrRetry, hubtel/activity.go); what may never reach it is
// any other error, and no round may end with the write refused after its tries.
func TestHubActivityWriteAgainstAClientBatchAndAManualWriter(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	ep := f.create(t, A, f.A.Profile, "hub-busy")[0]
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_clients_per_endpoint = 1000 WHERE tenant_id = $1`, A)
	hub := f.db.Store(f.ctx, t, store.RoleHub)
	a := f.auth(A, &fakeVerifier{})
	node := uuid.New()
	for round := 0; round < 6; round++ {
		f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) SELECT $1::uuid, $2::uuid, 'seen-' || g, 'auto' FROM generate_series(1, 60) g
			ON CONFLICT DO NOTHING`, A, ep.ID)
		at := time.Now().Truncate(time.Minute)
		items := make([]store.HubActivityItem, 0, 70)
		for i := 1; i <= 70; i++ { // 60 labels the delete is removing, ten the write adds
			items = append(items, store.HubActivityItem{Endpoint: ep.ID, Label: fmt.Sprintf("seen-%d", i), First: at, Last: at, Node: node, ClientCap: 1000})
		}
		var wg sync.WaitGroup
		var delErr, userErr, hubErr error
		retries := 0
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _, delErr = f.env.BatchClients(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "delete", All: true})
		}()
		go func() {
			defer wg.Done()
			for try := 0; try < 3; try++ {
				_, hubErr = hub.HubActivityWrite(f.ctx, A, items)
				if hubErr == nil || !errors.Is(hubErr, store.ErrRetry) {
					return
				}
				retries++
			}
		}()
		go func() {
			defer wg.Done()
			_, userErr = f.env.CreateClient(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientCreate{Alias: fmt.Sprintf("manual %d", round)})
		}()
		wg.Wait()
		refusalOrNil(t, "the delete by selector", delErr)
		refusalOrNil(t, "the manual client create", userErr)
		if hubErr != nil {
			t.Fatalf("round %d: the hub's write ended in %v after %d lost races", round, hubErr, retries)
		}
		if delErr != nil {
			t.Fatalf("round %d: the delete by selector was refused: %v", round, delErr)
		}
		// The Endpoint's times moved whichever of the three went first.
		if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND last_query_at IS NOT NULL`, ep.ID); n != 1 {
			t.Fatalf("round %d: the Endpoint's times did not move", round)
		}
		f.exec(t, `DELETE FROM ctrlz.clients WHERE endpoint_id = $1 AND source = 'auto'`, ep.ID)
	}
}
