package endpoints_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// E2 for the deletes (docs/specs/p3-endpoints.md 11.2; review round 1 of D6, p3-D6-r1-12): an Endpoint delete, a batch delete and
// a client delete write endpoint_set exactly once, whatever the number of ids, and a client delete writes it only when a deleted
// client held a record of the compiler (a profile or an Analytics level of its own). Without a mark the nodes of P4 keep serving a
// deleted Endpoint's resolver id and DoH token until some other change of the tenant.
func TestE2DeletesMarkOnce(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	a := f.auth(A, &fakeVerifier{})
	marks := func(what string, want int, change func() error) {
		t.Helper()
		n, err := f.marks(t, A, change)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if n != want {
			t.Errorf("%s marked %d endpoint_set rows, want %d", what, n, want)
		}
	}

	one := f.create(t, A, f.A.Profile, "e2-del-one")[0]
	marks("the delete of one Endpoint", 1, func() error { return f.env.Delete(f.ctx, f.st, A, opts, a, []uuid.UUID{one.ID}) })

	three := f.create(t, A, f.A.Profile, "e2-del-a", "e2-del-b", "e2-del-c")
	ids3 := []uuid.UUID{three[0].ID, three[1].ID, three[2].ID}
	marks("the batch delete of three Endpoints", 1, func() error {
		_, err := f.env.Batch(f.ctx, f.st, A, opts, a, endpoints.BatchIn{IDs: ids3[:2], Op: "delete"})
		return err
	})
	marks("the delete of the last one by its own route", 1, func() error { return f.env.Delete(f.ctx, f.st, A, opts, a, ids3[2:]) })

	// A batch edit of a compiled column over several Endpoints is one mark too.
	pair := f.create(t, A, f.A.Profile, "e2-edit-a", "e2-edit-b")
	other := f.A.Profile2
	marks("a batch edit of the profile of two Endpoints", 1, func() error {
		_, err := f.env.Batch(f.ctx, f.st, A, opts, a, endpoints.BatchIn{IDs: []uuid.UUID{pair[0].ID, pair[1].ID}, Op: "edit", Set: endpoints.Patch{ProfileID: &other}})
		return err
	})

	// Clients: a delete of clients that hold a record marks once for all of them, and a delete of clients with none marks nothing.
	ep := f.create(t, A, f.A.Profile, "e2-del-clients")[0]
	mk := func(alias string, profile uuid.UUID) store.ClientRow {
		c, err := f.env.CreateClient(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientCreate{Alias: alias, ProfileID: profile})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	withStack := []store.ClientRow{mk("stack one", f.A.Profile2), mk("stack two", f.A.Profile2), mk("stack three", f.A.Profile2)}
	plain := []store.ClientRow{mk("plain one", uuid.Nil), mk("plain two", uuid.Nil)}
	marks("a batch delete of clients with no record", 0, func() error {
		_, _, err := f.env.BatchClients(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "delete", IDs: []uuid.UUID{plain[0].ID, plain[1].ID}})
		return err
	})
	marks("a batch delete of three clients that hold a stack", 1, func() error {
		_, _, err := f.env.BatchClients(f.ctx, f.st, A, opts, a, ep.ID, endpoints.ClientBatchIn{Op: "delete", IDs: []uuid.UUID{withStack[0].ID, withStack[1].ID, withStack[2].ID}})
		return err
	})
	if n := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1`, ep.ID); n != 0 {
		t.Errorf("%d clients left after the two deletes", n)
	}
}
