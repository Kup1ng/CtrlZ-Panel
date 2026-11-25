package endpoints_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// A request that does not write the clients reads them as the distinct stacks they hold and not one by one (docs/specs/p3-endpoints.md
// 3.3, 11.2; review round 1 of D6, p3-D6-r1-8): 50 Endpoints with 1,000 clients each were 50,000 rows in memory twice for one batch
// request, about 21 MiB live against the 5 MiB an ordinary request is budgeted. The stacks are what decides which profiles a change
// takes away, so the answer of Guard.Check must be the one it gave when every client was read; that is the walk of e3_walk_test.go
// (the clients of its cases are read through this path) and TestNeededReadsUntouchedClientsAsDistinctStacks, which holds the
// reduction itself against the 30-minute reference.
func TestGuardInputsReadClientsAsDistinctStacks(t *testing.T) {
	f := newFx(t)
	A := f.A.Tenant
	ep := f.create(t, A, f.A.Profile, "lean")[0]
	stacks := []struct{ p, p2 any }{{f.A.Profile, nil}, {f.A.Profile2, nil}, {f.A.Profile, f.A.Profile2}}
	for i := 0; i < 90; i++ {
		s := stacks[i%3]
		f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, profile_id, profile2_id, source) VALUES ($1, $2, $3, $4, $5, 'manual')`,
			A, ep.ID, fmt.Sprintf("lean%02d", i), s.p, s.p2)
	}
	// A client with no stack of its own is no identity of its own: neither list holds it.
	f.exec(t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source) VALUES ($1, $2, 'nostack', 'manual')`, A, ep.ID)

	read := func(touched ...string) *endpoints.Input {
		t.Helper()
		var in *endpoints.Input
		err := f.st.WithTenant(f.ctx, A, store.TxOpts{ReadOnly: true}, func(tx store.Tx) error {
			got, err := (&endpoints.Guard{}).InputsFor(tx, []uuid.UUID{ep.ID}, touched)
			in = got[ep.ID]
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return in
	}

	in := read()
	if len(in.Clients) != 0 || len(in.Rest) != 3 {
		t.Errorf("a request that touches no client reads %d clients one by one and %d distinct stacks, want 0 and 3", len(in.Clients), len(in.Rest))
	}
	// The clients a request names come one by one, the others as distinct stacks, and "nostack" is in neither.
	in = read("lean00", "lean01", "nostack")
	if len(in.Clients) != 2 || len(in.Rest) != 3 {
		t.Errorf("two touched clients: %d read one by one and %d distinct stacks, want 2 and 3 (%+v)", len(in.Clients), len(in.Rest), in.Clients)
	}
	if got := in.Clients["lean00"]; got.First != f.A.Profile || got.Second != uuid.Nil {
		t.Errorf("lean00 is %+v", got)
	}
	// Every profile of every client is still in Profiles, which the destinations check and the key shares read.
	want := map[uuid.UUID]bool{f.A.Profile: true, f.A.Profile2: true}
	for _, p := range in.Profiles() {
		delete(want, p)
	}
	if len(want) != 0 {
		t.Errorf("Profiles misses %v", want)
	}
}
