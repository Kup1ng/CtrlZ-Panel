package compiler

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of review round 2 of package W4 (the compiler). Each names the finding it closes.

// twoTenants is a world of two tenants, one Endpoint each, written to the log by a first compiler. It returns the number of
// entries and the two tenant ids. The next compiler of the test is a new process: it knows no owner.
func twoTenants(t *testing.T) (e *env, a, b uuid.UUID, n int) {
	t.Helper()
	e = newEnv(t, nil)
	a, b = uid(1, 1), uid(1, 2)
	ia, ib := newTenantInput(), newTenantInput()
	ia.profile(uid(2, 1), "a.example")
	ia.endpoint(uid(3, 1), uid(2, 1))
	ib.profile(uid(2, 2), "b.example")
	ib.endpoint(uid(3, 2), uid(2, 2))
	e.m.tenants[a], e.m.tenants[b] = ia, ib
	e.m.mark(a, uuid.New())
	e.m.mark(b, uuid.New())
	e.tick(0)
	n = e.m.seqs()
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2" })
	return e, a, b, n
}

// W4-r2-1, W4-r2-6: the sweep of orphans waits until every tenant has been compiled, and not only until a pass skips nobody.
// After a restart tenant A cannot be read; any pass that meets only other tenants used to find A unowned and delete its
// Endpoints on every node.
func TestTheOrphanSweepWaitsForEveryTenantAndNotForOnePass(t *testing.T) {
	cases := []struct {
		name string
		// between is what happens while A waits for its retry.
		between func(e *env, a, b uuid.UUID)
	}{
		{"another tenant's mark", func(e *env, _, b uuid.UUID) { e.m.mark(b, uuid.New()) }},
		{"a free DNS change", func(e *env, _, _ uuid.UUID) { e.m.freeVer++; e.m.freeQPS = 500 }},
		{"every tenant's read fails", func(e *env, a, b uuid.UUID) {
			e.m.freeVer++
			e.m.freeQPS = 500
			e.m.tenantErr[b] = errBoom
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, a, b, n := twoTenants(t)
			e.m.tenantErr = map[uuid.UUID]error{a: errBoom}
			if tc.name == "every tenant's read fails" {
				e.m.tenantErr[b] = errBoom
			}
			e.tick(0)
			tc.between(e, a, b)
			e.settle() // 15 s: the retry of A is 60 s away
			if len(e.node().Endpoints) != 2 {
				t.Fatalf("a pass that did not meet the unread tenant swept its Endpoints: %d on the node", len(e.node().Endpoints))
			}
			for i := n + 1; i <= e.m.seqs(); i++ {
				if len(e.entry(i).DelEndpoints) != 0 || len(e.entry(i).DelClaims) != 0 {
					t.Fatalf("entry %d deletes records", i)
				}
			}
			// A can be read again, and the sweep that was owed has nothing to take.
			e.m.tenantErr = nil
			e.clk.add(time.Minute)
			e.settle()
			if len(e.node().Endpoints) != 2 || e.c.sweepOwed || len(e.c.unmet) != 0 {
				t.Fatalf("after the retry: %d Endpoints, sweepOwed %v, unmet %d", len(e.node().Endpoints), e.c.sweepOwed, len(e.c.unmet))
			}
		})
	}
}

// W4-r2-1: once every tenant has been met, a record no tenant owns is still taken out, by the pass that meets the last of
// them.
func TestTheOrphanSweepRunsOnceTheLastTenantIsMet(t *testing.T) {
	e, a, b, _ := twoTenants(t)
	// A record of the log that no tenant row has: its Endpoint was deleted with no mark (a purge cascades past the outbox).
	e.m.tenants[b].Endpoints = nil
	e.m.tenantErr = map[uuid.UUID]error{a: errBoom}
	e.tick(0)
	e.settle()
	if len(e.node().Endpoints) != 2 {
		t.Fatalf("the record of B was swept while A was unmet: %d", len(e.node().Endpoints))
	}
	e.m.tenantErr = nil
	e.clk.add(time.Minute)
	e.settle()
	if len(e.node().Endpoints) != 1 {
		t.Fatalf("B's deleted Endpoint stayed once every tenant was met: %d", len(e.node().Endpoints))
	}
}

// commitHook is the backend with a function run as Commit is entered, before the transaction does anything.
type commitHook struct {
	*memBackend
	before func(c *Commit)
}

func (h *commitHook) Commit(ctx context.Context, c *Commit) error {
	h.before(c)
	return h.memBackend.Commit(ctx, c)
}

// W4-r2-2, W4-r3-1: the blob files are put before the transaction and its log lock, and looked at again inside it. A file the
// collector took away between the two refuses the entry (the bytes are not kept to put it again); the next pass compiles the
// tenant again, puts the file and writes the entry.
func TestBlobFilesAreWrittenBeforeTheTransactionAndCheckedInsideIt(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())

	entered, missing, taken := 0, 0, false
	e.c = e.compiler(func(c *Config) {
		c.Backend = &commitHook{memBackend: e.m, before: func(cm *Commit) {
			for _, row := range cm.Put {
				entered++
				if e.a.Size(row.Hash) < 0 {
					missing++
				}
				// The collector deletes a file under the log lock, between the put before it and the check inside, once.
				if !taken {
					if err := e.a.Delete(row.Hash); err != nil {
						t.Error(err)
					}
				}
			}
			taken = true
		}}
	})
	e.clk.add(time.Second)
	if err := e.c.Tick(e.ctx); !errors.Is(err, ErrBlobGone) {
		t.Fatalf("an entry whose file the collector took was written, or failed otherwise: %v", err)
	}
	if e.m.seqs() != 0 || len(e.m.marks) != 1 {
		t.Fatalf("%d entries and %d marks after a refused entry", e.m.seqs(), len(e.m.marks))
	}
	e.settle()
	if entered < 2 {
		t.Fatal("the entry was not tried again")
	}
	if missing != 0 {
		t.Fatalf("%d blob files were not in the store when the transaction began", missing)
	}
	if st := e.node(); len(st.Endpoints) != 1 || len(st.Profiles) != 1 {
		t.Fatalf("the node holds %d endpoints and %d blobs", len(st.Endpoints), len(st.Profiles))
	}
}

// W4-r2-8: a compile that outlasts the lease does not make the commit lose it. The lease is renewed before every write, since
// a lease nobody else took is only taken again.
func TestASlowTenantDoesNotLoseTheLeaseBeforeItsWrite(t *testing.T) {
	e := newEnv(t, nil)
	e.m.now = e.clk.Now
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		e.clk.add(15 * time.Second) // the lease is 10 s
		return CompileTenantWith(in, now, prev)
	}
	e.m.mark(a, uuid.New())
	e.tick(0)
	if e.m.seqs() == 0 || len(e.m.marks) != 0 {
		t.Fatalf("the pass wrote %d entries and left %d marks", e.m.seqs(), len(e.m.marks))
	}

	// The same for a pass that writes no entry and only deletes its marks.
	n := e.m.seqs()
	e.m.mark(a, uuid.New())
	e.settle()
	if e.m.seqs() != n || len(e.m.marks) != 0 {
		t.Fatalf("a mark with nothing to say: %d new entries, %d marks left", e.m.seqs()-n, len(e.m.marks))
	}

	// A lease another worker really took is still lost.
	e.m.mark(a, uuid.New())
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		e.clk.add(15 * time.Second)
		e.m.mu.Lock()
		e.m.holder, e.m.leaseUntil = "other", e.clk.Now().Add(10*time.Second)
		e.m.mu.Unlock()
		return CompileTenantWith(in, now, prev)
	}
	in.Endpoints = nil
	e.clk.add(5 * time.Second)
	var err error
	for i := 0; i < 30 && err == nil; i++ {
		e.clk.add(500 * time.Millisecond)
		err = e.c.Tick(e.ctx)
	}
	if !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("a lease another worker took was not reported lost: %v", err)
	}
}

// W4-r2-9: the tail of the log is read in batches and applied as it comes, and the bytes since the last snapshot are counted.
func TestTheTailOfTheLogIsReadInBatchesAndCounted(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SnapshotEvery = 1 << 30; c.SnapshotAge = 1000 * time.Hour })
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	for i := 0; i < loadBatch+10; i++ {
		// A new rule changes the blob, and so the record, and so the entry.
		in.Rules = append(in.Rules, store.ProfileRule{ProfileID: uid(2, 1), RuleRow: store.RuleRow{
			ID: uuid.UUID{0: 0xE1, 14: byte(i >> 8), 15: byte(i)}, Key: "x" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example", MatchKind: "domain", Action: "block", Enabled: true}})
		e.m.mark(a, uuid.New())
		e.settle()
	}
	want := e.m.seqs()
	if want <= loadBatch {
		t.Fatalf("the log has %d entries, not more than a batch", want)
	}
	var bytesWritten uint64
	for _, r := range e.m.log {
		bytesWritten += uint64(len(r.Payload))
	}
	// The new blob files count too: churn of blobs with small entries fills the volume as surely as large entries (W4-r3-8).
	withBlobs := bytesWritten
	for _, a := range e.m.arts {
		withBlobs += uint64(a.Size)
	}
	if e.c.sinceSnap != withBlobs {
		t.Fatalf("the bytes since the snapshot are %d, the log and the new blobs hold %d", e.c.sinceSnap, withBlobs)
	}

	e.c = e.compiler(func(c *Config) { c.SnapshotEvery = 1 << 30; c.SnapshotAge = 1000 * time.Hour })
	e.m.logCalls = 0
	e.tick(0)
	if e.c.View().Seq != uint64(want) {
		t.Fatalf("the loaded view is at %d, the log at %d", e.c.View().Seq, want)
	}
	if e.m.logCalls < 2 {
		t.Fatalf("%d entries were read in %d calls", want, e.m.logCalls)
	}
	if e.c.sinceSnap < bytesWritten {
		t.Fatalf("a restart counts %d bytes of the tail, the log holds %d", e.c.sinceSnap, bytesWritten)
	}
}

// W4-r2-9: a snapshot is due when the entries after the last one are large, not only when they are many.
func TestASnapshotIsDueWhenTheTailIsLargeInBytes(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SnapshotEvery = 1 << 30; c.SnapshotAge = 1000 * time.Hour; c.SnapshotBytes = 1 })
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.settle()
	if len(e.m.snaps) != 1 || e.c.sinceSnap != 0 {
		t.Fatalf("%d snapshots, %d bytes counted since", len(e.m.snaps), e.c.sinceSnap)
	}
}

// W4-r2-7: the rules of a profile are asked for one profile at a time, only for the profiles something binds, and a failed
// read is the tenant's failed read.
func TestRulesAreReadOneProfileAtATimeAndOnlyForBoundProfiles(t *testing.T) {
	mk := func() *TenantInput {
		in := newTenantInput()
		in.profile(uid(2, 1), "a.example", "b.example")
		in.profile(uid(2, 2), "c.example")
		in.profile(uid(2, 3), "unbound.example") // nothing binds it
		in.endpoint(uid(3, 1), uid(2, 1))
		in.endpoint(uid(3, 2), uid(2, 2))
		return in
	}
	whole := CompileTenant(mk(), time.Unix(1_800_000_000, 0))

	in := mk()
	rows := map[uuid.UUID][]store.RuleRow{}
	for _, r := range in.Rules {
		rows[r.ProfileID] = append(rows[r.ProfileID], r.RuleRow)
	}
	in.Rules = nil
	var asked []uuid.UUID
	in.RulesOf = func(p uuid.UUID) ([]store.RuleRow, error) {
		asked = append(asked, p)
		return rows[p], nil
	}
	got := CompileTenant(in, time.Unix(1_800_000_000, 0))
	if len(asked) != 2 || asked[0] == uid(2, 3) || asked[1] == uid(2, 3) || asked[0] == asked[1] {
		t.Fatalf("the rules of %v were read", asked)
	}
	if len(got.Blobs) != 2 || len(got.Blobs) != len(whole.Blobs) {
		t.Fatalf("%d blobs, %d from the whole read", len(got.Blobs), len(whole.Blobs))
	}
	for h := range whole.Blobs {
		if got.Blobs[h] == nil || !bytes.Equal(got.Blobs[h].Bytes, whole.Blobs[h].Bytes) {
			t.Fatal("a blob differs between the one-profile read and the whole read")
		}
	}

	// A read that fails is the tenant's: it is skipped and alerted, and nothing of it is written.
	e := newEnv(t, nil)
	a := uid(1, 1)
	e.m.tenants[a] = mk()
	e.m.rulesErr = map[uuid.UUID]error{a: errBoom}
	e.m.mark(a, uuid.New())
	e.tick(0)
	if len(e.c.View().Endpoints) != 0 || !e.alertFor(ReasonProfile, a) {
		t.Fatalf("a tenant whose rules could not be read: %d records, alert %v", len(e.c.View().Endpoints), e.alertFor(ReasonProfile, a))
	}
	// A lost connection is the database's: the pass stops and the mark stays.
	e.m.checkErr = store.ErrConnection
	e.m.rulesErr = map[uuid.UUID]error{a: store.ErrConnection}
	e.clk.add(time.Minute)
	var err error
	for i := 0; i < 30 && err == nil; i++ {
		e.clk.add(500 * time.Millisecond)
		err = e.c.Tick(e.ctx)
	}
	if err == nil {
		t.Fatal("a lost connection while the rules were read did not stop the pass")
	}
}
