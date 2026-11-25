package compiler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/google/uuid"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of review round 3 of package W4 (the compiler). Each names the finding it closes.

// addRule gives a profile one more rule, which changes its blob and so the record that binds it.
func addRule(in *TenantInput, pid uuid.UUID, n int) {
	in.Rules = append(in.Rules, store.ProfileRule{ProfileID: pid, RuleRow: store.RuleRow{
		ID: uuid.UUID{0: 0xE2, 14: byte(n >> 8), 15: byte(n)}, Key: "r" + uuid.UUID{14: byte(n >> 8), 15: byte(n)}.String() + ".example",
		MatchKind: "domain", Action: "block", Enabled: true}})
}

// tenantsOf names the tenant of an input, for a test that replaces the compile function.
func (e *env) tenantOf(in *TenantInput) uuid.UUID {
	for id, x := range e.m.tenants {
		if x == in {
			return id
		}
	}
	return uuid.Nil
}

// W4-r3-1, W4-r3-6: a pass does not hold the bytes of the blobs of the tenants it has compiled while it compiles the others.
// Each tenant compiles to a blob of 2 MiB; when the first entry is committed, every tenant is compiled, and at most the one
// that was compiled last may still be reachable.
func TestAPassHoldsNoBlobBytesOfTheTenantsItHasCompiled(t *testing.T) {
	const tenants = 6
	e := newEnv(t, nil)
	for i := byte(1); i <= tenants; i++ {
		in := newTenantInput()
		in.profile(uid(2, i), "t"+string(rune('a'+i))+".example")
		in.endpoint(uid(3, i), uid(2, i))
		e.m.tenants[uid(1, i)] = in
		e.m.mark(uid(1, i), uuid.New())
	}
	var weaks []weak.Pointer[Profile]
	live := -1
	e.c = e.compiler(func(c *Config) {
		c.Backend = &commitHook{memBackend: e.m, before: func(*Commit) {
			if live >= 0 {
				return
			}
			runtime.GC()
			runtime.GC()
			live = 0
			for _, w := range weaks {
				if w.Value() != nil {
					live++
				}
			}
		}}
	})
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		// The blobs are made here and not stored by the sink, so that the compiler's own handling of held bytes is what is judged.
		in.Sink = nil
		out := CompileTenantWith(in, now, prev)
		blobs := map[string]*Profile{}
		for h, p := range out.Blobs {
			big := append(bytes.Clone(p.Bytes), make([]byte, 2<<20)...)
			sum := sha256.Sum256(big)
			np := &Profile{Bytes: big, Hash: sum[:], Opts: p.Opts, MaxLabels: p.MaxLabels, HasDestGeo: p.HasDestGeo, Explicit: p.Explicit}
			blobs[string(sum[:])] = np
			weaks = append(weaks, weak.Make(np))
			for _, rec := range out.Endpoints {
				if rec.Base != nil && string(rec.Base.Profile1Hash) == h {
					rec.Base.Profile1Hash = sum[:]
				}
			}
		}
		out.Blobs = blobs
		return out
	}
	e.tick(0)
	if len(weaks) != tenants {
		t.Fatalf("%d blobs were compiled, want %d", len(weaks), tenants)
	}
	if live < 0 {
		t.Fatal("no entry was committed")
	}
	if live > 1 {
		t.Fatalf("%d of %d compiled blobs of 2 MiB were still held when the entry was committed", live, tenants)
	}
	if e.m.seqs() != 1 || len(e.m.marks) != 0 {
		t.Fatalf("%d entries, %d marks", e.m.seqs(), len(e.m.marks))
	}
	// The entry names every blob, and each file is in the store.
	for _, p := range e.entry(1).PutBlobs {
		if e.a.Size(p.Hash) != int64(p.Size) {
			t.Fatalf("a blob the entry names has %d bytes in the store, the entry says %d", e.a.Size(p.Hash), p.Size)
		}
	}
	if n := len(e.entry(1).PutBlobs); n != tenants {
		t.Fatalf("the entry names %d blobs, want %d", n, tenants)
	}
}

// W4-r3-7: what is finished is written once a slice of compile time has passed, with the marks of those tenants only, and the
// tenants that compiled to the most go last.
func TestFinishedTenantsAreWrittenInSlicesSmallOnesFirst(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Slice = time.Second })
	a, b, c := uid(1, 1), uid(1, 2), uid(1, 3)
	for i, id := range []uuid.UUID{a, b, c} {
		in := newTenantInput()
		in.profile(uid(2, byte(i+1)), "t"+string(rune('a'+i))+".example")
		in.endpoint(uid(3, byte(i+1)), uid(2, byte(i+1)))
		e.m.tenants[id] = in
		e.m.mark(id, uuid.New())
	}
	var order []uuid.UUID
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		order = append(order, e.tenantOf(in))
		e.clk.add(2 * time.Second) // a compile that takes longer than the slice
		return real(in, now, prev)
	}
	compiledAtCommit, outboxAtCommit := []int{}, []int{}
	e.c.cfg.Backend = &commitHook{memBackend: e.m, before: func(cm *Commit) {
		compiledAtCommit = append(compiledAtCommit, len(order))
		outboxAtCommit = append(outboxAtCommit, len(cm.Outbox))
	}}
	// The full pass of a new lease meets every tenant; A is the large one by the class the compiler remembers.
	e.c.cost[a] = costClass(1 << 30)
	e.tick(0)
	if len(order) != 3 || order[2] != a || order[0] != b || order[1] != c {
		t.Fatalf("the tenants were compiled in the order %v, want the large one last", order)
	}
	if len(compiledAtCommit) != 3 || compiledAtCommit[0] != 1 || outboxAtCommit[0] != 1 {
		t.Fatalf("commits after %v compiles with %v marks each: the first tenant was not written before the others were compiled", compiledAtCommit, outboxAtCommit)
	}
	if len(e.m.marks) != 0 || len(e.node().Endpoints) != 3 {
		t.Fatalf("%d marks left, %d endpoints on the node", len(e.m.marks), len(e.node().Endpoints))
	}
}

// loadHook counts the lease renewals the load makes between the reads of the tail, and moves the clock as a slow read does.
type loadHook struct {
	*memBackend
	clk    *fakeClock
	leases int
	atRead []int
}

func (h *loadHook) Lease(ctx context.Context, holder string, secs int) (bool, error) {
	h.leases++
	return h.memBackend.Lease(ctx, holder, secs)
}

func (h *loadHook) LogAfter(ctx context.Context, seq uint64, limit int, each func(store.LogRow) error) error {
	h.atRead = append(h.atRead, h.leases)
	h.clk.add(3 * time.Second)
	return h.memBackend.LogAfter(ctx, seq, limit, each)
}

// W4-r3-2: a load that fails is not tried again on every tick, and the lease is renewed between the batches of the tail.
func TestALoadThatFailsWaitsAndALongLoadRenewsTheLease(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SnapshotEvery = 1 << 30; c.SnapshotAge = 1000 * time.Hour })
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	for i := 0; i < loadBatch+3; i++ {
		addRule(in, uid(2, 1), i)
		e.m.mark(a, uuid.New())
		e.settle()
	}
	if e.m.seqs() <= loadBatch {
		t.Fatalf("the log has %d entries", e.m.seqs())
	}

	// A new compiler reads the log in two batches or more, and the clock moves 3 s with each read.
	h := &loadHook{memBackend: e.m, clk: e.clk}
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2"; c.Backend = h })
	e.tick(0)
	if len(h.atRead) < 2 || h.atRead[len(h.atRead)-1] <= h.atRead[0] {
		t.Fatalf("the lease was asked for %v times before the reads of the tail: it was not renewed between them", h.atRead)
	}

	// A log that does not chain fails the load; the next ticks within the cap do not read it again.
	e.m.holder = ""
	e.m.log[len(e.m.log)-1].Payload = []byte("not an entry")
	e.c = e.compiler(func(c *Config) { c.Holder = "w3" })
	e.clk.add(time.Second)
	if err := e.c.Tick(e.ctx); err == nil {
		t.Fatal("a log that does not chain loaded")
	}
	reads := e.m.logCalls
	for i := 0; i < 10; i++ {
		e.clk.add(500 * time.Millisecond)
		if err := e.c.Tick(e.ctx); err != nil {
			t.Fatalf("a tick within the back-off tried the load again: %v", err)
		}
	}
	if e.m.logCalls != reads {
		t.Fatalf("the log was read %d more times within the back-off", e.m.logCalls-reads)
	}
	e.clk.add(11 * time.Second)
	if err := e.c.Tick(e.ctx); err == nil || e.m.logCalls == reads {
		t.Fatalf("the load was not tried again after the back-off: %v", err)
	}
	if !e.m.hasAlert(ReasonLoad) {
		t.Fatal("a failed load raised no alert")
	}
}

// W4-r3-3: the owner of an Endpoint that was kept (it has no record) does not outlive its tenant.
func TestTheOwnerOfAKeptEndpointIsDroppedWithItsTenant(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	breakProfile(in, uid(2, 1))
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	if len(e.c.View().Endpoints) != 0 || e.c.View().owner[ub(uid(3, 1))] != a {
		t.Fatalf("the Endpoint has a record, or no owner: %d records", len(e.c.View().Endpoints))
	}
	delete(e.m.tenants, a)
	e.clk.add(time.Minute)
	e.settle()
	if len(e.c.View().owner) != 0 || len(e.c.vanishedTenants(nil)) != 0 || e.c.owed {
		t.Fatalf("a purged tenant is still owned %d keys, owed %v", len(e.c.View().owner), e.c.owed)
	}
}

// W4-r3-4: a tenant whose compile panics for ever does not hold the orphan sweep: its Endpoints were read, so they are its own and
// the records no tenant owns are taken out.
func TestAPoisonTenantDoesNotBlockTheOrphanSweep(t *testing.T) {
	e, a, b, _ := twoTenants(t)
	// A's Endpoint is gone from the database with no mark, B panics in its compile.
	e.m.tenants[a].Endpoints = nil
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		if in == e.m.tenants[b] {
			panic("poison")
		}
		return real(in, now, prev)
	}
	e.tick(0)
	e.settle()
	st := e.node()
	if len(st.Endpoints) != 1 {
		t.Fatalf("%d Endpoints on the node: the sweep was blocked by the poison tenant, or took its record", len(st.Endpoints))
	}
	if _, ok := e.c.View().Endpoints[ub(uid(3, 2))]; !ok {
		t.Fatal("the record of the poison tenant was swept")
	}
	if !e.alertFor(ReasonProfile, b) {
		t.Fatal("the poison tenant raised no alert")
	}
}

// W4-r3-9: a timeout of one tenant's own read looks like the database's. When the database answers a cheap question the tenant
// is skipped and the others are written; when it does not, the pass stops as before.
func TestATenantsOwnTimeoutDoesNotStopTheCompilerForEveryone(t *testing.T) {
	for _, class := range []error{store.ErrRetry, store.ErrConnection} {
		e := newEnv(t, nil)
		a, b := uid(1, 1), uid(1, 2)
		ia, ib := newTenantInput(), newTenantInput()
		ia.profile(uid(2, 1), "a.example")
		ia.endpoint(uid(3, 1), uid(2, 1))
		ib.profile(uid(2, 2), "b.example")
		ib.endpoint(uid(3, 2), uid(2, 2))
		e.m.tenants[a], e.m.tenants[b] = ia, ib
		e.m.tenantErr = map[uuid.UUID]error{a: class}
		e.m.mark(a, uuid.New())
		e.m.mark(b, uuid.New())
		e.tick(0)
		if _, ok := e.c.View().Endpoints[ub(uid(3, 2))]; !ok || len(e.m.marks) != 0 {
			t.Fatalf("%v: the healthy tenant waited for the one that timed out", class)
		}
		if !e.alertFor(ReasonProfile, a) || !e.c.retry[a] {
			t.Fatalf("%v: the tenant that timed out raised no alert or is not retried", class)
		}
		if e.c.cost[a] != costClass(1<<62) {
			t.Fatalf("%v: the tenant that timed out is not last in the next pass", class)
		}

		// The database that does not answer is another matter.
		e2 := newEnv(t, nil)
		e2.m.tenants[a] = newTenantInput()
		e2.m.tenantErr = map[uuid.UUID]error{a: class}
		e2.m.checkErr = store.ErrConnection
		e2.m.mark(a, uuid.New())
		e2.clk.add(time.Second)
		if err := e2.c.Tick(e2.ctx); err == nil || len(e2.m.marks) != 1 {
			t.Fatalf("%v: a database that does not answer was taken for a slow tenant", class)
		}
	}
}

// W4-r3-10: the entry a snapshot was cut at is read for the format major, and a read that fails fails the load.
func TestAFailedReadOfTheSnapshotsEntryFailsTheLoad(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SnapshotEvery = 2 })
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	for i := byte(2); i <= 4; i++ {
		in.endpoint(uid(3, i), uid(2, 1))
		e.m.mark(a, uuid.New())
		e.settle()
	}
	if len(e.m.snaps) == 0 {
		t.Fatal("no snapshot")
	}
	snap := e.m.snaps[len(e.m.snaps)-1].Seq
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2" })
	e.m.logAfterErr = map[uint64]error{snap - 1: errBoom}
	e.clk.add(time.Second)
	if err := e.c.Tick(e.ctx); !errors.Is(err, errBoom) || e.c.View() != nil {
		t.Fatalf("the load went on with a major it could not read: %v", err)
	}
	e.m.logAfterErr = nil
	e.clk.add(11 * time.Second)
	e.tick(0)
	if e.c.View() == nil || e.c.View().Major != 1 {
		t.Fatal("the load did not succeed once the read did")
	}
}
