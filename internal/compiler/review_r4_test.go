package compiler

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
)

// Tests of review round 4 of package W4 (the compiler). Each names the finding it closes.

// newBlobs is how many blob files the entries after seq `from` name.
func (e *env) newBlobs(from int) int {
	n := 0
	for i := from + 1; i <= e.m.seqs(); i++ {
		n += len(e.entry(i).PutBlobs)
	}
	return n
}

// W4-r4-1: a tenant that failed in a slice that was written is still tried again when a later slice of the same pass errors.
func TestAFailedTenantIsRetriedWhenALaterSliceErrors(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Slice = time.Second })
	a, b, c := uid(1, 1), uid(1, 2), uid(1, 3)
	for i, id := range []uuid.UUID{a, b, c} {
		in := newTenantInput()
		in.profile(uid(2, byte(i+1)), "t"+string(rune('a'+i))+".example")
		in.endpoint(uid(3, byte(i+1)), uid(2, byte(i+1)))
		e.m.tenants[id] = in
		e.m.mark(id, uuid.New())
	}
	breakProfile(e.m.tenants[a], uid(2, 1)) // A does not compile and has no record in the log to fall back on
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		e.clk.add(2 * time.Second) // a slice of its own for each tenant
		if e.tenantOf(in) == b {
			// The slice that holds A has been written and its marks are gone; the commit of the next one fails.
			e.m.failCommit = errBoom
		}
		return real(in, now, prev)
	}
	e.clk.add(time.Second)
	if err := e.c.Tick(e.ctx); !errors.Is(err, errBoom) {
		t.Fatalf("the pass did not fail as the test set it up: %v", err)
	}
	for _, m := range e.m.marks {
		if m.Tenant == a {
			t.Fatal("the marks of A stayed: the test does not meet the case")
		}
	}
	if !e.c.retry[a] || e.c.retryDue.IsZero() {
		t.Fatal("A lost its retry with its marks when a later slice failed")
	}
}

// twoOfTwo is two tenants of one Endpoint each, written by the full pass, with a budget that the first compile already uses up.
func budgetWorld(t *testing.T) (e *env, a, b uuid.UUID, ia, ib *TenantInput) {
	t.Helper()
	e = newEnv(t, func(c *Config) { c.TenantBlobBytes = 1 })
	a, b = uid(1, 1), uid(1, 2)
	ia, ib = newTenantInput(), newTenantInput()
	ia.profile(uid(2, 1), "a.example")
	ia.endpoint(uid(3, 1), uid(2, 1))
	ib.profile(uid(2, 2), "b.example")
	ib.endpoint(uid(3, 2), uid(2, 2))
	e.m.tenants[a], e.m.tenants[b] = ia, ib
	e.m.mark(a, uuid.New())
	e.m.mark(b, uuid.New())
	e.tick(0)
	if e.c.blobUse[a] == nil || e.c.blobUse[b] == nil {
		t.Fatal("the first compile was not counted")
	}
	return e, a, b, ia, ib
}

// W4-r3-8, W4-r4-2, W4-r4-5: a tenant past its share is compiled with no new blob. Its hold goes out at once, the new blob waits for
// the window, and the others go on.
func TestATenantPastItsBudgetStillHasItsHoldWrittenAndItsBlobWaits(t *testing.T) {
	e, a, _, ia, _ := budgetWorld(t)
	n := e.m.seqs()
	was := e.c.View().Endpoints[ub(uid(3, 1))].Base.Profile1Hash

	addRule(ia, uid(2, 1), 1)
	ia.Row.AdminHold = true
	e.m.mark(a, uuid.New())
	e.settle()
	rec := e.c.View().Endpoints[ub(uid(3, 1))]
	if rec.AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED {
		t.Fatal("the hold of a tenant past its budget was not written")
	}
	if !bytes.Equal(rec.Base.Profile1Hash, was) || e.newBlobs(n) != 0 {
		t.Fatalf("a new blob was written for a tenant past its budget (%d)", e.newBlobs(n))
	}
	if len(e.m.marks) != 0 || e.c.waiting[a].IsZero() {
		t.Fatalf("%d marks left, waiting %v: the tenant is not owed its blob", len(e.m.marks), e.c.waiting[a])
	}
	e.node()

	// A setting that is not about access waits too: it would cost every node the whole record.
	n = e.m.seqs()
	ia.Endpoints[0].ExposeIP = true
	e.m.mark(a, uuid.New())
	e.settle()
	if e.m.seqs() != n || e.c.View().Endpoints[ub(uid(3, 1))].ExposeIp {
		t.Fatal("a flag that is not about access was written for a tenant past its budget")
	}

	// The window ends and the tenant is compiled again with no mark.
	e.clk.add(11 * time.Minute)
	e.settle()
	rec = e.c.View().Endpoints[ub(uid(3, 1))]
	if bytes.Equal(rec.Base.Profile1Hash, was) || !rec.ExposeIp || e.newBlobs(n) != 1 || len(e.c.waiting) != 0 {
		t.Fatalf("after the window: blob changed %v, expose %v, %d new blobs, %d waiting", !bytes.Equal(rec.Base.Profile1Hash, was), rec.ExposeIp, e.newBlobs(n), len(e.c.waiting))
	}
	e.node()
}

// W4-r4-6: the retry of another tenant, or of the tenant itself, does not lift the budget. Over 400 s a tenant that edits a rule
// every 80 s gets no new blob while a poison tenant is retried every minute.
func TestTheRetryPassDoesNotLiftTheBlobBudget(t *testing.T) {
	e, a, _, ia, _ := budgetWorld(t)
	c := uid(1, 3)
	ic := newTenantInput()
	ic.profile(uid(2, 3), "c.example")
	breakProfile(ic, uid(2, 3))
	ic.endpoint(uid(3, 3), uid(2, 3))
	e.m.tenants[c] = ic
	e.m.mark(c, uuid.New())
	e.settle()
	if !e.c.retry[c] {
		t.Fatal("the poison tenant is not retried")
	}
	n := e.m.seqs()
	for i := 1; i <= 5; i++ {
		addRule(ia, uid(2, 1), i)
		e.m.mark(a, uuid.New())
		e.clk.add(65 * time.Second)
		e.settle()
	}
	if got := e.newBlobs(n); got != 0 {
		t.Fatalf("%d blobs were written for a tenant past its budget while another tenant was retried", got)
	}
}

// W4-r4-5: the two tenants of one batch are written in one entry even when one of them is past its budget, so the old claim and
// the new claim of an address are never on the nodes together.
func TestABatchStaysWholeWhenOneTenantIsPastItsBudget(t *testing.T) {
	e, a, _, ia, _ := budgetWorld(t)
	// C is new, so it is not past its budget; A's hold and C's first compile are one batch.
	c := uid(1, 3)
	ic := newTenantInput()
	ic.profile(uid(2, 3), "c.example")
	ic.endpoint(uid(3, 3), uid(2, 3))
	e.m.tenants[c] = ic
	n := e.m.seqs()
	ia.Row.AdminHold = true
	batch := uuid.New()
	e.m.mark(a, batch)
	e.m.mark(c, batch)
	e.settle()
	if e.m.seqs() != n+1 {
		t.Fatalf("%d entries for a batch of two tenants", e.m.seqs()-n)
	}
	ent := e.entry(n + 1)
	if len(ent.PutEndpoints) != 2 || len(ent.PutBlobs) != 1 {
		t.Fatalf("%d records and %d blobs in the entry of the batch", len(ent.PutEndpoints), len(ent.PutBlobs))
	}
}

// W4-r4-5: a compile that panics costs the tenant its new blobs and not its revocations.
func TestAPanickingCompileStillWritesTheHold(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		if !in.Degraded {
			panic("poison")
		}
		return real(in, now, prev)
	}
	in.Row.AdminHold = true
	e.m.mark(a, uuid.New())
	e.settle()
	if e.c.View().Endpoints[ub(uid(3, 1))].AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED {
		t.Fatal("the hold of a tenant whose compile panics was not written")
	}
	if !e.alertFor(ReasonProfile, a) || !e.c.retry[a] || len(e.m.marks) != 0 {
		t.Fatal("the tenant is not alerted and retried")
	}
	e.c.compile = real
	e.clk.add(time.Minute)
	e.settle()
	if len(e.c.retry) != 0 {
		t.Fatal("the tenant stayed in the retry set once it compiled")
	}
}

// failingArtifacts refuses every new file while fail is set, as a full volume does.
type failingArtifacts struct {
	Artifacts
	fail bool
}

func (f *failingArtifacts) Put(h, d []byte) error {
	if f.fail && !f.Artifacts.Has(h, int64(len(d))) {
		return errBoom
	}
	return f.Artifacts.Put(h, d)
}

func (f *failingArtifacts) Ensure(h, d []byte) error {
	if f.fail {
		return errBoom
	}
	return f.Artifacts.Ensure(h, d)
}

// W4-r4-9: a volume that refuses a file ends no pass. The tenant keeps the stacks it had, its hold goes out, an alert is raised and
// the other tenant is written; once the volume takes files again the tenant is compiled with no new mark.
func TestAFullVolumeCostsOnlyTheNewBlobsAndRaisesAnAlert(t *testing.T) {
	e := newEnv(t, nil)
	arts := &failingArtifacts{Artifacts: e.a}
	e.c = e.compiler(func(c *Config) { c.Artifacts = arts })
	a, b := uid(1, 1), uid(1, 2)
	ia, ib := newTenantInput(), newTenantInput()
	ia.profile(uid(2, 1), "a.example")
	ia.endpoint(uid(3, 1), uid(2, 1))
	ib.profile(uid(2, 2), "b.example")
	ib.endpoint(uid(3, 2), uid(2, 2))
	e.m.tenants[a], e.m.tenants[b] = ia, ib
	e.m.mark(a, uuid.New())
	e.m.mark(b, uuid.New())
	e.tick(0)
	n := e.m.seqs()
	was := e.c.View().Endpoints[ub(uid(3, 1))].Base.Profile1Hash

	arts.fail = true
	addRule(ia, uid(2, 1), 1)
	ia.Row.AdminHold = true
	ib.Endpoints[0].AdminState = "soft_disabled"
	e.m.mark(a, uuid.New())
	e.m.mark(b, uuid.New())
	e.settle()
	if e.c.View().Endpoints[ub(uid(3, 1))].AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED ||
		e.c.View().Endpoints[ub(uid(3, 2))].AdminState != commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED {
		t.Fatal("a refused file stopped the writes of the pass")
	}
	if !bytes.Equal(e.c.View().Endpoints[ub(uid(3, 1))].Base.Profile1Hash, was) || e.newBlobs(n) != 0 {
		t.Fatal("a blob that was not stored was named")
	}
	if !e.alertFor(ReasonArtifacts, a) || !e.c.retry[a] || len(e.m.marks) != 0 {
		t.Fatal("no alert, no retry, or the marks stayed")
	}
	arts.fail = false
	e.clk.add(time.Minute)
	e.settle()
	if bytes.Equal(e.c.View().Endpoints[ub(uid(3, 1))].Base.Profile1Hash, was) || len(e.c.retry) != 0 {
		t.Fatal("the tenant was not compiled once the volume took files")
	}
	e.node()
}

// W4-r4-7: a change marked while a pass works is compiled before the large tenants that are left.
func TestAMarkThatArrivesDuringAPassIsServedBeforeTheLargeTenantsLeft(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Slice = time.Second })
	ids := map[string]uuid.UUID{"a": uid(1, 1), "b": uid(1, 2), "c": uid(1, 3), "d": uid(1, 4)}
	for i, name := range []string{"a", "b", "c", "d"} {
		in := newTenantInput()
		in.profile(uid(2, byte(i+1)), "t"+name+".example")
		in.endpoint(uid(3, byte(i+1)), uid(2, byte(i+1)))
		e.m.tenants[ids[name]] = in
	}
	// B and C are marked, A and D are large; the full pass of a new lease meets everyone.
	e.m.mark(ids["b"], uuid.New())
	e.m.mark(ids["c"], uuid.New())
	e.c.cost[ids["a"]], e.c.cost[ids["d"]] = costClass(1<<30), costClass(1<<30)
	var order []uuid.UUID
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		t := e.tenantOf(in)
		order = append(order, t)
		if t == ids["b"] {
			e.m.mark(ids["d"], uuid.New()) // a revocation, say, arriving while B compiles
		}
		e.clk.add(2 * time.Second)
		return real(in, now, prev)
	}
	e.tick(0)
	if len(order) != 4 || order[0] != ids["b"] || order[1] != ids["c"] || order[2] != ids["d"] || order[3] != ids["a"] {
		t.Fatalf("the tenants were compiled in the order %v: the mark of D waited behind the large A", order)
	}
	if len(e.m.marks) != 0 {
		t.Fatalf("%d marks left", len(e.m.marks))
	}
}

// W4-r4-4: a slice is also ended by the bytes that are pending, so a pass of many small and fast tenants does not hold their
// diffs until the last one is compiled.
func TestASliceEndsWhenEnoughBytesArePending(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Slice = time.Hour; c.MaxEntryBytes = 1500 })
	const tenants = 8
	for i := byte(1); i <= tenants; i++ {
		in := newTenantInput()
		in.profile(uid(2, i), "t"+string(rune('a'+i))+".example")
		in.endpoint(uid(3, i), uid(2, i))
		e.m.tenants[uid(1, i)] = in
		e.m.mark(uid(1, i), uuid.New())
	}
	compiled := 0
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		compiled++
		return real(in, now, prev)
	}
	first := -1
	e.c.cfg.Backend = &commitHook{memBackend: e.m, before: func(*Commit) {
		if first < 0 {
			first = compiled
		}
	}}
	e.tick(0)
	if first < 1 || first >= tenants {
		t.Fatalf("the first entry was committed after %d of %d tenants: the pending bytes did not end the slice", first, tenants)
	}
	if len(e.m.marks) != 0 || len(e.node().Endpoints) != tenants {
		t.Fatal("not every tenant was written")
	}
}

// W4-r4-4: the stacks of one record that are equal are one object in the view, however many clients name them.
func TestEqualStacksOfARecordAreOneObjectInTheView(t *testing.T) {
	stack := func() *policyv1.StackRecord {
		return &policyv1.StackRecord{Profile1Hash: bytes.Repeat([]byte{1}, 32), MergedOptions: []byte{1, 2, 3}, MaxDepth: 2}
	}
	rec := &policyv1.EndpointRecord{EndpointId: bytes.Repeat([]byte{9}, 16), Base: stack()}
	for i := byte(0); i < 100; i++ {
		rec.Clients = append(rec.Clients, &policyv1.ClientRecord{ClientId: []byte{i}, Stack: stack()})
	}
	other := stack()
	other.Profile2Hash = bytes.Repeat([]byte{2}, 32)
	rec.Clients[7].Stack = other
	v := NewView(1)
	v.Apply(&policyv1.ConfigEntry{Seq: 1, PutEndpoints: []*policyv1.EndpointRecord{rec}}, make([]byte, 32))
	got := v.Endpoints[string(rec.EndpointId)]
	for i, c := range got.Clients {
		switch {
		case i == 7 && c.Stack == got.Base:
			t.Fatal("a stack that differs was shared")
		case i != 7 && c.Stack != got.Base:
			t.Fatalf("client %d holds a stack of its own", i)
		}
	}
	if got.Clients[7].Stack.Profile2Hash == nil {
		t.Fatal("the other stack lost its content")
	}
}

// W4-r4-4: a profile is handed to the sink as it is built and its bytes are let go, so a tenant does not hold all its blobs.
func TestACompileHandsEachBlobToTheSinkAndLetsItGo(t *testing.T) {
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.profile(uid(2, 2), "b.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	in.endpoint(uid(3, 2), uid(2, 2))
	var seen []int
	in.Sink = func(p *Profile) error {
		if len(p.Bytes) == 0 {
			t.Fatal("the sink got no bytes")
		}
		seen = append(seen, len(p.Bytes))
		return nil
	}
	out := CompileTenant(in, time.Unix(1_800_000_000, 0))
	if len(seen) != 2 || len(out.Blobs) != 2 {
		t.Fatalf("%d blobs sunk, %d in the output", len(seen), len(out.Blobs))
	}
	for _, p := range out.Blobs {
		if p.Bytes != nil || p.Len() == 0 {
			t.Fatal("a blob that was sunk still holds its bytes, or lost its size")
		}
	}
	// A sink that refuses ends the compile with its error.
	in.Sink = func(*Profile) error { return errBoom }
	if out := CompileTenant(in, time.Unix(1_800_000_000, 0)); !errors.Is(out.readErr, errBoom) {
		t.Fatalf("the refusal of the sink is %v", out.readErr)
	}
}
