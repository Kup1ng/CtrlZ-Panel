package compiler

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of review round 5 of package W4 (the compiler). Each names the finding it closes.

// files is how many blob files the artifact store holds (a temporary file of a write in progress is not one).
func (e *env) files() int {
	e.t.Helper()
	ents, err := os.ReadDir(e.a.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	n := 0
	for _, f := range ents {
		if !strings.HasPrefix(f.Name(), ".") {
			n++
		}
	}
	return n
}

// W4-r5-1: a tenant that registers while a sliced pass runs, and marks itself, is compiled by that pass and not taken for a gone one.
func TestATenantCreatedDuringAPassIsCompiledNotTakenForGone(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Slice = time.Second })
	a, b, n := uid(1, 1), uid(1, 2), uid(1, 9)
	for i, id := range []uuid.UUID{a, b} {
		in := newTenantInput()
		in.profile(uid(2, byte(i+1)), "t"+string(rune('a'+i))+".example")
		in.endpoint(uid(3, byte(i+1)), uid(2, byte(i+1)))
		e.m.tenants[id] = in
		e.m.mark(id, uuid.New())
	}
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		if e.tenantOf(in) == a {
			// The tenant row and its first Endpoint commit after the pass listed the tenants.
			ni := newTenantInput()
			ni.profile(uid(2, 9), "new.example")
			ni.endpoint(uid(3, 9), uid(2, 9))
			e.m.mu.Lock()
			e.m.tenants[n] = ni
			e.m.mu.Unlock()
			e.m.mark(n, uuid.New())
		}
		e.clk.add(2 * time.Second)
		return real(in, now, prev)
	}
	e.tick(0)
	if e.c.View().Endpoints[ub(uid(3, 9))] == nil {
		t.Fatal("the Endpoint of a tenant created during the pass has no record")
	}
	if len(e.m.marks) != 0 {
		t.Fatalf("%d marks left", len(e.m.marks))
	}
	e.node()
}

// failOnce makes the next commit fail and runs ticks across the window, ignoring the error of the pass that met it.
func (e *env) failOnce() {
	e.t.Helper()
	e.m.failCommit = errBoom
	failed := false
	for i := 0; i < 30; i++ {
		e.clk.add(500 * time.Millisecond)
		if err := e.c.Tick(e.ctx); err != nil {
			failed = true
		}
	}
	if !failed {
		e.t.Fatal("no pass met the failed commit")
	}
}

// W4-r5-3: a tenant leaves the waiting set when its entry is committed, and not when it is compiled: a commit that fails once does
// not lose the change that waited for the window.
func TestAWaitingTenantStaysWaitingWhenTheCommitFails(t *testing.T) {
	e, a, _, ia, _ := budgetWorld(t)
	was := e.c.View().Endpoints[ub(uid(3, 1))].Base.Profile1Hash
	addRule(ia, uid(2, 1), 1)
	e.m.mark(a, uuid.New())
	e.settle()
	if e.c.waiting[a].IsZero() {
		t.Fatal("the tenant is not waiting for its window")
	}
	e.clk.add(11 * time.Minute)
	e.failOnce()
	e.settle()
	rec := e.c.View().Endpoints[ub(uid(3, 1))]
	if string(rec.Base.Profile1Hash) == string(was) || len(e.c.waiting) != 0 {
		t.Fatalf("the change that waited was lost with one failed commit (waiting %d)", len(e.c.waiting))
	}
	e.node()
}

// W4-r5-3: the same for a tenant in the retry set.
func TestARetriedTenantStaysRetriedWhenTheCommitFails(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	breakProfile(in, uid(2, 1))
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.settle()
	if !e.c.retry[a] {
		t.Fatal("the tenant is not retried")
	}
	mendProfile(in)
	e.clk.add(2 * time.Minute)
	e.failOnce()
	e.settle()
	if e.c.View().Endpoints[ub(uid(3, 1))] == nil || len(e.c.retry) != 0 {
		t.Fatal("the mended tenant was lost with one failed commit")
	}
	e.node()
}

// W4-r5-4: a profile whose sibling in a stack does not compile leaves no file behind, and the work is charged.
func TestAFileNoRecordBindsIsNotLeftInTheStore(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.profile(uid(2, 2), "b.example")
	breakProfile(in, uid(2, 2))
	in.endpoint(uid(3, 1), uid(2, 1))
	in.Endpoints[0].Profile2ID = uid(2, 2)
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.settle()
	for i := 1; i <= 5; i++ {
		addRule(in, uid(2, 1), i)
		e.m.mark(a, uuid.New())
		e.settle()
	}
	if got := e.files(); got != 0 {
		t.Fatalf("%d blob files with no record that binds them", got)
	}
	if u := e.c.blobUse[a]; u == nil || u.bytes == 0 {
		t.Fatal("the files that were written and removed were not charged")
	}
}

// W4-r5-4: a file a record binds is kept.
func TestABoundFileIsKept(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.settle()
	if e.files() != 1 {
		t.Fatalf("%d files", e.files())
	}
	e.node()
}

// W4-r5-5: a rules read that fails with the error handed back as the database does still has the hold compiled.
func TestAHoldGoesOutWhenTheRulesReadFailsAsTheDatabaseReportsIt(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	e.m.rulesErr = map[uuid.UUID]error{a: errBoom}
	in.Row.AdminHold = true
	e.m.mark(a, uuid.New())
	e.settle()
	if e.c.View().Endpoints[ub(uid(3, 1))].AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED {
		t.Fatal("the hold of a tenant whose rules cannot be read was not written")
	}
}

// W4-r5-6: a waiting tenant whose compile fails is retried once a minute and not at every debounce.
func TestAWaitingTenantThatFailsIsNotCompiledEveryDebounce(t *testing.T) {
	e, a, _, ia, _ := budgetWorld(t)
	addRule(ia, uid(2, 1), 1)
	e.m.mark(a, uuid.New())
	e.settle()
	if e.c.waiting[a].IsZero() {
		t.Fatal("the tenant is not waiting")
	}
	e.clk.add(11 * time.Minute)
	e.m.rulesErr = map[uuid.UUID]error{a: errBoom}
	e.settle()
	reads := e.m.reads
	for i := 0; i < 120; i++ { // one minute
		e.tick(500 * time.Millisecond)
	}
	if got := e.m.reads - reads; got > 4 {
		t.Fatalf("%d reads of a failing tenant in a minute", got)
	}
}

// W4-r5-7: two tenants of one batch are not split by a pass that has finished one of them.
func TestABatchThatArrivesMidPassIsWrittenWhole(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Slice = time.Second })
	a, b, c := uid(1, 1), uid(1, 2), uid(1, 3)
	ins := map[uuid.UUID]*TenantInput{}
	for i, id := range []uuid.UUID{a, b, c} {
		in := newTenantInput()
		in.profile(uid(2, byte(i+1)), "t"+string(rune('a'+i))+".example")
		in.endpoint(uid(3, byte(i+1)), uid(2, byte(i+1)))
		e.m.tenants[id], ins[id] = in, in
		e.m.mark(id, uuid.New())
	}
	e.tick(0)
	n := e.m.seqs()
	e.c.cost[b] = costClass(1 << 30) // B is the large one: it goes after A and C
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		out := real(in, now, prev)
		if e.tenantOf(in) == a {
			// A and B change together (a take) after A was compiled.
			ins[a].Row.AdminHold = true
			ins[b].Endpoints[0].AdminState = "soft_disabled"
			batch := uuid.New()
			e.m.mark(a, batch)
			e.m.mark(b, batch)
		}
		e.clk.add(2 * time.Second)
		return out
	}
	ins[a].Endpoints[0].ExposeIP = true
	ins[c].Endpoints[0].ExposeIP = true
	e.m.mark(a, uuid.New())
	e.m.mark(c, uuid.New())
	e.tick(0)
	e.settle()
	e.c.compile = real
	e.settle()
	// Whatever order the passes ran in, the hold of A and the state of B are in one entry.
	for i := n + 1; i <= e.m.seqs(); i++ {
		ent := e.entry(i)
		var gotA, gotB bool
		for _, r := range ent.PutEndpoints {
			gotA = gotA || (string(r.EndpointId) == ub(uid(3, 1)) && r.AdminState == commonv1.AdminState_ADMIN_STATE_HARD_DISABLED)
			gotB = gotB || (string(r.EndpointId) == ub(uid(3, 2)) && r.AdminState == commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED)
		}
		if gotA != gotB {
			t.Fatalf("entry %d holds one tenant of the batch and not the other (A %v, B %v)", i, gotA, gotB)
		}
	}
	if e.c.View().Endpoints[ub(uid(3, 1))].AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED ||
		e.c.View().Endpoints[ub(uid(3, 2))].AdminState != commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED || len(e.m.marks) != 0 {
		t.Fatal("the batch was not written")
	}
}

// W4-r5-8: a client whose stack cannot be compiled, and that has none in the log, keeps its analytics override.
func TestADegradedCompileKeepsTheAnalyticsOverrideOfAClient(t *testing.T) {
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.profile(uid(2, 2), "b.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	ep := &in.Endpoints[0]
	in.Clients = []store.CompilerClient{{ID: uid(7, 1), EndpointID: ep.ID, Label: "phone", Analytics: "none"}}
	now := time.Unix(1_800_000_000, 0)
	old := CompileTenant(in, now).Endpoints[string(ep.ID[:])]
	if old == nil || len(old.Clients) != 1 {
		t.Fatal("no first record")
	}
	// The client is given a profile, and the tenant is compiled with no new blob.
	in.Clients[0].ProfileID = uid(2, 2)
	in.Degraded = true
	got := CompileTenantWith(in, now, func(string) *policyv1.EndpointRecord { return old }).Endpoints[string(ep.ID[:])]
	if got == nil || len(got.Clients) != 1 || !got.Clients[0].HasAnalyticsOverride || got.Clients[0].Stack != nil {
		t.Fatalf("clients of the degraded record: %+v", got.GetClients())
	}
}
