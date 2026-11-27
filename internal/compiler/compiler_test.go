package compiler

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

func uid(kind, n byte) uuid.UUID { return uuid.UUID{0: 0xA0 | kind, 15: n} }

// newTenantInput is a tenant with a client cap and no content.
func newTenantInput() *TenantInput {
	return &TenantInput{Row: store.CompilerTenantRow{Status: "active", ClientCap: 50}}
}

// profile adds a profile that blocks the domains.
func (in *TenantInput) profile(pid uuid.UUID, domains ...string) {
	in.Profiles = append(in.Profiles, store.CompilerProfile{ID: pid})
	for i, d := range domains {
		in.Rules = append(in.Rules, store.ProfileRule{ProfileID: pid, RuleRow: store.RuleRow{
			ID: uuid.UUID{0: 0xE0, 15: byte(i + 1)}, Key: d, MatchKind: "domain", Action: "block", Enabled: true}})
	}
}

func (in *TenantInput) endpoint(eid, pid uuid.UUID) {
	in.Endpoints = append(in.Endpoints, store.CompilerEndpoint{ID: eid, ResolverID: "res" + eid.String(), TokenHash: bytes.Repeat([]byte{eid[15]}, 32),
		AdminState: "enabled", AnalyticsLevel: "full", ProfileID: pid, ScheduleTimezone: "Asia/Tehran"})
}

type env struct {
	t   *testing.T
	m   *memBackend
	a   *DirArtifacts
	clk *fakeClock
	c   *Compiler
	ctx context.Context
}

func newEnv(t *testing.T, mutate func(*Config)) *env {
	t.Helper()
	a, err := NewDirArtifacts(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, m: newMem(), a: a, clk: &fakeClock{t: time.Unix(1_800_000_000, 0)}, ctx: context.Background()}
	e.c = e.compiler(mutate)
	return e
}

func (e *env) compiler(mutate func(*Config)) *Compiler {
	cfg := Config{Backend: e.m, Artifacts: e.a, Clock: e.clk.Now, Holder: "w1"}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) tick(d time.Duration) {
	e.t.Helper()
	e.clk.add(d)
	if err := e.c.Tick(e.ctx); err != nil {
		e.t.Fatalf("tick: %v", err)
	}
}

// settle runs ticks across the whole merge window so every owed mark is written.
func (e *env) settle() {
	e.t.Helper()
	for i := 0; i < 30; i++ {
		e.tick(500 * time.Millisecond)
	}
}

func (e *env) entry(seq int) *policyv1.ConfigEntry {
	e.t.Helper()
	ent, err := wire.DecodeEntry(e.m.log[seq-1].Payload)
	if err != nil {
		e.t.Fatal(err)
	}
	return ent
}

func (e *env) node() *quarantine.State { return applyAll(e.t, e.m, e.a) }

func ub(u uuid.UUID) string { return string(u[:]) }

func TestFirstPassIsJudgedByTheNode(t *testing.T) {
	e := newEnv(t, nil)
	a, b := uid(1, 1), uid(1, 2)
	ia, ib := newTenantInput(), newTenantInput()
	ia.profile(uid(2, 1), "a.example", "b.example")
	ia.endpoint(uid(3, 1), uid(2, 1))
	ib.profile(uid(2, 2), "a.example", "b.example") // the same content: one blob for both tenants
	ib.endpoint(uid(3, 2), uid(2, 2))
	e.m.tenants[a], e.m.tenants[b] = ia, ib
	e.m.mark(a, uuid.New())
	e.m.mark(b, uuid.New())

	e.tick(0)
	if e.m.seqs() == 0 || len(e.m.marks) != 0 {
		t.Fatalf("the first pass wrote %d entries and left %d marks", e.m.seqs(), len(e.m.marks))
	}
	st := e.node()
	if len(st.Endpoints) != 2 || len(st.Profiles) != 1 {
		t.Fatalf("the node holds %d endpoints and %d blobs, want 2 and 1", len(st.Endpoints), len(st.Profiles))
	}
	puts := 0
	for i := 1; i <= e.m.seqs(); i++ {
		puts += len(e.entry(i).PutBlobs)
	}
	if puts != 1 {
		t.Fatalf("the shared blob was named %d times, want once", puts)
	}
	// The entries chain, and the view the compiler keeps is the node's state.
	if e.c.View().Seq != uint64(e.m.seqs()) || len(e.c.View().Endpoints) != 2 {
		t.Fatalf("view at %d with %d endpoints", e.c.View().Seq, len(e.c.View().Endpoints))
	}
	if string(e.c.View().Head) != string(st.Head[:]) {
		t.Fatal("the compiler's head is not the node's")
	}
}

func TestDebounceAndCap(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	base := e.m.seqs()

	// A change waits 2 s from the last mark.
	in.endpoint(uid(3, 2), uid(2, 1))
	e.m.mark(a, uuid.New())
	e.tick(0)
	e.tick(time.Second)
	if e.m.seqs() != base {
		t.Fatal("an entry was written inside the 2 s window")
	}
	e.tick(1100 * time.Millisecond)
	if e.m.seqs() != base+1 || len(e.m.marks) != 0 {
		t.Fatalf("after the window: %d new entries, %d marks", e.m.seqs()-base, len(e.m.marks))
	}

	// A mark that keeps coming holds the quiet window open, and the cap of 10 s from the first ends it.
	base = e.m.seqs()
	in.endpoint(uid(3, 3), uid(2, 1))
	e.m.mark(a, uuid.New())
	e.tick(0)
	for i := 1; i <= 8; i++ {
		e.tick(1500 * time.Millisecond)
		if i < 7 && e.m.seqs() != base {
			t.Fatalf("written before the cap, at %.1f s", 1.5*float64(i))
		}
		e.m.mark(a, uuid.New())
	}
	if e.m.seqs() == base {
		t.Fatal("the cap of 10 s did not end the window")
	}
}

func TestBlobLifecycleIsOneShot(t *testing.T) {
	e := newEnv(t, nil)
	a, b := uid(1, 1), uid(1, 2)
	ia, ib := newTenantInput(), newTenantInput()
	ia.profile(uid(2, 1), "a.example")
	ia.endpoint(uid(3, 1), uid(2, 1))
	ib.profile(uid(2, 2), "a.example")
	ib.endpoint(uid(3, 2), uid(2, 2))
	e.m.tenants[a], e.m.tenants[b] = ia, ib
	e.m.mark(a, uuid.New())
	e.m.mark(b, uuid.New())
	e.tick(0)
	var hash string
	for h := range e.c.View().refs {
		hash = h
	}
	if e.c.View().refs[hash] != 2 {
		t.Fatalf("the shared blob is bound %d times", e.c.View().refs[hash])
	}

	// Tenant B lets go of it: the other still binds it, so it is not named in del_blobs.
	ib.Endpoints = nil
	e.m.mark(b, uuid.New())
	e.settle()
	last := e.entry(e.m.seqs())
	if len(last.DelEndpoints) != 1 || len(last.DelBlobs) != 0 {
		t.Fatalf("the first release: %d endpoint deletes, %d blob deletes", len(last.DelEndpoints), len(last.DelBlobs))
	}
	if n := len(e.node().Profiles); n != 1 {
		t.Fatalf("the node holds %d blobs, want 1", n)
	}

	// The last binding goes: now it is named, once, and marked for collection.
	ia.Endpoints = nil
	e.m.mark(a, uuid.New())
	e.settle()
	last = e.entry(e.m.seqs())
	if len(last.DelBlobs) != 1 || string(last.DelBlobs[0]) != hash {
		t.Fatalf("the last release names %d blobs", len(last.DelBlobs))
	}
	if e.m.arts[hash].GCAfter != last.Seq {
		t.Fatalf("gc_after_seq %d, want %d", e.m.arts[hash].GCAfter, last.Seq)
	}
	if n := len(e.node().Profiles); n != 0 {
		t.Fatalf("the node still holds %d blobs", n)
	}

	// Bound again: named again, the collection mark cleared, and the node holds it.
	ia.endpoint(uid(3, 5), uid(2, 1))
	e.m.mark(a, uuid.New())
	e.settle()
	last = e.entry(e.m.seqs())
	if len(last.PutBlobs) != 1 || e.m.arts[hash].GCAfter != 0 {
		t.Fatalf("rebind: %d blobs named, gc_after_seq %d", len(last.PutBlobs), e.m.arts[hash].GCAfter)
	}
	if n := len(e.node().Profiles); n != 1 {
		t.Fatalf("the node holds %d blobs after the rebind", n)
	}
}

func TestMovingBetweenProfilesKeepsTheSharedBlob(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.profile(uid(2, 2), "b.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	// Endpoint 1 moves to profile 2 and endpoint 2 takes profile 1 in one batch: nothing leaves the log.
	in.Endpoints[0].ProfileID = uid(2, 2)
	in.endpoint(uid(3, 2), uid(2, 1))
	e.m.mark(a, uuid.New())
	e.settle()
	last := e.entry(e.m.seqs())
	if len(last.DelBlobs) != 0 || len(last.PutEndpoints) != 2 {
		t.Fatalf("a move named %d deletes and %d puts", len(last.DelBlobs), len(last.PutEndpoints))
	}
	e.node()
}

func TestMembershipReachesTheLogWithNoOutboxRow(t *testing.T) {
	e := newEnv(t, nil)
	e.m.freeVer = 0 // no free DNS value yet: the pass has nothing else to carry
	mk := func(slot int, ip string) store.MemberNode {
		return store.MemberNode{ID: uid(9, byte(slot)), Status: "active", Slot: slot, DNSIP: ip, ProxyIP: ip, SPKI: bytes.Repeat([]byte{byte(slot)}, 32), BlobMajor: 1}
	}
	n1, n2 := mk(1, "8.8.8.8"), mk(2, "8.8.4.4")
	e.m.members = &Membership{Nodes: []store.MemberNode{n1, n2}, Pairs: []store.MemberPair{{ID: uid(8, 1), Primary: n1.ID, Fallback: n2.ID}}, Global: uid(8, 1)}
	e.m.freeVer = 1
	e.tick(0)
	pt := e.c.View().Pair
	if pt == nil || len(pt.Nodes) != 2 || string(pt.GlobalPairId) != ub(uid(8, 1)) {
		t.Fatalf("the table in the log: %+v", pt)
	}
	n := e.m.seqs()

	// Nothing changed: no entry, however many passes.
	e.settle()
	if e.m.seqs() != n {
		t.Fatal("an unchanged membership wrote an entry")
	}

	// A revocation empties the SPKI inside the window and changes nothing else.
	n2.Status = "revoked"
	e.m.members = &Membership{Nodes: []store.MemberNode{n1, n2}, Pairs: e.m.members.Pairs, Global: uid(8, 1)}
	e.settle()
	if e.m.seqs() != n+1 {
		t.Fatalf("the revocation wrote %d entries", e.m.seqs()-n)
	}
	pt = e.entry(n + 1).PairTable
	if len(pt.Nodes[1].SpkiSha256) != 0 || len(pt.Nodes[0].SpkiSha256) != 32 || len(pt.Pairs) != 1 {
		t.Fatalf("the revocation entry: %+v", pt)
	}

	// A table the validator refuses (a shared address) is not written: the last table stands and an alert is raised,
	// and a node revoked meanwhile still has its SPKI empty.
	n1.DNSIP = "8.8.4.4"
	e.m.members = &Membership{Nodes: []store.MemberNode{n1, n2}, Pairs: e.m.members.Pairs, Global: uid(8, 1)}
	e.settle()
	if e.m.seqs() != n+1 || !e.m.hasAlert(ReasonPairTable) {
		t.Fatalf("a refused table: %d entries, alert %v", e.m.seqs()-n, e.m.hasAlert(ReasonPairTable))
	}
}

func TestRevokedStaysEmptyAndRemovedLeavesTheTable(t *testing.T) {
	last := BuildPairTable(&Membership{Nodes: []store.MemberNode{
		{ID: uid(9, 1), Status: "revoked", Slot: 1, DNSIP: "8.8.8.8", ProxyIP: "8.8.8.8"},
		{ID: uid(9, 2), Status: "active", Slot: 2, DNSIP: "8.8.4.4", ProxyIP: "8.8.4.4", SPKI: bytes.Repeat([]byte{2}, 32)},
	}})
	// The row of node 1 reads active with an SPKI again (it cannot, by the trigger, but a table must not trust it).
	m := &Membership{Nodes: []store.MemberNode{
		{ID: uid(9, 1), Status: "active", Slot: 1, DNSIP: "8.8.8.8", ProxyIP: "8.8.8.8", SPKI: bytes.Repeat([]byte{1}, 32)},
		{ID: uid(9, 2), Status: "active", Slot: 2, DNSIP: "8.8.4.4", ProxyIP: "8.8.4.4", SPKI: bytes.Repeat([]byte{2}, 32)},
	}}
	if pt, _ := NextPairTable(m, last); pt != nil {
		t.Fatalf("an SPKI once empty was written non-empty: %+v", pt)
	}
	// A removed node is out of the next table.
	m.Nodes = m.Nodes[1:]
	pt, _ := NextPairTable(m, last)
	if pt == nil || len(pt.Nodes) != 1 {
		t.Fatalf("the removal: %+v", pt)
	}
}

func TestRestartLearnsTheViewAndAddsNothing(t *testing.T) {
	e := newEnv(t, nil)
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

	// A second process takes the lease after the first lost it: same log, nothing written.
	e.m.holder = ""
	c2 := e.compiler(func(c *Config) { c.Holder = "w2" })
	e.c = c2
	e.tick(0)
	e.settle()
	if e.m.seqs() != n {
		t.Fatalf("a restart wrote %d entries", e.m.seqs()-n)
	}
	if len(c2.View().Endpoints) != 2 || len(c2.View().owner) != 2 {
		t.Fatalf("the restarted view: %d endpoints, %d owned", len(c2.View().Endpoints), len(c2.View().owner))
	}

	// Tenant B is gone with no mark: the reconcile finds its Endpoint, and nothing of tenant A moves.
	delete(e.m.tenants, b)
	e.clk.add(2 * time.Minute)
	e.settle()
	last := e.entry(e.m.seqs())
	if len(last.DelEndpoints) != 1 || string(last.DelEndpoints[0]) != ub(uid(3, 2)) || len(last.PutEndpoints) != 0 {
		t.Fatalf("the vanished tenant: %d deletes, %d puts", len(last.DelEndpoints), len(last.PutEndpoints))
	}
	if st := e.node(); len(st.Endpoints) != 1 {
		t.Fatalf("the node holds %d endpoints", len(st.Endpoints))
	}
}

func TestFullPassRemovesWhatNoTenantOwns(t *testing.T) {
	e := newEnv(t, nil)
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

	// Tenant B is purged while the compiler is down (its outbox rows went with it).
	delete(e.m.tenants, b)
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2" })
	e.tick(0)
	last := e.entry(e.m.seqs())
	if len(last.DelEndpoints) != 1 {
		t.Fatalf("the orphan was not taken out: %d deletes", len(last.DelEndpoints))
	}
	if len(e.node().Endpoints) != 1 {
		t.Fatal("the node still has the orphan")
	}
}

func TestMergedPassIsCutAndABatchStaysWhole(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxPerEntry = 6 })
	var ts []uuid.UUID
	for i := byte(1); i <= 3; i++ {
		in := newTenantInput()
		in.profile(uid(2, i), "t.example")
		in.endpoint(uid(3, i), uid(2, i))
		in.endpoint(uid(3, i+10), uid(2, i))
		e.m.tenants[uid(1, i)] = in
		ts = append(ts, uid(1, i))
	}
	shared := uuid.New() // tenants 1 and 2 are one batch
	e.m.mark(ts[0], shared)
	e.m.mark(ts[1], shared)
	e.m.mark(ts[2], uuid.New())
	e.tick(0)
	// Each entry is within the cap, and the two tenants of the batch are in one entry.
	together := false
	for i := 1; i <= e.m.seqs(); i++ {
		ent := e.entry(i)
		if n := len(ent.PutEndpoints) + len(ent.PutBlobs); n > 6 {
			t.Fatalf("entry %d has %d records over the cap of 6", i, n)
		}
		ids := map[string]bool{}
		for _, ep := range ent.PutEndpoints {
			ids[string(ep.EndpointId)] = true
		}
		if ids[ub(uid(3, 1))] && ids[ub(uid(3, 2))] {
			together = true
		}
	}
	if !together || e.m.seqs() < 2 {
		t.Fatalf("batch together %v in %d entries", together, e.m.seqs())
	}
	if len(e.node().Endpoints) != 6 {
		t.Fatal("the node lacks endpoints")
	}
}

func TestAProfileThatDoesNotCompileKeepsItsEndpointsRecord(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	n := e.m.seqs()

	// The profile now names a service the catalog does not have.
	in.Services = append(in.Services, store.ProfileService{ProfileID: uid(2, 1), ServiceRow: store.ServiceRow{Slug: "nope", Enabled: true, Action: "block"}})
	e.m.mark(a, uuid.New())
	e.settle()
	if e.m.seqs() != n || !e.m.hasAlert(ReasonProfile) {
		t.Fatalf("a failed profile wrote %d entries, alert %v", e.m.seqs()-n, e.m.hasAlert(ReasonProfile))
	}
	if len(e.c.View().Endpoints) != 1 || len(e.m.marks) != 0 {
		t.Fatal("the Endpoint lost its record or the mark stayed")
	}
}

func TestACommitThatFailsIsRepairedByTheNextPass(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.m.failCommit = errBoom
	e.clk.add(time.Second)
	if err := e.c.Tick(e.ctx); err == nil {
		t.Fatal("the failed commit was not reported")
	}
	if e.m.seqs() != 0 || len(e.m.marks) != 1 {
		t.Fatal("a failed commit left a trace")
	}
	e.settle()
	if e.m.seqs() != 1 || len(e.m.marks) != 0 {
		t.Fatalf("after the retry: %d entries, %d marks", e.m.seqs(), len(e.m.marks))
	}
	e.node()
}

func TestAnotherWriterMakesTheCompilerLoadAgain(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	// The log grows behind the compiler's back, as when a stale holder wrote after the lease passed on.
	other := newEnv(t, nil)
	other.m, other.a = e.m, e.a
	other.c = other.compiler(func(c *Config) { c.Holder = "w1" })
	in.endpoint(uid(3, 2), uid(2, 1))
	e.m.mark(a, uuid.New())
	other.settle()
	n := e.m.seqs()
	// The first compiler still thinks the head is the old one: its write is refused and it loads again.
	e.m.mark(a, uuid.New())
	in.endpoint(uid(3, 3), uid(2, 1))
	for i := 0; i < 40; i++ { // the refused write is an error of one tick, and the next ticks load again
		e.clk.add(500 * time.Millisecond)
		_ = e.c.Tick(e.ctx)
	}
	if e.c.View() == nil || e.c.View().Seq != uint64(e.m.seqs()) || e.m.seqs() < n {
		t.Fatalf("the compiler did not catch up: %d of %d", e.c.View().Seq, e.m.seqs())
	}
	if len(e.node().Endpoints) != 3 {
		t.Fatal("the node does not have the three endpoints")
	}
}

func TestSnapshotKeepsTwoAndStartsAFreshCompiler(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SnapshotEvery = 2 })
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	for i := byte(2); i <= 9; i++ {
		in.endpoint(uid(3, i), uid(2, 1))
		e.m.mark(a, uuid.New())
		e.settle()
	}
	if len(e.m.snaps) != 2 {
		t.Fatalf("%d snapshots kept, want 2", len(e.m.snaps))
	}
	for _, s := range e.m.snaps {
		if _, err := e.a.Get(mustHex(s.StoreRef)); err != nil {
			t.Fatalf("a kept snapshot has no file: %v", err)
		}
	}
	// A snapshot that is not a head of the log is still a state: a new compiler loads from the newest and its view equals
	// the first one's.
	want := e.c.View()
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2" })
	e.tick(0)
	got := e.c.View()
	if got.Seq != want.Seq || string(got.Head) != string(want.Head) || len(got.Endpoints) != len(want.Endpoints) {
		t.Fatalf("a compiler started from a snapshot sees seq %d and %d endpoints, want %d and %d", got.Seq, len(got.Endpoints), want.Seq, len(want.Endpoints))
	}
	// A snapshot is what a new node starts from: the state it describes is the node's.
	if len(e.node().Endpoints) != 9 {
		t.Fatal("the node lacks endpoints")
	}
}

func TestFormatBumpWaitsForEveryReport(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.BlobMajor = 2 })
	// The log is at major 1; one node reports 2, one has reported nothing, one is pending with no report.
	nodes := []store.MemberNode{
		{ID: uid(9, 1), Status: "active", Slot: 1, DNSIP: "8.8.8.8", ProxyIP: "8.8.8.8", SPKI: bytes.Repeat([]byte{1}, 32), BlobMajor: 2},
		{ID: uid(9, 2), Status: "active", Slot: 2, DNSIP: "8.8.4.4", ProxyIP: "8.8.4.4", SPKI: bytes.Repeat([]byte{2}, 32), BlobMajor: 0},
	}
	e.m.members = &Membership{Nodes: nodes}
	e.tick(0)
	e.settle()
	if e.c.View().Major != 1 {
		t.Fatal("the major moved before every node reported it")
	}
	for i := 1; i <= e.m.seqs(); i++ {
		if e.entry(i).MinBlobMajor != 1 {
			t.Fatalf("entry %d carries major %d", i, e.entry(i).MinBlobMajor)
		}
	}
	if !e.m.hasAlert(ReasonMajorGate) {
		t.Fatal("the held bump raised no alert")
	}
	// The second node reports it: the bump is a catalog-class entry.
	nodes[1].BlobMajor = 2
	e.m.members = &Membership{Nodes: nodes}
	e.settle()
	last := e.entry(e.m.seqs())
	if last.Class != commonv1.EntryClass_ENTRY_CLASS_CATALOG || last.MinBlobMajor != 2 || e.c.View().Major != 2 {
		t.Fatalf("the bump entry: class %v major %d", last.Class, last.MinBlobMajor)
	}
}

func TestGateCountsAMissingReportAsLatest(t *testing.T) {
	m := &Membership{Nodes: []store.MemberNode{{Status: "active", BlobMajor: 3}, {Status: "pending"}, {Status: "revoked", BlobMajor: 1}}}
	if g := gate(m, 2); g != 2 {
		t.Fatalf("gate %d, want the latest major 2 for the node with no report", g)
	}
	if g := gate(&Membership{}, 4); g != 4 {
		t.Fatalf("gate %d with no node", g)
	}
}

func TestFreeDNSAndCatalogAreEntriesOfTheirOwn(t *testing.T) {
	e := newEnv(t, nil)
	e.tick(0)
	if e.m.seqs() != 1 || e.entry(1).FreeDns == nil || e.entry(1).FreeDns.Version != 1 {
		t.Fatalf("the free DNS value did not reach the log: %d entries", e.m.seqs())
	}
	e.m.freeVer = 2
	e.m.freeQPS = 500
	e.settle()
	if e.m.seqs() != 2 || e.entry(2).FreeDns.Qps != 500 {
		t.Fatal("a new version of the free DNS value was not carried")
	}
	table := []byte("a filter table")
	if err := e.a.Put(sha256Sum(table), table); err != nil {
		t.Fatal(err)
	}
	e.m.catalog = &store.CatalogVersionRow{Version: 7, Key: bytes.Repeat([]byte{4}, 16), Tables: []store.CatalogTableRow{{FilterWire: 1, ModeWire: 2, Hash: sha256Sum(table)}}}
	e.settle()
	if e.m.seqs() != 3 || e.entry(3).Class != commonv1.EntryClass_ENTRY_CLASS_CATALOG || e.entry(3).Catalog.CatalogVersion != 7 {
		t.Fatal("the catalog reference did not make a catalog entry")
	}
	if e.entry(3).Catalog.Tables[0].WireId != 1<<16|2 {
		t.Fatalf("filter table wire id %d", e.entry(3).Catalog.Tables[0].WireId)
	}
	e.node()
}

func TestCatalogAndPolicyAreNeverMerged(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.catalog = &store.CatalogVersionRow{Version: 1, Key: bytes.Repeat([]byte{4}, 16)}
	e.m.mark(a, uuid.New())
	e.tick(0)
	var cat, pol int
	for i := 1; i <= e.m.seqs(); i++ {
		ent := e.entry(i)
		if ent.Class == commonv1.EntryClass_ENTRY_CLASS_CATALOG {
			cat++
			if len(ent.PutEndpoints)+len(ent.PutBlobs) != 0 {
				t.Fatal("a catalog entry carries tenant records")
			}
		} else {
			pol++
			if ent.Catalog != nil {
				t.Fatal("a policy entry carries the catalog")
			}
		}
	}
	if cat != 1 || pol == 0 {
		t.Fatalf("%d catalog and %d policy entries", cat, pol)
	}
}

func TestEndpointRecordFollowsTheCompileMap(t *testing.T) {
	in := newTenantInput()
	in.Row.AdminHold = true
	in.profile(uid(2, 1), "a.example")
	in.profile(uid(2, 2), "b.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	ep := &in.Endpoints[0]
	ep.Profile2ID = uid(2, 2)
	ep.LegacyDNS, ep.ExposeIP, ep.RequireAuthorizedIPs, ep.AuthorizeSecureDNS = true, true, true, true
	ep.AnalyticsLevel, ep.PairVersion = "some", 7
	pfx := netip.MustParsePrefix("203.0.113.0/24")
	in.Authorized = []store.CompilerPrefix{{ID: uid(5, 1), EndpointID: ep.ID, Prefix: pfx}}
	in.Claims = []store.CompilerPrefix{{ID: uid(6, 1), EndpointID: ep.ID, Prefix: netip.MustParsePrefix("198.51.100.0/24")}}
	in.Clients = []store.CompilerClient{{ID: uid(7, 1), EndpointID: ep.ID, Label: "phone", ProfileID: uid(2, 2), Analytics: "none"}}
	in.Windows = []store.WindowRow{{ID: uid(4, 1), EndpointID: ep.ID, Start: 60, End: 120, ProfileID: uid(2, 2)}}
	out := CompileTenant(in, time.Unix(1_800_000_000, 0))
	rec := out.Endpoints[string(ep.ID[:])]
	if rec == nil {
		t.Fatalf("no record: kept %v problems %v", out.Kept, out.Problems)
	}
	if rec.AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED {
		t.Fatal("the tenant's hold is not a hard disable")
	}
	if rec.PairVersion != 7 || len(rec.PairId) != 16 || rec.GrantCap != 4096 || rec.ClientCap != 50 || !rec.LegacyDns || !rec.AuthorizeSecureDns {
		t.Fatalf("flags: %+v", rec)
	}
	if rec.AnalyticsLevel != commonv1.AnalyticsLevel_ANALYTICS_LEVEL_SOME || len(rec.Authorized) != 1 || rec.Authorized[0].Bits != 24 {
		t.Fatalf("access: %+v", rec)
	}
	if len(rec.Clients) != 1 || !rec.Clients[0].HasAnalyticsOverride || rec.Clients[0].Stack == nil {
		t.Fatalf("clients: %+v", rec.Clients)
	}
	if rec.Schedule == nil || len(rec.Schedule.Windows) != 1 || rec.Schedule.Grid[2] != 1 || rec.Schedule.Grid[3] != 1 || rec.Schedule.Grid[4] != 0 {
		t.Fatalf("schedule: %+v", rec.Schedule)
	}
	if len(out.Claims) != 1 {
		t.Fatalf("claims: %d", len(out.Claims))
	}
	if err := wire.ValidateEndpoint(rec); err != nil {
		t.Fatal(err)
	}
	// Without legacy_dns the claim is not compiled.
	ep.LegacyDNS = false
	if len(CompileTenant(in, time.Unix(1_800_000_000, 0)).Claims) != 0 {
		t.Fatal("a claim of an Endpoint without legacy_dns was compiled")
	}
}

func TestAuthorizedPastTheCapIsCutAndReported(t *testing.T) {
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	for i := 0; i < wire.MaxAuthorizedIPs+5; i++ {
		in.Authorized = append(in.Authorized, store.CompilerPrefix{EndpointID: uid(3, 1), Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)})
	}
	out := CompileTenant(in, time.Unix(1_800_000_000, 0))
	if n := len(out.Endpoints[ub(uid(3, 1))].Authorized); n != wire.MaxAuthorizedIPs {
		t.Fatalf("%d prefixes written", n)
	}
	found := false
	for _, p := range out.Problems {
		found = found || p == ReasonAuthorizedCut
	}
	if !found {
		t.Fatal("the cut was not reported")
	}
}

func TestTwoTenantsNeverSeeEachOthersRecords(t *testing.T) {
	e := newEnv(t, nil)
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
	// Tenant A empties itself; B's record, blob and ownership stay.
	ia.Endpoints = nil
	e.m.mark(a, uuid.New())
	e.settle()
	st := e.node()
	if _, ok := st.Endpoints[uid(3, 2)]; !ok || len(st.Endpoints) != 1 {
		t.Fatalf("tenant B's Endpoint was touched: %d records", len(st.Endpoints))
	}
	if e.c.View().owner[ub(uid(3, 2))] != b {
		t.Fatal("tenant B lost its ownership")
	}
}
