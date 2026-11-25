package compiler

import (
	"bytes"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Tests of review round 1 of package W4 (the compiler). Each names the finding it closes.

// breakProfile makes the profile name a service the catalog does not have, so it no longer compiles.
func breakProfile(in *TenantInput, pid uuid.UUID) {
	in.Services = append(in.Services, store.ProfileService{ProfileID: pid, ServiceRow: store.ServiceRow{Slug: "nope", Enabled: true, Action: "block"}})
}

func mendProfile(in *TenantInput) { in.Services = nil }

func (e *env) alertFor(r Reason, tenant uuid.UUID) bool {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	for _, a := range e.m.alerts {
		if a.Reason == r && a.Tenant == tenant {
			return true
		}
	}
	return false
}

// bigTenant is a tenant whose records together are larger than one entry may be: 20 Endpoints of 10,000 clients, each client
// with a stack of its own, about 20 MB of records against the 16 MiB of wire.MaxEntrySize.
func bigTenant() *TenantInput {
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.profile(uid(2, 2), "b.example")
	for i := byte(1); i <= 20; i++ {
		in.endpoint(uid(3, i), uid(2, 1))
		for j := 0; j < wire.MaxClientsPerEP; j++ {
			in.Clients = append(in.Clients, store.CompilerClient{ID: uuid.UUID{0: 0xC0, 14: byte(j >> 8), 15: byte(j)}, EndpointID: uid(3, i),
				Label: "client-" + string(rune('a'+i)) + "-" + uuid.UUID{14: byte(j >> 8), 15: byte(j)}.String(), ProfileID: uid(2, 2)})
		}
	}
	return in
}

// W4-r1-1, W4-r1-11: an entry is cut by its bytes too, so tenants whose records together pass 16 MiB do not stop the compiler.
func TestAnEntryIsCutByItsBytesAndTheNodeAppliesEveryPart(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	e.m.tenants[a] = bigTenant()
	e.m.mark(a, uuid.New())
	e.tick(0)
	if e.m.seqs() < 2 || len(e.m.marks) != 0 {
		t.Fatalf("%d entries and %d marks: the oversize unit was not cut", e.m.seqs(), len(e.m.marks))
	}
	for i := 1; i <= e.m.seqs(); i++ {
		if n := len(e.m.log[i-1].Payload); n > wire.MaxEntrySize {
			t.Fatalf("entry %d is %d bytes", i, n)
		}
	}
	if !e.m.hasAlert(ReasonRecordCap) {
		t.Fatal("a unit cut in parts raised no alert")
	}
	if len(e.node().Endpoints) != 20 {
		t.Fatal("the node lacks Endpoints")
	}
}

// W4-r1-1: with the estimate out of the way, the validator's refusal is met and the entry is halved, not retried for ever.
func TestAnEntryTheValidatorRefusesIsHalved(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxEntryBytes = 1 << 30 })
	a := uid(1, 1)
	e.m.tenants[a] = bigTenant()
	e.m.mark(a, uuid.New())
	e.tick(0)
	if e.m.seqs() < 2 || len(e.m.marks) != 0 || !e.m.hasAlert(ReasonEntryTooLarge) {
		t.Fatalf("%d entries, %d marks, alert %v", e.m.seqs(), len(e.m.marks), e.m.hasAlert(ReasonEntryTooLarge))
	}
	if len(e.node().Endpoints) != 20 {
		t.Fatal("the node lacks Endpoints")
	}
}

// W4-r1-1: a delete counts the blobs it may free, so records and del_blobs together stay under the entry's count. Three tenants
// delete two Endpoints each, every one with a blob of its own: a unit weighs 4, and two units do not share an entry of 6.
func TestFreedBlobsCountInTheCut(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxPerEntry = 6 })
	var ins []*TenantInput
	for k := byte(1); k <= 3; k++ {
		in := newTenantInput()
		for i := byte(1); i <= 2; i++ {
			pid, eid := uid(2, k*10+i), uid(3, k*10+i)
			in.profile(pid, "d"+string(rune(48+k))+string(rune(48+i))+".example")
			in.endpoint(eid, pid)
		}
		ins = append(ins, in)
		e.m.tenants[uid(1, k)] = in
		e.m.mark(uid(1, k), uuid.New())
	}
	e.tick(0)
	e.settle()
	first := e.m.seqs()
	for k, in := range ins {
		in.Endpoints = nil
		e.m.mark(uid(1, byte(k+1)), uuid.New())
	}
	e.settle()
	freed := 0
	for i := first + 1; i <= e.m.seqs(); i++ {
		ent := e.entry(i)
		n := len(ent.PutBlobs) + len(ent.DelBlobs) + len(ent.PutEndpoints) + len(ent.DelEndpoints) + len(ent.PutClaims) + len(ent.DelClaims)
		if n > 6 {
			t.Fatalf("entry %d counts %d records and blob names against a cut of 6", i, n)
		}
		freed += len(ent.DelBlobs)
	}
	if e.m.seqs()-first < 2 || freed != 6 || len(e.node().Endpoints) != 0 {
		t.Fatalf("%d entries, %d blobs freed", e.m.seqs()-first, freed)
	}
}

// W4-r1-2, W4-r1-12: a profile that does not compile says nothing about who may query the Endpoint.
func TestAFailingProfileDoesNotFreezeWhoMayQuery(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	ep := &in.Endpoints[0]
	ep.LegacyDNS = true
	in.Claims = []store.CompilerPrefix{{ID: uid(6, 1), EndpointID: ep.ID, Prefix: netip.MustParsePrefix("198.51.100.0/24")}}
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	old := e.c.View().Endpoints[ub(uid(3, 1))]
	if old == nil || len(e.c.View().Claims) != 1 {
		t.Fatalf("the first compile: %v, %d claims", old, len(e.c.View().Claims))
	}

	// The profile stops compiling, and in the same minute the Endpoint is held, its token rotates, an address is
	// authorized and the legacy claim is given up.
	breakProfile(in, uid(2, 1))
	ep.AdminHold = true
	ep.TokenHash = bytes.Repeat([]byte{0x77}, 32)
	ep.RequireAuthorizedIPs = true
	ep.LegacyDNS = false
	in.Authorized = []store.CompilerPrefix{{ID: uid(5, 1), EndpointID: ep.ID, Prefix: netip.MustParsePrefix("203.0.113.0/24")}}
	e.m.mark(a, uuid.New())
	e.settle()
	rec := e.c.View().Endpoints[ub(uid(3, 1))]
	if rec.AdminState != commonv1.AdminState_ADMIN_STATE_HARD_DISABLED {
		t.Fatal("a held Endpoint is still served as enabled")
	}
	if !bytes.Equal(rec.DohTokenHash, bytes.Repeat([]byte{0x77}, 32)) || !rec.RequireAuthorizedIps || len(rec.Authorized) != 1 {
		t.Fatalf("the access fields did not follow the rows: %+v", rec)
	}
	if !proto.Equal(rec.Base, old.Base) {
		t.Fatal("the stack that failed to compile did not stay as the log had it")
	}
	if len(e.c.View().Claims) != 0 {
		t.Fatal("a claim given up outlived its row because a profile did not compile")
	}
	if !e.alertFor(ReasonProfile, a) {
		t.Fatal("the failure raised no alert")
	}
	e.node()
}

// W4-r1-3: a compile that failed is tried again with no new mark, once the state it depends on has come.
func TestAFailedCompileIsTriedAgainWithNoMark(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	breakProfile(in, uid(2, 1))
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	if _, ok := e.c.View().Endpoints[ub(uid(3, 1))]; ok || len(e.m.marks) != 0 {
		t.Fatal("an Endpoint whose profile fails was written, or its mark stayed")
	}
	// The catalog (here: the profile) mends with no event of the tenant.
	mendProfile(in)
	e.settle()
	if _, ok := e.c.View().Endpoints[ub(uid(3, 1))]; ok {
		t.Fatal("tried again before its time")
	}
	e.clk.add(time.Minute)
	e.settle()
	if _, ok := e.c.View().Endpoints[ub(uid(3, 1))]; !ok {
		t.Fatal("the failed tenant was never compiled again")
	}
	e.settle()
	e.clk.add(5 * time.Minute)
	n := e.m.seqs()
	e.settle()
	if e.m.seqs() != n || len(e.c.retry) != 0 {
		t.Fatalf("a tenant that compiles is still retried: %d retries", len(e.c.retry))
	}
}

// W4-r1-4, W4-r1-20: one tenant that panics, or that cannot be read, does not stop the others.
func TestOnePoisonTenantDoesNotStopTheOthers(t *testing.T) {
	for _, name := range []string{"panic", "read"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			a, b := uid(1, 1), uid(1, 2)
			ia, ib := newTenantInput(), newTenantInput()
			ia.profile(uid(2, 1), "a.example")
			ia.endpoint(uid(3, 1), uid(2, 1))
			ib.profile(uid(2, 2), "b.example")
			ib.endpoint(uid(3, 2), uid(2, 2))
			e.m.tenants[a], e.m.tenants[b] = ia, ib
			real := e.c.compile
			if name == "panic" {
				e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
					if in == ia {
						panic("poison")
					}
					return real(in, now, prev)
				}
			} else {
				e.m.tenantErr = map[uuid.UUID]error{a: errBoom}
			}
			e.m.mark(a, uuid.New())
			e.m.mark(b, uuid.New())
			e.tick(0)
			if _, ok := e.c.View().Endpoints[ub(uid(3, 2))]; !ok || len(e.m.marks) != 0 {
				t.Fatal("the healthy tenant waited for the poison one")
			}
			if _, ok := e.c.View().Endpoints[ub(uid(3, 1))]; ok || !e.alertFor(ReasonProfile, a) {
				t.Fatal("the poison tenant was written, or raised no alert")
			}
			e.c.compile = real
			e.m.tenantErr = nil
			e.clk.add(time.Minute)
			e.settle()
			if len(e.node().Endpoints) != 2 {
				t.Fatal("the poison tenant was not compiled again once it could be")
			}
		})
	}
}

// W4-r1-4: an error of the database is not a tenant's: the pass stops, the marks stay and nobody is skipped.
func TestADatabaseErrorStopsThePassAndKeepsTheMarks(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.tenantErr = map[uuid.UUID]error{a: store.ErrConnection}
	e.m.checkErr = store.ErrConnection // the database does not answer the probe either
	e.m.mark(a, uuid.New())
	e.clk.add(time.Second)
	if err := e.c.Tick(e.ctx); err == nil {
		t.Fatal("a lost connection was taken for a poison tenant")
	}
	if len(e.m.marks) != 1 || len(e.c.retry) != 0 {
		t.Fatal("the mark of a tenant that could not be read was consumed")
	}
}

// W4-r1-4: a tenant that was skipped in the full pass has no owner yet, and must not be swept as an orphan.
func TestASkippedTenantIsNotSweptAsAnOrphan(t *testing.T) {
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

	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2" })
	e.m.tenantErr = map[uuid.UUID]error{a: errBoom}
	e.tick(0)
	e.settle()
	if e.m.seqs() != n || len(e.node().Endpoints) != 2 {
		t.Fatalf("a tenant that could not be read was swept: %d new entries", e.m.seqs()-n)
	}
	e.m.tenantErr = nil
	e.clk.add(time.Minute)
	e.settle()
	if e.m.seqs() != n || len(e.node().Endpoints) != 2 {
		t.Fatalf("the tenant's retry changed the log: %d new entries", e.m.seqs()-n)
	}
	if e.c.sweepOwed {
		t.Fatal("the sweep is still owed after every tenant was met")
	}
}

// W4-r1-5: a catalog table with no file in the store is not carried.
func TestACatalogWhoseTableFileIsMissingIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.tick(0)
	n := e.m.seqs()
	e.m.catalog = &store.CatalogVersionRow{Version: 7, Key: bytes.Repeat([]byte{4}, 16), Tables: []store.CatalogTableRow{{FilterWire: 1, ModeWire: 2, Hash: bytes.Repeat([]byte{5}, 32)}}}
	e.settle()
	if e.m.seqs() != n || !e.m.hasAlert(ReasonCatalog) {
		t.Fatalf("a table with no file: %d entries, alert %v", e.m.seqs()-n, e.m.hasAlert(ReasonCatalog))
	}
	table := []byte("a filter table")
	if err := e.a.Put(sha256Sum(table), table); err != nil {
		t.Fatal(err)
	}
	e.m.catalog.Tables[0].Hash = sha256Sum(table)
	e.settle()
	if e.m.seqs() != n+1 || e.entry(n + 1).Catalog.Tables[0].Size != uint64(len(table)) {
		t.Fatal("the catalog was not carried once its file was there")
	}
}

// W4-r1-6: the hour of a snapshot runs while the compiler is idle, and a snapshot that fails waits before the next try.
func TestTheHourOfASnapshotRunsWhileIdle(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	e.settle()
	if len(e.m.snaps) != 0 {
		t.Fatal("a snapshot before its hour")
	}
	e.m.failSnap = errBoom
	e.clk.add(61 * time.Minute)
	for i := 0; i < 10; i++ {
		e.clk.add(500 * time.Millisecond)
		_ = e.c.Tick(e.ctx)
	}
	if e.m.snapTries != 1 {
		t.Fatalf("a failing snapshot was tried %d times in 5 s", e.m.snapTries)
	}
	e.m.failSnap = nil
	e.clk.add(11 * time.Second)
	e.tick(0)
	if len(e.m.snaps) != 1 || e.m.snaps[0].Seq != uint64(e.m.seqs()) {
		t.Fatalf("no snapshot of the idle hour: %d", len(e.m.snaps))
	}
}

// W4-r1-7 is in rollout. W4-r1-8, W4-r1-14: the marks of a pass are never consumed by a compiler that is no longer the writer.
func TestAStaleCompilerCannotConsumeMarks(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.LeaseRenew = time.Hour })
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	e.settle()
	// Another worker took the lease. The tenant's compile equals the view, so the pass would only delete the mark.
	e.m.holder = "w2"
	e.m.mark(a, uuid.New())
	for i := 0; i < 30; i++ {
		e.clk.add(500 * time.Millisecond)
		_ = e.c.Tick(e.ctx)
	}
	if len(e.m.marks) != 1 {
		t.Fatalf("a compiler without the lease consumed the marks: %d left", len(e.m.marks))
	}
}

// W4-r1-14: a pass that outlasts the lease renews it between tenants and stops when it is gone.
func TestALongPassRenewsTheLeaseAndStopsWhenItIsLost(t *testing.T) {
	e := newEnv(t, nil)
	a, b := uid(1, 1), uid(1, 2)
	ia, ib := newTenantInput(), newTenantInput()
	ia.profile(uid(2, 1), "a.example")
	ia.endpoint(uid(3, 1), uid(2, 1))
	ib.profile(uid(2, 2), "b.example")
	ib.endpoint(uid(3, 2), uid(2, 2))
	e.m.tenants[a], e.m.tenants[b] = ia, ib
	real := e.c.compile
	e.c.compile = func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output {
		e.clk.add(3 * time.Second) // each tenant takes longer than the renewal
		e.m.holder = "w2"          // and the lease passes to another worker meanwhile
		return real(in, now, prev)
	}
	e.m.mark(a, uuid.New())
	e.m.mark(b, uuid.New())
	e.clk.add(time.Second)
	if err := e.c.Tick(e.ctx); err == nil {
		t.Fatal("a pass that lost its lease went on")
	}
	if e.m.seqs() != 0 || len(e.m.marks) != 2 {
		t.Fatalf("%d entries written and %d marks left by a pass that lost its lease", e.m.seqs(), len(e.m.marks))
	}
}

// W4-r1-17: a file is written inside the commit, after the fence: a refused entry leaves no file behind.
func TestFilesAreWrittenOnlyOnceTheCommitIsAllowed(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.LeaseRenew = time.Hour })
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.tick(0)
	e.m.holder = "w2"
	in.profile(uid(2, 9), "z.example")
	in.endpoint(uid(3, 9), uid(2, 9))
	e.m.mark(a, uuid.New())
	for i := 0; i < 30; i++ {
		e.clk.add(500 * time.Millisecond)
		_ = e.c.Tick(e.ctx)
	}
	entries, _ := os.ReadDir(e.a.dir)
	// Only the blob of the first, allowed entry is in the store.
	blobs := 0
	for _, f := range entries {
		if len(f.Name()) == 64 {
			blobs++
		}
	}
	if blobs != 1 {
		t.Fatalf("%d files in the store, want the one of the allowed entry", blobs)
	}
}

// W4-r1-13: a claim the tenant gave up while the compiler was down is deleted by the full pass of the next one.
func TestAClaimGivenUpWhileTheCompilerWasDownIsDeleted(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	in.Endpoints[0].LegacyDNS = true
	in.Claims = []store.CompilerPrefix{{ID: uid(6, 1), EndpointID: uid(3, 1), Prefix: netip.MustParsePrefix("198.51.100.0/24")}}
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	if len(e.c.View().Claims) != 1 {
		t.Fatal("no claim in the log")
	}
	// The compiler is gone; the tenant releases the claim (its mark is consumed with the old compiler's pass, or never
	// read), and a new compiler starts.
	in.Claims = nil
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2" })
	e.tick(0)
	e.settle()
	if len(e.c.View().Claims) != 0 {
		t.Fatal("the claim stayed in the log after a restart")
	}
	if len(e.node().Claims) != 0 {
		t.Fatal("the node still holds the claim")
	}
}

// W4-r1-16: the full pass writes again the file of a blob the log binds that the store lost, or holds with wrong bytes.
func TestAFullPassWritesALostBlobFileAgain(t *testing.T) {
	e := newEnv(t, nil)
	a := uid(1, 1)
	in := newTenantInput()
	in.profile(uid(2, 1), "a.example")
	in.endpoint(uid(3, 1), uid(2, 1))
	e.m.tenants[a] = in
	e.m.mark(a, uuid.New())
	e.tick(0)
	h := e.c.View().Endpoints[ub(uid(3, 1))].Base.Profile1Hash
	data, err := e.a.Get(h)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.a.Delete(h); err != nil {
		t.Fatal(err)
	}
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w2" })
	e.tick(0)
	if got, err := e.a.Get(h); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the lost file was not written again: %v", err)
	}
	// A file of the right size and the wrong bytes.
	if err := os.WriteFile(e.a.dir+"/"+hexOf(h), bytes.Repeat([]byte{1}, len(data)), 0o644); err != nil {
		t.Fatal(err)
	}
	e.m.holder = ""
	e.c = e.compiler(func(c *Config) { c.Holder = "w3" })
	e.tick(0)
	if got, err := e.a.Get(h); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("a corrupt file of the right size was kept: %v", err)
	}
}

// W4-r1-15, W4-r1-9: an active node with no key is not written as a revoked one.
func TestAnActiveNodeWithNoKeyIsNotWrittenAsRevoked(t *testing.T) {
	mk := func(slot int, ip string, spki []byte) store.MemberNode {
		return store.MemberNode{ID: uid(9, byte(slot)), Status: "active", Slot: slot, DNSIP: ip, ProxyIP: ip, SPKI: spki}
	}
	n1, n2 := mk(1, "8.8.8.8", bytes.Repeat([]byte{1}, 32)), mk(2, "8.8.4.4", bytes.Repeat([]byte{2}, 32))
	last, refused := NextPairTable(&Membership{Nodes: []store.MemberNode{n1, n2}}, nil)
	if last == nil || refused {
		t.Fatalf("the first table: %+v %v", last, refused)
	}
	n2.SPKI = nil // the column is nullable and nothing ties it to the status
	n3 := mk(3, "1.1.1.1", bytes.Repeat([]byte{3}, 32))
	pt, refused := NextPairTable(&Membership{Nodes: []store.MemberNode{n1, n2, n3}}, last)
	if !refused {
		t.Fatal("an active row with no SPKI was accepted")
	}
	if pt != nil {
		t.Fatalf("a table was written with an empty SPKI for an active node: %+v", pt)
	}
	// A row that is revoked on purpose is written empty as ever.
	n2.Status = "revoked"
	pt, refused = NextPairTable(&Membership{Nodes: []store.MemberNode{n1, n2}}, last)
	if refused || pt == nil || len(pt.Nodes[1].SpkiSha256) != 0 {
		t.Fatalf("the revocation: %+v %v", pt, refused)
	}
}

// W4-r1-19: a tenant's diff reads its own claims, found through the index and not by sorting the fleet's.
func TestClaimIndexHoldsClaimsByEndpoint(t *testing.T) {
	v := NewView(1)
	for i := byte(1); i <= 3; i++ {
		cid, eid := uid(6, i), uid(3, 1+i%2)
		v.Claims[string(cid[:])] = &policyv1.ClaimRecord{ClaimId: cid[:], EndpointId: eid[:]}
	}
	idx := claimIndex(v)
	if len(idx[ub(uid(3, 1))]) != 1 || len(idx[ub(uid(3, 2))]) != 2 {
		t.Fatalf("index: %v", idx)
	}
}
