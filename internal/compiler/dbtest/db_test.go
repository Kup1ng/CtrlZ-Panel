// Package dbtest runs the compiler over a real, migrated database as the role it logs in as. It is a package of its own
// because its TestMain starts a container, which the unit tests of internal/compiler must not need.
package dbtest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
	_ "time/tzdata" // the zone of a seeded Endpoint, in a runner with no zoneinfo

	"github.com/google/uuid"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"

	"github.com/Kup1ng/CtrlZ-Panel/internal/catalogfx"
	"github.com/Kup1ng/CtrlZ-Panel/internal/compiler"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store/catalogtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

type fetcher struct{ a compiler.Artifacts }

func (f fetcher) Fetch(hash [32]byte, _ policyv1.BlobKind, _ uint64) ([]byte, bool) {
	b, err := f.a.Get(hash[:])
	return b, err == nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type world struct {
	ctx  context.Context
	db   *testpg.DB
	A, B catalogtest.SeedIDs
	st   *store.Store
	arts *compiler.DirArtifacts
	clk  *clock
}

func newWorld(t *testing.T) *world {
	t.Helper()
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	db := c.NewDB(ctx, t)
	super, err := db.Super(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(context.Background()) }()
	w := &world{ctx: ctx, db: db, A: catalogtest.NewSeedIDs(1), B: catalogtest.NewSeedIDs(2), clk: &clock{t: time.Unix(1_800_000_000, 0)}}
	if err := catalogtest.SeedGlobal(ctx, super); err != nil {
		t.Fatal(err)
	}
	for _, ids := range []catalogtest.SeedIDs{w.A, w.B} {
		if err := catalogtest.SeedTenant(ctx, super, ids); err != nil {
			t.Fatal(err)
		}
	}
	w.st = db.Store(ctx, t, store.RoleCompiler)
	if w.arts, err = compiler.NewDirArtifacts(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) compiler(t *testing.T, holder string) *compiler.Compiler {
	t.Helper()
	c, err := compiler.New(compiler.Config{Backend: compiler.NewDB(w.st), Artifacts: w.arts, Clock: w.clk.now, Holder: holder})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (w *world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.db.Scan(w.ctx, sql, args, &n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// run ticks across the merge window.
func (w *world) run(t *testing.T, c *compiler.Compiler) {
	t.Helper()
	for i := 0; i < 30; i++ {
		w.clk.t = w.clk.t.Add(500 * time.Millisecond)
		if err := c.Tick(w.ctx); err != nil {
			t.Fatalf("tick: %v", err)
		}
	}
}

// node applies the whole log the way a node does and fails on anything it would set aside.
func (w *world) node(t *testing.T) *quarantine.State {
	t.Helper()
	st := quarantine.NewState()
	var seq uint64
	for {
		var rows []store.LogRow
		if err := w.st.WithGlobal(w.ctx, store.TxOpts{ReadOnly: true}, func(g store.GlobalTx) (err error) {
			rows, err = g.CompilerLogAfter(seq, 100)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			rep := quarantine.Apply(st, r.Payload, fetcher{w.arts})
			if rep.Entry != nil || !rep.Advanced || len(rep.Quarantined) != 0 || len(rep.Failed) != 0 || len(rep.Missing) != 0 {
				t.Fatalf("the node refused entry %d: %+v", r.Seq, rep)
			}
			seq = r.Seq
		}
		if len(rows) < 100 {
			return st
		}
	}
}

func TestTheCompilerWritesWhatTheRealTablesHold(t *testing.T) {
	w := newWorld(t)
	c := w.compiler(t, "w1")
	w.run(t, c)

	if n := w.count(t, `SELECT count(*) FROM ctrlz.config_log`); n == 0 {
		t.Fatal("nothing was written")
	}
	if n := w.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`); n != 0 {
		t.Fatalf("%d outbox rows are left", n)
	}
	st := w.node(t)
	if len(st.Endpoints) != 2 {
		t.Fatalf("the node holds %d endpoints, want the 2 seeded", len(st.Endpoints))
	}
	if len(st.Claims) != 0 {
		t.Fatalf("the seeded Endpoints have no legacy_dns, yet the node holds %d claims", len(st.Claims))
	}
	for id, ep := range st.Endpoints {
		if len(ep.Authorized) != 1 || ep.Schedule == nil || len(ep.Clients) != 1 || ep.Base.Profile2Hash == nil {
			t.Fatalf("endpoint %x: authorized %d, schedule %v, clients %d", id, len(ep.Authorized), ep.Schedule != nil, len(ep.Clients))
		}
	}
	if n := w.count(t, `SELECT count(*) FROM ctrlz.policy_artifacts WHERE gc_after_seq IS NULL`); n < 2 {
		t.Fatalf("%d bound artifacts", n)
	}
	before := w.count(t, `SELECT count(*) FROM ctrlz.config_log`)

	// A second process sees the same log and adds nothing, and a change of tenant A reaches the log without touching B.
	if err := w.db.Exec(w.ctx, `DELETE FROM ctrlz.leases WHERE name = 'compiler'`); err != nil {
		t.Fatal(err)
	}
	c2 := w.compiler(t, "w2")
	w.run(t, c2)
	if n := w.count(t, `SELECT count(*) FROM ctrlz.config_log`); n != before {
		t.Fatalf("a restart wrote %d entries", n-before)
	}
	if err := w.db.Exec(w.ctx, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action) VALUES ($1, $2, 'new.example.test', 'domain', 'block');
INSERT INTO ctrlz.policy_outbox (tenant_id, aggregate_type, aggregate_id, batch_id) VALUES ($1, 'profile', $2, gen_random_uuid())`, w.A.Tenant, w.A.Profile); err != nil {
		t.Fatal(err)
	}
	w.run(t, c2)
	if n := w.count(t, `SELECT count(*) FROM ctrlz.config_log`); n != before+1 {
		t.Fatalf("a change of one profile wrote %d entries, want 1", n-before)
	}
	if n := w.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`); n != 0 {
		t.Fatal("the mark was not deleted")
	}
	st2 := w.node(t)
	if string(st2.Endpoints[w.B.Endpoint].Base.Profile1Hash) != string(st.Endpoints[w.B.Endpoint].Base.Profile1Hash) {
		t.Fatal("tenant B's Endpoint changed with a change of tenant A")
	}
	if string(st2.Endpoints[w.A.Endpoint].Base.Profile1Hash) == string(st.Endpoints[w.A.Endpoint].Base.Profile1Hash) {
		t.Fatal("tenant A's Endpoint did not move to the new blob")
	}

	// The old blob of A is unbound now (only A's seeded profile used it), named once and marked for its collection.
	if n := w.count(t, `SELECT count(*) FROM ctrlz.policy_artifacts WHERE gc_after_seq IS NOT NULL`); n != 1 {
		t.Fatalf("%d artifacts marked for collection, want 1", n)
	}
}

func TestAnEntryThatMeetsAMovedHeadIsRefused(t *testing.T) {
	w := newWorld(t)
	db := compiler.NewDB(w.st)
	if ok, err := db.Lease(w.ctx, "a", 30); err != nil || !ok {
		t.Fatalf("lease: %v %v", ok, err)
	}
	first := &compiler.Commit{Seq: 1, Class: "policy", PrevHash: make([]byte, 32), EntryHash: make([]byte, 32), Payload: []byte{1}, Holder: "a"}
	if err := db.Commit(w.ctx, first); err != nil {
		t.Fatal(err)
	}
	// A second writer that thinks the log is empty is refused, and so is a gap.
	if err := db.Commit(w.ctx, first); !errors.Is(err, compiler.ErrHeadMoved) {
		t.Fatalf("a repeat of seq 1: %v", err)
	}
	gap := &compiler.Commit{Seq: 3, Class: "policy", PrevHash: make([]byte, 32), EntryHash: make([]byte, 32), Payload: []byte{1}, Holder: "a"}
	if err := db.Commit(w.ctx, gap); !errors.Is(err, compiler.ErrHeadMoved) {
		t.Fatalf("a gap: %v", err)
	}
	if n := w.count(t, `SELECT count(*) FROM ctrlz.config_log`); n != 1 {
		t.Fatalf("%d rows in the log", n)
	}
}

// A pass longer than the lease can leave a second worker holding it: every write is fenced by the lease and the head
// (W4-r1-8, W4-r1-14), the marks and the snapshot row included, and the files of an entry are written only after the fence.
func TestAWriteWithoutTheLeaseOrTheHeadIsRefused(t *testing.T) {
	w := newWorld(t)
	db := compiler.NewDB(w.st)
	if ok, err := db.Lease(w.ctx, "a", 30); err != nil || !ok {
		t.Fatalf("lease: %v %v", ok, err)
	}
	wrote := false
	c := &compiler.Commit{Seq: 1, Class: "policy", PrevHash: make([]byte, 32), EntryHash: make([]byte, 32), Payload: []byte{1}, Holder: "b",
		Files: func() error { wrote = true; return nil }}
	if err := db.Commit(w.ctx, c); !errors.Is(err, compiler.ErrLeaseLost) || wrote {
		t.Fatalf("a commit of a holder that has no lease: %v (files written %v)", err, wrote)
	}
	if err := db.DeleteMarks(w.ctx, []uuid.UUID{uuid.New()}, compiler.Fence{Holder: "b", Head: make([]byte, 32)}); !errors.Is(err, compiler.ErrLeaseLost) {
		t.Fatalf("marks of a holder that has no lease: %v", err)
	}
	if err := db.DeleteMarks(w.ctx, nil, compiler.Fence{Holder: "a", Seq: 5, Head: make([]byte, 32)}); !errors.Is(err, compiler.ErrHeadMoved) {
		t.Fatalf("marks of a view that is behind: %v", err)
	}
	if err := db.PutSnapshot(w.ctx, store.SnapshotRow{Seq: 9, EntryHash: make([]byte, 32), StoreRef: "x"}, nil, "a"); !errors.Is(err, compiler.ErrHeadMoved) {
		t.Fatalf("a snapshot of a view that is not the head: %v", err)
	}
	c.Holder = "a"
	if err := db.Commit(w.ctx, c); err != nil || !wrote {
		t.Fatalf("the holder's commit: %v (files written %v)", err, wrote)
	}
}

func TestTheLeaseIsHeldByOneCompilerAtATime(t *testing.T) {
	w := newWorld(t)
	db := compiler.NewDB(w.st)
	if ok, err := db.Lease(w.ctx, "a", 30); err != nil || !ok {
		t.Fatalf("first: %v %v", ok, err)
	}
	if ok, err := db.Lease(w.ctx, "b", 30); err != nil || ok {
		t.Fatalf("second: %v %v", ok, err)
	}
	if ok, err := db.Lease(w.ctx, "a", 30); err != nil || !ok {
		t.Fatalf("the holder renews: %v %v", ok, err)
	}
}

func TestACatalogAndAFreeDNSValueAreCarried(t *testing.T) {
	w := newWorld(t)
	// The table's file is in the store: a reference to one the store lacks is refused (W4-r1-5).
	table := []byte("a filter table")
	sum := sha256.Sum256(table)
	if err := w.arts.Put(sum[:], table); err != nil {
		t.Fatal(err)
	}
	if err := w.db.Exec(w.ctx, `INSERT INTO ctrlz.catalog_versions (version, key, state) VALUES (5, decode(repeat('ab', 16), 'hex'), 'current');
INSERT INTO ctrlz.catalog_filter_table (filter_id, mode, version, hash, store_ref, state) VALUES ('ads-trackers', 'strict', 5, decode('`+hex.EncodeToString(sum[:])+`', 'hex'), 'x', 'current')`); err != nil {
		t.Fatal(err)
	}
	c := w.compiler(t, "w1")
	w.run(t, c)
	v := c.View()
	if v.Catalog == nil || v.Catalog.CatalogVersion != 5 || len(v.Catalog.Tables) != 1 {
		t.Fatalf("catalog in the log: %+v", v.Catalog)
	}
	if v.Free == nil || v.Free.Version == 0 {
		t.Fatalf("free DNS in the log: %+v", v.Free)
	}
	if n := w.count(t, `SELECT count(*) FROM ctrlz.config_log WHERE class = 'catalog'`); n != 1 {
		t.Fatalf("%d catalog entries", n)
	}
}

func TestLoadFixtureMakesACatalogTheCompilerCarries(t *testing.T) {
	w := newWorld(t)
	worker := w.db.Store(w.ctx, t, store.RoleWorker)
	data, err := os.ReadFile("../../../shared/vectors/fixtures/base.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := catalogfx.Load(w.ctx, worker, w.arts, data)
	if err != nil {
		t.Fatal(err)
	}
	// Of the fixture's four filter tables the seed has two: (filter 1, mode 1) and (filter 1, mode 2).
	if res.Version != 1 || res.Tables != 2 || res.Skipped != 2 {
		t.Fatalf("result %+v", res)
	}
	again, err := catalogfx.Load(w.ctx, worker, w.arts, data)
	if err != nil || again.Version != 2 {
		t.Fatalf("second load: %+v %v", again, err)
	}
	if n := w.count(t, `SELECT count(*) FROM ctrlz.catalog_versions WHERE state = 'current'`); n != 1 {
		t.Fatalf("%d current versions after a second load", n)
	}
	c := w.compiler(t, "w1")
	w.run(t, c)
	cat := c.View().Catalog
	if cat == nil || cat.CatalogVersion != 2 || len(cat.Tables) != 2 || cat.Tables[0].Size == 0 {
		t.Fatalf("the catalog in the log: %+v", cat)
	}
}
