package compiler

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/quarantine"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// memBackend is the database of the compiler in memory: the same contract as DB, so the loop is judged without a
// container. It keeps what the real tables keep: the outbox, the log, the artifacts and snapshots rows, the alerts.
type memBackend struct {
	mu sync.Mutex

	holder  string
	tenants map[uuid.UUID]*TenantInput
	marks   []store.OutboxMark
	members *Membership
	freeVer uint64
	freeOn  bool
	freeQPS int
	catalog *store.CatalogVersionRow

	log    []store.LogRow
	arts   map[string]artifactRow
	snaps  []store.SnapshotRow
	alerts []Alert

	// failCommit makes the next Commit fail with this error, once.
	failCommit error
	// failSnap makes every PutSnapshot fail with this error while it is set; snaps counts the attempts.
	failSnap  error
	snapTries int
	reads     int
	// tenantErr makes the read of one tenant fail with an error of its own.
	tenantErr map[uuid.UUID]error
	// now, when set, makes the lease run out as the database's does: a write after leaseUntil is refused with ErrLeaseLost
	// unless the holder took the lease again.
	now        func() time.Time
	leaseUntil time.Time
	// rulesErr makes the read of one tenant's rules fail after its profiles are known.
	rulesErr map[uuid.UUID]error
	// logCalls counts the calls of LogAfter.
	logCalls int
}

func newMem() *memBackend {
	return &memBackend{tenants: map[uuid.UUID]*TenantInput{}, members: &Membership{}, freeVer: 1, freeOn: true, freeQPS: 1000, arts: map[string]artifactRow{}}
}

func (m *memBackend) Lease(_ context.Context, holder string, secs int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.holder != "" && m.holder != holder && (m.now == nil || m.now().Before(m.leaseUntil)) {
		return false, nil
	}
	m.holder = holder
	if m.now != nil {
		m.leaseUntil = m.now().Add(time.Duration(secs) * time.Second)
	}
	return true, nil
}

// leaseHeld is the check of CompilerLeaseHeld: the holder's, and not run out.
func (m *memBackend) leaseHeld(holder string) bool {
	return m.holder == holder && (m.now == nil || m.now().Before(m.leaseUntil))
}

func (m *memBackend) Marks(_ context.Context, limit int) ([]store.OutboxMark, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]store.OutboxMark(nil), m.marks...)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// fenced is the check of DB.fence: the lease is the holder's and the log's head is where the writer thinks.
func (m *memBackend) fenced(holder string, seq uint64, head []byte) error {
	if !m.leaseHeld(holder) {
		return ErrLeaseLost
	}
	if uint64(len(m.log)) != seq || (seq != 0 && string(m.log[seq-1].EntryHash) != string(head)) {
		return ErrHeadMoved
	}
	return nil
}

func (m *memBackend) Check(_ context.Context, f Fence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fenced(f.Holder, f.Seq, f.Head)
}

func (m *memBackend) DeleteMarks(_ context.Context, ids []uuid.UUID, f Fence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fenced(f.Holder, f.Seq, f.Head); err != nil {
		return err
	}
	m.dropMarks(ids)
	return nil
}

func (m *memBackend) dropMarks(ids []uuid.UUID) {
	gone := map[uuid.UUID]bool{}
	for _, id := range ids {
		gone[id] = true
	}
	kept := m.marks[:0]
	for _, k := range m.marks {
		if !gone[k.ID] {
			kept = append(kept, k)
		}
	}
	m.marks = kept
}

func (m *memBackend) Tenants(context.Context) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []uuid.UUID
	for id := range m.tenants {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i][:]) < string(out[j][:]) })
	return out, nil
}

func (m *memBackend) Tenant(_ context.Context, id uuid.UUID, compile func(*TenantInput) *Output) (*Output, bool, error) {
	m.mu.Lock()
	m.reads++
	if err := m.tenantErr[id]; err != nil {
		m.mu.Unlock()
		return nil, false, err
	}
	in, ok := m.tenants[id]
	rerr := m.rulesErr[id]
	m.mu.Unlock()
	if !ok {
		return nil, false, nil
	}
	// The compile runs outside the lock, as it runs inside a transaction and not inside the database's own lock.
	if rerr != nil {
		cp := *in
		cp.RulesOf = func(uuid.UUID) ([]store.RuleRow, error) { return nil, rerr }
		in = &cp
	}
	return compile(in), true, nil
}

func (m *memBackend) Membership(context.Context) (*Membership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.members, nil
}

func (m *memBackend) FreeDNS(context.Context) (bool, int, uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.freeOn, m.freeQPS, m.freeVer, nil
}

func (m *memBackend) Catalog(context.Context) (store.CatalogVersionRow, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.catalog == nil {
		return store.CatalogVersionRow{}, false, nil
	}
	return *m.catalog, true, nil
}

func (m *memBackend) Snapshots(_ context.Context, limit int) ([]store.SnapshotRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]store.SnapshotRow(nil), m.snaps...)
	sort.Slice(out, func(i, j int) bool { return out[i].Seq > out[j].Seq })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memBackend) LogAfter(_ context.Context, seq uint64, limit int, each func(store.LogRow) error) error {
	m.mu.Lock()
	m.logCalls++
	var out []store.LogRow
	for _, r := range m.log {
		if r.Seq > seq && len(out) < limit {
			out = append(out, r)
		}
	}
	m.mu.Unlock()
	for _, r := range out {
		if err := each(r); err != nil {
			return err
		}
	}
	return nil
}

func (m *memBackend) Artifacts(context.Context) ([]artifactRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []artifactRow
	for _, a := range m.arts {
		out = append(out, a)
	}
	return out, nil
}

func (m *memBackend) Commit(_ context.Context, c *Commit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failCommit != nil {
		err := m.failCommit
		m.failCommit = nil
		return err
	}
	if !m.leaseHeld(c.Holder) {
		return ErrLeaseLost
	}
	if uint64(len(m.log))+1 != c.Seq {
		return ErrHeadMoved
	}
	if len(m.log) > 0 && string(m.log[len(m.log)-1].EntryHash) != string(c.PrevHash) {
		return ErrHeadMoved
	}
	if c.Files != nil {
		if err := c.Files(); err != nil {
			return err
		}
	}
	m.log = append(m.log, store.LogRow{Seq: c.Seq, Class: c.Class, PrevHash: c.PrevHash, EntryHash: c.EntryHash, Payload: c.Payload})
	for _, a := range c.Put {
		a.GCAfter = 0
		m.arts[string(a.Hash)] = a
	}
	for _, h := range c.GC {
		if a, ok := m.arts[string(h)]; ok && a.GCAfter == 0 {
			a.GCAfter = c.Seq
			m.arts[string(h)] = a
		}
	}
	m.dropMarks(c.Outbox)
	return nil
}

func (m *memBackend) PutSnapshot(_ context.Context, s store.SnapshotRow, drop []uint64, holder string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapTries++
	if m.failSnap != nil {
		return m.failSnap
	}
	if err := m.fenced(holder, s.Seq, s.EntryHash); err != nil {
		return err
	}
	m.snaps = append(m.snaps, s)
	gone := map[uint64]bool{}
	for _, d := range drop {
		gone[d] = true
	}
	kept := m.snaps[:0]
	for _, r := range m.snaps {
		if !gone[r.Seq] {
			kept = append(kept, r)
		}
	}
	m.snaps = kept
	return nil
}

func (m *memBackend) Alert(_ context.Context, a Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, a)
	return nil
}

// mark adds an outbox row for a tenant.
func (m *memBackend) mark(tenant uuid.UUID, batch uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.marks = append(m.marks, store.OutboxMark{Tenant: tenant, ID: uuid.New(), Aggregate: "endpoint_set", Subject: tenant, Batch: batch})
}

func (m *memBackend) hasAlert(r Reason) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.alerts {
		if a.Reason == r {
			return true
		}
	}
	return false
}

func (m *memBackend) seqs() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.log)
}

// ---------------------------------------------------------------------------
// The node, as the judge: shared/quarantine applies the stored entries with a fetcher over the artifact store.

type storeFetcher struct{ a Artifacts }

func (f storeFetcher) Fetch(hash [32]byte, _ policyv1.BlobKind, _ uint64) ([]byte, bool) {
	b, err := f.a.Get(hash[:])
	return b, err == nil
}

// applyAll applies the log to a fresh node state and fails the test on any refusal, quarantine or missing blob.
func applyAll(t *testing.T, m *memBackend, a Artifacts) *quarantine.State {
	t.Helper()
	st := quarantine.NewState()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.log {
		rep := quarantine.Apply(st, r.Payload, storeFetcher{a})
		if rep.Entry != nil || !rep.Advanced || len(rep.Quarantined) != 0 || len(rep.Failed) != 0 || len(rep.Missing) != 0 || len(rep.Degraded) != 0 {
			t.Fatalf("the node refused entry %d: %+v", r.Seq, rep)
		}
	}
	return st
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

var errBoom = errors.New("boom")
