// Package compiler turns what the tenants wrote into the ordered config log the nodes apply (docs/specs/p4-nodes.md 6).
//
// One compiler runs at a time, under the lease `compiler` of the worker, and it is the only writer of config_log.seq.
// A pass reads the outbox, the membership of the nodes, the free DNS settings and the catalog reference, and compares
// each with the view it keeps of the log (the latest snapshot plus the entries after it). What differs is merged over a
// debounce of 2 s with a cap of 10 s, compiled in one consistent snapshot per tenant and written as entries.
//
// The compare is by state and not by event: a tenant's whole compile is diffed with the view, so a lost mark, a mark
// that arrives twice and an entry that failed half way are all repaired by the next pass that meets the tenant.
package compiler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/logattr"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Config builds a Compiler.
type Config struct {
	Backend   Backend
	Artifacts Artifacts
	Log       *slog.Logger
	// Holder names this process in the lease.
	Holder string
	Clock  appclock.Func

	// Interval is how often a pass runs (500 ms). Debounce and Cap are the merge window (2 s and 10 s, D31).
	Interval, Debounce, Cap time.Duration
	// LeaseSecs is the lease length, renewed every LeaseRenew.
	LeaseSecs  int
	LeaseRenew time.Duration
	// MaxPerEntry is the records of one entry before a merged pass is cut (20,000, D31).
	MaxPerEntry int
	// MaxEntryBytes is the encoded size of one entry before a pass is cut: what the validator allows less a reserve for
	// the pair table and the header. Tests set it to meet the cut with small records, or above the validator's to meet its
	// refusal.
	MaxEntryBytes int
	// BlobMajor is the format major the blobs of this build have. Tests set it above blob.Major to meet the gate.
	BlobMajor uint32
	// SnapshotEvery and SnapshotAge decide when a snapshot is written: that many entries, or that age with at least one
	// entry (1000 and an hour, D31).
	SnapshotEvery uint64
	SnapshotAge   time.Duration
	// SnapshotBytes is the encoded size of the entries since the last snapshot that also makes one due (64 MiB): a restart
	// reads the tail after the latest snapshot, and a few large entries are as slow to read as many small ones.
	SnapshotBytes uint64
	// Reconcile is how often the tenants are listed to find the ones that vanished (60 s).
	Reconcile time.Duration
	// AlertEvery is the least time between two writes of the same alert.
	AlertEvery time.Duration
}

func (c *Config) defaults() {
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Holder == "" {
		c.Holder = "compiler"
	}
	c.Clock = appclock.Or(c.Clock)
	setD := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	setD(&c.Interval, 500*time.Millisecond)
	setD(&c.Debounce, 2*time.Second)
	setD(&c.Cap, 10*time.Second)
	setD(&c.LeaseRenew, 2*time.Second)
	setD(&c.SnapshotAge, time.Hour)
	setD(&c.Reconcile, time.Minute)
	setD(&c.AlertEvery, 5*time.Minute)
	if c.LeaseSecs <= 0 {
		c.LeaseSecs = 10
	}
	if c.MaxPerEntry <= 0 {
		c.MaxPerEntry = 20000
	}
	if c.MaxEntryBytes <= 0 {
		c.MaxEntryBytes = wire.MaxEntrySize - entryReserve
	}
	if c.BlobMajor == 0 {
		c.BlobMajor = blob.Major
	}
	if c.SnapshotEvery == 0 {
		c.SnapshotEvery = 1000
	}
	if c.SnapshotBytes == 0 {
		c.SnapshotBytes = 64 << 20
	}
}

// Compiler is the loop. Its fields are owned by one goroutine (Run or a test calling Tick).
type Compiler struct {
	cfg Config

	view   *View
	loaded bool
	leased time.Time

	// seen is when each outbox row was first met, by this process's clock.
	seen map[uuid.UUID]time.Time
	// first and last bound the merge window: the first unmerged mark, and the latest new one.
	first, last time.Time
	// full says every tenant is owed a compile: after the lease is taken, so that the view learns who owns what and
	// records of no tenant are found.
	full          bool
	lastReconcile time.Time
	alerted       map[string]time.Time
	lastSnapSeq   uint64
	lastSnapAt    time.Time
	// sinceSnap is the payload bytes of the entries after the latest snapshot.
	sinceSnap uint64
	retryAt   time.Time
	// owed says the last reconcile found a tenant that vanished and no entry has taken its records out yet.
	owed bool
	// retry is the tenants whose compile failed or was skipped, compiled again at retryDue with no mark: a failure
	// that depends on state (a catalog row or a location that arrives later) mends with no event the tenant makes, and
	// its marks are gone with the pass that met the failure. It lives in memory: a new lease starts with a full pass.
	retry    map[uuid.UUID]bool
	retryDue time.Time
	// sweepOwed says a full pass could not take out the records no tenant owns, because a tenant was skipped and its
	// records would have been taken for orphans.
	sweepOwed bool
	// unmet is the tenants of this view that no pass has compiled yet: seeded with every tenant by the full pass and
	// emptied as each compiles. Until it is empty the view does not know who owns what, so a record with no owner may be
	// one of theirs and is not swept, however many passes that meet other tenants go by (W4-r2-1).
	unmet map[uuid.UUID]bool
	// snapRetry is when a failed snapshot may be tried again.
	snapRetry time.Time
	// compile is CompileTenantWith; a test replaces it.
	compile func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output
}

// New builds a Compiler.
func New(cfg Config) (*Compiler, error) {
	if cfg.Backend == nil || cfg.Artifacts == nil {
		return nil, errors.New("compiler: a backend and an artifact store are required")
	}
	cfg.defaults()
	return &Compiler{cfg: cfg, seen: map[uuid.UUID]time.Time{}, alerted: map[string]time.Time{}, retry: map[uuid.UUID]bool{}, compile: CompileTenantWith}, nil
}

// View is the compiler's picture of the log, for tests and the status of a pass. It is nil before the lease is taken.
func (c *Compiler) View() *View { return c.view }

// Run ticks until ctx ends. An error of a tick is logged by class and the next tick tries again.
func (c *Compiler) Run(ctx context.Context) error {
	t := time.NewTicker(c.cfg.Interval)
	defer t.Stop()
	for {
		// A panic costs one pass, not the compiler: the loop goroutine would end and the worker would stay healthy while
		// nothing compiled. The view may be half moved, so it is dropped and loaded again.
		var err error
		if safego.Run(c.cfg.Log, unitPass, func() { err = c.Tick(ctx) }) {
			c.drop()
		} else if err != nil && ctx.Err() == nil {
			c.cfg.Log.Warn("compiler pass failed", logattr.Enum("class", classOf2(err)))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func classOf2(err error) logattr.ErrClass {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return logattr.ErrTimeout
	case errors.Is(err, store.ErrConnection):
		return logattr.ErrConnection
	case errors.Is(err, store.ErrRetry):
		return logattr.ErrRetry
	}
	return logattr.ErrOther
}

// Tick is one pass of the loop (6.1): hold the lease, load the view if it is new, and merge and write what is owed.
func (c *Compiler) Tick(ctx context.Context) error {
	now := c.cfg.Clock()
	if !c.loaded || now.Sub(c.leased) >= c.cfg.LeaseRenew {
		ok, err := c.cfg.Backend.Lease(ctx, c.cfg.Holder, c.cfg.LeaseSecs)
		if err != nil {
			return err
		}
		if !ok {
			c.drop()
			return nil
		}
		c.leased = now
	}
	if !c.loaded {
		if err := c.load(ctx, now); err != nil {
			c.alert(ctx, Alert{Reason: ReasonLoad}, now)
			return err
		}
	}
	if err := c.pass(ctx, now); err != nil {
		if errors.Is(err, ErrHeadMoved) || errors.Is(err, ErrLeaseLost) {
			c.drop()
		}
		return err
	}
	return nil
}

// renew keeps the lease while a long pass works: a first pass compiles every tenant before it writes, and the lease is
// short (6.1 renews it every 2 s). Losing it ends the pass, which Tick turns into a reload.
func (c *Compiler) renew(ctx context.Context) error {
	now := c.cfg.Clock()
	if now.Sub(c.leased) < c.cfg.LeaseRenew {
		return nil
	}
	ok, err := c.cfg.Backend.Lease(ctx, c.cfg.Holder, c.cfg.LeaseSecs)
	if err != nil {
		return err
	}
	if !ok {
		return ErrLeaseLost
	}
	c.leased = now
	return nil
}

// drop forgets everything learned from the log, as when the lease is lost.
func (c *Compiler) drop() {
	c.owed, c.sweepOwed, c.unmet = false, false, nil
	c.retry, c.retryDue = map[uuid.UUID]bool{}, time.Time{}
	c.view, c.loaded = nil, false
	c.seen = map[uuid.UUID]time.Time{}
	c.first, c.last = time.Time{}, time.Time{}
}

// load builds the view: the latest snapshot that reads, plus the entries after it, each checked against the chain.
func (c *Compiler) load(ctx context.Context, now time.Time) error {
	be := c.cfg.Backend
	snaps, err := be.Snapshots(ctx, 2)
	if err != nil {
		return err
	}
	// 1 while the log is empty (SC 8a.11 L5): the major of the build is not the latest entry's until a bump is written.
	view := NewView(1)
	c.lastSnapSeq = 0
	for _, s := range snaps {
		data, err := c.cfg.Artifacts.Get(mustHex(s.StoreRef))
		if err != nil {
			continue // the next older one, or the whole log
		}
		var sn signv1.Snapshot
		if err := proto.Unmarshal(data, &sn); err != nil || sn.Seq != s.Seq || string(sn.EntryHash) != string(s.EntryHash) {
			continue
		}
		view = FromSnapshot(&sn, 1)
		// A snapshot does not carry the format major; the entry it was cut at does, and the log keeps it (pruning stops below the
		// older kept snapshot).
		_ = be.LogAfter(ctx, s.Seq-1, 1, func(r store.LogRow) error {
			if e, err := wire.DecodeEntry(r.Payload); err == nil && r.Seq == s.Seq && e.MinBlobMajor != 0 {
				view.Major = e.MinBlobMajor
			}
			return nil
		})
		c.lastSnapSeq = s.Seq
		break
	}
	// The tail is applied entry by entry as the rows arrive: an entry may be 15 MiB, and 200 of them in one slice would not fit
	// in the worker (W4-r2-9). A batch is its own short transaction, so a long tail is not one transaction of minutes.
	c.sinceSnap = 0
	for {
		n := 0
		err := be.LogAfter(ctx, view.Seq, loadBatch, func(r store.LogRow) error {
			n++
			c.sinceSnap += uint64(len(r.Payload))
			return view.Chain(r.Seq, r.PrevHash, r.EntryHash, r.Payload)
		})
		if err != nil {
			return err
		}
		if n < loadBatch {
			break
		}
	}
	arts, err := be.Artifacts(ctx)
	if err != nil {
		return err
	}
	view.LoadArtifacts(arts)
	c.view, c.loaded, c.full = view, true, true
	c.lastSnapAt = now
	return nil
}

// loadBatch is the entries one read of the tail holds.
const loadBatch = 64

// mustHex reads a store_ref, which is the hex of a 32-byte hash; anything else reads as a hash that has no file.
func mustHex(s string) []byte {
	if len(s) != 64 {
		return nil
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi, lo := unhex(s[2*i]), unhex(s[2*i+1])
		if hi > 15 || lo > 15 {
			return nil
		}
		out[i] = hi<<4 | lo
	}
	return out
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 255
}

// sources are the three values a pass compares with the view besides the outbox.
type sources struct {
	pair    *policyv1.PairTable
	refused bool
	free    *policyv1.FreeDns
	catalog *policyv1.CatalogRef
	// bump is the format major a catalog entry would move the log to, 0 for none.
	bump uint32
}

// readSources reads the membership, the free DNS version and the catalog and says what differs from the view.
func (c *Compiler) readSources(ctx context.Context, now time.Time) (*sources, error) {
	be, v := c.cfg.Backend, c.view
	s := &sources{}
	m, err := be.Membership(ctx)
	if err != nil {
		return nil, err
	}
	s.pair, s.refused = NextPairTable(m, v.Pair)
	if s.refused {
		c.alert(ctx, Alert{Reason: ReasonPairTable}, now)
	}
	en, qps, ver, err := be.FreeDNS(ctx)
	if err != nil {
		return nil, err
	}
	if v.Free == nil || v.Free.Version != ver {
		f := &policyv1.FreeDns{Enabled: en, Qps: uint32(qps), Version: ver}
		if wire.ValidateFreeDns(f) == nil {
			s.free = f
		} else {
			c.alert(ctx, Alert{Reason: ReasonFreeDNS}, now)
		}
	}
	cur, found, err := be.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	if found {
		ref, whole := c.catalogRef(&cur)
		if !whole || wire.ValidateCatalog(ref) != nil {
			c.alert(ctx, Alert{Reason: ReasonCatalog}, now)
		} else if !proto.Equal(ref, v.Catalog) {
			s.catalog = ref
		}
	}
	// A format bump travels as a catalog-class entry (SC 9.6), and only once every non-revoked node has reported it can
	// apply the higher major (the gate). A node with no report counts as the major of the latest entry (L5).
	if c.cfg.BlobMajor > v.Major {
		if gate(m, v.Major) >= c.cfg.BlobMajor {
			s.bump = c.cfg.BlobMajor
		} else {
			c.alert(ctx, Alert{Reason: ReasonMajorGate}, now)
		}
	}
	return s, nil
}

// gate is the lowest major among the non-revoked nodes, a node that has reported none counting as latest, the major of
// the latest entry (SC 8a.11 L5). With no node it is latest: nobody blocks a bump. It is the rule a plain SQL min()
// would break, since min() skips the NULLs.
func gate(m *Membership, latest uint32) uint32 {
	low := ^uint32(0)
	for _, n := range m.Nodes {
		if n.Status == "revoked" {
			continue
		}
		maj := uint32(n.BlobMajor)
		if maj == 0 {
			maj = latest
		}
		low = min(low, maj)
	}
	if low == ^uint32(0) {
		return latest
	}
	return low
}

// catalogRef is the reference of a catalog version: its key, the filter tables ordered by wire id, and their sizes as the
// store knows them. whole is false when a table the version names has no file in the store: a reference to it would send
// every node to fetch what the hub cannot serve, so the one in force stands until the file is there.
func (c *Compiler) catalogRef(cur *store.CatalogVersionRow) (ref *policyv1.CatalogRef, whole bool) {
	ref = &policyv1.CatalogRef{CatalogVersion: cur.Version, Key: cur.Key, SysnamesVersion: cur.SysnamesVersion}
	whole = true
	for _, t := range cur.Tables {
		size := c.cfg.Artifacts.Size(t.Hash)
		if size < 0 {
			whole, size = false, 0
		}
		ref.Tables = append(ref.Tables, &policyv1.TableRef{WireId: uint32(t.FilterWire)<<16 | uint32(t.ModeWire), Kind: policyv1.TableKind_TABLE_KIND_FILTER,
			Hash: t.Hash, Size: uint64(size)})
	}
	sort.Slice(ref.Tables, func(i, j int) bool { return ref.Tables[i].WireId < ref.Tables[j].WireId })
	return ref, whole
}

// differs says whether the sources hold anything an entry would carry.
func (s *sources) differs() bool {
	return s.pair != nil || s.free != nil || s.catalog != nil || s.bump != 0
}

// pass is one turn of the merge window. It writes nothing until the window ends.
func (c *Compiler) pass(ctx context.Context, now time.Time) error {
	if now.Before(c.retryAt) {
		return nil
	}
	be := c.cfg.Backend
	marks, err := be.Marks(ctx, 5000)
	if err != nil {
		return err
	}
	fresh := false
	live := make(map[uuid.UUID]time.Time, len(marks))
	for _, m := range marks {
		t, ok := c.seen[m.ID]
		if !ok {
			t, fresh = now, true
		}
		live[m.ID] = t
	}
	c.seen = live
	src, err := c.readSources(ctx, now)
	if err != nil {
		return err
	}
	vanished := c.owed
	if now.Sub(c.lastReconcile) >= c.cfg.Reconcile && !c.full {
		ids, err := be.Tenants(ctx)
		if err != nil {
			return err
		}
		c.lastReconcile = now
		c.owed = c.owed || len(c.vanishedTenants(ids)) != 0
		vanished = c.owed
	}
	retryNow := len(c.retry) > 0 && !now.Before(c.retryDue)
	if len(marks) == 0 && !c.full && !src.differs() && !vanished && !retryNow {
		c.first, c.last = time.Time{}, time.Time{}
		// The hour of a snapshot runs with the clock and not with the writes (6.5).
		return c.snapshotIfDue(ctx, now)
	}
	if c.first.IsZero() {
		c.first, c.last = now, now
	} else if fresh {
		c.last = now
	}
	// A compiler that has just taken the lease writes at once: the window is for merging bursts of marks, and a full
	// pass is not one.
	if !c.full && now.Sub(c.last) < c.cfg.Debounce && now.Sub(c.first) < c.cfg.Cap {
		return nil
	}
	if err := c.fire(ctx, now); err != nil {
		c.retryAt = now.Add(c.cfg.Debounce)
		return err
	}
	c.first, c.last = time.Time{}, time.Time{}
	if err := c.snapshotIfDue(ctx, now); err != nil {
		return err
	}
	return nil
}

// vanishedTenants lists the tenants the view has records for that no longer exist.
func (c *Compiler) vanishedTenants(ids []uuid.UUID) []uuid.UUID {
	alive := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		alive[id] = true
	}
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, t := range c.view.owner {
		if !alive[t] && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// emptyOutput is the output of a tenant that is gone: nothing it owned stays.
func emptyOutput() *Output {
	return &Output{Endpoints: map[string]*policyv1.EndpointRecord{}, Claims: map[string]*policyv1.ClaimRecord{}, Blobs: map[string]*Profile{}, Kept: map[string]bool{}}
}

// transient says an error is the database's and not the tenant's: the whole pass stops and tries again, since every
// tenant would meet the same.
func transient(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, store.ErrConnection) || errors.Is(err, store.ErrRetry) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// compileOne reads and compiles one tenant. A tenant whose read fails for its own reasons, or whose compile panics, is
// skipped (nil output and nil error) and not allowed to stop the others: one poison tenant would otherwise hold back every
// change, revocation and snapshot of the fleet. The error is for what stops the pass.
func (c *Compiler) compileOne(ctx context.Context, id uuid.UUID, alive bool, now time.Time) (*Output, error) {
	if !alive {
		return emptyOutput(), nil
	}
	v := c.view
	var (
		out   *Output
		found bool
		rerr  error
	)
	// The compile runs inside the read snapshot, which reads the rules a profile at a time. A panic unwinds through the
	// transaction, which rolls back.
	panicked := safego.Run(c.cfg.Log, unitTenant, func() {
		out, found, rerr = c.cfg.Backend.Tenant(ctx, id, func(in *TenantInput) *Output {
			return c.compile(in, now, func(k string) *policyv1.EndpointRecord { return v.Endpoints[k] })
		})
	})
	if rerr == nil && out != nil {
		rerr = out.readErr
	}
	switch {
	case panicked:
		return nil, nil
	case rerr != nil:
		if transient(ctx, rerr) {
			return nil, rerr
		}
		return nil, nil
	case !found:
		return emptyOutput(), nil
	}
	return out, nil
}

// retriable says a problem is a failure to compile and not a fact about the data: it may mend with no event the tenant makes.
func retriable(r Reason) bool {
	return r == ReasonProfile || r == ReasonSchedule || r == ReasonRecordInvalid
}

// fire compiles what is owed and writes it.
func (c *Compiler) fire(ctx context.Context, now time.Time) error {
	be, v := c.cfg.Backend, c.view
	marks, err := be.Marks(ctx, 5000)
	if err != nil {
		return err
	}
	// Tenants to compile: those with a mark, every tenant on a full pass, and the ones whose last compile failed once
	// their time has come.
	tenants := map[uuid.UUID]bool{}
	for _, m := range marks {
		tenants[m.Tenant] = true
	}
	full := c.full
	retryNow := len(c.retry) > 0 && !now.Before(c.retryDue)
	if retryNow {
		for t := range c.retry {
			tenants[t] = true
		}
	}
	ids, err := be.Tenants(ctx)
	if err != nil {
		return err
	}
	c.lastReconcile = now
	if full {
		for _, id := range ids {
			tenants[id] = true
		}
	}
	alive := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		alive[id] = true
	}
	for _, t := range c.vanishedTenants(ids) {
		tenants[t] = true
	}

	byOwner := map[uuid.UUID][]string{}
	for k := range v.Endpoints {
		if t, ok := v.owner[k]; ok {
			byOwner[t] = append(byOwner[t], k)
		}
	}
	claimsOf := claimIndex(v)
	// A batch id shared by marks of several tenants (a sweep that walks them) keeps those tenants in one entry: the
	// tenants of a batch are joined, and a tenant stands for the first one of its set.
	rep := map[uuid.UUID]uuid.UUID{}
	find := func(t uuid.UUID) uuid.UUID {
		for {
			p, ok := rep[t]
			if !ok || p == t {
				return t
			}
			t = p
		}
	}
	first := map[uuid.UUID]uuid.UUID{}
	for _, m := range marks {
		f, ok := first[m.Batch]
		if !ok {
			first[m.Batch] = m.Tenant
			continue
		}
		if a, b := find(f), find(m.Tenant); a != b {
			rep[b] = a
		}
	}

	if full {
		c.unmet = make(map[uuid.UUID]bool, len(ids))
		for _, id := range ids {
			c.unmet[id] = true
		}
	}
	var diffs []*diff
	var problems []Alert
	failed := map[uuid.UUID]bool{}
	for _, id := range sortedIDs(tenants) {
		if err := c.renew(ctx); err != nil {
			return err
		}
		out, err := c.compileOne(ctx, id, alive[id], now)
		if err != nil {
			return err
		}
		if out == nil {
			// Its marks go with the pass, as every tenant's do, and the retry set brings it back.
			failed[id] = true
			problems = append(problems, Alert{Reason: ReasonProfile, Tenant: id})
			continue
		}
		delete(c.unmet, id)
		if full {
			// The row of a bound blob says the nodes may fetch it, not that the file is still there (a restored
			// database, a volume that lost a directory entry). The full pass has every compiled blob in hand.
			for _, h := range sortedKeys(out.Blobs) {
				if p := out.Blobs[h]; p != nil {
					if err := c.cfg.Artifacts.Ensure([]byte(h), p.Bytes); err != nil {
						return err
					}
				}
			}
		}
		sort.Strings(byOwner[id])
		d := diffTenant(v, id, out, byOwner[id], claimsOf)
		diffs = append(diffs, d)
		for _, r := range out.Problems {
			problems = append(problems, Alert{Reason: r, Tenant: id})
			if retriable(r) {
				failed[id] = true
			}
		}
	}
	// A tenant that was skipped has no owner in a view that just started: its records would be taken for orphans. The sweep
	// waits until every tenant of the view has been compiled once, whichever pass that is: a pass that meets only other tenants
	// (a mark, a pair table, free DNS) must not run it while this one is still unowned (W4-r2-1, W4-r2-6).
	unmet := false
	for t := range c.unmet {
		if alive[t] {
			unmet = true
		} else {
			delete(c.unmet, t)
		}
	}
	if (full || c.sweepOwed) && !unmet {
		if o := orphans(v); o.records() != 0 {
			diffs = append(diffs, o)
			problems = append(problems, Alert{Reason: ReasonOrphanSweep})
		}
	}

	// The units: tenants of one batch group are one unit.
	units := map[uuid.UUID][]*diff{}
	var order []uuid.UUID
	for _, d := range diffs {
		key := uuid.Nil
		if len(d.tenants) == 1 {
			key = find(d.tenants[0])
		} else {
			key = uuid.New() // orphans: their own unit
		}
		if _, ok := units[key]; !ok {
			order = append(order, key)
		}
		units[key] = append(units[key], d)
	}
	var merged []*diff
	for _, k := range order {
		merged = append(merged, merge(v, units[k]))
	}
	chunks, oversize := pack(v, merged, limits{count: c.cfg.MaxPerEntry, hard: wire.MaxRecordsPerEntry, bytes: c.cfg.MaxEntryBytes})
	if oversize {
		problems = append(problems, Alert{Reason: ReasonRecordCap})
	}

	src, err := c.readSources(ctx, now)
	if err != nil {
		return err
	}
	if len(chunks) == 0 && (src.pair != nil || src.free != nil) {
		chunks = append(chunks, newChunk(v))
	}
	if len(chunks) != 0 {
		chunks[0].pair, chunks[0].free = src.pair, src.free
	}
	// A catalog entry is its own and never merged with a policy one (6.3). The policy entries go first: they are not held
	// behind a canary.
	if src.catalog != nil || src.bump != 0 {
		cat := newChunk(v)
		cat.class, cat.catalog, cat.major = commonv1.EntryClass_ENTRY_CLASS_CATALOG, src.catalog, src.bump
		chunks = append(chunks, cat)
	}
	outbox := outboxIDs(marks)
	for i, ch := range chunks {
		var ids []uuid.UUID
		if i == len(chunks)-1 {
			ids = outbox
		}
		if err := c.write(ctx, ch, now, ids); err != nil {
			return err
		}
	}
	if len(chunks) == 0 && len(outbox) != 0 {
		if err := c.renew(ctx); err != nil {
			return err
		}
		if err := be.DeleteMarks(ctx, outbox, c.fence()); err != nil {
			return err
		}
	}
	if full {
		c.full = false
	}
	c.sweepOwed = (full || c.sweepOwed) && unmet
	c.owed = false
	// The retry set keeps the tenants this pass did not meet and adds the ones that failed in it.
	next := map[uuid.UUID]bool{}
	for t := range c.retry {
		if !tenants[t] {
			next[t] = true
		}
	}
	for t := range failed {
		next[t] = true
	}
	switch {
	case len(next) == 0:
		c.retryDue = time.Time{}
	case retryNow || c.retryDue.IsZero():
		c.retryDue = now.Add(c.cfg.Reconcile)
	}
	c.retry = next
	for _, a := range problems {
		c.alert(ctx, a, now)
	}
	return nil
}

// fence is what a write that is not an entry carries, so the database refuses it when this compiler is no longer the writer
// or the log is not where the view says (PS 10).
func (c *Compiler) fence() Fence {
	return Fence{Holder: c.cfg.Holder, Seq: c.view.Seq, Head: c.view.Head}
}

func sortedIDs(m map[uuid.UUID]bool) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

// write chains one chunk, puts its files in the store, commits it and moves the view. An entry the validator refuses is
// halved and each half written, so a chunk that the estimate let through does not stop the compiler for every tenant; a
// single record that is still refused is left out with an alert.
func (c *Compiler) write(ctx context.Context, ch *chunk, now time.Time, outbox []uuid.UUID) error {
	v := c.view
	major := v.Major
	if ch.major != 0 {
		major = ch.major
	}
	b, err := build(v, ch, now, major)
	if err != nil {
		c.alert(ctx, Alert{Reason: ReasonEntryTooLarge}, now)
		if x, y, ok := split(ch); ok {
			if err := c.write(ctx, x, now, nil); err != nil {
				return err
			}
			return c.write(ctx, y, now, outbox)
		}
		if ch.n == 0 || ch.pair != nil || ch.free != nil || ch.catalog != nil || ch.major != 0 {
			return err // what the entry carries besides records cannot be left out
		}
		if len(outbox) != 0 {
			if err := c.renew(ctx); err != nil {
				return err
			}
			return c.cfg.Backend.DeleteMarks(ctx, outbox, c.fence())
		}
		return nil
	}
	// Every blob a record binds is in the store before the entry that names it is visible. The files are written first,
	// outside the transaction: thousands of fsyncs under the log lock would outlast the idle and transaction timeouts of the
	// role and hold up the pruning and the next pass (W4-r2-2). They are put again inside the commit, after the lock is
	// held, which costs a stat of each file that is there and writes only one the collector deleted in between: it deletes
	// under the same lock, so a file put before the lock could be gone by the time the row that binds it is written.
	files := func() error {
		for _, h := range sortedKeys(ch.blobs) {
			if p := ch.blobs[h]; p != nil {
				if err := c.cfg.Artifacts.Put([]byte(h), p.Bytes); err != nil {
					return err
				}
			}
		}
		return nil
	}
	// A compiler that is no longer the writer finds out before it writes a file, so a refused entry leaves none behind
	// (W4-r1-17); the commit asks again under the lock.
	if err := c.renew(ctx); err != nil {
		return err
	}
	if err := c.cfg.Backend.Check(ctx, c.fence()); err != nil {
		return err
	}
	if err := files(); err != nil {
		return err
	}
	// The files and the compile before them can outlast the lease (10 s); the commit refuses a lease that has run out, and
	// a lease nobody else took is simply taken again (W4-r2-8).
	if err := c.renew(ctx); err != nil {
		return err
	}
	err = c.cfg.Backend.Commit(ctx, &Commit{Seq: b.entry.Seq, Class: classOf(b.entry.Class), PrevHash: v.Head, EntryHash: b.hash,
		Payload: b.payload, Put: b.put, GC: b.gc, Outbox: outbox, Holder: c.cfg.Holder, Files: files})
	if err != nil {
		if !errors.Is(err, ErrHeadMoved) && !errors.Is(err, ErrLeaseLost) {
			c.alert(ctx, Alert{Reason: ReasonCommit}, now)
		}
		return err
	}
	// The view takes the entry as the nodes decode it, so what it holds is what they hold.
	e, err := wire.DecodeEntry(b.payload)
	if err != nil {
		return err
	}
	v.Apply(e, b.hash)
	c.sinceSnap += uint64(len(b.payload))
	for _, row := range b.put {
		if bi := v.blobs[string(row.Hash)]; bi != nil {
			bi.firstSeq = row.FirstSeq
		}
	}
	return nil
}

// snapshotIfDue writes a snapshot of the view when 1000 entries or an hour with at least one entry have passed, keeps
// the two newest and deletes the older ones with their files (6.5). A failure waits a cap before the next try, so a store
// that is full does not make every pass marshal the whole view again.
func (c *Compiler) snapshotIfDue(ctx context.Context, now time.Time) error {
	v := c.view
	if v.Seq == c.lastSnapSeq || now.Before(c.snapRetry) {
		return nil
	}
	if v.Seq-c.lastSnapSeq < c.cfg.SnapshotEvery && now.Sub(c.lastSnapAt) < c.cfg.SnapshotAge && c.sinceSnap < c.cfg.SnapshotBytes {
		return nil
	}
	if err := c.Snapshot(ctx, now); err != nil {
		c.snapRetry = now.Add(c.cfg.Cap)
		return err
	}
	return nil
}

// Snapshot writes one now.
func (c *Compiler) Snapshot(ctx context.Context, now time.Time) error {
	v, be := c.view, c.cfg.Backend
	data, err := MarshalSnapshot(v.Snapshot())
	if err != nil {
		return err
	}
	h := sha256Sum(data)
	if err := c.cfg.Artifacts.Put(h, data); err != nil {
		return err
	}
	have, err := be.Snapshots(ctx, 100)
	if err != nil {
		return err
	}
	if err := c.renew(ctx); err != nil {
		return err
	}
	// Keep this one and the newest other: two (D31).
	var drop []uint64
	var dropRefs []string
	kept := 1
	for _, s := range have {
		if s.Seq == v.Seq {
			continue
		}
		if kept < 2 {
			kept++
			continue
		}
		drop = append(drop, s.Seq)
		dropRefs = append(dropRefs, s.StoreRef)
	}
	if err := be.PutSnapshot(ctx, store.SnapshotRow{Seq: v.Seq, EntryHash: v.Head, StoreRef: hexOf(h)}, drop, c.cfg.Holder); err != nil {
		return err
	}
	for _, ref := range dropRefs {
		if b := mustHex(ref); b != nil && ref != hexOf(h) {
			_ = c.cfg.Artifacts.Delete(b) // a file that stays is only space; the row is gone
		}
	}
	c.lastSnapSeq, c.lastSnapAt, c.sinceSnap = v.Seq, now, 0
	return nil
}

// alert raises an alert at most once an AlertEvery for the same reason and tenant: the store dedupes while one is open,
// and this keeps a refusal that lasts from opening a transaction every pass.
func (c *Compiler) alert(ctx context.Context, a Alert, now time.Time) {
	k := a.key().String()
	if t, ok := c.alerted[k]; ok && now.Sub(t) < c.cfg.AlertEvery {
		return
	}
	c.alerted[k] = now
	if err := c.cfg.Backend.Alert(ctx, a); err != nil {
		c.cfg.Log.Warn("compiler alert not written", logattr.Enum("reason", a.Reason))
	}
}
