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
	// Slice is the time (by Clock) of a pass after which the units that are finished are written and their marks deleted, and
	// the pass goes on with the rest (5 s). Without it nothing of a pass is visible until the last tenant is compiled, and a
	// revocation waits behind every large tenant of the fleet (W4-r3-7).
	Slice time.Duration
	// TenantBlobBytes is the bytes one tenant may cause in TenantBlobWindow (128 MiB in 10 minutes): new blob files, and the
	// encoded records it puts in the log, which fill config_log and every node the way files fill the volume. Past it the tenant is
	// compiled with no new blob (TenantInput.Degraded): what says who may query goes out at once, the rest waits for the window to
	// end, and the others go on (W4-r3-8, W4-r4-2, W4-r4-8).
	TenantBlobBytes  uint64
	TenantBlobWindow time.Duration
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
	setD(&c.Slice, 5*time.Second)
	setD(&c.TenantBlobWindow, 10*time.Minute)
	if c.TenantBlobBytes == 0 {
		c.TenantBlobBytes = 128 << 20
	}
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
	// sinceSnap is the payload bytes of the entries after the latest snapshot, and the bytes of the blob files written since: a
	// tenant that changes blobs under small entries fills the volume as surely as large entries do, and the older blob goes only
	// when two snapshots are newer than its mark (W4-r3-8).
	sinceSnap uint64
	retryAt   time.Time
	// owed says the last reconcile found a tenant that vanished and no entry has taken its records out yet.
	owed bool
	// retry is the tenants whose compile failed or was skipped, compiled again at retryDue with no mark: a failure
	// that depends on state (a catalog row or a location that arrives later) mends with no event the tenant makes, and
	// its marks are gone with the pass that met the failure. It lives in memory: a new lease starts with a full pass.
	retry    map[uuid.UUID]bool
	retryDue time.Time
	// waiting is the tenants that were compiled with no new blob because they were past their budget, with the end of the
	// window they wait for. Like retry it lives in memory: a new lease starts with a full pass (W4-r4-2).
	waiting map[uuid.UUID]time.Time
	// sweepOwed says a full pass could not take out the records no tenant owns, because a tenant was skipped and its
	// records would have been taken for orphans.
	sweepOwed bool
	// unmet is the tenants of this view that no pass has compiled yet: seeded with every tenant by the full pass and
	// emptied as each compiles. Until it is empty the view does not know who owns what, so a record with no owner may be
	// one of theirs and is not swept, however many passes that meet other tenants go by (W4-r2-1).
	unmet map[uuid.UUID]bool
	// snapRetry is when a failed snapshot may be tried again.
	snapRetry time.Time
	// loadRetry is when a failed load may be tried again.
	loadRetry time.Time
	// cost is the size class of what each tenant compiled to last, so that the small tenants of a pass go first and are
	// written before a large one is compiled. Unknown is the smallest class. It is deterministic (blob bytes, not a timing).
	cost map[uuid.UUID]uint64
	// blobUse is the bytes of new blob files each tenant caused in its current window.
	blobUse map[uuid.UUID]*blobUse
	// compile is CompileTenantWith; a test replaces it.
	compile func(in *TenantInput, now time.Time, prev func(string) *policyv1.EndpointRecord) *Output
}

// New builds a Compiler.
func New(cfg Config) (*Compiler, error) {
	if cfg.Backend == nil || cfg.Artifacts == nil {
		return nil, errors.New("compiler: a backend and an artifact store are required")
	}
	cfg.defaults()
	return &Compiler{cfg: cfg, seen: map[uuid.UUID]time.Time{}, alerted: map[string]time.Time{}, retry: map[uuid.UUID]bool{}, waiting: map[uuid.UUID]time.Time{}, compile: CompileTenantWith,
		cost: map[uuid.UUID]uint64{}, blobUse: map[uuid.UUID]*blobUse{}}, nil
}

// blobUse is one tenant's new blob bytes in a window that began at start.
type blobUse struct {
	start time.Time
	bytes uint64
}

// overBudget says the tenant has caused its share of new blob files in the window that is running.
func (c *Compiler) overBudget(id uuid.UUID, now time.Time) bool {
	u := c.blobUse[id]
	if u == nil {
		return false
	}
	if now.Sub(u.start) >= c.cfg.TenantBlobWindow {
		delete(c.blobUse, id)
		return false
	}
	return u.bytes >= c.cfg.TenantBlobBytes
}

func (c *Compiler) addBlobUse(id uuid.UUID, n uint64, now time.Time) {
	if n == 0 {
		return
	}
	u := c.blobUse[id]
	if u == nil || now.Sub(u.start) >= c.cfg.TenantBlobWindow {
		u = &blobUse{start: now}
		c.blobUse[id] = u
	}
	u.bytes += n
}

// costClass puts a tenant's compiled blob bytes into a class (0 under 256 KiB, up to 3 over 16 MiB). Classes and not bytes,
// so tenants of about the same size keep the order of their ids and the order of a pass is stable.
func costClass(n uint64) uint64 {
	switch {
	case n < 256<<10:
		return 0
	case n < 2<<20:
		return 1
	case n < 16<<20:
		return 2
	}
	return 3
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
		// A load that fails reads the snapshot and the tail again on every try; twice a second that is heavy for a log that
		// does not chain. The lease is still held and renewed above while it waits (W4-r3-2).
		if now.Before(c.loadRetry) {
			return nil
		}
		if err := c.load(ctx, now); err != nil {
			if errors.Is(err, ErrLeaseLost) {
				c.drop()
				return err
			}
			c.loadRetry = now.Add(c.cfg.Cap)
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
	c.retry, c.retryDue, c.waiting = map[uuid.UUID]bool{}, time.Time{}, map[uuid.UUID]time.Time{}
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
		// older kept snapshot). A read that fails, or an entry that is missing or does not decode, fails the load: a view that
		// guessed major 1 would write policy entries below the major of their blobs (W4-r3-10).
		majorRead := false
		if s.Seq == 0 {
			return errors.New("compiler: a snapshot at seq 0")
		}
		if err := be.LogAfter(ctx, s.Seq-1, 1, func(r store.LogRow) error {
			e, err := wire.DecodeEntry(r.Payload)
			if err != nil || r.Seq != s.Seq {
				return errors.New("compiler: the entry of a snapshot does not decode")
			}
			if e.MinBlobMajor != 0 {
				view.Major = e.MinBlobMajor
			}
			majorRead = true
			return nil
		}); err != nil {
			return err
		}
		if !majorRead {
			return errors.New("compiler: the entry of a snapshot is missing")
		}
		c.lastSnapSeq = s.Seq
		break
	}
	// The tail is applied entry by entry as the rows arrive: an entry may be 15 MiB, and 200 of them in one slice would not fit
	// in the worker (W4-r2-9). A batch is its own short transaction, so a long tail is not one transaction of minutes.
	c.sinceSnap = 0
	for {
		// The lease is 10 s and a long tail takes longer: it is renewed between batches, or two workers would take it from each
		// other for ever while neither finishes a load (W4-r3-2).
		if err := c.renew(ctx); err != nil {
			return err
		}
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
	if len(marks) == 0 && !c.full && !src.differs() && !vanished && !retryNow && !c.waitDue(now) {
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

// tenantResult is what compileOne found of one tenant.
type tenantResult struct {
	// out is nil for a tenant that was skipped.
	out *Output
	// known says the tenant's Endpoints were read, so the view may learn who owns them even when the compile did not finish: a
	// tenant that panics has Endpoints in the log that are its own and not orphans (W4-r3-4).
	known bool
	// written is the bytes of new blob files the sink put in the store.
	written uint64
	// storeFailed says the artifact store refused a file: the tenant is compiled again with no new blob.
	storeFailed bool
	// compileFailed says the compile itself panicked or could not read the rules, which a compile with no blob does not do.
	compileFailed bool
}

// compileOne reads and compiles one tenant. A tenant whose read fails for its own reasons, or whose compile panics, is
// skipped (nil output and nil error) and not allowed to stop the others: one poison tenant would otherwise hold back every
// change, revocation and snapshot of the fleet. The error is for what stops the pass.
//
// degraded compiles with no new blob (TenantInput.Degraded); otherwise each blob is put in the store as it is built, with the
// full pass making sure of the file that is there (the row of a bound blob says the nodes may fetch it, not that the file is still
// there: a restored database, a volume that lost a directory entry).
func (c *Compiler) compileOne(ctx context.Context, id uuid.UUID, alive bool, now time.Time, degraded, full bool) (res tenantResult, err error) {
	if !alive {
		return tenantResult{out: emptyOutput()}, nil
	}
	v := c.view
	var (
		found    bool
		rerr     error
		renewErr error
		keys     []string
		out      *Output
		// The sink's two kinds of failure differ: a lease or a head that moved (or a context that ended) stops the pass, and a file
		// the store would not take only costs the tenant its new blobs.
		fenceErr, putErr error
		written          uint64
		fenced           bool
	)
	sink := func(p *Profile) error {
		had := c.cfg.Artifacts.Has(p.Hash, int64(len(p.Bytes)))
		if !fenced && (full || !had) {
			// A compiler that is no longer the writer finds out before it writes a file, so a refused entry leaves none
			// behind (W4-r1-17); the commit asks again under the lock.
			if fenceErr = c.renew(ctx); fenceErr == nil {
				fenceErr = c.cfg.Backend.Check(ctx, c.fence())
			}
			if fenceErr != nil {
				return fenceErr
			}
			fenced = true
		}
		if full {
			putErr = c.cfg.Artifacts.Ensure(p.Hash, p.Bytes)
		} else if !had {
			putErr = c.cfg.Artifacts.Put(p.Hash, p.Bytes)
		}
		if putErr != nil {
			return putErr
		}
		if !had {
			written += uint64(len(p.Bytes))
		}
		return nil
	}
	// The compile runs inside the read snapshot, which reads the rules a profile at a time. A panic unwinds through the
	// transaction, which rolls back. The lease is renewed before each profile's rules are read: one maxed tenant takes longer
	// than the lease, and a second worker would take it in the middle (W4-r3-7).
	panicked := safego.Run(c.cfg.Log, unitTenant, func() {
		out, found, rerr = c.cfg.Backend.Tenant(ctx, id, func(in *TenantInput) *Output {
			for i := range in.Endpoints {
				keys = append(keys, string(in.Endpoints[i].ID[:]))
			}
			if orig := in.RulesOf; orig != nil {
				in.RulesOf = func(p uuid.UUID) ([]store.RuleRow, error) {
					if renewErr = c.renew(ctx); renewErr != nil {
						return nil, renewErr
					}
					return orig(p)
				}
			}
			// Both are set on every call: a backend may hand the same input again.
			in.Degraded = degraded
			in.Sink = nil
			if !degraded {
				in.Sink = sink
			}
			return c.compile(in, now, func(k string) *policyv1.EndpointRecord { return v.Endpoints[k] })
		})
	})
	if renewErr != nil {
		return res, renewErr
	}
	if fenceErr != nil {
		return res, fenceErr
	}
	for _, k := range keys {
		if _, ok := v.owner[k]; !ok {
			v.owner[k] = id
		}
	}
	res.known = len(keys) != 0 || (!panicked && rerr == nil && found)
	if putErr != nil {
		res.storeFailed = true
		return res, nil
	}
	fromCompile := panicked
	if rerr == nil && out != nil {
		rerr = out.readErr
		fromCompile = fromCompile || rerr != nil
	}
	res.compileFailed = fromCompile
	switch {
	case panicked:
		return res, nil
	case rerr != nil:
		if !transient(ctx, rerr) {
			return res, nil
		}
		if ctx.Err() != nil || errors.Is(rerr, context.Canceled) {
			return res, rerr
		}
		// A timeout of the tenant's own read (statement, idle or transaction timeout) looks like the database's. Ask it a cheap
		// question: when it answers, the failure is this tenant's and the others go on; when it does not, or the lease or the
		// head moved, the pass ends as before (W4-r3-9).
		if perr := c.cfg.Backend.Check(ctx, c.fence()); perr != nil {
			if errors.Is(perr, ErrLeaseLost) || errors.Is(perr, ErrHeadMoved) {
				return res, perr
			}
			return res, rerr
		}
		// Last in the order of the next pass: it is the one that costs the database its timeouts.
		c.cost[id] = costClass(1 << 62)
		return res, nil
	case !found:
		return tenantResult{out: emptyOutput()}, nil
	}
	res.out, res.written = out, written
	return res, nil
}

// retriable says a problem is a failure to compile and not a fact about the data: it may mend with no event the tenant makes.
func retriable(r Reason) bool {
	return r == ReasonProfile || r == ReasonSchedule || r == ReasonRecordInvalid
}

// markRetry puts a tenant in the retry set at once, and not when the pass ends: the marks of a tenant go with the slice that
// meets it, and a pass that fails after that slice would otherwise leave the tenant with neither a mark nor a retry (W4-r4-1).
func (c *Compiler) markRetry(id uuid.UUID, now time.Time) {
	c.retry[id] = true
	if c.retryDue.IsZero() {
		c.retryDue = now.Add(c.cfg.Reconcile)
	}
}

// windowEnd is when the budget window of a tenant ends.
func (c *Compiler) windowEnd(id uuid.UUID, now time.Time) time.Time {
	if u := c.blobUse[id]; u != nil {
		return u.start.Add(c.cfg.TenantBlobWindow)
	}
	return now.Add(c.cfg.TenantBlobWindow)
}

// waitDue says a tenant that waits for its budget window has come to the end of it.
func (c *Compiler) waitDue(now time.Time) bool {
	for _, due := range c.waiting {
		if !now.Before(due) {
			return true
		}
	}
	return false
}

// fire compiles what is owed and writes it. The tenants go in groups of one batch, the marked ones first and the small ones
// before the large, and what is finished is written once Config.Slice of compile time has passed or enough bytes are pending: a
// pass that compiled every tenant before it wrote anything made a revocation wait behind every large tenant of the fleet
// (W4-r3-7). After each write the outbox is read again, and a tenant that was marked meanwhile goes to the front of what is left
// (W4-r4-7). A pass that is not long is one slice, as before.
func (c *Compiler) fire(ctx context.Context, now time.Time) error {
	be, v := c.cfg.Backend, c.view
	marks, err := be.Marks(ctx, 5000)
	if err != nil {
		return err
	}
	// Tenants to compile: those with a mark, every tenant on a full pass, the ones whose last compile failed once their time has
	// come, and the ones that waited for their blob budget once their window has ended.
	tenants := map[uuid.UUID]bool{}
	markIDs := map[uuid.UUID][]uuid.UUID{}
	knownMark := map[uuid.UUID]bool{}
	for _, m := range marks {
		tenants[m.Tenant] = true
		markIDs[m.Tenant] = append(markIDs[m.Tenant], m.ID)
		knownMark[m.ID] = true
	}
	full := c.full
	retryNow := len(c.retry) > 0 && !now.Before(c.retryDue)
	if retryNow {
		for t := range c.retry {
			tenants[t] = true
		}
	}
	for t, due := range c.waiting {
		if !now.Before(due) {
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
	join := func(ms []store.OutboxMark) {
		for _, m := range ms {
			f, ok := first[m.Batch]
			if !ok {
				first[m.Batch] = m.Tenant
				continue
			}
			if a, b := find(f), find(m.Tenant); a != b {
				rep[b] = a
			}
		}
	}
	join(marks)

	if full {
		c.unmet = make(map[uuid.UUID]bool, len(ids))
		for _, id := range ids {
			c.unmet[id] = true
		}
	}
	// The groups, in the order they are compiled: the tenants with a mark first, then by the size class of what the tenants
	// compiled to last (a tenant not met yet is the smallest), then by id. A group is never split by a slice, since its tenants
	// share an entry.
	done := map[uuid.UUID]bool{}
	plan := func() [][]uuid.UUID {
		groupOf := map[uuid.UUID][]uuid.UUID{}
		var reps []uuid.UUID
		class := map[uuid.UUID]uint64{}
		marked := map[uuid.UUID]bool{}
		for _, id := range sortedIDs(tenants) {
			if done[id] {
				continue
			}
			r := find(id)
			if _, ok := groupOf[r]; !ok {
				reps = append(reps, r)
			}
			groupOf[r] = append(groupOf[r], id)
			class[r] = max(class[r], c.cost[id])
			if len(markIDs[id]) != 0 {
				marked[r] = true
			}
		}
		sort.SliceStable(reps, func(i, j int) bool {
			a, b := reps[i], reps[j]
			if marked[a] != marked[b] {
				return marked[a]
			}
			return class[a] < class[b]
		})
		out := make([][]uuid.UUID, len(reps))
		for i, r := range reps {
			out[i] = groupOf[r]
		}
		return out
	}

	var (
		pending      []*diff
		pendingMarks []uuid.UUID
		pendingBytes int
		problems     []Alert
	)
	// flush writes the diffs of the slice and deletes the marks of the tenants in it. final also carries what belongs to the
	// whole pass and not to a tenant: the catalog entry and the bump.
	flush := func(final bool) error {
		if !final && len(pending) == 0 && len(pendingMarks) == 0 {
			return nil
		}
		// The units: tenants of one batch group are one unit.
		units := map[uuid.UUID][]*diff{}
		var order []uuid.UUID
		for _, d := range pending {
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
		if final && (src.catalog != nil || src.bump != 0) {
			cat := newChunk(v)
			cat.class, cat.catalog, cat.major = commonv1.EntryClass_ENTRY_CLASS_CATALOG, src.catalog, src.bump
			chunks = append(chunks, cat)
		}
		for i, ch := range chunks {
			var ids []uuid.UUID
			if i == len(chunks)-1 {
				ids = pendingMarks
			}
			if err := c.write(ctx, ch, now, ids); err != nil {
				return err
			}
		}
		if len(chunks) == 0 && len(pendingMarks) != 0 {
			if err := c.renew(ctx); err != nil {
				return err
			}
			if err := be.DeleteMarks(ctx, pendingMarks, c.fence()); err != nil {
				return err
			}
		}
		pending, pendingMarks, pendingBytes = nil, nil, 0
		return nil
	}

	deferred := false
	// one compiles a tenant and queues what it changes.
	one := func(id uuid.UUID) error {
		// A tenant past its share of new blob files and of record bytes is compiled with no new blob: what says who may query
		// still goes out at once, and the rest waits for its window to end (W4-r4-2, W4-r4-5). A group stays whole, since the
		// tenant is compiled and written with the others of its batch.
		over := alive[id] && c.overBudget(id, now)
		degraded := over
		var fallback Reason
		var (
			res tenantResult
			d   *diff
			n   uint64
		)
		for {
			if err := c.renew(ctx); err != nil {
				return err
			}
			var err error
			res, err = c.compileOne(ctx, id, alive[id], now, degraded, full)
			if err != nil {
				return err
			}
			if res.known {
				// The view knows who owns its Endpoints now, compiled or not.
				delete(c.unmet, id)
			}
			// A compile that panics, or a file the store would not take, costs the tenant its new blobs and not its revocations
			// (W4-r4-5, W4-r4-9).
			if !degraded && (res.storeFailed || (res.out == nil && res.compileFailed)) {
				degraded, fallback = true, ReasonProfile
				if res.storeFailed {
					fallback = ReasonArtifacts
				}
				continue
			}
			if res.out == nil {
				break
			}
			sort.Strings(byOwner[id])
			d = diffTenant(v, id, res.out, byOwner[id], claimsOf)
			var perr error
			if n, perr = c.putBlobs(ctx, d, res.out, full); perr != nil {
				var ae *artifactError
				if errors.As(perr, &ae) && !degraded {
					degraded, fallback = true, ReasonArtifacts
					continue
				}
				return perr
			}
			break
		}
		// Its marks go with the slice, as every tenant's do, and the retry set brings a failed one back.
		pendingMarks = append(pendingMarks, markIDs[id]...)
		done[id] = true
		out := res.out
		if out == nil {
			c.markRetry(id, now)
			problems = append(problems, Alert{Reason: ReasonProfile, Tenant: id})
			return nil
		}
		if alive[id] && !degraded {
			var bytesOf uint64
			for _, p := range out.Blobs {
				if p != nil {
					bytesOf += uint64(p.Len())
				}
			}
			c.cost[id] = costClass(bytesOf)
		}
		pending = append(pending, d)
		pendingBytes += d.bytes
		for _, r := range out.Problems {
			problems = append(problems, Alert{Reason: r, Tenant: id})
		}
		switch {
		case over:
			// The retry set is left as it is: a tenant that waits for its window is not one that failed to compile.
			deferred = true
			c.waiting[id] = c.windowEnd(id, now)
		case degraded:
			c.markRetry(id, now)
			problems = append(problems, Alert{Reason: fallback, Tenant: id})
		default:
			n += res.written
			c.addBlobUse(id, n+uint64(d.bytes), now)
			c.sinceSnap += n
			delete(c.waiting, id)
			failed := false
			for _, r := range out.Problems {
				failed = failed || retriable(r)
			}
			if failed {
				c.markRetry(id, now)
			} else {
				delete(c.retry, id)
			}
		}
		return nil
	}

	sliceStart := c.cfg.Clock()
	groups := plan()
	for gi := 0; gi < len(groups); gi++ {
		for _, id := range groups[gi] {
			if err := one(id); err != nil {
				return err
			}
		}
		if gi == len(groups)-1 || (c.cfg.Clock().Sub(sliceStart) < c.cfg.Slice && pendingBytes < c.cfg.MaxEntryBytes) {
			continue
		}
		if err := flush(false); err != nil {
			return err
		}
		sliceStart = c.cfg.Clock()
		// A change marked while the pass worked is served before the large tenants that are left. A mark of a tenant that is done
		// stays for the next pass: it came after the compile.
		fresh, err := be.Marks(ctx, 5000)
		if err != nil {
			return err
		}
		var added []store.OutboxMark
		for _, m := range fresh {
			if knownMark[m.ID] || done[m.Tenant] {
				continue
			}
			knownMark[m.ID] = true
			markIDs[m.Tenant] = append(markIDs[m.Tenant], m.ID)
			tenants[m.Tenant] = true
			added = append(added, m)
		}
		if len(added) != 0 {
			join(added)
			groups, gi = plan(), -1
		}
	}
	// A tenant that is gone and had an Endpoint that was kept (no record in the log) left an owner behind that nothing deletes:
	// the tenant would be vanished for ever and every reconcile would compile it again (W4-r3-3). A key with a record loses its
	// owner when the entry that deletes it is applied.
	gone := map[uuid.UUID]bool{}
	for t := range tenants {
		if !alive[t] {
			gone[t] = true
		}
	}
	if len(gone) != 0 {
		for k, t := range v.owner {
			if _, has := v.Endpoints[k]; gone[t] && !has {
				delete(v.owner, k)
			}
		}
	}
	// A tenant that was skipped has no owner in a view that just started: its records would be taken for orphans. The sweep
	// waits until every tenant of the view has been compiled once, or at least read as far as its Endpoints, whichever pass that
	// is: a pass that meets only other tenants (a mark, a pair table, free DNS) must not run it while this one is still unowned
	// (W4-r2-1, W4-r2-6).
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
			pending = append(pending, o)
			problems = append(problems, Alert{Reason: ReasonOrphanSweep})
		}
	}
	if err := flush(true); err != nil {
		return err
	}
	if full {
		c.full = false
	}
	c.sweepOwed = (full || c.sweepOwed) && unmet
	c.owed = false
	if deferred {
		c.cfg.Log.Warn("compiler: tenants wait for their blob budget")
	}
	// The retry set was kept as the tenants were met: the ones that failed are in it and the ones that compiled are not.
	switch {
	case len(c.retry) == 0:
		c.retryDue = time.Time{}
	case retryNow:
		c.retryDue = now.Add(c.cfg.Reconcile)
	}
	for _, a := range problems {
		c.alert(ctx, a, now)
	}
	return nil
}

// artifactError is a refusal of the artifact store (a full volume, an I/O error), told from a lease or a head that moved: the
// first costs a tenant its new blobs, the second ends the pass.
type artifactError struct{ err error }

func (e *artifactError) Error() string { return "compiler: artifact store: " + e.err.Error() }
func (e *artifactError) Unwrap() error { return e.err }

// putBlobs puts in the store the files of the blobs a diff's put records bind that it does not hold and whose bytes are still
// held (a compile with a sink has put its own), and returns the bytes it wrote. The full pass makes sure of every blob it holds:
// the row of a bound blob says the nodes may fetch it, not that the file is still there (a restored database, a volume that lost
// a directory entry). A compiler that is no longer the writer finds out before it writes a file, so a refused entry leaves none
// behind (W4-r1-17); the commit asks again under the lock.
func (c *Compiler) putBlobs(ctx context.Context, d *diff, out *Output, full bool) (uint64, error) {
	var need []string
	for _, h := range sortedKeys(out.Blobs) {
		p := out.Blobs[h]
		if p == nil || p.Bytes == nil {
			continue
		}
		if _, bound := d.blobs[h]; !full && !bound {
			continue
		}
		if full || !c.cfg.Artifacts.Has([]byte(h), int64(len(p.Bytes))) {
			need = append(need, h)
		}
	}
	if len(need) == 0 {
		return 0, nil
	}
	if err := c.renew(ctx); err != nil {
		return 0, err
	}
	if err := c.cfg.Backend.Check(ctx, c.fence()); err != nil {
		return 0, err
	}
	var n uint64
	for _, h := range need {
		p := out.Blobs[h]
		had := c.cfg.Artifacts.Has([]byte(h), int64(len(p.Bytes)))
		var err error
		if full {
			err = c.cfg.Artifacts.Ensure([]byte(h), p.Bytes)
		} else {
			err = c.cfg.Artifacts.Put([]byte(h), p.Bytes)
		}
		if err != nil {
			return 0, &artifactError{err}
		}
		if !had {
			n += uint64(len(p.Bytes))
		}
	}
	return n, nil
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
	// Every blob the entry names is in the store before the entry is visible. The files were put as the tenant compiled,
	// outside any transaction: thousands of fsyncs under the log lock would outlast the idle and transaction timeouts of the
	// role and hold up the pruning and the next pass (W4-r2-2). Inside the commit, with the lock held, each is only looked at,
	// since the bytes are not kept (W4-r3-1): the collector deletes under the same lock, so a file that was there when it was
	// put could be gone by now. The entry is then refused, and the next pass compiles the tenant again and puts the file again.
	files := func() error {
		for _, h := range sortedKeys(b.files) {
			if !c.cfg.Artifacts.Has([]byte(h), int64(b.files[h])) {
				return ErrBlobGone
			}
		}
		return nil
	}
	// The compile and the files before this can outlast the lease (10 s); the commit refuses a lease that has run out, and
	// a lease nobody else took is simply taken again (W4-r2-8).
	if err := c.renew(ctx); err != nil {
		return err
	}
	err = c.cfg.Backend.Commit(ctx, &Commit{Seq: b.entry.Seq, Class: classOf(b.entry.Class), PrevHash: v.Head, EntryHash: b.hash,
		Payload: b.payload, Put: b.put, GC: b.gc, Outbox: outbox, Holder: c.cfg.Holder, Files: files})
	if err != nil {
		if !errors.Is(err, ErrHeadMoved) && !errors.Is(err, ErrLeaseLost) && !errors.Is(err, ErrBlobGone) {
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
