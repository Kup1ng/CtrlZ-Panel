package hubtel

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	telemetryv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/telemetry/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// akey is one thing a node reports activity for: an Endpoint, a client label, and the claim or authorized prefix the source
// belongs to. The protocol is not part of it, since no write depends on it.
type akey struct {
	ep    uuid.UUID
	label string
	claim uuid.UUID
	hash  string
}

// astate is what the hub holds per key (5.4): the latest buckets any node reported, when the key was last written, and the
// node that introduced it, which the per-node bound counts against.
type astate struct {
	first, last int64 // unix seconds of the 5-minute buckets; last is the maximum over nodes
	wroteLast   int64 // the last bucket a write carried, 0 before the first write
	wroteAt     time.Time
	seen        time.Time
	owner       uuid.UUID // counted against this node's bound
	sender      uuid.UUID // the node that reported the latest bucket, for created_by_node_id
}

// activity keeps the keys in memory and writes the due ones: a key is written when it has a bucket the last write did not
// carry and it was never written or was written an hour ago ("at most once an hour per key after the first sighting").
type activity struct {
	t *Telemetry

	mu    sync.Mutex
	keys  map[akey]*astate
	perNd map[uuid.UUID]int
}

func newActivity(t *Telemetry) *activity {
	return &activity{t: t, keys: make(map[akey]*astate), perNd: make(map[uuid.UUID]int)}
}

// Keys is the number of keys held.
func (a *activity) Keys() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.keys)
}

// accept takes a validated batch of a node. The pair rule and the bounds are applied here, before anything is held or
// written, and every refusal is counted. It never waits on the database.
func (t *Telemetry) acceptActivity(node uuid.UUID, b *telemetryv1.ActivityBatch) {
	now := t.cfg.Now()
	t.mu.Lock()
	if last, ok := t.batchAt[node]; ok && now.Sub(last.t) < ActivityBatchEvery {
		t.mu.Unlock()
		t.dropBatchRate.add()
		return
	}
	t.batchAt[node] = stamp{t: now}
	t.mu.Unlock()
	if len(b.Entries) > ActivityBatchEntries {
		t.dropBatchSize.add()
		return
	}
	a := t.act
	allowed := map[uuid.UUID]bool{} // the pair rule is asked once for each Endpoint of the batch
	for _, e := range b.Entries {
		ep, err := uuid.FromBytes(e.EndpointId)
		if err != nil {
			t.dropBatchInvalid.add()
			continue
		}
		ok, asked := allowed[ep]
		if !asked {
			ok = t.cfg.Directory != nil && t.cfg.Directory.Allowed(ep, node, now)
			allowed[ep] = ok
		}
		if !ok {
			t.dropPair.add()
			continue
		}
		k := akey{ep: ep, label: e.ClientLabel}
		switch {
		case len(e.ClaimId) == 16:
			k.claim, _ = uuid.FromBytes(e.ClaimId)
		case len(e.SourceIpHash) != 0:
			k.hash = string(e.SourceIpHash)
		}
		a.take(node, k, e.FirstSeenBucket, e.LastSeenBucket, now, t)
	}
}

func (a *activity) take(node uuid.UUID, k akey, first, last int64, now time.Time, t *Telemetry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.keys[k]
	if s == nil {
		if a.perNd[node] >= t.cfg.KeysPerNode || len(a.keys) >= t.cfg.KeysTotal {
			t.dropKeyCap.add()
			return
		}
		s = &astate{first: first, last: last, owner: node, sender: node}
		a.keys[k] = s
		a.perNd[node]++
	}
	s.seen = now
	if first < s.first {
		s.first = first
	}
	// The maximum over nodes: a node whose clock runs fast gets no further than validation allowed (five minutes ahead).
	if last > s.last {
		s.last, s.sender = last, node
	}
}

func (a *activity) loop(ctx context.Context) {
	tk := time.NewTicker(a.t.cfg.ActivityTick)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			a.Flush(ctx)
		}
	}
}

type due struct {
	k    akey
	last int64
}

// flushChunk bounds the items of one transaction, so a tenant with many keys does not hold its locks for long.
const flushChunk = 500

// Flush writes the keys that are due, grouped by tenant, one transaction per tenant chunk; it also lets go of keys idle for
// two hours. A failed write leaves the keys due for the next pass.
func (a *activity) Flush(ctx context.Context) {
	t := a.t
	now := t.cfg.Now()
	var dueKeys []due
	a.mu.Lock()
	for k, s := range a.keys {
		if now.Sub(s.seen) > 2*time.Hour && s.last <= s.wroteLast {
			delete(a.keys, k)
			a.perNd[s.owner]--
			if a.perNd[s.owner] <= 0 {
				delete(a.perNd, s.owner)
			}
			continue
		}
		if s.last > s.wroteLast && (s.wroteAt.IsZero() || now.Sub(s.wroteAt) >= ActivityWriteEvery) {
			dueKeys = append(dueKeys, due{k, s.last})
		}
	}
	a.mu.Unlock()
	if len(dueKeys) == 0 {
		return
	}
	eps := make([]uuid.UUID, 0, len(dueKeys))
	seenEp := map[uuid.UUID]bool{}
	for _, d := range dueKeys {
		if !seenEp[d.k.ep] {
			seenEp[d.k.ep] = true
			eps = append(eps, d.k.ep)
		}
	}
	lctx, cancel := context.WithTimeout(ctx, writeTimeout)
	tenants, err := t.cfg.Store.HubEndpointTenants(lctx, eps)
	cancel()
	if err != nil {
		return
	}
	byTenant := map[uuid.UUID][]due{}
	for _, d := range dueKeys {
		tn, ok := tenants[d.k.ep]
		if !ok {
			// The Endpoint is gone: nothing to write, and the key goes with it.
			t.dropNoTenant.add()
			a.forget(d.k)
			continue
		}
		byTenant[tn] = append(byTenant[tn], d)
	}
	tns := make([]uuid.UUID, 0, len(byTenant))
	for tn := range byTenant {
		tns = append(tns, tn)
	}
	sort.Slice(tns, func(i, j int) bool { return string(tns[i][:]) < string(tns[j][:]) })
	for _, tn := range tns {
		ds := byTenant[tn]
		for len(ds) > 0 {
			n := min(len(ds), flushChunk)
			a.writeChunk(ctx, tn, ds[:n], now)
			ds = ds[n:]
		}
	}
}

func (a *activity) forget(k akey) {
	a.mu.Lock()
	if s := a.keys[k]; s != nil {
		delete(a.keys, k)
		a.perNd[s.owner]--
	}
	a.mu.Unlock()
}

func (a *activity) writeChunk(ctx context.Context, tenant uuid.UUID, ds []due, now time.Time) {
	t := a.t
	items := make([]store.HubActivityItem, 0, len(ds))
	sent := make([]due, 0, len(ds))
	a.mu.Lock()
	for _, d := range ds {
		s := a.keys[d.k]
		if s == nil {
			continue
		}
		capv, ok := uint32(0), false
		if t.cfg.Directory != nil {
			capv, ok = t.cfg.Directory.ClientCap(d.k.ep)
		}
		if !ok {
			// The log view has no record of the Endpoint (it is new, or the view is behind): try again later.
			t.dropNoRecord.add()
			continue
		}
		it := store.HubActivityItem{
			Endpoint: d.k.ep, Label: d.k.label, Claim: d.k.claim, Hash: []byte(d.k.hash),
			First: time.Unix(s.first, 0), Last: time.Unix(d.last, 0), Node: s.sender, ClientCap: capv,
		}
		items = append(items, it)
		sent = append(sent, due{d.k, d.last})
	}
	a.mu.Unlock()
	if len(items) == 0 {
		return
	}
	var res store.HubActivityResult
	var err error
	for try := 0; try < 3; try++ { // a lost lock race (40P01, T-532) is tried again
		wctx, cancel := context.WithTimeout(ctx, writeTimeout)
		res, err = t.cfg.Store.HubActivityWrite(wctx, tenant, items)
		cancel()
		if err == nil || !errors.Is(err, store.ErrRetry) {
			break
		}
	}
	if err != nil {
		return
	}
	for range res.OverCap {
		t.dropClientCap.add()
	}
	a.mu.Lock()
	for _, d := range sent {
		if s := a.keys[d.k]; s != nil {
			s.wroteLast, s.wroteAt = d.last, now
		}
	}
	a.mu.Unlock()
	t.wroteActivity.n.Add(uint64(len(sent)))
}
