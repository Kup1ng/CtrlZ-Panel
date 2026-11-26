package hubtel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/google/uuid"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// maxHealthItems bounds the health lists kept in version_info: a Heartbeat may list 65,536 of each, and the Overview
// shows a handful.
const maxHealthItems = 64

type healthJSON struct {
	ID        string `json:"id,omitempty"`
	Location  uint32 `json:"location,omitempty"`
	Healthy   bool   `json:"healthy"`
	LatencyMS uint32 `json:"latency_ms"`
}

// versionInfo is what nodes.version_info holds (p4-nodes 3.2 item 8): versions, flags and counts, and the health of the
// upstreams and locations by id, never an address of a client.
type versionInfo struct {
	NodeVersion      string       `json:"node_version"`
	UnboundVersion   string       `json:"unbound_version"`
	CatalogVersion   uint64       `json:"catalog_version"`
	BlobMajorMax     uint32       `json:"blob_major_max"`
	Isolated         bool         `json:"isolated"`
	Quarantined      uint32       `json:"quarantined"`
	QPS              uint32       `json:"qps"`
	CacheHitPermille uint32       `json:"cache_hit_permille"`
	Upstreams        []healthJSON `json:"upstreams"`
	Locations        []healthJSON `json:"locations"`
}

func beatOf(h *hubv1.Heartbeat) (store.HubBeat, error) {
	v := versionInfo{
		NodeVersion: h.NodeVersion, UnboundVersion: h.UnboundVersion, CatalogVersion: h.CatalogVersion, BlobMajorMax: h.BlobMajorMax,
		Isolated: h.Isolated, Quarantined: h.Quarantined, QPS: h.Qps, CacheHitPermille: h.CacheHitPermille,
		Upstreams: []healthJSON{}, Locations: []healthJSON{},
	}
	for i, u := range h.Upstreams {
		if i == maxHealthItems {
			break
		}
		v.Upstreams = append(v.Upstreams, healthJSON{ID: hex.EncodeToString(u.Id), Healthy: u.Healthy, LatencyMS: u.LatencyMs})
	}
	for i, l := range h.Locations {
		if i == maxHealthItems {
			break
		}
		v.Locations = append(v.Locations, healthJSON{Location: l.Location, Healthy: l.Healthy, LatencyMS: l.LatencyMs})
	}
	b, err := json.Marshal(v)
	return store.HubBeat{VersionInfo: b, AppliedSeq: h.AppliedSeq}, err
}

// beatLoop writes each node's latest Heartbeat fields at most every BeatEvery, on the telemetry pool (5.3). A node that has
// said nothing for ten minutes is dropped from the trackers: its fields stay as the last write left them.
func (t *Telemetry) beatLoop(ctx context.Context) {
	tk := time.NewTicker(t.cfg.BeatTick)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			t.BeatPass(ctx)
		}
	}
}

// BeatPass is one pass of that loop; tests call it directly.
func (t *Telemetry) BeatPass(ctx context.Context) {
	now := t.cfg.Now()
	for _, n := range t.cfg.Trackers.Nodes() {
		hb, at, ok := t.cfg.Trackers.Latest(n)
		if !ok {
			continue
		}
		if now.Sub(at) > 10*time.Minute {
			t.cfg.Trackers.Forget(n)
			t.mu.Lock()
			delete(t.lastBeat, n)
			delete(t.skewed, n)
			t.mu.Unlock()
			continue
		}
		t.mu.Lock()
		last := t.lastBeat[n].t
		t.mu.Unlock()
		if !last.IsZero() && now.Sub(last) < BeatEvery {
			continue
		}
		in, err := beatOf(hb)
		if err != nil {
			continue
		}
		wctx, cancel := context.WithTimeout(ctx, writeTimeout)
		err = t.cfg.Store.HubWriteBeat(wctx, n, in)
		cancel()
		if err != nil {
			continue // tried again at the next pass
		}
		t.mu.Lock()
		t.lastBeat[n] = stamp{now}
		t.mu.Unlock()
		t.wroteBeats.add()
	}
}

// skew raises the clock alert once when a node's clock differs from the hub's by more than SkewLimit, and again only after
// the node was back within it (SC 18 item 6).
func (t *Telemetry) skew(node uuid.UUID, h *hubv1.Heartbeat) {
	d := t.cfg.Now().Sub(time.Unix(h.NodeTime, 0))
	if d < 0 {
		d = -d
	}
	over := d > SkewLimit
	t.mu.Lock()
	was := t.skewed[node]
	t.skewed[node] = over
	t.mu.Unlock()
	if over && !was {
		t.dropBeatSkew.add()
		t.raise("warning", store.HubAlertNodeClockSkew, map[string]string{"node_id": node.String(), "seconds": strconv.FormatInt(int64(d/time.Second), 10)})
	}
}

// hourWindow counts one node's quarantine rows in the hour that began at start.
type hourWindow struct {
	start time.Time
	n     int
}

type quarReq struct {
	node         uuid.UUID
	seq          uint64
	item, reason string
}

// itemText is the text of a quarantined item: its bytes in hex, or the hash of them when long, so a row stays small.
func itemText(b []byte) string {
	if len(b) <= 64 {
		return hex.EncodeToString(b)
	}
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// quarantineOffer queues a report for its row. The cap of 60 an hour per node and the queue are checked here, in memory, so a
// node cannot make the hub write faster (5.3).
func (t *Telemetry) quarantineOffer(node uuid.UUID, q *hubv1.QuarantineReport) {
	now := t.cfg.Now()
	t.mu.Lock()
	w := t.quar[node]
	if w == nil || now.Sub(w.start) >= time.Hour {
		w = &hourWindow{start: now}
		t.quar[node] = w
	}
	if w.n >= QuarantinePerHour {
		t.mu.Unlock()
		t.dropQuarCap.add()
		return
	}
	w.n++
	t.mu.Unlock()
	select {
	case t.quarQ <- quarReq{node: node, seq: q.Seq, item: itemText(q.Item), reason: q.Reason}:
	default:
		t.dropQuarFull.add()
	}
}

func (t *Telemetry) quarLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-t.quarQ:
			t.quarantineWrite(ctx, r)
		}
	}
}

// quarantineWrite writes one report; the same failure reported by a second node raises the alert, one node's report acts
// locally (R18, SC 9.7).
func (t *Telemetry) quarantineWrite(ctx context.Context, r quarReq) {
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	inserted, nodes, err := t.cfg.Store.HubQuarantineAdd(wctx, r.node, r.seq, r.item, r.reason)
	if err != nil || !inserted || nodes < 2 {
		return
	}
	t.raise("warning", store.HubAlertQuarantineTwoNodes, map[string]string{
		"seq": strconv.FormatUint(r.seq, 10), "reason": r.reason, "nodes": strconv.Itoa(nodes),
	})
}
