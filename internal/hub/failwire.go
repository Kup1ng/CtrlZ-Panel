package hub

import (
	"context"
	"crypto/x509"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubctl"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubfail"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubprobe"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubrev"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubsign"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtel"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtrust"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubview"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The wiring of 5.5 and 5.6: the log view, the revocations, the prober and the failover loop. They exist together or not at all
// (Stores.View and Stores.Eval both given), because each needs the others: the loop reads the view's membership, the release point
// reads the loop's last_table, and the revocations are derived from the entries the view reads.

// logView builds the view and the loop and returns what the NodeHub server takes from them: the Directory of 5.4 and the
// evaluator of 5.6. A Directory or Evaluator the caller gave in Deps wins (tests).
func (h *Hub) logView(d Deps, signer *hubsign.Signer) (hubtel.Directory, hubctl.Evaluator) {
	dir, eval := d.Directory, d.Evaluator
	if d.Stores.View == nil || d.Stores.Eval == nil {
		return dir, eval
	}
	h.view = hubview.New()
	h.fail = hubfail.New(hubfail.Config{
		Store: d.Stores.Eval, View: h.view, Beats: h.trackers, Lease: h.lease, Signer: signer,
		Alert: h.raise,
		// An unknown zone counts as probing: the prober has nothing to probe through, so no round completes and Ready is false.
		Probing: func() bool { zone, known := h.zones.get(d); return !known || zone != "" },
		Now:     d.Now, Log: d.Log,
	})
	if dir == nil {
		dir = h.view
	}
	if eval == nil {
		eval = h.fail
	}
	return dir, eval
}

// raise sends an alert through the telemetry pool's writer, or drops it where there is none.
func (h *Hub) raise(sev string, kind store.HubAlertKind, params map[string]string) {
	if h.tel != nil {
		h.tel.Raise(sev, kind, params)
	}
}

// wireFailover connects the pieces that need the Control server, which is built after them.
func (h *Hub) wireFailover(d Deps) {
	if h.fail == nil {
		return
	}
	h.fail.SetSender(h.ctl)
	h.keeper = hubrev.New(h.ctl, keeperNodes{h}, d.Now, h.raise, d.Log)
	h.prober = hubprobe.New(hubprobe.Config{
		Targets: h.fail.Targets,
		Zone:    func() string { zone, _ := h.zones.get(d); return zone },
		Roots:   h.zoneRoots,
		Report:  h.fail.Report,
		Now:     d.Now, Log: d.Log,
	})
	if d.Release == nil {
		h.Roll.SetRelease(h.fail)
	}
	h.feed.Before = h.catch
}

// accepting, opened and headSent are the hooks the Control server calls; each is a no-op where there is no failover.
func (h *Hub) accepting() bool { return h.fail == nil || h.fail.Started() }

func (h *Hub) opened(node uuid.UUID) {
	if h.keeper != nil {
		h.keeper.Opened(node)
	}
}

func (h *Hub) headSent(node uuid.UUID, seq uint64, at time.Time) {
	if h.fail != nil {
		h.fail.NoteHead(node, seq, at)
	}
}

// catch is the feed's Before hook: it brings the view up to the entry, queues the entry's Revocations ahead of the roll, and ends
// the streams of a node the entry's table empties the SPKI of (G2 of 8a.9). The entries are applied in order, so a failure part
// way still announces what was applied.
func (h *Hub) catch(ctx context.Context, head store.HubLogHead, live bool) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	applied, err := h.view.Catch(cctx, h.deps.Stores.View, head.Seq)
	if !live {
		return err
	}
	for _, a := range applied {
		if len(a.Revs) > 0 {
			h.keeper.Add(a)
		}
		for _, n := range a.Emptied {
			h.Streams.Kill(n)
		}
	}
	return err
}

// keeperNodes tells the revocation keeper which nodes have to catch up and how far each has.
type keeperNodes struct{ h *Hub }

// Pending is the non-revoked nodes of the hub's latest membership.
func (k keeperNodes) Pending() []uuid.UUID {
	t, _, ok := k.h.view.Membership()
	if !ok {
		return nil
	}
	var out []uuid.UUID
	for _, n := range t.Nodes {
		if len(n.SpkiSha256) == 0 {
			continue
		}
		if id, err := uuid.FromBytes(n.NodeId); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func (k keeperNodes) Applied(node uuid.UUID) (uint64, bool) {
	hb, _, ok := k.h.trackers.Latest(node)
	if !ok || hb == nil {
		return 0, false
	}
	return hb.AppliedSeq, true
}

// zoneRoots is the pool the probes verify the zone certificate against: the zone CA, and the public roots too while the hub serves
// uploaded wildcards (hubctl.Wildcards), since a zone that an upload covers is served with a public chain and the rest with the
// zone CA's. A hub with no zone CA yet gets an empty pool of its own, which no certificate chains to: a probe fails closed, and
// a nil pool would have meant the system's roots.
func (h *Hub) zoneRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	if h.publicRoots != nil {
		pool = h.publicRoots.Clone()
	}
	if z := h.CAs.Zone(); z != nil {
		pool.AddCert(z.Cert())
	}
	return pool
}

// zoneCache is the live zone the prober probes through, read from domain_settings at most every 30 s.
//
// Three answers are told apart (H-r1-5, H-r1-10). A zone is live. No zone is live, which is a fact about the settings and lets
// the hub decide with no probe round (SC 8a.11 L4). Nothing is known yet, because no read has succeeded: that is not "no zone",
// so the hub is not ready on the strength of it. Every attempt, a failed one or an empty answer too, stamps the cache, so a
// database that is slow or down costs one read of 2 s per window and not one per call.
type zoneCache struct {
	zone  atomic.Pointer[string] // the last successful answer, "" when none was live
	at    atomic.Int64           // unix nanos the window of the next read counts from, 0 for none
	known atomic.Bool            // a read has succeeded at least once
}

const (
	zoneEvery = 30 * time.Second
	zoneRetry = 5 * time.Second // the window after a failed read
)

func (z *zoneCache) last() (string, bool) {
	known := z.known.Load()
	if p := z.zone.Load(); p != nil {
		return *p, known
	}
	return "", known
}

// get returns the live zone ("" for none) and whether the answer is known.
func (z *zoneCache) get(d Deps) (zone string, known bool) {
	now := d.Now()
	if at := z.at.Load(); at != 0 && now.Sub(time.Unix(0, at)) < zoneEvery {
		return z.last()
	}
	// No lock is held across the read: two callers that read at once both store the same answer.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	zs, err := d.Stores.Control.HubLiveZones(ctx)
	if err != nil {
		z.at.Store(now.Add(zoneRetry - zoneEvery).UnixNano())
		return z.last() // the last answer stands; unknown until the first read succeeds
	}
	live := hubtrust.LiveZones(zs, now)
	var cur string
	if len(live) > 0 {
		cur = live[0]
	}
	z.zone.Store(&cur)
	z.known.Store(true)
	z.at.Store(now.UnixNano())
	return cur, true
}

// keepRevocations ticks the revocation keeper once a second: it drops what every node has applied, sends again to the nodes that lag
// and alerts for the ones 60 s behind.
func (h *Hub) keepRevocations(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer safego.Keep(h.deps.Log, unitCtl)
				h.keeper.Tick()
			}()
		}
	}
}
