package hubctl

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
)

// The lease of p4-nodes 5.2: one hub instance in stage 1, and the evaluator (5.6) runs, and the hub says anything about
// time, only under lease hub-decider, so a second hub started by mistake never signs and never sends ServerTime.
const (
	LeaseName  = "hub-decider"
	LeaseEvery = 2 * time.Second
	LeaseSecs  = 10
)

// LeaseStore takes or renews a lease on the lease pool (one connection, 5.7).
type LeaseStore interface {
	HubLeaseTake(ctx context.Context, name, holder string, secs int) (bool, error)
}

// Lease keeps the hub-decider lease. Held answers from memory: the hub counts the lease as held until ten seconds after
// the last renewal that the database confirmed, so a database that cannot answer takes the lease away at the same time
// another hub could take it, and not later.
type Lease struct {
	st     LeaseStore
	holder string
	now    func() time.Time
	log    *slog.Logger
	until  atomic.Int64 // unix nanos of the end of the last confirmed renewal's life, 0 for none
}

// NewLease makes a lease for one process: holder names the process (a random id), so a restarted hub is another holder
// and waits for its predecessor's lease to run out or takes it back at once when it is its own.
func NewLease(st LeaseStore, holder string, now func() time.Time, log *slog.Logger) *Lease {
	return &Lease{st: st, holder: holder, now: now, log: log}
}

// Held says whether this process holds the lease now.
func (l *Lease) Held() bool { return l.now().UnixNano() < l.until.Load() }

// Renew takes or renews once and records the answer. A lost lease (someone else holds it) ends the hold at once.
func (l *Lease) Renew(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, LeaseEvery)
	defer cancel()
	start := l.now()
	ok, err := l.st.HubLeaseTake(cctx, LeaseName, l.holder, LeaseSecs)
	switch {
	case err != nil:
		if l.log != nil {
			l.log.Warn("hub-decider lease: renewal failed")
		}
	case ok:
		l.until.Store(start.Add(LeaseSecs * time.Second).UnixNano())
	default:
		l.until.Store(0)
	}
}

// Run renews every two seconds until ctx ends.
func (l *Lease) Run(ctx context.Context) {
	t := time.NewTicker(LeaseEvery)
	defer t.Stop()
	for {
		l.Renew(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Evaluator is what 5.6 plugs in: the failover loop's own readiness (its tick ended, its read of pair_event_state
// succeeded, its prober completed a round, L4) and the latest signed PairTable it has to push. Nil means no evaluator is
// built yet, and the hub then decides on the lease and the heartbeats alone.
type Evaluator interface {
	Ready() bool
	Push() *signv1.Envelope
}

// Decider says whether the hub may send ServerTime and what it pushes after it (SC 8a.4 Publication, 8a.11 L4).
type Decider interface {
	CanDecide() bool
	Push() *signv1.Envelope
}

// HeartbeatFreshness is how recent the trackers' latest Heartbeat must be, while a Control stream is open (L4).
const HeartbeatFreshness = 15 * time.Second

// LeaseDecider is the Decider of the hub: the lease, the recency of the heartbeats while a stream is open, and the evaluator
// when there is one.
type LeaseDecider struct {
	Lease    *Lease
	Trackers *Trackers
	Streams  func() int
	Eval     Evaluator
}

// CanDecide is L4's conjunction. Each part fails closed.
func (d *LeaseDecider) CanDecide() bool {
	if d.Lease == nil || !d.Lease.Held() {
		return false
	}
	if d.Streams != nil && d.Streams() > 0 && !d.Trackers.Recent(HeartbeatFreshness) {
		return false
	}
	return d.Eval == nil || d.Eval.Ready()
}

// Push is the evaluator's latest signed table, nil while there is none.
func (d *LeaseDecider) Push() *signv1.Envelope {
	if d.Eval == nil {
		return nil
	}
	return d.Eval.Push()
}

type beat struct {
	hb *hubv1.Heartbeat
	at int64 // unix nanos
}

// Trackers keep the latest Heartbeat of each node in memory (5.3). A Heartbeat is validated before it gets here, and nothing
// here waits on the database: the reader of a stream calls Take inline.
type Trackers struct {
	now  func() time.Time
	mu   sync.Mutex
	last map[uuid.UUID]beat
	any  int64
}

// NewTrackers makes empty trackers.
func NewTrackers(now func() time.Time) *Trackers {
	return &Trackers{now: now, last: make(map[uuid.UUID]beat)}
}

// Take records a node's Heartbeat.
func (t *Trackers) Take(node uuid.UUID, hb *hubv1.Heartbeat) {
	at := t.now().UnixNano()
	t.mu.Lock()
	t.last[node] = beat{hb: hb, at: at}
	t.any = at
	t.mu.Unlock()
}

// Latest is the node's latest Heartbeat and when it came, found false for a node not heard from.
func (t *Trackers) Latest(node uuid.UUID) (hb *hubv1.Heartbeat, at time.Time, found bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.last[node]
	if !ok {
		return nil, time.Time{}, false
	}
	return b.hb, time.Unix(0, b.at), true
}

// Recent says whether any Heartbeat was taken in the last d.
func (t *Trackers) Recent(d time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.any != 0 && t.now().UnixNano()-t.any <= int64(d)
}

// Forget drops a node's entry.
func (t *Trackers) Forget(node uuid.UUID) {
	t.mu.Lock()
	delete(t.last, node)
	t.mu.Unlock()
}

// RunLease runs the lease loop under a unit of its own.
func RunLease(ctx context.Context, l *Lease, log *slog.Logger) {
	safego.Go(log, unitCtl, func() { l.Run(ctx) })
}

// Nodes lists the nodes the trackers hold a Heartbeat of: the telemetry writer (5.3) walks them every few seconds.
func (t *Trackers) Nodes() []uuid.UUID {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]uuid.UUID, 0, len(t.last))
	for n := range t.last {
		out = append(out, n)
	}
	return out
}
