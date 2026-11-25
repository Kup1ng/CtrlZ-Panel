package hubnodes

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
)

// RecheckEvery is how often every open stream is judged again against its node's row (4.4).
const RecheckEvery = 60 * time.Second

type entry struct {
	method   string
	spki     []byte
	serial   string
	notAfter time.Time // the certificate that opened the stream stops being valid then (4.4)
	cancel   context.CancelFunc
}

// killMemory is how long Registry remembers that a node was killed. It only has to outlive the gap
// between a stream's row check and its registration (a check is bounded by OpenTimeout), with room to spare.
const killMemory = 2 * time.Minute

type killMark struct {
	seq uint64
	at  time.Time
}

// Registry holds every open NodeHub stream under its node id, transfer and upload streams included
// (4.4): a revocation that ended only Control would leave a revoked node's other streams to run on.
type Registry struct {
	mu  sync.Mutex
	seq uint64
	m   map[uuid.UUID]map[uint64]*entry
	// kseq counts Kill calls and killed holds the last one of each node, so a stream whose row check
	// ran before a Kill and whose registration came after it is ended on arrival and not left to the next
	// 60 s check (G2, W3-r2-2).
	kseq   uint64
	killed map[uuid.UUID]killMark
}

// NewRegistry makes an empty registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[uuid.UUID]map[uint64]*entry), killed: make(map[uuid.UUID]killMark)}
}

// Gen is the mark a stream takes before it reads its node row. Add ends a stream whose node was killed
// after the mark: the row it read may be older than the revocation that caused the Kill.
func (r *Registry) Gen() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.kseq
}

// Add registers a stream whose row check began at gen (Gen), for a certificate valid until notAfter. If
// the node was killed since gen the stream is cancelled at once. The returned function removes the
// stream, and is safe to call twice.
func (r *Registry) Add(node uuid.UUID, method string, spki []byte, serial string, notAfter time.Time, gen uint64, cancel context.CancelFunc) (remove func()) {
	r.mu.Lock()
	r.seq++
	k := r.seq
	if r.m[node] == nil {
		r.m[node] = make(map[uint64]*entry)
	}
	r.m[node][k] = &entry{method: method, spki: spki, serial: serial, notAfter: notAfter, cancel: cancel}
	stale := r.killed[node].seq > gen
	r.mu.Unlock()
	if stale {
		cancel()
	}
	return func() {
		r.mu.Lock()
		if es := r.m[node]; es != nil {
			delete(es, k)
			if len(es) == 0 {
				delete(r.m, node)
			}
		}
		r.mu.Unlock()
	}
}

// Kill cancels every stream of a node and returns how many. It is what a revocation, a removal or a
// PairTable that empties the node's SPKI calls (G2); the hub does not wait for the next 60 s check.
func (r *Registry) Kill(node uuid.UUID) int {
	r.mu.Lock()
	r.kseq++
	now := appclock.Now()
	r.killed[node] = killMark{seq: r.kseq, at: now}
	for n, m := range r.killed {
		if now.Sub(m.at) > killMemory {
			delete(r.killed, n)
		}
	}
	es := r.m[node]
	cancels := make([]context.CancelFunc, 0, len(es))
	for _, e := range es {
		cancels = append(cancels, e.cancel)
	}
	r.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	return len(cancels)
}

// Count is the number of open streams of a node.
func (r *Registry) Count(node uuid.UUID) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.m[node])
}

// Nodes lists the nodes that have an open stream.
func (r *Registry) Nodes() []uuid.UUID {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]uuid.UUID, 0, len(r.m))
	for n := range r.m {
		out = append(out, n)
	}
	return out
}

// killInvalid ends the streams of node whose certificate the row no longer accepts.
func (r *Registry) killInvalid(node uuid.UUID, accepts func(spki []byte, serial string) bool) int {
	r.mu.Lock()
	var cancels []context.CancelFunc
	for _, e := range r.m[node] {
		if !accepts(e.spki, e.serial) {
			cancels = append(cancels, e.cancel)
		}
	}
	r.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	return len(cancels)
}

// killExpired ends the streams whose certificate is past not_after at now. It reads no row, so it also
// runs while the database is down: only RenewCert may be called with an expired certificate (4.3), and
// a stream that began on the last day must not outlive it (W3-r2-9).
func (r *Registry) killExpired(now time.Time) int {
	r.mu.Lock()
	var cancels []context.CancelFunc
	for _, es := range r.m {
		for _, e := range es {
			if !e.notAfter.IsZero() && !now.Before(e.notAfter) {
				cancels = append(cancels, e.cancel)
			}
		}
	}
	r.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	return len(cancels)
}

// Rechecker runs the 60-second check of open streams on the control pool (4.4).
type Rechecker struct {
	Reg   *Registry
	Nodes NodeReader // the control pool
	Log   *slog.Logger
	Every time.Duration
	Now   func() time.Time // the clock the certificates are judged by; appclock.Now when nil
}

// Pass judges every registered node once. A row that cannot be read ends nothing: a database outage
// must not end a Control stream (SC 12), and the next pass looks again.
func (c *Rechecker) Pass(ctx context.Context) (ended int) {
	now := appclock.Now
	if c.Now != nil {
		now = c.Now
	}
	ended = c.Reg.killExpired(now())
	for _, node := range c.Reg.Nodes() {
		rctx, cancel := context.WithTimeout(ctx, OpenTimeout)
		n, found, err := c.Nodes.HubNodeLoad(rctx, node)
		cancel()
		if err != nil {
			continue
		}
		ended += c.Reg.killInvalid(node, func(spki []byte, serial string) bool {
			if !found || n.Status != "active" || !bytes.Equal(n.SPKI, spki) {
				return false
			}
			return (n.CertSerial != "" && serial == n.CertSerial) || (n.PrevCertSerial != "" && serial == n.PrevCertSerial)
		})
	}
	return ended
}

// Run calls Pass every interval until ctx ends. A panic in one pass costs that pass.
func (c *Rechecker) Run(ctx context.Context) {
	every := c.Every
	if every <= 0 {
		every = RecheckEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.pass(ctx)
		}
	}
}

func (c *Rechecker) pass(ctx context.Context) {
	defer safego.Keep(c.Log, unitRecheck)
	c.Pass(ctx)
}
