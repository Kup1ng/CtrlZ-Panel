package hubnodes

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
)

// RecheckEvery is how often every open stream is judged again against its node's row (4.4).
const RecheckEvery = 60 * time.Second

type entry struct {
	method string
	spki   []byte
	serial string
	cancel context.CancelFunc
}

// Registry holds every open NodeHub stream under its node id, transfer and upload streams included
// (4.4): a revocation that ended only Control would leave a revoked node's other streams to run on.
type Registry struct {
	mu  sync.Mutex
	seq uint64
	m   map[uuid.UUID]map[uint64]*entry
}

// NewRegistry makes an empty registry.
func NewRegistry() *Registry { return &Registry{m: make(map[uuid.UUID]map[uint64]*entry)} }

// Add registers a stream. The returned function removes it, and is safe to call twice.
func (r *Registry) Add(node uuid.UUID, method string, spki []byte, serial string, cancel context.CancelFunc) (remove func()) {
	r.mu.Lock()
	r.seq++
	k := r.seq
	if r.m[node] == nil {
		r.m[node] = make(map[uint64]*entry)
	}
	r.m[node][k] = &entry{method: method, spki: spki, serial: serial, cancel: cancel}
	r.mu.Unlock()
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

// Rechecker runs the 60-second check of open streams on the control pool (4.4).
type Rechecker struct {
	Reg   *Registry
	Nodes NodeReader // the control pool
	Log   *slog.Logger
	Every time.Duration
}

// Pass judges every registered node once. A row that cannot be read ends nothing: a database outage
// must not end a Control stream (SC 12), and the next pass looks again.
func (c *Rechecker) Pass(ctx context.Context) (ended int) {
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
