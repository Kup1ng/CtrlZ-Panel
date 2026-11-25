// Package bulkgate bounds the memory that the bulk routes (Import, Upload, Duplicate and the two batch routes) hold at
// once (docs/specs/p2-profiles.md 6.2). A route whose body limit is large opens a Reservation after its session resolved
// and its buckets were charged, and before its body is read. The reservation follows the bytes that have arrived: a body
// that trickles in holds only what it has sent, so a slow sender costs a connection and no more of the gate than its
// bytes. When the body is complete the reservation is set to the weight of the work on it, the memory the checks, the
// decode and the item rules need, and it keeps that until the request answers or queues its job. Two bounds hold: the
// whole process, sized from the share of memory the api has, and one tenant's share, so a tenant with many sessions
// cannot take it all. Either full is a refusal and never a wait: a request that waits holds a connection and a goroutine,
// which is what the gate exists to avoid.
package bulkgate

import "sync"

// Sizes (D31). A request's weight is BodyWeight times its body: the body itself, the copies the request check and the
// strict decode make of it, the decoded file, and the trees of the document (measured on a 4 MiB document of 40,000
// rules: about 6 times the body in the pipeline, the rest in the document). The process share is about half of the
// 200 MiB of GOMEMLIMIT the api container runs with. A tenant may hold one Import or Upload of the largest size
// (6 MiB, 48 MiB of weight) and some small bodies beside it.
const (
	DefaultTotal     = 96 << 20
	DefaultPerTenant = 56 << 20
	// ReadWeight is what a byte of a body being read costs: the read buffer grows by doubling.
	ReadWeight = 2
	// BodyWeight is what a byte of a body costs while the work on it runs.
	BodyWeight = 8
)

// Gate is the pool. The zero value is not usable: call New.
type Gate struct {
	mu        sync.Mutex
	total     int64
	perTenant int64
	used      int64
	byTenant  map[string]int64
}

// New returns a gate of total bytes with perTenant of them for one tenant.
func New(total, perTenant int64) *Gate {
	return &Gate{total: total, perTenant: perTenant, byTenant: map[string]int64{}}
}

// Reservation is the share of the gate one request holds. It starts at nothing.
type Reservation struct {
	g      *Gate
	tenant string
	held   int64
	done   bool
}

// Reserve opens a reservation of nothing for the tenant. Call Release when the request is over.
func (g *Gate) Reserve(tenant string) *Reservation {
	return &Reservation{g: g, tenant: tenant}
}

// To sets what the reservation holds to n bytes, taking more from the gate or giving back. It never waits. When a bound
// would be passed it returns false and the reservation keeps what it had.
func (r *Reservation) To(n int64) bool {
	g := r.g
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.done || n < 0 {
		return false
	}
	d := n - r.held
	if d > 0 && (g.used+d > g.total || g.byTenant[r.tenant]+d > g.perTenant) {
		return false
	}
	g.used += d
	if g.byTenant[r.tenant] += d; g.byTenant[r.tenant] <= 0 {
		delete(g.byTenant, r.tenant)
	}
	r.held = n
	return true
}

// Release gives everything back. It is safe to call more than once.
func (r *Reservation) Release() {
	g := r.g
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	g.used -= r.held
	if g.byTenant[r.tenant] -= r.held; g.byTenant[r.tenant] <= 0 {
		delete(g.byTenant, r.tenant)
	}
	r.held = 0
}

// Acquire reserves n bytes for the tenant at once. It never waits. The release function gives them back and is safe to
// call more than once.
func (g *Gate) Acquire(tenant string, n int64) (release func(), ok bool) {
	r := g.Reserve(tenant)
	if !r.To(n) {
		return nil, false
	}
	return r.Release, true
}

// Held reports the bytes reserved now and by that tenant, for tests.
func (g *Gate) Held(tenant string) (all, mine int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.used, g.byTenant[tenant]
}
