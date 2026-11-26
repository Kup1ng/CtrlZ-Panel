package hub

import (
	"context"
	"fmt"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The pools of p4-nodes 5.7 (D31). Every database access of the hub belongs to exactly one of them, and
// the hub's CTRLZ_DB_MAX_CONNS is their sum. A pool is its own Store, so a component that holds the L3 store
// cannot put a query on the control pool's connections, and a flood that fills one pool cannot starve the
// work of another: the check of every NodeHub RPC at open (L3), the evaluation loop (L4), the transfer
// RPCs, the lease, telemetry, the messages an outside party can cause, the control work, and
// enrolment.
const (
	PoolL3         = 2
	PoolL4         = 1
	PoolTransfer   = 2
	PoolLease      = 1
	PoolTelemetry  = 2
	PoolOutside    = 2
	PoolControl    = 2
	PoolEnrollment = 1
	// PoolTotal is the sum, and what CTRLZ_DB_MAX_CONNS must equal for the hub.
	PoolTotal = PoolL3 + PoolL4 + PoolTransfer + PoolLease + PoolTelemetry + PoolOutside + PoolControl + PoolEnrollment

	// EnrollmentStatementTimeout bounds a statement of the enrollment pool: its one connection is the
	// one an unauthenticated caller can reach, so a slow statement must not hold it (5.7).
	EnrollmentStatementTimeout = 2 * time.Second
	// L4StatementTimeout bounds a statement of the evaluation loop (8a.11 L4).
	L4StatementTimeout = time.Second
	// acquireWait is how long a call waits for a free connection of its pool before it is refused, so
	// a full pool answers UNAVAILABLE within the time bound of L3 and not when the client gives up.
	acquireWait = 2 * time.Second
)

// Pools are the eight stores of the hub.
type Pools struct {
	L3, L4, Transfer, Lease, Telemetry, Outside, Control, Enrollment *store.Store
}

// OpenPools opens every pool from one base configuration (host, database, role and password), giving each
// its size and its name in pg_stat_activity. A failure closes what was opened.
func OpenPools(ctx context.Context, base store.Config) (*Pools, error) {
	p := &Pools{}
	open := func(dst **store.Store, name string, size int32, tune func(*store.Config)) error {
		c := base
		c.MaxConns, c.MinConns = size, 0
		c.ApplicationName = "ctrlz-hub-" + name
		c.AcquireTimeout = acquireWait
		if tune != nil {
			tune(&c)
		}
		s, err := store.Open(ctx, c)
		if err != nil {
			return fmt.Errorf("pool %s: %w", name, err)
		}
		*dst = s
		return nil
	}
	steps := []struct {
		dst  **store.Store
		name string
		size int32
		tune func(*store.Config)
	}{
		{&p.L3, "l3", PoolL3, nil},
		// The evaluation loop fails a statement after 1 s so a lock or a database that cannot answer keeps its tick from ending (L4).
		{&p.L4, "l4", PoolL4, func(c *store.Config) { c.StatementTimeout = L4StatementTimeout }},
		{&p.Transfer, "transfer", PoolTransfer, nil},
		{&p.Lease, "lease", PoolLease, nil},
		{&p.Telemetry, "telemetry", PoolTelemetry, nil},
		{&p.Outside, "outside", PoolOutside, nil},
		{&p.Control, "control", PoolControl, nil},
		{&p.Enrollment, "enrollment", PoolEnrollment, func(c *store.Config) { c.StatementTimeout = EnrollmentStatementTimeout }},
	}
	for _, s := range steps {
		if err := open(s.dst, s.name, s.size, s.tune); err != nil {
			p.Close()
			return nil, err
		}
	}
	return p, nil
}

// Close closes every pool that was opened.
func (p *Pools) Close() {
	for _, s := range []*store.Store{p.L3, p.L4, p.Transfer, p.Lease, p.Telemetry, p.Outside, p.Control, p.Enrollment} {
		if s != nil {
			s.Close()
		}
	}
}

// Stores gives the components of this package the pool each one works on.
func (p *Pools) Stores() Stores {
	return Stores{L3: p.L3, Control: p.Control, Telemetry: p.Telemetry, Enrollment: p.Enrollment, Transfer: p.Transfer, Lease: p.Lease, Stream: p.Control, Tel: p.Telemetry, Outside: p.Outside, View: p.Control, Eval: p.L4}
}
