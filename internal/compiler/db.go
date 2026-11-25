package compiler

import (
	"bytes"
	"context"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// leaseName is the lease the worker holds while it is the compiler (6.1).
const leaseName = "compiler"

// DB is the Backend over the store, opened as ctrlz_compiler.
type DB struct{ st *store.Store }

// NewDB wraps a store that was opened as ctrlz_compiler.
func NewDB(st *store.Store) *DB { return &DB{st: st} }

// readOnly is the transaction of every read: one snapshot, no write.
func readOnly() store.TxOpts { return store.TxOpts{Isolation: store.RepeatableRead, ReadOnly: true} }

// Lease takes or renews the compiler lease.
func (d *DB) Lease(ctx context.Context, holder string, secs int) (bool, error) {
	var ok bool
	err := d.st.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) (err error) {
		ok, err = g.LeaseTake(leaseName, holder, secs)
		return err
	})
	return ok, err
}

// Marks reads the outbox.
func (d *DB) Marks(ctx context.Context, limit int) (out []store.OutboxMark, err error) {
	err = d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) (err error) {
		out, err = g.CompilerOutbox(limit)
		return err
	})
	return out, err
}

// fence takes the log lock and refuses a writer that is not the one the lease names, or whose view of the head is not the
// log's: a pass longer than the lease can leave a second worker holding it, and a write of marks or of a snapshot from the
// older view would consume what only the newer one has compiled. head is what the writer believes the head to be, zero
// and nil for an empty log.
func fence(g store.GlobalTx, holder string, seq uint64, head []byte) error {
	if err := g.ConfigLogLock(); err != nil {
		return err
	}
	return checkFence(g, holder, seq, head)
}

// checkFence is the lease and the head of fence, read without the log lock.
func checkFence(g store.GlobalTx, holder string, seq uint64, head []byte) error {
	held, err := g.CompilerLeaseHeld(leaseName, holder)
	if err != nil {
		return err
	}
	if !held {
		return ErrLeaseLost
	}
	at, hash, found, err := g.CompilerHead()
	if err != nil {
		return err
	}
	switch {
	case !found && seq == 0:
	case found && at == seq && bytes.Equal(hash, head):
	default:
		return ErrHeadMoved
	}
	return nil
}

// Check reads what fence reads, without the lock and in a read-only transaction.
func (d *DB) Check(ctx context.Context, f Fence) error {
	return d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) error {
		return checkFence(g, f.Holder, f.Seq, f.Head)
	})
}

// DeleteMarks deletes outbox rows with no entry to go with them.
func (d *DB) DeleteMarks(ctx context.Context, ids []uuid.UUID, f Fence) error {
	return d.st.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		if err := fence(g, f.Holder, f.Seq, f.Head); err != nil {
			return err
		}
		_, err := g.CompilerOutboxDelete(ids)
		return err
	})
}

// Tenants lists the tenants.
func (d *DB) Tenants(ctx context.Context) (out []uuid.UUID, err error) {
	err = d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) (err error) {
		out, err = g.CompilerTenantIDs()
		return err
	})
	return out, err
}

// Tenant reads one tenant in one snapshot: every table the compile map names, as of the same instant, and the rules one
// profile at a time through in.RulesOf. compile runs inside the transaction, since the rules are read as it needs them.
func (d *DB) Tenant(ctx context.Context, id uuid.UUID, compile func(in *TenantInput) *Output) (*Output, bool, error) {
	in := &TenantInput{}
	var out *Output
	found := false
	err := d.st.WithTenant(ctx, id, readOnly(), func(t store.Tx) (err error) {
		if in.Row, found, err = t.CompilerTenant(); err != nil || !found {
			return err
		}
		if in.Endpoints, err = t.CompilerEndpoints(); err != nil {
			return err
		}
		if in.Windows, err = t.CompilerWindows(); err != nil {
			return err
		}
		if in.Clients, err = t.CompilerClients(); err != nil {
			return err
		}
		if in.Authorized, err = t.CompilerAuthorized(); err != nil {
			return err
		}
		if in.Claims, err = t.CompilerClaims(); err != nil {
			return err
		}
		if in.Profiles, err = t.CompilerProfiles(); err != nil {
			return err
		}
		in.RulesOf = t.CompilerRulesOf
		if in.Folders, err = t.CompilerFolders(); err != nil {
			return err
		}
		if in.Services, err = t.CompilerServices(); err != nil {
			return err
		}
		if in.Filters, err = t.CompilerFilters(); err != nil {
			return err
		}
		if in.Options, err = t.CompilerOptions(); err != nil {
			return err
		}
		if in.Maps, err = t.CompilerMaps(); err != nil {
			return err
		}
		out = compile(in)
		if out != nil {
			// A read of rules that failed may have aborted the transaction; its error is the transaction's.
			return out.readErr
		}
		return nil
	})
	return out, found, err
}

// Membership reads the nodes, the pairs and the global pair in one snapshot.
func (d *DB) Membership(ctx context.Context) (*Membership, error) {
	m := &Membership{}
	err := d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) (err error) {
		if m.Nodes, err = g.CompilerNodes(); err != nil {
			return err
		}
		if m.Pairs, err = g.CompilerPairs(); err != nil {
			return err
		}
		m.Global, err = g.CompilerGlobalPair()
		return err
	})
	return m, err
}

// FreeDNS reads the free DNS settings.
func (d *DB) FreeDNS(ctx context.Context) (enabled bool, qps int, version uint64, err error) {
	err = d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) (err error) {
		enabled, qps, version, err = g.CompilerFreeDNS()
		return err
	})
	return enabled, qps, version, err
}

// Catalog reads the current catalog version.
func (d *DB) Catalog(ctx context.Context) (cur store.CatalogVersionRow, found bool, err error) {
	err = d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) (err error) {
		cur, found, err = g.CompilerCatalogCurrent()
		return err
	})
	return cur, found, err
}

// Snapshots lists the newest snapshots.
func (d *DB) Snapshots(ctx context.Context, limit int) (out []store.SnapshotRow, err error) {
	err = d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) (err error) {
		out, err = g.CompilerSnapshots(limit)
		return err
	})
	return out, err
}

// LogAfter hands entries after seq to each, one at a time.
func (d *DB) LogAfter(ctx context.Context, seq uint64, limit int, each func(store.LogRow) error) error {
	return d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) error {
		return g.CompilerLogEach(seq, limit, each)
	})
}

// Artifacts reads the artifact rows.
func (d *DB) Artifacts(ctx context.Context) (out []artifactRow, err error) {
	err = d.st.WithGlobal(ctx, readOnly(), func(g store.GlobalTx) (err error) {
		out, err = g.CompilerArtifacts()
		return err
	})
	return out, err
}

// Commit writes one entry with its artifact rows and the outbox deletes, holding the log lock the whole time (PS 10).
// The head is read after the lock is taken: a compiler that lost the lease while it was working finds another writer's
// entry there and is told so.
func (d *DB) Commit(ctx context.Context, c *Commit) error {
	return d.st.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		// The lease and the head are read after the lock is taken, so a compiler that lost the lease while it was working finds
		// the other writer's entry there, or its lease gone, and is told so.
		if c.Seq == 0 {
			return ErrHeadMoved
		}
		if err := fence(g, c.Holder, c.Seq-1, c.PrevHash); err != nil {
			return err
		}
		if c.Files != nil {
			if err := c.Files(); err != nil {
				return err
			}
		}
		if err := g.CompilerAppend(store.LogAppend{Seq: c.Seq, Class: c.Class, PrevHash: c.PrevHash, EntryHash: c.EntryHash, Payload: c.Payload}); err != nil {
			return err
		}
		for _, a := range c.Put {
			if err := g.CompilerArtifactPut(a); err != nil {
				return err
			}
		}
		for _, h := range c.GC {
			if err := g.CompilerArtifactGC(h, c.Seq); err != nil {
				return err
			}
		}
		_, err := g.CompilerOutboxDelete(c.Outbox)
		return err
	})
}

// PutSnapshot records a snapshot and drops the rows of older ones.
func (d *DB) PutSnapshot(ctx context.Context, s store.SnapshotRow, drop []uint64, holder string) error {
	return d.st.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		if err := fence(g, holder, s.Seq, s.EntryHash); err != nil {
			return err
		}
		if err := g.CompilerSnapshotPut(s); err != nil {
			return err
		}
		for _, seq := range drop {
			if err := g.CompilerSnapshotDelete(seq); err != nil {
				return err
			}
		}
		return nil
	})
}

// Alert raises an alert of the compiler. A reason about the log itself is critical: nodes may stop getting changes.
func (d *DB) Alert(ctx context.Context, a Alert) error {
	sev := "warning"
	switch a.Reason {
	case ReasonChain, ReasonCommit, ReasonLoad:
		sev = "critical"
	}
	return d.st.WithGlobal(ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := g.AlertOnce(sev, AlertKind, a.key(), a.params())
		return err
	})
}
