package compiler

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

const (
	kindProfile   = "profile"
	kindBlockPage = "block_page"
)

type artifactRow = store.ArtifactRow

// ErrHeadMoved is what Commit returns when the log's head is not the entry before the one written: another writer
// (a compiler that held the lease before this one) added to the log. The compiler drops its view and loads again.
var ErrHeadMoved = errors.New("compiler: the log head moved")

// ErrLeaseLost is what a write returns when the lease of the compiler is no longer this holder's: another worker took it
// while a long pass was working. Like ErrHeadMoved it makes the compiler drop its view and load again.
var ErrLeaseLost = errors.New("compiler: the lease is not held")

// Fence says who writes and what the writer believes the log to be, for a write that is not an entry (the delete of marks
// no entry stands for, the row of a snapshot): the database takes the log lock and refuses it when the lease is not the
// holder's, or when the head is not Seq and Head.
type Fence struct {
	Holder string
	Seq    uint64
	Head   []byte
}

// Commit is everything one entry writes, in one transaction under the log lock.
type Commit struct {
	Seq       uint64
	Class     string // policy or catalog
	PrevHash  []byte
	EntryHash []byte
	Payload   []byte
	// Put are the blobs the entry names for the first time, or again (the row of a hash that waited for its
	// collection is cleared, and one the collector deleted is written again).
	Put []artifactRow
	// GC are the hashes the entry names in del_blobs: they get gc_after_seq = Seq.
	GC [][]byte
	// Outbox are the rows the entry stands for, deleted in the same transaction. Only the last entry of a pass has any.
	Outbox []uuid.UUID
	// Holder is the lease holder that writes; the commit is refused with ErrLeaseLost when the lease is not its.
	Holder string
	// Files puts the files the entry names in the store. It runs with the log lock held, after the head is checked and
	// before the entry is appended, so a collection of blobs (which deletes under the same lock) never interleaves with it.
	Files func() error
}

// Backend is the compiler's door to the database. internal/compiler/db.go implements it over the store; a test
// implements it in memory.
type Backend interface {
	// Lease takes or renews the compiler lease for holder, secs seconds.
	Lease(ctx context.Context, holder string, secs int) (bool, error)
	// Marks reads up to limit outbox rows, oldest first.
	Marks(ctx context.Context, limit int) ([]store.OutboxMark, error)
	// DeleteMarks deletes outbox rows that no entry is written for, fenced: ErrLeaseLost or ErrHeadMoved when the writer is
	// not the one the lease names or the log is not where it thinks.
	DeleteMarks(ctx context.Context, ids []uuid.UUID, f Fence) error
	// Tenants lists every tenant id.
	Tenants(ctx context.Context) ([]uuid.UUID, error)
	// Tenant reads one tenant in one REPEATABLE READ READ ONLY snapshot; found is false for a tenant that is gone.
	Tenant(ctx context.Context, id uuid.UUID) (in *TenantInput, found bool, err error)
	// Membership reads the nodes, the pairs and the global pair.
	Membership(ctx context.Context) (*Membership, error)
	// FreeDNS reads the free DNS switch, its budget and its version.
	FreeDNS(ctx context.Context) (enabled bool, qps int, version uint64, err error)
	// Catalog reads the current catalog version, found false when there is none.
	Catalog(ctx context.Context) (store.CatalogVersionRow, bool, error)
	// Snapshots lists the newest snapshots, newest first.
	Snapshots(ctx context.Context, limit int) ([]store.SnapshotRow, error)
	// LogAfter reads entries after seq, in order.
	LogAfter(ctx context.Context, seq uint64, limit int) ([]store.LogRow, error)
	// Artifacts reads every policy_artifacts row.
	Artifacts(ctx context.Context) ([]artifactRow, error)
	// Commit writes one entry. ErrHeadMoved when the head is not the entry before it.
	Commit(ctx context.Context, c *Commit) error
	// PutSnapshot records a snapshot and drops the rows of the snapshots in drop, fenced like DeleteMarks (the head must be
	// the snapshot's own seq and hash).
	PutSnapshot(ctx context.Context, s store.SnapshotRow, drop []uint64, holder string) error
	// Alert raises an alert once while one with the same key is open.
	Alert(ctx context.Context, a Alert) error
}
