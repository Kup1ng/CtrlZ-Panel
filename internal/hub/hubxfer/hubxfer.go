// Package hubxfer serves the transfer RPCs of NodeHub: GetHead, FetchEntries, FetchBlob, GetSnapshot and FetchBundle
// (SC 12, p4-nodes 5.2, 6.4, 6.5).
//
// One rule runs through the first three that read the log: nothing above the node's bound is named, signed, sent or put in
// a snapshot, where the bound is the lower of the release point and the node's rollout cursor (hubroll.Roll.Bound). The
// bound is read once per call, so a call never mixes two answers of it.
//
// Blobs, snapshots and bundles come from files, never from a database connection (5.7): the two transfer connections are for the
// log rows alone, so a flood of blob fetches cannot starve the head. A file is hashed through its open handle and then read chunk
// by chunk from the same handle, so what is held in memory per stream is one chunk and the file that was checked is the file
// that is sent. The payloads of FetchEntries are in memory, so those are counted against one byte budget for the whole hub.
//
// Each node's transfer items are paced to 8 MiB/s in chunks of 256 KiB, all of its streams together (D31, L6), by one
// bucket per node_id, so a node that fetches a large blob over eight streams gets the same share as one that fetches it over one.
package hubxfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hublimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The numbers of D31 (5.7).
const (
	// ChunkBytes is the size of one pacing step and of one BlobChunk.
	ChunkBytes = 256 << 10
	// BytesPerSecond is the rate of all of one node's transfer streams together.
	BytesPerSecond = 8 << 20
	// MaxEntries is the most entries one FetchEntries returns; the node asks for at most this many in one call.
	MaxEntries = 200
	// MaxFetchBytes stops a FetchEntries once this much payload was read: the node stops at 64 MiB, and a read of that
	// size in memory, times eight streams, would be more than the hub needs to hold to keep a node moving.
	MaxFetchBytes = 16 << 20
	// FetchBudget is the payload bytes all FetchEntries calls of the hub may hold at once (the hub runs under GOMEMLIMIT 320 MiB).
	// One call reserves the most it can read, MaxFetchBytes plus the one entry that crosses the cap, so four run together and a
	// fifth waits; a node that fetches over eight streams, or several nodes at once, cannot take the hub's memory.
	FetchBudget = 128 << 20
	// MaxBlobBytes is the largest file FetchBlob serves: the cap of a profile blob. The catalog's filter tables share the
	// artifacts volume and are far larger; they are not served through this door.
	MaxBlobBytes = wire.MaxProfileBlob
	// MaxSnapshotBytes is the largest snapshot served: under four times the entry cap (the compiler's own bound).
	MaxSnapshotBytes = 4 * wire.MaxEntrySize
	// SnapshotLook is how many snapshot rows are read to find one under the bound (the compiler keeps two).
	SnapshotLook = 4
)

// Log is what the transfer pool is asked (the rows of config_log and config_snapshot).
type Log interface {
	HubLogHash(ctx context.Context, seq uint64) ([]byte, bool, error)
	HubLogEntries(ctx context.Context, after, upTo uint64, limit, maxBytes int) ([]store.LogRow, error)
	HubSnapshots(ctx context.Context, limit int) ([]store.SnapshotRow, error)
}

// Bounds says how far a node may read. known is false while the release point is not known.
type Bounds interface {
	Bound(node uuid.UUID) (seq uint64, known bool)
}

// Files opens a content-addressed file by its hash (compiler.DirArtifacts' Open). The caller checks the bytes against the name and
// closes the file.
type Files interface {
	Open(hash []byte) (*os.File, int64, error)
}

// Bundles is the one lookup of FetchBundle (5.1): the file of a verified bundle, by exact name.
type Bundles interface {
	OpenBundleFile(version uint64, path string) (*os.File, int64, error)
}

// Signer signs a head.
type Signer interface {
	Head(seq uint64, entryHash []byte, createdAt int64) (*signv1.Envelope, error)
}

// Service is the transfer half of the NodeHub server.
type Service struct {
	Log     Log
	Bounds  Bounds
	Files   Files
	Bundles Bundles
	Signer  Signer
	// Deciding says whether this hub holds the hub-decider lease; nil means it always does. A hub without it signs no head: a second
	// hub started by mistake would otherwise sign heads that the first one's release point withholds (H-r1-9).
	Deciding func() bool
	Now      func() time.Time
	Logger   *slog.Logger

	pace   *hublimit.Keyed
	budget *semaphore.Weighted
}

// New makes a Service, with its pacing bucket.
func New(s Service) *Service {
	if s.Now == nil {
		s.Now = appclock.Now
	}
	s.pace = hublimit.NewKeyed(BytesPerSecond, 4*ChunkBytes, s.Now)
	s.budget = semaphore.NewWeighted(FetchBudget)
	return &s
}

func nodeOf(ctx context.Context) (uuid.UUID, error) {
	id := hubnet.IdentityFrom(ctx)
	if !id.Node {
		return uuid.Nil, status.Error(codes.Unauthenticated, "certificate not accepted")
	}
	return id.NodeID, nil
}

// bound reads the node's bound once. Before the release point is known the hub serves nothing and returns no head
// (L12): the node retries, as after any transfer error.
func (s *Service) bound(node uuid.UUID) (uint64, error) {
	b, known := s.Bounds.Bound(node)
	if !known {
		return 0, status.Error(codes.Unavailable, "not ready")
	}
	return b, nil
}

// take waits until n bytes of the node's transfer rate are free, in steps of at most one chunk.
func (s *Service) take(ctx context.Context, node uuid.UUID, n int) error {
	key := node.String()
	for n > 0 {
		step := min(n, ChunkBytes)
		for !s.pace.AllowN(key, float64(step)) {
			d := max(s.pace.Wait(key, float64(step)), time.Millisecond)
			t := time.NewTimer(d)
			select {
			case <-ctx.Done():
				t.Stop()
				return status.FromContextError(ctx.Err()).Err()
			case <-t.C:
			}
		}
		n -= step
	}
	return nil
}

func (s *Service) readErr(err error) error {
	if s.Logger != nil {
		s.Logger.Warn("transfer read failed")
	}
	return status.Error(codes.Unavailable, "try again")
}

// GetHead returns the SignedHead of the node's bound, never of a later entry (SC 12).
func (s *Service) GetHead(ctx context.Context, _ *hubv1.GetHeadRequest) (*signv1.Envelope, error) {
	node, err := nodeOf(ctx)
	if err != nil {
		return nil, err
	}
	if s.Deciding != nil && !s.Deciding() {
		return nil, status.Error(codes.Unavailable, "not ready")
	}
	b, err := s.bound(node)
	if err != nil {
		return nil, err
	}
	if b == 0 {
		return nil, status.Error(codes.NotFound, "the log is empty")
	}
	hash, found, err := s.Log.HubLogHash(ctx, b)
	if err != nil {
		return nil, s.readErr(err)
	}
	if !found {
		return nil, status.Error(codes.NotFound, "no entry at the head")
	}
	env, err := s.Signer.Head(b, hash, s.Now().Unix())
	if err != nil {
		return nil, status.Error(codes.Internal, "cannot sign")
	}
	return env, nil
}

// FetchEntries streams the entries after after_seq, up to the bound, as stored (the chain hash runs over these bytes).
func (s *Service) FetchEntries(req *hubv1.FetchEntriesRequest, srv grpc.ServerStreamingServer[hubv1.StoredEntry]) error {
	ctx := srv.Context()
	node, err := nodeOf(ctx)
	if err != nil {
		return err
	}
	b, err := s.bound(node)
	if err != nil {
		return err
	}
	limit := int(req.GetLimit())
	if limit <= 0 || limit > MaxEntries {
		limit = MaxEntries
	}
	// The reservation covers the rows until the last one is sent; a node that reads slowly holds it for as long as it holds the rows.
	need := int64(MaxFetchBytes + wire.MaxEntrySize)
	if err := s.budget.Acquire(ctx, need); err != nil {
		return status.FromContextError(err).Err()
	}
	defer s.budget.Release(need)
	rows, err := s.Log.HubLogEntries(ctx, req.GetAfterSeq(), b, limit, MaxFetchBytes)
	if err != nil {
		return s.readErr(err)
	}
	for _, r := range rows {
		if err := s.take(ctx, node, len(r.Payload)); err != nil {
			return err
		}
		if err := srv.Send(&hubv1.StoredEntry{Seq: r.Seq, EntryHash: r.EntryHash, EntryBytes: r.Payload}); err != nil {
			return err
		}
	}
	return nil
}

// openChecked opens the file of a hash and checks its bytes against the name by streaming them through the open handle, so
// no more than a small buffer is held and the file that was checked is the one that is sent. A file above max, or one that
// is not there, is os.ErrNotExist; one whose bytes are not its name is refused and never sent under a name it does not have.
func (s *Service) openChecked(hash []byte, max int64) (*os.File, int64, error) {
	f, size, err := s.Files.Open(hash)
	if err != nil {
		return nil, 0, err
	}
	if size > max {
		f.Close()
		return nil, 0, os.ErrNotExist
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, size)); err != nil {
		f.Close()
		return nil, 0, err
	}
	if !bytes.Equal(h.Sum(nil), hash) {
		f.Close()
		return nil, 0, errors.New("hubxfer: artifact does not match its name")
	}
	return f, size, nil
}

// sendFile sends the file from offset in chunks, paced, the last marked. An empty file or an offset at the end is one empty
// chunk marked last.
func (s *Service) sendFile(ctx context.Context, node uuid.UUID, f *os.File, size int64, offset uint64, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	if offset > uint64(size) {
		return status.Error(codes.OutOfRange, "offset past the end")
	}
	buf := make([]byte, ChunkBytes)
	off := offset
	for {
		n, rerr := f.ReadAt(buf, int64(off))
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return status.Error(codes.Internal, "read")
		}
		last := off+uint64(n) >= uint64(size)
		if n == 0 && !last {
			return status.Error(codes.Internal, "read") // the file is shorter than it was when it was checked
		}
		if err := s.take(ctx, node, n); err != nil {
			return err
		}
		if err := srv.Send(&hubv1.BlobChunk{Offset: off, Data: buf[:n], Last: last}); err != nil {
			return err
		}
		off += uint64(n)
		if last {
			return nil
		}
	}
}

// FetchBlob streams a blob from the offset. The hash names the file and the file is checked against it first, so a file
// that is damaged on the volume is refused.
func (s *Service) FetchBlob(req *hubv1.FetchBlobRequest, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	ctx := srv.Context()
	node, err := nodeOf(ctx)
	if err != nil {
		return err
	}
	if len(req.GetHash()) != 32 {
		return status.Error(codes.InvalidArgument, "hash")
	}
	f, size, err := s.openChecked(req.GetHash(), MaxBlobBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return status.Error(codes.NotFound, "no such blob")
		}
		return s.readErr(err)
	}
	defer f.Close()
	return s.sendFile(ctx, node, f, size, req.GetOffset(), srv)
}

// GetSnapshot streams the newest snapshot at or below the node's bound, and at or above at_least_seq. A snapshot above the
// bound would hand the node an entry the hub withholds (L12), so none is chosen even when it is the only one.
func (s *Service) GetSnapshot(req *hubv1.GetSnapshotRequest, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	ctx := srv.Context()
	node, err := nodeOf(ctx)
	if err != nil {
		return err
	}
	b, err := s.bound(node)
	if err != nil {
		return err
	}
	rows, err := s.Log.HubSnapshots(ctx, SnapshotLook)
	if err != nil {
		return s.readErr(err)
	}
	for _, r := range rows { // newest first
		if r.Seq > b {
			continue
		}
		if r.Seq < req.GetAtLeastSeq() {
			break
		}
		name, ok := hashOfRef(r.StoreRef)
		if !ok {
			return status.Error(codes.Internal, "snapshot reference")
		}
		f, size, err := s.openChecked(name, MaxSnapshotBytes)
		if err != nil {
			return s.readErr(err)
		}
		defer f.Close()
		return s.sendFile(ctx, node, f, size, 0, srv)
	}
	return status.Error(codes.FailedPrecondition, "no snapshot in range")
}

// FetchBundle streams one file of a verified bundle. Only the node bundle exists before P6; every other kind is not found.
func (s *Service) FetchBundle(req *hubv1.FetchBundleRequest, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	ctx := srv.Context()
	node, err := nodeOf(ctx)
	if err != nil {
		return err
	}
	if req.GetKind() != signv1.Kind_KIND_NODE {
		return status.Error(codes.NotFound, "no such bundle")
	}
	f, size, err := s.Bundles.OpenBundleFile(req.GetVersion(), req.GetPath())
	if err != nil {
		return status.Error(codes.NotFound, "no such bundle")
	}
	defer f.Close()
	return s.sendFile(ctx, node, f, size, req.GetOffset(), srv)
}

// hashOfRef reads a store reference, which is the lower-case hex of a SHA-256.
func hashOfRef(ref string) ([]byte, bool) {
	if len(ref) != 64 {
		return nil, false
	}
	b, err := hex.DecodeString(ref)
	return b, err == nil
}
