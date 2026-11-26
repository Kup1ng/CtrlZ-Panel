// Package hubxfer serves the transfer RPCs of NodeHub: GetHead, FetchEntries, FetchBlob, GetSnapshot and FetchBundle
// (SC 12, p4-nodes 5.2, 6.4, 6.5).
//
// One rule runs through the first three that read the log: nothing above the node's bound is named, signed, sent or put in
// a snapshot, where the bound is the lower of the release point and the node's rollout cursor (hubroll.Roll.Bound). The
// bound is read once per call, so a call never mixes two answers of it.
//
// Blobs and bundles come from files, never from a database connection (5.7): the two transfer connections are for the
// log and the snapshot rows alone, so a flood of blob fetches cannot starve the head.
//
// Each node's transfer items are paced to 8 MiB/s in chunks of 256 KiB, all of its streams together (D31, L6), by one
// bucket per node_id, so a node that fetches a large blob over eight streams gets the same share as one that fetches it over one.
package hubxfer

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"

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

// Files reads a content-addressed file and checks its bytes against the name (compiler.Artifacts' Get).
type Files interface {
	Get(hash []byte) ([]byte, error)
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
	Now     func() time.Time
	Logger  *slog.Logger

	pace *hublimit.Keyed
}

// New makes a Service, with its pacing bucket.
func New(s Service) *Service {
	if s.Now == nil {
		s.Now = appclock.Now
	}
	s.pace = hublimit.NewKeyed(BytesPerSecond, 4*ChunkBytes, s.Now)
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

// sendChunks sends data from offset in chunks, paced, the last marked.
func (s *Service) sendChunks(ctx context.Context, node uuid.UUID, data []byte, offset uint64, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	if offset > uint64(len(data)) {
		return status.Error(codes.OutOfRange, "offset past the end")
	}
	for {
		end := min(offset+ChunkBytes, uint64(len(data)))
		if err := s.take(ctx, node, int(end-offset)); err != nil {
			return err
		}
		if err := srv.Send(&hubv1.BlobChunk{Offset: offset, Data: data[offset:end], Last: end == uint64(len(data))}); err != nil {
			return err
		}
		offset = end
		if offset == uint64(len(data)) {
			return nil
		}
	}
}

// FetchBlob streams a blob from the offset. The hash names the file and Get checks the bytes against it, so a file
// that is damaged on the volume is refused and never sent under a name it does not have.
func (s *Service) FetchBlob(req *hubv1.FetchBlobRequest, srv grpc.ServerStreamingServer[hubv1.BlobChunk]) error {
	ctx := srv.Context()
	node, err := nodeOf(ctx)
	if err != nil {
		return err
	}
	if len(req.GetHash()) != 32 {
		return status.Error(codes.InvalidArgument, "hash")
	}
	data, err := s.Files.Get(req.GetHash())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return status.Error(codes.NotFound, "no such blob")
		}
		return s.readErr(err)
	}
	return s.sendChunks(ctx, node, data, req.GetOffset(), srv)
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
		data, err := s.Files.Get(name)
		if err != nil {
			return s.readErr(err)
		}
		return s.sendChunks(ctx, node, data, 0, srv)
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
	if req.GetOffset() > uint64(size) {
		return status.Error(codes.OutOfRange, "offset past the end")
	}
	if _, err := f.Seek(int64(req.GetOffset()), io.SeekStart); err != nil {
		return status.Error(codes.Internal, "seek")
	}
	off := req.GetOffset()
	buf := make([]byte, ChunkBytes)
	for {
		n, rerr := io.ReadFull(f, buf)
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			return status.Error(codes.Internal, "read")
		}
		last := off+uint64(n) >= uint64(size)
		if n > 0 || last {
			if err := s.take(ctx, node, n); err != nil {
				return err
			}
			if err := srv.Send(&hubv1.BlobChunk{Offset: off, Data: buf[:n], Last: last}); err != nil {
				return err
			}
			off += uint64(n)
		}
		if last || rerr != nil {
			return nil
		}
	}
}

// hashOfRef reads a store reference, which is the lower-case hex of a SHA-256.
func hashOfRef(ref string) ([]byte, bool) {
	if len(ref) != 64 {
		return nil, false
	}
	b, err := hex.DecodeString(ref)
	return b, err == nil
}
