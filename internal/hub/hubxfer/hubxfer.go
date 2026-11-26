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
	"sync"
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
	"github.com/Kup1ng/CtrlZ-Panel/internal/safego"
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
	// FetchWait is how long a FetchEntries waits for its share of the budget before it answers Unavailable and lets the node
	// retry; it keeps a queue of calls from growing behind a holder (H-r2-1). It is well under the node's idle time for a
	// transfer call (30 s, agent/transfer IdleTimeout): the agent's watchdog starts before it sends the request and resets its
	// connection when no item arrives, so a wait as long as that would end in a stall and a reset and never in this answer
	// (H-r3-1). A test pins the relation to the agent's number.
	FetchWait = 15 * time.Second
	// FetchHold is the longest one FetchEntries may run once it holds its share, reading and sending together. An honest call
	// moves at most 16 MiB at the node's rate (about 2 s); a reader that keeps its socket alive but takes no data loses the share
	// at this deadline, which the transport's write timeout cannot do while no socket write is pending (H-r2-1, H-r2-3).
	FetchHold = 60 * time.Second
	// VerifiedKeep is how long a file that was hashed against its name is trusted again without hashing it (H-r2-2, H-r2-4); it
	// is short enough that a file damaged on the volume is found within minutes.
	VerifiedKeep = 10 * time.Minute
	// VerifiedMax is how many verified files the memo remembers.
	VerifiedMax = 256
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

	// FetchWait and FetchHold override the constants of the same name; zero means the constant (tests set them short).
	FetchWait time.Duration
	FetchHold time.Duration

	pace   *hublimit.Keyed
	budget *semaphore.Weighted

	mu       *sync.Mutex              // a pointer: New takes the Service by value
	fetching map[uuid.UUID]*fetchSlot // nodes with a FetchEntries in flight: one at a time each
	verified map[verifiedKey]time.Time
}

// fetchSlot is a node's one FetchEntries in flight. A newer call of the same node ends it (H-r3-2).
type fetchSlot struct{ stop func() }

// verifiedKey names a file as it was when it was hashed. The artifacts are content-addressed and never rewritten, so the
// size and modification time say the file is the one that was checked.
type verifiedKey struct {
	hash string
	size int64
	mod  int64
}

// New makes a Service, with its pacing bucket.
func New(s Service) *Service {
	if s.Now == nil {
		s.Now = appclock.Now
	}
	s.pace = hublimit.NewKeyed(BytesPerSecond, 4*ChunkBytes, s.Now)
	s.budget = semaphore.NewWeighted(FetchBudget)
	s.mu = new(sync.Mutex)
	s.fetching = map[uuid.UUID]*fetchSlot{}
	s.verified = map[verifiedKey]time.Time{}
	if s.FetchWait <= 0 {
		s.FetchWait = FetchWait
	}
	if s.FetchHold <= 0 {
		s.FetchHold = FetchHold
	}
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
	// The honest agent fetches one batch at a time, so a node holds at most one share. Without this, the eight transfer slots of a
	// node (hubnet.MaxTransfers) would be eight shares, and one node could hold the whole budget against every other (H-r2-3).
	// A newer call takes the slot over and ends the older one, as a new Control stream ends the older one: the agent that opens a
	// new call has given up the old one (its watchdog reset the connection), and the hub may not have seen the old connection die
	// yet, so refusing the new call would hold the node's log catch-up back for as long as the old handler lives (H-r3-2).
	parent := srv.Context()
	ctx, cancel := context.WithCancel(parent)
	slot := &fetchSlot{}
	slot.stop = sync.OnceFunc(func() {
		cancel()
		hubnet.AbortFrom(parent)()
	})
	s.mu.Lock()
	old := s.fetching[node]
	s.fetching[node] = slot
	s.mu.Unlock()
	if old != nil {
		old.stop()
	}
	leave := func() {
		cancel()
		s.mu.Lock()
		if s.fetching[node] == slot {
			delete(s.fetching, node)
		}
		s.mu.Unlock()
	}
	handedOver := false
	defer func() {
		if !handedOver {
			leave()
		}
	}()
	// The reservation covers the rows until the last one is sent. The wait for it and the hold of it are both bounded, so a
	// stalled reader frees its share at the deadline and a queue behind it moves on.
	need := int64(MaxFetchBytes + wire.MaxEntrySize)
	wctx, wcancel := context.WithTimeout(ctx, s.FetchWait)
	err = s.budget.Acquire(wctx, need)
	wcancel()
	if err != nil {
		if ctx.Err() == nil {
			return status.Error(codes.Unavailable, "busy, try again")
		}
		return status.FromContextError(ctx.Err()).Err()
	}
	holdEnd := time.Now().Add(s.FetchHold) // the real clock: the context's deadline below runs on it too
	err = s.within(ctx, s.FetchHold, func(ctx context.Context) error {
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
	})
	handedOver = true
	s.settle(hubnet.EndedFrom(parent), holdEnd, slot, func() {
		leave()
		s.budget.Release(need)
	})
	return err
}

// settle gives the share and the node's slot back once the call's HTTP stream is over, not when the handler returns. Under gRPC's
// ServeHTTP the answer is written after the handler returns, and a node that gives its stream no window keeps that write, and the
// entries it holds, for as long as it likes; counting the bytes as free at the handler's return would let eight such streams per
// node hold memory outside the budget (H-r3-3). A stream that is still not over at the end of the hold is ended, as a registry kill
// ends it. A call with no root handler (a test) has its stream over already, and nothing waits.
func (s *Service) settle(ended <-chan struct{}, holdEnd time.Time, slot *fetchSlot, release func()) {
	select {
	case <-ended:
		release()
		return
	default:
	}
	safego.Go(s.Logger, unitFetch, func() {
		t := time.NewTimer(time.Until(holdEnd))
		defer t.Stop()
		select {
		case <-ended:
		case <-t.C:
			slot.stop() // the stream's write fails, so what it holds goes with it
		}
		release()
	})
}

// within runs fn under a deadline and returns when fn does or the deadline passes (or the call is ended), whichever is first. A
// Send that waits for flow control cannot be interrupted from the handler, so fn runs on its own goroutine and the handler
// returns without it. Returning alone does not end the HTTP stream: the hub serves NodeHub through grpc's ServeHTTP, where a
// write that waits for a window holds the stream's goroutine, its slots and the entries in flight until the peer goes away. So
// the handler ends the stream itself, as a registry kill does, before it returns; that fails the pending Send and lets the
// goroutine go, and the memory it holds is freed with the share (H-r3-3).
func (s *Service) within(parent context.Context, d time.Duration, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, d)
	defer cancel()
	done := make(chan error, 1)
	safego.Go(s.Logger, unitFetch, func() {
		err := status.Error(codes.Internal, "read") // what a panic in fn leaves, so the handler does not wait for the deadline
		defer func() { done <- err }()
		err = fn(ctx)
	})
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		hubnet.AbortFrom(parent)()
		return status.FromContextError(ctx.Err()).Err()
	}
}

// openChecked opens the file of a hash and checks its bytes against the name by streaming them through the open handle, so
// no more than a small buffer is held and the file that was checked is the one that is sent. A file above max, or one that
// is not there, is os.ErrNotExist; one whose bytes are not its name is refused and never sent under a name it does not have.
//
// Hashing is work the node asks for, so it is paid for: a call that sends no byte (offset at or past the end) does not hash, a
// file hashed within VerifiedKeep is not hashed again, and a hash that is done is charged to the node's transfer rate like the
// bytes it would send (H-r2-2, H-r2-4).
func (s *Service) openChecked(ctx context.Context, node uuid.UUID, hash []byte, max int64, offset uint64) (*os.File, int64, error) {
	f, size, err := s.Files.Open(hash)
	if err != nil {
		return nil, 0, err
	}
	if size > max {
		f.Close()
		return nil, 0, os.ErrNotExist
	}
	if offset >= uint64(size) {
		return f, size, nil // only an empty last chunk goes out; sendFile refuses an offset past the end
	}
	key := verifiedKey{hash: string(hash), size: size}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	key.mod = st.ModTime().UnixNano()
	if s.isVerified(key) {
		return f, size, nil
	}
	if err := s.take(ctx, node, int(size)); err != nil {
		f.Close()
		return nil, 0, err
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
	s.markVerified(key)
	return f, size, nil
}

func (s *Service) isVerified(k verifiedKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.verified[k]
	if ok && s.Now().Sub(at) >= VerifiedKeep {
		delete(s.verified, k)
		return false
	}
	return ok
}

func (s *Service) markVerified(k verifiedKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	for len(s.verified) >= VerifiedMax {
		var oldest verifiedKey
		var oldestAt time.Time
		for old, at := range s.verified {
			if oldestAt.IsZero() || at.Before(oldestAt) {
				oldest, oldestAt = old, at
			}
		}
		delete(s.verified, oldest)
	}
	s.verified[k] = now
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
	f, size, err := s.openChecked(ctx, node, req.GetHash(), MaxBlobBytes, req.GetOffset())
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
		f, size, err := s.openChecked(ctx, node, name, MaxSnapshotBytes, 0)
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

// unit names the goroutine of a FetchEntries for the log of a kept panic (a closed value, never a request detail).
type unit string

const unitFetch unit = "hub_fetch"

func (u unit) Valid() bool { return u == unitFetch }
