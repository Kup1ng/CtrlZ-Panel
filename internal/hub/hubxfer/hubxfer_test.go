package hubxfer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubnet"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubsign"
	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubxfer"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

type fakeLog struct {
	rows  []store.LogRow
	snaps []store.SnapshotRow
}

func (f *fakeLog) HubLogHash(_ context.Context, seq uint64) ([]byte, bool, error) {
	for _, r := range f.rows {
		if r.Seq == seq {
			return r.EntryHash, true, nil
		}
	}
	return nil, false, nil
}

func (f *fakeLog) HubLogEntries(_ context.Context, after, upTo uint64, limit, _ int) ([]store.LogRow, error) {
	var out []store.LogRow
	for _, r := range f.rows {
		if r.Seq > after && r.Seq <= upTo && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeLog) HubSnapshots(context.Context, int) ([]store.SnapshotRow, error) {
	return f.snaps, nil
}

type bounds map[uuid.UUID]uint64

func (b bounds) Bound(id uuid.UUID) (uint64, bool) { v, ok := b[id]; return v, ok }

type files map[string][]byte

func (f files) Get(h []byte) ([]byte, error) {
	d, ok := f[hex.EncodeToString(h)]
	if !ok {
		return nil, os.ErrNotExist
	}
	return d, nil
}

type bundles struct{ dir string }

func (b bundles) OpenBundleFile(v uint64, p string) (*os.File, int64, error) {
	if v != 3 || p != "bin/x" {
		return nil, 0, os.ErrNotExist
	}
	f, err := os.Open(filepath.Join(b.dir, "x"))
	if err != nil {
		return nil, 0, err
	}
	st, _ := f.Stat()
	return f, st.Size(), nil
}

// stream is a server stream that records what is sent.
type stream[T any] struct {
	grpc.ServerStream
	ctx  context.Context
	mu   sync.Mutex
	sent []*T
}

func (s *stream[T]) Context() context.Context     { return s.ctx }
func (s *stream[T]) SetHeader(metadata.MD) error  { return nil }
func (s *stream[T]) SendHeader(metadata.MD) error { return nil }
func (s *stream[T]) SetTrailer(metadata.MD)       {}
func (s *stream[T]) SendMsg(any) error            { return nil }
func (s *stream[T]) RecvMsg(any) error            { return nil }
func (s *stream[T]) Send(m *T) error {
	s.mu.Lock()
	s.sent = append(s.sent, m)
	s.mu.Unlock()
	return nil
}
func ctxOf(n uuid.UUID) context.Context {
	return hubnet.WithIdentity(context.Background(), hubnet.Identity{Node: true, NodeID: n})
}

func entry(seq uint64) store.LogRow {
	h := sha256.Sum256([]byte{byte(seq)})
	return store.LogRow{Seq: seq, Class: "policy", EntryHash: h[:], Payload: []byte{byte(seq), 1, 2}}
}

type world struct {
	svc    *hubxfer.Service
	log    *fakeLog
	bounds bounds
	files  files
	pub    ed25519.PublicKey
	a, b   uuid.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x"), bytes.Repeat([]byte("z"), hubxfer.ChunkBytes+5), 0o600); err != nil {
		t.Fatal(err)
	}
	w := &world{log: &fakeLog{}, bounds: bounds{}, files: files{}, pub: pub, a: uuid.New(), b: uuid.New()}
	for i := uint64(1); i <= 5; i++ {
		w.log.rows = append(w.log.rows, entry(i))
	}
	w.svc = hubxfer.New(hubxfer.Service{Log: w.log, Bounds: w.bounds, Files: w.files, Bundles: bundles{dir}, Signer: hubsign.New(priv), Now: time.Now})
	return w
}

// Two nodes on one log, with different bounds: each is told, signed and sent the log up to its own bound and not a
// seq beyond it, by every door that reads the log (GetHead, FetchEntries, GetSnapshot).
func TestEveryDoorStopsAtTheNodesOwnBound(t *testing.T) {
	w := newWorld(t)
	w.bounds[w.a], w.bounds[w.b] = 2, 5
	snapBytes := []byte("snapshot-4")
	sum := sha256.Sum256(snapBytes)
	w.files[hex.EncodeToString(sum[:])] = snapBytes
	w.log.snaps = []store.SnapshotRow{{Seq: 4, StoreRef: hex.EncodeToString(sum[:])}}

	headSeq := func(n uuid.UUID) uint64 {
		env, err := w.svc.GetHead(ctxOf(n), &hubv1.GetHeadRequest{})
		if err != nil {
			t.Fatal(err)
		}
		root := &signv1.Root{Version: 1, ExpiresAt: 1 << 40, Threshold: 1,
			Keys:  []*signv1.PublicKey{{KeyId: manifest.KeyID(w.pub), Ed25519: w.pub}},
			Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{manifest.KeyID(w.pub)}, Threshold: 1, ExpiresAt: 1 << 40}}}
		p, err := manifest.Verify(env, root, signv1.Role_ROLE_POLICY, manifest.TypeHead, time.Now().Unix())
		if err != nil {
			t.Fatalf("head does not verify: %v", err)
		}
		var h signv1.SignedHead
		_ = proto.Unmarshal(p, &h)
		if !bytes.Equal(h.EntryHash, w.log.rows[h.Seq-1].EntryHash) {
			t.Fatalf("head hash is not the entry's")
		}
		return h.Seq
	}
	if headSeq(w.a) != 2 || headSeq(w.b) != 5 {
		t.Fatal("a head names a seq other than the node's bound")
	}

	fetch := func(n uuid.UUID, after uint64) []*hubv1.StoredEntry {
		st := &stream[hubv1.StoredEntry]{ctx: ctxOf(n)}
		if err := w.svc.FetchEntries(&hubv1.FetchEntriesRequest{AfterSeq: after}, st); err != nil {
			t.Fatal(err)
		}
		return st.sent
	}
	if got := fetch(w.a, 0); len(got) != 2 || got[1].Seq != 2 {
		t.Fatalf("node a got %d entries", len(got))
	}
	if got := fetch(w.a, 2); len(got) != 0 {
		t.Fatal("node a was given an entry above its bound")
	}
	if got := fetch(w.b, 3); len(got) != 2 || got[0].Seq != 4 || !bytes.Equal(got[0].EntryBytes, w.log.rows[3].Payload) {
		t.Fatalf("node b got %v", got)
	}

	snap := func(n uuid.UUID, atLeast uint64) error {
		return w.svc.GetSnapshot(&hubv1.GetSnapshotRequest{AtLeastSeq: atLeast}, &stream[hubv1.BlobChunk]{ctx: ctxOf(n)})
	}
	if status.Code(snap(w.a, 0)) != codes.FailedPrecondition {
		t.Fatal("a snapshot above the bound was served")
	}
	if err := snap(w.b, 4); err != nil {
		t.Fatalf("snapshot for b: %v", err)
	}
	if status.Code(snap(w.b, 5)) != codes.FailedPrecondition {
		t.Fatal("a snapshot older than asked was served")
	}
}

// Before the release point is known the hub serves nothing and returns no head (L12).
func TestNothingIsServedWhileTheBoundIsUnknown(t *testing.T) {
	w := newWorld(t)
	if _, err := w.svc.GetHead(ctxOf(w.a), &hubv1.GetHeadRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("head: %v", err)
	}
	if err := w.svc.FetchEntries(&hubv1.FetchEntriesRequest{}, &stream[hubv1.StoredEntry]{ctx: ctxOf(w.a)}); status.Code(err) != codes.Unavailable {
		t.Fatalf("entries: %v", err)
	}
}

// A call that carries no node identity is refused, whatever the interceptors did before it.
func TestACallWithoutAnIdentityIsRefused(t *testing.T) {
	w := newWorld(t)
	if _, err := w.svc.GetHead(context.Background(), &hubv1.GetHeadRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("head: %v", err)
	}
}

func TestBlobResumesAtTheOffsetInChunksAndTheLastIsMarked(t *testing.T) {
	w := newWorld(t)
	data := bytes.Repeat([]byte("b"), hubxfer.ChunkBytes+100)
	sum := sha256.Sum256(data)
	w.files[hex.EncodeToString(sum[:])] = data

	st := &stream[hubv1.BlobChunk]{ctx: ctxOf(w.a)}
	if err := w.svc.FetchBlob(&hubv1.FetchBlobRequest{Hash: sum[:]}, st); err != nil {
		t.Fatal(err)
	}
	if len(st.sent) != 2 || st.sent[0].Last || !st.sent[1].Last || st.sent[1].Offset != hubxfer.ChunkBytes {
		t.Fatalf("chunks: %d", len(st.sent))
	}
	st = &stream[hubv1.BlobChunk]{ctx: ctxOf(w.a)}
	if err := w.svc.FetchBlob(&hubv1.FetchBlobRequest{Hash: sum[:], Offset: hubxfer.ChunkBytes}, st); err != nil || len(st.sent) != 1 || len(st.sent[0].Data) != 100 {
		t.Fatalf("resume: %v", err)
	}
	if err := w.svc.FetchBlob(&hubv1.FetchBlobRequest{Hash: sum[:], Offset: uint64(len(data)) + 1}, &stream[hubv1.BlobChunk]{ctx: ctxOf(w.a)}); status.Code(err) != codes.OutOfRange {
		t.Fatalf("offset past the end: %v", err)
	}
	if err := w.svc.FetchBlob(&hubv1.FetchBlobRequest{Hash: make([]byte, 32)}, &stream[hubv1.BlobChunk]{ctx: ctxOf(w.a)}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown blob: %v", err)
	}
	if err := w.svc.FetchBlob(&hubv1.FetchBlobRequest{Hash: []byte{1}}, &stream[hubv1.BlobChunk]{ctx: ctxOf(w.a)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("short hash: %v", err)
	}
}

func TestBundleServesOnlyTheNodeKindByExactLookup(t *testing.T) {
	w := newWorld(t)
	get := func(k signv1.Kind, v uint64, p string, off uint64) (*stream[hubv1.BlobChunk], error) {
		st := &stream[hubv1.BlobChunk]{ctx: ctxOf(w.a)}
		return st, w.svc.FetchBundle(&hubv1.FetchBundleRequest{Kind: k, Version: v, Path: p, Offset: off}, st)
	}
	st, err := get(signv1.Kind_KIND_NODE, 3, "bin/x", 0)
	if err != nil || len(st.sent) != 2 || !st.sent[1].Last || len(st.sent[1].Data) != 5 {
		t.Fatalf("bundle: %v", err)
	}
	for name, c := range map[string]struct {
		k signv1.Kind
		v uint64
		p string
	}{
		"another kind":    {signv1.Kind_KIND_FILTERS, 3, "bin/x"},
		"another version": {signv1.Kind_KIND_NODE, 4, "bin/x"},
		"another path":    {signv1.Kind_KIND_NODE, 3, "../x"},
	} {
		if _, err := get(c.k, c.v, c.p, 0); status.Code(err) != codes.NotFound {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// All of one node's transfer streams share one bucket: after the burst is spent, the next chunk waits for the rate.
func TestPacingIsPerNodeAndNotPerStream(t *testing.T) {
	w := newWorld(t)
	data := bytes.Repeat([]byte("p"), 6*hubxfer.ChunkBytes)
	sum := sha256.Sum256(data)
	w.files[hex.EncodeToString(sum[:])] = data
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := w.svc.FetchBlob(&hubv1.FetchBlobRequest{Hash: sum[:]}, &stream[hubv1.BlobChunk]{ctx: ctxOf(w.a)}); err != nil {
			t.Fatal(err)
		}
	}
	// 18 chunks of 256 KiB = 4.5 MiB; the burst is 1 MiB and the rate 8 MiB/s, so about 0.4 s must pass.
	if d := time.Since(start); d < 250*time.Millisecond {
		t.Fatalf("4.5 MiB went out in %v: not paced", d)
	}
}
