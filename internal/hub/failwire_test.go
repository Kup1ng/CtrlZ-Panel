package hub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// failDB is the L4 pool of the failover loop over one row: pair_event_state, and no node rows or requests.
type failDB struct {
	mu      sync.Mutex
	version uint64
	last    []byte
}

func (f *failDB) HubFailRead(context.Context) (store.HubFailState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return store.HubFailState{Version: f.version, LastTable: f.last}, nil
}

func (f *failDB) HubFailCommit(_ context.Context, ev store.HubFailEvent) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.version + 1
	if ms := uint64(ev.Now.UnixMilli()); ms > v {
		v = ms
	}
	b, err := ev.Table(v)
	if err != nil {
		return 0, err
	}
	f.version, f.last = v, b
	return v, nil
}

func (f *failDB) HubFailDecide(context.Context, uuid.UUID, string, string) error { return nil }
func (f *failDB) HubNodeStateWrite(context.Context, []store.HubNodeState) error  { return nil }

// The hub's default wiring with the log view and the failover loop: a Control stream opened before the start event has committed
// is told to come back (UNAVAILABLE), and once it has, the first messages are ServerTime and the signed PairTable, which verifies
// against the policy key as a pair table.
func TestTheHubTakesControlOnlyAfterItsStartEventAndPushesTheSignedTable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	var fdb *fakeDB
	fail := &failDB{}
	mod := func(d *hub.Deps) {
		d.Next = nil
		d.Stores.Stream, d.Stores.Transfer, d.Stores.Lease = fdb, fdb, fdb
		d.Stores.View, d.Stores.Eval = fdb, fail
		d.PolicyKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		d.ProofKey = make([]byte, 32)
		d.ArtifactsDir = t.TempDir()
	}
	h := newHarnessMod(t, func(d *fakeDB) { fdb = d }, mod)
	e := h.enrol()
	client := hubv1.NewNodeHubClient(h.dial(e.cert))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var sawUnavailable bool
	var pushed *signv1.Envelope
	var gotTime bool
	for pushed == nil {
		if ctx.Err() != nil {
			t.Fatalf("no push (server time %v)", gotTime)
		}
		st, err := client.Control(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = st.Send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: &hubv1.Heartbeat{NodeTime: h.clk.Now().Unix(), NodeVersion: "1", BlobMajorMax: 1}}})
		for pushed == nil {
			m, err := st.Recv()
			if err != nil {
				if code(err) == codes.Unavailable {
					sawUnavailable = true
				}
				time.Sleep(100 * time.Millisecond)
				break
			}
			if m.GetServerTime() != nil {
				gotTime = true
			}
			if m.GetPairTable() != nil {
				if !gotTime {
					t.Fatal("the push came before ServerTime")
				}
				pushed = m.GetPairTable()
			}
		}
	}
	_ = sawUnavailable // the window before the first tick is short and the test does not depend on seeing it
	id := manifest.KeyID(pub)
	root := &signv1.Root{Version: 1, ExpiresAt: 1 << 40, Threshold: 1,
		Keys:  []*signv1.PublicKey{{KeyId: id, Ed25519: pub}},
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{id}, Threshold: 1, ExpiresAt: 1 << 40}}}
	payload, err := manifest.Verify(pushed, root, signv1.Role_ROLE_POLICY, manifest.TypePairTable, h.clk.Now().Unix())
	if err != nil {
		t.Fatalf("the push does not verify: %v", err)
	}
	var pt policyv1.PairTable
	if err := proto.Unmarshal(payload, &pt); err != nil {
		t.Fatal(err)
	}
	fail.mu.Lock()
	defer fail.mu.Unlock()
	if pt.Version != fail.version || pt.Version == 0 {
		t.Fatalf("the push carries version %d, the database holds %d", pt.Version, fail.version)
	}
}
