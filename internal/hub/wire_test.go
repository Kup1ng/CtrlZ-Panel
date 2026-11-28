package hub_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	hubv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/hub/v1"
	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The default wiring of the hub, through the real listener, the checks at open and the registry: a node with a certificate
// opens Control, sends its Heartbeat, and is told the time, the head it may read and its config and certificate; GetHead
// then names that head under a signature the policy key made, and FetchEntries gives the entries up to it.
func TestTheHubServesControlAndTransferThroughTheDoor(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	var fdb *fakeDB
	pre := func(d *fakeDB) {
		fdb = d
		for i := uint64(1); i <= 3; i++ {
			sum := sha256.Sum256([]byte{byte(i)})
			d.log = append(d.log, store.LogRow{Seq: i, Class: "policy", EntryHash: sum[:], Payload: []byte{byte(i)}})
		}
	}
	mod := func(d *hub.Deps) {
		d.Next = nil
		d.Stores.Stream, d.Stores.Transfer, d.Stores.Lease = fdb, fdb, fdb
		d.PolicyKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		d.ProofKey = make([]byte, 32)
		d.ArtifactsDir = t.TempDir()
	}
	h := newHarnessMod(t, pre, mod)
	e := h.enrol()
	cc := h.dial(e.cert)
	client := hubv1.NewNodeHubClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := client.Control(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&hubv1.NodeMessage{Body: &hubv1.NodeMessage_Heartbeat{Heartbeat: &hubv1.Heartbeat{
		NodeTime: h.clk.Now().Unix(), NodeVersion: "1", BlobMajorMax: 1}}}); err != nil {
		t.Fatal(err)
	}
	var st1, head, cfg, cert bool
	for !(st1 && head && cfg && cert) {
		m, err := st.Recv()
		if err != nil {
			t.Fatalf("recv: %v (time %v head %v config %v cert %v)", err, st1, head, cfg, cert)
		}
		switch {
		case m.GetServerTime() != nil:
			st1 = true
		case m.GetHeadNotice() != nil:
			head = true
			if m.GetHeadNotice().Seq != 3 {
				t.Fatalf("head notice %d", m.GetHeadNotice().Seq)
			}
		case m.GetNodeConfig() != nil:
			cfg = true
		case m.GetCertBundle() != nil:
			cert = true
		}
	}

	env, err := client.GetHead(ctx, &hubv1.GetHeadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	id := manifest.KeyID(pub)
	root := &signv1.Root{Version: 1, ExpiresAt: 1 << 40, Threshold: 1,
		Keys:  []*signv1.PublicKey{{KeyId: id, Ed25519: pub}},
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_POLICY, KeyIds: [][]byte{id}, Threshold: 1, ExpiresAt: 1 << 40}}}
	payload, err := manifest.Verify(env, root, signv1.Role_ROLE_POLICY, manifest.TypeHead, h.clk.Now().Unix())
	if err != nil {
		t.Fatalf("the head does not verify: %v", err)
	}
	var sh signv1.SignedHead
	if err := proto.Unmarshal(payload, &sh); err != nil || sh.Seq != 3 {
		t.Fatalf("head %v %v", &sh, err)
	}
	fe, err := client.FetchEntries(ctx, &hubv1.FetchEntriesRequest{AfterSeq: 1})
	if err != nil {
		t.Fatal(err)
	}
	var seqs []uint64
	for {
		m, err := fe.Recv()
		if err != nil {
			break
		}
		seqs = append(seqs, m.Seq)
	}
	if len(seqs) != 2 || seqs[0] != 2 || seqs[1] != 3 {
		t.Fatalf("entries %v", seqs)
	}
	// The bundle door is the manifest's: a path the manifest does not list is not found.
	bs, err := client.FetchBundle(ctx, &hubv1.FetchBundleRequest{Kind: signv1.Kind_KIND_NODE, Version: 1, Path: "no/such"})
	if err == nil {
		_, err = bs.Recv()
	}
	if code(err) != 5 { // NotFound
		t.Fatalf("an unlisted bundle path: %v", err)
	}
	_ = fdb
}
