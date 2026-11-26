package hub_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// fakeDB is the hub's database for the tests that run without a container: the same statements of
// internal/store/hub.go, written as their rules (what the SQL's WHERE says), so a test of the hub reads
// the hub's behaviour and not Postgres. The statements themselves are tested against Postgres in
// internal/store (hub_test.go).
type fakeDB struct {
	mu sync.Mutex

	enr   map[uuid.UUID]*fEnr
	nodes map[uuid.UUID]*fNode
	cas   map[string][]*fCA
	zones store.HubZones

	jobs       []string // reinstall kind of each queued domain_change
	alerts     int
	kinds      []store.HubAlertKind
	alertErr   error // when set, an alert insert fails
	replaceErr error // when set, a CA row write fails
	loads      int
	downErr    error // when set, node reads fail (a database outage)
	log        []store.LogRow
}

type fEnr struct {
	tokenHash []byte
	state     string
	expired   bool
	bound     netip.Prefix
	csr, spki []byte
	from      netip.Addr
	node      uuid.UUID
	cert      []byte
}

type fNode struct {
	status, serial, prev string
	spki                 []byte
}

type fCA struct {
	row     store.HubCertRow
	retired bool
}

func newFakeDB() *fakeDB {
	return &fakeDB{enr: map[uuid.UUID]*fEnr{}, nodes: map[uuid.UUID]*fNode{}, cas: map[string][]*fCA{}}
}

// issueToken is what the admin route does: a row in state issued.
func (d *fakeDB) issueToken(hash []byte, bound netip.Prefix) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enr[uuid.New()] = &fEnr{tokenHash: hash, state: "issued", bound: bound}
}

func (d *fakeDB) expireToken(hash []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.enr {
		if bytes.Equal(e.tokenHash, hash) {
			e.expired = true
		}
	}
}

// confirm is the admin's fingerprint confirmation: the pending node row with the record's key.
func (d *fakeDB) confirm(id uuid.UUID) uuid.UUID {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.enr[id]
	n := uuid.New()
	d.nodes[n] = &fNode{status: "pending", spki: e.spki}
	e.state, e.node = "approved", n
	return n
}

func (d *fakeDB) setStatus(n uuid.UUID, s string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes[n].status = s
}

func (d *fakeDB) node(n uuid.UUID) fNode {
	d.mu.Lock()
	defer d.mu.Unlock()
	return *d.nodes[n]
}

// ---- hubenroll.Store, hubinstall.TokenChecker ----

func (d *fakeDB) HubEnroll(_ context.Context, in store.HubEnrollIn) (uuid.UUID, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, e := range d.enr {
		if !bytes.Equal(e.tokenHash, in.TokenHash) || e.state != "issued" || e.expired {
			continue
		}
		if e.bound.IsValid() && !e.bound.Contains(in.From) {
			continue
		}
		e.state, e.csr, e.spki, e.from = "pending_approval", in.CSR, in.SPKI, in.From
		return id, hex.EncodeToString(in.SPKI), nil
	}
	return uuid.Nil, "", store.ErrEnrollRefused
}

func (d *fakeDB) HubTokenLive(_ context.Context, hash []byte) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range d.enr {
		if bytes.Equal(e.tokenHash, hash) && e.state == "issued" && !e.expired {
			return true, nil
		}
	}
	return false, nil
}

func (d *fakeDB) HubEnrollmentLoad(_ context.Context, id uuid.UUID) (store.HubEnrollment, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.enr[id]
	if !ok {
		return store.HubEnrollment{}, false, nil
	}
	out := store.HubEnrollment{State: e.state, CSR: e.csr, SPKI: e.spki, CertDER: e.cert, NodeID: e.node}
	if n := d.nodes[e.node]; n != nil {
		out.NodeStatus, out.NodeSPKI = n.status, n.spki
	}
	return out, true, nil
}

func (d *fakeDB) HubIssueCert(_ context.Context, enrollment, node uuid.UUID, nodeSPKI []byte, serial string, _, _ time.Time, certDER []byte) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := d.enr[enrollment]
	if e == nil || e.state != "approved" || e.cert != nil || e.node != node {
		return false, nil
	}
	n := d.nodes[node]
	if n == nil || n.status != "active" || !bytes.Equal(n.spki, nodeSPKI) || n.serial != "" {
		return false, store.ErrNodeGone
	}
	e.cert, n.serial = certDER, serial
	return true, nil
}

// ---- hubnodes.NodeReader, Renewer, PrevClearer ----

func (d *fakeDB) HubNodeLoad(_ context.Context, id uuid.UUID) (store.HubNode, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loads++
	if d.downErr != nil {
		return store.HubNode{}, false, d.downErr
	}
	n := d.nodes[id]
	if n == nil {
		return store.HubNode{}, false, nil
	}
	return store.HubNode{Status: n.status, SPKI: n.spki, CertSerial: n.serial, PrevCertSerial: n.prev}, true, nil
}

func (d *fakeDB) HubRenewCert(_ context.Context, node uuid.UUID, nodeSPKI []byte, presented, serial string, _, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.nodes[node]
	if n == nil || n.status != "active" || !bytes.Equal(n.spki, nodeSPKI) || (n.serial != presented && n.prev != presented) {
		return store.ErrNodeGone
	}
	if n.serial == presented {
		n.prev = n.serial
	}
	n.serial = serial
	return nil
}

func (d *fakeDB) HubClearPrevSerial(_ context.Context, node uuid.UUID, current string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if n := d.nodes[node]; n != nil && n.serial == current {
		n.prev = ""
	}
	return nil
}

func (d *fakeDB) HubNodeAddrs(context.Context) (store.HubAddrs, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out store.HubAddrs
	for id, n := range d.nodes {
		if n.status != "revoked" {
			out.Nodes = append(out.Nodes, id)
		}
	}
	for _, e := range d.enr {
		// An approved enrolment counts only while its node is not revoked (the join of qHubEnrolledFrom).
		if !e.from.IsValid() || (e.state == "approved" && (d.nodes[e.node] == nil || d.nodes[e.node].status == "revoked")) {
			continue
		}
		out.Addrs = append(out.Addrs, e.from)
	}
	return out, nil
}

// ---- hubtrust.Rows and Alerter ----

func (d *fakeDB) HubActiveCA(_ context.Context, kind string) (store.HubCertRow, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := len(d.cas[kind]) - 1; i >= 0; i-- {
		if c := d.cas[kind][i]; !c.retired {
			return c.row, true, nil
		}
	}
	return store.HubCertRow{}, false, nil
}

func (d *fakeDB) HubReplaceCA(_ context.Context, kind string, old uuid.UUID, chain string, nb, na time.Time, names []string, queue bool, reinstall string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.replaceErr != nil {
		return d.replaceErr
	}
	for _, c := range d.cas[kind] {
		if c.row.ID == old {
			c.retired = true
		}
	}
	d.cas[kind] = append(d.cas[kind], &fCA{row: store.HubCertRow{ID: uuid.New(), ChainPEM: chain, NotBefore: nb, NotAfter: na, Names: names}})
	if queue {
		d.jobs = append(d.jobs, reinstall)
	}
	return nil
}

func (d *fakeDB) HubLiveZones(context.Context) (store.HubZones, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.zones, nil
}

func (d *fakeDB) HubAlert(_ context.Context, _ string, kind store.HubAlertKind, _ map[string]string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.alertErr != nil {
		return d.alertErr
	}
	d.alerts++
	d.kinds = append(d.kinds, kind)
	return nil
}
