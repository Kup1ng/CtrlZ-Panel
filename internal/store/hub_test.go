package store_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// These tests run the hub's statements (internal/store/hub.go) as ctrlz_hub against the migrated schema,
// so what the hub's grants, the row-level policies of migration 0100 and the freeze trigger allow is what
// the statements meet. Nothing here is tenant data: the enrolment, node and certificate tables are global.

type hubFx struct {
	ctx context.Context
	db  *testpg.DB
	hub *store.Store
}

func newHubFx(t *testing.T) *hubFx {
	t.Helper()
	c := testpg.Need(t, cluster)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	db := c.NewDB(ctx, t)
	return &hubFx{ctx: ctx, db: db, hub: db.Store(ctx, t, store.RoleHub)}
}

func tokenHash(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func (f *hubFx) issueToken(t *testing.T, hash []byte, bound string, minutes int) {
	t.Helper()
	var boundArg any
	if bound != "" {
		boundArg = bound
	}
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at, bound_ip) VALUES ($1, now() + make_interval(mins => $2::int), $3::text::inet)`,
		hash, minutes, boundArg); err != nil {
		t.Fatal(err)
	}
}

func enrollIn(hash []byte, from string) store.HubEnrollIn {
	return store.HubEnrollIn{
		TokenHash: hash, CSR: []byte("csr-der"), SPKI: bytes.Repeat([]byte{7}, 32), Hostname: "node1.example.net",
		OSRelease: "Ubuntu 24.04", NodeVersion: "0.4.0",
		DNSBind: netip.MustParseAddr("10.0.0.5"), DNSAdv: netip.MustParseAddr("203.0.113.5"),
		ProxyBind: netip.MustParseAddr("10.0.0.6"), ProxyAdv: netip.MustParseAddr("203.0.113.6"),
		From: netip.MustParseAddr(from),
	}
}

func TestHubEnrollWritesTheRecordOnce(t *testing.T) {
	f := newHubFx(t)
	f.issueToken(t, tokenHash(1), "", 15)
	id, fp, err := f.hub.HubEnroll(f.ctx, enrollIn(tokenHash(1), "198.51.100.9"))
	if err != nil {
		t.Fatal(err)
	}
	want := "0707070707070707070707070707070707070707070707070707070707070707"
	if fp != want {
		t.Fatalf("fingerprint %s", fp)
	}
	var state, host string
	var from string
	if err := f.db.Scan(f.ctx, `SELECT state, hostname, host(enrolled_from) FROM ctrlz.node_enrollments WHERE id = $1`, []any{id}, &state, &host, &from); err != nil {
		t.Fatal(err)
	}
	if state != "pending_approval" || host != "node1.example.net" || from != "198.51.100.9" {
		t.Fatalf("row: %s %s %s", state, host, from)
	}
	// The same token again: used. Unknown token: refused. Neither writes anything.
	if _, _, err := f.hub.HubEnroll(f.ctx, enrollIn(tokenHash(1), "198.51.100.9")); !errors.Is(err, store.ErrEnrollRefused) {
		t.Fatalf("second Enroll: %v", err)
	}
	if _, _, err := f.hub.HubEnroll(f.ctx, enrollIn(tokenHash(9), "198.51.100.9")); !errors.Is(err, store.ErrEnrollRefused) {
		t.Fatalf("unknown token: %v", err)
	}
	// Used, so no longer live for a bundle download.
	if live, err := f.hub.HubTokenLive(f.ctx, tokenHash(1)); err != nil || live {
		t.Fatalf("a used token is live: %v %v", live, err)
	}
}

func TestHubEnrollExpiryAndBoundAddress(t *testing.T) {
	f := newHubFx(t)
	f.issueToken(t, tokenHash(2), "", -1) // already expired
	if _, _, err := f.hub.HubEnroll(f.ctx, enrollIn(tokenHash(2), "198.51.100.9")); !errors.Is(err, store.ErrEnrollRefused) {
		t.Fatalf("an expired token: %v", err)
	}
	if live, _ := f.hub.HubTokenLive(f.ctx, tokenHash(2)); live {
		t.Fatal("an expired token is live")
	}
	f.issueToken(t, tokenHash(3), "10.0.0.0/8", 15)
	if live, err := f.hub.HubTokenLive(f.ctx, tokenHash(3)); err != nil || !live {
		t.Fatalf("a fresh token: %v %v", live, err)
	}
	if _, _, err := f.hub.HubEnroll(f.ctx, enrollIn(tokenHash(3), "198.51.100.9")); !errors.Is(err, store.ErrEnrollRefused) {
		t.Fatalf("a source outside bound_ip: %v", err)
	}
	if _, _, err := f.hub.HubEnroll(f.ctx, enrollIn(tokenHash(3), "10.1.2.3")); err != nil {
		t.Fatalf("a source inside bound_ip: %v", err)
	}
}

// approved makes the state the admin leaves: the enrolment approved and its node row, in the given status.
func (f *hubFx) approved(t *testing.T, hash []byte, status string) (enr, node uuid.UUID, spki []byte) {
	t.Helper()
	f.issueToken(t, hash, "", 15)
	in := enrollIn(hash, "198.51.100.9")
	in.SPKI = bytes.Repeat([]byte{hash[0]}, 32)
	enr, _, err := f.hub.HubEnroll(f.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	node = uuid.New()
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.nodes (id, slot, name, status, spki_sha256) VALUES ($1, $2, 'n', $3, $4)`, node, int(hash[0]), status, in.SPKI); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.node_enrollments SET state = 'approved', node_id = $2 WHERE id = $1`, enr, node); err != nil {
		t.Fatal(err)
	}
	return enr, node, in.SPKI
}

func TestHubIssueCertOnce(t *testing.T) {
	f := newHubFx(t)
	enr, node, spki := f.approved(t, tokenHash(1), "active")
	e, found, err := f.hub.HubEnrollmentLoad(f.ctx, enr)
	if err != nil || !found || e.State != "approved" || e.NodeID != node || e.NodeStatus != "active" || !bytes.Equal(e.NodeSPKI, spki) || e.CertDER != nil {
		t.Fatalf("load: %+v %v %v", e, found, err)
	}
	nb := time.Now().Add(-time.Minute)
	issued, err := f.hub.HubIssueCert(f.ctx, enr, node, spki, "abc123", nb, nb.Add(30*24*time.Hour), []byte("cert-1"))
	if err != nil || !issued {
		t.Fatalf("first issue: %v %v", issued, err)
	}
	// A replayed Poll cannot move cert_serial: the second statement matches nothing.
	issued, err = f.hub.HubIssueCert(f.ctx, enr, node, spki, "def456", nb, nb.Add(30*24*time.Hour), []byte("cert-2"))
	if err != nil || issued {
		t.Fatalf("second issue: %v %v", issued, err)
	}
	var serial, cert string
	if err := f.db.Scan(f.ctx, `SELECT n.cert_serial, convert_from(e.cert_der, 'UTF8') FROM ctrlz.nodes n, ctrlz.node_enrollments e WHERE n.id = $1 AND e.id = $2`, []any{node, enr}, &serial, &cert); err != nil {
		t.Fatal(err)
	}
	if serial != "abc123" || cert != "cert-1" {
		t.Fatalf("stored %s %s", serial, cert)
	}
	var certs int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.node_certs WHERE node_id = $1`, []any{node}, &certs); err != nil || certs != 1 {
		t.Fatalf("node_certs rows: %d %v", certs, err)
	}
	// The node and the row are frozen: the certificate of the enrolment never changes, for any role.
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.node_enrollments SET cert_der = '\x00' WHERE id = $1`, enr); err == nil {
		t.Fatal("the certificate of an enrolment changed")
	}
}

func TestHubIssueCertRefusesANodeThatIsNotActive(t *testing.T) {
	f := newHubFx(t)
	enr, node, spki := f.approved(t, tokenHash(2), "pending")
	nb := time.Now()
	if _, err := f.hub.HubIssueCert(f.ctx, enr, node, spki, "abc", nb, nb.Add(time.Hour), []byte("c")); !errors.Is(err, store.ErrNodeGone) {
		t.Fatalf("a pending node: %v", err)
	}
	// Nothing was written: not the enrolment's certificate, not a node_certs row.
	var withCert, certs int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.node_enrollments WHERE id = $1 AND cert_der IS NOT NULL`, []any{enr}, &withCert); err != nil || withCert != 0 {
		t.Fatalf("a refused issue left a certificate: %d %v", withCert, err)
	}
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.node_certs WHERE node_id = $1`, []any{node}, &certs); err != nil || certs != 0 {
		t.Fatalf("a refused issue left a node_certs row: %d %v", certs, err)
	}
	// Another key than the row's is refused the same way.
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.nodes SET status = 'active' WHERE id = $1`, node); err != nil {
		t.Fatal(err)
	}
	if _, err := f.hub.HubIssueCert(f.ctx, enr, node, bytes.Repeat([]byte{9}, 32), "abc", nb, nb.Add(time.Hour), []byte("c")); !errors.Is(err, store.ErrNodeGone) {
		t.Fatalf("another key: %v", err)
	}
}

func TestHubRenewKeepsThePreviousSerial(t *testing.T) {
	f := newHubFx(t)
	enr, node, spki := f.approved(t, tokenHash(3), "active")
	nb := time.Now()
	if _, err := f.hub.HubIssueCert(f.ctx, enr, node, spki, "s1", nb, nb.Add(time.Hour), []byte("c")); err != nil {
		t.Fatal(err)
	}
	read := func() store.HubNode {
		n, found, err := f.hub.HubNodeLoad(f.ctx, node)
		if err != nil || !found {
			t.Fatalf("load: %v %v", found, err)
		}
		return n
	}
	// s1 renews to s2: s1 becomes the previous serial.
	if err := f.hub.HubRenewCert(f.ctx, node, spki, "s1", "s2", nb, nb.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := read(); n.CertSerial != "s2" || n.PrevCertSerial != "s1" || n.Status != "active" {
		t.Fatalf("after the first renewal: %+v", n)
	}
	// The response was lost: the node renews with s1 again. s2 is dropped, s1 stays the previous one.
	if err := f.hub.HubRenewCert(f.ctx, node, spki, "s1", "s3", nb, nb.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := read(); n.CertSerial != "s3" || n.PrevCertSerial != "s1" {
		t.Fatalf("after the second renewal: %+v", n)
	}
	// A serial that is neither of the two, and another key, are refused with nothing written.
	if err := f.hub.HubRenewCert(f.ctx, node, spki, "s2", "s4", nb, nb.Add(time.Hour)); !errors.Is(err, store.ErrNodeGone) {
		t.Fatalf("a dropped serial: %v", err)
	}
	if err := f.hub.HubRenewCert(f.ctx, node, bytes.Repeat([]byte{1}, 32), "s3", "s4", nb, nb.Add(time.Hour)); !errors.Is(err, store.ErrNodeGone) {
		t.Fatalf("another key: %v", err)
	}
	// The first use of s3 clears the previous serial, and only for the current one.
	if err := f.hub.HubClearPrevSerial(f.ctx, node, "s2"); err != nil {
		t.Fatal(err)
	}
	if n := read(); n.PrevCertSerial != "s1" {
		t.Fatalf("a clear for a serial that is not current cleared it: %+v", n)
	}
	if err := f.hub.HubClearPrevSerial(f.ctx, node, "s3"); err != nil {
		t.Fatal(err)
	}
	if n := read(); n.PrevCertSerial != "" {
		t.Fatalf("the previous serial is still there: %+v", n)
	}
	var certs int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.node_certs WHERE node_id = $1`, []any{node}, &certs); err != nil || certs != 3 {
		t.Fatalf("node_certs rows: %d %v (the first issue and two renewals)", certs, err)
	}
	// A revoked node renews nothing.
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = $1`, node); err != nil {
		t.Fatal(err)
	}
	if err := f.hub.HubRenewCert(f.ctx, node, spki, "s3", "s5", nb, nb.Add(time.Hour)); !errors.Is(err, store.ErrNodeGone) {
		t.Fatalf("a revoked node renewed: %v", err)
	}
}

func TestHubNodeAddrs(t *testing.T) {
	f := newHubFx(t)
	_, node, _ := f.approved(t, tokenHash(4), "active")
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.nodes SET dns_advertised_ip = '203.0.113.50' WHERE id = $1`, node); err != nil {
		t.Fatal(err)
	}
	got, err := f.hub.HubNodeAddrs(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	addrs := got.Addrs
	if len(got.Nodes) != 1 || got.Nodes[0] != node {
		t.Fatalf("non-revoked nodes: %v", got.Nodes)
	}
	has := map[string]bool{}
	for _, a := range addrs {
		has[a.String()] = true
	}
	// The address of the enrolment's Enroll call, and the advertised one of the node.
	if !has["198.51.100.9"] || !has["203.0.113.50"] {
		t.Fatalf("addresses: %v", addrs)
	}
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = $1`, node); err != nil {
		t.Fatal(err)
	}
	got, _ = f.hub.HubNodeAddrs(f.ctx)
	for _, a := range got.Addrs {
		// The node's own address and the address its enrolment came from: neither survives the revocation.
		if a.String() == "203.0.113.50" || a.String() == "198.51.100.9" {
			t.Fatalf("a revoked node's address %s is still in the set", a)
		}
	}
	if len(got.Nodes) != 0 {
		t.Fatalf("a revoked node is listed: %v", got.Nodes)
	}
}

func TestHubCARowsAndJobs(t *testing.T) {
	f := newHubFx(t)
	if _, found, err := f.hub.HubActiveCA(f.ctx, store.CertKindZoneCA); err != nil || found {
		t.Fatalf("an empty table: %v %v", found, err)
	}
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(1000*time.Hour)
	if err := f.hub.HubReplaceCA(f.ctx, store.CertKindZoneCA, uuid.Nil, "PEM-1", nb, na, []string{"dns.example.ir"}, false, ""); err != nil {
		t.Fatal(err)
	}
	r1, found, err := f.hub.HubActiveCA(f.ctx, store.CertKindZoneCA)
	if err != nil || !found || r1.ChainPEM != "PEM-1" || len(r1.Names) != 1 || r1.Names[0] != "dns.example.ir" {
		t.Fatalf("row 1: %+v %v %v", r1, found, err)
	}
	// A replacement retires the old row and queues one domain_change; a second one while it is queued adds none.
	if err := f.hub.HubReplaceCA(f.ctx, store.CertKindZoneCA, r1.ID, "PEM-2", nb.Add(time.Minute), na, []string{"dns.example.ir"}, true, "same_key"); err != nil {
		t.Fatal(err)
	}
	r2, _, _ := f.hub.HubActiveCA(f.ctx, store.CertKindZoneCA)
	if r2.ChainPEM != "PEM-2" || r2.ID == r1.ID {
		t.Fatalf("row 2: %+v", r2)
	}
	if err := f.hub.HubReplaceCA(f.ctx, store.CertKindZoneCA, r2.ID, "PEM-3", nb.Add(2*time.Minute), na, []string{"dns.example.ir"}, true, "new_key"); err != nil {
		t.Fatalf("a second job while one is queued: %v", err)
	}
	var jobs, active int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'domain_change' AND state = 'queued'`, nil, &jobs); err != nil || jobs != 1 {
		t.Fatalf("queued domain_change jobs: %d %v", jobs, err)
	}
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.certificates WHERE kind = 'zone_ca' AND state = 'active'`, nil, &active); err != nil || active != 1 {
		t.Fatalf("active zone_ca rows: %d %v", active, err)
	}
	// The policy of migration 0100: the hub writes the rows of the two private CAs and no other kind.
	if err := f.hub.HubReplaceCA(f.ctx, "wildcard", uuid.Nil, "x", nb, na, nil, false, ""); err == nil {
		t.Fatal("the hub wrote a certificate of kind wildcard")
	}
}

// I-r1-4: replacing the node CA row writes the critical alert in the same transaction; the first row writes none.
func TestHubReplacingTheNodeCAWritesItsAlertWithTheRow(t *testing.T) {
	f := newHubFx(t)
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(1000*time.Hour)
	alerts := func() int {
		var n int
		if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.alerts WHERE kind = 'node_ca_changed'`, nil, &n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := f.hub.HubReplaceCA(f.ctx, store.CertKindNodeCA, uuid.Nil, "CA-1", nb, na, nil, false, ""); err != nil || alerts() != 0 {
		t.Fatalf("the first node CA row: %v, %d alerts", err, alerts())
	}
	r1, _, _ := f.hub.HubActiveCA(f.ctx, store.CertKindNodeCA)
	if err := f.hub.HubReplaceCA(f.ctx, store.CertKindNodeCA, r1.ID, "CA-2", nb.Add(time.Minute), na, nil, false, ""); err != nil || alerts() != 1 {
		t.Fatalf("a replaced node CA row: %v, %d alerts", err, alerts())
	}
}

func TestHubLiveZonesAndAlert(t *testing.T) {
	f := newHubFx(t)
	z, err := f.hub.HubLiveZones(f.ctx)
	if err != nil || z.DNSZone != "" || z.PrevDNSZone != "" || !z.TransitionUntil.IsZero() {
		t.Fatalf("no domain: %+v %v", z, err)
	}
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.domain_settings SET dns_zone = 'dns.example.ir', prev_dns_zone = 'dns.old.ir', transition_until = now() + interval '1 day'`); err != nil {
		t.Fatal(err)
	}
	z, err = f.hub.HubLiveZones(f.ctx)
	if err != nil || z.DNSZone != "dns.example.ir" || z.PrevDNSZone != "dns.old.ir" || !z.TransitionUntil.After(time.Now()) {
		t.Fatalf("zones: %+v %v", z, err)
	}
	if err := f.hub.HubAlert(f.ctx, "warning", store.HubAlertZoneCAReissued, map[string]string{"reinstall": "same_key"}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.db.Scan(f.ctx, `SELECT count(*) FROM ctrlz.alerts WHERE kind = 'zone_ca_reissued'`, nil, &n); err != nil || n != 1 {
		t.Fatalf("alerts: %d %v", n, err)
	}
}
