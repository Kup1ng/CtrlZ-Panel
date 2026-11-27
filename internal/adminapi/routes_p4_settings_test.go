package adminapi

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/adminapi/gen"
	"github.com/Kup1ng/CtrlZ-Panel/internal/intakeseal"
)

// The tests of the free DNS, domain and certificate routes (p4-nodes 4.3, 9.2, 10.4). Like the node routes' they run against
// Postgres through the real handler, the real grants and the real triggers.

type freeDNSBody struct {
	Enabled bool  `json:"enabled"`
	Qps     int   `json:"qps"`
	Version int64 `json:"version"`
}

// TestFreeDNSSettings covers GET and PUT /settings/free-dns (Plan T-556).
func TestFreeDNSSettings(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	var f freeDNSBody
	b.get("/settings/free-dns").want(200, "").json(&f)
	if !f.Enabled || f.Qps != 1000 {
		t.Fatalf("the defaults are on at 1000, got %+v", f)
	}
	// 0 and anything above the ceiling of T-374 (2000 until it is measured) are refused, and nothing is written.
	for _, qps := range []int{0, 2001, 50000} {
		b.put("/settings/free-dns", map[string]any{"enabled": true, "qps": qps}).want(422, "qps_out_of_range")
	}
	// A negative number is outside the schema's range (minimum 0), so the boundary refuses it before the ceiling is asked.
	b.put("/settings/free-dns", map[string]any{"enabled": true, "qps": -1}).want(400, "bad_request")
	if r.auditCount(t, "settings.free_dns") != 0 {
		t.Fatal("a refused change left an audit row")
	}
	outbox := r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`)
	var g freeDNSBody
	b.put("/settings/free-dns", map[string]any{"enabled": false, "qps": 2000}).want(200, "").json(&g)
	if g.Enabled || g.Qps != 2000 || g.Version <= f.Version {
		t.Fatalf("after the change %+v (was %+v): the version must move", g, f)
	}
	if r.auditCount(t, "settings.free_dns") != 1 {
		t.Fatal("no audit row of the change")
	}
	// The same values change nothing: no write, so no new version for the nodes to react to, and no audit row.
	var same freeDNSBody
	b.put("/settings/free-dns", map[string]any{"enabled": false, "qps": 2000}).want(200, "").json(&same)
	if same.Version != g.Version || r.auditCount(t, "settings.free_dns") != 1 {
		t.Fatalf("a repeat moved the version or wrote an audit row: %+v", same)
	}
	b.get("/settings/free-dns").want(200, "").json(&same)
	if same != g {
		t.Fatalf("GET after PUT: %+v, want %+v", same, g)
	}
	// No route writes policy_outbox (T-081): the compiler reads the version itself.
	if r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`) != outbox {
		t.Fatal("the change wrote a policy outbox row")
	}
}

// TestFreeDNSCounters covers GET /free-dns/counters: hourly rows, paged, and no name or address in a row.
func TestFreeDNSCounters(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	now := time.Now().UTC().Truncate(time.Hour)
	other := r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "counters-other")
	for _, row := range []struct {
		node, proto, outcome string
		rcode                int
		hours                int
		count                int64
	}{
		{seedNode1, "udp", "answered", 0, 2, 100}, {seedNode1, "udp", "answered", 3, 2, 7}, {seedNode1, "tcp", "answered", 0, 1, 40},
		{seedNode2, "udp", "refused", 5, 1, 9}, {other, "udp", "answered", 0, 1, 11}, {seedNode1, "udp", "answered", 0, 40 * 24, 5},
	} {
		r.env.Exec(t, `INSERT INTO ctrlz.free_dns_counters (node_id, bucket_start, protocol, outcome, rcode, count) VALUES ($1, $2, $3, $4, $5, $6)`,
			row.node, now.Add(-time.Duration(row.hours)*time.Hour), row.proto, row.outcome, row.rcode, row.count)
	}
	type row struct {
		NodeID      string `json:"node_id"`
		BucketStart string `json:"bucket_start"`
		Transport   string `json:"transport"`
		Outcome     string `json:"outcome"`
		Rcode       int    `json:"rcode"`
		Count       int64  `json:"count"`
	}
	type page struct {
		Items      []row   `json:"items"`
		NextCursor *string `json:"next_cursor"`
	}
	var p page
	b.get("/free-dns/counters").want(200, "").json(&p)
	if len(p.Items) != 5 {
		t.Fatalf("the default window is the last day: got %d rows, want the 5 within 3 hours", len(p.Items))
	}
	for i := 1; i < len(p.Items); i++ {
		if p.Items[i-1].BucketStart > p.Items[i].BucketStart {
			t.Fatalf("rows are not in time order: %+v", p.Items)
		}
	}
	// A row carries these six columns and no other: no name, no address.
	raw := b.get("/free-dns/counters").want(200, "")
	for _, key := range []string{`"qname"`, `"name"`, `"ip"`, `"address"`, `"cidr"`, `"client"`} {
		if strings.Contains(string(raw.Body), key) {
			t.Errorf("a counter row names %s", key)
		}
	}
	// One node.
	b.get("/free-dns/counters?node_id="+other).want(200, "").json(&p)
	if len(p.Items) != 1 || p.Items[0].NodeID != other || p.Items[0].Count != 11 {
		t.Fatalf("one node: %+v", p.Items)
	}
	// Pages follow the primary key and lose nothing.
	var seen []row
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		path := "/free-dns/counters?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var pg page
		b.get(path).want(200, "").json(&pg)
		seen = append(seen, pg.Items...)
		if pg.NextCursor == nil {
			break
		}
		cursor = *pg.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("paged read gave %d rows, want 5", len(seen))
	}
	// A wider window reaches the old row; a window past 31 days, and one that ends before it starts, are refused.
	from := now.Add(-45 * 24 * time.Hour).Format(time.RFC3339)
	to := now.Add(-35 * 24 * time.Hour).Format(time.RFC3339)
	b.get("/free-dns/counters?from="+from+"&to="+to).want(200, "").json(&p)
	if len(p.Items) != 1 || p.Items[0].Count != 5 {
		t.Fatalf("the old window: %+v", p.Items)
	}
	b.get("/free-dns/counters?from="+from).want(422, "validation_failed")
	b.get("/free-dns/counters?from="+to+"&to="+from).want(422, "validation_failed")
	b.get("/free-dns/counters?cursor="+"AAAA").want(400, "bad_request")
}

// TestDomainSettings covers GET and PUT /settings/domain and its impact (10.4).
func TestDomainSettings(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	type view struct {
		DNSZone          string  `json:"dns_zone"`
		PanelHost        string  `json:"panel_host"`
		AdminHost        string  `json:"admin_host"`
		PrevDNSZone      string  `json:"prev_dns_zone"`
		TransitionUntil  *string `json:"transition_until"`
		AppliedPanelHost string  `json:"applied_panel_host"`
		ApplyPending     bool    `json:"apply_pending"`
	}
	jobs := func() int {
		return r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'domain_change' AND state = 'queued'`)
	}
	var v view
	// Decoding into a view that already holds a value keeps the members the answer leaves out (an unset host is not sent), so each
	// answer is read into an empty one.
	fresh := func(p *view) *view { *p = view{}; return p }
	b.get("/settings/domain").want(200, "").json(fresh(&v))
	if v.DNSZone != "" || v.ApplyPending {
		t.Fatalf("a fresh panel has no zone and nothing pending: %+v", v)
	}

	// Every refusal writes nothing.
	for name, body := range map[string]map[string]any{
		"not a dns. zone":            {"dns_zone": "example.ir"},
		"a public suffix":            {"dns_zone": "dns.co.ir"},
		"one label after dns.":       {"dns_zone": "dns.ir"},
		"a panel under the zone":     {"dns_zone": "dns.example.ir", "panel_host": "panel.dns.example.ir"},
		"an admin equal to the zone": {"dns_zone": "dns.example.ir", "admin_host": "dns.example.ir"},
		"one name for both hosts":    {"dns_zone": "dns.example.ir", "panel_host": "p.example.ir", "admin_host": "p.example.ir"},
	} {
		t.Run(name, func(t *testing.T) { b.put("/settings/domain", body).want(422, "domain_invalid") })
	}
	if r.auditCount(t, "settings.domain") != 0 || jobs() != 0 {
		t.Fatal("a refused change left an audit row or a job")
	}

	// A port is no part of a hostname: the schema refuses it before the rules are asked.
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "p.example.ir:8443"}).want(400, "bad_request")

	// A first set starts no transition, queues the job, and stamps changed_at.
	b.put("/settings/domain", map[string]any{"dns_zone": "DNS.Example.ir", "panel_host": "panel.example.ir", "admin_host": "admin.example.ir"}).want(200, "").json(fresh(&v))
	if v.DNSZone != "dns.example.ir" || v.PrevDNSZone != "" || v.TransitionUntil != nil || !v.ApplyPending {
		t.Fatalf("a first set: %+v (lower case, no transition, an apply pending)", v)
	}
	if jobs() != 1 || r.auditCount(t, "settings.domain") != 1 {
		t.Fatalf("a first set: %d jobs, %d audit rows", jobs(), r.auditCount(t, "settings.domain"))
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.domain_settings WHERE changed_at IS NOT NULL AND prev_dns_zone IS NULL`) != 1 {
		t.Fatal("changed_at is not stamped, or a first set started a transition")
	}
	// A host-only edit queues nothing and starts no transition.
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "panel2.example.ir", "admin_host": "admin.example.ir"}).want(200, "").json(fresh(&v))
	if v.PanelHost != "panel2.example.ir" || v.PrevDNSZone != "" || jobs() != 1 || r.auditCount(t, "settings.domain") != 2 {
		t.Fatalf("a host edit: %+v, %d jobs", v, jobs())
	}
	// The same values change nothing.
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "panel2.example.ir", "admin_host": "admin.example.ir"}).want(200, "")
	if r.auditCount(t, "settings.domain") != 2 {
		t.Fatal("a repeat wrote an audit row")
	}
	// A change of zone from one value to another starts the transition and supersedes the unfinished job.
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.new.ir", "transition_days": 7}).want(200, "").json(fresh(&v))
	if v.DNSZone != "dns.new.ir" || v.PrevDNSZone != "dns.example.ir" || v.TransitionUntil == nil || v.PanelHost != "" {
		t.Fatalf("a zone change: %+v", v)
	}
	if jobs() != 1 || r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'domain_change' AND state = 'failed' AND progress @> '{"superseded": true}'`) != 1 {
		t.Fatal("the zone change did not supersede the unfinished domain_change job")
	}
	// While the transition runs another change of zone is refused, and a host under the old zone is too.
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.third.ir"}).want(409, "transition_active")
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.new.ir", "panel_host": "p.dns.example.ir"}).want(422, "domain_invalid")
	// After it ends the zone may change again.
	r.env.Exec(t, `UPDATE ctrlz.domain_settings SET transition_until = now() - interval '1 hour'`)
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.third.ir"}).want(200, "").json(fresh(&v))
	if v.PrevDNSZone != "dns.new.ir" {
		t.Fatalf("the earlier zone is the one before: %+v", v)
	}
	// Impact: the counts are the database's.
	var im struct {
		Endpoints     int64 `json:"endpoints"`
		AppleProfiles int64 `json:"apple_profiles"`
	}
	b.get("/settings/domain/impact").want(200, "").json(&im)
	if int(im.Endpoints) != r.count(t, `SELECT count(*) FROM ctrlz.endpoints`) {
		t.Fatalf("impact %+v", im)
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox WHERE aggregate_type = 'domain_settings'`) != 0 {
		t.Fatal("the domain route wrote a policy outbox row")
	}
}

// ---------------------------------------------------------------------------
// Certificates

// testCA is a private root with one intermediate; the rig verifies upload chains against it (Deps.certRoots), where
// production uses the embedded public roots.
type testCA struct {
	inter *x509.Certificate
	ikey  *ecdsa.PrivateKey
	pool  *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	now := time.Now()
	rkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(1000 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, err := x509.CreateCertificate(rand.Reader, rt, rt, &rkey.PublicKey, rkey)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(rder)
	ikey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(900 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ider, err := x509.CreateCertificate(rand.Reader, it, root, &ikey.PublicKey, rkey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(ider)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &testCA{inter: inter, ikey: ikey, pool: pool}
}

// leaf returns the chain PEM (leaf, intermediate) and the leaf's key as PKCS #8 PEM.
func (c *testCA) leaf(t *testing.T, life time.Duration, names ...string) (chain, key string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(life), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.inter, &k.PublicKey, c.ikey)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.inter.Raw})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

// intakeRig is a rig whose upload route has intake keys and trusts the test root, and the two private halves.
type intakeRig struct {
	*rig
	ca           *testCA
	wildcardPriv []byte
	webPriv      []byte
}

func newIntakeRig(t *testing.T) *intakeRig {
	t.Helper()
	r := newRig(t)
	ca, wp, bp := r.withIntake(t)
	return &intakeRig{rig: r, ca: ca, wildcardPriv: wp, webPriv: bp}
}

// withIntake gives the rig's handler the two intake public keys and a private root to trust, and returns the root and the
// two private halves a test opens the seals with.
func (r *rig) withIntake(t *testing.T) (ca *testCA, wildcardPriv, webPriv []byte) {
	t.Helper()
	ca = newTestCA(t)
	mk := func() (priv []byte, pub intakeseal.PublicKey) {
		k, _ := ecdh.X25519().GenerateKey(rand.Reader)
		pk, _ := x509.MarshalPKCS8PrivateKey(k)
		pb, _ := x509.MarshalPKIXPublicKey(k.PublicKey())
		pub, err := intakeseal.ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb}))
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), pub
	}
	wp, wpub := mk()
	bp, bpub := mk()
	r.h = r.handler(t, func(d *Deps) { d.Intake = &Intake{Wildcard: wpub, Web: bpub}; d.certRoots = ca.pool })
	return ca, wp, bp
}

// certBody is the body of POST /certificates.
func certBody(kind, chain, key string) map[string]any {
	return map[string]any{"kind": kind, "chain_pem": chain, "key_pem": key}
}

type certCreated struct {
	ID       string   `json:"id"`
	Names    []string `json:"names"`
	NotAfter string   `json:"not_after"`
}

// TestUploadCertificate covers POST /certificates (4.3): the checks, the seal and what is stored.
func TestUploadCertificate(t *testing.T) {
	r := newIntakeRig(t)
	b, _ := r.admin(t)
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "panel.example.ir", "admin_host": "admin.example.ir"}).want(200, "")
	day := 24 * time.Hour
	zone := []string{"dns.example.ir", "*.dns.example.ir", "*.verify.dns.example.ir"}
	rows := func() int { return r.count(t, `SELECT count(*) FROM ctrlz.certificates WHERE source = 'uploaded'`) }

	// A good wildcard is stored active, with its names and end from the leaf, and its key sealed to the wildcard intake.
	chain, key := r.ca.leaf(t, 60*day, zone...)
	var c certCreated
	b.post("/certificates", certBody("wildcard", chain, key)).want(201, "").json(&c)
	if len(c.Names) != 3 || c.ID == "" {
		t.Fatalf("created %+v", c)
	}
	var state, source string
	var names []string
	var sealed []byte
	r.env.Scan(t, `SELECT state, source, names FROM ctrlz.certificates WHERE id = $1`, []any{c.ID}, &state, &source, &names)
	if state != "active" || source != "uploaded" || len(names) != 3 {
		t.Fatalf("stored %s %s %v", state, source, names)
	}
	// The sealed key is read as the owner (the admin has no grant to read it) and opens only with the wildcard intake key.
	r.env.Scan(t, `SELECT wrapped_key_ct FROM ctrlz.certificates WHERE id = $1`, []any{c.ID}, &sealed)
	if strings.Contains(string(sealed), "PRIVATE KEY") {
		t.Fatal("the stored key is not sealed")
	}
	got, err := intakeseal.Open(r.wildcardPriv, intakeseal.Wildcard, sealed)
	if err != nil || !strings.Contains(string(got), "BEGIN PRIVATE KEY") {
		t.Fatalf("the wildcard intake key does not open it: %v", err)
	}
	if _, err := intakeseal.Open(r.webPriv, intakeseal.Web, sealed); err == nil {
		t.Fatal("the web intake key opened a wildcard key")
	}
	if r.auditCount(t, "certificate.upload") != 1 {
		t.Fatal("no audit row of the upload")
	}
	// Nothing of the key or the chain is in the log, the audit row or the answer.
	var audited string
	r.env.Scan(t, `SELECT coalesce(string_agg(params::text || target, ' '), '') FROM ctrlz.audit_log WHERE action = 'certificate.upload'`, nil, &audited)
	for _, secret := range []string{"PRIVATE KEY", strings.SplitN(key, "\n", 3)[1], "BEGIN CERTIFICATE"} {
		if strings.Contains(audited, secret) {
			t.Errorf("the audit row holds %q", secret[:min(12, len(secret))])
		}
	}
	r.assertQuiet(t, strings.SplitN(key, "\n", 3)[1])

	// A panel certificate is sealed to the web intake key.
	pchain, pkey := r.ca.leaf(t, 60*day, "panel.example.ir")
	var pc certCreated
	b.post("/certificates", certBody("panel", pchain, pkey)).want(201, "").json(&pc)
	r.env.Scan(t, `SELECT wrapped_key_ct FROM ctrlz.certificates WHERE id = $1`, []any{pc.ID}, &sealed)
	if _, err := intakeseal.Open(r.webPriv, intakeseal.Web, sealed); err != nil {
		t.Fatalf("the web intake key does not open a panel key: %v", err)
	}

	// The refusals, each writing nothing.
	before := rows()
	short, shortKey := r.ca.leaf(t, 6*day, zone...)
	outside, outsideKey := r.ca.leaf(t, 60*day, append([]string{"www.example.ir"}, zone...)...)
	oneLabel, oneLabelKey := r.ca.leaf(t, 60*day, "dns.example.ir", "*.dns.example.ir")
	elsewhere, elsewhereKey := r.ca.leaf(t, 60*day, "dns.other.ir", "*.dns.other.ir", "*.verify.dns.other.ir")
	wrongHost, wrongHostKey := r.ca.leaf(t, 60*day, "other.example.ir")
	private := newTestCA(t) // a root the panel does not trust
	privChain, privKey := private.leaf(t, 60*day, zone...)
	_, strangerKey := r.ca.leaf(t, 60*day, zone...)
	// The codes are written out, one call each, so each is asserted where the document promises it.
	b.post("/certificates", certBody("wildcard", chain, strangerKey)).want(422, "cert_key_mismatch")                                                                                                                   // a key of another certificate
	b.post("/certificates", certBody("wildcard", short, shortKey)).want(422, "cert_expiring")                                                                                                                          // less than 7 days left
	b.post("/certificates", certBody("wildcard", outside, outsideKey)).want(422, "cert_invalid")                                                                                                                       // a SAN outside the zone
	b.post("/certificates", certBody("wildcard", oneLabel, oneLabelKey)).want(422, "cert_invalid")                                                                                                                     // one name of the three missing
	b.post("/certificates", certBody("wildcard", elsewhere, elsewhereKey)).want(422, "cert_invalid")                                                                                                                   // a zone that is not live
	b.post("/certificates", certBody("panel", wrongHost, wrongHostKey)).want(422, "cert_invalid")                                                                                                                      // a panel chain for another host
	b.post("/certificates", certBody("wildcard", privChain, privKey)).want(422, "cert_not_public")                                                                                                                     // a chain to a root the panel does not trust
	b.post("/certificates", certBody("wildcard", chain, "-----BEGIN PRIV"+"ATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIV"+"ATE KEY-----\n")).want(422, "cert_invalid") // a key that is not a key
	b.post("/certificates", certBody("wildcard", key, key)).want(422, "cert_invalid")                                                                                                                                  // a chain that is a key
	if rows() != before || r.auditCount(t, "certificate.upload") != 2 {
		t.Fatalf("a refused upload stored a row or audited: %d rows, %d audit rows", rows(), r.auditCount(t, "certificate.upload"))
	}
	// The kind is closed by the schema.
	b.post("/certificates", certBody("node_ca", chain, key)).want(400, "bad_request")

	// The list shows the rows and never a chain or a key.
	var page struct {
		Items []struct {
			ID     string   `json:"id"`
			Kind   string   `json:"kind"`
			Source string   `json:"source"`
			State  string   `json:"state"`
			Names  []string `json:"names"`
		} `json:"items"`
	}
	raw := b.get("/certificates").want(200, "")
	raw.json(&page)
	if len(page.Items) < 2 || page.Items[0].ID != pc.ID {
		t.Fatalf("the list is newest first, got %+v", page.Items)
	}
	for _, leak := range []string{"BEGIN", "chain_pem", "wrapped_key", "key_pem"} {
		if strings.Contains(string(raw.Body), leak) {
			t.Errorf("the list shows %q", leak)
		}
	}

	// Retire: an active uploaded row only, once.
	b.post("/certificates/"+c.ID+":retire", nil).want(204, "")
	b.post("/certificates/"+c.ID+":retire", nil).want(404, "not_found")
	b.post("/certificates/"+uuid.NewString()+":retire", nil).want(404, "not_found")
	var issued string
	r.env.Scan(t, `INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, source) VALUES ('zone_ca', 'x', now(), now() + interval '1 day', 'active', 'issued') RETURNING id::text`, nil, &issued)
	b.post("/certificates/"+issued+":retire", nil).want(404, "not_found") // a private CA's row is the hub's
	if r.auditCount(t, "certificate.retire") != 1 {
		t.Fatalf("%d retire audit rows, want 1", r.auditCount(t, "certificate.retire"))
	}
}

// TestUploadNeedsAnIntake: with no intake key mounted the route answers service_unavailable and stores nothing.
func TestUploadNeedsAnIntake(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	ca := newTestCA(t)
	chain, key := ca.leaf(t, 60*24*time.Hour, "panel.example.test")
	b.post("/certificates", map[string]any{"kind": "panel", "chain_pem": chain, "key_pem": key}).want(503, "service_unavailable")
	if r.count(t, `SELECT count(*) FROM ctrlz.certificates WHERE source = 'uploaded'`) != 0 {
		t.Fatal("a row was stored with no intake key")
	}
}

// TestApplyPendingFollowsTheChoiceRule: an uploaded certificate that the choice rule now picks for a host, and that the last
// apply did not use, makes the apply pending (3.2 item 6); once the apply has used it, nothing is pending.
func TestApplyPendingFollowsTheChoiceRule(t *testing.T) {
	r := newIntakeRig(t)
	b, _ := r.admin(t)
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "panel.example.ir", "admin_host": "admin.example.ir"}).want(200, "")
	// What `ctrlz domain-apply` does at its end: the requested hosts become the applied ones.
	r.env.Exec(t, `UPDATE ctrlz.domain_settings SET applied_panel_host = panel_host, applied_admin_host = admin_host, applied_at = now()`)
	var v struct {
		ApplyPending bool `json:"apply_pending"`
	}
	b.get("/settings/domain").want(200, "").json(&v)
	if v.ApplyPending {
		t.Fatal("nothing is pending after an apply with no certificate")
	}
	chain, key := r.ca.leaf(t, 60*24*time.Hour, "panel.example.ir")
	var c certCreated
	b.post("/certificates", map[string]any{"kind": "panel", "chain_pem": chain, "key_pem": key}).want(201, "").json(&c)
	b.get("/settings/domain").want(200, "").json(&v)
	if !v.ApplyPending {
		t.Fatal("a new panel certificate is not applied yet, so an apply is pending")
	}
	r.env.Exec(t, `UPDATE ctrlz.domain_settings SET applied_panel_cert_id = $1`, c.ID)
	b.get("/settings/domain").want(200, "").json(&v)
	if v.ApplyPending {
		t.Fatal("the apply used the chosen row, so nothing is pending")
	}
	b.post("/certificates/"+c.ID+":retire", nil).want(204, "")
	b.get("/settings/domain").want(200, "").json(&v)
	if !v.ApplyPending {
		t.Fatal("a retired certificate that was applied makes the apply pending (the choice is now none)")
	}
}

// TestSettingsRoutesNeedAFreshAdmin: every change asks for a code of the last five minutes, and the reads do not.
func TestSettingsRoutesNeedAFreshAdmin(t *testing.T) {
	r := newIntakeRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() - interval '10 minutes'`)
	id := uuid.NewString()
	b.put("/settings/free-dns", map[string]any{"enabled": true, "qps": 10}).want(403, "totp_fresh_required")
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir"}).want(403, "totp_fresh_required")
	b.post("/certificates", map[string]any{"kind": "panel", "chain_pem": "-----BEGIN CERTIFICATE-----" + strings.Repeat("A", 60), "key_pem": "-----BEGIN PRIV" + "ATE KEY-----" + strings.Repeat("A", 60)}).want(403, "totp_fresh_required")
	b.post("/certificates/"+id+":retire", nil).want(403, "totp_fresh_required")
	for _, path := range []string{"/overview", "/free-dns/counters", "/settings/free-dns", "/settings/domain", "/settings/domain/impact", "/certificates"} {
		b.get(path).want(200, "")
	}
}

// TestOverview covers GET /overview: the nodes, the head of the log and the free DNS switch, and a rate summed over the
// nodes that reported one.
func TestOverview(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET version_info = '{"qps": 100, "cache_hit_permille": 900}'::jsonb WHERE id = $1`, seedNode1)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET version_info = '{"qps": 300, "cache_hit_permille": 500}'::jsonb WHERE id = $1`, seedNode2)
	var o struct {
		Nodes      []map[string]any `json:"nodes"`
		ConfigHead int64            `json:"config_head"`
		Qps        *int             `json:"qps"`
		Cache      *int             `json:"cache_hit_permille"`
		FreeDNS    struct {
			Enabled bool `json:"enabled"`
		} `json:"free_dns"`
	}
	b.get("/overview").want(200, "").json(&o)
	if len(o.Nodes) != r.count(t, `SELECT count(*) FROM ctrlz.nodes`) || !o.FreeDNS.Enabled {
		t.Fatalf("overview %+v", o)
	}
	if o.Qps == nil || *o.Qps != 400 || o.Cache == nil || *o.Cache != 600 {
		t.Fatalf("the global rates are the sum and the QPS-weighted mean (400 and 600), got %v and %v", fmt.Sprint(o.Qps), fmt.Sprint(o.Cache))
	}
	if want := r.count(t, `SELECT coalesce(max(seq), 0) FROM ctrlz.config_log`); int(o.ConfigHead) != want {
		t.Fatalf("config_head %d, want %d", o.ConfigHead, want)
	}
}

// TestGlobalRatesWeighsOnlyNodesWithARate: a node that reports a QPS and no hit rate must not dilute the rate of the
// others (R34-r1-3).
func TestGlobalRatesWeighsOnlyNodesWithARate(t *testing.T) {
	i := func(v int) *int { return &v }
	active := gen.NodeViewStatusActive
	nodes := []gen.NodeView{
		{Status: active, Qps: i(1000), CacheHitPermille: i(800)},
		{Status: active, Qps: i(1000)},
		{Status: active, CacheHitPermille: i(100)}, // a rate and no QPS: no weight
		{Status: gen.NodeViewStatusPending, Qps: i(5000), CacheHitPermille: i(0)},
	}
	qps, hit := globalRates(nodes)
	if qps == nil || *qps != 2000 || hit == nil || *hit != 800 {
		t.Errorf("qps %v, hit %v; want 2000 and 800", qps, hit)
	}
	// No node reports a QPS: the plain mean of the rates.
	_, hit = globalRates([]gen.NodeView{{Status: active, CacheHitPermille: i(100)}, {Status: active, CacheHitPermille: i(300)}})
	if hit == nil || *hit != 200 {
		t.Errorf("plain mean %v, want 200", hit)
	}
}

// TestCounterCursorRefusesWhatPostgresWouldRefuse: a cursor is client text, so a NUL, invalid UTF-8 or a second out of the
// range of a timestamp is a 400 and never a driver error (R34-r1-11).
func TestCounterCursorRefusesWhatPostgresWouldRefuse(t *testing.T) {
	id := uuid.NewString()
	enc := func(sec, outcome string) *string {
		s := encodeKey(sec, id, "udp", outcome, "0")
		return &s
	}
	if _, err := counterCursor(enc("1700000000", "answered")); err != nil {
		t.Fatalf("a good cursor is refused: %v", err)
	}
	for name, c := range map[string]*string{
		"a NUL":              enc("1700000000", "a\x00b"),
		"invalid UTF-8":      enc("1700000000", "a\xffb"),
		"a capital":          enc("1700000000", "Answered"),
		"too long":           enc("1700000000", strings.Repeat("a", 33)),
		"empty":              enc("1700000000", ""),
		"a huge second":      enc("9223372036854775807", "answered"),
		"a negative second":  enc("-1", "answered"),
		"a second past 9999": enc("253402300800", "answered"),
	} {
		if _, err := counterCursor(c); err == nil {
			t.Errorf("%s: the cursor was accepted", name)
		}
	}
}

// TestApplyPendingIgnoresAnEmptyRequestedHost: once domain-apply has set an applied host, a requested host that is empty
// asks for nothing and must not keep the flag up for good (R34-r1-1, r1-9); and a zone that would swallow the host that
// serves now is refused even though the request names no host (R34-r1-10).
func TestApplyPendingIgnoresAnEmptyRequestedHost(t *testing.T) {
	r := newIntakeRig(t)
	b, _ := r.admin(t)
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir"}).want(200, "")
	r.env.Exec(t, `UPDATE ctrlz.domain_settings SET applied_panel_host = 'panel.example.ir', applied_admin_host = 'admin.example.ir', applied_at = now()`)
	var v struct {
		ApplyPending bool `json:"apply_pending"`
	}
	b.get("/settings/domain").want(200, "").json(&v)
	if v.ApplyPending {
		t.Fatal("no host is requested and the applied ones serve: nothing is pending")
	}
	// A requested host that differs is pending.
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "other.example.ir"}).want(200, "")
	b.get("/settings/domain").want(200, "").json(&v)
	if !v.ApplyPending {
		t.Fatal("a requested host that is not applied is pending")
	}
	// The host that serves now lies under the zone the request sets.
	r.env.Exec(t, `UPDATE ctrlz.domain_settings SET applied_panel_host = 'panel.dns.new.ir'`)
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.new.ir"}).want(422, "domain_invalid")
}

// T-105 (10.5): in production Passkey turns on only when nothing waits to be applied and the panel certificate the last apply
// used is an active uploaded row that covers the served host and verifies to the public roots. The rig trusts its test root in
// place of the embedded public ones. Each refusal below is one condition: dropping the applied-host test accepts the first,
// and dropping the apply_pending test accepts the second, the third and the retired case of step 5.
func TestPasskeyInProductionNeedsAnAppliedPublicPanelCert(t *testing.T) {
	r := newIntakeRig(t)
	b, _ := r.admin(t)
	prod := r.handler(t, func(d *Deps) { d.Env = EnvProduction; d.certRoots = r.ca.pool })
	enable := func() *aresp {
		return b.callOn(prod, adminHost, "PUT", "/settings/webauthn", map[string]any{"rp_id": "example.ir", "enabled": true})
	}
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "panel.example.ir", "admin_host": "admin.example.ir"}).want(200, "")

	// 1. Nothing was applied: the panel is served by the private CA of the first install.
	enable().want(422, "cert_not_public")

	// 2. A public certificate is uploaded and the host is requested, but domain-apply has not run: the change is pending.
	chain, key := r.ca.leaf(t, 60*24*time.Hour, "panel.example.ir")
	var c certCreated
	b.post("/certificates", certBody("panel", chain, key)).want(201, "").json(&c)
	enable().want(422, "cert_not_public")

	// 3. The apply used a row the choice rule no longer picks (the longer-lived one is in force now): the change waits.
	apply := func(cert any) {
		r.env.Exec(t, `UPDATE ctrlz.domain_settings SET applied_panel_host = 'panel.example.ir', applied_admin_host = 'admin.example.ir', applied_panel_cert_id = $1, applied_at = now()`, cert)
	}
	var other certCreated
	chain2, key2 := r.ca.leaf(t, 30*24*time.Hour, "panel.example.ir")
	b.post("/certificates", certBody("panel", chain2, key2)).want(201, "").json(&other)
	apply(other.ID) // the shorter row, so the choice rule picks the first one: an apply that is behind the rule
	enable().want(422, "cert_not_public")

	// 4. The apply used the row the rule picks: accepted, and the setting is stored.
	apply(c.ID)
	var cfg struct {
		Enabled bool `json:"enabled"`
	}
	enable().want(200, "").json(&cfg)
	if !cfg.Enabled {
		t.Fatal("Passkey was not enabled over an applied public certificate")
	}

	// 5. The certificate is retired afterwards: turning it on again is refused, and turning it off is always allowed.
	b.post("/certificates/"+c.ID+":retire", nil).want(204, "")
	b.post("/certificates/"+other.ID+":retire", nil).want(204, "")
	enable().want(422, "cert_not_public")
	b.callOn(prod, adminHost, "PUT", "/settings/webauthn", map[string]any{"rp_id": "example.ir", "enabled": false}).want(200, "")
}

// TestApplyPendingFollowsTheWildcardRows (V1 r2-1, r2-3): CTRLZ_VERIFY_ORIGIN lists a zone only while an active uploaded wildcard
// covers it, so an upload or a retirement after an apply leaves the origin stale until the next run. The page must say so. The
// run is simulated by what the apply step ends with, applied_at = now().
func TestApplyPendingFollowsTheWildcardRows(t *testing.T) {
	r := newIntakeRig(t)
	b, _ := r.admin(t)
	b.put("/settings/domain", map[string]any{"dns_zone": "dns.example.ir", "panel_host": "panel.example.ir", "admin_host": "admin.example.ir"}).want(200, "")
	applied := func() {
		r.env.Exec(t, `UPDATE ctrlz.domain_settings SET applied_panel_host = panel_host, applied_admin_host = admin_host, applied_at = now()`)
	}
	pending := func() bool {
		var v struct {
			ApplyPending bool `json:"apply_pending"`
		}
		b.get("/settings/domain").want(200, "").json(&v)
		return v.ApplyPending
	}
	applied()
	if pending() {
		t.Fatal("nothing is pending after an apply with no wildcard")
	}
	// The usual first-install order: the apply ran, then the public wildcard is uploaded.
	chain, key := r.ca.leaf(t, 60*24*time.Hour, "dns.example.ir", "*.dns.example.ir", "*.verify.dns.example.ir")
	var c certCreated
	b.post("/certificates", certBody("wildcard", chain, key)).want(201, "").json(&c)
	if !pending() {
		t.Fatal("a wildcard uploaded after the apply changes the origin, so an apply is pending")
	}
	applied()
	if pending() {
		t.Fatal("the apply has seen the wildcard, so nothing is pending")
	}
	b.post("/certificates/"+c.ID+":retire", nil).want(204, "")
	if !pending() {
		t.Fatal("a retired wildcard takes the zone back to the private CA, so an apply is pending")
	}
	applied()
	if pending() {
		t.Fatal("the apply has seen the retirement, so nothing is pending")
	}
	// No live zone, no origin: a wildcard row changes nothing.
	r.env.Exec(t, `UPDATE ctrlz.domain_settings SET dns_zone = NULL, changed_at = NULL`)
	r.env.Exec(t, `UPDATE ctrlz.certificates SET updated_at = now() WHERE kind = 'wildcard'`)
	if pending() {
		t.Fatal("with no zone the origin is empty whatever the wildcard rows do")
	}
}
