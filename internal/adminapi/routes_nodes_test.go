package adminapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	signv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/sign/v1"
	"github.com/Kup1ng/CtrlZ-Shared/manifest"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"

	"github.com/Kup1ng/CtrlZ-Panel/internal/hub/hubtoken"
	"github.com/Kup1ng/CtrlZ-Panel/internal/nodeadmin"
)

// The seeded nodes of the catalog fixture (internal/store/catalogtest seed.go): two active nodes, a pair and the
// global pair. Their addresses are documentation ranges and they have no key, so a PairTable built from them is
// invalid; the tests that confirm a node make them what a real node is first.
const (
	seedNode1 = "00000000-0000-7000-8000-0000000000c1"
	seedNode2 = "00000000-0000-7000-8000-0000000000c2"
)

// seedRealNodes gives the two seeded nodes a public address, a proxy address and a key, so the table of the
// panel is valid before the test adds a third node.
func (r *rig) seedRealNodes(t *testing.T) {
	t.Helper()
	for i, id := range []string{seedNode1, seedNode2} {
		r.env.Exec(t, `UPDATE ctrlz.nodes SET dns_advertised_ip = $2, proxy_advertised_ip = $3, spki_sha256 = sha256(convert_to($4, 'UTF8')) WHERE id = $1`,
			id, fmt.Sprintf("93.184.216.%d", i+1), fmt.Sprintf("93.184.216.%d", i+101), "seed-key-"+id)
	}
}

// record inserts an enrolment as the hub leaves it after Enroll: one issued row, then the frozen record in one
// UPDATE. label makes the key (the same label is the same key). It returns the id and the fingerprint.
func (r *rig) record(t *testing.T, label, dnsBind, dnsAdv, proxyBind, proxyAdv string) (id, fp string) {
	t.Helper()
	r.env.Scan(t, `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at) VALUES (sha256(convert_to($1, 'UTF8')), now() + interval '15 minutes') RETURNING id::text`,
		[]any{"token-" + uuid.NewString()}, &id)
	r.env.Exec(t, `UPDATE ctrlz.node_enrollments SET csr_der = '\x01', spki_sha256 = sha256(convert_to($2, 'UTF8')),
  key_fingerprint = encode(sha256(convert_to($2, 'UTF8')), 'hex'), hostname = 'node-host', os_release = 'Ubuntu 24.04', node_version = '0.1.0',
  dns_bind_ip = $3, dns_advertised_ip = $4, proxy_bind_ip = $5, proxy_advertised_ip = $6, enrolled_from = '203.0.113.77', enrolled_at = now(),
  state = 'pending_approval' WHERE id = $1`, id, label, dnsBind, dnsAdv, proxyBind, proxyAdv)
	r.env.Scan(t, `SELECT key_fingerprint FROM ctrlz.node_enrollments WHERE id = $1`, []any{id}, &fp)
	return id, fp
}

// goodRecord is a record whose addresses make a valid table next to the seeded nodes.
func (r *rig) goodRecord(t *testing.T, label string, n int) (id, fp string) {
	return r.record(t, label, "10.0.0.5", fmt.Sprintf("93.184.217.%d", n), "10.0.0.6", fmt.Sprintf("93.184.217.%d", n+100))
}

// testInstaller makes an installer over an in-memory pin file and one signed node bundle.
func testInstaller(t *testing.T) *nodeadmin.Installer {
	t.Helper()
	now := time.Now()
	var keys []*signv1.PublicKey
	var priv []ed25519.PrivateKey
	var ids [][]byte
	for i := 0; i < 3; i++ {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := manifest.KeyID(pub)
		keys = append(keys, &signv1.PublicKey{KeyId: id, Ed25519: pub})
		priv, ids = append(priv, pk), append(ids, id)
	}
	exp := now.Add(365 * 24 * time.Hour).Unix()
	root := &signv1.Root{Version: 1, ExpiresAt: exp, Keys: keys, Threshold: 2, RootKeyIds: ids,
		Roles: []*signv1.RoleGrant{{Role: signv1.Role_ROLE_BUNDLE, KeyIds: ids, Threshold: 2, ExpiresAt: exp}}}
	rj, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	script := []byte("#!/bin/sh\necho node\n")
	sum := sha256.Sum256(script)
	m := &signv1.Manifest{Kind: signv1.Kind_KIND_NODE, Version: 1, CreatedAt: now.Unix(), ExpiresAt: exp, MinVersion: 1,
		Files: []*signv1.FileEntry{{Path: "packaging/install/node.sh", Sha256: sum[:], Size: uint64(len(script))}}}
	payload, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	typ := manifest.ManifestPayloadType(signv1.Kind_KIND_NODE)
	env := &signv1.Envelope{PayloadType: typ, Payload: payload}
	for i := 0; i < 2; i++ {
		env.Signatures = append(env.Signatures, &signv1.Signature{KeyId: ids[i], Sig: ed25519.Sign(priv[i], manifest.SigningInput(typ, payload))})
	}
	ej, err := protojson.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256([]byte("hub key"))
	inst, err := nodeadmin.NewInstaller(nodeadmin.InstallConfig{
		HubHost: "hub.example.test",
		Public:  fstest.MapFS{"hub_tls.spki": {Data: []byte(base64.StdEncoding.EncodeToString(pin[:]) + "\n")}},
		Bundles: fstest.MapFS{"root.json": {Data: rj}, "node/1/manifest.json": {Data: ej}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

// withInstall puts an installer on the rig's handler, as the admin process has one when the hub volumes are mounted.
func (r *rig) withInstall(t *testing.T) {
	t.Helper()
	inst := testInstaller(t)
	r.h = r.handler(t, func(d *Deps) { d.Install = inst })
}

var enrollBody = map[string]any{
	"dns_bind_ip": "10.0.0.5", "dns_advertised_ip": "93.184.216.34", "proxy_bind_ip": "10.0.0.6", "proxy_advertised_ip": "93.184.216.134",
}

func withBody(extra map[string]any) map[string]any {
	m := map[string]any{}
	for k, v := range enrollBody {
		m[k] = v
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// TestCreateNodeEnrollment covers POST /node-enrollments (p4-nodes 4.2 step 1).
func TestCreateNodeEnrollment(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	rows := `SELECT count(*) FROM ctrlz.node_enrollments`
	before := r.count(t, rows)

	// A panel with no install files cannot show a command, and then it makes no enrolment either.
	b.post("/node-enrollments", enrollBody).want(503, "service_unavailable")
	if r.count(t, rows) != before {
		t.Fatal("an enrolment was made although no command could be shown")
	}

	r.withInstall(t)
	var out struct {
		ID      string `json:"id"`
		Expires string `json:"expires_at"`
		Command string `json:"install_command"`
	}
	b.post("/node-enrollments", withBody(map[string]any{"bound_ip": "203.0.113.77"})).want(201, "").json(&out)
	if !strings.HasPrefix(out.Command, " curl -k --pinnedpubkey sha256//") || !strings.Contains(out.Command, "--dns-advertised-ip 93.184.216.34") {
		t.Fatalf("command %q", out.Command)
	}
	// The token is in the command and nowhere else: the row holds the SHA-256 of its 32 bytes, and no log line and
	// no audit row has it.
	_, rest, _ := strings.Cut(out.Command, "printf %s '")
	token, _, _ := strings.Cut(rest, "'")
	hash, ok := hubtoken.Parse(token)
	if !ok {
		t.Fatalf("the token %q is not one", token)
	}
	var stored []byte
	var life bool
	var bound string
	r.env.Scan(t, `SELECT token_hash, expires_at - created_at = interval '15 minutes', host(bound_ip) FROM ctrlz.node_enrollments WHERE id = $1`, []any{out.ID}, &stored, &life, &bound)
	if string(stored) != string(hash) || !life || bound != "203.0.113.77" {
		t.Fatalf("stored hash matches: %v, 15 minute life: %v, bound %q", string(stored) == string(hash), life, bound)
	}
	var params string
	r.env.Scan(t, `SELECT params::text FROM ctrlz.audit_log WHERE action = 'node_enrollment.create'`, nil, &params)
	if strings.Contains(params, token) || !strings.Contains(jsonCompact(params), `"bound":true`) {
		t.Fatalf("audit params %s", params)
	}
	r.assertQuiet(t, token)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	list := b.get("/node-enrollments").want(200, "")
	list.json(&page)
	if len(page.Items) != 1 || page.Items[0]["state"] != "issued" || strings.Contains(string(list.Body), token) || strings.Contains(string(list.Body), "token") {
		t.Fatalf("list %s", list.Body)
	}

	// The addresses: an embedded IPv4 form, a zone, a bind address nobody can bind, and an advertised address that
	// is not public are each refused with the field named.
	bad := []map[string]any{
		{"dns_advertised_ip": "::ffff:93.184.216.34"},
		{"dns_bind_ip": "0.0.0.0"},
		{"proxy_bind_ip": "fe80::1%eth0"},
		{"bound_ip": "64:ff9b::5db8:d822"},
		{"proxy_advertised_ip": "198.51.100.9"},
	}
	if !netclass.AllowPrivatePairAddrs {
		bad = append(bad, map[string]any{"dns_advertised_ip": "192.168.1.5"})
	}
	for _, extra := range bad {
		resp := b.post("/node-enrollments", withBody(extra)).want(422, "address_refused")
		if !strings.Contains(string(resp.Body), `"fields"`) {
			t.Errorf("%v: no field named in %s", extra, resp.Body)
		}
	}
	if n := r.count(t, rows); n != before+1 {
		t.Fatalf("%d enrolments, want the one", n)
	}
}

// TestConfirmNodeEnrollment covers POST /node-enrollments/{id}:confirm (4.2 step 4).
func TestConfirmNodeEnrollment(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	outbox := r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`)
	nodes := func() int { return r.count(t, `SELECT count(*) FROM ctrlz.nodes`) }

	b.post("/node-enrollments/"+uuid.NewString()+":confirm", map[string]any{"fingerprint": strings.Repeat("ab", 32), "name": "x"}).want(404, "not_found")

	id, fp := r.goodRecord(t, "first", 1)
	// The fingerprint the admin typed must be the record's.
	wrong := strings.Repeat("0", 64)
	b.post("/node-enrollments/"+id+":confirm", map[string]any{"fingerprint": wrong, "name": "frankfurt"}).want(422, "fingerprint_mismatch")
	if nodes() != 2 {
		t.Fatal("a node row was made for a wrong fingerprint")
	}
	// A record that is not waiting for approval (a token nobody used) is refused.
	var issued string
	r.env.Scan(t, `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at) VALUES (sha256('\x01'), now() + interval '15 minutes') RETURNING id::text`, nil, &issued)
	b.post("/node-enrollments/"+issued+":confirm", map[string]any{"fingerprint": fp, "name": "x"}).want(409, "enrollment_state")

	// Typed from a console as pairs of capitals with colons.
	var pairs []string
	for i := 0; i < len(fp); i += 2 {
		pairs = append(pairs, strings.ToUpper(fp[i:i+2]))
	}
	var done struct {
		NodeID string `json:"node_id"`
		Slot   int    `json:"slot"`
	}
	b.post("/node-enrollments/"+id+":confirm", map[string]any{"fingerprint": strings.Join(pairs, ":"), "name": "  frankfurt  "}).want(201, "").json(&done)
	if done.Slot != 3 || done.NodeID == "" {
		t.Fatalf("answer %+v: the two seeded nodes hold slots 1 and 2", done)
	}
	var status, name, key, dns string
	var state, approvedNode string
	r.env.Scan(t, `SELECT status, name, encode(spki_sha256, 'hex'), host(dns_advertised_ip) FROM ctrlz.nodes WHERE id = $1`, []any{done.NodeID}, &status, &name, &key, &dns)
	r.env.Scan(t, `SELECT state, node_id::text FROM ctrlz.node_enrollments WHERE id = $1`, []any{id}, &state, &approvedNode)
	if status != "pending" || name != "frankfurt" || key != fp || dns != "93.184.217.1" || state != "approved" || approvedNode != done.NodeID {
		t.Fatalf("node %q %q %q %q, record %q %q", status, name, key, dns, state, approvedNode)
	}
	// A pending node is in no PairTable and a confirmation writes no policy outbox row (T-081).
	if r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`) != outbox {
		t.Fatal("the confirmation wrote a policy outbox row")
	}
	var params string
	r.env.Scan(t, `SELECT params::text FROM ctrlz.audit_log WHERE action = 'node_enrollment.confirm'`, nil, &params)
	if !strings.Contains(params, done.NodeID) || strings.Contains(params, fp) {
		t.Fatalf("audit params %s", params)
	}
	// The same record cannot be confirmed twice.
	b.post("/node-enrollments/"+id+":confirm", map[string]any{"fingerprint": fp, "name": "again"}).want(409, "enrollment_state")

	// A key that was admitted is never admitted again: while its node row exists, and after the row is removed.
	again, _ := r.goodRecord(t, "first", 2)
	b.post("/node-enrollments/"+again+":confirm", map[string]any{"fingerprint": fp, "name": "same key"}).want(409, "key_reused")
	r.env.Exec(t, `DELETE FROM ctrlz.nodes WHERE id = $1`, done.NodeID)
	b.post("/node-enrollments/"+again+":confirm", map[string]any{"fingerprint": fp, "name": "same key"}).want(409, "key_reused")
	if nodes() != 2 {
		t.Fatal("a node row was made for a key that was admitted before")
	}
	r.assertQuiet(t)
}

// TestConfirmNodeEnrollmentRefusals: the addresses of the record and the table they would make.
func TestConfirmNodeEnrollmentRefusals(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	nodes := func() int { return r.count(t, `SELECT count(*) FROM ctrlz.nodes`) }
	body := func(fp string) map[string]any { return map[string]any{"fingerprint": fp, "name": "n"} }

	// The record repeats the address of a node in the table: the table would be invalid.
	id, fp := r.record(t, "dup", "10.0.0.5", "93.184.216.1", "10.0.0.6", "93.184.217.150")
	resp := b.post("/node-enrollments/"+id+":confirm", body(fp)).want(422, "table_invalid")
	if !strings.Contains(string(resp.Body), "pair_table") || !strings.Contains(string(resp.Body), "duplicate_dns_ip") {
		t.Errorf("the reason of the table is missing: %s", resp.Body)
	}
	var state string
	r.env.Scan(t, `SELECT state FROM ctrlz.node_enrollments WHERE id = $1`, []any{id}, &state)
	if nodes() != 2 || state != "pending_approval" {
		t.Fatalf("a refused confirmation left %d nodes and the record %q", nodes(), state)
	}
	// A revoked node keeps its address in the table (4.5): it must be removed first.
	r.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = $1`, seedNode2)
	id2, fp2 := r.record(t, "dup2", "10.0.0.5", "93.184.216.2", "10.0.0.6", "93.184.217.151")
	b.post("/node-enrollments/"+id2+":confirm", body(fp2)).want(422, "table_invalid")

	// No proxy address: the compiler would refuse the table, so the confirmation does.
	id3, fp3 := r.record(t, "noproxy", "10.0.0.5", "93.184.217.60", "10.0.0.6", "93.184.217.160")
	r.env.Exec(t, `ALTER TABLE ctrlz.node_enrollments DISABLE TRIGGER node_enrollments_frozen`)
	r.env.Exec(t, `UPDATE ctrlz.node_enrollments SET proxy_advertised_ip = NULL WHERE id = $1`, id3)
	r.env.Exec(t, `ALTER TABLE ctrlz.node_enrollments ENABLE TRIGGER node_enrollments_frozen`)
	b.post("/node-enrollments/"+id3+":confirm", body(fp3)).want(422, "table_invalid")

	// An advertised address that is not public (outside a lab build), and a bind address nobody can use.
	if !netclass.AllowPrivatePairAddrs {
		id4, fp4 := r.record(t, "private", "10.0.0.5", "192.168.7.7", "10.0.0.6", "93.184.217.161")
		b.post("/node-enrollments/"+id4+":confirm", body(fp4)).want(422, "address_refused")
	}
	id5, fp5 := r.record(t, "unbindable", "0.0.0.0", "93.184.217.70", "10.0.0.6", "93.184.217.170")
	b.post("/node-enrollments/"+id5+":confirm", body(fp5)).want(422, "address_refused")
	// An address that an upstream of a node names is refused by name, not as a bare constraint error at commit.
	r.env.Exec(t, `INSERT INTO ctrlz.node_upstreams (node_id, group_name, position, kind, address, bootstrap_ip)
VALUES ($1, 'g', 0, 'doh', 'https://resolver.example/dns-query', '93.184.217.80')`, seedNode1)
	id6, fp6 := r.record(t, "loop", "10.0.0.5", "93.184.217.80", "10.0.0.6", "93.184.217.180")
	b.post("/node-enrollments/"+id6+":confirm", body(fp6)).want(409, "upstream_loop")
	if nodes() != 2 {
		t.Fatalf("%d nodes after the refusals, want the two seeded", nodes())
	}
}

// TestConfirmNodeEnrollmentFourNodes: a fifth node is refused (D25), and a freed slot is used first.
func TestConfirmNodeEnrollmentFourNodes(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	for slot := 3; slot <= 4; slot++ {
		r.env.Exec(t, `INSERT INTO ctrlz.nodes (slot, name, dns_bind_ip, dns_advertised_ip, proxy_bind_ip, proxy_advertised_ip, spki_sha256)
VALUES ($1, 'extra', '10.0.0.9', $2, '10.0.0.10', $3, sha256(convert_to($4, 'UTF8')))`,
			slot, fmt.Sprintf("93.184.218.%d", slot), fmt.Sprintf("93.184.218.%d", slot+100), fmt.Sprintf("extra-%d", slot))
	}
	id, fp := r.goodRecord(t, "fifth", 5)
	b.post("/node-enrollments/"+id+":confirm", map[string]any{"fingerprint": fp, "name": "fifth"}).want(409, "node_limit_reached")
	r.env.Exec(t, `DELETE FROM ctrlz.nodes WHERE slot = 3`)
	var done struct {
		Slot int `json:"slot"`
	}
	b.post("/node-enrollments/"+id+":confirm", map[string]any{"fingerprint": fp, "name": "fifth"}).want(201, "").json(&done)
	if done.Slot != 3 {
		t.Fatalf("slot %d, want the freed 3", done.Slot)
	}
}

// TestRejectNodeEnrollment covers POST /node-enrollments/{id}:reject.
func TestRejectNodeEnrollment(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.post("/node-enrollments/"+uuid.NewString()+":reject", map[string]any{}).want(404, "not_found")

	var issued string
	r.env.Scan(t, `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at) VALUES (sha256('\x02'), now() + interval '15 minutes') RETURNING id::text`, nil, &issued)
	b.post("/node-enrollments/"+issued+":reject", nil).want(204, "")
	var state string
	var rejected bool
	r.env.Scan(t, `SELECT state, rejected_at IS NOT NULL FROM ctrlz.node_enrollments WHERE id = $1`, []any{issued}, &state, &rejected)
	if state != "rejected" || !rejected {
		t.Fatalf("state %q rejected_at set %v", state, rejected)
	}
	b.post("/node-enrollments/"+issued+":reject", nil).want(409, "enrollment_state")

	// A pending record can be rejected, and an approved one cannot.
	pending, _ := r.goodRecord(t, "reject-me", 20)
	b.post("/node-enrollments/"+pending+":reject", nil).want(204, "")
	r.seedRealNodes(t)
	approved, fp := r.goodRecord(t, "approve-me", 21)
	b.post("/node-enrollments/"+approved+":confirm", map[string]any{"fingerprint": fp, "name": "ok"}).want(201, "")
	b.post("/node-enrollments/"+approved+":reject", nil).want(409, "enrollment_state")
	if got := r.auditCount(t, "node_enrollment.reject"); got != 2 {
		t.Fatalf("%d reject audit rows, want 2", got)
	}
}

func (r *rig) auditCount(t *testing.T, action string) int {
	t.Helper()
	return r.count(t, `SELECT count(*) FROM ctrlz.audit_log WHERE action = $1`, action)
}

// TestListNodeEnrollmentsPages: newest first, paged by cursor, and the record shows what the host said.
func TestListNodeEnrollmentsPages(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	_, fp1 := r.goodRecord(t, "page-1", 30)
	r.goodRecord(t, "page-2", 31)
	r.goodRecord(t, "page-3", 32)
	type page struct {
		Items []struct {
			ID             string `json:"id"`
			KeyFingerprint string `json:"key_fingerprint"`
		} `json:"items"`
		Next *string `json:"next_cursor"`
	}
	var p1, p2 page
	b.get("/node-enrollments?limit=2").want(200, "").json(&p1)
	if len(p1.Items) != 2 || p1.Next == nil {
		t.Fatalf("first page %+v", p1)
	}
	b.get("/node-enrollments?limit=2&cursor="+*p1.Next).want(200, "").json(&p2)
	if len(p2.Items) != 1 || p2.Next != nil || p2.Items[0].KeyFingerprint != fp1 {
		t.Fatalf("second page %+v, want the oldest record", p2)
	}
	b.get("/node-enrollments?cursor=%21%21").want(400, "bad_request")
	var raw map[string]any
	b.get("/node-enrollments?limit=1").want(200, "").json(&raw)
	row := raw["items"].([]any)[0].(map[string]any)
	for _, k := range []string{"hostname", "os_release", "node_version", "enrolled_from", "dns_bind_ip", "dns_advertised_ip", "proxy_bind_ip", "proxy_advertised_ip", "key_fingerprint"} {
		if _, ok := row[k]; !ok {
			t.Errorf("a pending record shows no %s: %v", k, row)
		}
	}
	for _, k := range []string{"token_hash", "csr_der", "cert_der", "spki_sha256"} {
		if _, ok := row[k]; ok {
			t.Errorf("the record shows %s", k)
		}
	}
}

// TestNodesList covers GET /nodes and GET /nodes/{id}.
func TestNodesList(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET last_heartbeat_at = now(), applied_seq = 7, dns_hold = true,
  version_info = '{"node_version":"0.1.0","unbound_version":"1.19","catalog_version":12,"blob_major_max":1,"isolated":false,"quarantined":2,"qps":321,"cache_hit_permille":900,"surprise":{"a":1}}'
  WHERE id = $1`, seedNode1)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET version_info = '{"qps":"fast","quarantined":-3}' WHERE id = $1`, seedNode2)

	type page struct {
		Items []struct {
			ID              string  `json:"id"`
			Slot            int     `json:"slot"`
			Status          string  `json:"status"`
			NodeVersion     string  `json:"node_version"`
			UnboundVersion  string  `json:"unbound_version"`
			CatalogVersion  string  `json:"catalog_version"`
			Qps             *int    `json:"qps"`
			Quarantined     *int    `json:"quarantined"`
			CacheHit        *int    `json:"cache_hit_permille"`
			AppliedSeq      int64   `json:"applied_seq"`
			Lag             int64   `json:"applied_seq_lag"`
			DNSHold         bool    `json:"dns_hold"`
			Peer            string  `json:"pair_peer_id"`
			KeyFingerprint  string  `json:"key_fingerprint"`
			LastHeartbeatAt *string `json:"last_heartbeat_at"`
			ProxyAdvertised string  `json:"proxy_advertised_ip"`
			PendingRequests int     `json:"pending_requests"`
		} `json:"items"`
		Next *string `json:"next_cursor"`
	}
	var head int64
	r.env.Scan(t, `SELECT COALESCE(max(seq), 0) FROM ctrlz.config_log`, nil, &head)
	wantLag := max(head-7, 0)
	var all page
	b.get("/nodes").want(200, "").json(&all)
	if len(all.Items) != 2 || all.Items[0].ID != seedNode1 || all.Items[1].ID != seedNode2 {
		t.Fatalf("list %+v", all)
	}
	n := all.Items[0]
	if n.Slot != 1 || n.Status != "active" || n.NodeVersion != "0.1.0" || n.UnboundVersion != "1.19" || n.CatalogVersion != "12" ||
		n.Qps == nil || *n.Qps != 321 || n.Quarantined == nil || *n.Quarantined != 2 || n.CacheHit == nil || *n.CacheHit != 900 ||
		n.AppliedSeq != 7 || n.Lag != wantLag || !n.DNSHold || n.Peer != seedNode2 || n.LastHeartbeatAt == nil || len(n.KeyFingerprint) != 64 || n.ProxyAdvertised != "93.184.216.101" {
		t.Fatalf("node 1 = %+v", n)
	}
	// A field the hub wrote with a value of another kind is left out and does not fail the page.
	if m := all.Items[1]; m.Qps != nil || m.Quarantined != nil || m.Peer != seedNode1 {
		t.Fatalf("node 2 = %+v", m)
	}
	var first, second page
	b.get("/nodes?limit=1").want(200, "").json(&first)
	if len(first.Items) != 1 || first.Next == nil {
		t.Fatalf("first page %+v", first)
	}
	b.get("/nodes?limit=1&cursor="+*first.Next).want(200, "").json(&second)
	if len(second.Items) != 1 || second.Items[0].ID != seedNode2 || second.Next != nil {
		t.Fatalf("second page %+v", second)
	}
	var one struct {
		ID string `json:"id"`
	}
	b.get("/nodes/"+seedNode2).want(200, "").json(&one)
	if one.ID != seedNode2 {
		t.Fatalf("get = %+v", one)
	}
	b.get("/nodes/"+uuid.NewString()).want(404, "not_found")
	b.get("/nodes/not-a-uuid").want(400, "bad_request")
}

// TestAddressesGivenUp covers GET /nodes/addresses-given-up (SC 8a.4): the old addresses of the audit rows of a
// removal or an edit, with the date from which giving them back is safe, minus what a node holds now.
func TestAddressesGivenUp(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	now := r.ck.now()
	audit := func(at time.Time, action, target, params string) {
		r.env.Exec(t, `INSERT INTO ctrlz.audit_log (at, action, target, params, entry_hash) VALUES ($1, $2, $3, $4::jsonb, '\x01')`, at, action, target, params)
	}
	gone := uuid.NewString()
	audit(now.Add(-48*time.Hour), "node.remove", "node:"+gone, `{"old_dns_ip":"93.184.230.1","old_proxy_ip":"93.184.230.2","name":"gone"}`)
	audit(now.Add(-24*time.Hour), "node.addresses_change", "node:"+seedNode1, `{"old_dns_ip":"93.184.231.1"}`)
	// Past its date, held again by a node, and rows that are not about addresses or hold nothing usable.
	audit(now.Add(-31*24*time.Hour), "node.remove", "node:"+uuid.NewString(), `{"old_dns_ip":"93.184.232.1"}`)
	audit(now.Add(-time.Hour), "node.remove", "node:"+uuid.NewString(), `{"old_dns_ip":"93.184.216.1"}`)
	audit(now.Add(-time.Hour), "node.remove", "node:"+uuid.NewString(), `{"old_dns_ip":"not an address","old_proxy_ip":"::ffff:1.2.3.4"}`)
	audit(now.Add(-time.Hour), "invite.create", "invite:"+uuid.NewString(), `{"old_dns_ip":"93.184.233.1"}`)

	var out struct {
		Items []struct {
			Address  string `json:"address"`
			Kind     string `json:"kind"`
			NodeID   string `json:"node_id"`
			NodeName string `json:"node_name"`
			Given    string `json:"given_up_at"`
			Safe     string `json:"safe_from"`
		} `json:"items"`
	}
	b.get("/nodes/addresses-given-up").want(200, "").json(&out)
	if len(out.Items) != 3 {
		t.Fatalf("items %+v", out.Items)
	}
	// Newest first: the edit, then the removal's two addresses.
	e := out.Items[0]
	if e.Address != "93.184.231.1" || e.Kind != "dns" || e.NodeID != seedNode1 || e.NodeName != "" {
		t.Errorf("edit %+v", e)
	}
	d, p := out.Items[1], out.Items[2]
	if d.Address != "93.184.230.1" || d.Kind != "dns" || d.NodeID != gone || d.NodeName != "gone" || p.Address != "93.184.230.2" || p.Kind != "proxy" {
		t.Errorf("removal %+v %+v", d, p)
	}
	given, err1 := time.Parse(time.RFC3339Nano, d.Given)
	safe, err2 := time.Parse(time.RFC3339Nano, d.Safe)
	if err1 != nil || err2 != nil || safe.Sub(given) != 30*24*time.Hour {
		t.Errorf("the wait is not 30 days: %v %v %v", err1, err2, safe.Sub(given))
	}
}

// TestNodeReports covers GET /nodes/{id}/reports (4.5): the claims taken on the node's observations since `from`,
// across tenants, and the learned rows the node_revoked job could not delete.
func TestNodeReports(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.get("/nodes/"+uuid.NewString()+"/reports").want(404, "not_found")

	var empty struct {
		Claims   []map[string]any `json:"claims"`
		KeptRows []map[string]any `json:"kept_rows"`
	}
	raw := b.get("/nodes/"+seedNode1+"/reports").want(200, "")
	raw.json(&empty)
	if len(empty.Claims) != 0 || len(empty.KeptRows) != 0 || !strings.Contains(string(raw.Body), `"claims":[]`) || !strings.Contains(string(raw.Body), `"kept_rows":[]`) {
		t.Fatalf("a node with no reports: %s", raw.Body)
	}

	// Both tenants' claims were proven on a challenge the node observed, at one instant (as a take writes them).
	taken := r.ck.now().Add(-time.Minute).UTC()
	for _, tn := range []uuid.UUID{r.env.A.Tenant, r.env.B.Tenant} {
		r.env.Exec(t, `UPDATE ctrlz.ip_claims SET proven_at = $2 WHERE tenant_id = $1`, tn, taken)
		r.env.Exec(t, `UPDATE ctrlz.ip_proof_challenges SET observed_by_node_id = $2, consumed_at = $3 WHERE tenant_id = $1`, tn, seedNode1, taken)
	}
	type reports struct {
		Claims []struct {
			TenantID   string `json:"tenant_id"`
			EndpointID string `json:"endpoint_id"`
			ClaimID    string `json:"claim_id"`
			CIDR       string `json:"cidr"`
		} `json:"claims"`
		KeptRows []struct {
			TenantID   string `json:"tenant_id"`
			EndpointID string `json:"endpoint_id"`
		} `json:"kept_rows"`
	}
	var got reports
	b.get("/nodes/"+seedNode1+"/reports").want(200, "").json(&got)
	tenants := map[string]bool{}
	for _, c := range got.Claims {
		tenants[c.TenantID] = true
		if c.CIDR == "" || c.ClaimID == "" || c.EndpointID == "" {
			t.Errorf("claim %+v", c)
		}
	}
	if !tenants[r.env.A.Tenant.String()] || !tenants[r.env.B.Tenant.String()] {
		t.Fatalf("claims %+v, want those of both tenants", got.Claims)
	}
	// Another node's observations are not this node's; a window that starts after the take shows none.
	var other reports
	b.get("/nodes/"+seedNode2+"/reports").want(200, "").json(&other)
	if len(other.Claims) != 0 {
		t.Fatalf("node 2 reports %+v", other.Claims)
	}
	after := r.ck.now().Add(time.Hour).UTC().Format(time.RFC3339)
	var late reports
	b.get("/nodes/"+seedNode1+"/reports?from="+after).want(200, "").json(&late)
	if len(late.Claims) != 0 {
		t.Fatalf("a window after the take shows %+v", late.Claims)
	}
	// The end of the window: before the take nothing shows, and the instant of the take is included, so a page that
	// ends inside it can be read again from there.
	var early, at reports
	b.get("/nodes/"+seedNode1+"/reports?to="+taken.Add(-time.Hour).Format(time.RFC3339)).want(200, "").json(&early)
	b.get("/nodes/"+seedNode1+"/reports?to="+taken.Format(time.RFC3339)).want(200, "").json(&at)
	if len(early.Claims) != 0 || len(at.Claims) != len(got.Claims) {
		t.Fatalf("the end of the window: %d claims before the take, %d at it, want 0 and %d", len(early.Claims), len(at.Claims), len(got.Claims))
	}

	// The node_revoked job records the rows it kept; two jobs naming the node list a row once.
	ep, tn := uuid.NewString(), r.env.A.Tenant.String()
	prog := fmt.Sprintf(`{"kept":[{"tenant_id":%q,"endpoint_id":%q}]}`, tn, ep)
	r.env.Exec(t, `INSERT INTO ctrlz.admin_jobs (kind, params, state, progress) VALUES ('node_revoked', $1::jsonb, 'done', $2::jsonb)`, fmt.Sprintf(`{"node_ids":[%q]}`, seedNode1), prog)
	r.env.Exec(t, `INSERT INTO ctrlz.admin_jobs (kind, params, state, progress) VALUES ('node_revoked', $1::jsonb, 'queued', $2::jsonb)`, fmt.Sprintf(`{"node_ids":[%q,%q]}`, seedNode1, seedNode2), prog)
	var kept reports
	b.get("/nodes/"+seedNode1+"/reports").want(200, "").json(&kept)
	if len(kept.KeptRows) != 1 || kept.KeptRows[0].TenantID != tn || kept.KeptRows[0].EndpointID != ep {
		t.Fatalf("kept rows %+v", kept.KeptRows)
	}
	var none reports
	b.get("/nodes/"+seedNode2+"/reports").want(200, "").json(&none)
	if len(none.KeptRows) != 1 { // the second job names node 2 as well
		t.Fatalf("node 2 kept rows %+v", none.KeptRows)
	}
}

// TestKeptRowsOfOneNode: a node_revoked job covers every node it superseded, so the rows of the other nodes are not
// this node's report, and a list the worker cut (kept_total above the list) says so.
func TestKeptRowsOfOneNode(t *testing.T) {
	a, bn := uuid.New(), uuid.New()
	row := func(node uuid.UUID, n int) string {
		return fmt.Sprintf(`{"tenant_id":%q,"endpoint_id":%q,"node_id":%q}`, uuid.NewSHA1(uuid.Nil, []byte{byte(n)}), uuid.NewSHA1(uuid.Nil, []byte{byte(n), 1}), node)
	}
	doc := json.RawMessage(fmt.Sprintf(`{"kept":[%s,%s,%s],"kept_total":3}`, row(a, 1), row(bn, 2), row(a, 3)))
	rows, cut := keptRows([]json.RawMessage{doc}, a)
	if len(rows) != 2 || cut {
		t.Fatalf("node a: %d rows, truncated %v, want 2 and false", len(rows), cut)
	}
	rows, _ = keptRows([]json.RawMessage{doc}, bn)
	if len(rows) != 1 {
		t.Fatalf("node b: %d rows, want 1", len(rows))
	}
	short := json.RawMessage(fmt.Sprintf(`{"kept":[%s],"kept_total":900}`, row(a, 1)))
	if _, cut := keptRows([]json.RawMessage{short}, a); !cut {
		t.Fatal("a list shorter than kept_total was not reported as cut")
	}
}

// TestNodeRoutesNeedAFreshAdmin: every change of state asks for a code of the last five minutes, and the reads do
// not.
func TestNodeRoutesNeedAFreshAdmin(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() - interval '10 minutes'`)
	id := uuid.NewString()
	b.post("/node-enrollments", enrollBody).want(403, "totp_fresh_required")
	b.post("/node-enrollments/"+id+":confirm", map[string]any{"fingerprint": strings.Repeat("ab", 32), "name": "x"}).want(403, "totp_fresh_required")
	b.post("/node-enrollments/"+id+":reject", map[string]any{}).want(403, "totp_fresh_required")
	b.get("/node-enrollments").want(200, "")
	b.get("/nodes").want(200, "")
	b.get("/nodes/addresses-given-up").want(200, "")
}
