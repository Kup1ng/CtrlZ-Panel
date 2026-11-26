package adminapi

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/netclass"
)

// The tests of the routes that change membership, addresses and pairs (p4-nodes 4.5, 9.2). Like those of the
// enrolment routes they run against Postgres through the real handler, the real grants and the real triggers.

// seedPair is the pair and global pair of the catalog fixture (seedNode1 primary, seedNode2 fallback).
const seedPair = "00000000-0000-7000-8000-0000000000d1"

// addNode inserts a node row as the test owner, in any status, and returns its id. An empty proxy is NULL, a node the
// compiler would refuse a table for. The key is the SHA-256 of the label, so every label is a different key.
func (r *rig) addNode(t *testing.T, slot int, status, dns, proxy, label string) string {
	t.Helper()
	var id string
	r.env.Scan(t, `INSERT INTO ctrlz.nodes (slot, name, status, dns_bind_ip, dns_advertised_ip, proxy_bind_ip, proxy_advertised_ip, spki_sha256)
VALUES ($1, $2, $3, '10.0.0.9', $4, '10.0.0.10', NULLIF($5, '')::inet, sha256(convert_to($6, 'UTF8'))) RETURNING id::text`,
		[]any{slot, label, status, dns, proxy, "key-" + label}, &id)
	return id
}

// isoClear removes what an earlier isolation case made: every pair but the seeded one, which is the global pair
// again, and every node whose name begins with iso.
func (r *rig) isoClear(t *testing.T) {
	t.Helper()
	r.env.Exec(t, `UPDATE ctrlz.public_settings SET global_pair_id = $1`, seedPair)
	r.env.Exec(t, `DELETE FROM ctrlz.node_pairs WHERE id <> $1`, seedPair)
	r.env.Exec(t, `DELETE FROM ctrlz.nodes WHERE name LIKE 'iso%'`)
}

// isoNode is one node of slot 3 with the given status for the isolation cases.
func (r *rig) isoNode(t *testing.T, status string) string {
	t.Helper()
	r.isoClear(t)
	return r.addNode(t, 3, status, "93.184.230.3", "93.184.230.103", "iso-a")
}

// isoNodes are two active nodes, slots 3 and 4.
func (r *rig) isoNodes(t *testing.T) (a, b string) {
	t.Helper()
	r.isoClear(t)
	a = r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "iso-a")
	b = r.addNode(t, 4, "active", "93.184.230.4", "93.184.230.104", "iso-b")
	return a, b
}

type nodeStatus struct {
	Status string `json:"status"`
	Name   string `json:"name"`
	Proxy  bool   `json:"proxy_blocked"`
	Dns    string `json:"dns_advertised_ip"`
}

// TestApproveNode covers POST /nodes/{id}:approve (4.2 step 5).
func TestApproveNode(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	b.post("/nodes/"+uuid.NewString()+":approve", nil).want(404, "not_found")

	outbox := r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`)
	id := r.addNode(t, 3, "pending", "93.184.230.3", "93.184.230.103", "approve-me")
	var v nodeStatus
	b.post("/nodes/"+id+":approve", nil).want(200, "").json(&v)
	if v.Status != "active" {
		t.Fatalf("status %q", v.Status)
	}
	if r.auditCount(t, "node.approve") != 1 {
		t.Fatal("no audit row of the approval")
	}
	// A node that is not pending is not approved again, and a revoked one never returns to service.
	b.post("/nodes/"+id+":approve", nil).want(409, "node_state")
	r.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = $1`, id)
	b.post("/nodes/"+id+":approve", nil).want(409, "node_state")

	// A node that repeats an address in use is refused with the validator's reason and stays pending (SC 8a.9).
	dup := r.addNode(t, 4, "pending", "93.184.216.1", "93.184.230.104", "dup")
	resp := b.post("/nodes/"+dup+":approve", nil).want(422, "table_invalid")
	if !strings.Contains(string(resp.Body), "duplicate_dns_ip") {
		t.Errorf("the reason of the table is missing: %s", resp.Body)
	}
	var status string
	r.env.Scan(t, `SELECT status FROM ctrlz.nodes WHERE id = $1`, []any{dup}, &status)
	if status != "pending" {
		t.Fatalf("a refused approval left the node %q", status)
	}
	// The approval writes no outbox row: the compiler finds the new membership by comparing tables (T-081).
	if r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`) != outbox {
		t.Fatal("the approval wrote a policy outbox row")
	}
	r.assertQuiet(t)
}

// TestRevokeNode covers POST /nodes/{id}:revoke (4.5): terminal, queues node_revoked with the nodes of the job it
// supersedes, and is never refused for the state of the table.
func TestRevokeNode(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.post("/nodes/"+uuid.NewString()+":revoke", nil).want(404, "not_found")

	// The seeded addresses are not valid for a table (they have no key), and a revocation does not care.
	n3 := r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "revoke-3")
	n4 := r.addNode(t, 4, "pending", "93.184.230.4", "93.184.230.104", "revoke-4")
	b.post("/nodes/"+n4+":revoke", nil).want(409, "node_state") // a pending node is removed, not revoked

	var v nodeStatus
	b.post("/nodes/"+n3+":revoke", nil).want(200, "").json(&v)
	if v.Status != "revoked" {
		t.Fatalf("status %q", v.Status)
	}
	jobs := func(state, ids string) int {
		return r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'node_revoked' AND state = $1 AND params->'node_ids' @> $2::jsonb`, state, ids)
	}
	if jobs("queued", fmt.Sprintf(`["%s"]`, n3)) != 1 {
		t.Fatal("the revocation did not queue its node_revoked job")
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.node_spki_retired`) != 1 {
		t.Fatal("the key of the revoked node was not remembered")
	}
	b.post("/nodes/"+n3+":revoke", nil).want(409, "node_state")

	// A second revocation supersedes the unfinished job and carries its node.
	r.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'active' WHERE id = $1`, n4)
	b.post("/nodes/"+n4+":revoke", nil).want(200, "")
	if jobs("queued", fmt.Sprintf(`["%s","%s"]`, n3, n4)) != 1 {
		t.Fatal("the newer job does not name both nodes")
	}
	var ended int
	r.env.Scan(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'node_revoked' AND state = 'failed' AND progress @> '{"superseded": true}'`, nil, &ended)
	if ended != 1 {
		t.Fatalf("%d superseded jobs, want 1", ended)
	}
	if r.auditCount(t, "node.revoke") != 2 {
		t.Fatal("the revocations are not both in the audit log")
	}
}

// TestRemoveNode covers DELETE /nodes/{id} (SC 8a.4 Membership).
func TestRemoveNode(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	b.call("DELETE", "/nodes/"+uuid.NewString(), nil).want(404, "not_found")
	// A node a row of node_pairs holds stays.
	b.call("DELETE", "/nodes/"+seedNode1, nil).want(409, "node_paired")

	n3 := r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "remove-3")
	n4 := r.addNode(t, 4, "active", "93.184.230.4", "93.184.230.104", "remove-4")
	// The hub's last signing event pairs it: the removal waits until the event that took it out of its pair has been
	// decided.
	id3, id4 := uuid.MustParse(n3), uuid.MustParse(n4)
	last, err := proto.Marshal(&policyv1.PairTable{Pairs: []*policyv1.Pair{{Primary: id3[:], Fallback: id4[:]}}})
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.pair_event_state SET last_table = $1`, last)
	b.call("DELETE", "/nodes/"+n3, nil).want(409, "node_in_table")
	r.env.Exec(t, `UPDATE ctrlz.pair_event_state SET last_table = NULL`)

	b.call("DELETE", "/nodes/"+n3, nil).want(204, "")
	if r.count(t, `SELECT count(*) FROM ctrlz.nodes WHERE id = $1`, n3) != 0 {
		t.Fatal("the node row is still there")
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.node_spki_retired`) != 1 {
		t.Fatal("the key of the removed node was not remembered")
	}
	// Its reports outlive the row (4.5): the removed node answers, an id that never was does not.
	b.get("/nodes/"+n3+"/reports").want(200, "")
	b.get("/nodes/"+uuid.NewString()+"/reports").want(404, "not_found")
	var params string
	r.env.Scan(t, `SELECT params::text FROM ctrlz.audit_log WHERE action = $1`, []any{"node.remove"}, &params)
	params = jsonCompact(params)
	if !strings.Contains(params, `"old_dns_ip":"93.184.230.3"`) || !strings.Contains(params, `"old_proxy_ip":"93.184.230.103"`) || !strings.Contains(params, `"name":"remove-3"`) {
		t.Fatalf("audit params %s", params)
	}
	// The addresses it gave up are on the nodes page with their safe date.
	var out struct {
		Items []struct {
			Address string `json:"address"`
			Kind    string `json:"kind"`
			NodeID  string `json:"node_id"`
		} `json:"items"`
	}
	b.get("/nodes/addresses-given-up").want(200, "").json(&out)
	if len(out.Items) != 2 || out.Items[0].NodeID != n3 {
		t.Fatalf("given up %+v", out.Items)
	}
	r.assertQuiet(t)
}

// TestRemoveNodeReadsTheLastTableTheLogCarried: an entry carries a table only when the membership changed, so a
// tenant-only entry on top of the log must not hide the table below it (SC 8a.4 Membership), and a log that never
// carried a table (every entry of a fresh install is tenant-only) judges no removal "in a table".
func TestRemoveNodeReadsTheLastTableTheLogCarried(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	n3 := r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "log-3")
	n4 := r.addNode(t, 4, "active", "93.184.230.4", "93.184.230.104", "log-4")
	id3, id4 := uuid.MustParse(n3), uuid.MustParse(n4)
	withTable, err := proto.Marshal(&policyv1.ConfigEntry{PairTable: &policyv1.PairTable{Pairs: []*policyv1.Pair{{Primary: id3[:], Fallback: id4[:]}}}})
	if err != nil {
		t.Fatal(err)
	}
	tenantOnly, err := proto.Marshal(&policyv1.ConfigEntry{Seq: 9})
	if err != nil {
		t.Fatal(err)
	}
	logRow := func(seq int, payload []byte) {
		r.env.Exec(t, `INSERT INTO ctrlz.config_log (seq, class, entry_hash, payload) VALUES ($1, 'policy', sha256(convert_to($3, 'UTF8')), $2)`, seq, payload, strconv.Itoa(seq))
	}
	logRow(1, withTable)
	logRow(2, tenantOnly)
	logRow(3, []byte{})
	b.call("DELETE", "/nodes/"+n3, nil).want(409, "node_in_table")

	// The log was pruned past its last table, and the hub has written none: nothing can be judged yet, which is
	// the retry-later answer and not an internal error.
	r.env.Exec(t, `DELETE FROM ctrlz.config_log WHERE seq = 1`)
	b.call("DELETE", "/nodes/"+n3, nil).want(409, "node_in_table")
	if r.count(t, `SELECT count(*) FROM ctrlz.nodes WHERE id = $1`, n3) != 1 {
		t.Fatal("a removal that could not be judged removed the row")
	}
	// The hub's last event is evidence when the log has none: it does not pair the node, so the node may go.
	other, err := proto.Marshal(&policyv1.PairTable{Pairs: []*policyv1.Pair{{Primary: id4[:]}}})
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `UPDATE ctrlz.pair_event_state SET last_table = $1`, other)
	b.call("DELETE", "/nodes/"+n3, nil).want(204, "")
	r.env.Exec(t, `UPDATE ctrlz.pair_event_state SET last_table = NULL`)

	// A log that starts at seq 1 and holds no table at all is the state before the first pair: not pruned, so not
	// unjudgeable, and the node leaves.
	r.env.Exec(t, `DELETE FROM ctrlz.config_log`)
	logRow(1, tenantOnly)
	logRow(2, []byte{})
	b.call("DELETE", "/nodes/"+n4, nil).want(204, "")
}

// TestRemoveNodePendingNeedsNoTable: a pending node was never in a table, so a log that holds none, and has lost
// its first entries, does not stop the removal of a wrong or rogue enrolment.
func TestRemoveNodePendingNeedsNoTable(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	pending := r.addNode(t, 3, "pending", "93.184.230.5", "93.184.230.105", "log-pending")
	tenantOnly, err := proto.Marshal(&policyv1.ConfigEntry{Seq: 9})
	if err != nil {
		t.Fatal(err)
	}
	r.env.Exec(t, `INSERT INTO ctrlz.config_log (seq, class, entry_hash, payload) VALUES (7, 'policy', sha256(convert_to('7', 'UTF8')), $1)`, tenantOnly)
	b.call("DELETE", "/nodes/"+pending, nil).want(204, "")
	if r.count(t, `SELECT count(*) FROM ctrlz.nodes WHERE id = $1`, pending) != 0 {
		t.Fatal("the pending row is still there")
	}
}

// TestAddressesGivenUpCountsFromTheNewestRow: an edit gives up only the address it replaces, and an address that
// several audit rows name is listed once, so no row shows a date before the node stopped serving it plus the wait.
func TestAddressesGivenUpCountsFromTheNewestRow(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	n3 := r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "given-3")
	edit := func(dns string) {
		b.put("/nodes/"+n3+"/addresses", map[string]any{"dns_advertised_ip": dns, "proxy_advertised_ip": "93.184.230.103"}).want(200, "")
	}
	// Only the DNS address moves: the proxy address stays in service and is not given up.
	edit("93.184.230.33")
	var params string
	r.env.Scan(t, `SELECT params::text FROM ctrlz.audit_log WHERE action = $1`, []any{"node.addresses_change"}, &params)
	params = jsonCompact(params)
	if !strings.Contains(params, `"old_dns_ip":"93.184.230.3"`) || !strings.Contains(params, `"old_proxy_ip":""`) {
		t.Fatalf("audit params %s", params)
	}
	// The node takes the first address back and gives it up again: two rows name it.
	edit("93.184.230.3")
	edit("93.184.230.34")
	var out struct {
		Items []struct {
			Address string `json:"address"`
		} `json:"items"`
	}
	b.get("/nodes/addresses-given-up").want(200, "").json(&out)
	seen := map[string]int{}
	for _, it := range out.Items {
		seen[it.Address]++
	}
	if len(out.Items) != 2 || seen["93.184.230.3"] != 1 || seen["93.184.230.33"] != 1 {
		t.Fatalf("given up %+v", out.Items)
	}
}

// TestPatchNode covers PATCH /nodes/{id}.
func TestPatchNode(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.call("PATCH", "/nodes/"+uuid.NewString(), map[string]any{"name": "x"}).want(404, "not_found")
	b.call("PATCH", "/nodes/"+seedNode1, map[string]any{"name": "   "}).want(422, "validation_failed")

	var v nodeStatus
	b.call("PATCH", "/nodes/"+seedNode1, map[string]any{"name": "  frankfurt  ", "proxy_blocked": true}).want(200, "").json(&v)
	if v.Name != "frankfurt" || !v.Proxy {
		t.Fatalf("view %+v", v)
	}
	var params string
	r.env.Scan(t, `SELECT params::text FROM ctrlz.audit_log WHERE action = $1`, []any{"node.update"}, &params)
	params = jsonCompact(params)
	if !strings.Contains(params, `"renamed":true`) || !strings.Contains(params, `"proxy_blocked":true`) || strings.Contains(params, "frankfurt") {
		t.Fatalf("audit params %s", params)
	}
	// One field alone leaves the other as it was.
	b.call("PATCH", "/nodes/"+seedNode1, map[string]any{"proxy_blocked": false}).want(200, "").json(&v)
	if v.Name != "frankfurt" || v.Proxy {
		t.Fatalf("view %+v", v)
	}
}

// TestPutNodeAddresses covers PUT /nodes/{id}/addresses.
func TestPutNodeAddresses(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	body := func(dns, proxy string) map[string]any {
		return map[string]any{"dns_advertised_ip": dns, "proxy_advertised_ip": proxy}
	}
	b.put("/nodes/"+uuid.NewString()+"/addresses", body("93.184.230.9", "93.184.230.109")).want(404, "not_found")

	n3 := r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "move-3")
	pairChanges := func(state string) int {
		return r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'pair_change' AND state = $1`, state)
	}
	// A node in no pair: the addresses move, the old ones are given up, and nobody is told (no pair, no devices).
	var v nodeStatus
	b.put("/nodes/"+n3+"/addresses", body("93.184.230.33", "93.184.230.133")).want(200, "").json(&v)
	if v.Dns != "93.184.230.33" || pairChanges("queued") != 0 {
		t.Fatalf("view %+v, %d pair_change jobs", v, pairChanges("queued"))
	}
	var params string
	r.env.Scan(t, `SELECT params::text FROM ctrlz.audit_log WHERE action = $1`, []any{"node.addresses_change"}, &params)
	params = jsonCompact(params)
	if !strings.Contains(params, `"old_dns_ip":"93.184.230.3"`) || !strings.Contains(params, `"old_proxy_ip":"93.184.230.103"`) {
		t.Fatalf("audit params %s", params)
	}
	// The same addresses again are no change: no audit row, no job.
	b.put("/nodes/"+n3+"/addresses", body("93.184.230.33", "93.184.230.133")).want(200, "")
	if r.auditCount(t, "node.addresses_change") != 1 {
		t.Fatal("a repeat of the same addresses was audited")
	}

	// Refusals, each leaving the row as it was.
	b.put("/nodes/"+n3+"/addresses", body("::ffff:93.184.230.9", "93.184.230.109")).want(422, "address_refused")
	b.put("/nodes/"+n3+"/addresses", body("93.184.230.9", "0.0.0.0")).want(422, "address_refused")
	if !netclass.AllowPrivatePairAddrs {
		b.put("/nodes/"+n3+"/addresses", body("192.168.1.5", "93.184.230.109")).want(422, "address_refused")
	}
	resp := b.put("/nodes/"+n3+"/addresses", body("93.184.216.2", "93.184.230.133")).want(422, "table_invalid")
	if !strings.Contains(string(resp.Body), "duplicate_dns_ip") {
		t.Errorf("the reason of the table is missing: %s", resp.Body)
	}
	r.env.Exec(t, `INSERT INTO ctrlz.node_upstreams (node_id, group_name, position, kind, address, bootstrap_ip)
VALUES ($1, 'g', 0, 'doh', 'https://resolver.example/dns-query', '93.184.220.9')`, n3)
	b.put("/nodes/"+n3+"/addresses", body("93.184.220.9", "93.184.230.133")).want(409, "upstream_loop")
	var dns string
	r.env.Scan(t, `SELECT host(dns_advertised_ip) FROM ctrlz.nodes WHERE id = $1`, []any{n3}, &dns)
	if dns != "93.184.230.33" {
		t.Fatalf("a refused edit left the address %q", dns)
	}

	// A node in a pair changes DNS1 or DNS2 for its devices: the job is queued, and a second edit supersedes it.
	b.put("/nodes/"+seedNode1+"/addresses", body("93.184.232.1", "93.184.232.101")).want(200, "")
	if pairChanges("queued") != 1 {
		t.Fatalf("%d queued pair_change jobs, want 1", pairChanges("queued"))
	}
	b.put("/nodes/"+seedNode1+"/addresses", body("93.184.232.2", "93.184.232.101")).want(200, "")
	if pairChanges("queued") != 1 || pairChanges("failed") != 1 {
		t.Fatalf("queued %d, superseded %d", pairChanges("queued"), pairChanges("failed"))
	}

	// A repeat of the same addresses on a paired node changes nothing, so the unfinished job is still there.
	b.put("/nodes/"+seedNode1+"/addresses", body("93.184.232.2", "93.184.232.101")).want(200, "")
	if pairChanges("queued") != 1 || pairChanges("failed") != 1 {
		t.Fatalf("a repeat PUT: queued %d, superseded %d", pairChanges("queued"), pairChanges("failed"))
	}

	// A revoked node has no address to move.
	rev := r.addNode(t, 4, "revoked", "93.184.230.4", "93.184.230.104", "move-4")
	b.put("/nodes/"+rev+"/addresses", body("93.184.230.44", "93.184.230.144")).want(409, "node_state")
}

// TestNodeDNSRequests covers POST /nodes/{id}/dns-requests.
func TestNodeDNSRequests(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	b.post("/nodes/"+uuid.NewString()+"/dns-requests", map[string]any{"kind": "hold"}).want(404, "not_found")
	var out struct {
		ID string `json:"request_id"`
	}
	b.post("/nodes/"+seedNode1+"/dns-requests", map[string]any{"kind": "hold"}).want(202, "").json(&out)
	var kind, state string
	var by bool
	r.env.Scan(t, `SELECT kind, state, requested_by IS NOT NULL FROM ctrlz.node_dns_requests WHERE id = $1`, []any{out.ID}, &kind, &state, &by)
	if kind != "hold" || state != "pending" || !by {
		t.Fatalf("request %q %q %v", kind, state, by)
	}
	// The route writes the request only: no failover column moves.
	var hold bool
	r.env.Scan(t, `SELECT dns_hold FROM ctrlz.nodes WHERE id = $1`, []any{seedNode1}, &hold)
	if hold {
		t.Fatal("the route wrote a failover column")
	}
	b.post("/nodes/"+seedNode1+"/dns-requests", map[string]any{"kind": "force_failback"}).want(202, "")
	pending := r.addNode(t, 3, "pending", "93.184.230.3", "93.184.230.103", "req-3")
	b.post("/nodes/"+pending+"/dns-requests", map[string]any{"kind": "release"}).want(409, "node_state")
	if r.auditCount(t, "node.dns_request") != 2 {
		t.Fatal("the requests are not both in the audit log")
	}
}

type pairOut struct {
	ID       string `json:"id"`
	Primary  string `json:"primary_node_id"`
	Fallback string `json:"fallback_node_id"`
	IsGlobal bool   `json:"is_global"`
}

// TestPairs covers GET, POST, PUT and DELETE /pairs and PUT /settings/global-pair.
func TestPairs(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.seedRealNodes(t)
	outbox := r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`)
	n3 := r.addNode(t, 3, "active", "93.184.230.3", "93.184.230.103", "pair-3")
	n4 := r.addNode(t, 4, "pending", "93.184.230.4", "93.184.230.104", "pair-4")
	pairJobs := func() int {
		return r.count(t, `SELECT count(*) FROM ctrlz.admin_jobs WHERE kind = 'pair_change' AND state = 'queued'`)
	}
	pb := func(p, f string, global bool) map[string]any {
		return map[string]any{"primary_node_id": p, "fallback_node_id": f, "make_global": global}
	}

	var page struct {
		Items []pairOut `json:"items"`
	}
	b.get("/pairs").want(200, "").json(&page)
	if len(page.Items) != 1 || page.Items[0].ID != seedPair || !page.Items[0].IsGlobal {
		t.Fatalf("pairs %+v", page.Items)
	}

	// The members: two different, existing, active nodes, none with a second peer.
	b.post("/pairs", pb(n3, n3, false)).want(422, "validation_failed")
	b.post("/pairs", pb(n3, uuid.NewString(), false)).want(422, "validation_failed")
	b.post("/pairs", pb(n3, n4, false)).want(409, "node_state") // n4 is pending
	r.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'active' WHERE id = $1`, n4)
	b.post("/pairs", pb(seedNode1, n3, false)).want(409, "second_peer")
	b.post("/pairs", pb(n3, seedNode2, false)).want(409, "second_peer")
	if pairJobs() != 0 {
		t.Fatal("a refused change queued a job")
	}

	var made pairOut
	b.post("/pairs", pb(n3, n4, false)).want(201, "").json(&made)
	if made.IsGlobal || made.Primary != n3 || pairJobs() != 1 {
		t.Fatalf("pair %+v, %d jobs", made, pairJobs())
	}
	// The first pair is the global pair: with none set, a pair that is not made global is refused.
	r.env.Exec(t, `UPDATE ctrlz.public_settings SET global_pair_id = NULL`)
	b.post("/pairs", pb(n3, n4, false)).want(422, "global_pair_required")
	r.env.Exec(t, `UPDATE ctrlz.public_settings SET global_pair_id = $1`, seedPair)

	// Swap the roles and make it the global pair; the seeded pair is then free to dissolve.
	var swapped pairOut
	b.put("/pairs/"+made.ID, map[string]any{"primary_node_id": n4, "fallback_node_id": n3, "make_global": true}).want(200, "").json(&swapped)
	if swapped.Primary != n4 || !swapped.IsGlobal {
		t.Fatalf("pair %+v", swapped)
	}
	b.put("/pairs/"+uuid.NewString(), map[string]any{"primary_node_id": n4, "fallback_node_id": n3}).want(404, "not_found")
	// The same member rules as the creation apply to a change.
	b.put("/pairs/"+swapped.ID, pb(n3, n3, false)).want(422, "validation_failed")
	// No slot is free for a fourth kind of node, so one is made pending again with the trigger off, for this one case.
	r.env.Exec(t, `ALTER TABLE ctrlz.nodes DISABLE TRIGGER nodes_revoked_terminal`)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'pending' WHERE id = $1`, n4)
	b.put("/pairs/"+swapped.ID, pb(n3, n4, false)).want(409, "node_state")
	r.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'active' WHERE id = $1`, n4)
	r.env.Exec(t, `ALTER TABLE ctrlz.nodes ENABLE TRIGGER nodes_revoked_terminal`)
	b.put("/pairs/"+swapped.ID, pb(n3, seedNode1, false)).want(409, "second_peer")
	b.call("DELETE", "/pairs/"+swapped.ID, nil).want(409, "pair_in_use")
	b.call("DELETE", "/pairs/"+uuid.NewString(), nil).want(404, "not_found")
	b.call("DELETE", "/pairs/"+seedPair, nil).want(204, "")

	// Nodes 1 and 2 are free again: pair them, then switch the global pair back to that pair.
	var again pairOut
	b.post("/pairs", pb(seedNode1, seedNode2, false)).want(201, "").json(&again)
	b.put("/settings/global-pair", map[string]any{"pair_id": uuid.NewString()}).want(404, "not_found")
	audits := r.auditCount(t, "settings.global_pair")
	b.put("/settings/global-pair", map[string]any{"pair_id": again.ID}).want(200, "")
	b.put("/settings/global-pair", map[string]any{"pair_id": again.ID}).want(200, "") // no change, no second row
	if r.auditCount(t, "settings.global_pair") != audits+1 {
		t.Fatal("the switch is not audited exactly once")
	}
	var global string
	r.env.Scan(t, `SELECT global_pair_id::text FROM ctrlz.public_settings`, nil, &global)
	if global != again.ID {
		t.Fatalf("global pair %q", global)
	}

	// A table that is not valid refuses every change of pairs, whatever the change is: node 4 has no proxy address.
	r.env.Exec(t, `UPDATE ctrlz.nodes SET proxy_advertised_ip = NULL WHERE id = $1`, n4)
	before := r.count(t, `SELECT count(*) FROM ctrlz.node_pairs`)
	b.post("/pairs", pb(seedNode1, seedNode2, false)).want(422, "table_invalid")
	b.put("/pairs/"+swapped.ID, map[string]any{"primary_node_id": n3, "fallback_node_id": n4}).want(422, "table_invalid")
	b.call("DELETE", "/pairs/"+swapped.ID, nil).want(422, "table_invalid")
	b.put("/settings/global-pair", map[string]any{"pair_id": swapped.ID}).want(422, "table_invalid")
	if r.count(t, `SELECT count(*) FROM ctrlz.node_pairs`) != before {
		t.Fatal("a refused change was kept")
	}
	if r.count(t, `SELECT count(*) FROM ctrlz.policy_outbox`) != outbox {
		t.Fatal("a pair route wrote a policy outbox row")
	}
}

// TestNodeChangeRoutesNeedAFreshAdmin: every change of membership, address and pair asks for a code of the last five
// minutes (SC 8a.4, Fresh TOTP), and the one read of pairs does not.
func TestNodeChangeRoutesNeedAFreshAdmin(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)
	r.env.Exec(t, `UPDATE ctrlz.admin_sessions SET totp_verified_at = now() - interval '10 minutes'`)
	id := uuid.NewString()
	b.post("/nodes/"+id+":approve", nil).want(403, "totp_fresh_required")
	b.post("/nodes/"+id+":revoke", nil).want(403, "totp_fresh_required")
	b.call("DELETE", "/nodes/"+id, nil).want(403, "totp_fresh_required")
	b.call("PATCH", "/nodes/"+id, map[string]any{"name": "x"}).want(403, "totp_fresh_required")
	b.put("/nodes/"+id+"/addresses", map[string]any{"dns_advertised_ip": "93.184.230.9", "proxy_advertised_ip": "93.184.230.109"}).want(403, "totp_fresh_required")
	b.post("/nodes/"+id+"/dns-requests", map[string]any{"kind": "hold"}).want(403, "totp_fresh_required")
	body := map[string]any{"primary_node_id": seedNode1, "fallback_node_id": seedNode2}
	b.post("/pairs", body).want(403, "totp_fresh_required")
	b.put("/pairs/"+id, body).want(403, "totp_fresh_required")
	b.call("DELETE", "/pairs/"+id, nil).want(403, "totp_fresh_required")
	b.put("/settings/global-pair", map[string]any{"pair_id": id}).want(403, "totp_fresh_required")
	b.get("/pairs").want(200, "")
}

// jsonCompact removes the spaces PostgreSQL puts after the colons and commas of a jsonb rendered as text, so a test can
// look for `"key":"value"`.
func jsonCompact(s string) string {
	return strings.NewReplacer(`": `, `":`, `, "`, `,"`).Replace(s)
}
