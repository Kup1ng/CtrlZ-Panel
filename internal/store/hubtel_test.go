package store_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// These tests run the hub's telemetry statements (internal/store/hubtel.go) as ctrlz_hub against two seeded tenants. A
// write is given the tenant the hub's own lookup returned; each test also hands a statement the other tenant's Endpoint, claim
// or challenge and requires that nothing of that tenant moves (R5).

func (f *fixture) hubStore(t *testing.T) *store.Store { return f.db.Store(f.ctx, t, store.RoleHub) }

func (f *fixture) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.db.Scan(f.ctx, sql, args, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHubEndpointTenantsMapsEachEndpointToItsOwnTenant(t *testing.T) {
	f := newFixture(t)
	hub := f.hubStore(t)
	gone := uuid.New()
	got, err := hub.HubEndpointTenants(f.ctx, []uuid.UUID{f.A.Endpoint, f.B.Endpoint, gone})
	if err != nil {
		t.Fatal(err)
	}
	if got[f.A.Endpoint] != f.A.Tenant || got[f.B.Endpoint] != f.B.Tenant || len(got) != 2 {
		t.Fatalf("map: %v", got)
	}
}

func TestHubActivityWriteMovesOnlyTheTenantsOwnRows(t *testing.T) {
	f := newFixture(t)
	hub := f.hubStore(t)
	node := uuid.New()
	at := time.Now().Truncate(5 * time.Minute)
	hashA := store.SourceIPHash(f.A.Endpoint, netip.MustParsePrefix("198.51.1.0/24"))
	items := []store.HubActivityItem{
		{Endpoint: f.A.Endpoint, Label: "default", Claim: f.A.Claim, First: at, Last: at, Node: node, ClientCap: 0},
		{Endpoint: f.A.Endpoint, Label: "default", Hash: hashA, First: at, Last: at, Node: node, ClientCap: 0},
		{Endpoint: f.A.Endpoint, Label: "phone", First: at, Last: at, Node: node, ClientCap: 0}, // over a cap of 0
	}
	res, err := hub.HubActivityWrite(f.ctx, f.A.Tenant, items)
	if err != nil {
		t.Fatal(err)
	}
	if res.OverCap != 1 || res.ClientsAdded != 0 {
		t.Fatalf("result %+v: a label past client_cap 0 is refused and default is not new", res)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND first_query_at IS NOT NULL AND last_query_at IS NOT NULL`, f.A.Endpoint); n != 1 {
		t.Fatal("the Endpoint's times did not move")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE id = $1 AND last_seen_at IS NOT NULL`, f.A.Claim); n != 1 {
		t.Fatal("the claim's last_seen_at did not move")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1 AND last_seen_at IS NOT NULL`, f.A.Endpoint); n != 1 {
		t.Fatal("the authorized row that the source hash names did not move")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1 AND label = 'phone'`, f.A.Endpoint); n != 0 {
		t.Fatal("a client row was made past client_cap")
	}
	// Under the cap, the label gets a row with the sender recorded; a second pass adds nothing.
	for i := 0; i < 2; i++ {
		res, err = hub.HubActivityWrite(f.ctx, f.A.Tenant, []store.HubActivityItem{{Endpoint: f.A.Endpoint, Label: "phone", First: at, Last: at, Node: node, ClientCap: 3}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE endpoint_id = $1 AND label = 'phone' AND source = 'auto' AND created_by_node_id = $2`, f.A.Endpoint, node); n != 1 {
		t.Fatalf("the auto client row: %d", n)
	}
	// Tenant B's rows are untouched by everything above.
	if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND (first_query_at IS NOT NULL OR last_query_at IS NOT NULL)`, f.B.Endpoint); n != 0 {
		t.Fatal("tenant B's Endpoint moved")
	}
	// Tenant A's write handed B's Endpoint and claim: the Endpoint is not A's, so nothing of B is written and nothing fails.
	if _, err := hub.HubActivityWrite(f.ctx, f.A.Tenant, []store.HubActivityItem{
		{Endpoint: f.B.Endpoint, Label: "intruder", Claim: f.B.Claim, First: at, Last: at, Node: node, ClientCap: 9},
	}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.endpoints WHERE id = $1 AND (first_query_at IS NOT NULL OR last_query_at IS NOT NULL)`, f.B.Endpoint); n != 0 {
		t.Fatal("tenant B's Endpoint moved by a write in tenant A")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.ip_claims WHERE id = $1 AND last_seen_at IS NOT NULL`, f.B.Claim); n != 0 {
		t.Fatal("tenant B's claim moved by a write in tenant A")
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.clients WHERE label = 'intruder'`); n != 0 {
		t.Fatal("a client row was made on another tenant's Endpoint")
	}
}

func TestHubLearnIPRules(t *testing.T) {
	f := newFixture(t)
	hub := f.hubStore(t)
	node := uuid.New()
	learn := func(tenant, ep uuid.UUID, ip string) store.HubLearnOutcome {
		t.Helper()
		out, err := hub.HubLearnIP(f.ctx, tenant, store.HubLearn{Endpoint: ep, Source: netip.MustParseAddr(ip), Node: node})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := learn(f.A.Tenant, f.A.Endpoint, "203.0.113.1"); got != store.LearnOff {
		t.Fatalf("authorize_secure_dns is off: %v", got)
	}
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.endpoints SET authorize_secure_dns = true WHERE id = $1`, f.A.Endpoint); err != nil {
		t.Fatal(err)
	}
	if got := learn(f.A.Tenant, f.A.Endpoint, "203.0.113.1"); got != store.LearnWritten {
		t.Fatalf("first address: %v", got)
	}
	if got := learn(f.A.Tenant, f.A.Endpoint, "203.0.113.1"); got != store.LearnRefreshed {
		t.Fatalf("same address again: %v", got)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1 AND source = 'secure_dns' AND learned_by_node_id = $2`, f.A.Endpoint, node); n != 1 {
		t.Fatalf("learned rows: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set'`, f.A.Tenant); n != 1 {
		t.Fatalf("endpoint_set marks: %d", n)
	}
	// B's Endpoint, named inside A's tenant, is not found: nothing is written, B's setting does not matter.
	if got := learn(f.A.Tenant, f.B.Endpoint, "203.0.113.2"); got != store.LearnOff {
		t.Fatalf("another tenant's Endpoint: %v", got)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1 AND source = 'secure_dns'`, f.B.Endpoint); n != 0 {
		t.Fatal("a learned row landed on tenant B's Endpoint")
	}
	// The bound: 100 rows, then a new address is dropped and nothing is evicted.
	for i := 2; i <= store.MaxLearnedPerEndpoint; i++ {
		if got := learn(f.A.Tenant, f.A.Endpoint, netip.AddrFrom4([4]byte{203, 0, 114, byte(i)}).String()); got != store.LearnWritten {
			t.Fatalf("address %d: %v", i, got)
		}
	}
	if got := learn(f.A.Tenant, f.A.Endpoint, "203.0.115.1"); got != store.LearnOverCap {
		t.Fatalf("past the bound: %v", got)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.authorized_ips WHERE endpoint_id = $1 AND source = 'secure_dns'`, f.A.Endpoint); n != store.MaxLearnedPerEndpoint {
		t.Fatalf("learned rows %d", n)
	}
}

func TestHubProofObserveWritesOnceInTheLabelsTenantAndAsksThePairRule(t *testing.T) {
	f := newFixture(t)
	hub := f.hubStore(t)
	tn, ch, claim, found, err := hub.HubProofLookup(f.ctx, "label1")
	if err != nil || !found || tn != f.A.Tenant || claim != f.A.Claim {
		t.Fatalf("lookup: %v %v %v %v %v", tn, ch, claim, found, err)
	}
	if _, _, _, found, _ := hub.HubProofLookup(f.ctx, "nolabel"); found {
		t.Fatal("an unknown label was found")
	}
	node := uuid.New()
	in := store.HubProof{Challenge: ch, Claim: claim, Source: netip.MustParseAddr("198.51.100.7"), Protocol: "udp", CodeHash: make([]byte, 32), Node: node}
	// The pair rule refuses: nothing is written.
	out, err := hub.HubProofObserve(f.ctx, tn, in, func(ep uuid.UUID) bool { return ep != f.A.Endpoint })
	if err != nil || out != store.ProofDenied {
		t.Fatalf("denied: %v %v", out, err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.ip_proof_challenges WHERE id = $1 AND observed_at IS NOT NULL`, ch); n != 0 {
		t.Fatal("a refused observation was written")
	}
	var asked uuid.UUID
	out, err = hub.HubProofObserve(f.ctx, tn, in, func(ep uuid.UUID) bool { asked = ep; return true })
	if err != nil || out != store.ProofWritten || asked != f.A.Endpoint {
		t.Fatalf("written: %v %v asked %v", out, err, asked)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.ip_proof_challenges WHERE id = $1 AND observed_protocol = 'udp' AND observed_by_node_id = $2 AND txt_code_hash IS NOT NULL`, ch, node); n != 1 {
		t.Fatal("the observation is not on the row")
	}
	// Once: the second is stale.
	if out, err = hub.HubProofObserve(f.ctx, tn, in, func(uuid.UUID) bool { return true }); err != nil || out != store.ProofStale {
		t.Fatalf("second: %v %v", out, err)
	}
	// B's challenge cannot be written through A's tenant: the claim is not found there.
	_, chB, claimB, _, _ := hub.HubProofLookup(f.ctx, "label2")
	inB := in
	inB.Challenge, inB.Claim = chB, claimB
	if out, err = hub.HubProofObserve(f.ctx, f.A.Tenant, inB, func(uuid.UUID) bool { return true }); err != nil || out != store.ProofGone {
		t.Fatalf("another tenant's claim: %v %v", out, err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.ip_proof_challenges WHERE id = $1 AND observed_at IS NOT NULL`, chB); n != 0 {
		t.Fatal("tenant B's challenge was written")
	}
}

func TestHubFreeCountersCountABatchOnce(t *testing.T) {
	f := newFixture(t)
	hub := f.hubStore(t)
	node := uuid.New()
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.nodes (id, slot, name, status, spki_sha256) VALUES ($1, 3, 'n1', 'active', $2)`, node, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	bucket := time.Now().Unix() / 300 * 300
	items := []store.HubFreeItem{{Protocol: "udp", Outcome: "answered", RCode: 0, Count: 5}, {Protocol: "tcp", Outcome: "rd0", RCode: 5, Count: 2}}
	if ok, err := hub.HubFreeCounters(f.ctx, node, 1<<63|7, bucket, items); err != nil || !ok {
		t.Fatalf("first: %v %v", ok, err)
	}
	if ok, err := hub.HubFreeCounters(f.ctx, node, 1<<63|7, bucket, items); err != nil || ok {
		t.Fatalf("resent batch: %v %v", ok, err)
	}
	if ok, err := hub.HubFreeCounters(f.ctx, node, 9, bucket, items); err != nil || ok {
		t.Fatalf("another id for the same bucket: %v %v", ok, err)
	}
	if n := f.count(t, `SELECT sum(count)::int FROM ctrlz.free_dns_counters WHERE node_id = $1`, node); n != 7 {
		t.Fatalf("counted %d, want 7", n)
	}
}

func TestHubQuarantineAddCountsNodes(t *testing.T) {
	f := newFixture(t)
	hub := f.hubStore(t)
	a, b := uuid.New(), uuid.New()
	// The seed holds slots 1 and 2, so the two new nodes take 3 and 4.
	for i, n := range []uuid.UUID{a, b} {
		if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.nodes (id, slot, name, status, spki_sha256) VALUES ($1, $2, $3, 'active', $4)`,
			n, i+3, "n"+string(rune('a'+i)), append(make([]byte, 31), byte(i+1))); err != nil {
			t.Fatal(err)
		}
	}
	ins, n, err := hub.HubQuarantineAdd(f.ctx, a, 12, "ab", "bad_section")
	if err != nil || !ins || n != 1 {
		t.Fatalf("first: %v %d %v", ins, n, err)
	}
	if ins, n, err = hub.HubQuarantineAdd(f.ctx, a, 12, "ab", "bad_section"); err != nil || ins || n != 1 {
		t.Fatalf("repeat: %v %d %v", ins, n, err)
	}
	if ins, n, err = hub.HubQuarantineAdd(f.ctx, b, 12, "ab", "bad_section"); err != nil || !ins || n != 2 {
		t.Fatalf("second node: %v %d %v", ins, n, err)
	}
}

func TestHubWriteBeatWritesOnlyAnActiveNode(t *testing.T) {
	f := newFixture(t)
	hub := f.hubStore(t)
	node := uuid.New()
	if err := f.db.Exec(f.ctx, `INSERT INTO ctrlz.nodes (id, slot, name, status, spki_sha256) VALUES ($1, 3, 'n1', 'pending', $2)`, node, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	heard := time.Now().Add(-9 * time.Minute).Truncate(time.Second)
	in := store.HubBeat{VersionInfo: []byte(`{"node_version":"1.0"}`), AppliedSeq: 42, At: heard}
	if err := hub.HubWriteBeat(f.ctx, node, in); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.nodes WHERE id = $1 AND applied_seq = 42`, node); n != 0 {
		t.Fatal("a pending node was written")
	}
	if err := f.db.Exec(f.ctx, `UPDATE ctrlz.nodes SET status = 'active' WHERE id = $1`, node); err != nil {
		t.Fatal(err)
	}
	if err := hub.HubWriteBeat(f.ctx, node, in); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.nodes WHERE id = $1 AND applied_seq = 42 AND last_heartbeat_at = $2 AND version_info->>'node_version' = '1.0'`, node, heard); n != 1 {
		t.Fatal("an active node's Heartbeat fields were not written")
	}
}
