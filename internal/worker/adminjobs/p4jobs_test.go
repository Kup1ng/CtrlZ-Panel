package adminjobs_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/adminjobs"
)

// The seed's two active nodes and their global pair (internal/store/catalogtest/seed.go).
const (
	seedNode1 = "00000000-0000-7000-8000-0000000000c1"
	seedNode2 = "00000000-0000-7000-8000-0000000000c2"
)

// supersede plays the admin route: it ends the unfinished job of the kind and queues the next one, in one transaction as the
// routes do (migration 0028).
func (r *rig) supersede(kind string, params any) uuid.UUID {
	r.t.Helper()
	if err := r.admin.WithGlobal(r.env.Ctx, store.TxOpts{}, func(g store.GlobalTx) error {
		_, err := g.AdminJobsSupersede(kind)
		return err
	}); err != nil {
		r.t.Fatal(err)
	}
	return r.queue(kind, params)
}

func (r *rig) notices(tenant uuid.UUID, kind string) int {
	r.t.Helper()
	return r.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = $2`, tenant, kind)
}

func (r *rig) pairVersion(endpoint uuid.UUID) int {
	r.t.Helper()
	return r.count(`SELECT pair_version FROM ctrlz.endpoints WHERE id = $1`, endpoint)
}

func TestPairChangeBumpsEveryEndpointAndNotifiesAPlainDNSTenantOncePerAddresses(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	a, b := r.env.A, r.env.B
	// B holds no Plain DNS claim any more: it still has its records rewritten, and is told nothing.
	r.env.Exec(t, `UPDATE ctrlz.ip_claims SET state = 'released' WHERE tenant_id = $1`, b.Tenant)
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)
	a0, b0 := r.pairVersion(a.Endpoint), r.pairVersion(b.Endpoint)

	id := r.queue(adminjobs.KindPairChange, map[string]string{})
	if n := r.runOnce(); n != 1 {
		t.Fatalf("ran %d jobs", n)
	}
	if state, progress := r.job(id); state != "done" || progress["endpoints_bumped"] != float64(2) || progress["tenants_notified"] != float64(1) {
		t.Fatalf("state %s, progress %v", state, progress)
	}
	if r.pairVersion(a.Endpoint) != a0+1 || r.pairVersion(b.Endpoint) != b0+1 {
		t.Error("an Endpoint was not bumped")
	}
	for _, tenant := range []uuid.UUID{a.Tenant, b.Tenant} {
		if r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set'`, tenant) == 0 {
			t.Errorf("tenant %v: the Endpoint records were not marked", tenant)
		}
	}
	if r.notices(a.Tenant, "pair_changed") != 1 || r.notices(b.Tenant, "pair_changed") != 0 {
		t.Error("the notice went to the wrong tenants")
	}

	// A run again for the same addresses: the records are written again (a bump), and nobody is told twice.
	r.queue(adminjobs.KindPairChange, map[string]string{})
	r.runOnce()
	if r.pairVersion(a.Endpoint) != a0+2 {
		t.Error("a repeat run did not bump")
	}
	if r.notices(a.Tenant, "pair_changed") != 1 {
		t.Errorf("a repeat run told tenant A again: %d notices", r.notices(a.Tenant, "pair_changed"))
	}

	// New addresses are news.
	var orig string
	r.env.Scan(t, `SELECT host(dns_advertised_ip) FROM ctrlz.nodes WHERE id = $1`, []any{seedNode1}, &orig)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET dns_advertised_ip = '192.0.2.77' WHERE id = $1`, seedNode1)
	r.queue(adminjobs.KindPairChange, map[string]string{})
	r.runOnce()
	if r.notices(a.Tenant, "pair_changed") != 2 {
		t.Errorf("tenant A was not told the new addresses: %d notices", r.notices(a.Tenant, "pair_changed"))
	}
	// J12-r1-6 and 14: the pair moves back to the addresses the tenant was told first. That is a change the tenant must act on
	// (the address it moved its router off is given back), so it is told again; a run that repeats the same pair is not.
	r.env.Exec(t, `UPDATE ctrlz.nodes SET dns_advertised_ip = $2::inet WHERE id = $1`, seedNode1, orig)
	r.queue(adminjobs.KindPairChange, map[string]string{})
	r.runOnce()
	if r.notices(a.Tenant, "pair_changed") != 3 {
		t.Errorf("tenant A was not told of the move back: %d notices", r.notices(a.Tenant, "pair_changed"))
	}
	r.queue(adminjobs.KindPairChange, map[string]string{})
	r.runOnce()
	if r.notices(a.Tenant, "pair_changed") != 3 {
		t.Errorf("a repeat of the pair told tenant A again: %d notices", r.notices(a.Tenant, "pair_changed"))
	}
	// The key is a hash and the notice carries the two addresses for the text, and no other tenant's.
	if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'pair_changed' AND params ->> 'primary' = '192.0.2.77' AND params ->> 'fallback' = '192.0.2.2'`) != 1 {
		t.Error("the notice does not carry the addresses")
	}
}

// Two quick changes, the first superseded after half the tenants (spec 8): the second job walks every tenant, and each
// tenant ends with the notice of the addresses in force once, whatever the first job did before it was ended.
func TestPairChangeSupersededHalfWayLosesNothingAndDoublesNothing(t *testing.T) {
	var r *rig
	var second uuid.UUID
	r = newRig(t, adminjobs.Config{AfterPage: func(done int) {
		if done == 1 && second == uuid.Nil {
			// Between the first tenant and the second, an admin moves the primary address and queues the next job.
			r.env.Exec(r.t, `UPDATE ctrlz.nodes SET dns_advertised_ip = '192.0.2.88' WHERE id = $1`, seedNode1)
			second = r.supersede(adminjobs.KindPairChange, map[string]string{})
		}
	}})
	a, b := r.env.A, r.env.B
	a0, b0 := r.pairVersion(a.Endpoint), r.pairVersion(b.Endpoint)

	first := r.queue(adminjobs.KindPairChange, map[string]string{})
	r.runOnce()
	if state, progress := r.job(first); state != "failed" || progress["superseded"] != true {
		t.Fatalf("the first job: state %s, progress %v", state, progress)
	}
	if second == uuid.Nil {
		t.Fatal("the hook did not run")
	}
	if n := r.runOnce(); n != 1 {
		t.Fatalf("ran %d jobs", n)
	}
	if state, _ := r.job(second); state != "done" {
		t.Fatalf("the second job: state %s", state)
	}
	// Every Endpoint was bumped by the job that reached it, and the tenant the first job did reach is bumped again.
	if r.pairVersion(a.Endpoint) < a0+1 || r.pairVersion(b.Endpoint) < b0+1 {
		t.Error("an Endpoint was left alone")
	}
	for _, tenant := range []uuid.UUID{a.Tenant, b.Tenant} {
		// The new addresses: once. A tenant the first job reached before the move holds one for the old addresses as well.
		if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'pair_changed' AND params ->> 'primary' = '192.0.2.88'`, tenant) != 1 {
			t.Errorf("tenant %v does not hold exactly one notice of the addresses in force", tenant)
		}
		if r.count(`SELECT count(*) - count(DISTINCT params ->> 'key') FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'pair_changed'`, tenant) != 0 {
			t.Errorf("tenant %v was told one state twice", tenant)
		}
	}
}

func TestDomainChangeNotifiesEachTenantOncePerStateAndStartsAgainWhenTheStateMoves(t *testing.T) {
	var r *rig
	moved, pending := false, false
	r = newRig(t, adminjobs.Config{AfterPage: func(done int) {
		if done == 1 && !moved && pending {
			moved = true
			// The hub issues a new zone CA while the walk is between its first and second tenant: its own job met this one in
			// the table and queued nothing (4.3).
			r.zoneCA("2 hours")
		}
	}})
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `UPDATE ctrlz.domain_settings SET dns_zone = 'dns.example.org'`)
	r.zoneCA("1 day")

	// A plain run: each tenant is told once, with the reinstall line, and a run again tells nobody.
	id := r.queue(adminjobs.KindDomainChange, map[string]string{})
	r.runOnce()
	if state, progress := r.job(id); state != "done" || progress["tenants_notified"] != float64(2) || progress["passes"] != float64(1) {
		t.Fatalf("state %s, progress %v", state, progress)
	}
	for _, tenant := range []uuid.UUID{a.Tenant, b.Tenant} {
		if r.notices(tenant, "domain_changed") != 1 {
			t.Errorf("tenant %v: %d notices", tenant, r.notices(tenant, "domain_changed"))
		}
		if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE tenant_id = $1 AND kind = 'domain_changed' AND params ->> 'reinstall' = 'yes' AND params ->> 'zone' = 'dns.example.org'`, tenant) != 1 {
			t.Errorf("tenant %v: the notice does not carry the zone and the reinstall line", tenant)
		}
	}
	r.queue(adminjobs.KindDomainChange, map[string]string{})
	r.runOnce()
	if r.notices(a.Tenant, "domain_changed") != 1 || r.notices(b.Tenant, "domain_changed") != 1 {
		t.Error("a run again told a tenant twice for one state")
	}

	// An upload that covers the zone changes the line and not the key: no second notice.
	r.env.Exec(t, `INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, names, source)
		VALUES ('wildcard', 'x', now() - interval '1 day', now() + interval '60 days', 'active',
		        ARRAY['dns.example.org', '*.dns.example.org', '*.verify.dns.example.org'], 'uploaded')`)
	r.queue(adminjobs.KindDomainChange, map[string]string{})
	r.runOnce()
	if r.notices(a.Tenant, "domain_changed") != 1 {
		t.Error("an upload alone made a second notice")
	}

	// The state moves while a pass runs: the pass starts again, and every tenant ends with the notice of the final state.
	pending = true
	id = r.queue(adminjobs.KindDomainChange, map[string]string{})
	r.runOnce()
	state, progress := r.job(id)
	if state != "done" || progress["passes"] != float64(2) {
		t.Fatalf("state %s, progress %v", state, progress)
	}
	// A held the notice of the old state already and is told the new one in the second pass; B saw only the new one, in the
	// first, and the second pass finds it told.
	if r.notices(a.Tenant, "domain_changed") != 2 || r.notices(b.Tenant, "domain_changed") != 2 {
		t.Errorf("notices A %d, B %d", r.notices(a.Tenant, "domain_changed"), r.notices(b.Tenant, "domain_changed"))
	}
	// An upload covers the zone now, so the line is not the reinstall one.
	if r.count(`SELECT count(*) FROM ctrlz.notifications WHERE kind = 'domain_changed' AND params ->> 'reinstall' = 'no'`) != 2 {
		t.Error("the reinstall line was not left out where an upload covers the zone")
	}
}

// zoneCA retires the active zone CA row and issues a new one that began the given interval ago (so the newer row has the
// later start when the interval is shorter).
func (r *rig) zoneCA(ago string) {
	r.t.Helper()
	r.env.Exec(r.t, `UPDATE ctrlz.certificates SET state = 'retired' WHERE kind = 'zone_ca' AND state = 'active'`)
	r.env.Exec(r.t, `INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, names)
		VALUES ('zone_ca', 'x', now() - $1::interval, now() + interval '10 years', 'active', ARRAY['dns.example.org'])`, ago)
}

func (r *rig) addLearned(tenant, endpoint uuid.UUID, cidr, node string) uuid.UUID {
	r.t.Helper()
	var id uuid.UUID
	r.env.Scan(r.t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, learned_by_node_id)
		VALUES ($1, $2, $3::cidr, 'secure_dns', $4) RETURNING id`, []any{tenant, endpoint, cidr, node}, &id)
	return id
}

func (r *rig) addClient(tenant, endpoint uuid.UUID, label, node string, alias any) {
	r.t.Helper()
	r.env.Exec(r.t, `INSERT INTO ctrlz.clients (tenant_id, endpoint_id, label, source, created_by_node_id, alias, last_seen_at)
		VALUES ($1, $2, $3, 'auto', $4, $5, now() - interval '1 hour')`, tenant, endpoint, label, node, alias)
}

func TestNodeRevokedDeletesWhatTheNodeReportedAndNothingElse(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	a, b := r.env.A, r.env.B
	// The seeded address of each Endpoint is a manual one and stays. Tenant A: two addresses and four clients of the revoked
	// node and one of another node. Tenant B: one address of each node.
	r.addLearned(a.Tenant, a.Endpoint, "203.0.113.1/32", seedNode1)
	r.addLearned(a.Tenant, a.Endpoint, "203.0.113.2/32", seedNode1)
	r.addLearned(a.Tenant, a.Endpoint, "203.0.113.3/32", seedNode2)
	r.addLearned(b.Tenant, b.Endpoint, "203.0.113.1/32", seedNode1)
	r.addLearned(b.Tenant, b.Endpoint, "203.0.113.2/32", seedNode2)
	r.addClient(a.Tenant, a.Endpoint, "plain-one", seedNode1, nil)
	r.addClient(a.Tenant, a.Endpoint, "plain-two", seedNode1, nil)
	r.addClient(a.Tenant, a.Endpoint, "named", seedNode1, "mine")
	r.addClient(a.Tenant, a.Endpoint, "other-node", seedNode2, nil)
	r.addClient(b.Tenant, b.Endpoint, "plain-b", seedNode1, nil)
	// A client of the revoked node that was seen after the revoke is a real device: it stays.
	r.addClient(a.Tenant, a.Endpoint, "seen-later", seedNode1, nil)
	r.env.Exec(t, `UPDATE ctrlz.clients SET last_seen_at = now() + interval '1 hour' WHERE tenant_id = $1 AND label = 'seen-later'`, a.Tenant)
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)

	id := r.queue(adminjobs.KindNodeRevoked, map[string]any{"node_ids": []string{seedNode1}})
	r.runOnce()
	state, progress := r.job(id)
	if state != "done" || progress["addresses_deleted"] != float64(3) || progress["clients_deleted"] != float64(3) {
		t.Fatalf("state %s, progress %v", state, progress)
	}
	left := func(tenant uuid.UUID, table, where string) int {
		return r.count(`SELECT count(*) FROM ctrlz.`+table+` WHERE tenant_id = $1 AND `+where, tenant)
	}
	if left(a.Tenant, "authorized_ips", `learned_by_node_id IS NOT NULL`) != 1 || left(b.Tenant, "authorized_ips", `learned_by_node_id IS NOT NULL`) != 1 {
		t.Error("the learned addresses of the revoked node did not all go, or another node's went")
	}
	if left(a.Tenant, "authorized_ips", `source = 'manual'`) != 1 || left(b.Tenant, "authorized_ips", `source = 'manual'`) != 1 {
		t.Error("a manual address went")
	}
	if left(a.Tenant, "clients", `source = 'auto' AND label IN ('named', 'other-node', 'seen-later', 'default')`) != 4 || left(b.Tenant, "clients", `label = 'plain-b'`) != 0 {
		t.Error("a client row went that was not the revoked node's untouched one, or stayed that was")
	}
	for _, tenant := range []uuid.UUID{a.Tenant, b.Tenant} {
		if r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set'`, tenant) == 0 {
			t.Errorf("tenant %v: the Endpoint records were not marked", tenant)
		}
	}
	if r.notices(a.Tenant, "authorized_review") != 0 {
		t.Error("a tenant that lost nothing it needs was told to review")
	}
	// A run again finds nothing and changes nothing.
	r.queue(adminjobs.KindNodeRevoked, map[string]any{"node_ids": []string{seedNode1}})
	r.runOnce()
	if left(a.Tenant, "authorized_ips", `learned_by_node_id IS NOT NULL`) != 1 {
		t.Error("a repeat run deleted more")
	}
}

func TestNodeRevokedKeepsTheLastAddressOfAnEndpointThatRequiresThemAndSaysSo(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	a, b := r.env.A, r.env.B
	// Tenant A requires authorized addresses and holds only what the revoked node learned. B holds the same under no
	// requirement: B loses all of them, and is not told to review.
	r.env.Exec(t, `DELETE FROM ctrlz.authorized_ips WHERE tenant_id = ANY ($1)`, []uuid.UUID{a.Tenant, b.Tenant})
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET require_authorized_ips = true WHERE id = $1`, a.Endpoint)
	r.addLearned(a.Tenant, a.Endpoint, "203.0.113.1/32", seedNode1)
	r.addLearned(a.Tenant, a.Endpoint, "203.0.113.2/32", seedNode1)
	r.addLearned(b.Tenant, b.Endpoint, "203.0.113.1/32", seedNode1)
	r.addLearned(b.Tenant, b.Endpoint, "203.0.113.2/32", seedNode1)

	params := map[string]any{"node_ids": []string{seedNode1}}
	id := r.queue(adminjobs.KindNodeRevoked, params)
	r.runOnce()
	state, progress := r.job(id)
	if state != "done" || progress["addresses_deleted"] != float64(3) || progress["kept_total"] != float64(1) {
		t.Fatalf("state %s, progress %v", state, progress)
	}
	kept, _ := progress["kept"].([]any)
	if len(kept) != 1 {
		t.Fatalf("the kept row is not in the progress: %v", progress["kept"])
	}
	k, _ := kept[0].(map[string]any)
	if k["tenant_id"] != a.Tenant.String() || k["endpoint_id"] != a.Endpoint.String() || k["node_id"] != seedNode1 {
		t.Errorf("the kept row names %v", k)
	}
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, a.Tenant) != 1 || r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, b.Tenant) != 0 {
		t.Error("the last address went, or one of the tenant without a requirement stayed")
	}
	if r.notices(a.Tenant, "authorized_review") != 1 || r.notices(b.Tenant, "authorized_review") != 0 {
		t.Error("the review notice went to the wrong tenants")
	}
	alerts := func() int {
		return r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'node_revoked' AND resolved_at IS NULL AND params ->> 'tenant_id' = $1 AND params ->> 'endpoint_id' = $2`, a.Tenant.String(), a.Endpoint.String())
	}
	if alerts() != 1 {
		t.Errorf("%d open alerts for the Endpoint", alerts())
	}

	// A run again, or the job that replaces this one with the same node behind it: still one notice and one open alert, and the
	// row is recorded again.
	id = r.supersede(adminjobs.KindNodeRevoked, params)
	r.runOnce()
	if _, progress := r.job(id); progress["kept_total"] != float64(1) {
		t.Errorf("the repeat did not record the kept row: %v", progress)
	}
	if r.notices(a.Tenant, "authorized_review") != 1 || alerts() != 1 {
		t.Error("a repeat run raised the alert or told the tenant twice")
	}
}

func TestNodeRevokedWithoutNodesIsRefused(t *testing.T) {
	r := newRig(t, adminjobs.Config{})
	id := r.queue(adminjobs.KindNodeRevoked, map[string]any{"node_ids": []string{}})
	_, _ = r.runner.RunOnce(r.env.Ctx)
	if state, progress := r.job(id); state != "failed" || progress["error"] != "bad_params" {
		t.Errorf("state %s, progress %v", state, progress)
	}
}

// J12-r1-13: a P4 job that keeps losing lock races is not given up (nobody queues a revoke twice), and an admin is told; a P4 job
// that ends as failed raises an alert and keeps what its last run reported.
func TestAP4JobThatKeepsLosingLockRacesStaysRunningAndAFailedOneAlerts(t *testing.T) {
	boom := errors.New("boom")
	r := newRig(t, adminjobs.Config{MaxFailures: 2, Backoff: []time.Duration{time.Nanosecond}, Handlers: map[string]adminjobs.Handler{
		adminjobs.KindNodeRevoked: func(_ context.Context, _ store.AdminJob, report adminjobs.Report) (any, error) {
			report(map[string]int{"kept_total": 7})
			return nil, store.ErrRetry
		},
		adminjobs.KindPairChange: func(_ context.Context, _ store.AdminJob, report adminjobs.Report) (any, error) {
			report(map[string]int{"tenants": 3})
			return nil, boom
		},
	}})
	revoke := r.queue(adminjobs.KindNodeRevoked, map[string]any{"node_ids": []string{seedNode1}})
	for i := 0; i < 5; i++ {
		_, _ = r.runner.RunOnce(r.env.Ctx)
		time.Sleep(2 * time.Millisecond)
	}
	if state, _ := r.job(revoke); state != "running" {
		t.Errorf("the revoke ended as %s after lost lock races", state)
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'node_revoked' AND params ->> 'reason' = 'job_stuck'`) != 1 {
		t.Error("no single alert for the stuck revoke")
	}

	pair := r.queue(adminjobs.KindPairChange, map[string]string{})
	for i := 0; i < 5; i++ {
		_, _ = r.runner.RunOnce(r.env.Ctx)
		time.Sleep(2 * time.Millisecond)
	}
	state, progress := r.job(pair)
	if state != "failed" || progress["error"] != "error" || progress["tenants"] != float64(3) {
		t.Errorf("state %s, progress %v: the failure must keep the last progress", state, progress)
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'pair_change' AND params ->> 'reason' = 'job_failed'`) != 1 {
		t.Error("no alert for the failed pair change")
	}
}

// J12-r2-6: once a revoke has lost enough runs to a lock race, a lost database connection does not end it as failed either.
func TestAStuckP4JobSurvivesALostConnection(t *testing.T) {
	calls := 0
	r := newRig(t, adminjobs.Config{MaxFailures: 2, Backoff: []time.Duration{time.Nanosecond}, Handlers: map[string]adminjobs.Handler{
		adminjobs.KindNodeRevoked: func(context.Context, store.AdminJob, adminjobs.Report) (any, error) {
			calls++
			if calls <= 3 {
				return nil, store.ErrRetry
			}
			return nil, store.ErrConnection
		},
	}})
	revoke := r.queue(adminjobs.KindNodeRevoked, map[string]any{"node_ids": []string{seedNode1}})
	for i := 0; i < 8; i++ {
		_, _ = r.runner.RunOnce(r.env.Ctx)
		time.Sleep(2 * time.Millisecond)
	}
	if calls < 5 {
		t.Fatalf("the handler ran %d times, too few to reach the connection errors", calls)
	}
	if state, _ := r.job(revoke); state != "running" {
		t.Errorf("a lost connection ended the stuck revoke as %s", state)
	}
}
