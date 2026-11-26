// Package dbtest runs the periodic jobs of P4 (docs/specs/p4-nodes.md 8) over a real, migrated database as ctrlz_worker. It is a
// package of its own because its TestMain starts a container, which the unit tests of internal/worker/periodic must not need.
//
// Every test has two tenants (the seed's A and B) and checks that a job writes for the tenant whose state asked for it and
// leaves the other's rows and digests as they were.
package dbtest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
	"github.com/Kup1ng/CtrlZ-Panel/internal/worker/periodic"
)

var cluster *testpg.Cluster

func TestMain(m *testing.M) {
	os.Exit(testpg.RunMain(m, func(c *testpg.Cluster) { cluster = c }))
}

// The seed's two active nodes (internal/store/catalogtest/seed.go).
const (
	seedNode1 = "00000000-0000-7000-8000-0000000000c1"
	seedNode2 = "00000000-0000-7000-8000-0000000000c2"
)

// resolver answers from a table; a host with no entry fails.
type resolver struct {
	mu   sync.Mutex
	by   map[string][]netip.Addr
	fail map[string]bool
	// onLookup, when set, runs while a host is being resolved: a tenant's change between the read of the work and the write.
	onLookup func(host string)
}

func (r *resolver) Lookup(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.onLookup != nil {
		r.onLookup(host)
	}
	if r.fail[host] {
		return nil, errors.New("the lookup failed")
	}
	return r.by[host], nil
}

// budget lets a number of claim requests through and then refuses.
type budget struct {
	mu    sync.Mutex
	left  int
	asked []uuid.UUID
}

func (b *budget) Allow(_ context.Context, tenant uuid.UUID) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asked = append(b.asked, tenant)
	if b.left <= 0 {
		return false, nil
	}
	b.left--
	return true, nil
}

type blobs struct {
	mu   sync.Mutex
	gone [][]byte
	// probe, when set, runs on every Delete and its answer is kept in locked: whether the log lock was held at that moment.
	probe  func() bool
	locked []bool
	// fail, when set, is what every Delete answers: a file that will not go.
	fail error
	// failFor, when set, makes the Delete of the hashes it names fail and no other.
	failFor func(h []byte) bool
}

func (b *blobs) Delete(h []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gone = append(b.gone, append([]byte(nil), h...))
	if b.probe != nil {
		b.locked = append(b.locked, b.probe())
	}
	if b.failFor != nil && b.failFor(h) {
		return errors.New("the file will not go")
	}
	return b.fail
}

type rig struct {
	t      *testing.T
	env    *authtest.Env
	runner *periodic.Runner
	res    *resolver
	bud    *budget
	blobs  *blobs
}

func newRig(t *testing.T) *rig {
	t.Helper()
	env := authtest.New(t, cluster)
	r := &rig{t: t, env: env, res: &resolver{by: map[string][]netip.Addr{}, fail: map[string]bool{}}, bud: &budget{left: 100}, blobs: &blobs{}}
	runner, err := periodic.New(periodic.Config{
		Store: env.Worker(t), Log: slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Resolver: r.res, Claims: r.bud, Blobs: r.blobs, Page: 1, Batch: 2, // one tenant per read and two rows per batch: the paging is exercised
	})
	if err != nil {
		t.Fatal(err)
	}
	r.runner = runner
	return r
}

func (r *rig) run(j periodic.Job) {
	r.t.Helper()
	if err := r.runner.RunJob(r.env.Ctx, j); err != nil {
		r.t.Fatalf("%s: %v", j, err)
	}
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.env.DB.Scan(r.env.Ctx, sql, args, &n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// ---------------------------------------------------------------------------
// DDNS.

// The host of tenant A answers with a public address, an injected one and a private one; B's host answers with another
// public address. A's pass writes A's address and only A's, B's writes B's, the injected answer raises an alert and is never
// written, and each tenant's Endpoint record is marked for the compiler.
func TestDDNSWritesThePublicAnswersOfEachTenantsOwnHostsOnly(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true`)
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)
	r.res.by["home1.example.test"] = addrs("8.8.8.8", "10.10.34.5", "192.168.1.1")
	r.res.by["home2.example.test"] = addrs("9.9.9.9")

	r.run(periodic.JobDDNS)

	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '8.8.8.8/32'`, a.Tenant) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '9.9.9.9/32'`, b.Tenant) != 1 {
		t.Fatal("a tenant's own host address was not written")
	}
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE source = 'ddns' AND tenant_id = $1 AND cidr = '9.9.9.9/32'`, a.Tenant) != 0 ||
		r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE source = 'ddns' AND tenant_id = $1 AND cidr = '8.8.8.8/32'`, b.Tenant) != 0 {
		t.Fatal("an address crossed to the other tenant")
	}
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE cidr IN ('10.10.34.5/32', '192.168.1.1/32')`) != 0 {
		t.Fatal("a non-public answer was written")
	}
	// The seed's row of the host (198.51.N.0/24) is not among the answers: the host answered without it, so it goes.
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND cidr = '198.51.1.0/24'`, a.Tenant) != 0 {
		t.Error("a row the host no longer answers with stayed")
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'periodic' AND params ->> 'reason' = 'ddns_injected'`) != 1 {
		t.Error("the injected answer raised no alert, or raised it twice")
	}
	for _, tenant := range []uuid.UUID{a.Tenant, b.Tenant} {
		if r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set'`, tenant) == 0 {
			t.Errorf("tenant %v: the Endpoint record was not marked", tenant)
		}
	}
	if r.count(`SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND last_resolved_at IS NOT NULL AND last_error IS NULL AND last_ips = ARRAY['8.8.8.8']::inet[]`, a.Tenant) != 1 {
		t.Error("the host's last answer was not recorded")
	}

	// The host moves: the old address goes, the new one comes, once, and a repeat pass changes nothing.
	r.res.by["home1.example.test"] = addrs("1.1.1.1")
	r.run(periodic.JobDDNS)
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)
	r.run(periodic.JobDDNS)
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns'`, a.Tenant) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '1.1.1.1/32'`, a.Tenant) != 1 {
		t.Error("the moved host's rows are not exactly its new address")
	}
	if r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1`, a.Tenant) != 0 {
		t.Error("a pass that changed nothing marked the Endpoint")
	}
}

// A failed lookup changes nothing (an outage of the resolver is not an answer), an empty answer changes nothing, and more
// than twenty public addresses change nothing and alert.
func TestDDNSChangesNothingOnAFailedEmptyOrCrowdedAnswer(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true`)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.run(periodic.JobDDNS)
	rows := r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, a.Tenant)

	r.res.fail["home1.example.test"] = true
	r.run(periodic.JobDDNS)
	delete(r.res.fail, "home1.example.test")
	r.res.by["home1.example.test"] = nil
	r.run(periodic.JobDDNS)
	var many []netip.Addr
	for i := 0; i < 21; i++ {
		many = append(many, netip.AddrFrom4([4]byte{8, 8, byte(i), 1}))
	}
	r.res.by["home1.example.test"] = many
	r.run(periodic.JobDDNS)

	if got := r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1`, a.Tenant); got != rows {
		t.Fatalf("rows %d, want %d: a bad answer changed the Endpoint", got, rows)
	}
	if r.count(`SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND last_error = 'too_many' AND last_ips = ARRAY['8.8.8.8']::inet[]`, a.Tenant) != 1 {
		t.Error("the failure was not recorded beside the last good answer")
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'periodic' AND params ->> 'reason' = 'ddns_too_many'`) != 1 {
		t.Error("no alert for the crowded answer")
	}
}

// A host of an Endpoint with authorize_ddns off is neither resolved nor written, and a lookup that has failed for more than 24 h
// alerts.
func TestDDNSLeavesAnEndpointWithTheFlagOffAndAlertsOnAStaleHost(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true WHERE tenant_id = $1`, a.Tenant) // B's stays off
	r.env.Exec(t, `UPDATE ctrlz.endpoint_ddns_hosts SET created_at = now() - interval '2 days' WHERE tenant_id = $1`, a.Tenant)
	r.res.fail["home1.example.test"] = true
	r.res.by["home2.example.test"] = addrs("9.9.9.9")
	r.run(periodic.JobDDNS)
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns'`, b.Tenant) != 0 {
		t.Error("an Endpoint with the flag off was written")
	}
	if r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'periodic' AND params ->> 'reason' = 'ddns_lookup_stale'`) != 1 {
		t.Error("a host with no answer for two days raised no alert")
	}
}

// On a Plain DNS Endpoint a new address is a claim request charged to the tenant's ip-claim class: with room, the claim and
// the row appear; with none, nothing changes and the old rows stay, and the next pass with room makes the change.
func TestDDNSChargesAClaimRequestAndWaitsWhenTheBudgetIsSpent(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")

	r.bud.left = 0
	r.run(periodic.JobDDNS)
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns'`, a.Tenant) != 0 ||
		r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND cidr = '198.51.1.0/24'`, a.Tenant) != 1 {
		t.Fatal("a spent budget changed the Endpoint")
	}
	if r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND source = 'ddns'`, a.Tenant) != 0 {
		t.Fatal("a claim was requested without a charge")
	}

	r.bud.left = 5
	r.run(periodic.JobDDNS)
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '8.8.8.8/32'`, a.Tenant) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '8.8.8.8/32'`, a.Tenant) != 1 {
		t.Fatal("with room, the address and its claim were not written")
	}
	left := r.bud.left
	r.run(periodic.JobDDNS)
	if r.bud.left != left {
		t.Error("an address the Endpoint already holds was charged again")
	}
}

// ---------------------------------------------------------------------------
// The rest.

func (r *rig) enrolment(state, expires, extra string, node any) {
	r.t.Helper()
	r.env.Exec(r.t, `INSERT INTO ctrlz.node_enrollments (token_hash, expires_at, bound_ip, state, enrolled_at, node_id`+extra+`)
		VALUES (sha256(convert_to(gen_random_uuid()::text, 'UTF8')), now() + $1::interval, '198.51.100.1', $2, now() - interval '25 hours', $3`+valuesOf(extra)+`)`,
		expires, state, node)
}

func valuesOf(extra string) string {
	if extra == "" {
		return ""
	}
	return `, '\x30'::bytea`
}

func TestEnrollmentsExpireAndAreSweptAWeekLater(t *testing.T) {
	r := newRig(t)
	// A node that was revoked: its approved enrolment with no certificate goes, where an active node's stays.
	r.env.Exec(t, `INSERT INTO ctrlz.nodes (id, slot, name) VALUES ('00000000-0000-7000-8000-0000000000c9', 3, 'gone')`)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET status = 'revoked' WHERE id = '00000000-0000-7000-8000-0000000000c9'`)

	r.enrolment("issued", "-1 minute", "", nil)                                    // expired
	r.enrolment("issued", "10 minutes", "", nil)                                   // stays
	r.enrolment("pending_approval", "1 day", "", nil)                              // enrolled 25 h ago: expired
	r.enrolment("expired", "-8 days", "", nil)                                     // deleted
	r.enrolment("expired", "-1 day", "", nil)                                      // stays
	r.enrolment("rejected", "-8 days", "", nil)                                    // deleted
	r.enrolment("approved", "-8 days", ", cert_der", seedNode1)                    // issued by Poll: deleted
	r.enrolment("approved", "-8 days", "", seedNode1)                              // the agent still polls: stays
	r.enrolment("approved", "-8 days", "", "00000000-0000-7000-8000-0000000000c9") // its node was revoked: deleted

	r.run(periodic.JobEnrollments)

	want := map[string]int{"issued": 1, "pending_approval": 0, "expired": 3, "rejected": 0, "approved": 1}
	for state, n := range want {
		if got := r.count(`SELECT count(*) FROM ctrlz.node_enrollments WHERE state = $1`, state); got != n {
			t.Errorf("%s: %d rows, want %d", state, got, n)
		}
	}
}

func TestFreeCountersAreSweptAfterThirtyDays(t *testing.T) {
	r := newRig(t)
	for _, node := range []string{seedNode1, seedNode2} {
		r.env.Exec(t, `INSERT INTO ctrlz.free_dns_counters (node_id, bucket_start, protocol, outcome, rcode, count)
			VALUES ($1, now() - interval '31 days', 'udp', 'answered', 0, 5), ($1, now() - interval '1 hour', 'udp', 'answered', 0, 5)`, node)
		r.env.Exec(t, `INSERT INTO ctrlz.free_dns_counter_batches (node_id, batch_id, bucket_start, received_at)
			VALUES ($1, 1, now() - interval '31 days', now() - interval '31 days'), ($1, 2, now() - interval '1 hour', now() - interval '1 hour')`, node)
	}
	r.run(periodic.JobCounters)
	if r.count(`SELECT count(*) FROM ctrlz.free_dns_counters`) != 2 || r.count(`SELECT count(*) FROM ctrlz.free_dns_counter_batches`) != 2 {
		t.Error("the old rows stayed or the new ones went")
	}
}

// A's rule is past its expiry and B's is not: A's goes, with a step of the version of its profile and no outbox row, and B's
// rows and version are as they were.
func TestExpiredRulesAreDeletedPerTenantWithTheProfileVersionStepped(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `UPDATE ctrlz.rules SET expires_at = now() - interval '1 hour' WHERE tenant_id = $1`, a.Tenant)
	r.env.Exec(t, `UPDATE ctrlz.rules SET expires_at = now() + interval '1 hour' WHERE tenant_id = $1`, b.Tenant)
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)
	va := r.count(`SELECT version FROM ctrlz.profiles WHERE id = $1`, a.Profile)
	vb := r.count(`SELECT version FROM ctrlz.profiles WHERE id = $1`, b.Profile)

	r.run(periodic.JobRules)

	if r.count(`SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1`, a.Tenant) != 0 {
		t.Error("A's expired rule stayed")
	}
	if r.count(`SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1`, b.Tenant) != 1 {
		t.Error("B's live rule went")
	}
	if r.count(`SELECT version FROM ctrlz.profiles WHERE id = $1`, a.Profile) != va+1 {
		t.Error("the version of A's profile was not stepped")
	}
	if r.count(`SELECT version FROM ctrlz.profiles WHERE id = $1`, b.Profile) != vb {
		t.Error("B's profile version moved")
	}
	if r.count(`SELECT count(*) FROM ctrlz.policy_outbox`) != 0 {
		t.Error("the purge wrote an outbox row")
	}
}

// Only a tenant that has a schedule window is marked.
func TestScheduleHorizonMarksTheTenantsThatHaveAWindow(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `DELETE FROM ctrlz.schedule_windows WHERE tenant_id = $1`, b.Tenant)
	r.env.Exec(t, `DELETE FROM ctrlz.policy_outbox`)
	r.run(periodic.JobHorizon)
	if r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set'`, a.Tenant) != 1 {
		t.Error("the tenant with a window was not marked")
	}
	if r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1`, b.Tenant) != 0 {
		t.Error("the tenant with no window was marked")
	}
}

// Log pruning: the log below the older kept snapshot goes, a blob nobody can need goes with its file after its row, a blob a
// kept snapshot still names stays, and a blob an active node has not applied past stays.
func TestPruneDeletesTheLogBelowTheOlderSnapshotAndTheBlobsNoNodeNeeds(t *testing.T) {
	r := newRig(t)
	for seq := 1; seq <= 250; seq++ {
		r.env.Exec(t, `INSERT INTO ctrlz.config_log (seq, class, entry_hash, payload) VALUES ($1, 'policy', sha256(convert_to($1::text, 'UTF8')), '\x00')`, seq)
	}
	for _, seq := range []int{50, 100, 200} {
		r.env.Exec(t, `INSERT INTO ctrlz.config_snapshot (seq, entry_hash, store_ref) VALUES ($1, sha256(convert_to($1::text, 'UTF8')), 'ref')`, seq)
	}
	blob := func(name string, gcAfter any) {
		r.env.Exec(t, `INSERT INTO ctrlz.policy_artifacts (hash, kind, size, store_ref, first_seq, gc_after_seq)
			VALUES (sha256(convert_to($1::text, 'UTF8')), 'profile', 1, $1, 1, $2)`, name, gcAfter)
	}
	blob("bound", nil)
	blob("old", 60)    // at or below the older kept snapshot (100), and below both nodes: goes
	blob("fresh", 150) // above the older kept snapshot: a kept snapshot may still name it
	blob("held", 90)   // a node has applied only up to 80
	r.env.Exec(t, `UPDATE ctrlz.nodes SET applied_seq = 250 WHERE id = $1`, seedNode1)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET applied_seq = 80 WHERE id = $1`, seedNode2)

	// The floor is the older of the two latest snapshots (200 and 100), so 100; the snapshot at 50 is an older one the compiler would
	// already have deleted, and it changes nothing here.
	r.run(periodic.JobPrune)

	if got := r.count(`SELECT count(*) FROM ctrlz.config_log WHERE seq < 100`); got != 0 {
		t.Errorf("%d log rows below the floor stayed", got)
	}
	if got := r.count(`SELECT count(*) FROM ctrlz.config_log WHERE seq >= 100`); got != 151 {
		t.Errorf("%d log rows at or above the floor, want 151", got)
	}
	if r.count(`SELECT count(*) FROM ctrlz.policy_artifacts WHERE store_ref = 'old'`) != 0 || len(r.blobs.gone) != 1 {
		t.Errorf("the collectable blob: files deleted %d", len(r.blobs.gone))
	}
	for _, name := range []string{"bound", "fresh", "held"} {
		if r.count(`SELECT count(*) FROM ctrlz.policy_artifacts WHERE store_ref = $1`, name) != 1 {
			t.Errorf("blob %s was collected", name)
		}
	}
}

// J12-r1-3 and 10: a file goes while the compiler's log lock is still held, so a re-bind of the same content can never meet a
// row that is gone and a file that is still there, or the other way round, and a file is never removed after the lock is
// released. The probe asks from a second session whether the lock is free at the moment the file is removed.
func TestPruneRemovesEachBlobFileWhileTheLogLockIsHeld(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `INSERT INTO ctrlz.config_snapshot (seq, entry_hash, store_ref) VALUES (100, sha256(convert_to('100', 'UTF8')), 'ref'), (200, sha256(convert_to('200', 'UTF8')), 'ref')`)
	for _, name := range []string{"a", "b", "c"} {
		r.env.Exec(t, `INSERT INTO ctrlz.policy_artifacts (hash, kind, size, store_ref, first_seq, gc_after_seq)
			VALUES (sha256(convert_to($1::text, 'UTF8')), 'profile', 1, $1, 1, 10)`, name)
	}
	r.env.Exec(t, `UPDATE ctrlz.nodes SET applied_seq = 250`)
	r.blobs.probe = func() bool {
		conn, err := r.env.DB.Super(r.env.Ctx)
		if err != nil {
			t.Error(err)
			return false
		}
		defer conn.Close(r.env.Ctx)
		var free bool
		if err := conn.QueryRow(r.env.Ctx, `SELECT pg_try_advisory_lock(hashtextextended('ctrlz.config_log', 0))`).Scan(&free); err != nil {
			t.Error(err)
			return false
		}
		return !free
	}
	r.run(periodic.JobPrune)
	if len(r.blobs.gone) != 3 {
		t.Fatalf("%d files removed, want 3", len(r.blobs.gone))
	}
	for i, held := range r.blobs.locked {
		if !held {
			t.Errorf("file %d was removed after the log lock was released", i)
		}
	}
}

// J12-r2-7: a file that will not go fails the batch, which rolls back: the rows stay collectable and the next pass retries them,
// instead of the row going and the file being an orphan nothing collects.
func TestPruneKeepsTheRowsOfABatchWhoseFileWillNotGo(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `INSERT INTO ctrlz.config_snapshot (seq, entry_hash, store_ref) VALUES (100, sha256(convert_to('100', 'UTF8')), 'ref'), (200, sha256(convert_to('200', 'UTF8')), 'ref')`)
	r.env.Exec(t, `INSERT INTO ctrlz.policy_artifacts (hash, kind, size, store_ref, first_seq, gc_after_seq)
		VALUES (sha256(convert_to('a', 'UTF8')), 'profile', 1, 'a', 1, 10)`)
	r.env.Exec(t, `UPDATE ctrlz.nodes SET applied_seq = 250`)
	r.blobs.fail = errors.New("the volume refused")
	if err := r.runner.RunJob(r.env.Ctx, periodic.JobPrune); err == nil {
		t.Fatal("a file that would not go was not reported")
	}
	if r.count(`SELECT count(*) FROM ctrlz.policy_artifacts`) != 1 {
		t.Fatal("the row went although its file did not")
	}
	r.blobs.fail = nil
	r.run(periodic.JobPrune)
	if r.count(`SELECT count(*) FROM ctrlz.policy_artifacts`) != 0 {
		t.Error("the retry did not collect the row")
	}
}

// J12-r1-4: a tenant with more profiles than one batch names, each holding a few expired rules, is purged in one run. The
// drain used to stop after the first 50 profiles whenever they held fewer than a batch of rules.
func TestExpiredRulesPurgeTheProfilesBeyondTheFirstPage(t *testing.T) {
	r := newRig(t)
	// A batch big enough that the rules deleted never reach it: only the page of profiles can say there is more.
	big, err := periodic.New(periodic.Config{Store: r.env.Worker(t), Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Page: 1, Batch: 1000})
	if err != nil {
		t.Fatal(err)
	}
	r.runner = big
	a := r.env.A
	r.env.Exec(t, `INSERT INTO ctrlz.profiles (tenant_id, id, name) SELECT $1, gen_random_uuid(), 'bulk ' || g FROM generate_series(1, 120) g`, a.Tenant)
	r.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, expires_at)
		SELECT p.tenant_id, p.id, 'gone.example.test', 'domain', 'block', now() - interval '1 hour' FROM ctrlz.profiles p WHERE p.tenant_id = $1 AND p.name LIKE 'bulk %'`, a.Tenant)
	r.run(periodic.JobRules)
	if got := r.count(`SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND expires_at <= now()`, a.Tenant); got != 0 {
		t.Errorf("%d expired rules of A stayed after one run", got)
	}
}

// J12-r1-5 and 16: the tenant deletes the host while the pass resolves it. The write must skip the host and the pass must end
// without an error (the row would have failed the whole Endpoint at commit, on the deferred foreign key).
func TestDDNSSkipsAHostTheTenantDeletedWhileItWasResolved(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true WHERE tenant_id = $1`, a.Tenant)
	r.env.Exec(t, `INSERT INTO ctrlz.endpoint_ddns_hosts (tenant_id, endpoint_id, hostname) VALUES ($1, $2, 'second.example.test')`, a.Tenant, a.Endpoint)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.res.by["second.example.test"] = addrs("1.1.1.1")
	r.res.onLookup = func(host string) {
		if host == "home1.example.test" {
			r.env.Exec(t, `DELETE FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND hostname = 'home1.example.test'`, a.Tenant)
		}
	}
	r.run(periodic.JobDDNS)
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '1.1.1.1/32'`, a.Tenant) != 1 {
		t.Error("the other host of the Endpoint was not updated")
	}
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND cidr = '8.8.8.8/32'`, a.Tenant) != 0 {
		t.Error("an address was written for the deleted host")
	}
}

// J12-r1-12: hosts that all raise the same alert leave one open alert for the tenant, and another tenant's alert is its own.
func TestDDNSRaisesOneAlertPerReasonAndTenant(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true`)
	for _, h := range []string{"x1", "x2", "x3"} {
		r.env.Exec(t, `INSERT INTO ctrlz.endpoint_ddns_hosts (tenant_id, endpoint_id, hostname) VALUES ($1, $2, $3)`, a.Tenant, a.Endpoint, h+".example.test")
		r.res.by[h+".example.test"] = addrs("10.10.34.5")
	}
	r.res.by["home1.example.test"] = addrs("10.10.34.5")
	r.res.by["home2.example.test"] = addrs("10.10.34.5")
	r.run(periodic.JobDDNS)
	if got := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'periodic' AND params ->> 'reason' = 'ddns_injected' AND params ->> 'tenant_id' = $1`, a.Tenant.String()); got != 1 {
		t.Errorf("%d open alerts for tenant A, want 1", got)
	}
	if got := r.count(`SELECT count(*) FROM ctrlz.alerts WHERE kind = 'periodic' AND params ->> 'reason' = 'ddns_injected' AND params ->> 'tenant_id' = $1`, b.Tenant.String()); got != 1 {
		t.Errorf("%d open alerts for tenant B, want 1", got)
	}
}

// J12-r1-15: an address the Endpoint already holds from another source still gets its Plain DNS claim.
func TestDDNSRequestsTheClaimOfAnAddressTheEndpointAlreadyHolds(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	r.env.Exec(t, `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source) VALUES ($1, $2, '8.8.8.8/32', 'manual')`, a.Tenant, a.Endpoint)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.run(periodic.JobDDNS)
	if r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '8.8.8.8/32' AND state IN ('active', 'pending_proof')`, a.Tenant) != 1 {
		t.Error("the held address got no claim")
	}
}

// J12-r1-9: while the claim budget is spent, a name that answers with new IPv6 addresses on each pass never grows the host's
// rows past the answer it gave last.
func TestDDNSKeepsAHostWithASpentBudgetWithinItsCap(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	r.bud.left = 0
	for pass := 0; pass < 4; pass++ {
		ans := addrs("8.8.8.8")
		for i := 0; i < 10; i++ {
			ans = append(ans, netip.MustParseAddr(fmt.Sprintf("2001:4860:4860::%x:%x", pass+1, i+1)))
		}
		r.res.by["home1.example.test"] = ans
		r.run(periodic.JobDDNS)
		if got := r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND ddns_host_id IS NOT NULL`, a.Tenant); got > 20 {
			t.Fatalf("pass %d: the host holds %d rows, above the cap of 20", pass, got)
		}
	}
	if got := r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND family(cidr) = 6`, a.Tenant); got != 10 {
		t.Errorf("%d IPv6 rows, want the 10 of the last answer", got)
	}
}

// J12-r2-3 and 4: a claim that was released, or that the database would refuse (suspended, or the tenant at its quota), is not
// asked for again and costs no budget, and an address whose claim is not asked for is still written, so one refusal never holds
// another address back.
func TestDDNSDoesNotAskAgainForAReleasedOrRefusedClaim(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	claim := func(cidr, state string) {
		r.env.Exec(t, `INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source) VALUES ($1, $2, $3, $4, 'manual')`,
			a.Tenant, a.Endpoint, cidr, state)
	}
	claim("8.8.8.8/32", "released")
	claim("9.9.9.9/32", "suspended")
	// The host has kept answering with 8.8.8.8 since the tenant let its claim go: that is what keeps it released (J12-r3-3).
	r.env.Exec(t, `UPDATE ctrlz.endpoint_ddns_hosts SET last_ips = ARRAY['8.8.8.8']::inet[] WHERE tenant_id = $1`, a.Tenant)
	r.res.by["home1.example.test"] = addrs("8.8.8.8", "9.9.9.9", "1.1.1.1")
	r.bud.left = 1

	r.run(periodic.JobDDNS)

	for _, c := range []string{"8.8.8.8/32", "9.9.9.9/32", "1.1.1.1/32"} {
		if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = $2`, a.Tenant, c) != 1 {
			t.Errorf("%s was not written as an authorized address", c)
		}
	}
	if r.bud.left != 0 {
		t.Errorf("budget left %d, want exactly the one request for the new address charged", r.bud.left)
	}
	if r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND cidr = '8.8.8.8/32' AND state <> 'released'`, a.Tenant) != 0 {
		t.Error("a released claim came back")
	}
	if r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND cidr = '1.1.1.1/32' AND source = 'ddns'`, a.Tenant) != 1 {
		t.Error("the new address got no claim")
	}

	// A second pass asks for nothing at all.
	r.bud.left = 5
	r.run(periodic.JobDDNS)
	if r.bud.left != 5 {
		t.Errorf("a repeat pass charged %d requests", 5-r.bud.left)
	}

	// At its quota the tenant asks for nothing, and the address is still written.
	r.env.Exec(t, `UPDATE ctrlz.tenant_entitlements SET max_ip_claims = (SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state <> 'released')
		WHERE tenant_id = $1`, a.Tenant)
	r.res.by["home1.example.test"] = addrs("4.4.4.4")
	r.run(periodic.JobDDNS)
	if r.bud.left != 5 {
		t.Error("a tenant at its quota was charged for a request that cannot succeed")
	}
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = '4.4.4.4/32'`, a.Tenant) != 1 {
		t.Error("the address was not written for a tenant at its quota")
	}
	// J12-r3-4: the tenant sees why, and the claim of the address that left frees its slot, so the next pass asks for the new one.
	if r.count(`SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND hostname = 'home1.example.test' AND last_error = 'claim_quota'`, a.Tenant) != 1 {
		t.Error("a tenant at its quota was not told")
	}
	if r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND cidr = '1.1.1.1/32' AND state = 'released'`, a.Tenant) != 1 {
		t.Error("the claim of the address that left was not released")
	}
	r.run(periodic.JobDDNS)
	if r.bud.left != 4 || r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND cidr = '4.4.4.4/32' AND state <> 'released'`, a.Tenant) != 1 {
		t.Error("the freed slot was not used for the new address")
	}
	if r.count(`SELECT count(*) FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND last_error IS NOT NULL`, a.Tenant) != 0 {
		t.Error("the quota note stayed after the claim was made")
	}
}

func (r *rig) ddnsClaims(tenant uuid.UUID, cidr string) int {
	r.t.Helper()
	return r.count(`SELECT count(*) FROM ctrlz.ip_claims WHERE tenant_id = $1 AND source = 'ddns' AND cidr = $2 AND state <> 'released'`, tenant, cidr)
}

// J12-r3-3 and 4: when the host leaves an address its claim is released, and the address that comes back is a new claim; the
// other tenant's claims are not touched.
func TestDDNSReleasesTheClaimOfAnAddressThatLeftAndAsksAgainWhenItReturns(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true`)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.res.by["home2.example.test"] = addrs("9.9.9.9")
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 1 || r.ddnsClaims(b.Tenant, "9.9.9.9/32") != 1 {
		t.Fatal("the first answers got no claims")
	}

	r.res.by["home1.example.test"] = addrs("1.1.1.1")
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 0 || r.ddnsClaims(a.Tenant, "1.1.1.1/32") != 1 {
		t.Error("the claim did not follow the address")
	}
	if r.ddnsClaims(b.Tenant, "9.9.9.9/32") != 1 {
		t.Error("another tenant's claim was released")
	}
	if r.count(`SELECT count(*) FROM ctrlz.policy_outbox WHERE tenant_id = $1 AND aggregate_type = 'endpoint_set'`, a.Tenant) == 0 {
		t.Error("the release was not marked for the compiler")
	}

	// A line that gets its old address back is a new claim, though the old row is released.
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 1 || r.ddnsClaims(a.Tenant, "1.1.1.1/32") != 0 {
		t.Error("the returning address was not asked for again")
	}
	if r.ddnsClaims(b.Tenant, "9.9.9.9/32") != 1 {
		t.Error("another tenant's claim was released")
	}
}

// J12-r3-3: a released or never approved claim that only overlaps the address does not stop its claim.
func TestDDNSAsksForAnAddressInsideAReleasedOrPendingWiderClaim(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	r.env.Exec(t, `INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source) VALUES
		($1, $2, '5.1.2.0/28', 'released', 'manual'), ($1, $2, '5.1.3.0/28', 'pending_proof', 'manual')`, a.Tenant, a.Endpoint)
	r.res.by["home1.example.test"] = addrs("5.1.2.3", "5.1.3.3")
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "5.1.2.3/32") != 1 || r.ddnsClaims(a.Tenant, "5.1.3.3/32") != 1 {
		t.Error("a claim that only overlaps the address stopped its request")
	}
}

// J12-r3-4: while a new address waits for claim budget, the host keeps the claim it has; the pass that gets the new one in
// releases the old one.
func TestDDNSKeepsTheOldClaimUntilTheNewOneIsIn(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.run(periodic.JobDDNS)
	r.res.by["home1.example.test"] = addrs("1.1.1.1")
	r.bud.left = 0
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 1 || r.ddnsClaims(a.Tenant, "1.1.1.1/32") != 0 {
		t.Fatal("the host lost its last claim while the new one waited for budget")
	}
	r.bud.left = 5
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 0 || r.ddnsClaims(a.Tenant, "1.1.1.1/32") != 1 {
		t.Error("the claim did not move once the budget allowed it")
	}
}

// J12-r4-1: an address that returns while the budget is spent is not recorded as answered, so its old released row (the
// worker's own release) is not read as the tenant's, and the claim is asked for once the budget allows.
func TestDDNSReturningAddressIsClaimedAgainWhenItsFirstRequestWasDeferred(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.run(periodic.JobDDNS)
	r.res.by["home1.example.test"] = addrs("1.1.1.1")
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 0 || r.ddnsClaims(a.Tenant, "1.1.1.1/32") != 1 {
		t.Fatal("the claim did not follow the address")
	}
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.bud.left = 0
	r.run(periodic.JobDDNS)
	r.run(periodic.JobDDNS)
	r.bud.left = 5
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 1 {
		t.Error("the returning address was never claimed again")
	}
}

// J12-r3-4: an address another host of the Endpoint still answers with keeps its claim.
func TestDDNSKeepsTheClaimOfAnAddressAnotherHostStillAnswersWith(t *testing.T) {
	r := newRig(t)
	a := r.env.A
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true, legacy_dns = true WHERE tenant_id = $1`, a.Tenant)
	r.env.Exec(t, `INSERT INTO ctrlz.endpoint_ddns_hosts (tenant_id, endpoint_id, hostname) VALUES ($1, $2, 'second.example.test')`, a.Tenant, a.Endpoint)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.res.by["second.example.test"] = addrs("8.8.8.8")
	r.run(periodic.JobDDNS)
	r.res.by["home1.example.test"] = addrs("1.1.1.1")
	r.run(periodic.JobDDNS)
	if r.ddnsClaims(a.Tenant, "8.8.8.8/32") != 1 {
		t.Error("an address a host still answers with lost its claim")
	}
}

// J12-r3-5: a pass whose time ends inside a tenant does not move past it: the next pass begins with that tenant.
func TestDDNSPassThatEndsInsideATenantResumesAtThatTenant(t *testing.T) {
	r := newRig(t)
	a, b := r.env.A, r.env.B
	r.env.Exec(t, `UPDATE ctrlz.endpoints SET authorize_ddns = true`)
	r.res.by["home1.example.test"] = addrs("8.8.8.8")
	r.res.by["home2.example.test"] = addrs("9.9.9.9")
	// The tenants are walked in id order; the pass is cut while it resolves the second one's host.
	second, secondHost, secondAddr := b.Tenant, "home2.example.test", "9.9.9.9/32"
	if b.Tenant.String() < a.Tenant.String() {
		second, secondHost, secondAddr = a.Tenant, "home1.example.test", "8.8.8.8/32"
	}
	ctx, cancel := context.WithCancel(r.env.Ctx)
	defer cancel()
	r.res.onLookup = func(host string) {
		if host == secondHost {
			cancel()
		}
	}
	if err := r.runner.RunJob(ctx, periodic.JobDDNS); err != nil {
		t.Fatalf("a pass that ran out of time failed: %v", err)
	}
	r.res.onLookup = nil
	r.run(periodic.JobDDNS)
	if r.count(`SELECT count(*) FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND source = 'ddns' AND cidr = $2`, second, secondAddr) != 1 {
		t.Error("the tenant the first pass was cut in was skipped for a round")
	}
}

// J12-r3-2: a file that will not go keeps its own row only; the rows after it in hash order are collected, and the pass says
// it failed.
func TestPruneGoesPastAFileThatWillNotGo(t *testing.T) {
	r := newRig(t)
	r.env.Exec(t, `INSERT INTO ctrlz.config_snapshot (seq, entry_hash, store_ref) VALUES (100, sha256(convert_to('100', 'UTF8')), 'ref'), (200, sha256(convert_to('200', 'UTF8')), 'ref')`)
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		r.env.Exec(t, `INSERT INTO ctrlz.policy_artifacts (hash, kind, size, store_ref, first_seq, gc_after_seq)
			VALUES (sha256(convert_to($1::text, 'UTF8')), 'profile', 1, $1, 1, 10)`, name)
	}
	r.env.Exec(t, `UPDATE ctrlz.nodes SET applied_seq = 250`)
	stuck := sha256.Sum256([]byte("a"))
	r.blobs.failFor = func(h []byte) bool { return bytes.Equal(h, stuck[:]) }
	if err := r.runner.RunJob(r.env.Ctx, periodic.JobPrune); err == nil {
		t.Fatal("a file that would not go was not reported")
	}
	if r.count(`SELECT count(*) FROM ctrlz.policy_artifacts`) != 1 ||
		r.count(`SELECT count(*) FROM ctrlz.policy_artifacts WHERE hash = $1`, stuck[:]) != 1 {
		t.Fatal("the rows other than the stuck one were not collected, or the stuck one went")
	}
}
