package store

import (
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The statements of the periodic worker jobs of P4 (docs/specs/p4-nodes.md 8, package J2, internal/worker/periodic): the
// DDNS pass, the purge of expired rules, the sweep of the free DNS counters, the schedule horizon mark, the expiry of
// node enrolments and the pruning of the config log with the collection of blobs. They run as ctrlz_worker. Every
// statement is bounded (a LIMIT, or an age that only old rows meet) and none decides a security window on a clock in Go.

// ---------------------------------------------------------------------------
// Node enrolments.

// qEnrollmentsExpire moves an enrolment nobody finished to expired: an issued one past its expiry, and one waiting for the
// admin more than 24 h after the node enrolled (4.2). The rows are locked in id order, so two workers (or a worker and
// the hub's Enroll) meet in one order.
const qEnrollmentsExpire = `UPDATE ctrlz.node_enrollments SET state = 'expired' WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.node_enrollments
  WHERE (state = 'issued' AND expires_at <= now()) OR (state = 'pending_approval' AND enrolled_at <= now() - interval '24 hours')` +
	keyOrder + ` LIMIT $1` + lockNoKeyUpdate + `))`

// EnrollmentsExpire expires at most limit enrolments and says how many it did.
func (g GlobalTx) EnrollmentsExpire(limit int) (int, error) {
	tag, err := g.tx.Exec(g.ctx, qEnrollmentsExpire, int32(limit))
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

// qEnrollmentsDelete deletes, 7 days after expires_at, the enrolments that are over: expired and rejected ones, approved
// ones whose certificate Poll issued, and approved ones whose node was revoked (a revoked node cannot poll, 4.5). An approved
// row with no certificate stays while its node is pending, active or draining, because the agent still polls for it, and
// goes with the node row by the cascade if that is removed.
const qEnrollmentsDelete = `DELETE FROM ctrlz.node_enrollments WHERE id = ANY (ARRAY(SELECT id FROM ctrlz.node_enrollments
  WHERE expires_at <= now() - interval '7 days'
    AND (state IN ('expired', 'rejected')
      OR (state = 'approved' AND (cert_der IS NOT NULL
        OR NOT EXISTS (SELECT 1 FROM ctrlz.nodes n WHERE n.id = node_enrollments.node_id AND n.status <> 'revoked'))))` +
	keyOrder + ` LIMIT $1` + lockUpdate + `))`

// EnrollmentsDelete deletes at most limit finished enrolments and says how many it did.
func (g GlobalTx) EnrollmentsDelete(limit int) (int, error) {
	tag, err := g.tx.Exec(g.ctx, qEnrollmentsDelete, int32(limit))
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// Free DNS counters (PS 5): 30 days.

// The two statements delete only rows older than 30 days. The hub writes the rows of the last 25 hours and nothing else
// touches a row this old, so no two statements meet on a row and no order between them can matter (the reason of the
// entries of rowOrderExempt in internal/lint). The worker can read only the time column of either table, so a keyed
// subselect is not possible.
const (
	qFreeCountersSweep = `DELETE FROM ctrlz.free_dns_counters WHERE bucket_start < now() - interval '30 days'`
	qFreeBatchesSweep  = `DELETE FROM ctrlz.free_dns_counter_batches WHERE received_at < now() - interval '30 days'`
)

// FreeCountersSweep deletes the counters and the dedupe rows of batches older than 30 days.
func (g GlobalTx) FreeCountersSweep() (counters, batches int, err error) {
	tag, err := g.tx.Exec(g.ctx, qFreeCountersSweep)
	if err != nil {
		return 0, 0, sanitize(err)
	}
	counters = int(tag.RowsAffected())
	tag, err = g.tx.Exec(g.ctx, qFreeBatchesSweep)
	if err != nil {
		return counters, 0, sanitize(err)
	}
	return counters, int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// Expired rules (T-185).

// qExpiredRuleProfiles names the profiles that hold rules past their expiry, on the application clock (T-184).
const qExpiredRuleProfiles = `SELECT DISTINCT profile_id FROM ctrlz.rules WHERE tenant_id = $1 AND expires_at <= $2::timestamptz ORDER BY profile_id LIMIT $3`

// ExpiredRuleProfiles lists at most limit profiles of the tenant that hold a rule whose expiry has passed.
func (t Tx) ExpiredRuleProfiles(now time.Time, limit int) ([]uuid.UUID, error) {
	return idRows(t.tx.Query(t.ctx, qExpiredRuleProfiles, t.tenant, now, int32(limit)))
}

const qProfilesBumpVersion = `UPDATE ctrlz.profiles SET version = version + 1 WHERE tenant_id = $1
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.profiles WHERE tenant_id = $1 AND id = ANY($2::uuid[])` + orderedUpdate + `))`

// ProfilesBumpVersion steps the version of the profiles, so the rule count of the profile list (which answers for one exact
// version, P2 6.5) is not served stale after the purge. The purge is a system writer: it passes no profile lock and writes
// no outbox row, because an expired rule is already inert on the node (spec 8).
func (t Tx) ProfilesBumpVersion(ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := t.tx.Exec(t.ctx, qProfilesBumpVersion, t.tenant, ids)
	return sanitize(err)
}

const qExpiredRulesDelete = `DELETE FROM ctrlz.rules WHERE tenant_id = $1 AND id = ANY (ARRAY(SELECT id FROM ctrlz.rules
  WHERE tenant_id = $1 AND profile_id = ANY($2::uuid[]) AND expires_at <= $3::timestamptz` + keyOrder + ` LIMIT $4` + lockUpdate + `))`

// ExpiredRulesDelete deletes at most limit expired rules of the profiles and says how many it did.
func (t Tx) ExpiredRulesDelete(profiles []uuid.UUID, now time.Time, limit int) (int, error) {
	if len(profiles) == 0 {
		return 0, nil
	}
	tag, err := t.tx.Exec(t.ctx, qExpiredRulesDelete, t.tenant, profiles, now, int32(limit))
	if err != nil {
		return 0, sanitize(err)
	}
	return int(tag.RowsAffected()), nil
}

// ---------------------------------------------------------------------------
// The schedule horizon.

const qHasScheduleWindows = `SELECT EXISTS (SELECT 1 FROM ctrlz.schedule_windows WHERE tenant_id = $1)`

// HasScheduleWindows says whether any Endpoint of the tenant has a schedule window, which is when a ScheduleRecord (and its
// offset transitions) is compiled for it.
func (t Tx) HasScheduleWindows() (bool, error) {
	var yes bool
	if err := t.tx.QueryRow(t.ctx, qHasScheduleWindows, t.tenant).Scan(&yes); err != nil {
		return false, sanitize(err)
	}
	return yes, nil
}

// ---------------------------------------------------------------------------
// Log pruning and blob collection (6.5, 8).

const qPruneFloor = `SELECT min(seq) FROM (SELECT seq FROM ctrlz.config_snapshot ORDER BY seq DESC LIMIT 2) s`

// PruneFloor is the seq of the older of the two kept snapshots (the compiler keeps two): the log below it and the blobs
// that were unbound at or before it are no node's to ask for. ok is false while no snapshot exists, when nothing is pruned.
func (g GlobalTx) PruneFloor() (seq uint64, ok bool, err error) {
	var s *int64
	if err := g.tx.QueryRow(g.ctx, qPruneFloor).Scan(&s); err != nil {
		return 0, false, sanitize(err)
	}
	if s == nil || *s < 0 {
		return 0, false, nil
	}
	return uint64(*s), true, nil
}

// NodeApplied is how far an active node has applied the log.
type NodeApplied struct {
	Node uuid.UUID
	Seq  uint64
}

const qActiveApplied = `SELECT id, applied_seq FROM ctrlz.nodes WHERE status = 'active' ORDER BY id`

// ActiveApplied reads applied_seq of every active node. A pending node starts from GetSnapshot and holds nothing back.
func (g GlobalTx) ActiveApplied() ([]NodeApplied, error) {
	rows, err := g.tx.Query(g.ctx, qActiveApplied)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []NodeApplied
	for rows.Next() {
		var n NodeApplied
		var s int64
		if err := rows.Scan(&n.Node, &s); err != nil {
			return nil, sanitize(err)
		}
		if s < 0 {
			s = 0
		}
		n.Seq = uint64(s)
		out = append(out, n)
	}
	return out, sanitize(rows.Err())
}

// The log and the blobs are pruned one key at a time: ctrlz_worker holds S and D on config_log and policy_artifacts and no
// UPDATE column, and Postgres refuses any row-lock clause (FOR UPDATE, with or without SKIP LOCKED) without UPDATE on a column.
// A keyed delete needs none. The caller holds the log lock (ConfigLogLock) and the compiler is the only other writer, so no
// row lock is wanted: it appends above the floor and the hub only reads.
const (
	qConfigLogSeqs   = `SELECT seq FROM ctrlz.config_log WHERE seq < $1::bigint ORDER BY seq LIMIT $2`
	qConfigLogDelete = `DELETE FROM ctrlz.config_log WHERE seq = $1`
)

// ConfigLogPrune deletes at most limit log rows below seq, oldest first, and says how many it did. The caller holds the log
// lock (ConfigLogLock), so the compiler's append and a re-bind never interleave with it.
func (g GlobalTx) ConfigLogPrune(below uint64, limit int) (int, error) {
	rows, err := g.tx.Query(g.ctx, qConfigLogSeqs, int64(below), int32(limit))
	if err != nil {
		return 0, sanitize(err)
	}
	var seqs []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return 0, sanitize(err)
		}
		seqs = append(seqs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, sanitize(err)
	}
	n := 0
	for _, s := range seqs {
		tag, err := g.tx.Exec(g.ctx, qConfigLogDelete, s)
		if err != nil {
			return n, sanitize(err)
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

// ErrCollectStop is what a remove function of ArtifactsCollect wraps when the batch must end and not go on past the hash: the
// log lock is gone or the pass is over. Any other error it returns is one file that will not go.
var ErrCollectStop = errors.New("store: the blob batch must stop")

// CollectResult is what one batch of ArtifactsCollect did.
type CollectResult struct {
	Scanned int    // collectable rows it looked at
	Removed int    // rows deleted, each after its file
	Last    []byte // the last hash looked at: where the next batch of the pass begins
	// Failed joins what remove said for the hashes it could not remove. Their rows were left alone, so they stay collectable.
	Failed error
}

// The collectable blobs are the unbound ones no node and no kept snapshot can need: gc_after_seq at or below the older kept
// snapshot ($1), and below applied_seq of every active node ($2, NULL when there is none). The cursor ($4) is where the previous batch of the same pass ended, so a hash whose file will not go is passed over and not met first by every batch. The delete of one hash repeats the
// predicate, so a row the compiler re-bound (which clears gc_after_seq) between the read and the delete stays.
const (
	qArtifactsCollectable = `SELECT hash FROM ctrlz.policy_artifacts
  WHERE gc_after_seq IS NOT NULL AND gc_after_seq <= $1::bigint AND ($2::bigint IS NULL OR gc_after_seq < $2::bigint)
  AND ($4::bytea IS NULL OR hash > $4::bytea)
  ORDER BY hash LIMIT $3`
	qArtifactDelete = `DELETE FROM ctrlz.policy_artifacts WHERE hash = $1
  AND gc_after_seq IS NOT NULL AND gc_after_seq <= $2::bigint AND ($3::bigint IS NULL OR gc_after_seq < $3::bigint) RETURNING store_ref`
)

// ArtifactsCollect removes at most limit collectable blobs after the cursor, one at a time: the file first through remove, and
// only when it went, the row. minApplied is the lowest applied_seq of the active nodes, nil when there is no active node.
// The caller holds the log lock for the whole transaction, so the compiler's re-bind of the same content (it takes the same
// lock) sees the row and the file go together. A file that will not go leaves its row, and the batch goes on past it: the one
// stuck hash must not hold back every blob that sorts after it, hour after hour (J12-r3-2). The failures come back in Failed;
// the transaction still commits what it did.
func (g GlobalTx) ArtifactsCollect(floor uint64, minApplied *uint64, after []byte, limit int, remove func(hash []byte) error) (CollectResult, error) {
	var min *int64
	if minApplied != nil {
		v := int64(*minApplied)
		min = &v
	}
	rows, err := g.tx.Query(g.ctx, qArtifactsCollectable, int64(floor), min, int32(limit), after)
	if err != nil {
		return CollectResult{}, sanitize(err)
	}
	var hashes [][]byte
	for rows.Next() {
		var h []byte
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return CollectResult{}, sanitize(err)
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return CollectResult{}, sanitize(err)
	}
	res := CollectResult{Scanned: len(hashes)}
	var failed []error
	for _, h := range hashes {
		res.Last = h
		if err := remove(h); err != nil {
			if errors.Is(err, ErrCollectStop) {
				return res, err
			}
			failed = append(failed, err)
			continue
		}
		var ref string
		err := g.tx.QueryRow(g.ctx, qArtifactDelete, h, int64(floor), min).Scan(&ref)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // bound again since the read
		}
		if err != nil {
			return res, sanitize(err)
		}
		res.Removed++
	}
	res.Failed = errors.Join(failed...)
	return res, nil
}

const qArtifactsHeldAt = `SELECT max(gc_after_seq) FROM ctrlz.policy_artifacts WHERE gc_after_seq IS NOT NULL AND gc_after_seq <= $1::bigint`

// ArtifactsWaitingUpTo is the newest gc_after_seq among the blobs that the kept snapshots no longer need: a node whose
// applied_seq is not above it holds at least one of them back. ok is false when no blob waits.
func (g GlobalTx) ArtifactsWaitingUpTo(floor uint64) (seq uint64, ok bool, err error) {
	var s *int64
	if err := g.tx.QueryRow(g.ctx, qArtifactsHeldAt, int64(floor)).Scan(&s); err != nil {
		return 0, false, sanitize(err)
	}
	if s == nil || *s < 0 {
		return 0, false, nil
	}
	return uint64(*s), true, nil
}

// ---------------------------------------------------------------------------
// DDNS (T-091).

// DDNSWork is one host of an Endpoint that authorizes DDNS addresses.
type DDNSWork struct {
	Endpoint, Host uuid.UUID
	Hostname       string
	LastResolvedAt *time.Time
	CreatedAt      time.Time
}

const qDDNSWork = `SELECT h.endpoint_id, h.id, h.hostname, h.last_resolved_at, h.created_at FROM ctrlz.endpoint_ddns_hosts h
JOIN ctrlz.endpoints e ON e.tenant_id = h.tenant_id AND e.id = h.endpoint_id
WHERE h.tenant_id = $1 AND e.authorize_ddns ORDER BY h.endpoint_id, h.id`

// DDNSWork lists the hosts of the tenant's Endpoints that have authorize_ddns on, in Endpoint and host order. It locks
// nothing: the pass resolves outside any transaction and re-reads the flag under the Endpoint's row before it writes.
func (t Tx) DDNSWork() ([]DDNSWork, error) {
	rows, err := t.tx.Query(t.ctx, qDDNSWork, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []DDNSWork
	for rows.Next() {
		var w DDNSWork
		if err := rows.Scan(&w.Endpoint, &w.Host, &w.Hostname, &w.LastResolvedAt, &w.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, w)
	}
	return out, sanitize(rows.Err())
}

// DDNSFlags are the two flags of an Endpoint the DDNS pass acts on.
type DDNSFlags struct {
	Authorize, LegacyDNS bool
}

const qDDNSFlags = `SELECT authorize_ddns, legacy_dns FROM ctrlz.endpoints WHERE tenant_id = $1 AND id = $2`

// DDNSFlags reads the flags of an Endpoint the caller holds the row of. ok is false for an Endpoint that is gone.
func (t Tx) DDNSFlags(endpoint uuid.UUID) (f DDNSFlags, ok bool, err error) {
	ok, err = notFound(t.tx.QueryRow(t.ctx, qDDNSFlags, t.tenant, endpoint).Scan(&f.Authorize, &f.LegacyDNS))
	return f, ok, err
}

// DDNSFailure is why a host's last lookup changed nothing: a closed set, because it is stored where the tenant reads it.
type DDNSFailure string

// The failures.
const (
	DDNSLookup   DDNSFailure = "lookup_failed" // the resolver did not answer, or answered with an error
	DDNSEmpty    DDNSFailure = "no_address"    // the answer held no address of either family
	DDNSNoPublic DDNSFailure = "no_public"     // every address was private, reserved or injected
	DDNSTooMany  DDNSFailure = "too_many"      // more public addresses than the cap
	// DDNSClaimQuota is the one code that rides on a lookup that was used: the addresses are written, and the tenant is at
	// its max_ip_claims, so a new address has no Plain DNS claim until one is released (J12-r3-4). It is the tenant's own to
	// fix, and without it the host would look healthy while its newest address is filtered nowhere.
	DDNSClaimQuota DDNSFailure = "claim_quota"
)

// Valid reports membership.
func (f DDNSFailure) Valid() bool {
	switch f {
	case DDNSLookup, DDNSEmpty, DDNSNoPublic, DDNSTooMany, DDNSClaimQuota:
		return true
	}
	return false
}

// String is the code.
func (f DDNSFailure) String() string { return string(f) }

const qDDNSRecordOK = `UPDATE ctrlz.endpoint_ddns_hosts SET last_resolved_at = now(), last_ips = ARRAY(SELECT x::inet FROM unnest($4::text[]) AS x), last_error = NULLIF($5::text, '')
WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3`

// DDNSRecordOK records a lookup whose answer was used: the time, the public addresses and, as a note, the one closed code
// (DDNSClaimQuota) that can ride on a good answer, or "" for none. The addresses are text the caller made from addresses it
// parsed; the statement casts them to inet.
func (t Tx) DDNSRecordOK(endpoint, host uuid.UUID, ips []string, note DDNSFailure) error {
	if note != "" && note != DDNSClaimQuota {
		return errors.New("store: a DDNS note outside its closed set")
	}
	_, err := t.tx.Exec(t.ctx, qDDNSRecordOK, t.tenant, endpoint, host, ips, string(note))
	return sanitize(err)
}

const qDDNSRecordFailed = `UPDATE ctrlz.endpoint_ddns_hosts SET last_error = $4 WHERE tenant_id = $1 AND endpoint_id = $2 AND id = $3`

// DDNSRecordFailed records why the last lookup changed nothing. last_resolved_at and last_ips stay as they were, so the
// 24 hour rule counts from the last answer that was used.
func (t Tx) DDNSRecordFailed(endpoint, host uuid.UUID, why DDNSFailure) error {
	if !why.Valid() {
		return errors.New("store: a DDNS failure outside its closed set")
	}
	_, err := t.tx.Exec(t.ctx, qDDNSRecordFailed, t.tenant, endpoint, host, string(why))
	return sanitize(err)
}

const qDDNSStale = `SELECT id, family(cidr) = 4 FROM ctrlz.authorized_ips WHERE tenant_id = $1 AND endpoint_id = $2 AND ddns_host_id = $3
  AND NOT (cidr = ANY ($4::text[]::cidr[])) ORDER BY id`

// DDNSStaleRow is a row a host made whose address its last answer no longer holds.
type DDNSStaleRow struct {
	ID     uuid.UUID
	IsIPv4 bool
}

// DDNSStale lists the rows the host made whose address is not among keep: the host answered without them, oldest first (the
// ids are time ordered). The comparison is the database's, on cidr values, so the spelling of an address in Go or in the table
// decides nothing.
func (t Tx) DDNSStale(endpoint, host uuid.UUID, keep []string) ([]DDNSStaleRow, error) {
	rows, err := t.tx.Query(t.ctx, qDDNSStale, t.tenant, endpoint, host, keep)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []DDNSStaleRow
	for rows.Next() {
		var r DDNSStaleRow
		if err := rows.Scan(&r.ID, &r.IsIPv4); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qDDNSHostIDs = `SELECT id FROM ctrlz.endpoint_ddns_hosts WHERE tenant_id = $1 AND endpoint_id = $2`

// DDNSHostIDs lists the hosts the Endpoint has now. The pass reads its work long before it writes (the lookups take
// seconds), so under the Endpoint's row it asks again which of those hosts are still there: a row written for a host the
// tenant deleted meanwhile would fail the whole transaction at commit, on the deferred foreign key.
func (t Tx) DDNSHostIDs(endpoint uuid.UUID) ([]uuid.UUID, error) {
	return idRows(t.tx.Query(t.ctx, qDDNSHostIDs, t.tenant, endpoint))
}

// qDDNSClaimWanted says whether ip_claim_request could write a claim for the address that nothing has asked for yet, and
// whether the only thing in the way is the tenant's quota. It reads the request's own refusals ahead, because a refusal writes
// nothing and would repeat on every pass, each time charged to the tenant's ip-claim budget (J12-r2-3). The address is
// covered, and not asked for, when:
//   - the tenant has an active, grace or suspended claim overlapping it on any Endpoint (the function answers own or
//     suspended);
//   - the Endpoint has a pending claim for exactly this address: it was asked for and waits for its proof;
//   - the Endpoint has a released claim for exactly this address and a host of the Endpoint has kept answering with it since:
//     the tenant let it go, or another tenant's proof displaced it, and asking again would undo that (J12-r2-4). A released
//     claim of an address the hosts have stopped answering with, as the one the worker itself releases when an address leaves,
//     does not count: the address that comes back is a new claim (P3 4.5; J12-r3-3).
//
// A claim that overlaps the address without being it (a /28 that was never approved, a released /28) covers nothing: the
// function would accept the request, and the address is its own claim.
//
// The quota is the function's count (every row not released) against the effective limit as ctrlz_fn.tenant_plan states it,
// compared through ctrlz.cap_reached like every limit; ip_claim_request enforces it under the tenant's advisory lock, and this
// is the read ahead that saves a charge and tells the tenant why nothing was asked.
const qDDNSClaimWanted = `WITH lim AS (SELECT * FROM ctrlz_fn.tenant_plan()),
covered AS (SELECT EXISTS (
    SELECT 1 FROM ctrlz.ip_claims c WHERE c.tenant_id = $1 AND (
      (c.state IN ('active', 'grace', 'suspended') AND c.cidr && $3::text::cidr)
      OR (c.endpoint_id = $2 AND c.state = 'pending_proof' AND c.cidr = $3::text::cidr)
      OR (c.endpoint_id = $2 AND c.state = 'released' AND c.cidr = $3::text::cidr
          AND EXISTS (SELECT 1 FROM ctrlz.endpoint_ddns_hosts h WHERE h.tenant_id = $1 AND h.endpoint_id = $2
                        AND $3::text::inet = ANY (h.last_ips))))) AS held),
quota AS (SELECT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.ip_claims q WHERE q.tenant_id = $1 AND q.state <> 'released'),
    COALESCE((SELECT lim.max_ip_claims FROM lim), 0)) AS reached)
SELECT NOT covered.held AND NOT quota.reached, NOT covered.held AND quota.reached FROM covered, quota`

// DDNSClaimWanted says whether a Plain DNS claim should be requested for a DDNS address now, and, when it should not, whether
// that is only because the tenant is at its quota (qDDNSClaimWanted). It does not look at authorized_ips: an address the
// Endpoint learned another way is authorized and still has no claim of its own. The caller holds the Endpoint's row.
func (t Tx) DDNSClaimWanted(endpoint uuid.UUID, addr string) (want, atQuota bool, err error) {
	err = t.tx.QueryRow(t.ctx, qDDNSClaimWanted, t.tenant, endpoint, addr).Scan(&want, &atQuota)
	return want, atQuota, sanitize(err)
}

// ddnsGone is what a claim of one Endpoint must be for the worker to release it: its own, still live, not suspended (a
// suspension is the admin's, and ip_claim_release leaves it alone too).
const ddnsGone = `tenant_id = $1 AND endpoint_id = $2 AND source = 'ddns' AND state IN ('active', 'grace', 'pending_proof')`

// qDDNSClaimsRelease releases the Endpoint's DDNS claims whose address is in no host's last answer. The claims are picked and
// locked in key order like the sweeps of worker_claims.go, and the outer statement repeats what a claim must still be, so one
// the tenant released or an admin suspended in the meantime is left alone. The worker holds U(state) on ip_claims, which the
// registration sweep already uses.
const qDDNSClaimsRelease = `UPDATE ctrlz.ip_claims SET state = 'released'
WHERE ` + ddnsGone + `
  AND id = ANY (ARRAY(SELECT id FROM ctrlz.ip_claims WHERE ` + ddnsGone + `
    AND NOT EXISTS (SELECT 1 FROM ctrlz.endpoint_ddns_hosts h WHERE h.tenant_id = $1 AND h.endpoint_id = $2 AND ip_claims.cidr::inet = ANY (h.last_ips))` +
	keyOrder + lockNoKeyUpdate + `))
RETURNING id`

// DDNSClaimsRelease releases the DDNS claims of the Endpoint whose address no host of it answers with, by what the hosts' last_ips
// say once the pass has written them. It returns how many it released. A host that keeps its address keeps its claim; one
// that left it gives the claim up, so the address, which the next subscriber of the line may hold, is not served under this
// tenant's profile, and the claim stops using one of the tenant's max_ip_claims (J12-r3-4). The caller holds the Endpoint's
// row, as the claim functions' callers do, and marks the Endpoint's record when this returns more than zero.
func (t Tx) DDNSClaimsRelease(endpoint uuid.UUID) (int, error) {
	ids, err := idRows(t.tx.Query(t.ctx, qDDNSClaimsRelease, t.tenant, endpoint))
	return len(ids), err
}

const qDDNSInsert = `INSERT INTO ctrlz.authorized_ips (tenant_id, endpoint_id, cidr, source, ddns_host_id)
VALUES ($1, $2, $3::text::cidr, 'ddns', $4) ON CONFLICT DO NOTHING RETURNING id`

// DDNSInsert adds one address (a /32 or /128 made from the text) as a row the host made, unless the Endpoint already holds
// that prefix from any source, in which case the existing row stays as it is. It says whether a row was written. The caller
// holds the Endpoint's row.
func (t Tx) DDNSInsert(endpoint, host uuid.UUID, addr string) (bool, error) {
	var id uuid.UUID
	return notFound(t.tx.QueryRow(t.ctx, qDDNSInsert, t.tenant, endpoint, addr, host).Scan(&id))
}
