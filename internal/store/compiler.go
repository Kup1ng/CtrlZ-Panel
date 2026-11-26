package store

import (
	"bytes"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This file is the compiler's door to the database (docs/specs/p4-nodes.md 6). internal/compiler holds the
// logic and no SQL: every statement it runs is a constant here, the way the profile and endpoint code keeps
// theirs, so the lints that read the store (dynamic SQL, lock order, clocks) judge them all.
//
// The compiler runs as ctrlz_compiler, which reads every table of a tenant through the same row level security
// policy as the tenant role (it sets the tenant of the transaction), and holds S, I and U on the three
// artifact tables, S and I on config_log and S, I and D on config_snapshot. Nothing here reads a secret: the
// profile read excludes lock_password_hash by its column grant, the Endpoint read excludes the DoH token
// ciphertext, and the authorized addresses and clients are read through the narrow grants of migration 0037.

// ---------------------------------------------------------------------------
// The outbox.

// OutboxMark is one policy_outbox row the compiler read. Its time is not read: the debounce counts from the
// moment the compiler first saw the row, by its own clock, so no database timestamp is decided on in Go.
type OutboxMark struct {
	Tenant    uuid.UUID
	ID        uuid.UUID
	Aggregate string // profile or endpoint_set
	Subject   uuid.UUID
	Batch     uuid.UUID
}

const qCompilerOutbox = `SELECT tenant_id, id, aggregate_type, aggregate_id, batch_id FROM ctrlz.policy_outbox ORDER BY created_at, id LIMIT $1`

// CompilerOutbox reads up to limit rows of the outbox across tenants, oldest first (the compiler's drain policy,
// named compiler_drain_select). It deletes nothing: the rows go with the entry that carries what they stand for.
func (g GlobalTx) CompilerOutbox(limit int) ([]OutboxMark, error) {
	rows, err := g.tx.Query(g.ctx, qCompilerOutbox, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []OutboxMark
	for rows.Next() {
		var m OutboxMark
		if err := rows.Scan(&m.Tenant, &m.ID, &m.Aggregate, &m.Subject, &m.Batch); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, m)
	}
	return out, sanitize(rows.Err())
}

// One DELETE by id. The ordered, locking subselect of the other multi-row writes (locks.go orderedDelete) is not open to the
// compiler: ctrlz_compiler holds S and D on policy_outbox and no UPDATE, and SELECT ... FOR UPDATE needs it, so the statement
// would fail with 42501 and no entry that carries a mark could ever be committed. The ids are sorted here instead, and the
// compiler is the only deleter of these rows besides the cascade of a tenant purge, which locks by tenant.
const qCompilerOutboxDelete = `DELETE FROM ctrlz.policy_outbox WHERE id = ANY ($1::uuid[])`

// CompilerOutboxDelete deletes the outbox rows the entry just written stands for.
func (g GlobalTx) CompilerOutboxDelete(ids []uuid.UUID) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	ids = slices.Clone(ids)
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	tag, err := g.tx.Exec(g.ctx, qCompilerOutboxDelete, ids)
	return int(tag.RowsAffected()), sanitize(err)
}

const qCompilerTenantIDs = `SELECT id FROM ctrlz.tenants ORDER BY id`

// CompilerTenantIDs lists every tenant (the compiler's cross-tenant read, named compiler_list).
func (g GlobalTx) CompilerTenantIDs() ([]uuid.UUID, error) {
	return idRows(g.tx.Query(g.ctx, qCompilerTenantIDs))
}

// ---------------------------------------------------------------------------
// The log, the snapshots and the artifacts.

// LogRow is one config_log row.
type LogRow struct {
	Seq       uint64
	Class     string
	PrevHash  []byte
	EntryHash []byte
	Payload   []byte
}

const qCompilerHead = `SELECT seq, entry_hash FROM ctrlz.config_log ORDER BY seq DESC LIMIT 1`

// CompilerHead is the latest entry of the log, found false for an empty log.
func (g GlobalTx) CompilerHead() (seq uint64, hash []byte, found bool, err error) {
	var s int64
	ok, err := notFound(g.tx.QueryRow(g.ctx, qCompilerHead).Scan(&s, &hash))
	return uint64(s), hash, ok, err
}

const qCompilerLogAfter = `SELECT seq, class, prev_hash, entry_hash, payload FROM ctrlz.config_log WHERE seq > $1 ORDER BY seq LIMIT $2`

// CompilerLogAfter reads up to limit entries after seq, in order.
func (g GlobalTx) CompilerLogAfter(seq uint64, limit int) ([]LogRow, error) {
	var out []LogRow
	err := g.CompilerLogEach(seq, limit, func(r LogRow) error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// CompilerLogEach hands up to limit entries after seq, in order, to each one at a time. An entry may be 15 MiB, so a
// caller that applies them as they come holds one payload and not the whole run (the load of a compiler after a restart).
// An error of each ends the read and is returned as it is.
func (g GlobalTx) CompilerLogEach(seq uint64, limit int, each func(LogRow) error) error {
	rows, err := g.tx.Query(g.ctx, qCompilerLogAfter, int64(seq), int32(limit))
	if err != nil {
		return sanitize(err)
	}
	defer rows.Close()
	for rows.Next() {
		var r LogRow
		var s int64
		if err := rows.Scan(&s, &r.Class, &r.PrevHash, &r.EntryHash, &r.Payload); err != nil {
			return sanitize(err)
		}
		r.Seq = uint64(s)
		if err := each(r); err != nil {
			return err
		}
	}
	return sanitize(rows.Err())
}

// LogAppend is what one entry writes in the transaction that holds the log lock.
type LogAppend struct {
	Seq       uint64
	Class     string
	PrevHash  []byte // nil for the first entry
	EntryHash []byte
	Payload   []byte
}

const qCompilerAppend = `INSERT INTO ctrlz.config_log (seq, class, prev_hash, entry_hash, payload) VALUES ($1, $2, $3, $4, $5)`

// CompilerAppend writes one entry. The caller holds ConfigLogLock and has checked the head, so a second writer
// cannot interleave; the primary key refuses a repeat of a seq as the last wall.
func (g GlobalTx) CompilerAppend(a LogAppend) error {
	_, err := g.tx.Exec(g.ctx, qCompilerAppend, int64(a.Seq), a.Class, a.PrevHash, a.EntryHash, a.Payload)
	return sanitize(err)
}

const qCompilerLeaseHeld = `SELECT holder = $2 AND expires_at > now() FROM ctrlz.leases WHERE name = $1`

// CompilerLeaseHeld says whether the named lease is the holder's and has not run out. A plain read: the head check under
// the log lock is what keeps the log single-writer, and this one only refuses early a writer whose lease a long pass let go.
func (g GlobalTx) CompilerLeaseHeld(name, holder string) (bool, error) {
	var held bool
	ok, err := notFound(g.tx.QueryRow(g.ctx, qCompilerLeaseHeld, name, holder).Scan(&held))
	return ok && held, err
}

const qConfigLogLock = `SELECT ctrlz_fn.config_log_lock()`

// ConfigLogLock takes the transaction advisory lock of the single writer of config_log.seq (PS 10). The compiler's
// pass and the worker's log pruning hold it for the whole of their write.
func (g GlobalTx) ConfigLogLock() error {
	_, err := g.tx.Exec(g.ctx, qConfigLogLock)
	return sanitize(err)
}

// SnapshotRow is one config_snapshot row.
type SnapshotRow struct {
	Seq       uint64
	EntryHash []byte
	StoreRef  string
}

const qCompilerSnapshots = `SELECT seq, entry_hash, store_ref FROM ctrlz.config_snapshot ORDER BY seq DESC LIMIT $1`

// CompilerSnapshots lists the newest snapshots, newest first.
func (g GlobalTx) CompilerSnapshots(limit int) ([]SnapshotRow, error) {
	rows, err := g.tx.Query(g.ctx, qCompilerSnapshots, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []SnapshotRow
	for rows.Next() {
		var r SnapshotRow
		var s int64
		if err := rows.Scan(&s, &r.EntryHash, &r.StoreRef); err != nil {
			return nil, sanitize(err)
		}
		r.Seq = uint64(s)
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qCompilerSnapshotPut = `INSERT INTO ctrlz.config_snapshot (seq, entry_hash, store_ref) VALUES ($1, $2, $3) ON CONFLICT (seq) DO NOTHING`

// CompilerSnapshotPut records a snapshot written to the store.
func (g GlobalTx) CompilerSnapshotPut(s SnapshotRow) error {
	_, err := g.tx.Exec(g.ctx, qCompilerSnapshotPut, int64(s.Seq), s.EntryHash, s.StoreRef)
	return sanitize(err)
}

const qCompilerSnapshotDelete = `DELETE FROM ctrlz.config_snapshot WHERE seq = $1`

// CompilerSnapshotDelete drops the row of a snapshot the compiler no longer keeps.
func (g GlobalTx) CompilerSnapshotDelete(seq uint64) error {
	_, err := g.tx.Exec(g.ctx, qCompilerSnapshotDelete, int64(seq))
	return sanitize(err)
}

// ArtifactRow is one policy_artifacts row. GCAfter is 0 for a hash that is bound.
type ArtifactRow struct {
	Hash     []byte
	Kind     string // profile or block_page
	Size     int64
	StoreRef string
	FirstSeq uint64
	GCAfter  uint64
}

const qCompilerArtifacts = `SELECT hash, kind, size, store_ref, first_seq, COALESCE(gc_after_seq, 0) FROM ctrlz.policy_artifacts`

// CompilerArtifacts reads every artifact row, which is how a compiler that takes the lease learns which blobs the
// nodes may hold and which are waiting for their collection.
func (g GlobalTx) CompilerArtifacts() ([]ArtifactRow, error) {
	rows, err := g.tx.Query(g.ctx, qCompilerArtifacts)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ArtifactRow
	for rows.Next() {
		var r ArtifactRow
		var first, gc int64
		if err := rows.Scan(&r.Hash, &r.Kind, &r.Size, &r.StoreRef, &first, &gc); err != nil {
			return nil, sanitize(err)
		}
		r.FirstSeq, r.GCAfter = uint64(first), uint64(gc)
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

// A bound hash has no gc_after_seq: a re-bind of a hash that was waiting for its collection clears it, and
// writes the row again when the collector already deleted it.
const qCompilerArtifactPut = `INSERT INTO ctrlz.policy_artifacts (hash, kind, size, store_ref, first_seq) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (hash) DO UPDATE SET gc_after_seq = NULL`

// CompilerArtifactPut records a blob an entry names, or clears the collection mark of one that is bound again.
func (g GlobalTx) CompilerArtifactPut(a ArtifactRow) error {
	_, err := g.tx.Exec(g.ctx, qCompilerArtifactPut, a.Hash, a.Kind, a.Size, a.StoreRef, int64(a.FirstSeq))
	return sanitize(err)
}

const qCompilerArtifactGC = `UPDATE ctrlz.policy_artifacts SET gc_after_seq = $2 WHERE hash = $1 AND gc_after_seq IS NULL`

// CompilerArtifactGC marks a hash that no record of the latest state binds: it may be collected once every active
// node has applied a later entry (6.5).
func (g GlobalTx) CompilerArtifactGC(hash []byte, after uint64) error {
	_, err := g.tx.Exec(g.ctx, qCompilerArtifactGC, hash, int64(after))
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// The membership, the free DNS switch and the catalog (what a pass compares with the latest entry).

// MemberNode is a node row as the PairTable reads it. The addresses are text: the compiler turns them into the
// wire bytes in one place.
type MemberNode struct {
	ID           uuid.UUID
	Status       string
	Slot         int
	DNSIP        string
	ProxyIP      string
	SPKI         []byte
	ProxyBlocked bool
	// BlobMajor is blob_major_max of the latest Heartbeat, 0 when the node reported none.
	BlobMajor int
}

const qCompilerNodes = `SELECT id, status, slot, COALESCE(host(dns_advertised_ip), ''), COALESCE(host(proxy_advertised_ip), ''), spki_sha256, proxy_blocked,
  COALESCE((version_info ->> 'blob_major_max')::int, 0)
FROM ctrlz.nodes ORDER BY slot`

// CompilerNodes reads every node row.
func (g GlobalTx) CompilerNodes() ([]MemberNode, error) {
	rows, err := g.tx.Query(g.ctx, qCompilerNodes)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []MemberNode
	for rows.Next() {
		var n MemberNode
		var slot, major int32
		if err := rows.Scan(&n.ID, &n.Status, &slot, &n.DNSIP, &n.ProxyIP, &n.SPKI, &n.ProxyBlocked, &major); err != nil {
			return nil, sanitize(err)
		}
		n.Slot, n.BlobMajor = int(slot), int(major)
		out = append(out, n)
	}
	return out, sanitize(rows.Err())
}

// MemberPair is a node_pairs row.
type MemberPair struct {
	ID, Primary, Fallback uuid.UUID
}

const qCompilerPairs = `SELECT id, primary_node_id, fallback_node_id FROM ctrlz.node_pairs ORDER BY id`

// CompilerPairs reads every pair.
func (g GlobalTx) CompilerPairs() ([]MemberPair, error) {
	rows, err := g.tx.Query(g.ctx, qCompilerPairs)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []MemberPair
	for rows.Next() {
		var p MemberPair
		if err := rows.Scan(&p.ID, &p.Primary, &p.Fallback); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}

const qCompilerGlobalPair = `SELECT global_pair_id FROM ctrlz.public_settings`

// CompilerGlobalPair is public_settings.global_pair_id, Nil before the first pair.
func (g GlobalTx) CompilerGlobalPair() (uuid.UUID, error) {
	var id *uuid.UUID
	if err := g.tx.QueryRow(g.ctx, qCompilerGlobalPair).Scan(&id); err != nil {
		return uuid.Nil, sanitize(err)
	}
	if id == nil {
		return uuid.Nil, nil
	}
	return *id, nil
}

const qCompilerFreeDNS = `SELECT enabled, qps, version FROM ctrlz.free_dns_settings`

// CompilerFreeDNS is the free DNS switch, its budget and its version (T-556).
func (g GlobalTx) CompilerFreeDNS() (enabled bool, qps int, version uint64, err error) {
	var q int32
	var v int64
	if err = g.tx.QueryRow(g.ctx, qCompilerFreeDNS).Scan(&enabled, &q, &v); err != nil {
		return false, 0, 0, sanitize(err)
	}
	return enabled, int(q), uint64(v), nil
}

// CatalogVersionRow is the current row of catalog_versions and the filter tables of that version.
type CatalogVersionRow struct {
	Version         uint64
	Key             []byte
	SysnamesVersion uint32
	Tables          []CatalogTableRow
}

// CatalogTableRow is one filter table of a catalog version: the wire id of the filter and of its mode, and the hash
// the table file is named by.
type CatalogTableRow struct {
	FilterWire uint16
	ModeWire   uint16
	Hash       []byte
}

const qCompilerCatalogCurrent = `SELECT version, key, COALESCE(sysnames_version, 0) FROM ctrlz.catalog_versions WHERE state = 'current' ORDER BY version DESC LIMIT 1`

const qCompilerCatalogTables = `SELECT f.wire_id, m.wire_id, t.hash FROM ctrlz.catalog_filter_table t
JOIN ctrlz.catalog_filter f ON f.id = t.filter_id JOIN ctrlz.catalog_filter_mode m ON m.filter_id = t.filter_id AND m.mode = t.mode
WHERE t.version = $1 AND t.state = 'current' ORDER BY f.wire_id, m.wire_id`

// CompilerCatalogCurrent reads the current catalog version, found false when there is none.
func (g GlobalTx) CompilerCatalogCurrent() (CatalogVersionRow, bool, error) {
	var c CatalogVersionRow
	var v, sys int64
	ok, err := notFound(g.tx.QueryRow(g.ctx, qCompilerCatalogCurrent).Scan(&v, &c.Key, &sys))
	if err != nil || !ok {
		return CatalogVersionRow{}, ok, err
	}
	c.Version, c.SysnamesVersion = uint64(v), uint32(sys)
	rows, err := g.tx.Query(g.ctx, qCompilerCatalogTables, v)
	if err != nil {
		return CatalogVersionRow{}, false, sanitize(err)
	}
	defer rows.Close()
	for rows.Next() {
		var t CatalogTableRow
		var f, m int32
		if err := rows.Scan(&f, &m, &t.Hash); err != nil {
			return CatalogVersionRow{}, false, sanitize(err)
		}
		t.FilterWire, t.ModeWire = uint16(f), uint16(m)
		c.Tables = append(c.Tables, t)
	}
	return c, true, sanitize(rows.Err())
}

// ---------------------------------------------------------------------------
// One tenant, read in one snapshot.

// CompilerTenantRow is what the tenant's own row and plan say about its compiled records.
type CompilerTenantRow struct {
	Status    string
	AdminHold bool
	ClientCap int
}

const qCompilerTenant = `SELECT t.status, t.admin_hold, COALESCE(te.max_clients_per_endpoint, p.max_clients_per_endpoint)
FROM ctrlz.tenants t JOIN ctrlz.plans p ON p.id = t.plan_id LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = t.id WHERE t.id = $1`

// CompilerTenant reads the tenant of the transaction; found false for a tenant that is gone.
func (t Tx) CompilerTenant() (CompilerTenantRow, bool, error) {
	var r CompilerTenantRow
	var cap32 int32
	ok, err := notFound(t.tx.QueryRow(t.ctx, qCompilerTenant, t.tenant).Scan(&r.Status, &r.AdminHold, &cap32))
	r.ClientCap = int(cap32)
	return r, ok, err
}

// CompilerEndpoint is an Endpoint as the compile map of P3 3.2 reads it.
type CompilerEndpoint struct {
	ID                   uuid.UUID
	ResolverID           string
	TokenHash            []byte
	AdminState           string
	AdminHold            bool
	LegacyDNS            bool
	RequireAuthorizedIPs bool
	ExposeIP             bool
	AuthorizeSecureDNS   bool
	AnalyticsLevel       string
	ProfileID            uuid.UUID
	Profile2ID           uuid.UUID // Nil for none
	ScheduleTimezone     string
	PairVersion          int64
}

const qCompilerEndpoints = `SELECT id, resolver_id, doh_token_hash, admin_state, admin_hold, legacy_dns, require_authorized_ips, expose_ip, authorize_secure_dns,
  analytics_level, profile_id, profile2_id, schedule_timezone, pair_version
FROM ctrlz.endpoints WHERE tenant_id = $1 ORDER BY id`

// CompilerEndpoints reads every Endpoint of the tenant.
func (t Tx) CompilerEndpoints() ([]CompilerEndpoint, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerEndpoints, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CompilerEndpoint
	for rows.Next() {
		var e CompilerEndpoint
		var p2 *uuid.UUID
		if err := rows.Scan(&e.ID, &e.ResolverID, &e.TokenHash, &e.AdminState, &e.AdminHold, &e.LegacyDNS, &e.RequireAuthorizedIPs, &e.ExposeIP,
			&e.AuthorizeSecureDNS, &e.AnalyticsLevel, &e.ProfileID, &p2, &e.ScheduleTimezone, &e.PairVersion); err != nil {
			return nil, sanitize(err)
		}
		if p2 != nil {
			e.Profile2ID = *p2
		}
		out = append(out, e)
	}
	return out, sanitize(rows.Err())
}

const qCompilerWindows = `SELECT id, endpoint_id, lower(minutes), upper(minutes), profile_id, profile2_id FROM ctrlz.schedule_windows
WHERE tenant_id = $1 ORDER BY endpoint_id, lower(minutes)`

// CompilerWindows reads every schedule window of the tenant, by Endpoint and start.
func (t Tx) CompilerWindows() ([]WindowRow, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerWindows, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []WindowRow
	for rows.Next() {
		var w WindowRow
		var start, end int32
		var p2 *uuid.UUID
		if err := rows.Scan(&w.ID, &w.EndpointID, &start, &end, &w.ProfileID, &p2); err != nil {
			return nil, sanitize(err)
		}
		w.Start, w.End = int(start), int(end)
		if p2 != nil {
			w.Profile2ID = *p2
		}
		out = append(out, w)
	}
	return out, sanitize(rows.Err())
}

// CompilerClient is a client row that carries a profile or an analytics level of its own.
type CompilerClient struct {
	ID         uuid.UUID
	EndpointID uuid.UUID
	Label      string
	ProfileID  uuid.UUID
	Profile2ID uuid.UUID
	Analytics  string // "" for none
}

const qCompilerClients = `SELECT id, endpoint_id, label, profile_id, profile2_id, analytics_level FROM ctrlz.clients
WHERE tenant_id = $1 AND (profile_id IS NOT NULL OR analytics_level IS NOT NULL) ORDER BY endpoint_id, label`

// CompilerClients reads the clients of the tenant that compile (P3 3.2: a profile or an analytics level).
func (t Tx) CompilerClients() ([]CompilerClient, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerClients, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CompilerClient
	for rows.Next() {
		var c CompilerClient
		var p1, p2 *uuid.UUID
		var an *string
		if err := rows.Scan(&c.ID, &c.EndpointID, &c.Label, &p1, &p2, &an); err != nil {
			return nil, sanitize(err)
		}
		if p1 != nil {
			c.ProfileID = *p1
		}
		if p2 != nil {
			c.Profile2ID = *p2
		}
		if an != nil {
			c.Analytics = *an
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

// CompilerPrefix is an authorized prefix or a claim: the Endpoint it belongs to, its id (a claim's) and the prefix.
type CompilerPrefix struct {
	ID         uuid.UUID
	EndpointID uuid.UUID
	Prefix     netip.Prefix
}

const qCompilerAuthorized = `SELECT id, endpoint_id, cidr FROM ctrlz.authorized_ips WHERE tenant_id = $1 ORDER BY endpoint_id, cidr`

// CompilerAuthorized reads every authorized prefix of the tenant, any source, by Endpoint and prefix. The
// compiler holds no read of the source column (migration 0037), so the order a cut would follow is the
// prefix's alone.
func (t Tx) CompilerAuthorized() ([]CompilerPrefix, error) {
	return compilerPrefixes(t.tx.Query(t.ctx, qCompilerAuthorized, t.tenant))
}

const qCompilerClaims = `SELECT id, endpoint_id, cidr FROM ctrlz.ip_claims WHERE tenant_id = $1 AND state IN ('active', 'grace') ORDER BY endpoint_id, cidr`

// CompilerClaims reads the claims in active or grace (P3 3.2: of an Endpoint with legacy_dns, which the compiler checks).
func (t Tx) CompilerClaims() ([]CompilerPrefix, error) {
	return compilerPrefixes(t.tx.Query(t.ctx, qCompilerClaims, t.tenant))
}

// compilerPrefixes reads the rows of one of the two prefix statements, which differ in the table and nothing else.
func compilerPrefixes(rows pgx.Rows, err error) ([]CompilerPrefix, error) {
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CompilerPrefix
	for rows.Next() {
		var p CompilerPrefix
		if err := rows.Scan(&p.ID, &p.EndpointID, scanPrefix(&p.Prefix)); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}

// CompilerProfile is a profile's own row.
type CompilerProfile struct {
	ID            uuid.UUID
	DisabledUntil *time.Time
}

const qCompilerProfiles = `SELECT id, disabled_until FROM ctrlz.profiles WHERE tenant_id = $1 ORDER BY id`

// CompilerProfiles reads the profile rows of the tenant.
func (t Tx) CompilerProfiles() ([]CompilerProfile, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerProfiles, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CompilerProfile
	for rows.Next() {
		var p CompilerProfile
		if err := rows.Scan(&p.ID, &p.DisabledUntil); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, p)
	}
	return out, sanitize(rows.Err())
}

// ProfileRule is a rule with the profile it belongs to: the shape a test hands the compiler when it has no database.
type ProfileRule struct {
	ProfileID uuid.UUID
	RuleRow
}

// The rules of one profile, with the columns a blob is built from and no more: the comment (up to 64 characters) and the two
// timestamps are never compiled, and for a profile of 10,000 rules they are a third of the row. A tenant's rules are read one
// profile at a time, and each profile's rows are dropped once its blob is built, so the worker holds one profile's rules
// and not the 200,000 a Free plan allows.
const qCompilerRulesOf = `SELECT id, folder_id, rule_key, match_kind, negated, action, target_kind, target_location_id,
  host(target_ipv4), host(target_ipv6), target_host, enabled, expires_at, location_unavailable
FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 ORDER BY rule_key, id`

// CompilerRulesOf reads the rules of one profile of the transaction's tenant, in blob order.
func (t Tx) CompilerRulesOf(profile uuid.UUID) ([]RuleRow, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerRulesOf, t.tenant, profile)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []RuleRow
	for rows.Next() {
		var x RuleRow
		var folder, loc *uuid.UUID
		var kind, v4, v6, host *string
		if err := rows.Scan(&x.ID, &folder, &x.Key, &x.MatchKind, &x.Negated, &x.Action, &kind, &loc, &v4, &v6, &host, &x.Enabled,
			&x.ExpiresAt, &x.LocationUnavailable); err != nil {
			return nil, sanitize(err)
		}
		if folder != nil {
			x.FolderID = *folder
		}
		x.Target = scanTarget(kind, loc, v4, v6, host)
		out = append(out, x)
	}
	return out, sanitize(rows.Err())
}

// ProfileFolder is a folder with the profile it belongs to. The rule count is not read.
type ProfileFolder struct {
	ProfileID uuid.UUID
	FolderRow
}

const qCompilerFolders = `SELECT f.profile_id, f.id, f.name, f.kind, f.action, f.target_kind, f.target_location_id, host(f.target_ipv4), host(f.target_ipv6),
  f.target_host, f.location_unavailable
FROM ctrlz.rule_folders f WHERE f.tenant_id = $1 ORDER BY f.profile_id, f.id`

// CompilerFolders reads every rule folder of the tenant.
func (t Tx) CompilerFolders() ([]ProfileFolder, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerFolders, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ProfileFolder
	for rows.Next() {
		var f ProfileFolder
		var action, kind, v4, v6, host *string
		var loc *uuid.UUID
		if err := rows.Scan(&f.ProfileID, &f.ID, &f.Name, &f.Kind, &action, &kind, &loc, &v4, &v6, &host, &f.LocationUnavailable); err != nil {
			return nil, sanitize(err)
		}
		if action != nil {
			f.Action = *action
		}
		f.Target = scanTarget(kind, loc, v4, v6, host)
		out = append(out, f)
	}
	return out, sanitize(rows.Err())
}

// ProfileService is a service state with the profile it belongs to.
type ProfileService struct {
	ProfileID uuid.UUID
	ServiceRow
}

const qCompilerServices = `SELECT profile_id, service_slug, enabled, action, target_kind, target_location_id, host(target_ipv4), host(target_ipv6), target_host, location_unavailable
FROM ctrlz.profile_services WHERE tenant_id = $1 ORDER BY profile_id, service_slug`

// CompilerServices reads every service state of the tenant.
func (t Tx) CompilerServices() ([]ProfileService, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerServices, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ProfileService
	for rows.Next() {
		var s ProfileService
		var kind, v4, v6, host *string
		var loc *uuid.UUID
		if err := rows.Scan(&s.ProfileID, &s.Slug, &s.Enabled, &s.Action, &kind, &loc, &v4, &v6, &host, &s.LocationUnavailable); err != nil {
			return nil, sanitize(err)
		}
		s.Target = scanTarget(kind, loc, v4, v6, host)
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

// ProfileFilter is a filter state with the profile it belongs to.
type ProfileFilter struct {
	ProfileID uuid.UUID
	FilterRow
}

const qCompilerFilters = `SELECT profile_id, filter_id, enabled, mode FROM ctrlz.profile_filters WHERE tenant_id = $1 ORDER BY profile_id, filter_id`

// CompilerFilters reads every filter state of the tenant.
func (t Tx) CompilerFilters() ([]ProfileFilter, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerFilters, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ProfileFilter
	for rows.Next() {
		var f ProfileFilter
		var mode *string
		if err := rows.Scan(&f.ProfileID, &f.FilterID, &f.Enabled, &mode); err != nil {
			return nil, sanitize(err)
		}
		if mode != nil {
			f.Mode = *mode
		}
		out = append(out, f)
	}
	return out, sanitize(rows.Err())
}

// ProfileOptions is the options row with the profile it belongs to.
type ProfileOptions struct {
	ProfileID uuid.UUID
	OptionsRow
}

const qCompilerOptions = `SELECT profile_id, default_action, default_target_kind, default_target_location_id, host(default_target_ipv4), host(default_target_ipv6),
  default_target_host, default_location_unavailable, block_exfiltration, rebind_protection, disable_dnssec, block_ttl, redirect_ttl, bypass_ttl,
  block_response, host(block_custom_v4), host(block_custom_v6), ecs_mode, ecs_v4::text, ecs_v6::text, dns64, cname_flattening, safe_search, restricted_youtube
FROM ctrlz.profile_options WHERE tenant_id = $1 ORDER BY profile_id`

// CompilerOptions reads the options row of every profile of the tenant that has one.
func (t Tx) CompilerOptions() ([]ProfileOptions, error) {
	rows, err := t.tx.Query(t.ctx, qCompilerOptions, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ProfileOptions
	for rows.Next() {
		var o ProfileOptions
		var action, kind, v4, v6, host, resp, b4, b6, ecs, e4, e6 *string
		var loc *uuid.UUID
		if err := rows.Scan(&o.ProfileID, &action, &kind, &loc, &v4, &v6, &host, &o.DefaultLocationUnavailable,
			&o.BlockExfiltration, &o.RebindProtection, &o.DisableDNSSEC, &o.BlockTTL, &o.RedirectTTL, &o.BypassTTL, &resp, &b4, &b6, &ecs, &e4, &e6,
			&o.DNS64, &o.CNAMEFlattening, &o.SafeSearch, &o.RestrictedYouTube); err != nil {
			return nil, sanitize(err)
		}
		str := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		o.DefaultAction = str(action)
		o.DefaultTarget = scanTarget(kind, loc, v4, v6, host)
		o.BlockResponse, o.BlockV4, o.BlockV6, o.ECSMode, o.ECSV4, o.ECSV6 = str(resp), str(b4), str(b6), str(ecs), str(e4), str(e6)
		out = append(out, o)
	}
	return out, sanitize(rows.Err())
}

// CompilerMaps are the catalog ids a profile names by text, and the wire ids the blob holds instead.
type CompilerMaps struct {
	Services  map[string]uint32            // service slug to wire id
	Filters   map[string]uint16            // filter id to wire id
	Modes     map[string]map[string]uint16 // filter id, mode to wire id
	Locations map[uuid.UUID]uint16         // location id to wire id
}

const (
	qCompilerMapServices  = `SELECT slug, wire_id FROM ctrlz.catalog_service`
	qCompilerMapFilters   = `SELECT id, wire_id FROM ctrlz.catalog_filter`
	qCompilerMapModes     = `SELECT filter_id, mode, wire_id FROM ctrlz.catalog_filter_mode`
	qCompilerMapLocations = `SELECT id, wire_id FROM ctrlz.locations`
)

// CompilerMaps reads the four id maps. They are global tables, read in the tenant's snapshot so a profile and the
// ids it names are one consistent picture.
func (t Tx) CompilerMaps() (CompilerMaps, error) {
	m := CompilerMaps{Services: map[string]uint32{}, Filters: map[string]uint16{}, Modes: map[string]map[string]uint16{}, Locations: map[uuid.UUID]uint16{}}
	rows, err := t.tx.Query(t.ctx, qCompilerMapServices)
	if err != nil {
		return m, sanitize(err)
	}
	for rows.Next() {
		var slug string
		var w int32
		if err := rows.Scan(&slug, &w); err != nil {
			rows.Close()
			return m, sanitize(err)
		}
		m.Services[slug] = uint32(w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, sanitize(err)
	}
	if rows, err = t.tx.Query(t.ctx, qCompilerMapFilters); err != nil {
		return m, sanitize(err)
	}
	for rows.Next() {
		var id string
		var w int32
		if err := rows.Scan(&id, &w); err != nil {
			rows.Close()
			return m, sanitize(err)
		}
		m.Filters[id] = uint16(w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, sanitize(err)
	}
	if rows, err = t.tx.Query(t.ctx, qCompilerMapModes); err != nil {
		return m, sanitize(err)
	}
	for rows.Next() {
		var id, mode string
		var w int32
		if err := rows.Scan(&id, &mode, &w); err != nil {
			rows.Close()
			return m, sanitize(err)
		}
		if m.Modes[id] == nil {
			m.Modes[id] = map[string]uint16{}
		}
		m.Modes[id][mode] = uint16(w)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, sanitize(err)
	}
	if rows, err = t.tx.Query(t.ctx, qCompilerMapLocations); err != nil {
		return m, sanitize(err)
	}
	for rows.Next() {
		var id uuid.UUID
		var w int32
		if err := rows.Scan(&id, &w); err != nil {
			rows.Close()
			return m, sanitize(err)
		}
		m.Locations[id] = uint16(w)
	}
	rows.Close()
	return m, sanitize(rows.Err())
}
