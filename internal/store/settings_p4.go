package store

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The admin's half of the P4 settings: free DNS, the domain, the free DNS counters (p4-nodes 9.2). Every method runs in
// WithGlobal as ctrlz_admin, so its reach is the role's grants (migration 0100: U on free_dns_settings (enabled, qps), U on
// domain_settings of six columns, S on free_dns_counters). None of it is tenant data and none of it writes policy_outbox
// (T-081): the compiler reads free_dns_settings.version itself.

// FreeDNS is the one row of free_dns_settings.
type FreeDNS struct {
	Enabled   bool
	QPS       int
	Version   int64
	UpdatedAt time.Time
}

const qFreeDNSGet = `SELECT enabled, qps, version, updated_at FROM ctrlz.free_dns_settings`
const qFreeDNSLock = qFreeDNSGet + lockNoKeyUpdate

func scanFreeDNS(row pgx.Row) (FreeDNS, error) {
	var f FreeDNS
	var qps int32
	err := row.Scan(&f.Enabled, &qps, &f.Version, &f.UpdatedAt)
	f.QPS = int(qps)
	return f, sanitize(err)
}

// FreeDNSGet reads the switch and the rate.
func (g GlobalTx) FreeDNSGet() (FreeDNS, error) {
	return scanFreeDNS(g.tx.QueryRow(g.ctx, qFreeDNSGet))
}

// FreeDNSLock reads the row and locks it, so two admins changing it are ordered and the audit row says what was replaced.
func (g GlobalTx) FreeDNSLock() (FreeDNS, error) {
	return scanFreeDNS(g.tx.QueryRow(g.ctx, qFreeDNSLock))
}

const qFreeDNSSet = `UPDATE ctrlz.free_dns_settings SET enabled = $1, qps = $2`

// FreeDNSSet writes the switch and the rate. The trigger of the table moves version on every update, so the compiler and
// the off floor of SC 5.2a see each change, a revert included.
func (g GlobalTx) FreeDNSSet(enabled bool, qps int) error {
	_, err := g.tx.Exec(g.ctx, qFreeDNSSet, enabled, int32(qps))
	return sanitize(err)
}

// FreeCounterKey is the sort key of free_dns_counters as the route pages it.
type FreeCounterKey struct {
	Bucket   time.Time
	NodeID   uuid.UUID
	Protocol string
	Outcome  string
	RCode    int
}

// FreeCounterRow is one hourly row: a count of queries by node, transport, outcome and rcode. The table has no name and no
// address of any client (SC 5.2a), so neither can appear here.
type FreeCounterRow struct {
	FreeCounterKey
	Count int64
}

// qFreeCounters pages by the primary key (the order is the key's, which the index serves). The first page passes $4 true
// and the key compared against is then ignored.
const qFreeCounters = `SELECT bucket_start, node_id, protocol, outcome, rcode, count
FROM ctrlz.free_dns_counters
WHERE bucket_start >= $1 AND bucket_start < $2 AND ($3::uuid IS NULL OR node_id = $3)
  AND ($4::boolean OR (bucket_start, node_id, protocol, outcome, rcode) > ($5::timestamptz, $6::uuid, $7::text, $8::text, $9::smallint))
ORDER BY bucket_start, node_id, protocol, outcome, rcode
LIMIT $10`

// FreeCounters lists the counter rows in [from, to), optionally of one node, after a key.
func (g GlobalTx) FreeCounters(from, to time.Time, node uuid.UUID, after *FreeCounterKey, limit int) ([]FreeCounterRow, error) {
	var k FreeCounterKey
	if after != nil {
		k = *after
	}
	rows, err := g.tx.Query(g.ctx, qFreeCounters, from, to, nilUUID(node), after == nil, k.Bucket, k.NodeID, k.Protocol, k.Outcome, int16(k.RCode), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []FreeCounterRow
	for rows.Next() {
		var r FreeCounterRow
		var rc int16
		if err := rows.Scan(&r.Bucket, &r.NodeID, &r.Protocol, &r.Outcome, &rc, &r.Count); err != nil {
			return nil, sanitize(err)
		}
		r.RCode = int(rc)
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

// DomainSettings is the one row of domain_settings. A NULL text is the empty string, a NULL time is nil.
type DomainSettings struct {
	DNSZone            string
	PanelHost          string
	AdminHost          string
	PrevDNSZone        string
	TransitionUntil    *time.Time
	ChangedAt          *time.Time
	AppliedPanelHost   string
	AppliedAdminHost   string
	AppliedPanelCertID *uuid.UUID
	AppliedAdminCertID *uuid.UUID
	AppliedAt          *time.Time
}

const qDomainGet = `SELECT COALESCE(dns_zone, ''), COALESCE(panel_host, ''), COALESCE(admin_host, ''), COALESCE(prev_dns_zone, ''),
  transition_until, changed_at, COALESCE(applied_panel_host, ''), COALESCE(applied_admin_host, ''),
  applied_panel_cert_id, applied_admin_cert_id, applied_at
FROM ctrlz.domain_settings`
const qDomainLock = qDomainGet + lockNoKeyUpdate

func scanDomain(row pgx.Row) (DomainSettings, error) {
	var d DomainSettings
	err := row.Scan(&d.DNSZone, &d.PanelHost, &d.AdminHost, &d.PrevDNSZone, &d.TransitionUntil, &d.ChangedAt,
		&d.AppliedPanelHost, &d.AppliedAdminHost, &d.AppliedPanelCertID, &d.AppliedAdminCertID, &d.AppliedAt)
	return d, sanitize(err)
}

// DomainGet reads the domain settings.
func (g GlobalTx) DomainGet() (DomainSettings, error) {
	return scanDomain(g.tx.QueryRow(g.ctx, qDomainGet))
}

// DomainLock reads them and locks the row, so two changes of the zone are ordered and the second sees the transition the
// first started.
func (g GlobalTx) DomainLock() (DomainSettings, error) {
	return scanDomain(g.tx.QueryRow(g.ctx, qDomainLock))
}

const qDomainSet = `UPDATE ctrlz.domain_settings SET dns_zone = $1, panel_host = $2, admin_host = $3, prev_dns_zone = $4,
  transition_until = $5, changed_at = $6`

// DomainSet writes the six columns the admin may write. The route passes every one, the unchanged ones as they were, so
// the statement has one shape; an empty text is NULL.
func (g GlobalTx) DomainSet(d DomainSettings) error {
	_, err := g.tx.Exec(g.ctx, qDomainSet, emptyNull(d.DNSZone), emptyNull(d.PanelHost), emptyNull(d.AdminHost), emptyNull(d.PrevDNSZone), d.TransitionUntil, d.ChangedAt)
	return sanitize(err)
}

const qDomainImpact = `SELECT count(*), count(apple_profile_generated_at) FROM ctrlz.endpoints`

// DomainImpact counts what a change of zone touches (10.4): every Endpoint, and the Endpoints that have an Apple profile,
// which turn stale because the zone CA and the names in them change. It reads across tenants through the admin's policy.
func (g GlobalTx) DomainImpact() (endpoints, appleProfiles int64, err error) {
	err = g.tx.QueryRow(g.ctx, qDomainImpact).Scan(&endpoints, &appleProfiles)
	return endpoints, appleProfiles, sanitize(err)
}

const qConfigHead = `SELECT COALESCE(max(seq), 0) FROM ctrlz.config_log`

// ConfigHead is the newest sequence number of the configuration log, 0 while it is empty.
func (g GlobalTx) ConfigHead() (int64, error) {
	var head int64
	err := g.tx.QueryRow(g.ctx, qConfigHead).Scan(&head)
	return head, sanitize(err)
}
