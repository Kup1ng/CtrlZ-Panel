package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// The hub's side of enrolment, node certificates and the private CAs (p4-nodes 3.2 items 3 and 5, 4.2,
// 4.3, 4.4). Every method is one transaction of the role it is called on, and the hub opens the
// store several times over, one pool per kind of work (p4-nodes 5.7): which pool a statement runs on
// is decided by which Store the caller holds, so a method here says nothing about it.
//
// Nothing here is tenant-scoped. The hub's grants on these tables are the whole boundary: hub U on the
// record columns of node_enrollments, hub I and U on node_certs, and a row-level policy that lets it
// write the rows of the two private CAs and no other certificate (migration 0100).

// ErrEnrollRefused is Enroll's one answer for a used, expired, unknown or wrongly bound token: the
// caller cannot tell which, and neither can the sender.
var ErrEnrollRefused = errors.New("store: enrolment token refused")

// ErrNodeGone is returned by HubIssueCert when the node row stopped being active (or changed its key)
// between the read that decided to issue and the write: nothing was written.
var ErrNodeGone = errors.New("store: the node is no longer active")

// HubEnrollIn is the record of a first Enroll: the whole of it is written in one statement, because
// the database freezes it once set (node_enrollments_frozen).
type HubEnrollIn struct {
	TokenHash   []byte
	CSR         []byte
	SPKI        []byte // SHA-256 of the SubjectPublicKeyInfo, 32 bytes
	Hostname    string
	OSRelease   string
	NodeVersion string
	DNSBind     netip.Addr
	DNSAdv      netip.Addr
	ProxyBind   netip.Addr // invalid means none
	ProxyAdv    netip.Addr // invalid means none
	From        netip.Addr
}

const qHubEnroll = `UPDATE ctrlz.node_enrollments SET csr_der = $2, spki_sha256 = $3, key_fingerprint = pg_catalog.encode($3::bytea, 'hex'),
  hostname = $4, os_release = $5, node_version = $6, dns_bind_ip = $7, dns_advertised_ip = $8, proxy_bind_ip = $9,
  proxy_advertised_ip = $10, enrolled_from = $11, enrolled_at = pg_catalog.now(), state = 'pending_approval'
WHERE token_hash = $1 AND state = 'issued' AND expires_at > pg_catalog.now() AND (bound_ip IS NULL OR bound_ip >>= $11)
RETURNING id, key_fingerprint`

// HubEnroll writes the record of a first Enroll and returns the enrolment id and the fingerprint (the
// hex SHA-256 of the key). A token that is not live, or a source outside the token's bound address,
// writes nothing and is ErrEnrollRefused.
func (s *Store) HubEnroll(ctx context.Context, in HubEnrollIn) (uuid.UUID, string, error) {
	var id uuid.UUID
	var fp string
	err := s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubEnroll, in.TokenHash, in.CSR, in.SPKI, in.Hostname, in.OSRelease, in.NodeVersion,
			addrArg(in.DNSBind), addrArg(in.DNSAdv), addrArg(in.ProxyBind), addrArg(in.ProxyAdv), addrArg(in.From)).Scan(&id, &fp))
		if err != nil {
			return err
		}
		if !ok {
			return ErrEnrollRefused
		}
		return nil
	})
	return id, fp, err
}

const qHubTokenLive = `SELECT EXISTS (SELECT 1 FROM ctrlz.node_enrollments WHERE token_hash = $1 AND state = 'issued' AND expires_at > pg_catalog.now())`

// HubTokenLive says whether an enrolment token is issued and unexpired: the door of a bundle download
// (p4-nodes 5.1). It runs on the enrollment pool, one connection with a short statement timeout.
func (s *Store) HubTokenLive(ctx context.Context, hash []byte) (bool, error) {
	var live bool
	err := s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		return sanitize(g.tx.QueryRow(g.ctx, qHubTokenLive, hash).Scan(&live))
	})
	return live, err
}

// HubEnrollment is what Poll reads: the record, the state, and the node row the admin made when it
// confirmed the fingerprint.
type HubEnrollment struct {
	State      string
	CSR        []byte
	SPKI       []byte // enrolment record's key, SHA-256 of the SPKI
	CertDER    []byte // the certificate a Poll issued, nil before
	NodeID     uuid.UUID
	NodeStatus string // "" when there is no node row yet
	NodeSPKI   []byte
}

const qHubEnrollment = `SELECT e.state, e.csr_der, e.spki_sha256, e.cert_der, e.node_id, n.status, n.spki_sha256
FROM ctrlz.node_enrollments e LEFT JOIN ctrlz.nodes n ON n.id = e.node_id WHERE e.id = $1`

// HubEnrollmentLoad reads one enrolment by id. found is false for an unknown id.
func (s *Store) HubEnrollmentLoad(ctx context.Context, id uuid.UUID) (e HubEnrollment, found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		var node *uuid.UUID
		var status *string
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubEnrollment, id).Scan(&e.State, &e.CSR, &e.SPKI, &e.CertDER, &node, &status, &e.NodeSPKI))
		if err != nil || !ok {
			return err
		}
		found = true
		if node != nil {
			e.NodeID = *node
		}
		if status != nil {
			e.NodeStatus = *status
		}
		return nil
	})
	return e, found, err
}

const qHubEnrollCert = `UPDATE ctrlz.node_enrollments SET cert_der = $2 WHERE id = $1 AND state = 'approved' AND cert_der IS NULL AND node_id = $3 RETURNING id`
const qHubCertInsert = `INSERT INTO ctrlz.node_certs (serial, node_id, not_before, not_after) VALUES ($1, $2, $3, $4)`
const qHubNodeFirstSerial = `UPDATE ctrlz.nodes SET cert_serial = $2 WHERE id = $1 AND status = 'active' AND spki_sha256 = $3 AND cert_serial IS NULL RETURNING id`

// HubIssueCert records the first certificate of an approved enrolment in one transaction: the
// enrolment's cert_der, the node_certs row and nodes.cert_serial. issued is false when another Poll
// got there first (the caller reads the stored certificate); ErrNodeGone when the node row is no
// longer active with this key, in which case nothing was written. A replayed Poll cannot move
// cert_serial, because the first statement matches only while cert_der is still empty.
func (s *Store) HubIssueCert(ctx context.Context, enrollment, node uuid.UUID, nodeSPKI []byte, serial string, notBefore, notAfter time.Time, certDER []byte) (issued bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var got uuid.UUID
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubEnrollCert, enrollment, certDER, node).Scan(&got))
		if err != nil || !ok {
			return err
		}
		if _, err := g.tx.Exec(g.ctx, qHubCertInsert, serial, node, notBefore, notAfter); err != nil {
			return sanitize(err)
		}
		ok, err = notFound(g.tx.QueryRow(g.ctx, qHubNodeFirstSerial, node, serial, nodeSPKI).Scan(&got))
		if err != nil {
			return err
		}
		if !ok {
			return ErrNodeGone
		}
		issued = true
		return nil
	})
	return issued, err
}

// HubNode is what a check of a node's certificate reads (p4-nodes 4.4).
type HubNode struct {
	Status         string
	SPKI           []byte
	CertSerial     string
	PrevCertSerial string
}

const qHubNode = `SELECT status, spki_sha256, COALESCE(cert_serial, ''), COALESCE(prev_cert_serial, '') FROM ctrlz.nodes WHERE id = $1`

// HubNodeLoad reads a node row for a certificate check.
func (s *Store) HubNodeLoad(ctx context.Context, id uuid.UUID) (n HubNode, found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubNode, id).Scan(&n.Status, &n.SPKI, &n.CertSerial, &n.PrevCertSerial))
		found = ok
		return err
	})
	return n, found, err
}

// A renewal. The serial presented is either the current one (it becomes the previous one, so the node
// that never gets the response keeps working) or the previous one (the response was lost: the lost
// serial is dropped and the previous one stays, because the node still holds that certificate).
const qHubNodeRenew = `UPDATE ctrlz.nodes SET prev_cert_serial = CASE WHEN cert_serial = $4 THEN cert_serial ELSE prev_cert_serial END, cert_serial = $2
WHERE id = $1 AND status = 'active' AND spki_sha256 = $3 AND (cert_serial = $4 OR prev_cert_serial = $4) RETURNING id`

// HubRenewCert writes a renewal: the node_certs row and the node's serials, in one transaction, only
// while the node is active with this key and the presented serial is one of its two. ErrNodeGone
// otherwise, with nothing written.
func (s *Store) HubRenewCert(ctx context.Context, node uuid.UUID, nodeSPKI []byte, presented, serial string, notBefore, notAfter time.Time) error {
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		var got uuid.UUID
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubNodeRenew, node, serial, nodeSPKI, presented).Scan(&got))
		if err != nil {
			return err
		}
		if !ok {
			return ErrNodeGone
		}
		if _, err := g.tx.Exec(g.ctx, qHubCertInsert, serial, node, notBefore, notAfter); err != nil {
			return sanitize(err)
		}
		return nil
	})
}

const qHubClearPrev = `UPDATE ctrlz.nodes SET prev_cert_serial = NULL WHERE id = $1 AND cert_serial = $2 AND prev_cert_serial IS NOT NULL`

// HubClearPrevSerial drops the previous serial once the node has opened an RPC with the new one (4.3).
func (s *Store) HubClearPrevSerial(ctx context.Context, node uuid.UUID, current string) error {
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		_, err := g.tx.Exec(g.ctx, qHubClearPrev, node, current)
		return sanitize(err)
	})
}

const qHubNodeAddrs = `SELECT id, dns_bind_ip, dns_advertised_ip, proxy_bind_ip, proxy_advertised_ip FROM ctrlz.nodes WHERE status <> 'revoked'`

// An approved enrolment counts only while its node is not revoked or removed: a revoked node's host
// must not keep a reserved handshake slot for as long as its enrolment row exists.
const qHubEnrolledFrom = `SELECT e.enrolled_from FROM ctrlz.node_enrollments e
LEFT JOIN ctrlz.nodes n ON n.id = e.node_id
WHERE e.enrolled_from IS NOT NULL AND (e.state = 'pending_approval' OR (e.state = 'approved' AND n.status IS NOT NULL AND n.status <> 'revoked'))`

// HubAddrs is what the 60 s pass learns: the addresses and the non-revoked nodes they belong to.
type HubAddrs struct {
	Addrs []netip.Addr
	Nodes []uuid.UUID // every node that is not revoked
}

// HubNodeAddrs is the set of source addresses that may use the reserved handshake slots (5.1): each
// non-revoked node's bind and advertised addresses, and the address a pending enrolment or an approved
// one of a non-revoked node came from. It is a list of infrastructure addresses of the operator, never
// a client's. Nodes lets the hub forget the last source it saw of a node that is gone.
func (s *Store) HubNodeAddrs(ctx context.Context) (HubAddrs, error) {
	var out HubAddrs
	err := s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		rows, err := g.tx.Query(g.ctx, qHubNodeAddrs)
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var a [4]*netip.Addr
			var id uuid.UUID
			if err := rows.Scan(&id, scanAddr(&a[0]), scanAddr(&a[1]), scanAddr(&a[2]), scanAddr(&a[3])); err != nil {
				return sanitize(err)
			}
			out.Nodes = append(out.Nodes, id)
			for _, p := range a {
				if p != nil {
					out.Addrs = append(out.Addrs, p.Unmap())
				}
			}
		}
		if err := rows.Err(); err != nil {
			return sanitize(err)
		}
		rows.Close()
		rows2, err := g.tx.Query(g.ctx, qHubEnrolledFrom)
		if err != nil {
			return sanitize(err)
		}
		defer rows2.Close()
		for rows2.Next() {
			var p *netip.Addr
			if err := rows2.Scan(scanAddr(&p)); err != nil {
				return sanitize(err)
			}
			if p != nil {
				out.Addrs = append(out.Addrs, p.Unmap())
			}
		}
		return sanitize(rows2.Err())
	})
	return out, err
}

// ---------------------------------------------------------------------------------------------------
// The private CAs' certificates rows and the live zones (4.3).

// The kinds of certificates row the hub owns.
const (
	CertKindNodeCA = "node_ca"
	CertKindZoneCA = "zone_ca"
)

// HubCertRow is a certificates row of a private CA.
type HubCertRow struct {
	ID        uuid.UUID
	ChainPEM  string
	NotBefore time.Time
	NotAfter  time.Time
	Names     []string
}

const qHubActiveCA = `SELECT id, chain_pem, not_before, not_after, names FROM ctrlz.certificates
WHERE kind = $1 AND state = 'active' AND source = 'issued' ORDER BY not_before DESC, id DESC LIMIT 1`

// HubActiveCA reads the newest active row of a private CA kind.
func (s *Store) HubActiveCA(ctx context.Context, kind string) (r HubCertRow, found bool, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		ok, err := notFound(g.tx.QueryRow(g.ctx, qHubActiveCA, kind).Scan(&r.ID, &r.ChainPEM, &r.NotBefore, &r.NotAfter, &r.Names))
		found = ok
		return err
	})
	return r, found, err
}

const qHubRetireCert = `UPDATE ctrlz.certificates SET state = 'retired' WHERE id = $1`
const qHubInsertCA = `INSERT INTO ctrlz.certificates (kind, chain_pem, not_before, not_after, state, names, source)
VALUES ($1, $2, $3, $4, 'active', $5, 'issued')`
const qHubDomainChangeJob = `INSERT INTO ctrlz.admin_jobs (kind, params) VALUES ('domain_change', $1::jsonb) ON CONFLICT DO NOTHING`

// HubReplaceCA stores a CA certificate as the active row of its kind and retires the row it replaces
// (old is uuid.Nil when there is none). For the zone CA it also queues the domain_change job whose notice
// carries the reinstall line (4.3): with ON CONFLICT DO NOTHING, since a job in flight reads the state
// when it runs. reinstall is "same_key" or "new_key".
func (s *Store) HubReplaceCA(ctx context.Context, kind string, old uuid.UUID, chainPEM string, notBefore, notAfter time.Time, names []string, queueJob bool, reinstall string) error {
	params, err := json.Marshal(map[string]string{"reason": "zone_ca_reissued", "reinstall": reinstall})
	if err != nil {
		return err
	}
	if names == nil {
		names = []string{}
	}
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		if old != uuid.Nil {
			if _, err := g.tx.Exec(g.ctx, qHubRetireCert, old); err != nil {
				return sanitize(err)
			}
		}
		if _, err := g.tx.Exec(g.ctx, qHubInsertCA, kind, chainPEM, notBefore, notAfter, names); err != nil {
			return sanitize(err)
		}
		if queueJob {
			if _, err := g.tx.Exec(g.ctx, qHubDomainChangeJob, string(params)); err != nil {
				return sanitize(err)
			}
		}
		return nil
	})
}

// HubZones are the zones domain_settings holds.
type HubZones struct {
	DNSZone         string // "" while no domain is set
	PrevDNSZone     string
	TransitionUntil time.Time // zero when none
}

const qHubZones = `SELECT COALESCE(dns_zone, ''), COALESCE(prev_dns_zone, ''), transition_until FROM ctrlz.domain_settings`

// HubLiveZones reads the zone settings. The live zones are DNSZone and, until TransitionUntil,
// PrevDNSZone (4.3).
func (s *Store) HubLiveZones(ctx context.Context) (z HubZones, err error) {
	err = s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		var until *time.Time
		if err := g.tx.QueryRow(g.ctx, qHubZones).Scan(&z.DNSZone, &z.PrevDNSZone, &until); err != nil {
			return sanitize(err)
		}
		if until != nil {
			z.TransitionUntil = *until
		}
		return nil
	})
	return z, err
}

const qHubAlert = `INSERT INTO ctrlz.alerts (severity, kind, params) VALUES ($1, $2, $3::jsonb)`

// HubAlertKind is a closed value: the alert kinds the hub raises.
type HubAlertKind string

// The alerts of the hub's trust code.
const (
	HubAlertZoneCAReissued HubAlertKind = "zone_ca_reissued"
	HubAlertNodeCAChanged  HubAlertKind = "node_ca_changed"
	// HubAlertZoneInvalid says a live zone in domain_settings failed the hub's own zone rule and was left
	// out of the zone CA.
	HubAlertZoneInvalid HubAlertKind = "zone_invalid"
	// HubAlertNodeClockSkew says a node's clock differs from the hub's by more than 2 s (p4-nodes 5.3).
	HubAlertNodeClockSkew HubAlertKind = "node_clock_skew"
	// HubAlertQuarantineTwoNodes says two nodes quarantined the same item for the same reason (p4-nodes 5.3, SC 9.7).
	HubAlertQuarantineTwoNodes HubAlertKind = "node_quarantine_two_nodes"
	// HubAlertRevocationPending says a node is 60 s behind a Revocation (5.5, R34).
	HubAlertRevocationPending HubAlertKind = "node_revocation_pending"
	// The alerts of the failover loop (8a.4 Admin, 8a.6): every signing event but a refresh names its row, and the hub alerts for a
	// node that has resolve paths and none healthy, which moves nothing by itself.
	HubAlertFailMembership        HubAlertKind = "failover_membership"
	HubAlertFailWithdrawal        HubAlertKind = "failover_withdrawal"
	HubAlertFailWithdrawalResolve HubAlertKind = "failover_withdrawal_resolve"
	HubAlertFailFailback          HubAlertKind = "failover_failback"
	HubAlertFailHold              HubAlertKind = "failover_hold"
	HubAlertFailRelease           HubAlertKind = "failover_release"
	HubAlertFailForceFailback     HubAlertKind = "failover_force_failback"
	HubAlertFailFlapping          HubAlertKind = "failover_flapping"
	HubAlertFailNotDecided        HubAlertKind = "failover_event_not_committed"
	HubAlertNodeCannotResolve     HubAlertKind = "node_cannot_resolve"
)

// HubAlert inserts an alert. params carry names and counts only, never a key or a token.
func (s *Store) HubAlert(ctx context.Context, severity string, kind HubAlertKind, params map[string]string) error {
	b, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		_, err := g.tx.Exec(g.ctx, qHubAlert, severity, string(kind), string(b))
		return sanitize(err)
	})
}
