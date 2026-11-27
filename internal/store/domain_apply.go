package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// The apply step's half of domain_settings and certificates (p4-nodes 3.2 item 6, 10.4). It runs as ctrlz_domain_apply,
// the login of the one-shot `ctrlz domain-apply`: SELECT on domain_settings, SELECT on the active rows of kind panel and
// admin (the sealed key included, which nobody else reads back) and the uploaded wildcards (0104; chain and names only), and UPDATE of the five applied_* columns. Nothing here is
// tenant data and every method is one transaction of that role; the grants are the boundary, not these statements.

// ErrDomainChanged is DomainApplyCommit's answer when the requested values moved between the read the plan was made from
// and the write: the files of the plan are in place, the columns are not, and a new run decides again.
var ErrDomainChanged = errors.New("store: the domain settings changed during the apply")

// DomainApplyCert is an active panel, admin or uploaded wildcard certificate row as the apply step reads it. The wildcards are
// read to learn which zones run on a public certificate (the verify origin, p4-nodes 10.3), so their SealedKey is always nil:
// the query returns NULL in its place, whatever the row holds.
type DomainApplyCert struct {
	ID        uuid.UUID
	Kind      string
	ChainPEM  string
	SealedKey []byte // the HPKE seal of the private key (intakeseal.Web); never logged, printed or written as it is
}

// domainApplyCertsLimit is a ceiling and not a page: a row ends or is retired by hand, so a few rows are active at once.
const domainApplyCertsLimit = 400

// The wildcard filter is the hub's (HubWildcardRows): an active uploaded row with a sealed key, which is what a node is served.
const qDomainApplyCerts = `SELECT id, kind, chain_pem, CASE WHEN kind = 'wildcard' THEN NULL ELSE wrapped_key_ct END FROM ctrlz.certificates
WHERE state = 'active' AND (kind IN ('panel', 'admin') OR (kind = 'wildcard' AND source = 'uploaded' AND wrapped_key_ct IS NOT NULL))
ORDER BY id DESC LIMIT 400`

// DomainApplyLoad reads the settings and the active web certificates in one transaction, so the plan is made from one
// snapshot of both.
func (s *Store) DomainApplyLoad(ctx context.Context) (DomainSettings, []DomainApplyCert, error) {
	var d DomainSettings
	var certs []DomainApplyCert
	err := s.WithGlobal(ctx, TxOpts{ReadOnly: true}, func(g GlobalTx) error {
		var err error
		if d, err = scanDomain(g.tx.QueryRow(g.ctx, qDomainGet)); err != nil {
			return err
		}
		rows, err := g.tx.Query(g.ctx, qDomainApplyCerts)
		if err != nil {
			return sanitize(err)
		}
		defer rows.Close()
		for rows.Next() {
			var c DomainApplyCert
			if err := rows.Scan(&c.ID, &c.Kind, &c.ChainPEM, &c.SealedKey); err != nil {
				return sanitize(err)
			}
			certs = append(certs, c)
		}
		return sanitize(rows.Err())
	})
	return d, certs, err
}

// DomainApplyCommitIn is what the apply step wrote and what it decided from.
type DomainApplyCommitIn struct {
	// Seen is the settings row the plan was made from. Only the five requested columns are compared at the write.
	Seen DomainSettings

	// PanelHost and AdminHost are the hosts that were put in force. Empty records NULL: the host came from the .env or the
	// default, which keeps deciding (R34-r1-9).
	PanelHost, AdminHost string
	// The certificate rows the plan installed, nil for a host that runs on the private CA.
	PanelCert, AdminCert *uuid.UUID
}

// The applied columns move only while the requested ones are still what the plan read. A row the admin changed in the
// meantime matches nothing, so the answer is ErrDomainChanged and the next run plans again from the new row. The table
// holds one row by construction (a CHECK on its key).
const qDomainApplyCommit = `UPDATE ctrlz.domain_settings SET applied_panel_host = $1, applied_admin_host = $2,
  applied_panel_cert_id = $3, applied_admin_cert_id = $4, applied_at = pg_catalog.now()
WHERE dns_zone IS NOT DISTINCT FROM $5 AND panel_host IS NOT DISTINCT FROM $6 AND admin_host IS NOT DISTINCT FROM $7
  AND prev_dns_zone IS NOT DISTINCT FROM $8 AND transition_until IS NOT DISTINCT FROM $9`

// DomainApplyCommit sets the applied_* columns and applied_at.
func (s *Store) DomainApplyCommit(ctx context.Context, in DomainApplyCommitIn) error {
	return s.WithGlobal(ctx, TxOpts{}, func(g GlobalTx) error {
		tag, err := g.tx.Exec(g.ctx, qDomainApplyCommit, emptyNull(in.PanelHost), emptyNull(in.AdminHost), uuidPtrArg(in.PanelCert), uuidPtrArg(in.AdminCert),
			emptyNull(in.Seen.DNSZone), emptyNull(in.Seen.PanelHost), emptyNull(in.Seen.AdminHost), emptyNull(in.Seen.PrevDNSZone), in.Seen.TransitionUntil)
		if err != nil {
			return sanitize(err)
		}
		if tag.RowsAffected() != 1 {
			return ErrDomainChanged
		}
		return nil
	})
}

// uuidPtrArg is NULL for a nil pointer.
func uuidPtrArg(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return *id
}
