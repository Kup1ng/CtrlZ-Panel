package store

import (
	"time"

	"github.com/google/uuid"
)

// The admin's half of the certificates table (p4-nodes 4.3, 9.2). The admin reads every column but the sealed key and
// inserts a row of kind wildcard, panel or admin with source uploaded and state active (a named policy says so in the
// database as well), and moves state only. The sealed key is written and never read back: no method here selects it.

// CertRow is a certificate row as the admin shows it. ChainPEM is filled only by CertsActive, where the choice rule needs it.
type CertRow struct {
	ID        uuid.UUID
	Kind      string
	Source    string
	State     string
	Names     []string
	NotBefore time.Time
	NotAfter  time.Time
	CreatedAt time.Time
	ChainPEM  string
}

const qCertsPage = `SELECT id, kind, source, state, names, not_before, not_after, created_at FROM ctrlz.certificates
WHERE ($1::uuid IS NULL OR id < $1) ORDER BY id DESC LIMIT $2`

// CertsPage lists rows newest first (ids are uuidv7). Rows of the private CAs are listed beside the uploaded ones, so the
// page shows the whole chain of trust; the chain text is not read.
func (g GlobalTx) CertsPage(before uuid.UUID, limit int) ([]CertRow, error) {
	rows, err := g.tx.Query(g.ctx, qCertsPage, nilUUID(before), int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CertRow
	for rows.Next() {
		var c CertRow
		if err := rows.Scan(&c.ID, &c.Kind, &c.Source, &c.State, &c.Names, &c.NotBefore, &c.NotAfter, &c.CreatedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

const qCertsActive = `SELECT id, kind, source, state, names, not_before, not_after, created_at, chain_pem FROM ctrlz.certificates
WHERE kind = $1 AND state = 'active' ORDER BY id DESC LIMIT 200`

// CertsActive reads the active rows of a kind with their chains, for the choice rule. The limit is a ceiling the upload
// route keeps far from (a row ends or is retired by hand), not a page.
func (g GlobalTx) CertsActive(kind string) ([]CertRow, error) {
	rows, err := g.tx.Query(g.ctx, qCertsActive, kind)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CertRow
	for rows.Next() {
		var c CertRow
		if err := rows.Scan(&c.ID, &c.Kind, &c.Source, &c.State, &c.Names, &c.NotBefore, &c.NotAfter, &c.CreatedAt, &c.ChainPEM); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

const qCertInsertUploaded = `INSERT INTO ctrlz.certificates (kind, chain_pem, wrapped_key_ct, not_before, not_after, state, names, source)
VALUES ($1, $2, $3, $4, $5, 'active', $6, 'uploaded') RETURNING id`

// CertInsertUploaded stores an uploaded row, active, with the key sealed to the intake key of its kind. names and the two
// times come from the leaf, as certcheck read them, never from the request.
func (g GlobalTx) CertInsertUploaded(kind, chainPEM string, sealedKey []byte, notBefore, notAfter time.Time, names []string) (uuid.UUID, error) {
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qCertInsertUploaded, kind, chainPEM, sealedKey, notBefore, notAfter, names).Scan(&id)
	return id, sanitize(err)
}

const qCertRetire = `UPDATE ctrlz.certificates SET state = 'retired' WHERE id = $1 AND source = 'uploaded' AND state = 'active'`

// CertRetire moves an active uploaded row to retired. False means there is no such row: unknown, issued by a private CA,
// or already retired, which the route answers alike (not_found).
func (g GlobalTx) CertRetire(id uuid.UUID) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qCertRetire, id)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}
