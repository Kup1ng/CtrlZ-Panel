package store

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Store methods the admin routes and the ctrlz-admin CLI need beyond the ones of
// work package A1. They run in WithGlobal as ctrlz_admin.

const qGlobalCreateUser = `SELECT tenant_id, user_id FROM ctrlz_fn.admin_create_user($1, $2, $3)`

// CreateUser is AdminFns.CreateUser inside the caller's global transaction. POST
// /users uses it so the user.create audit row commits with the user (13.1: a
// change without its audit row cannot commit). ok is false for a taken phone.
func (g GlobalTx) CreateUser(phone string, oneTimeHash secret.String, locale string) (Registered, bool, error) {
	var v Registered
	err := g.tx.QueryRow(g.ctx, qGlobalCreateUser, phone, oneTimeHash.Reveal(), emptyNull(locale)).Scan(&v.TenantID, &v.UserID)
	ok, err := notFound(err)
	return v, ok, err
}

const qPanelHost = `SELECT COALESCE(panel_host, '') FROM ctrlz.domain_settings`

// PanelHost is domain_settings.panel_host, empty while nothing has set it (it is
// NULL after install and P4 writes it). The effective panel host of 7.2 is this
// value, else CTRLZ_PANEL_HOST.
func (g GlobalTx) PanelHost() (string, error) {
	var h string
	err := g.tx.QueryRow(g.ctx, qPanelHost).Scan(&h)
	if ok, err := notFound(err); err != nil || !ok {
		return "", err
	}
	return h, nil
}

const qAlertsPageAfter = `SELECT id, severity, kind, params, created_at, resolved_at FROM ctrlz.alerts
WHERE NOT $1::boolean
   OR ((resolved_at IS NOT NULL) > $2::boolean)
   OR ((resolved_at IS NOT NULL) = $2::boolean AND id < $3::uuid)
ORDER BY (resolved_at IS NOT NULL), id DESC LIMIT $4`

// AlertsPageAfter is AlertsPage with a keyset cursor that follows the sort
// order: open alerts first, then resolved ones, each newest id first. A cursor is
// the last row's (resolved, id); paging by id alone would skip or repeat rows at
// the boundary between the two groups. hasCursor false returns the first page.
func (g GlobalTx) AlertsPageAfter(hasCursor, resolved bool, id uuid.UUID, limit int) ([]AlertRow, error) {
	rows, err := g.tx.Query(g.ctx, qAlertsPageAfter, hasCursor, resolved, id, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []AlertRow
	for rows.Next() {
		var r AlertRow
		if err := rows.Scan(&r.ID, &r.Severity, &r.Kind, &r.Params, &r.CreatedAt, &r.ResolvedAt); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

// ---------------------------------------------------------------------------
// Key rotation of the admin's own domains (8.4): admin_totp and sms_cred. The
// user_totp domain is the rekey tool's (worker.go TOTPSecrets).

// SealedAdminTOTP is an admin's sealed TOTP seed, for rekey and keys status.
type SealedAdminTOTP struct {
	Admin uuid.UUID
	CT    []byte
}

const qAdminTOTPSecrets = `SELECT id, totp_secret_ct FROM ctrlz.admin_users WHERE totp_secret_ct IS NOT NULL ORDER BY id`

// AdminTOTPSecrets returns every sealed admin TOTP seed.
func (g GlobalTx) AdminTOTPSecrets() ([]SealedAdminTOTP, error) {
	rows, err := g.tx.Query(g.ctx, qAdminTOTPSecrets)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []SealedAdminTOTP
	for rows.Next() {
		var s SealedAdminTOTP
		if err := rows.Scan(&s.Admin, &s.CT); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

const qAdminTOTPReplace = `SELECT ctrlz_fn.admin_totp_replace($1, $2, $3)`

// AdminTOTPReplace swaps a sealed seed for its re-encryption. The old value is
// compared, so a seed the admin changed in the meantime is not overwritten. It is a
// definer function and not an UPDATE of the admin role: only a re-seal made by ctrlz_auth
// leaves the credential generation alone, and a plain write of a live seed by the role
// moves it (db-r7-4).
func (g GlobalTx) AdminTOTPReplace(admin uuid.UUID, old, replacement []byte) (bool, error) {
	var ok bool
	if err := g.tx.QueryRow(g.ctx, qAdminTOTPReplace, admin, old, replacement).Scan(&ok); err != nil {
		return false, sanitize(err)
	}
	return ok, nil
}

// SealedGatewayCredentials is a gateway's sealed credentials, for rekey.
type SealedGatewayCredentials struct {
	ID       uuid.UUID
	Provider string
	CT       []byte
	// Pending marks the credentials a PUT saved that the owner has not confirmed yet
	// (credentials_pending_ct). They are sealed like the active ones, so a rekey re-seals them and a
	// lost key strands them the same way.
	Pending bool
}

const qSMSCredentialsSealed = `SELECT id, provider, credentials_ct, false FROM ctrlz.sms_gateways WHERE credentials_ct IS NOT NULL
UNION ALL
SELECT id, provider, credentials_pending_ct, true FROM ctrlz.sms_gateways WHERE credentials_pending_ct IS NOT NULL
ORDER BY 2, 4`

// SMSCredentialsSealed returns the sealed credentials of every gateway that has
// some, the active ones and the pending ones as rows of their own (Pending). Only the rekey command and `keys status` call it: no route does, so the
// admin API never holds a credential, even sealed, though the role can read the column (guarded.yaml).
func (g GlobalTx) SMSCredentialsSealed() ([]SealedGatewayCredentials, error) {
	rows, err := g.tx.Query(g.ctx, qSMSCredentialsSealed)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []SealedGatewayCredentials
	for rows.Next() {
		var s SealedGatewayCredentials
		if err := rows.Scan(&s.ID, &s.Provider, &s.CT, &s.Pending); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

// A rekey re-seals the same credentials, so a hold of a refused login (held_ct_sum, the digest of
// the ciphertext the refusal was made for) moves with them in the same statement (sms-r13-4). Left
// alone, the digest of the new ciphertext matched nothing, the hold stopped counting, and the
// refused key was asked again by the traffic of users, the run of failed logins the hold exists to
// avoid. Only a hold that named the old ciphertext moves; a hold for anything else is not this
// statement's to touch. The worker's judgement that no sender can be built (unusable_ct_sum,
// sms-r15-1) is keyed on the same digest and moves the same way: a statement that rewrites
// credentials_ct owes every state keyed on its digest that.
const qSMSCredentialsReplace = `UPDATE ctrlz.sms_gateways SET credentials_ct = $3,
  held_ct_sum = CASE WHEN held_ct_sum = sha256($2::bytea) THEN sha256($3::bytea) ELSE held_ct_sum END,
  unusable_ct_sum = CASE WHEN unusable_ct_sum = sha256($2::bytea) THEN sha256($3::bytea) ELSE unusable_ct_sum END
WHERE id = $1 AND credentials_ct = $2`

// SMSCredentialsReplace swaps sealed credentials for their re-encryption, with
// the same compare-first rule as AdminTOTPReplace, and carries a hold over to them.
func (g GlobalTx) SMSCredentialsReplace(id uuid.UUID, old, replacement []byte) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qSMSCredentialsReplace, id, old, replacement)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// qSMSPendingCredentialsReplace is the rekey of credentials_pending_ct: the same compare-first
// rule, and nothing is keyed on the digest of a pending value (no hold, no judgement), so there is
// nothing to carry over.
const qSMSPendingCredentialsReplace = `UPDATE ctrlz.sms_gateways SET credentials_pending_ct = $3 WHERE id = $1 AND credentials_pending_ct = $2`

// SMSPendingCredentialsReplace swaps pending sealed credentials for their re-encryption.
func (g GlobalTx) SMSPendingCredentialsReplace(id uuid.UUID, old, replacement []byte) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qSMSPendingCredentialsReplace, id, old, replacement)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qSMSGatewayByProvider = `SELECT id, credentials_ct IS NOT NULL FROM ctrlz.sms_gateways WHERE provider = $1`

// SMSGatewayByProvider finds a gateway row; false when the provider has none.
func (g GlobalTx) SMSGatewayByProvider(provider string) (id uuid.UUID, configured, ok bool, err error) {
	err = g.tx.QueryRow(g.ctx, qSMSGatewayByProvider, provider).Scan(&id, &configured)
	if err == pgx.ErrNoRows {
		return uuid.Nil, false, false, nil
	}
	if err != nil {
		return uuid.Nil, false, false, sanitize(err)
	}
	return id, configured, true, nil
}
