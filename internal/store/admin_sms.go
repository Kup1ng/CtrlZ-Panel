package store

import (
	"time"

	"github.com/google/uuid"
)

// The SMS side of the admin service (spec 15.2): gateways, routing, templates,
// limits, the outbox and the statistics. All of it runs in WithGlobal as
// ctrlz_admin. The admin writes credentials and never reads them back: the
// credentials_ct column is sealed under sms_cred, and no method here returns it. The
// admin role can read the column, though: see guarded.yaml (sms-r5-5).

// SMSGatewayRow is a gateway as GET /sms/gateways shows it. Configured says
// credentials exist; the credentials themselves are never returned.
type SMSGatewayRow struct {
	ID               uuid.UUID
	Provider         string // sms_ir, melipayamak or noop
	Role             string // primary, fallback or disabled
	Configured       bool
	Hint             string
	CostPerMessage   *string // numeric as text, nil until the owner gives prices
	LastOKAt         *time.Time
	LastErrorAt      *time.Time
	LastErrorCode    string
	BreakerOpenUntil *time.Time
}

const qSMSGateways = `SELECT id, provider, role, credentials_ct IS NOT NULL, COALESCE(hint, ''), cost_per_message::text,
  last_ok_at, last_error_at, COALESCE(last_error_code, ''), breaker_open_until
FROM ctrlz.sms_gateways ORDER BY provider`

// SMSGateways lists the gateways.
func (g GlobalTx) SMSGateways() ([]SMSGatewayRow, error) {
	rows, err := g.tx.Query(g.ctx, qSMSGateways)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []SMSGatewayRow
	for rows.Next() {
		var r SMSGatewayRow
		if err := rows.Scan(&r.ID, &r.Provider, &r.Role, &r.Configured, &r.Hint, &r.CostPerMessage, &r.LastOKAt,
			&r.LastErrorAt, &r.LastErrorCode, &r.BreakerOpenUntil); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qSMSGatewayEnsure = `INSERT INTO ctrlz.sms_gateways (id, provider) VALUES ($1, $2)
ON CONFLICT (provider) DO UPDATE SET provider = EXCLUDED.provider
RETURNING id`

// SMSGatewayEnsure returns the id of the gateway for a provider, creating the
// row with candidate when there is none. The caller generates the id before the
// insert because it is part of the credentials' AAD (8.2): a database default
// is unknown until the row exists.
func (g GlobalTx) SMSGatewayEnsure(candidate uuid.UUID, provider string) (uuid.UUID, error) {
	var id uuid.UUID
	err := g.tx.QueryRow(g.ctx, qSMSGatewayEnsure, candidate, provider).Scan(&id)
	return id, sanitize(err)
}

const qSMSGatewaySetCredentials = `UPDATE ctrlz.sms_gateways SET credentials_ct = $2, hint = $3, consecutive_failures = 0, breaker_open_until = NULL,
  held_ct_sum = NULL, held_code = NULL, unusable_ct_sum = NULL
WHERE id = $1`

// SMSGatewaySetCredentials stores sealed credentials and the plain hint (the
// last four characters of the sms.ir key or of the Melipayamak username, never
// derived from a password). New credentials close the breaker: the old failures
// were about the old ones.
func (g GlobalTx) SMSGatewaySetCredentials(id uuid.UUID, credentialsCT []byte, hint string) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qSMSGatewaySetCredentials, id, credentialsCT, emptyNull(hint))
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qSMSGatewaySetCost = `UPDATE ctrlz.sms_gateways SET cost_per_message = $2::numeric WHERE id = $1`

// SMSGatewaySetCost sets the price of a message in Rial (text, so no float
// rounds it); nil clears it.
func (g GlobalTx) SMSGatewaySetCost(id uuid.UUID, cost *string) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qSMSGatewaySetCost, id, cost)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

const qSMSRoutingClear = `UPDATE ctrlz.sms_gateways SET role = 'disabled'
WHERE provider = ANY ($1::text[]) OR role = ANY ($2::text[])`

// The noop gateway has no credentials to hold (senders.CheckCredentials refuses
// them), so its row existing is what "configured" means for it, as in the
// gateway list. The route refuses noop outside dev and test (15.2), so this
// clause cannot route a production OTP into a file.
const qSMSRoutingAssign = `UPDATE ctrlz.sms_gateways SET role = $2
WHERE provider = $1 AND (credentials_ct IS NOT NULL OR provider = 'noop')`

// SMSRoutingSet assigns primary and fallback in one transaction. sms_gateways_role_uq
// is a partial unique index and cannot be deferred, so a single swapping UPDATE
// would fail row by row: first every gateway named in the request and every
// gateway that holds a role in the request goes to disabled, then the roles are
// assigned. An empty provider leaves that role alone (and unassigned only if the
// other request freed it). It returns false when a named gateway does not exist
// or has no credentials; the caller then rolls the transaction back.
func (g GlobalTx) SMSRoutingSet(primary, fallback string) (bool, error) {
	failed, err := g.SMSRoutingSetNamed(primary, fallback)
	return failed == "", err
}

// SMSRoutingSetNamed is SMSRoutingSet that says which role could not be given:
// "primary" or "fallback", or "" when both were assigned. The caller rolls the
// transaction back on a name, and can then report the right field.
func (g GlobalTx) SMSRoutingSetNamed(primary, fallback string) (string, error) {
	var names, roles []string
	if primary != "" {
		names, roles = append(names, primary), append(roles, "primary")
	}
	if fallback != "" {
		names, roles = append(names, fallback), append(roles, "fallback")
	}
	if len(names) == 0 {
		return "", nil
	}
	if _, err := g.tx.Exec(g.ctx, qSMSRoutingClear, names, roles); err != nil {
		return "", sanitize(err)
	}
	for _, a := range []struct{ provider, role string }{{primary, "primary"}, {fallback, "fallback"}} {
		if a.provider == "" {
			continue
		}
		tag, err := g.tx.Exec(g.ctx, qSMSRoutingAssign, a.provider, a.role)
		if err != nil {
			return "", sanitize(err)
		}
		if tag.RowsAffected() != 1 {
			return a.role, nil
		}
	}
	return "", nil
}

// SMSTemplateRow is a text we ask the provider to approve.
type SMSTemplateRow struct {
	Key    string
	Locale string
	Body   string
}

const qSMSTemplates = `SELECT key, locale, body FROM ctrlz.sms_templates ORDER BY key, locale`

// SMSTemplates lists the templates.
func (g GlobalTx) SMSTemplates() ([]SMSTemplateRow, error) {
	rows, err := g.tx.Query(g.ctx, qSMSTemplates)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []SMSTemplateRow
	for rows.Next() {
		var r SMSTemplateRow
		if err := rows.Scan(&r.Key, &r.Locale, &r.Body); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qSMSTemplateSet = `UPDATE ctrlz.sms_templates SET body = $3 WHERE key = $1 AND locale = $2`

// SMSTemplateSet changes the text of an existing template. The set of keys is
// fixed by the seed; false means there is no such template.
func (g GlobalTx) SMSTemplateSet(key, locale, body string) (bool, error) {
	tag, err := g.tx.Exec(g.ctx, qSMSTemplateSet, key, locale, body)
	if err != nil {
		return false, sanitize(err)
	}
	return tag.RowsAffected() == 1, nil
}

// SMSProviderTemplate maps one of our templates to the provider's approved id.
type SMSProviderTemplate struct {
	GatewayID          uuid.UUID
	Provider           string
	Key                string
	Locale             string
	ProviderTemplateID string
	ParamNames         []string
}

const qSMSProviderTemplates = `SELECT p.gateway_id, g.provider, p.key, p.locale, p.provider_template_id, p.param_names
FROM ctrlz.sms_provider_templates p JOIN ctrlz.sms_gateways g ON g.id = p.gateway_id
ORDER BY p.key, p.locale, g.provider`

// SMSProviderTemplates lists every mapping.
func (g GlobalTx) SMSProviderTemplates() ([]SMSProviderTemplate, error) {
	rows, err := g.tx.Query(g.ctx, qSMSProviderTemplates)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []SMSProviderTemplate
	for rows.Next() {
		var r SMSProviderTemplate
		if err := rows.Scan(&r.GatewayID, &r.Provider, &r.Key, &r.Locale, &r.ProviderTemplateID, &r.ParamNames); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qSMSProviderTemplateSet = `INSERT INTO ctrlz.sms_provider_templates (gateway_id, key, locale, provider_template_id, param_names)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (gateway_id, key, locale) DO UPDATE SET provider_template_id = EXCLUDED.provider_template_id, param_names = EXCLUDED.param_names`

// SMSProviderTemplateSet stores or replaces a mapping.
func (g GlobalTx) SMSProviderTemplateSet(gateway uuid.UUID, key, locale, providerTemplateID string, paramNames []string) error {
	if paramNames == nil {
		paramNames = []string{}
	}
	_, err := g.tx.Exec(g.ctx, qSMSProviderTemplateSet, gateway, key, locale, providerTemplateID, paramNames)
	return sanitize(err)
}

// SMSLimits are the OTP caps and the SMS spending caps (the columns of
// system_settings that 0011 added). CostCapDaily is Rial as text, nil for none.
type SMSLimits struct {
	CapPhone        int
	CapPhoneNet     int
	CapIP           int
	CapNet24        int
	CapPhoneTrusted int
	CapNet48        int
	CapGlobal       int
	CooldownSeconds int
	SoftPercent     int
	CostCapDaily    *string
	OutboxCapDaily  int
}

const qSMSLimitsGet = `SELECT otp_cap_phone, otp_cap_phone_net, otp_cap_ip, otp_cap_net24, otp_cap_phone_trusted, otp_cap_net48,
  otp_cap_global, otp_cooldown_s, otp_soft_pct, sms_cost_cap_daily::text, sms_outbox_cap_daily
FROM ctrlz.system_settings`

// SMSLimitsGet reads the limits.
func (g GlobalTx) SMSLimitsGet() (SMSLimits, error) {
	var l SMSLimits
	err := g.tx.QueryRow(g.ctx, qSMSLimitsGet).Scan(&l.CapPhone, &l.CapPhoneNet, &l.CapIP, &l.CapNet24, &l.CapPhoneTrusted,
		&l.CapNet48, &l.CapGlobal, &l.CooldownSeconds, &l.SoftPercent, &l.CostCapDaily, &l.OutboxCapDaily)
	return l, sanitize(err)
}

const qSMSLimitsLock = qSMSLimitsGet + lockNoKeyUpdate

// SMSLimitsLock reads the limits and locks the settings row until the transaction ends. A writer
// that names what it changed (the limits route) must read the old values this way and not with
// SMSLimitsGet: a read with no lock is the state before another admin's commit, and the audit row
// built from it omits a field that really moved, or names one that did not (admin-r11-1). It takes
// the same lock as SMSSettingsLock, so the money-cap invariant keeps its order.
func (g GlobalTx) SMSLimitsLock() (SMSLimits, error) {
	var l SMSLimits
	err := g.tx.QueryRow(g.ctx, qSMSLimitsLock).Scan(&l.CapPhone, &l.CapPhoneNet, &l.CapIP, &l.CapNet24, &l.CapPhoneTrusted,
		&l.CapNet48, &l.CapGlobal, &l.CooldownSeconds, &l.SoftPercent, &l.CostCapDaily, &l.OutboxCapDaily)
	return l, sanitize(err)
}

const qSMSLimitsSet = `UPDATE ctrlz.system_settings SET otp_cap_phone = $1, otp_cap_phone_net = $2, otp_cap_ip = $3, otp_cap_net24 = $4,
  otp_cap_phone_trusted = $5, otp_cap_net48 = $6, otp_cap_global = $7, otp_cooldown_s = $8, otp_soft_pct = $9,
  sms_cost_cap_daily = $10::numeric, sms_outbox_cap_daily = $11`

// SMSLimitsSet replaces the limits. The table's CHECKs refuse values out of
// range (ErrConstraint).
func (g GlobalTx) SMSLimitsSet(l SMSLimits) error {
	_, err := g.tx.Exec(g.ctx, qSMSLimitsSet, l.CapPhone, l.CapPhoneNet, l.CapIP, l.CapNet24, l.CapPhoneTrusted, l.CapNet48,
		l.CapGlobal, l.CooldownSeconds, l.SoftPercent, l.CostCapDaily, l.OutboxCapDaily)
	return sanitize(err)
}

const qSMSPriceMissingUnderCap = `SELECT EXISTS (
  SELECT 1 FROM ctrlz.sms_gateways g
  WHERE g.role IN ('primary', 'fallback') AND (g.cost_per_message IS NULL OR g.cost_per_message = 0)
) AND EXISTS (SELECT 1 FROM ctrlz.system_settings s WHERE s.sms_cost_cap_daily IS NOT NULL)`

// SMSPriceMissingUnderCap says whether the daily money cap is set while a gateway the router can
// choose (primary or fallback) has no price. The worker adds a gateway's configured price to the
// day's cost when it accepts a message and adds nothing for an unpriced one, so with such a route
// the cost stays 0 and the cap never refuses (sms-r5-6).
//
// It is the one statement of that invariant, and it takes the settings row lock first
// (SMSSettingsLock), which is why the writers of the cap, of a price and of the routing call this
// and not their own SELECTs: under Read Committed each of them writes one table and would read
// the other's old state, so a cap and an unpriced primary both committed (round 6, admin-r6-3).
// With the lock the second writer waits for the first's commit and reads it. The lock is taken
// here, inside the method, so a caller cannot forget it; a gateway is rank 495 and the settings
// 600, the global order.
func (g GlobalTx) SMSPriceMissingUnderCap() (bool, error) {
	if err := g.SMSSettingsLock(); err != nil {
		return false, err
	}
	var missing bool
	err := g.tx.QueryRow(g.ctx, qSMSPriceMissingUnderCap).Scan(&missing)
	return missing, sanitize(err)
}

// NewOutbox is the input of SMSOutboxInsert.
type NewOutbox struct {
	ID          uuid.UUID // generated by the caller: it is in the AAD of ParamsCT
	Kind        string    // invite or test
	GatewayID   uuid.UUID // the nil uuid lets the router choose
	Phone       string
	TemplateKey string
	Locale      string
	ParamsCT    []byte // sealed under sms_cred, aad = id \0 phone
	CreatedBy   uuid.UUID
}

const qSMSOutboxInsert = `INSERT INTO ctrlz.sms_outbox (id, kind, gateway_id, phone_e164, template_key, locale, params_ct, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// SMSOutboxInsert queues a message. It does not wake the worker: the worker polls its outbox, and
// a NOTIFY inside this transaction would fail the commit, and the audit row with it, whenever the
// cluster's notification queue is full, which any login role can cause (db-r15-6; see the note in
// store.go).
func (g GlobalTx) SMSOutboxInsert(o NewOutbox) error {
	_, err := g.tx.Exec(g.ctx, qSMSOutboxInsert, o.ID, o.Kind, nilUUID(o.GatewayID), o.Phone, o.TemplateKey, o.Locale,
		o.ParamsCT, nilUUID(o.CreatedBy))
	return sanitize(err)
}

// SMSOutboxStatus is GET /sms/outbox/{id}: the state, never the phone or the
// parameters.
type SMSOutboxStatus struct {
	State     string
	LastError string
}

const qSMSOutboxStatus = `SELECT state, COALESCE(last_error, '') FROM ctrlz.sms_outbox WHERE id = $1`

// SMSOutboxStatus reads the state of one outbox row.
func (g GlobalTx) SMSOutboxStatus(id uuid.UUID) (SMSOutboxStatus, bool, error) {
	var s SMSOutboxStatus
	err := g.tx.QueryRow(g.ctx, qSMSOutboxStatus, id).Scan(&s.State, &s.LastError)
	ok, err := notFound(err)
	return s, ok, err
}

// SMSDay is one day of GET /sms/stats.
type SMSDay struct {
	Day         time.Time
	OTPCount    int
	OutboxCount int
	Cost        string
}

// SMSGatewayStat counts the attempts a gateway made in the window.
type SMSGatewayStat struct {
	Provider string
	Accepted int
	Failed   int
}

// The admin role has no grant on sms_counters: its phone, phone_net and ip rows are
// keyed by raw numbers and source networks, decoys included, and spec 9.5 keeps them
// from becoming a history of who was asked about. The function returns the global
// rows only (db-r4-4, db-r4-9).
const qSMSStatsDays = `SELECT day, sent, outbox, cost FROM ctrlz_fn.admin_sms_stats($1)`
const qSMSStatsGateways = `SELECT d.provider, count(*) FILTER (WHERE d.outcome = 'accepted')::int, count(*) FILTER (WHERE d.outcome <> 'accepted')::int
FROM ctrlz.sms_deliveries d
WHERE d.created_at > now() - make_interval(days => $1::int)
GROUP BY d.provider ORDER BY d.provider`

// SMSStats reads the daily counters and the per-gateway outcomes for the last
// days days. The delivery log has no phone number or text, so this holds none.
func (g GlobalTx) SMSStats(days int) ([]SMSDay, []SMSGatewayStat, error) {
	rows, err := g.tx.Query(g.ctx, qSMSStatsDays, int32(days))
	if err != nil {
		return nil, nil, sanitize(err)
	}
	var ds []SMSDay
	for rows.Next() {
		var d SMSDay
		if err := rows.Scan(&d.Day, &d.OTPCount, &d.OutboxCount, &d.Cost); err != nil {
			rows.Close()
			return nil, nil, sanitize(err)
		}
		ds = append(ds, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, sanitize(err)
	}
	grows, err := g.tx.Query(g.ctx, qSMSStatsGateways, int32(days))
	if err != nil {
		return nil, nil, sanitize(err)
	}
	defer grows.Close()
	var gs []SMSGatewayStat
	for grows.Next() {
		var s SMSGatewayStat
		if err := grows.Scan(&s.Provider, &s.Accepted, &s.Failed); err != nil {
			return nil, nil, sanitize(err)
		}
		gs = append(gs, s)
	}
	return ds, gs, sanitize(grows.Err())
}
