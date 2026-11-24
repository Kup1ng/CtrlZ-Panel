-- P1: what login, sessions, OTP, TOTP, Passkey, SMS and the minimum admin need
-- from the database. A new file and not an edit of 0006 to 0010, because a
-- migration that has been applied anywhere is never edited (README, Rules).
-- Spec: docs/specs/p1-auth.md section 16.
--
--  1. Six global tables: short-lived login tickets, attempt limits that survive
--     a Valkey outage, admin jobs, the SMS outbox, the delivery log (no phone
--     number and no text, by design) and the provider template map.
--  2. New columns for sessions (restricted, reauth, method, address), users
--     (password expiry, pending TOTP, the Enforce delay, passkey review),
--     passkeys (the backup flags go-webauthn keeps), OTP rows (delivery claim,
--     known device), gateways, system settings (the OTP caps move out of the
--     functions), admin users and sessions, and the admin audit log.
--  3. Grants. The tenant loses UPDATE on phone_change_requests, because only
--     auth_phone_change_complete finishes a request. The worker gets the
--     column reach its sweeps filter on (a DELETE that filters on a column
--     needs SELECT on it).
--  4. Functions, as ctrlz_auth: public config, the OTP issue with decoy mode,
--     a soft breaker and a key for a known device, tickets, attempt limits for
--     users and for admins (two pairs, so a compromised api cannot reset an
--     admin key), the phone change, the phone verification, user flags,
--     admin_create_user. Three functions change their result row and are
--     dropped and created again.
--  5. The five SMS templates in both languages.
--
-- T-536 (D46, spec 10.7) adds three lines: ctrlz_admin may update
-- password_expires_at, may read the columns of refresh_tokens its revoke
-- filters on, and may call auth_tickets_revoke. The CHECK users_one_time_password
-- lets the admin tell a one-time password from a user's own without reading the
-- hash.

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- Tables, as the owner. ------------------------------------------------------------------

-- Short-lived state of a login step. Reached only through ctrlz_fn. The subject
-- columns are values: a ticket exists before a session, and global tables
-- reference no tenant row. They are not named tenant_id, so catalog test 4
-- needs no exception.
CREATE TABLE ctrlz.auth_tickets (
  id             uuid PRIMARY KEY DEFAULT uuidv7(),
  token_hash     bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  kind           text NOT NULL CHECK (kind IN ('mfa', 'reset', 'passkey_login', 'passkey_register', 'passkey_reauth')),
  subject_tenant uuid,
  subject_user   uuid,
  remember_me    boolean NOT NULL DEFAULT false,
  first_factor   text CHECK (first_factor IN ('password', 'otp')),
  payload        bytea CHECK (octet_length(payload) <= 4096),
  attempts       integer NOT NULL DEFAULT 0,
  expires_at     timestamptz NOT NULL,
  consumed_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX auth_tickets_expires_idx ON ctrlz.auth_tickets (expires_at);
CREATE INDEX auth_tickets_subject_idx ON ctrlz.auth_tickets (subject_user) WHERE consumed_at IS NULL;

-- Attempt limits that survive a Valkey outage (R44). key is an HMAC, so the
-- table holds no phone number.
CREATE TABLE ctrlz.auth_throttle (
  scope        text NOT NULL CHECK (scope IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user',
                  'reauth_user', 'otp_verify_net', 'invite_net', 'admin_login', 'admin_login_user', 'admin_login_net',
                  'admin_totp')),
  key          bytea NOT NULL CHECK (octet_length(key) = 32),
  window_start timestamptz NOT NULL,
  count        integer NOT NULL,
  PRIMARY KEY (scope, key)
);
CREATE INDEX auth_throttle_window_idx ON ctrlz.auth_throttle (window_start);

-- Admin-initiated work that spans tenants. job_outbox needs a tenant.
CREATE TABLE ctrlz.admin_jobs (
  id          uuid PRIMARY KEY DEFAULT uuidv7(),
  kind        text NOT NULL CHECK (kind IN ('registration_transition', 'webauthn_rp_change')),
  params      jsonb NOT NULL DEFAULT '{}',
  state       text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
  progress    jsonb NOT NULL DEFAULT '{}',
  created_by  uuid REFERENCES ctrlz.admin_users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  started_at  timestamptz,
  finished_at timestamptz
);
CREATE UNIQUE INDEX admin_jobs_one_active_uq ON ctrlz.admin_jobs (kind) WHERE state IN ('queued', 'running');

-- SMS that is not an OTP. params_ct is sealed under domain sms_cred.
CREATE TABLE ctrlz.sms_outbox (
  id             uuid PRIMARY KEY DEFAULT uuidv7(),
  kind           text NOT NULL CHECK (kind IN ('invite', 'test')),
  gateway_id     uuid REFERENCES ctrlz.sms_gateways (id) ON DELETE CASCADE,
  phone_e164     text NOT NULL CHECK (phone_e164 ~ '^\+[1-9][0-9]{7,14}$'),
  template_key   text NOT NULL,
  locale         text NOT NULL CHECK (locale IN ('fa', 'en')),
  params_ct      bytea,
  state          text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sent', 'failed')),
  attempts       integer NOT NULL DEFAULT 0,
  claimed_until  timestamptz,
  last_error     text,
  created_by     uuid REFERENCES ctrlz.admin_users (id) ON DELETE SET NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  sent_at        timestamptz
);
CREATE INDEX sms_outbox_pending_idx ON ctrlz.sms_outbox (created_at) WHERE state = 'pending';

-- One row per provider attempt. No phone number and no text, by design.
CREATE TABLE ctrlz.sms_deliveries (
  id               uuid PRIMARY KEY DEFAULT uuidv7(),
  source           text NOT NULL CHECK (source IN ('otp', 'outbox')),
  source_id        uuid NOT NULL,
  gateway_id       uuid REFERENCES ctrlz.sms_gateways (id) ON DELETE SET NULL,
  provider         text NOT NULL,
  template_key     text NOT NULL,
  outcome          text NOT NULL CHECK (outcome IN ('accepted', 'rejected', 'unreachable')),
  provider_status  text,
  provider_msg_id  text,
  cost_raw         text,
  latency_ms       integer,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sms_deliveries_created_idx ON ctrlz.sms_deliveries (created_at);

-- A provider stores the approved copy. This maps our template to its id.
CREATE TABLE ctrlz.sms_provider_templates (
  gateway_id           uuid NOT NULL REFERENCES ctrlz.sms_gateways (id) ON DELETE CASCADE,
  key                  text NOT NULL,
  locale               text NOT NULL CHECK (locale IN ('fa', 'en')),
  provider_template_id text NOT NULL,
  param_names          text[] NOT NULL DEFAULT '{}',
  updated_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (gateway_id, key, locale)
);
{{touch "ctrlz.sms_provider_templates"}}

ALTER TABLE ctrlz.sessions
  ADD COLUMN restricted  boolean NOT NULL DEFAULT false,
  ADD COLUMN reauth_at   timestamptz,
  ADD COLUMN auth_method text NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'otp', 'passkey')),
  ADD COLUMN ip          inet,
  ADD COLUMN user_agent  text CHECK (char_length(user_agent) <= 256);

ALTER TABLE ctrlz.users
  ADD COLUMN password_changed_at timestamptz,
  ADD COLUMN password_expires_at timestamptz,
  ADD COLUMN totp_pending_at     timestamptz,
  ADD COLUMN enforce_lift_at     timestamptz,
  ADD COLUMN passkey_review_at   timestamptz,
  ALTER COLUMN onboarding_hints SET DEFAULT '{"enabled": true}',
  -- An expiry marks an admin-issued one-time password (10.6, 10.7). ctrlz_admin
  -- cannot read password_hash, so the re-issue relies on this to know a hash
  -- exists and the user has not set their own.
  ADD CONSTRAINT users_one_time_password
    CHECK (password_expires_at IS NULL OR (must_reset AND password_hash IS NOT NULL));

ALTER TABLE ctrlz.webauthn_credentials
  ADD COLUMN aaguid           uuid,
  ADD COLUMN attestation_type text NOT NULL DEFAULT 'none',
  ADD COLUMN backup_eligible  boolean NOT NULL DEFAULT false,
  ADD COLUMN backup_state     boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT webauthn_credentials_name_len CHECK (char_length(name) <= 64);

ALTER TABLE ctrlz.phone_change_requests
  ADD CONSTRAINT phone_change_requests_lifetime CHECK (expires_at <= created_at + interval '15 minutes');

ALTER TABLE ctrlz.otp_challenges
  ADD COLUMN delivery_claimed_until timestamptz,
  ADD COLUMN delivery_attempts      integer NOT NULL DEFAULT 0,
  ADD COLUMN trusted                boolean NOT NULL DEFAULT false;
CREATE INDEX otp_challenges_delivery_idx ON ctrlz.otp_challenges (created_at) WHERE delivery_ct IS NOT NULL;
CREATE INDEX otp_challenges_cooldown_idx ON ctrlz.otp_challenges (phone_e164, purpose, created_at);
CREATE INDEX otp_challenges_expires_idx ON ctrlz.otp_challenges (expires_at);

ALTER TABLE ctrlz.invites ADD COLUMN locale text NOT NULL DEFAULT 'fa' CHECK (locale IN ('fa', 'en'));

ALTER TABLE ctrlz.sms_gateways
  ADD COLUMN cost_per_message     numeric(14, 4),
  ADD COLUMN hint                 text CHECK (char_length(hint) <= 8),
  ADD COLUMN last_ok_at           timestamptz,
  ADD COLUMN last_error_at        timestamptz,
  ADD COLUMN last_error_code      text,
  ADD COLUMN consecutive_failures integer NOT NULL DEFAULT 0,
  ADD COLUMN breaker_open_until   timestamptz;
CREATE UNIQUE INDEX sms_gateways_provider_uq ON ctrlz.sms_gateways (provider);

-- The OTP caps and the cooldown were constants of the function. The defaults
-- keep the numbers of 0010 (D31); the admin changes them from the SMS page.
ALTER TABLE ctrlz.system_settings
  ADD COLUMN otp_cap_phone      integer NOT NULL DEFAULT 5    CHECK (otp_cap_phone >= 1),
  ADD COLUMN otp_cap_phone_net  integer NOT NULL DEFAULT 3    CHECK (otp_cap_phone_net >= 1),
  ADD COLUMN otp_cap_ip         integer NOT NULL DEFAULT 20   CHECK (otp_cap_ip >= 1),
  ADD COLUMN otp_cap_net24      integer NOT NULL DEFAULT 100  CHECK (otp_cap_net24 >= 1),
  ADD COLUMN otp_cap_phone_trusted integer NOT NULL DEFAULT 5 CHECK (otp_cap_phone_trusted >= 1),
  ADD COLUMN otp_cap_net48      integer NOT NULL DEFAULT 100  CHECK (otp_cap_net48 >= 1),
  ADD COLUMN otp_cap_global     integer NOT NULL DEFAULT 5000 CHECK (otp_cap_global >= 1),
  ADD COLUMN otp_cooldown_s     integer NOT NULL DEFAULT 60   CHECK (otp_cooldown_s BETWEEN 10 AND 3600),
  ADD COLUMN otp_soft_pct       integer NOT NULL DEFAULT 80   CHECK (otp_soft_pct BETWEEN 1 AND 100),
  ADD COLUMN sms_cost_cap_daily numeric(14, 4) CHECK (sms_cost_cap_daily >= 0),
  ADD COLUMN sms_outbox_cap_daily integer NOT NULL DEFAULT 200 CHECK (sms_outbox_cap_daily >= 0);

ALTER TABLE ctrlz.admin_users
  ADD COLUMN totp_enabled_at     timestamptz,
  ADD COLUMN password_changed_at timestamptz,
  ADD COLUMN password_expires_at timestamptz,
  ADD COLUMN last_login_at       timestamptz,
  ADD COLUMN pending_notice      jsonb;

ALTER TABLE ctrlz.admin_sessions
  ADD COLUMN ip         inet,
  ADD COLUMN user_agent text CHECK (char_length(user_agent) <= 256);

ALTER TABLE ctrlz.audit_log ADD COLUMN ip inet;

-- One open alert per (kind, key). A worker that fails the same way every
-- second must not write an alert a second, and it may not read alerts to find
-- out (it holds INSERT only), so ON CONFLICT DO NOTHING on this index is how
-- it writes "once". An operator's ack closes the alert and the next failure
-- opens a new one. Alerts without a key (the hub's and the compiler's) are
-- outside the index.
CREATE UNIQUE INDEX alerts_open_key_uq ON ctrlz.alerts (kind, (params ->> 'key'))
  WHERE resolved_at IS NULL AND (params ->> 'key') IS NOT NULL;

-- Policies, as the owner. ----------------------------------------------------------------

-- Passkey impact counts on the RP ID page (Plan: shows the affected count).
CREATE POLICY admin_read ON ctrlz.webauthn_credentials FOR SELECT TO ctrlz_admin USING (true);

-- Grants, as the table owner. ------------------------------------------------------------

-- auth_tickets and auth_throttle: only through ctrlz_fn, plus the sweep.
GRANT SELECT, INSERT, UPDATE ON ctrlz.auth_tickets  TO ctrlz_auth;
GRANT SELECT, INSERT, UPDATE ON ctrlz.auth_throttle TO ctrlz_auth;
GRANT SELECT (id, expires_at), DELETE ON ctrlz.auth_tickets  TO ctrlz_worker;
GRANT SELECT (scope, key, window_start), DELETE ON ctrlz.auth_throttle TO ctrlz_worker;

GRANT SELECT, INSERT ON ctrlz.admin_jobs TO ctrlz_admin;
GRANT SELECT, UPDATE (state, progress, started_at, finished_at) ON ctrlz.admin_jobs TO ctrlz_worker;

GRANT INSERT ON ctrlz.sms_outbox TO ctrlz_admin;
GRANT SELECT (id, kind, gateway_id, state, attempts, last_error, created_by, created_at, sent_at) ON ctrlz.sms_outbox TO ctrlz_admin;
GRANT SELECT, UPDATE (state, attempts, claimed_until, last_error, sent_at, params_ct), DELETE ON ctrlz.sms_outbox TO ctrlz_worker;

GRANT SELECT ON ctrlz.sms_deliveries TO ctrlz_admin;
GRANT SELECT, INSERT, DELETE ON ctrlz.sms_deliveries TO ctrlz_worker;

GRANT SELECT, INSERT, UPDATE, DELETE ON ctrlz.sms_provider_templates TO ctrlz_admin;
GRANT SELECT ON ctrlz.sms_provider_templates TO ctrlz_worker;

-- Only auth_phone_change_complete finishes a request (T-110).
REVOKE UPDATE ON ctrlz.phone_change_requests FROM ctrlz_tenant;
GRANT SELECT (tenant_id, id, user_id, new_phone_e164, old_otp_id, new_otp_id, expires_at, completed_at, created_at)
  ON ctrlz.phone_change_requests TO ctrlz_auth;
GRANT UPDATE (completed_at) ON ctrlz.phone_change_requests TO ctrlz_auth;

-- auth_phone_change_complete and auth_phone_mark_verified. tenant_isolation
-- keeps these to the caller's tenant, because the setting stays the caller's.
-- password_changed_at: auth_user_by_phone returns it and a login compares it under
-- the row lock, so a login that verified a password the user has since replaced
-- is refused (spec 5.7).
GRANT SELECT (phone_verified_at, password_expires_at, enforce_lift_at, password_changed_at) ON ctrlz.users TO ctrlz_auth;
GRANT UPDATE (phone_e164, phone_verified_at) ON ctrlz.users TO ctrlz_auth;

-- users is granted to these two as S(-password_hash-totp_secret_ct), which is
-- fixed when it runs, so a new column is unreadable until granted (README, Rules).
GRANT SELECT (password_changed_at, password_expires_at, totp_pending_at, enforce_lift_at, passkey_review_at)
  ON ctrlz.users TO ctrlz_tenant, ctrlz_admin;
GRANT UPDATE (password_changed_at, password_expires_at, totp_pending_at, enforce_lift_at, passkey_review_at)
  ON ctrlz.users TO ctrlz_tenant;
-- ctrlz-admin keys declare-lost user_totp clears totp_last_step too. 0007 gives
-- admin U on the other TOTP columns but not on this. The re-issue of a one-time
-- password (T-536, 10.7) moves password_expires_at.
GRANT UPDATE (totp_last_step, password_expires_at) ON ctrlz.users TO ctrlz_admin;
-- Credential events write their notice in the transaction that changes the
-- credential. RLS keeps the row in the caller's tenant.
GRANT INSERT (tenant_id, kind, severity, params) ON ctrlz.notifications TO ctrlz_tenant;
GRANT UPDATE (backup_state) ON ctrlz.webauthn_credentials TO ctrlz_tenant;

-- auth_session_by_hash, auth_passkey_by_credential.
GRANT SELECT (restricted, reauth_at) ON ctrlz.sessions TO ctrlz_auth;
GRANT SELECT (transports, aaguid, backup_eligible, backup_state) ON ctrlz.webauthn_credentials TO ctrlz_auth;

-- auth_public_config.
GRANT SELECT (panel_host) ON ctrlz.domain_settings TO ctrlz_auth;
GRANT SELECT (rp_id, allowed_origins, enabled) ON ctrlz.webauthn_config TO ctrlz_auth;
GRANT SELECT (provider, role, breaker_open_until) ON ctrlz.sms_gateways TO ctrlz_auth;

-- Admin counts for the RP ID page.
GRANT SELECT (tenant_id, id, user_id, rp_id, stale_at) ON ctrlz.webauthn_credentials TO ctrlz_admin;

-- The re-issue of a one-time password revokes the user's refresh tokens, and an
-- UPDATE that filters on a column needs SELECT on it. Only the key columns.
GRANT SELECT (tenant_id, id, user_id, revoked_at) ON ctrlz.refresh_tokens TO ctrlz_admin;

-- Worker: the RP ID job, key rotation, SMS bookkeeping.
GRANT SELECT (tenant_id, id, user_id, rp_id, stale_at), UPDATE (stale_at) ON ctrlz.webauthn_credentials TO ctrlz_worker;
GRANT SELECT (totp_secret_ct), UPDATE (totp_secret_ct) ON ctrlz.users TO ctrlz_worker;
-- The RP ID job filters on it. U alone refused the statement on a live run.
GRANT SELECT (enforce_passkey) ON ctrlz.users TO ctrlz_worker;
-- ip and trusted build the refund keys of section 9.5.
GRANT SELECT (expires_at, created_at, delivery_claimed_until, delivery_attempts, consumed_at, ip, trusted),
      UPDATE (delivery_claimed_until, delivery_attempts) ON ctrlz.otp_challenges TO ctrlz_worker;
-- The pending TOTP sweep of section 9.5.
GRANT SELECT (totp_enabled_at, totp_pending_at), UPDATE (totp_pending_at) ON ctrlz.users TO ctrlz_worker;
GRANT UPDATE (last_ok_at, last_error_at, last_error_code, consecutive_failures, breaker_open_until)
  ON ctrlz.sms_gateways TO ctrlz_worker;

-- A DELETE that filters on a column needs SELECT on it (finding 4). Only the
-- key and expiry columns, never a token hash.
GRANT SELECT (tenant_id, id, absolute_expires_at, revoked_at) ON ctrlz.sessions TO ctrlz_worker;
GRANT SELECT (tenant_id, id, expires_at) ON ctrlz.refresh_tokens TO ctrlz_worker;
GRANT SELECT (tenant_id, id, expires_at, completed_at) ON ctrlz.phone_change_requests TO ctrlz_worker;
GRANT SELECT (id, expires_at, used_at) ON ctrlz.invites TO ctrlz_worker;
GRANT SELECT (tenant_id, id, at) ON ctrlz.tenant_audit_log TO ctrlz_worker;

-- Functions, as ctrlz_auth. --------------------------------------------------------------

SET ROLE ctrlz_auth;

GRANT USAGE ON SCHEMA ctrlz_fn TO ctrlz_admin;

-- Three functions change their result row, which CREATE OR REPLACE refuses. A
-- dropped function loses its grants, so each is granted again after it is made.
DROP FUNCTION ctrlz_fn.auth_session_by_hash(bytea);
DROP FUNCTION ctrlz_fn.auth_passkey_by_credential(bytea);
DROP FUNCTION ctrlz_fn.auth_user_by_phone(text);
DROP FUNCTION ctrlz_fn.auth_otp_issue(text, text, bytea, bytea, inet);

-- New columns come last, so the Go structs keep their scan order.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_session_by_hash(p_hash bytea)
RETURNS TABLE (tenant_id uuid, user_id uuid, session_id uuid, status text,
               idle_expires_at timestamptz, absolute_expires_at timestamptz, revoked_at timestamptz,
               restricted boolean, reauth_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.tenant_id, s.user_id, s.id, t.status,
         s.idle_expires_at, s.absolute_expires_at, s.revoked_at,
         s.restricted, s.reauth_at
  FROM ctrlz.sessions s
  JOIN ctrlz.tenants t ON t.id = s.tenant_id
  WHERE s.token_hash = p_hash
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_session_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_session_by_hash(bytea) TO ctrlz_tenant;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_passkey_by_credential(p_credential_id bytea)
RETURNS TABLE (tenant_id uuid, user_id uuid, id uuid, public_key bytea,
               sign_count bigint, rp_id text, stale_at timestamptz,
               transports text[], aaguid uuid, backup_eligible boolean, backup_state boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT w.tenant_id, w.user_id, w.id, w.public_key, w.sign_count, w.rp_id, w.stale_at,
         w.transports, w.aaguid, w.backup_eligible, w.backup_state
  FROM ctrlz.webauthn_credentials w
  WHERE w.credential_id = p_credential_id
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_passkey_by_credential(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_passkey_by_credential(bytea) TO ctrlz_tenant;

-- Login. One row per phone; the phone is globally unique.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_user_by_phone(p_phone text)
RETURNS TABLE (tenant_id uuid, user_id uuid, password_hash text, status text,
               totp_enabled boolean, enforce_passkey boolean, must_reset boolean,
               enforce_lift_at timestamptz, password_expires_at timestamptz,
               password_changed_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT u.tenant_id, u.id, u.password_hash, t.status,
         (u.totp_enabled_at IS NOT NULL), u.enforce_passkey, u.must_reset,
         u.enforce_lift_at, u.password_expires_at, u.password_changed_at
  FROM ctrlz.users u
  JOIN ctrlz.tenants t ON t.id = u.tenant_id
  WHERE u.phone_e164 = p_phone
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_user_by_phone(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_user_by_phone(text) TO ctrlz_tenant;

-- What the login page needs before a tenant is known: ctrlz_tenant has no
-- grant on system_settings, and WithGlobal refuses that role. One row, global,
-- no user data.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_public_config()
RETURNS TABLE (registration_mode text, panel_host text, rp_id text, allowed_origins text[],
               passkey_enabled boolean, sms_available boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.registration_mode, d.panel_host, w.rp_id, w.allowed_origins,
         w.enabled AND w.rp_id IS NOT NULL,
         EXISTS (SELECT 1 FROM ctrlz.sms_gateways g
                 WHERE g.role IN ('primary', 'fallback')
                   AND (g.breaker_open_until IS NULL OR g.breaker_open_until < pg_catalog.now()))
  FROM ctrlz.system_settings s, ctrlz.domain_settings d, ctrlz.webauthn_config w
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_public_config() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_public_config() TO ctrlz_tenant;

-- Whether the user has a password, without loading the hash. /me is the most
-- frequent route, and ctrlz_tenant cannot select the column.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_user_flags(p_user_id uuid)
RETURNS TABLE (has_password boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT (u.password_hash IS NOT NULL)
  FROM ctrlz.users u
  WHERE u.tenant_id = ctrlz.current_tenant_id() AND u.id = p_user_id
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_user_flags(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_user_flags(uuid) TO ctrlz_tenant;

-- Issue an OTP challenge. As in 0010 (caps on messages sent, bumped in one
-- subtransaction so a refusal leaves every counter as it was, the cooldown
-- checked after the counters so the row lock of the global counter
-- serialises overlapping sends, and the phone's own row a decoy for that phone), plus:
--
--  * The caps and the cooldown come from system_settings. The defaults are the
--    numbers of 0010.
--  * A decoy (no delivery_ct, an unknown phone) makes a real row, so the
--    response is the same, and it counts on every key but 'global': nothing is
--    sent, so nothing costs. A decoy is also refused where a real request would
--    be refused at the global or money cap, before any counter moves, so a full
--    cap does not tell which phones exist.
--  * A soft breaker: from otp_soft_pct of the global cap on, a request from a
--    device we do not know is refused. A known device (p_trusted) is not, and
--    counts on its own phone key, so a stranger who spends the shared phone
--    caps cannot lock the owner out.
--  * An IPv6 source also counts on its /48, which holds 65,536 /64s.
--  * The row stores trusted, so the worker can give back the same keys when
--    nothing was delivered, and a real challenge wakes the worker.
--
-- The global check below is racy by a few messages, since the counter is bumped
-- later. The bump's own WHERE count < cap is the hard stop.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_otp_issue(p_phone text, p_purpose text, p_code_hash bytea, p_delivery_ct bytea, p_ip inet, p_trusted boolean)
RETURNS TABLE (id uuid, allowed boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_day    date := (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date;
  v_ip     inet := p_ip;
  v_cfg    ctrlz.system_settings%ROWTYPE;
  v_decoy  boolean := p_delivery_ct IS NULL;
  v_trust  boolean := COALESCE(p_trusted, false);
  v_gcount integer;
  v_gcost  numeric;
  v_net    text;
  v_scopes text[];
  v_keys   text[];
  v_caps   integer[];
  v_id     uuid;
  v_n      integer;
  i        integer;
BEGIN
  IF p_phone IS NULL OR p_phone !~ '^\+[1-9][0-9]{7,14}$'
     OR p_purpose IS NULL OR p_purpose NOT IN ('login', 'signup', 'invite', 'reset', 'phone_old', 'phone_new')
     OR p_code_hash IS NULL OR p_ip IS NULL THEN
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END IF;

  -- ::ffff:a.b.c.d and a.b.c.d are one client.
  IF pg_catalog.family(v_ip) = 6 AND v_ip << '::ffff:0:0/96'::inet THEN
    v_ip := '0.0.0.0'::inet + (v_ip - '::ffff:0.0.0.0'::inet);
  END IF;

  SELECT * INTO v_cfg FROM ctrlz.system_settings;
  SELECT c.count, c.cost INTO v_gcount, v_gcost
  FROM ctrlz.sms_counters c WHERE c.day = v_day AND c.scope = 'global' AND c.key = 'all';
  v_gcount := COALESCE(v_gcount, 0);   -- no row yet leaves both NULL
  v_gcost  := COALESCE(v_gcost, 0);

  -- Both real and decoy refuse here, so a full cap reveals no phone.
  IF v_gcount >= v_cfg.otp_cap_global
     OR (v_cfg.sms_cost_cap_daily IS NOT NULL AND v_gcost >= v_cfg.sms_cost_cap_daily)
     OR (NOT v_trust
         AND v_gcount::bigint * 100 >= v_cfg.otp_cap_global::bigint * v_cfg.otp_soft_pct) THEN
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END IF;

  IF pg_catalog.family(v_ip) = 4 THEN
    v_net    := pg_catalog.network(pg_catalog.set_masklen(v_ip, 24))::text;
    v_scopes := ARRAY['ip', 'ip'];
    v_keys   := ARRAY[pg_catalog.host(v_ip), v_net];
    v_caps   := ARRAY[v_cfg.otp_cap_ip, v_cfg.otp_cap_net24];
  ELSE
    -- family 6: the /64 of 0010, plus the /48, which holds 65,536 /64s
    v_net    := pg_catalog.network(pg_catalog.set_masklen(v_ip, 64))::text;
    v_scopes := ARRAY['ip', 'ip'];
    v_keys   := ARRAY[v_net, pg_catalog.network(pg_catalog.set_masklen(v_ip, 48))::text];
    v_caps   := ARRAY[v_cfg.otp_cap_ip, v_cfg.otp_cap_net48];
  END IF;

  -- A known device leaves the shared keys alone, so a stranger cannot spend them.
  IF v_trust THEN
    v_scopes := v_scopes || ARRAY['phone'];
    v_keys   := v_keys   || ARRAY[p_phone || '|trusted'];
    v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_phone_trusted];
  ELSE
    v_scopes := v_scopes || ARRAY['phone_net', 'phone'];
    v_keys   := v_keys   || ARRAY[p_phone || '|' || v_net, p_phone];
    v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_phone_net, v_cfg.otp_cap_phone];
  END IF;
  IF NOT v_decoy THEN
    v_scopes := v_scopes || ARRAY['global'];
    v_keys   := v_keys   || ARRAY['all'];
    v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_global];
  END IF;

  BEGIN
    FOR i IN 1 .. pg_catalog.array_length(v_keys, 1) LOOP
      INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
      VALUES (v_day, v_scopes[i], v_keys[i], 1)
      ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1 WHERE c.count < v_caps[i]
      RETURNING c.count INTO v_n;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'cap' USING ERRCODE = 'P0001';
      END IF;
    END LOOP;

    -- The cooldown reads challenges, which exist only for messages sent. The
    -- global counter above is locked until the caller's transaction ends, so a
    -- concurrent send is already waiting behind it (a decoy has none: the phone's
    -- own row orders it).
    IF EXISTS (SELECT 1 FROM ctrlz.otp_challenges o
               WHERE o.phone_e164 = p_phone AND o.purpose = p_purpose
                 AND o.created_at > pg_catalog.now() - pg_catalog.make_interval(secs => v_cfg.otp_cooldown_s)) THEN
      RAISE EXCEPTION 'cooldown' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip, trusted)
    VALUES (p_phone, p_purpose, p_code_hash, p_delivery_ct, pg_catalog.now() + interval '5 minutes', v_ip, v_trust)
    RETURNING ctrlz.otp_challenges.id INTO v_id;

    -- Wakes the worker. A notification sent inside a subtransaction that is
    -- rolled back is dropped with it.
    IF NOT v_decoy THEN
      PERFORM pg_catalog.pg_notify('ctrlz_sms', '');
    END IF;
  EXCEPTION WHEN raise_exception THEN
    -- The subtransaction undoes the counters bumped before the refusal.
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END;

  RETURN QUERY SELECT v_id, true;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_otp_issue(text, text, bytea, bytea, inet, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_otp_issue(text, text, bytea, bytea, inet, boolean) TO ctrlz_tenant;

-- Login tickets. The tenant and the user are values the api passes in, for a
-- phase where no tenant setting exists yet. The table is global, and reading a
-- ticket needs the raw token, so this adds no cross-tenant reach. ttl_seconds
-- is capped at 600 (the table's CHECK says so too).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_ticket_put(p_token_hash bytea, p_kind text, p_tenant uuid, p_user uuid, p_remember boolean,
                                         p_first_factor text, p_payload bytea, p_ttl_seconds integer)
RETURNS TABLE (id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_token_hash IS NULL OR p_ttl_seconds IS NULL OR p_ttl_seconds < 1 THEN
    RETURN;
  END IF;
  RETURN QUERY
  INSERT INTO ctrlz.auth_tickets AS t (token_hash, kind, subject_tenant, subject_user, remember_me, first_factor, payload, expires_at)
  VALUES (p_token_hash, p_kind, p_tenant, p_user, COALESCE(p_remember, false), p_first_factor, p_payload,
          pg_catalog.now() + pg_catalog.make_interval(secs => LEAST(p_ttl_seconds, 600)))
  RETURNING t.id;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_ticket_put(bytea, text, uuid, uuid, boolean, text, bytea, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_ticket_put(bytea, text, uuid, uuid, boolean, text, bytea, integer) TO ctrlz_tenant;

-- Read a ticket and spend one attempt. No row when it is consumed, expired, of
-- another kind, or already read five times.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_ticket_peek(p_token_hash bytea, p_kind text)
RETURNS TABLE (subject_tenant uuid, subject_user uuid, remember_me boolean, first_factor text, payload bytea)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_tickets t SET attempts = t.attempts + 1
  WHERE t.token_hash = p_token_hash AND t.kind = p_kind
    AND t.consumed_at IS NULL AND t.expires_at > pg_catalog.now() AND t.attempts < 5
  RETURNING t.subject_tenant, t.subject_user, t.remember_me, t.first_factor, t.payload
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_ticket_peek(bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_ticket_peek(bytea, text) TO ctrlz_tenant;

-- Use a ticket. One UPDATE sets consumed_at, so single use holds when two
-- requests race: the second finds no row.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_ticket_take(p_token_hash bytea, p_kind text)
RETURNS TABLE (subject_tenant uuid, subject_user uuid, remember_me boolean, first_factor text, payload bytea)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_tickets t SET consumed_at = pg_catalog.now()
  WHERE t.token_hash = p_token_hash AND t.kind = p_kind
    AND t.consumed_at IS NULL AND t.expires_at > pg_catalog.now()
  RETURNING t.subject_tenant, t.subject_user, t.remember_me, t.first_factor, t.payload
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_ticket_take(bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_ticket_take(bytea, text) TO ctrlz_tenant;

-- A credential change closes the user's open mfa and reset tickets, so a ticket
-- does not outlive the credential it was issued against. The tenant is the
-- caller's setting. ctrlz_tenant has no grant on the table, so nothing else can
-- reach these rows. The admin's re-issue of a one-time password calls it too.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_tickets_revoke(p_user_id uuid)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_tickets t SET consumed_at = pg_catalog.now()
  WHERE t.subject_tenant = ctrlz.current_tenant_id() AND t.subject_user = p_user_id
    AND t.kind IN ('mfa', 'reset') AND t.consumed_at IS NULL
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_tickets_revoke(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_tickets_revoke(uuid) TO ctrlz_tenant, ctrlz_admin;

-- Attempt limits in Postgres (R44). The row is written by a VOLATILE function
-- in its own statement, so a failed login does not roll it back: store.Auth()
-- runs it outside any transaction. The count stops at max + 1, so a flood
-- cannot overflow it. User scopes only; the admin pair below has the others.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_throttle_hit(p_scope text, p_key bytea, p_max integer, p_window_seconds integer)
RETURNS TABLE (allowed boolean, retry_after_s integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_count integer;
  v_start timestamptz;
BEGIN
  IF p_scope IS NULL OR p_scope NOT IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                                        'otp_verify_net', 'invite_net')
     OR p_key IS NULL OR pg_catalog.octet_length(p_key) <> 32
     OR p_max IS NULL OR p_max < 1 OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 1 AND 86400 THEN
    RETURN QUERY SELECT false, 0;
    RETURN;
  END IF;

  INSERT INTO ctrlz.auth_throttle AS t (scope, key, window_start, count)
  VALUES (p_scope, p_key, pg_catalog.now(), 1)
  ON CONFLICT (scope, key) DO UPDATE SET
    count        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN 1 ELSE LEAST(t.count + 1, p_max + 1) END,
    window_start = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN pg_catalog.now() ELSE t.window_start END
  RETURNING t.count, t.window_start INTO v_count, v_start;

  IF v_count <= p_max THEN
    RETURN QUERY SELECT true, 0;
  ELSE
    RETURN QUERY SELECT false, GREATEST(1, pg_catalog.ceil(pg_catalog.date_part('epoch',
        v_start + pg_catalog.make_interval(secs => p_window_seconds) - pg_catalog.now()))::integer);
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_throttle_hit(text, bytea, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_throttle_hit(text, bytea, integer, integer) TO ctrlz_tenant;

-- Clear a key after a success. The window restarts at the next hit.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_throttle_reset(p_scope text, p_key bytea)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = 0
  WHERE t.scope = p_scope AND t.key = p_key
    AND p_scope IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                    'otp_verify_net', 'invite_net')
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_throttle_reset(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_throttle_reset(text, bytea) TO ctrlz_tenant;

-- The admin pair. Two pairs, not one, because T-321 keeps admin protection
-- separate at each layer: a compromised api holds EXECUTE on the user pair
-- only, so it cannot reset an admin key between guesses and cannot lock the
-- admin out.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_throttle_hit(p_scope text, p_key bytea, p_max integer, p_window_seconds integer)
RETURNS TABLE (allowed boolean, retry_after_s integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_count integer;
  v_start timestamptz;
BEGIN
  IF p_scope IS NULL OR p_scope NOT IN ('admin_login', 'admin_login_user', 'admin_login_net', 'admin_totp')
     OR p_key IS NULL OR pg_catalog.octet_length(p_key) <> 32
     OR p_max IS NULL OR p_max < 1 OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 1 AND 86400 THEN
    RETURN QUERY SELECT false, 0;
    RETURN;
  END IF;

  INSERT INTO ctrlz.auth_throttle AS t (scope, key, window_start, count)
  VALUES (p_scope, p_key, pg_catalog.now(), 1)
  ON CONFLICT (scope, key) DO UPDATE SET
    count        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN 1 ELSE LEAST(t.count + 1, p_max + 1) END,
    window_start = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN pg_catalog.now() ELSE t.window_start END
  RETURNING t.count, t.window_start INTO v_count, v_start;

  IF v_count <= p_max THEN
    RETURN QUERY SELECT true, 0;
  ELSE
    RETURN QUERY SELECT false, GREATEST(1, pg_catalog.ceil(pg_catalog.date_part('epoch',
        v_start + pg_catalog.make_interval(secs => p_window_seconds) - pg_catalog.now()))::integer);
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_throttle_hit(text, bytea, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_throttle_hit(text, bytea, integer, integer) TO ctrlz_admin;

-- A NULL key clears the whole scope: a key bound to a network cannot be listed,
-- and ctrlz-admin unlock needs to clear admin_login (10.1).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_throttle_reset(p_scope text, p_key bytea)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = 0
  WHERE t.scope = p_scope AND (p_key IS NULL OR t.key = p_key)
    AND p_scope IN ('admin_login', 'admin_login_user', 'admin_login_net', 'admin_totp')
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_throttle_reset(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_throttle_reset(text, bytea) TO ctrlz_admin;

-- Finish a phone change (T-110). ctrlz_tenant cannot write the phone or
-- phone_verified_at, and cannot update the request, so this is the only path.
-- The user comes from the request row, not from an argument, so it cannot act
-- on another user, and the setting keeps it in the caller's tenant (this holds
-- if D32 later adds members). Both OTPs must have been consumed after the
-- request was made, for the right number and purpose, in the last ten minutes,
-- so a code from an older attempt or another purpose does not count.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_phone_change_complete(p_request_id uuid)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  r        record;
  v_old    text;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;

  SELECT p.user_id, p.new_phone_e164, p.old_otp_id, p.new_otp_id, p.expires_at, p.completed_at, p.created_at
  INTO r
  FROM ctrlz.phone_change_requests p
  WHERE p.tenant_id = v_tenant AND p.id = p_request_id
  FOR UPDATE;
  IF NOT FOUND OR r.completed_at IS NOT NULL OR r.expires_at <= pg_catalog.now() THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  SELECT u.phone_e164 INTO v_old
  FROM ctrlz.users u
  WHERE u.tenant_id = v_tenant AND u.id = r.user_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  PERFORM 1 FROM ctrlz.otp_challenges o
  WHERE o.id = r.old_otp_id AND o.phone_e164 = v_old AND o.purpose = 'phone_old'
    AND o.consumed_at >= r.created_at AND o.consumed_at > pg_catalog.now() - interval '10 minutes';
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;
  PERFORM 1 FROM ctrlz.otp_challenges o
  WHERE o.id = r.new_otp_id AND o.phone_e164 = r.new_phone_e164 AND o.purpose = 'phone_new'
    AND o.consumed_at >= r.created_at AND o.consumed_at > pg_catalog.now() - interval '10 minutes';
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  BEGIN
    UPDATE ctrlz.users u SET phone_e164 = r.new_phone_e164, phone_verified_at = pg_catalog.now()
    WHERE u.tenant_id = v_tenant AND u.id = r.user_id;
    UPDATE ctrlz.phone_change_requests p SET completed_at = pg_catalog.now()
    WHERE p.tenant_id = v_tenant AND p.id = p_request_id;
  EXCEPTION WHEN unique_violation THEN
    -- The number belongs to someone else. Only a person who holds that SIM
    -- gets this far, so the outcome may say so.
    RETURN QUERY SELECT 'unavailable'::text;
    RETURN;
  END;

  RETURN QUERY SELECT 'ok'::text;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_phone_change_complete(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_phone_change_complete(uuid) TO ctrlz_tenant;

-- A user made by an admin has no verified phone. The first OTP that arrives for
-- that number (a login or a password reset, consumed in the last ten minutes)
-- verifies it. Only if it was NULL, and only for the caller's tenant.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_phone_mark_verified(p_user_id uuid, p_otp_id uuid)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant   uuid := ctrlz.current_tenant_id();
  v_phone    text;
  v_verified timestamptz;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;

  SELECT u.phone_e164, u.phone_verified_at INTO v_phone, v_verified
  FROM ctrlz.users u
  WHERE u.tenant_id = v_tenant AND u.id = p_user_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;
  IF v_verified IS NOT NULL THEN
    RETURN QUERY SELECT 'ok'::text;
    RETURN;
  END IF;

  PERFORM 1 FROM ctrlz.otp_challenges o
  WHERE o.id = p_otp_id AND o.phone_e164 = v_phone AND o.purpose IN ('login', 'reset')
    AND o.consumed_at IS NOT NULL AND o.consumed_at > pg_catalog.now() - interval '10 minutes';
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  UPDATE ctrlz.users u SET phone_verified_at = pg_catalog.now()
  WHERE u.tenant_id = v_tenant AND u.id = p_user_id AND u.phone_verified_at IS NULL;
  RETURN QUERY SELECT 'ok'::text;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_phone_mark_verified(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_phone_mark_verified(uuid, uuid) TO ctrlz_tenant;

-- The admin creates a user (T-327). As auth_register_user, with no OTP and no
-- registration mode: the admin is the authority. must_reset is true, so the
-- first session is restricted until the user sets a password, the phone is not
-- verified until the first OTP, and the one-time password stops working after
-- 72 hours (D31). An empty result is a taken phone, which the admin may know.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_create_user(p_phone text, p_password_hash text, p_locale text)
RETURNS TABLE (tenant_id uuid, user_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid;
  v_user   uuid;
BEGIN
  IF p_phone IS NULL OR p_phone !~ '^\+[1-9][0-9]{7,14}$'
     OR p_password_hash IS NULL OR p_password_hash = ''
     OR COALESCE(p_locale, 'fa') NOT IN ('fa', 'en') THEN
    RETURN;
  END IF;

  BEGIN
    INSERT INTO ctrlz.tenants (id) VALUES (pg_catalog.uuidv7()) RETURNING ctrlz.tenants.id INTO v_tenant;
    INSERT INTO ctrlz.users (tenant_id, phone_e164, password_hash, locale, must_reset, password_expires_at)
    VALUES (v_tenant, p_phone, p_password_hash, COALESCE(p_locale, 'fa'), true, pg_catalog.now() + interval '72 hours')
    RETURNING ctrlz.users.id INTO v_user;
    INSERT INTO ctrlz.tenant_entitlements (tenant_id) VALUES (v_tenant);
  EXCEPTION WHEN unique_violation THEN
    -- Taken phone. The subtransaction undoes the tenant row as well.
    RETURN;
  END;

  RETURN QUERY SELECT v_tenant, v_user;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_create_user(text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_create_user(text, text, text) TO ctrlz_admin;

RESET ROLE;

-- Seed, as the owner. --------------------------------------------------------------------

-- The text we ask the provider to approve, in both languages. The provider
-- stores the approved copy; sms_provider_templates maps it. No template holds a
-- link (a provider refuses one in a variable), and every value fits 25
-- characters.
INSERT INTO ctrlz.sms_templates (key, locale, body) VALUES
  ('otp', 'fa', 'کد تایید Ctrl Z: {code}. این کد ۵ دقیقه اعتبار دارد و نباید به کسی داده شود.'),
  ('otp', 'en', 'Ctrl Z code: {code}. Valid for 5 minutes. Do not share it.'),
  ('otp_reset', 'fa', 'کد بازیابی رمز Ctrl Z: {code}. اگر شما درخواست نداده‌اید این پیام را نادیده بگیرید.'),
  ('otp_reset', 'en', 'Ctrl Z password reset code: {code}. Ignore this if you did not ask for it.'),
  ('otp_phone', 'fa', 'کد تغییر شماره Ctrl Z: {code}. اگر شما درخواست نداده‌اید رمز حساب را عوض کنید.'),
  ('otp_phone', 'en', 'Ctrl Z phone change code: {code}. If this was not you, change your password.'),
  ('invite', 'fa', 'شما به Ctrl Z دعوت شده‌اید. کد دعوت: {code}. این کد را در صفحه دعوت پنل وارد کنید.'),
  ('invite', 'en', 'You are invited to Ctrl Z. Invite code: {code}. Enter it on the panel''s invite page.'),
  ('account_exists', 'fa', 'برای این شماره قبلا حساب Ctrl Z ساخته شده است. از صفحه ورود یا فراموشی رمز استفاده کنید.'),
  ('account_exists', 'en', 'This number already has a Ctrl Z account. Use the login or forgot password page.')
ON CONFLICT (key, locale) DO NOTHING;
