-- P2, package B1 (docs/specs/p2-profiles.md section 2.2): what the profile write path, the job
-- runner and the lock need from the database, on top of P0 and P1.
--
--  1. catalog_service.redirect_allowed and catalog_no_redirect_domain (PS 5, D42). Neither was in a
--     migration. The pattern table has no row yet: the seed (0056) fills it for the services it
--     carries and P6 adds the complete list.
--  2. max_rules_per_request is 10,000 (Plan T-198) and max_rules_per_profile is bounded at 10,000,
--     the maxItems of the profile document, so no profile outgrows its own Export.
--  3. rule_folders.location_unavailable: a Folder Rule whose location leaves the set has to carry
--     the flag that rules and services already carry.
--  4. batch_jobs.input and error, and one active job per tenant. The queueing transaction writes
--     the validated items into the row, so a job can run after the request is gone.
--  5. Worker reach for the job runner: the content tables, an INSERT of a profile that cannot set a
--     lock column, the reads allowed(profile) needs, and the columns the idempotency sweep filters.
--  6. profiles read narrowed: nobody but the tenant role (the unlock route) reads
--     lock_password_hash. The compiler and the worker held it through a table-level SELECT.
--  7. profiles.lock_message is bounded.
--  8. The throttle scopes profile_unlock and profile_lock_tenant, in the table CHECK and in the
--     scope lists of the user throttle functions (RULES rule 6). profile_lock_tenant is in hit and
--     refund only: no success clears the tenant-wide budget (spec 7.1), so reset does not list it.
--  9. tenant_profile_counts.option_count counts option units, so the list counter equals the set
--     rows of the Options tab (SC 6).
--
-- The catalog files (grants.yaml, guarded.yaml, clocks.yaml, tables.yaml) change in the same commit.
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- 1. ----------------------------------------------------------------------------------------

ALTER TABLE ctrlz.catalog_service ADD COLUMN redirect_allowed boolean NOT NULL DEFAULT true;

-- The enforcement list behind custom rules, wider than the service list. It holds no .ir or
-- .ایران name: a built-in TLD rule covers those. At most 8 labels per entry bounds the suffix
-- lookup of the write path (spec 3.6). scope: a 'domain' entry covers the name and everything
-- under it, a 'host' entry covers that exact name only.
CREATE TABLE ctrlz.catalog_no_redirect_domain (
  pattern text PRIMARY KEY CONSTRAINT catalog_no_redirect_domain_pattern_len CHECK (pg_catalog.char_length(pattern) BETWEEN 1 AND 253),
  scope   text NOT NULL CHECK (scope IN ('domain', 'host')),
  CONSTRAINT catalog_no_redirect_domain_labels CHECK (pg_catalog.cardinality(pg_catalog.string_to_array(pattern, '.')) <= 8),
  -- The write path looks names up by exact equality on their canonical suffixes (spec 3.6), so a
  -- pattern that is not already canonical (upper case, a leading, trailing or doubled dot, a U-label)
  -- would be accepted and never match, and the never-proxied guarantee would fail open for it. Each
  -- label is LDH, 1 to 63 characters, with no hyphen at either end; an IDN is stored as its A-label.
  CONSTRAINT catalog_no_redirect_domain_canonical CHECK (
    pattern ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
);

GRANT SELECT ON ctrlz.catalog_no_redirect_domain TO ctrlz_tenant, ctrlz_compiler;
GRANT SELECT, INSERT, UPDATE, DELETE ON ctrlz.catalog_no_redirect_domain TO ctrlz_worker, ctrlz_admin;

-- 2. ----------------------------------------------------------------------------------------

ALTER TABLE ctrlz.entitlement_defaults ALTER COLUMN max_rules_per_request SET DEFAULT 10000;
UPDATE ctrlz.entitlement_defaults SET max_rules_per_request = 10000 WHERE singleton AND max_rules_per_request = 1000;

ALTER TABLE ctrlz.entitlement_defaults
  ADD CONSTRAINT entitlement_defaults_rules_per_profile_max CHECK (max_rules_per_profile <= 10000);
ALTER TABLE ctrlz.tenant_entitlements
  ADD CONSTRAINT tenant_entitlements_rules_per_profile_max CHECK (max_rules_per_profile <= 10000);

-- 3. ----------------------------------------------------------------------------------------

ALTER TABLE ctrlz.rule_folders ADD COLUMN location_unavailable boolean NOT NULL DEFAULT false;

-- 4. ----------------------------------------------------------------------------------------

-- input: the validated items of a queued job, cleared when the job ends. error: the Error of a
-- failed job (a code and at most 100 fields), written by mark-failed only.
ALTER TABLE ctrlz.batch_jobs ADD COLUMN input jsonb;
ALTER TABLE ctrlz.batch_jobs ADD COLUMN error jsonb;
-- One active job per tenant. A second one is 409 job_running, and the index is what makes that
-- true for two requests that race.
CREATE UNIQUE INDEX batch_jobs_active_uq ON ctrlz.batch_jobs (tenant_id) WHERE state IN ('queued', 'running');

-- 5. ----------------------------------------------------------------------------------------

-- The job runner writes through the same code as a request, so it holds the same table
-- privileges on the content tables. It cannot write a lock column: its INSERT of a profile
-- names four columns, and its UPDATE is the two it already had.
GRANT INSERT, UPDATE, DELETE ON ctrlz.rules, ctrlz.rule_folders, ctrlz.profile_filters,
  ctrlz.profile_services, ctrlz.profile_options TO ctrlz_worker;
-- The table-level UPDATE covers the flag columns the worker held one by one (PS 7); keeping both
-- would leave two grants for one privilege and the catalog test reads them as an extra.
REVOKE UPDATE (default_location_unavailable) ON ctrlz.profile_options FROM ctrlz_worker;
REVOKE UPDATE (location_unavailable) ON ctrlz.profile_services, ctrlz.rules FROM ctrlz_worker;
GRANT INSERT (tenant_id, id, name, kind) ON ctrlz.profiles TO ctrlz_worker;

-- allowed(profile) (spec 4.2) reads the nodes an Endpoint of the profile can be served from.
GRANT SELECT (profile_id, profile2_id, pair_override_node_a, pair_override_node_b) ON ctrlz.endpoints TO ctrlz_worker;
GRANT SELECT (tenant_id, endpoint_id, profile_id, profile2_id) ON ctrlz.schedule_windows TO ctrlz_worker;

-- The idempotency sweep deletes by these.
GRANT SELECT (tenant_id, key, expires_at) ON ctrlz.idempotency_keys TO ctrlz_worker;

-- 6. ----------------------------------------------------------------------------------------

-- Revoking a table-level SELECT revokes its column grants too, so the lists below are complete.
REVOKE SELECT ON ctrlz.profiles FROM ctrlz_compiler, ctrlz_worker;
GRANT SELECT (tenant_id, id, name, kind, version, disabled_until, lock_state, lock_message, locked_by,
              locked_at, compiled_hash, created_at, updated_at)
  ON ctrlz.profiles TO ctrlz_compiler, ctrlz_worker;

-- 7. ----------------------------------------------------------------------------------------

ALTER TABLE ctrlz.profiles
  ADD CONSTRAINT profiles_lock_message_len CHECK (pg_catalog.char_length(lock_message) <= 256);

-- 8. ----------------------------------------------------------------------------------------

ALTER TABLE ctrlz.auth_throttle DROP CONSTRAINT auth_throttle_scope_check;
ALTER TABLE ctrlz.auth_throttle ADD CONSTRAINT auth_throttle_scope_check CHECK (scope IN (
  'login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user', 'otp_verify_net',
  'invite_net', 'profile_unlock', 'profile_lock_tenant', 'admin_login', 'admin_login_user', 'admin_login_net',
  'admin_totp'));

SET ROLE ctrlz_auth;

-- The bodies are those of 0032 (hit) and 0031 (reset, refund) with the new scopes added: both in hit
-- and refund, profile_unlock alone in reset (a success clears the per-profile line; nothing clears
-- the tenant-wide profile_lock_tenant budget, so the tenant role cannot wipe it).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_throttle_hit(p_scope text, p_key bytea, p_max integer, p_window_seconds integer)
RETURNS TABLE (allowed boolean, retry_after_s integer, window_epoch bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_count integer;
  v_start timestamptz;
  v_epoch bigint;
  v_old_count integer;
  v_old_epoch bigint;
BEGIN
  IF p_scope IS NULL OR p_scope NOT IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                                        'otp_verify_net', 'invite_net', 'profile_unlock', 'profile_lock_tenant')
     OR p_key IS NULL OR pg_catalog.octet_length(p_key) <> 32
     OR p_max IS NULL OR p_max < 1 OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 1 AND 86400 THEN
    RETURN QUERY SELECT false, 0, 0::bigint;
    RETURN;
  END IF;

  INSERT INTO ctrlz.auth_throttle AS t (scope, key, window_start, count)
  VALUES (p_scope, p_key, pg_catalog.now(), 1)
  ON CONFLICT (scope, key) DO UPDATE SET
    count        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN 1 ELSE LEAST(t.count + 1, p_max) END,
    epoch        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN t.epoch + 1 ELSE t.epoch END,
    window_start = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN pg_catalog.now() ELSE t.window_start END
  RETURNING t.count, t.window_start, t.epoch, old.count, old.epoch
  INTO v_count, v_start, v_epoch, v_old_count, v_old_epoch;

  IF v_old_count IS NULL OR v_old_epoch <> v_epoch OR v_old_count < p_max THEN
    RETURN QUERY SELECT true, 0, v_epoch;
  ELSE
    RETURN QUERY SELECT false, GREATEST(1, pg_catalog.ceil(pg_catalog.date_part('epoch',
        v_start + pg_catalog.make_interval(secs => p_window_seconds) - pg_catalog.now()))::integer), v_epoch;
  END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_throttle_reset(p_scope text, p_key bytea)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = 0, epoch = t.epoch + 1
  WHERE t.scope = p_scope AND t.key = p_key
    AND p_scope IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                    'otp_verify_net', 'invite_net', 'profile_unlock')
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_throttle_refund(p_scope text, p_key bytea, p_window_seconds integer, p_epoch bigint)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = t.count - 1
  WHERE t.scope = p_scope AND t.key = p_key AND t.count > 0
    AND t.epoch = p_epoch
    AND p_scope IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                    'otp_verify_net', 'invite_net', 'profile_unlock', 'profile_lock_tenant')
    AND p_window_seconds BETWEEN 1 AND 86400
    AND t.window_start > pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
$$;
-- +goose StatementEnd

RESET ROLE;

-- 9. ----------------------------------------------------------------------------------------

-- A unit counts once: Default Rule, Block Response (with its custom addresses) and ECS (mode and
-- subnets), as SC 6 merges them. Every other option is one. default_location_unavailable is a
-- flag and compatibility_mode is stored and not shown (D9), so neither counts.
CREATE OR REPLACE VIEW ctrlz.tenant_profile_counts WITH (security_invoker = true) AS
SELECT p.tenant_id, p.id AS profile_id,
       (SELECT count(*) FROM ctrlz.endpoints e
         WHERE e.tenant_id = p.tenant_id AND (e.profile_id = p.id OR e.profile2_id = p.id)) AS endpoint_count,
       (SELECT count(*) FROM ctrlz.profile_filters f
         WHERE f.tenant_id = p.tenant_id AND f.profile_id = p.id AND f.enabled) AS filter_count,
       (SELECT count(*) FROM ctrlz.profile_services s
         WHERE s.tenant_id = p.tenant_id AND s.profile_id = p.id AND s.enabled) AS service_count,
       (SELECT count(*) FROM ctrlz.rules r
         WHERE r.tenant_id = p.tenant_id AND r.profile_id = p.id) AS rule_count,
       COALESCE((SELECT (o.default_action IS NOT NULL)::int + (o.block_response IS NOT NULL)::int
                       + (o.ecs_mode IS NOT NULL)::int + (o.block_exfiltration IS NOT NULL)::int
                       + (o.rebind_protection IS NOT NULL)::int + (o.disable_dnssec IS NOT NULL)::int
                       + (o.block_ttl IS NOT NULL)::int + (o.redirect_ttl IS NOT NULL)::int
                       + (o.bypass_ttl IS NOT NULL)::int + (o.dns64 IS NOT NULL)::int
                       + (o.cname_flattening IS NOT NULL)::int + (o.safe_search IS NOT NULL)::int
                       + (o.restricted_youtube IS NOT NULL)::int
                  FROM ctrlz.profile_options o
                  WHERE o.tenant_id = p.tenant_id AND o.profile_id = p.id), 0)::bigint AS option_count
FROM ctrlz.profiles p;
