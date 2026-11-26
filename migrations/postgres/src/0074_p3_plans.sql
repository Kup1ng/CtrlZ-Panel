-- P3, package B9 (docs/specs/p3-endpoints.md 2.4, Plan D56 and T-562): the plans model.
--
--  1. plans: a global table of named sets of the eleven per-tenant limits, with the columns and
--     the CHECKs of entitlement_defaults, no NULL and no column default (a plan states every
--     limit), and exactly one default plan (a unique index for at most one, a deferred
--     constraint trigger for at least one).
--  2. The free plan is made from the values entitlement_defaults holds when this file runs.
--  3. tenants.plan_id NOT NULL, a restricting foreign key, so a plan that a tenant uses is never
--     deleted. Every existing tenant moves to the free plan: the column is added with the free
--     plan's id as its default and the default is dropped at once, because a backfill UPDATE would
--     see no row under FORCE row level security, and a column default reaches every row without
--     one (README, Rules).
--  4. entitlement_defaults is dropped, so one source of defaults remains.
--  5. The two tenant creators put the new tenant on the default plan.
--  6. Every reader of a limit takes the tenant's override in tenant_entitlements first and the
--     plan's value second: ip_claim_request and ip_claim_open_challenge here, and the Go
--     statements through ctrlz_fn.tenant_plan(), which is the only way the tenant role (and the
--     worker) reads a plan. The function acts for the tenant of the call and is owned by
--     ctrlz_scoped, so a tenant never reads the whole table or another tenant's plan.
--
-- ip_claim_request and ip_claim_open_challenge are the bodies of 0010 (the last file that
-- defines them), auth_register_user is the body of 0008 and admin_create_user that of 0011, each
-- with only the change above. A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- 1. ----------------------------------------------------------------------------------------

CREATE TABLE ctrlz.plans (
  id                        uuid PRIMARY KEY DEFAULT pg_catalog.uuidv7(),
  name                      text NOT NULL CONSTRAINT plans_name_key UNIQUE CONSTRAINT plans_name_len CHECK (pg_catalog.char_length(name) BETWEEN 1 AND 64),
  is_default                boolean NOT NULL DEFAULT false,
  max_profiles              integer NOT NULL CHECK (max_profiles >= 0),
  max_endpoints             integer NOT NULL CHECK (max_endpoints >= 0),
  max_clients_per_endpoint  integer NOT NULL CHECK (max_clients_per_endpoint >= 0),
  max_authorized_ips        integer NOT NULL CHECK (max_authorized_ips >= 0),
  max_api_tokens            integer NOT NULL CHECK (max_api_tokens >= 0),
  max_rules_per_request     integer NOT NULL CHECK (max_rules_per_request >= 0),
  max_rules_per_profile     integer NOT NULL CONSTRAINT plans_rules_per_profile_max CHECK (max_rules_per_profile >= 0 AND max_rules_per_profile <= 10000),
  max_wildcards_per_profile integer NOT NULL CHECK (max_wildcards_per_profile >= 0),
  max_realtime_sessions     integer NOT NULL CHECK (max_realtime_sessions >= 0),
  max_publishes_per_hour    integer NOT NULL CHECK (max_publishes_per_hour >= 0),
  max_ip_claims             integer NOT NULL CHECK (max_ip_claims >= 0),
  created_at                timestamptz NOT NULL DEFAULT now(),
  updated_at                timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER touch_updated_at BEFORE UPDATE ON ctrlz.plans
  FOR EACH ROW EXECUTE FUNCTION ctrlz.touch_updated_at();

-- At most one default. Every row of the index has the same key, so a second default is a unique
-- violation in the statement that makes it.
CREATE UNIQUE INDEX plans_one_default ON ctrlz.plans (is_default) WHERE is_default;

-- At least one default, checked when the transaction commits so that the default can move in two
-- statements (demote the old one, promote the new one). The same check refuses the delete of the
-- default plan, which would leave none. A plan that is no longer the default may be deleted when
-- no tenant uses it (the foreign key of 3).
-- +goose StatementBegin
CREATE FUNCTION ctrlz.plans_one_default() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n bigint;
BEGIN
  SELECT pg_catalog.count(*) INTO v_n FROM ctrlz.plans p WHERE p.is_default;
  IF v_n <> 1 THEN
    RAISE EXCEPTION 'exactly one plan is the default, found %', v_n
      USING ERRCODE = 'check_violation', CONSTRAINT = 'plans_one_default_row';
  END IF;
  RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.plans_one_default() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER plans_one_default_row AFTER INSERT OR DELETE OR UPDATE OF is_default ON ctrlz.plans
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ctrlz.plans_one_default();

-- 2. ----------------------------------------------------------------------------------------

-- The id is a constant of this file so that 3 can name it as a column default. The row is made from
-- the one row entitlement_defaults holds (an admin may have changed it since 0002), so a database
-- keeps the limits it had. A missing row fails the foreign key of 3 and so the migration.
INSERT INTO ctrlz.plans (id, name, is_default, max_profiles, max_endpoints, max_clients_per_endpoint,
                         max_authorized_ips, max_api_tokens, max_rules_per_request, max_rules_per_profile,
                         max_wildcards_per_profile, max_realtime_sessions, max_publishes_per_hour, max_ip_claims)
SELECT '00000000-0000-7000-8000-00000000f4ee'::uuid, 'Free', true, d.max_profiles, d.max_endpoints,
       d.max_clients_per_endpoint, d.max_authorized_ips, d.max_api_tokens, d.max_rules_per_request,
       d.max_rules_per_profile, d.max_wildcards_per_profile, d.max_realtime_sessions,
       d.max_publishes_per_hour, d.max_ip_claims
FROM ctrlz.entitlement_defaults d WHERE d.singleton;

-- 3. ----------------------------------------------------------------------------------------

ALTER TABLE ctrlz.tenants
  ADD COLUMN plan_id uuid NOT NULL DEFAULT '00000000-0000-7000-8000-00000000f4ee'
  CONSTRAINT tenants_plan_id_fkey REFERENCES ctrlz.plans (id) ON DELETE RESTRICT;
ALTER TABLE ctrlz.tenants ALTER COLUMN plan_id DROP DEFAULT;

-- 4. ----------------------------------------------------------------------------------------

DROP TABLE ctrlz.entitlement_defaults;

-- Grants. A tenant has none on plans: it reads its own plan through ctrlz_fn.tenant_plan() below.
-- The compiler reads every plan (P4 compiles client_cap from the tenant's limit). The admin console
-- only reads them here: its writes (edit a plan, move the default, change a tenant's plan) arrive
-- with their routes, their fresh TOTP and their audit rows in P7 (T-563), and a grant with no route
-- behind it would be reach nobody reviewed. ctrlz_auth reads what the two creators and the claim
-- functions need, and ctrlz_scoped what tenant_plan() returns.
GRANT SELECT ON ctrlz.plans TO ctrlz_compiler;
GRANT SELECT ON ctrlz.plans TO ctrlz_admin;
GRANT SELECT (id, is_default, max_ip_claims) ON ctrlz.plans TO ctrlz_auth;
GRANT SELECT (id, name, max_profiles, max_endpoints, max_clients_per_endpoint, max_authorized_ips, max_api_tokens,
              max_rules_per_request, max_rules_per_profile, max_wildcards_per_profile, max_realtime_sessions,
              max_publishes_per_hour, max_ip_claims) ON ctrlz.plans TO ctrlz_scoped;
GRANT SELECT (plan_id) ON ctrlz.tenants TO ctrlz_auth, ctrlz_scoped, ctrlz_compiler;
GRANT SELECT ON ctrlz.tenant_entitlements TO ctrlz_scoped;

-- 6. tenant_plan (the plan and the effective limits), owned by ctrlz_scoped (0055: a function that acts for the tenant of the call meets
-- tenant_isolation and nothing else). The schema grant lasts for this file only.
SET ROLE ctrlz_auth;
GRANT USAGE, CREATE ON SCHEMA ctrlz_fn TO ctrlz_scoped;
RESET ROLE;

SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.tenant_plan()
RETURNS TABLE (plan_id uuid, name text, max_profiles integer, max_endpoints integer, max_clients_per_endpoint integer,
               max_authorized_ips integer, max_api_tokens integer, max_rules_per_request integer,
               max_rules_per_profile integer, max_wildcards_per_profile integer, max_realtime_sessions integer,
               max_publishes_per_hour integer, max_ip_claims integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  -- The effective limits: the tenant's own value where it has one, the plan's otherwise. One place states the
  -- order, and every statement of the tenant and the worker reads the limits through here.
  SELECT p.id, p.name,
         COALESCE(te.max_profiles, p.max_profiles), COALESCE(te.max_endpoints, p.max_endpoints),
         COALESCE(te.max_clients_per_endpoint, p.max_clients_per_endpoint), COALESCE(te.max_authorized_ips, p.max_authorized_ips),
         COALESCE(te.max_api_tokens, p.max_api_tokens), COALESCE(te.max_rules_per_request, p.max_rules_per_request),
         COALESCE(te.max_rules_per_profile, p.max_rules_per_profile), COALESCE(te.max_wildcards_per_profile, p.max_wildcards_per_profile),
         COALESCE(te.max_realtime_sessions, p.max_realtime_sessions), COALESCE(te.max_publishes_per_hour, p.max_publishes_per_hour),
         COALESCE(te.max_ip_claims, p.max_ip_claims)
  FROM ctrlz.tenants t
  JOIN ctrlz.plans p ON p.id = t.plan_id
  LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = t.id
  WHERE t.id = ctrlz.current_tenant_id()
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.tenant_plan() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.tenant_plan() TO ctrlz_tenant, ctrlz_worker;
RESET ROLE;

SET ROLE ctrlz_auth;
REVOKE USAGE, CREATE ON SCHEMA ctrlz_fn FROM ctrlz_scoped;

-- 5 and 6. The functions that stay with ctrlz_auth. ------------------------------------------

-- ip_claim_request: the limit is the tenant's override, else its plan's value.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.ip_claim_request(p_endpoint_id uuid, p_cidr cidr, p_source text)
RETURNS TABLE (claim_id uuid, outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_mode   text;
  v_min    integer;
  v_id     uuid;
  v_grace  timestamptz;
  v_limit  integer;
  v_count  integer;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  IF p_source IS NULL OR p_source NOT IN ('manual', 'browser', 'secure_dns', 'ddns') THEN
    RETURN QUERY SELECT NULL::uuid, 'invalid_source'::text;
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM ctrlz.endpoints e WHERE e.tenant_id = v_tenant AND e.id = p_endpoint_id) THEN
    RETURN QUERY SELECT NULL::uuid, 'not_found'::text;
    RETURN;
  END IF;
  IF pg_catalog.family(p_cidr) <> 4 THEN
    RETURN QUERY SELECT NULL::uuid, 'unsupported'::text;
    RETURN;
  END IF;
  IF p_cidr && ANY (ARRAY[
       '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
       '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4']::cidr[]) THEN
    RETURN QUERY SELECT NULL::uuid, 'invalid_address'::text;
    RETURN;
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.ip_claim_request:' || v_tenant::text, 0));

  PERFORM 1 FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.cidr && p_cidr AND c.state <> 'released'
  ORDER BY c.id
  FOR UPDATE;

  IF EXISTS (SELECT 1 FROM ctrlz.ip_claims c
             WHERE c.tenant_id = v_tenant AND c.state = 'suspended' AND c.cidr && p_cidr) THEN
    RETURN QUERY SELECT NULL::uuid, 'suspended'::text;
    RETURN;
  END IF;

  -- The tenant's override first, then its plan's value. A tenant that cannot be read has no limit, and
  -- a NULL limit refuses the request below.
  SELECT COALESCE(te.max_ip_claims, p.max_ip_claims) INTO v_limit
  FROM ctrlz.tenants t
  JOIN ctrlz.plans p ON p.id = t.plan_id
  LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = t.id
  WHERE t.id = v_tenant;
  SELECT pg_catalog.count(*) INTO v_count
  FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.state <> 'released';
  IF v_limit IS NULL OR v_count >= v_limit THEN
    RETURN QUERY SELECT NULL::uuid, 'quota_exceeded'::text;
    RETURN;
  END IF;

  SELECT pg_catalog.max(c.first_grace_at) INTO v_grace
  FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.cidr && p_cidr;

  SELECT s.registration_mode INTO v_mode FROM ctrlz.system_settings s;
  v_min := CASE WHEN v_mode = 'open' THEN 32 ELSE 28 END;

  IF pg_catalog.masklen(p_cidr) < v_min THEN
    INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source, first_grace_at)
    VALUES (v_tenant, p_endpoint_id, p_cidr, 'pending_proof', p_source, v_grace)
    RETURNING ctrlz.ip_claims.id INTO v_id;
    RETURN QUERY SELECT v_id, 'wide_requires_approval'::text;
  ELSIF v_mode = 'open' THEN
    INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source, first_grace_at)
    VALUES (v_tenant, p_endpoint_id, p_cidr, 'pending_proof', p_source, v_grace)
    RETURNING ctrlz.ip_claims.id INTO v_id;
    RETURN QUERY SELECT v_id, 'pending_proof'::text;
  ELSE
    BEGIN
      INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source, first_grace_at)
      VALUES (v_tenant, p_endpoint_id, p_cidr, 'active', p_source, v_grace)
      RETURNING ctrlz.ip_claims.id INTO v_id;
    EXCEPTION WHEN exclusion_violation THEN
      RETURN QUERY SELECT NULL::uuid, 'unavailable'::text;
      RETURN;
    END;
    RETURN QUERY SELECT v_id, 'active'::text;
  END IF;
END
$$;
-- +goose StatementEnd

-- ip_claim_open_challenge: the same limit, read the same way.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.ip_claim_open_challenge(p_claim_id uuid)
RETURNS TABLE (challenge_id uuid, label text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_state  text;
  v_cidr   cidr;
  v_live   integer;
  v_limit  integer;
  v_held   integer;
  v_bits   pg_catalog.varbit;
  v_label  text;
  v_id     uuid;
  v_exp    timestamptz;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.ip_claim_request:' || v_tenant::text, 0));
  SELECT c.state, c.cidr INTO v_state, v_cidr
  FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.id = p_claim_id
  FOR UPDATE;
  IF NOT FOUND OR v_state IN ('released', 'suspended') THEN
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM ctrlz.ip_claims o
             WHERE o.tenant_id = v_tenant AND o.state = 'suspended' AND o.cidr && v_cidr AND o.id <> p_claim_id) THEN
    RETURN;
  END IF;
  SELECT pg_catalog.count(*) INTO v_live
  FROM ctrlz.ip_proof_challenges ch
  WHERE ch.tenant_id = v_tenant AND ch.claim_id = p_claim_id AND ch.expires_at > pg_catalog.now();
  IF v_live >= 10 THEN
    RETURN;
  END IF;
  -- The tenant's override first, then its plan's value. A tenant that cannot be read has no limit, and
  -- a NULL limit refuses the request below.
  SELECT COALESCE(te.max_ip_claims, p.max_ip_claims) INTO v_limit
  FROM ctrlz.tenants t
  JOIN ctrlz.plans p ON p.id = t.plan_id
  LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = t.id
  WHERE t.id = v_tenant;
  SELECT pg_catalog.count(*) INTO v_live
  FROM ctrlz.ip_proof_challenges ch
  WHERE ch.tenant_id = v_tenant AND ch.expires_at > pg_catalog.now();
  -- A limit lowered below what the tenant holds must stop new claims, not the
  -- proof of the claims it already holds: at a limit of 0 a claim in grace
  -- could never be proven and would be suspended at the end of its grace, which
  -- only an admin ends. So the cap is ten times the larger of the limit and the
  -- claims held, counted under the same lock as the request that makes them.
  -- The cast keeps ten times a limit near the top of integer from overflowing.
  SELECT pg_catalog.count(*) INTO v_held
  FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.state <> 'released';
  IF v_limit IS NULL OR v_live >= GREATEST(v_limit, v_held)::bigint * 10 THEN
    RETURN;
  END IF;

  -- 128 bits padded with two zero bits make 26 groups of 5.
  v_bits := ('x' || pg_catalog.encode(pg_catalog.uuid_send(pg_catalog.gen_random_uuid()), 'hex'))::pg_catalog.bit(128) || B'00';
  SELECT pg_catalog.string_agg(pg_catalog.substr('abcdefghijklmnopqrstuvwxyz234567',
           (pg_catalog.substr(v_bits::pg_catalog.text, n * 5 + 1, 5)::pg_catalog.bit(5))::integer + 1, 1), '' ORDER BY n)
    INTO v_label
  FROM pg_catalog.generate_series(0, 25) AS n;

  INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, expires_at)
  VALUES (v_tenant, p_claim_id, v_label, pg_catalog.now() + interval '10 minutes')
  RETURNING ctrlz.ip_proof_challenges.id, ctrlz.ip_proof_challenges.expires_at INTO v_id, v_exp;

  RETURN QUERY SELECT v_id, v_label, v_exp;
END
$$;
-- +goose StatementEnd

-- auth_register_user: the new tenant is on the default plan.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_register_user(p_phone text, p_password_hash text, p_locale text, p_invite_id uuid, p_otp_id uuid)
RETURNS TABLE (tenant_id uuid, user_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_mode         text;
  v_invite_phone text;
  v_tenant       uuid;
  v_plan         uuid;
  v_user         uuid;
BEGIN
  -- The OTP is locked so two registrations cannot both spend it.
  PERFORM 1
  FROM ctrlz.otp_challenges o
  WHERE o.id = p_otp_id AND o.phone_e164 = p_phone
    AND o.purpose = CASE WHEN p_invite_id IS NULL THEN 'signup' ELSE 'invite' END
    AND o.consumed_at IS NOT NULL AND o.consumed_at > pg_catalog.now() - interval '10 minutes'
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;

  SELECT s.registration_mode INTO v_mode FROM ctrlz.system_settings s;

  IF p_invite_id IS NOT NULL THEN
    -- Admin invites work in every mode (R44).
    SELECT i.phone_e164 INTO v_invite_phone
    FROM ctrlz.invites i
    WHERE i.id = p_invite_id AND i.used_at IS NULL AND i.revoked_at IS NULL
      AND i.expires_at > pg_catalog.now()
    FOR UPDATE;
    IF v_invite_phone IS NULL OR v_invite_phone <> p_phone THEN
      RETURN;
    END IF;
  ELSIF v_mode IS DISTINCT FROM 'open' THEN
    RETURN;
  END IF;

  -- The default plan. plans_one_default_row keeps exactly one, so a miss is a broken database: the
  -- registration then fails loudly on the NOT NULL of tenants.plan_id, outside the handler below.
  SELECT p.id INTO v_plan FROM ctrlz.plans p WHERE p.is_default;

  BEGIN
    INSERT INTO ctrlz.tenants (id, plan_id) VALUES (pg_catalog.uuidv7(), v_plan) RETURNING ctrlz.tenants.id INTO v_tenant;
    INSERT INTO ctrlz.users (tenant_id, phone_e164, phone_verified_at, password_hash, locale)
    VALUES (v_tenant, p_phone, pg_catalog.now(), p_password_hash, COALESCE(p_locale, 'fa'))
    RETURNING ctrlz.users.id INTO v_user;
    INSERT INTO ctrlz.tenant_entitlements (tenant_id) VALUES (v_tenant);
  EXCEPTION WHEN unique_violation THEN
    -- Taken phone. The subtransaction undoes the tenant row as well.
    RETURN;
  END;

  IF p_invite_id IS NOT NULL THEN
    UPDATE ctrlz.invites SET used_at = pg_catalog.now(), accepted_tenant_id = v_tenant
    WHERE id = p_invite_id;
  END IF;

  RETURN QUERY SELECT v_tenant, v_user;
END
$$;
-- +goose StatementEnd

-- admin_create_user: the same.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.admin_create_user(p_phone text, p_password_hash text, p_locale text)
RETURNS TABLE (tenant_id uuid, user_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid;
  v_plan   uuid;
  v_user   uuid;
BEGIN
  IF p_phone IS NULL OR p_phone !~ '^\+[1-9][0-9]{7,14}$'
     OR p_password_hash IS NULL OR p_password_hash = ''
     OR COALESCE(p_locale, 'fa') NOT IN ('fa', 'en') THEN
    RETURN;
  END IF;

  SELECT p.id INTO v_plan FROM ctrlz.plans p WHERE p.is_default;

  BEGIN
    INSERT INTO ctrlz.tenants (id, plan_id) VALUES (pg_catalog.uuidv7(), v_plan) RETURNING ctrlz.tenants.id INTO v_tenant;
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

RESET ROLE;
