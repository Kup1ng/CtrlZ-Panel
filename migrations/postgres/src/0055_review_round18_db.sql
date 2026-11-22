-- P1 auth review round 18, area database (findings db-r18-2, db-r18-11, db-r18-3 and db-r18-1; rules
-- role-reach, caps-and-endings and known-unknown-oracle).
--
-- db-r18-2 (D64 otp-global-row-serialisation). Since 0052 every OTP request, a decoy included, upserted the one
-- global counter row (day, 'global', 'all') and so took its row lock until commit. An unknown-phone request
-- costs its sender nothing, so a flood of them (5 a minute per network, about 2,400 networks for 200 requests a
-- second) queued every real request of every tenant behind the commits of the decoys, and they answered 503 at
-- lock_timeout. 0052 had put the decoy on the row for a reason (a decoy that skipped it waited for nobody while a
-- real request queued behind every real send, which marks a phone that has an account), so the fix keeps the
-- ORDER of the work equal for both and removes the one lock:
--
--   * the global COUNT is sixteen shard rows, 'all' and 'all:1' to 'all:15'; every request, real or decoy,
--     upserts ONE of them chosen at random, adding one for a real code and zero for a decoy, with the same
--     statement text as before. The count the caps compare with is the SUM of the shards, read without a lock.
--     The spend (cost) stays on the 'all' row, which only the worker writes.
--   * the cross-network cooldown used to hold because a second request for the same phone waited behind the first
--     on the global row (spec item 43). That serialisation is now taken where it belongs, on the phone: every
--     request first takes pg_advisory_xact_lock on a key made of the phone, real or decoy alike, so the cooldown
--     test that follows sees the first request's committed challenge, and a known and an unknown phone wait for
--     the same thing.
--
-- The hard and soft global caps are therefore not exact: requests that all read the sum below the cap before the
-- first of them commits each add one, so the excess is at most the requests in flight, which the connection limit
-- of the role that calls the function bounds (60). That slack is declared in the caps registry (internal/caps,
-- entry otp.global, field Slack) and is the D64 decision for this group. The per-key caps (phone, network,
-- address) are unchanged and exact: their rows are still locked by the upsert.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

SET ROLE ctrlz_auth;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_otp_issue(p_phone text, p_purpose text, p_code_hash bytea, p_delivery_ct bytea, p_ip inet, p_trusted boolean)
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
  v_gkey   text;
  v_net    text;
  v_scopes text[];
  v_keys   text[];
  v_caps   integer[];
  v_id     uuid;
  v_n      integer;
  v_inc    integer[];
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

  -- One request at a time per phone, real or decoy, before anything is counted (db-r18-2). The cooldown test
  -- below reads the challenges of committed requests, so two requests for one phone from two networks (they
  -- use different phone keys) must not run it side by side. The key is text, the way the audit lock's is,
  -- hashed to the bigint the function takes; it is a different text from every other advisory key of the schema.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.otp_issue:' || p_phone, 0));

  SELECT * INTO v_cfg FROM ctrlz.system_settings;
  -- The day's count is the sum of the shards and its spend is the worker's row; neither read takes a lock.
  SELECT COALESCE(pg_catalog.sum(c.count), 0)::integer, COALESCE(pg_catalog.sum(c.cost), 0)
    INTO v_gcount, v_gcost
  FROM ctrlz.sms_counters c
  WHERE c.day = v_day AND c.scope = 'global' AND (c.key = 'all' OR c.key LIKE 'all:%');

  -- Both real and decoy refuse here, so a full cap reveals no phone.
  IF ctrlz.cap_reached(v_gcount, v_cfg.otp_cap_global)
     OR ctrlz.cap_reached(v_gcost, v_cfg.sms_cost_cap_daily)
     OR (NOT v_trust
         AND ctrlz.cap_reached(v_gcount::numeric * 100, v_cfg.otp_cap_global::numeric * v_cfg.otp_soft_pct)) THEN
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
  -- One shard of the global count is probed and locked by EVERY request, in the same place, and only a real
  -- one adds to it (tenant-r16-11, db-r18-2): the shard is chosen at random, so a flood of decoys spreads over
  -- sixteen rows and no longer queues the real requests behind one.
  v_inc    := pg_catalog.array_fill(1, ARRAY[pg_catalog.array_length(v_keys, 1)]);
  v_gkey   := CASE WHEN pg_catalog.random() < 1.0 / 16 THEN 'all'
                   ELSE 'all:' || (1 + pg_catalog.floor(pg_catalog.random() * 15))::integer END;
  v_scopes := v_scopes || ARRAY['global'];
  v_keys   := v_keys   || ARRAY[v_gkey];
  v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_global];
  v_inc    := v_inc    || ARRAY[CASE WHEN v_decoy THEN 0 ELSE 1 END];

  BEGIN
    FOR i IN 1 .. pg_catalog.array_length(v_keys, 1) LOOP
      INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
      VALUES (v_day, v_scopes[i], v_keys[i], v_inc[i])
      ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + v_inc[i] WHERE NOT ctrlz.cap_reached(c.count, v_caps[i])
      RETURNING c.count INTO v_n;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'cap' USING ERRCODE = 'P0001';
      END IF;
    END LOOP;

    -- The cooldown reads challenges, which exist only for messages sent. The advisory lock above is held
    -- until the caller's transaction ends, so a concurrent request for this phone is already waiting behind
    -- it (a decoy took the same lock: the same wait for both, tenant-r16-11).
    IF EXISTS (SELECT 1 FROM ctrlz.otp_challenges o
               WHERE o.phone_e164 = p_phone AND o.purpose = p_purpose
                 AND o.created_at > pg_catalog.now() - pg_catalog.make_interval(secs => v_cfg.otp_cooldown_s)) THEN
      RAISE EXCEPTION 'cooldown' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip, trusted)
    VALUES (p_phone, p_purpose, p_code_hash, p_delivery_ct, pg_catalog.now() + interval '5 minutes', v_ip, v_trust)
    RETURNING ctrlz.otp_challenges.id INTO v_id;
  EXCEPTION WHEN raise_exception THEN
    -- The subtransaction undoes the counters bumped before the refusal.
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END;

  RETURN QUERY SELECT v_id, true;
END
$$;
-- +goose StatementEnd

-- The admin's OTP statistics (0017) read the global count from the 'all' row; it is the sum of the shards now.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.admin_sms_stats(p_days integer)
RETURNS TABLE (day date, sent integer, outbox integer, cost text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT c.day,
         COALESCE(pg_catalog.sum(c.count) FILTER (WHERE c.key = 'all' OR c.key LIKE 'all:%'), 0)::integer,
         COALESCE(pg_catalog.sum(c.count) FILTER (WHERE c.key = 'outbox'), 0)::integer,
         COALESCE(pg_catalog.sum(c.cost) FILTER (WHERE c.key = 'all'), 0)::text
    FROM ctrlz.sms_counters c
   WHERE c.scope = 'global' AND c.day > (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - p_days
   GROUP BY c.day ORDER BY c.day DESC
$$;
-- +goose StatementEnd

RESET ROLE;

-- ---------------------------------------------------------------------------------------------------------
-- db-r18-11. The class of D64 sms-cred-reach-admin, missed by it: certificates.wrapped_key_ct, the sealed private
-- key of a certificate of the panel-node trust, was readable by ctrlz_admin and ctrlz_worker through a table-level
-- SELECT, declared in guarded.yaml because "the admin issues it" and "the worker renews it". Issuing and renewing
-- WRITE a new sealed key and never read one back (an INSERT or an UPDATE of a column needs no SELECT on it), and
-- only the hub serves the key to nodes. A REVOKE of one column does nothing under a table-level grant, so the
-- table-level SELECT goes and the columns but that one are granted. Nothing reads the column today (the cert_wrap
-- key domain is P6's); this is the grant change that costs nothing before the key ring is mounted.
REVOKE SELECT ON ctrlz.certificates FROM ctrlz_admin, ctrlz_worker;
GRANT SELECT (id, kind, chain_pem, not_before, not_after, state, created_at, updated_at) ON ctrlz.certificates TO ctrlz_admin, ctrlz_worker;

-- ---------------------------------------------------------------------------------------------------------
-- db-r18-1 (D64 definer-isolation-harness). A definer function runs as the owner of ctrlz_fn, ctrlz_auth, whose
-- policies on the tables that auth has to look into before a tenant is known (tenants, users, sessions, api_tokens,
-- refresh_tokens, webauthn_credentials, the share and download tokens, endpoints, ip_claims) are USING (true). The
-- tenant predicate written inside each function body was therefore the ONLY isolation of its rows, and the harness
-- could try tenant B against tenant A's rows only where A's fixture happened to hold one: a function that dropped
-- its predicate, on an input no fixture creates, passed every test.
--
-- The split is by construction. ctrlz_scoped, a NOLOGIN role like ctrlz_auth, owns every definer function that
-- acts for the tenant of the call (ctrlz.current_tenant_id(), the setting the transaction made), and it has NO
-- named policy: on every table it reads or writes it meets tenant_isolation and nothing else, so another
-- tenant's row is refused by row-level security even when the body forgets its predicate. What stays on
-- ctrlz_auth is a closed list in migrations/catalog/functions.yaml (field owner: auth, with a reason each): the
-- lookups made before any tenant is known (by phone, by session hash, by token hash), the throttle and the
-- sweeps, which are not about one tenant, the creation of a tenant, the functions that read the login codes
-- (a table with no tenant column) and the ones that look across tenants by design (IP claims). Catalog check 10
-- fails a function owned by ctrlz_auth that is not on the list, and a function that acts for a tenant and is
-- not owned by ctrlz_scoped.
--
-- The role is made by bootstrap (10-cluster.sql), which the migrator cannot do; an installed database says so
-- below, as 0017 did for ctrlz_keytool. Each function is dropped and made again by ctrlz_scoped with the body it
-- had (taken from the catalog, not retyped), then given the same EXECUTE grants. The schema grants CREATE to the
-- role for the length of this file only.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ctrlz_scoped') THEN
    RAISE EXCEPTION 'role ctrlz_scoped does not exist: run the CREATE ROLE, ALTER ROLE and GRANT lines for it from migrations/postgres/bootstrap/10-cluster.sql and 15-role-bounds.sql, as the superuser';
  END IF;
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA ctrlz TO ctrlz_scoped;
GRANT EXECUTE ON FUNCTION ctrlz.current_tenant_id() TO ctrlz_scoped;
GRANT EXECUTE ON FUNCTION ctrlz.credential_state(boolean, timestamp with time zone, boolean) TO ctrlz_scoped;

-- What the twelve bodies read and write, and no more. Policies: tenant_isolation only (policies.yaml names none
-- for ctrlz_scoped, and catalog check 05 fails one that appears).
GRANT SELECT (id, tenant_id, must_reset, password_expires_at, password_hash, enforce_passkey, totp_enabled_at, totp_secret_ct, totp_pending_at),
      UPDATE (password_hash, password_expires_at, must_reset, password_changed_at, totp_secret_ct, totp_enabled_at, totp_last_step, enforce_passkey, totp_pending_at)
  ON ctrlz.users TO ctrlz_scoped;
GRANT SELECT (id, status) ON ctrlz.tenants TO ctrlz_scoped;
GRANT SELECT (id, tenant_id, user_id, revoked_at), UPDATE (revoked_at) ON ctrlz.sessions TO ctrlz_scoped;
GRANT SELECT (id, tenant_id, user_id, revoked_at), UPDATE (revoked_at) ON ctrlz.refresh_tokens TO ctrlz_scoped;
GRANT SELECT (id, tenant_id, user_id, rp_id, stale_at), UPDATE (stale_at) ON ctrlz.webauthn_credentials TO ctrlz_scoped;
GRANT SELECT (rp_id) ON ctrlz.webauthn_config TO ctrlz_scoped;
GRANT SELECT ON ctrlz.announcements TO ctrlz_scoped;
GRANT SELECT (id, tenant_id, pair_override_node_a, pair_override_node_b) ON ctrlz.endpoints TO ctrlz_scoped;
GRANT SELECT ON ctrlz.public_settings TO ctrlz_scoped;
GRANT SELECT ON ctrlz.node_pairs TO ctrlz_scoped;
GRANT SELECT (id, dns_advertised_ip) ON ctrlz.nodes TO ctrlz_scoped;
GRANT INSERT (tenant_id, kind, severity, params) ON ctrlz.notifications TO ctrlz_scoped;
GRANT INSERT (tenant_id, user_id, action, target, params) ON ctrlz.tenant_audit_log TO ctrlz_scoped;

SET ROLE ctrlz_auth;
GRANT USAGE, CREATE ON SCHEMA ctrlz_fn TO ctrlz_scoped;
RESET ROLE;
-- What ctrlz_auth has: a function the role makes is executable by its owner and nobody else until it is granted.
SET ROLE ctrlz_scoped;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
RESET ROLE;

-- admin_one_time_state
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.admin_one_time_state(p_user_id uuid);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_one_time_state(p_user_id uuid)
 RETURNS TABLE(cred_state text, no_second_factor boolean, tenant_status text)
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  SELECT ctrlz.credential_state(u.must_reset, u.password_expires_at, false),
         u.totp_enabled_at IS NULL AND NOT u.enforce_passkey
           AND NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_credentials w
                           WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id),
         t.status::text
    FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id
   WHERE u.tenant_id = ctrlz.current_tenant_id() AND u.id = p_user_id
     FOR NO KEY UPDATE OF u
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_one_time_state(p_user_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_one_time_state(p_user_id uuid) TO ctrlz_admin;
RESET ROLE;

-- admin_reissue_one_time_password
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.admin_reissue_one_time_password(p_user_id uuid, p_password_hash text);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_reissue_one_time_password(p_user_id uuid, p_password_hash text)
 RETURNS TABLE(outcome text, was_expired boolean, expires_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_tenant  uuid := ctrlz.current_tenant_id();
  v_expires timestamptz;
  r         record;
BEGIN
  IF v_tenant IS NULL OR p_user_id IS NULL OR p_password_hash IS NULL OR p_password_hash = '' THEN
    RETURN QUERY SELECT 'not_found'::text, false, NULL::timestamptz;
    RETURN;
  END IF;

  SELECT ctrlz.credential_state(u.must_reset, u.password_expires_at, false) AS st,
         (u.totp_enabled_at IS NULL AND NOT u.enforce_passkey
          AND NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_credentials w
                          WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id)) AS no_second_factor,
         t.status AS status
    INTO r
    FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id
   WHERE u.tenant_id = v_tenant AND u.id = p_user_id
     FOR NO KEY UPDATE OF u;
  IF NOT FOUND OR r.status = 'deleting' THEN
    RETURN QUERY SELECT 'not_found'::text, false, NULL::timestamptz;
    RETURN;
  END IF;
  IF r.st NOT IN ('one_time_live', 'one_time_expired') OR NOT r.no_second_factor THEN
    RETURN QUERY SELECT 'not_one_time'::text, false, NULL::timestamptz;
    RETURN;
  END IF;

  UPDATE ctrlz.users u
     SET password_hash = p_password_hash,
         password_expires_at = pg_catalog.now() + interval '72 hours',
         must_reset = true
   WHERE u.tenant_id = v_tenant AND u.id = p_user_id
  RETURNING u.password_expires_at INTO v_expires;

  RETURN QUERY SELECT 'ok'::text, r.st = 'one_time_expired', v_expires;
END
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_reissue_one_time_password(p_user_id uuid, p_password_hash text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_reissue_one_time_password(p_user_id uuid, p_password_hash text) TO ctrlz_admin;
RESET ROLE;

-- admin_revoke_user_sessions
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.admin_revoke_user_sessions(p_user_id uuid);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_revoke_user_sessions(p_user_id uuid)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_user_id IS NULL THEN
    RETURN 0;
  END IF;
  UPDATE ctrlz.sessions s SET revoked_at = pg_catalog.now()
   WHERE s.tenant_id = v_tenant AND s.revoked_at IS NULL AND s.id = ANY (ARRAY(SELECT x.id FROM ctrlz.sessions x
       WHERE x.tenant_id = v_tenant AND x.user_id = p_user_id AND x.revoked_at IS NULL
       ORDER BY x.id FOR NO KEY UPDATE));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  UPDATE ctrlz.refresh_tokens r SET revoked_at = pg_catalog.now()
   WHERE r.tenant_id = v_tenant AND r.revoked_at IS NULL AND r.id = ANY (ARRAY(SELECT x.id FROM ctrlz.refresh_tokens x
       WHERE x.tenant_id = v_tenant AND x.user_id = p_user_id AND x.revoked_at IS NULL
       ORDER BY x.id FOR NO KEY UPDATE));
  RETURN v_n;
END
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_revoke_user_sessions(p_user_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_revoke_user_sessions(p_user_id uuid) TO ctrlz_admin;
RESET ROLE;

-- announcements_for_tenant
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.announcements_for_tenant();
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.announcements_for_tenant()
 RETURNS TABLE(id uuid, audience text, body text, starts_at timestamp with time zone, ends_at timestamp with time zone)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  SELECT a.id, a.audience, a.body, a.starts_at, a.ends_at
  FROM ctrlz.announcements a
  WHERE ctrlz.current_tenant_id() IS NOT NULL
    AND (a.audience = 'all' OR a.tenant_id = ctrlz.current_tenant_id())
    AND a.starts_at <= pg_catalog.now()
    AND (a.ends_at IS NULL OR a.ends_at > pg_catalog.now())
  ORDER BY a.starts_at DESC, a.id
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.announcements_for_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.announcements_for_tenant() TO ctrlz_tenant;
RESET ROLE;

-- auth_totp_seed
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.auth_totp_seed(p_user_id uuid, p_tenant_id uuid);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_totp_seed(p_user_id uuid, p_tenant_id uuid)
 RETURNS TABLE(totp_secret_ct bytea)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  SELECT u.totp_secret_ct
  FROM ctrlz.users u
  WHERE u.id = p_user_id AND u.tenant_id = p_tenant_id
    AND ctrlz.current_tenant_id() = p_tenant_id
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_totp_seed(p_user_id uuid, p_tenant_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_totp_seed(p_user_id uuid, p_tenant_id uuid) TO ctrlz_tenant;
RESET ROLE;

-- auth_user_flags
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.auth_user_flags(p_user_id uuid);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_user_flags(p_user_id uuid)
 RETURNS TABLE(has_password boolean)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  SELECT (u.password_hash IS NOT NULL)
  FROM ctrlz.users u
  WHERE u.tenant_id = ctrlz.current_tenant_id() AND u.id = p_user_id
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_user_flags(p_user_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_user_flags(p_user_id uuid) TO ctrlz_tenant;
RESET ROLE;

-- endpoint_pair_ips
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.endpoint_pair_ips();
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.endpoint_pair_ips()
 RETURNS TABLE(endpoint_id uuid, primary_dns_ip inet, fallback_dns_ip inet)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  SELECT e.id, pn.dns_advertised_ip, fn.dns_advertised_ip
  FROM ctrlz.endpoints e
  CROSS JOIN ctrlz.public_settings ps
  LEFT JOIN ctrlz.node_pairs gp ON gp.id = ps.global_pair_id
  JOIN ctrlz.nodes pn ON pn.id = COALESCE(e.pair_override_node_a, gp.primary_node_id)
  JOIN ctrlz.nodes fn ON fn.id = COALESCE(e.pair_override_node_b, gp.fallback_node_id)
  WHERE e.tenant_id = ctrlz.current_tenant_id()
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.endpoint_pair_ips() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.endpoint_pair_ips() TO ctrlz_tenant, ctrlz_worker;
RESET ROLE;

-- keytool_totp_declare_lost
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.keytool_totp_declare_lost(p_key_number integer, p_user_ids uuid[], p_cts bytea[]);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.keytool_totp_declare_lost(p_key_number integer, p_user_ids uuid[], p_cts bytea[])
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_key_number IS NULL OR p_key_number NOT BETWEEN 1 AND 65535
     OR p_user_ids IS NULL OR p_cts IS NULL
     OR pg_catalog.cardinality(p_user_ids) <> pg_catalog.cardinality(p_cts)
     OR pg_catalog.cardinality(p_user_ids) = 0 THEN
    RETURN 0;
  END IF;
  IF pg_catalog.cardinality(p_user_ids) > 20000 THEN
    RAISE EXCEPTION 'keytool_totp_declare_lost: at most 20000 seeds per call' USING ERRCODE = '22023';
  END IF;
  -- Header: 'C' 'Z', format version 1, then the key number as two bytes (keyring). The users of the list are
  -- locked first, in key order, by the ordered subselect; the rest of the predicate judges each one.
  UPDATE ctrlz.users u
     SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL
    FROM unnest(p_user_ids, p_cts) AS l(id, ct)
   WHERE u.id = ANY (ARRAY(SELECT x.id FROM ctrlz.users x
                   WHERE x.tenant_id = v_tenant AND x.id = ANY (p_user_ids)
                   ORDER BY x.id FOR NO KEY UPDATE))
     AND u.tenant_id = v_tenant AND u.id = l.id AND u.totp_enabled_at IS NOT NULL
     AND u.totp_secret_ct IS NOT NULL
     -- The ciphertext listed for this user is still the one stored.
     AND u.totp_secret_ct = l.ct
     AND pg_catalog.octet_length(u.totp_secret_ct) >= 5
     AND pg_catalog.get_byte(u.totp_secret_ct, 0) = 67
     AND pg_catalog.get_byte(u.totp_secret_ct, 1) = 90
     AND pg_catalog.get_byte(u.totp_secret_ct, 2) = 1
     AND pg_catalog.get_byte(u.totp_secret_ct, 3) * 256 + pg_catalog.get_byte(u.totp_secret_ct, 4) = p_key_number;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n > 0 THEN
    INSERT INTO ctrlz.notifications (tenant_id, kind, severity, params)
    VALUES (v_tenant, 'totp_lost', 'warning', '{}');
    INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, target, params)
    VALUES (v_tenant, NULL, 'totp.declared_lost', NULL,
            pg_catalog.jsonb_build_object('key_number', p_key_number, 'users', v_n));
  END IF;
  RETURN v_n;
END
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(p_key_number integer, p_user_ids uuid[], p_cts bytea[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(p_key_number integer, p_user_ids uuid[], p_cts bytea[]) TO ctrlz_keytool;
RESET ROLE;

-- tenant_set_password
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.tenant_set_password(p_user_id uuid, p_password_hash text);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.tenant_set_password(p_user_id uuid, p_password_hash text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
BEGIN
  IF v_tenant IS NULL OR p_user_id IS NULL OR p_password_hash IS NULL OR p_password_hash = '' THEN
    RETURN false;
  END IF;
  UPDATE ctrlz.users u
     SET password_hash = p_password_hash, password_changed_at = pg_catalog.now(),
         must_reset = false, password_expires_at = NULL
   WHERE u.tenant_id = v_tenant AND u.id = p_user_id;
  RETURN FOUND;
END
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.tenant_set_password(p_user_id uuid, p_password_hash text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.tenant_set_password(p_user_id uuid, p_password_hash text) TO ctrlz_tenant;
RESET ROLE;

-- worker_enforce_clear_without_live
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.worker_enforce_clear_without_live(p_rp_id text);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_enforce_clear_without_live(p_rp_id text)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_rp_id IS NULL OR p_rp_id = ''
     OR NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_config c WHERE c.rp_id = p_rp_id) THEN
    RETURN 0;
  END IF;
  -- Every user of the set must be reached, so the rows are waited for, in key order (not skipped).
  UPDATE ctrlz.users u SET enforce_passkey = false
   WHERE u.id = ANY (ARRAY(SELECT x.id FROM ctrlz.users x
                   WHERE x.tenant_id = v_tenant AND x.enforce_passkey
                     AND NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_credentials w
                                     WHERE w.tenant_id = x.tenant_id AND w.user_id = x.id
                                       AND w.stale_at IS NULL AND w.rp_id = p_rp_id)
                   ORDER BY x.id FOR NO KEY UPDATE))
     AND u.tenant_id = v_tenant AND u.enforce_passkey;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n > 0 THEN
    INSERT INTO ctrlz.notifications (tenant_id, kind, severity, params)
    VALUES (v_tenant, 'passkey_enforce_cleared', 'warning', pg_catalog.jsonb_build_object('users', v_n));
    INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, target, params)
    VALUES (v_tenant, NULL, 'passkey.enforce_cleared', NULL,
            pg_catalog.jsonb_build_object('rp_id', p_rp_id, 'users', v_n));
  END IF;
  RETURN v_n;
END
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_enforce_clear_without_live(p_rp_id text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_enforce_clear_without_live(p_rp_id text) TO ctrlz_worker;
RESET ROLE;

-- worker_passkeys_mark_stale
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.worker_passkeys_mark_stale(p_rp_id text);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_passkeys_mark_stale(p_rp_id text)
 RETURNS TABLE(user_id uuid)
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  WITH marked AS (
    UPDATE ctrlz.webauthn_credentials w SET stale_at = pg_catalog.now()
     WHERE w.id = ANY (ARRAY(SELECT s.id FROM ctrlz.webauthn_credentials s
                 WHERE s.tenant_id = ctrlz.current_tenant_id() AND s.rp_id <> p_rp_id AND s.stale_at IS NULL
                   AND EXISTS (SELECT 1 FROM ctrlz.webauthn_config c WHERE c.rp_id = p_rp_id)
                 ORDER BY s.id FOR NO KEY UPDATE))
       AND w.tenant_id = ctrlz.current_tenant_id() AND w.rp_id <> p_rp_id AND w.stale_at IS NULL
    RETURNING w.user_id
  )
  SELECT DISTINCT m.user_id FROM marked m
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_passkeys_mark_stale(p_rp_id text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_passkeys_mark_stale(p_rp_id text) TO ctrlz_worker;
RESET ROLE;

-- worker_sweep_pending_totp
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.worker_sweep_pending_totp(p_limit integer);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_sweep_pending_totp(p_limit integer)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  -- The outer predicate repeats EVERY predicate of the subselect. Under READ COMMITTED a
  -- user who restarted the setup after the subselect read (a new seed and a new
  -- totp_pending_at) is re-read for this UPDATE and judged by this WHERE alone; without
  -- the 15 minute test the sweep cleared the seed the user was about to confirm.
  UPDATE ctrlz.users u SET totp_secret_ct = NULL, totp_pending_at = NULL
   WHERE u.id = ANY (ARRAY(SELECT s.id FROM ctrlz.users s
                   WHERE s.tenant_id = v_tenant AND s.totp_enabled_at IS NULL
                     AND s.totp_pending_at < pg_catalog.now() - interval '15 minutes'
                   ORDER BY s.id LIMIT LEAST(p_limit, 10000) FOR NO KEY UPDATE SKIP LOCKED))
     AND u.tenant_id = v_tenant AND u.totp_enabled_at IS NULL
     AND u.totp_pending_at < pg_catalog.now() - interval '15 minutes';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_sweep_pending_totp(p_limit integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_sweep_pending_totp(p_limit integer) TO ctrlz_worker;
RESET ROLE;

SET ROLE ctrlz_auth;
REVOKE USAGE, CREATE ON SCHEMA ctrlz_fn FROM ctrlz_scoped;
RESET ROLE;
