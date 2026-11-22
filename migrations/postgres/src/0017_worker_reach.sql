-- P1 auth review round 4 (database, roles and store): db-r4-1, db-r4-3 to db-r4-9.
--
-- 1. Lock strength (db-r4-1). The user-row lock of the one-time password
--    re-issue was FOR UPDATE. Every insert into sessions or refresh_tokens takes
--    FOR KEY SHARE on the users row through its foreign key, and that conflicts
--    with FOR UPDATE: a re-issue that held the user and then wanted a session
--    Refresh had locked formed a cycle with it (40P01, a 503). The key of a user
--    never changes there, so FOR NO KEY UPDATE keeps the mutual exclusion between
--    writers and no longer collides with the key share. (store.qUserLock is the
--    same change; Refresh also asks for the key share first.)
--
-- 2. The worker role (db-r4-3, db-r4-6, db-r4-7, db-r4-8). ctrlz_worker is the
--    long-running SMS sender: it opens delivery_ct, so it reads every login code,
--    and it makes outbound calls to providers. It must therefore hold nothing that
--    removes or rewrites a second factor, nor anything that erases the trail of
--    one. Round 3 had left it with:
--      - EXECUTE on worker_totp_declare_lost, and DELETE on notifications and
--        tenant_audit_log, so the notice and audit row that function writes could
--        be deleted again in the same transaction;
--      - UPDATE (enforce_passkey) and UPDATE (stale_at), which switch off Enforce
--        Passkey or kill every passkey of a tenant;
--      - SELECT/UPDATE on totp_secret_ct for the rekey tool;
--      - table-level DELETE on auth_throttle and auth_tickets, so it could empty
--        the admin login throttle or delete live tickets.
--    Now:
--      - The key tool (rekey and declare-lost of user_totp) logs in as its own
--        role, ctrlz_keytool, created by bootstrap/10-cluster.sql, whose password
--        is mounted in the one-shot rekey container only and which pg_hba.conf lets
--        in from that container's address. ctrlz_fn.keytool_totp_declare_lost
--        replaces worker_totp_declare_lost and is EXECUTE-granted to it alone.
--      - The RP ID job's two statements are SECURITY DEFINER functions that act
--        only for the RP ID in force (webauthn_config), so the worker cannot name
--        its own: worker_passkeys_mark_stale and worker_enforce_clear_without_live.
--        The second leaves a notice and an audit row. The worker loses its column
--        grants on both tables.
--      - The worker's DELETE on notifications is gone (no sweep uses it), and
--        a restrictive policy lets it delete audit rows older than the 365 day
--        retention only.
--      - The throttle and ticket sweeps are functions that delete only what the
--        sweep always deleted (throttle windows over a day old, expired tickets).
--
-- 3. sms_counters (db-r4-4, db-r4-9). Its phone, phone_net and ip rows are keyed by
--    raw numbers and source networks, decoys included (spec 9.5). ctrlz_admin read
--    them through a table-level SELECT; it needs the global rows only. They are
--    served by ctrlz_fn.admin_sms_stats, and the grant is gone.
--
-- A new file and not an edit of 0007 to 0016 (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- The role is made by bootstrap, which the migrator cannot do. Say so plainly on
-- a database whose bootstrap predates this file.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'ctrlz_keytool') THEN
    RAISE EXCEPTION 'role ctrlz_keytool does not exist: run the CREATE ROLE and ALTER ROLE lines for it from migrations/postgres/bootstrap/10-cluster.sql and the GRANT CONNECT of 20-database.sql, as the superuser (pg_hba.conf and the pg_keytool_password secret too)';
  END IF;
END
$$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- The key tool role.

GRANT USAGE ON SCHEMA ctrlz TO ctrlz_keytool;
-- The tenant policy of every table calls it.
GRANT EXECUTE ON FUNCTION ctrlz.current_tenant_id() TO ctrlz_keytool;

-- The tool pages the tenants and then works one tenant per transaction.
GRANT SELECT (id) ON ctrlz.tenants TO ctrlz_keytool;
CREATE POLICY keytool_list ON ctrlz.tenants FOR SELECT TO ctrlz_keytool USING (true);

-- Rekey reads the sealed seeds of the tenant of the transaction setting and swaps
-- each for its re-encryption. It can read ciphertext and write bytes; it cannot
-- seal one without the user_totp key, which only its container holds.
GRANT SELECT (tenant_id, id, totp_secret_ct), UPDATE (totp_secret_ct) ON ctrlz.users TO ctrlz_keytool;

-- ---------------------------------------------------------------------------
-- What the worker loses.

REVOKE SELECT (totp_secret_ct, enforce_passkey), UPDATE (enforce_passkey) ON ctrlz.users FROM ctrlz_worker;
REVOKE SELECT (tenant_id, id, user_id, rp_id, stale_at), UPDATE (stale_at) ON ctrlz.webauthn_credentials FROM ctrlz_worker;
-- A table-level REVOKE removes the column grants too.
REVOKE ALL ON ctrlz.auth_tickets FROM ctrlz_worker;
REVOKE ALL ON ctrlz.auth_throttle FROM ctrlz_worker;
REVOKE DELETE ON ctrlz.notifications FROM ctrlz_worker;
REVOKE SELECT ON ctrlz.sms_counters FROM ctrlz_admin;

-- The worker may still delete audit rows, but only those past the retention.
-- A tenant's own purge is a cascade, which row security does not apply to.
CREATE POLICY worker_retention ON ctrlz.tenant_audit_log AS RESTRICTIVE FOR DELETE TO ctrlz_worker
  USING (at < now() - interval '365 days');

-- What the new functions run as ctrlz_auth need.
GRANT UPDATE (enforce_passkey) ON ctrlz.users TO ctrlz_auth;
GRANT UPDATE (stale_at) ON ctrlz.webauthn_credentials TO ctrlz_auth;
GRANT DELETE ON ctrlz.auth_tickets TO ctrlz_auth;
GRANT DELETE ON ctrlz.auth_throttle TO ctrlz_auth;

SET ROLE ctrlz_auth;

-- ctrlz_auth owns the schema.
GRANT USAGE ON SCHEMA ctrlz_fn TO ctrlz_keytool;

-- ---------------------------------------------------------------------------
-- 1. The one-time password functions, with the weaker lock.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.admin_one_time_state(p_user_id uuid)
RETURNS TABLE (password_expires_at timestamptz, was_expired boolean, no_second_factor boolean, tenant_status text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT u.password_expires_at,
         COALESCE(u.password_expires_at <= pg_catalog.now(), false),
         u.totp_enabled_at IS NULL AND NOT u.enforce_passkey
           AND NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_credentials w
                           WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id),
         t.status::text
    FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id
   WHERE u.tenant_id = ctrlz.current_tenant_id() AND u.id = p_user_id
     FOR NO KEY UPDATE OF u
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.admin_reissue_one_time_password(p_user_id uuid, p_password_hash text)
RETURNS TABLE (outcome text, was_expired boolean, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant  uuid := ctrlz.current_tenant_id();
  v_expires timestamptz;
  r         record;
BEGIN
  IF v_tenant IS NULL OR p_user_id IS NULL OR p_password_hash IS NULL OR p_password_hash = '' THEN
    RETURN QUERY SELECT 'not_found'::text, false, NULL::timestamptz;
    RETURN;
  END IF;

  -- The row lock comes first: the user's own password change and a login take
  -- the same lock in the same order (4.4, 5.7, 10.7). FOR NO KEY UPDATE, as
  -- store.qUserLock (db-r4-1).
  SELECT u.password_expires_at AS pe,
         COALESCE(u.password_expires_at <= pg_catalog.now(), false) AS was_expired,
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
  IF r.pe IS NULL OR NOT r.no_second_factor THEN
    RETURN QUERY SELECT 'not_one_time'::text, false, NULL::timestamptz;
    RETURN;
  END IF;

  UPDATE ctrlz.users u
     SET password_hash = p_password_hash,
         password_expires_at = pg_catalog.now() + interval '72 hours',
         must_reset = true
   WHERE u.tenant_id = v_tenant AND u.id = p_user_id
  RETURNING u.password_expires_at INTO v_expires;

  RETURN QUERY SELECT 'ok'::text, r.was_expired, v_expires;
END
$$;
-- +goose StatementEnd

-- ---------------------------------------------------------------------------
-- 2. The key tool.

DROP FUNCTION ctrlz_fn.worker_totp_declare_lost(integer);

-- Same body as worker_totp_declare_lost (0015), under the new name and the new
-- caller. It still cannot tell a lost key from a wanted switch-off by looking at the
-- data: the tool refuses while the key it is told is lost is in the key ring, and
-- the function names the key, clears only the seeds sealed under it and leaves a
-- notice and an audit row. What changed is who may call it: a login whose password
-- the long-running worker does not hold.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.keytool_totp_declare_lost(p_key_number integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_key_number IS NULL OR p_key_number NOT BETWEEN 1 AND 65535 THEN
    RETURN 0;
  END IF;
  -- Header: 'C' 'Z', format version 1, then the key number as two bytes (keyring).
  UPDATE ctrlz.users u
     SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL
   WHERE u.tenant_id = v_tenant AND u.totp_enabled_at IS NOT NULL
     AND u.totp_secret_ct IS NOT NULL
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
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(integer) TO ctrlz_keytool;

-- ---------------------------------------------------------------------------
-- The RP ID job (7.4 step 4). Both functions act for the RP ID in force only, so a
-- caller that names another one, or none, changes nothing: the worker cannot
-- decide that every credential is stale, or that nobody has a live one.

-- Marks the tenant's live credentials of another RP ID stale, once, and returns the
-- users who lost one.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_passkeys_mark_stale(p_rp_id text)
RETURNS TABLE (user_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  WITH marked AS (
    UPDATE ctrlz.webauthn_credentials w SET stale_at = pg_catalog.now()
     WHERE w.tenant_id = ctrlz.current_tenant_id() AND w.rp_id <> p_rp_id AND w.stale_at IS NULL
       AND EXISTS (SELECT 1 FROM ctrlz.webauthn_config c WHERE c.rp_id = p_rp_id)
    RETURNING w.user_id
  )
  SELECT DISTINCT m.user_id FROM marked m
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_passkeys_mark_stale(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_passkeys_mark_stale(text) TO ctrlz_worker;

-- Turns Enforce Passkey off for users who have no live credential for the RP ID in
-- force, so nobody is locked out after a change, and says so: a notice and an audit
-- row whenever it cleared anyone. Returns how many users it cleared.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_enforce_clear_without_live(p_rp_id text)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_rp_id IS NULL OR p_rp_id = ''
     OR NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_config c WHERE c.rp_id = p_rp_id) THEN
    RETURN 0;
  END IF;
  UPDATE ctrlz.users u SET enforce_passkey = false
   WHERE u.tenant_id = v_tenant AND u.enforce_passkey
     AND NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_credentials w
                     WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id
                       AND w.stale_at IS NULL AND w.rp_id = p_rp_id);
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
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_enforce_clear_without_live(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_enforce_clear_without_live(text) TO ctrlz_worker;

-- ---------------------------------------------------------------------------
-- The two global sweeps that touched what the API's brute-force limit and the
-- login tickets live in. Same predicates as the statements they replace; the
-- batch is bounded.

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_sweep_throttle(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) IN
    (SELECT s.scope, s.key FROM ctrlz.auth_throttle s
      WHERE s.window_start < pg_catalog.now() - interval '1 day' LIMIT LEAST(p_limit, 10000));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_sweep_throttle(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_sweep_throttle(integer) TO ctrlz_worker;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_sweep_tickets(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  DELETE FROM ctrlz.auth_tickets t WHERE t.id IN
    (SELECT s.id FROM ctrlz.auth_tickets s WHERE s.expires_at < pg_catalog.now() LIMIT LEAST(p_limit, 10000));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_sweep_tickets(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_sweep_tickets(integer) TO ctrlz_worker;

-- ---------------------------------------------------------------------------
-- 3. The admin's OTP statistics: the global rows only. Same figures as the
-- statement it replaces (store.qSMSStatsDays).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_sms_stats(p_days integer)
RETURNS TABLE (day date, sent integer, outbox integer, cost text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT c.day,
         COALESCE(pg_catalog.sum(c.count) FILTER (WHERE c.key = 'all'), 0)::integer,
         COALESCE(pg_catalog.sum(c.count) FILTER (WHERE c.key = 'outbox'), 0)::integer,
         COALESCE(pg_catalog.sum(c.cost) FILTER (WHERE c.key = 'all'), 0)::text
    FROM ctrlz.sms_counters c
   WHERE c.scope = 'global' AND c.day > (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - p_days
   GROUP BY c.day ORDER BY c.day DESC
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_sms_stats(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_sms_stats(integer) TO ctrlz_admin;

RESET ROLE;
