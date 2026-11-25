-- P1 auth review round 5, area database, roles and store (findings db-r5-1, db-r5-5,
-- db-r5-6, db-r5-7, db-r5-9). Rules role-reach (catalog check 22), bounded-sweeps
-- (internal/lint TestBoundedSweeps) and the foreign-key shape of the credential tables.
--
--   1. DELETE was judged only on the trail tables, so the credential and authority tables
--      kept reaches nobody had decided on, and a tenant was not guarded at all:
--        - ctrlz_worker held UPDATE (status, deleted_at) and DELETE on tenants. The
--          tenants policy is "id = current_tenant_id()" and the worker can set the setting
--          to any tenant, so code running as the worker could delete a tenant, and the
--          foreign keys cascade through its users, sessions, passkeys, notifications and
--          tenant_audit_log (the trail worker_retention exists to protect; a cascade is
--          not bounded by a policy), or undo a suspension. Nothing uses the grant: the
--          purge is a P5 job. When it is built it is a definer function that deletes only
--          a tenant whose status is 'deleting' and whose deleted_at is past the grace
--          period, and it is added to guarded.yaml `delete` with the reason.
--        - ctrlz_admin held DELETE on admin_users and on recovery_codes. Nothing deletes
--          either as the admin. With admin_users empty, admin_account_bootstrap succeeds
--          for a password the caller knows; with recovery_codes the admin could take a
--          TOTP user's recovery path.
--      Check 22 now judges DELETE and TRUNCATE on every table of guarded.yaml, and counts
--      a DELETE on a parent as a DELETE of every table its ON DELETE CASCADE reaches.
--   2. auth_totp_seed answered for any tenant when no tenant was set. That branch served
--      the login lookup (AuthLookups.TOTPSeed), which the one-connection rule deleted; the
--      only caller is Tx.TOTPSeedCT, under a tenant setting. The function now needs the
--      setting to equal its tenant argument.
--   3. A sweep of the shape "pk IN (SELECT pk ... WHERE p LIMIT n)" lost its predicate
--      re-check. Under READ COMMITTED a row updated after the statement's snapshot is
--      re-read for the outer statement and judged against the OUTER WHERE alone, so the
--      predicate that lived only in the subselect (a TOTP setup older than 15 minutes, a
--      throttle window over a day old) was not asked again, and a setup the user had just
--      restarted, or a window a hit had just reopened, was cleared. The outer WHERE of
--      the four function sweeps repeats every predicate of the subselect, and the lint
--      requires it of every sweep.
--   4. refresh_tokens was tied to its session and to its user by two separate keys, so
--      the two could name different users. One key now ties the three together.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- 1. Reach.
REVOKE UPDATE (status, deleted_at), DELETE ON ctrlz.tenants FROM ctrlz_worker;
REVOKE DELETE ON ctrlz.recovery_codes FROM ctrlz_admin;
REVOKE DELETE ON ctrlz.admin_users FROM ctrlz_admin;

-- 4. The refresh token's user is its session's user.
CREATE UNIQUE INDEX sessions_tenant_user_id_uq ON ctrlz.sessions (tenant_id, user_id, id);
ALTER TABLE ctrlz.refresh_tokens DROP CONSTRAINT refresh_tokens_tenant_id_session_id_fkey;
ALTER TABLE ctrlz.refresh_tokens
  ADD CONSTRAINT refresh_tokens_session_user_fkey
  FOREIGN KEY (tenant_id, user_id, session_id) REFERENCES ctrlz.sessions (tenant_id, user_id, id) ON DELETE CASCADE;

SET ROLE ctrlz_auth;

-- 2.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_totp_seed(p_user_id uuid, p_tenant_id uuid)
RETURNS TABLE (totp_secret_ct bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT u.totp_secret_ct
  FROM ctrlz.users u
  WHERE u.id = p_user_id AND u.tenant_id = p_tenant_id
    AND ctrlz.current_tenant_id() = p_tenant_id
$$;
-- +goose StatementEnd

-- 3. The same bodies as before, with the predicate repeated in the outer statement.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_throttle(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  -- auth_throttle_hit moves window_start forward in place, so the window a hit has just
  -- reopened must survive: the outer statement asks again.
  DELETE FROM ctrlz.auth_throttle t WHERE (t.scope, t.key) IN
    (SELECT s.scope, s.key FROM ctrlz.auth_throttle s
      WHERE s.window_start < pg_catalog.now() - interval '1 day' LIMIT LEAST(p_limit, 10000))
    AND t.window_start < pg_catalog.now() - interval '1 day';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_tickets(p_limit integer)
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
    (SELECT s.id FROM ctrlz.auth_tickets s WHERE s.expires_at < pg_catalog.now() LIMIT LEAST(p_limit, 10000))
    AND t.expires_at < pg_catalog.now();
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_sms_deliveries(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  DELETE FROM ctrlz.sms_deliveries d WHERE d.id IN
    (SELECT s.id FROM ctrlz.sms_deliveries s
      WHERE s.created_at < pg_catalog.now() - interval '90 days' LIMIT LEAST(p_limit, 10000))
    AND d.created_at < pg_catalog.now() - interval '90 days';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_pending_totp(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
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
   WHERE u.id IN (SELECT s.id FROM ctrlz.users s
                   WHERE s.tenant_id = v_tenant AND s.totp_enabled_at IS NULL
                     AND s.totp_pending_at < pg_catalog.now() - interval '15 minutes'
                   LIMIT LEAST(p_limit, 10000))
     AND u.tenant_id = v_tenant AND u.totp_enabled_at IS NULL
     AND u.totp_pending_at < pg_catalog.now() - interval '15 minutes';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

RESET ROLE;
