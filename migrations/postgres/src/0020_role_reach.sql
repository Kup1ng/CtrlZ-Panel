-- P1 auth review round 5, rule role-reach (topics admin-r1-17, admin-r1-19, db-r2-1,
-- db-r2-2, db-r2-5, admin-r2-1, admin-r2-5, db-r3-1, db-r3-5, db-r3-6, admin-r3-9,
-- db-r4-3, db-r4-4, db-r4-6 to db-r4-9, sms-r4-7).
--
-- Rounds 2 to 4 each narrowed one more takeover path of a login role: password
-- columns, token tables, TOTP columns, the worker. The new catalog check 22 and
-- migrations/catalog/guarded.yaml turn that into a rule: no LOGIN role may INSERT or
-- UPDATE a guarded column, SELECT a secret column, or UPDATE or DELETE a trail row,
-- unless guarded.yaml declares it for the service that authors that data. Run against
-- 0019 the check flagged eight places; this file removes every one that was not the
-- owning service's own work.
--
--   1. ctrlz_worker held UPDATE (totp_secret_ct, totp_pending_at) on users for the
--      sweep of unconfirmed setups. A column grant cannot say "only when never
--      confirmed", so the worker, which opens every login code, could still clear the
--      seed of an enabled user and log in with a code alone. The sweep is now
--      ctrlz_fn.worker_sweep_pending_totp(), which clears only rows with
--      totp_enabled_at IS NULL and a pending time older than 15 minutes.
--   2. ctrlz_keytool held UPDATE (totp_secret_ct) for the rekey. The replacement is
--      ctrlz_fn.keytool_totp_replace(user, old, new): a compare-and-swap that refuses
--      a NULL or an implausibly short value, so the tool can re-seal a seed and cannot
--      switch a factor off.
--   3. ctrlz_admin held UPDATE (revoked_at) on sessions and refresh_tokens for the
--      re-issue of a one-time password. It is now
--      ctrlz_fn.admin_revoke_user_sessions(user), which revokes the user's rows of the
--      tenant of the transaction and nothing else.
--   4. ctrlz_admin held table-level SELECT, INSERT and UPDATE on invites, so it could
--      read token hashes and mark an invite used for another tenant. It keeps the
--      columns store.qInviteCreate, qInvitesPage and qInviteRevoke use.
--   5. ctrlz_worker held DELETE on sms_deliveries, the record of what was sent and what
--      it cost, so it could erase the figures the cost cap reads. The 90 day sweep is
--      now ctrlz_fn.worker_sweep_sms_deliveries(limit).
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- As the owner. ctrlz_auth needs the columns the new functions read and write.
GRANT SELECT (totp_pending_at), UPDATE (totp_pending_at) ON ctrlz.users TO ctrlz_auth;
GRANT UPDATE (revoked_at) ON ctrlz.sessions TO ctrlz_auth;
GRANT UPDATE (revoked_at) ON ctrlz.refresh_tokens TO ctrlz_auth;
GRANT SELECT (id, created_at), DELETE ON ctrlz.sms_deliveries TO ctrlz_auth;

REVOKE SELECT (totp_enabled_at, totp_pending_at), UPDATE (totp_secret_ct, totp_pending_at) ON ctrlz.users FROM ctrlz_worker;
REVOKE UPDATE (totp_secret_ct) ON ctrlz.users FROM ctrlz_keytool;
REVOKE UPDATE (revoked_at) ON ctrlz.sessions FROM ctrlz_admin;
REVOKE UPDATE (revoked_at) ON ctrlz.refresh_tokens FROM ctrlz_admin;
REVOKE DELETE ON ctrlz.sms_deliveries FROM ctrlz_worker;

REVOKE SELECT, INSERT, UPDATE ON ctrlz.invites FROM ctrlz_admin;
GRANT SELECT (id, phone_e164, locale, expires_at, created_at, used_at, revoked_at) ON ctrlz.invites TO ctrlz_admin;
GRANT INSERT (token_hash, phone_e164, locale, created_by, expires_at) ON ctrlz.invites TO ctrlz_admin;
GRANT UPDATE (revoked_at) ON ctrlz.invites TO ctrlz_admin;

SET ROLE ctrlz_auth;

-- The abandoned-setup sweep (spec 6.4, 9.5). It acts on the tenant of the transaction
-- setting, like the sweep it replaces, and clears the seed only where the user never
-- confirmed it: nothing was protecting the account, so no notice is due.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_sweep_pending_totp()
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN 0;
  END IF;
  UPDATE ctrlz.users u SET totp_secret_ct = NULL, totp_pending_at = NULL
   WHERE u.tenant_id = v_tenant AND u.totp_enabled_at IS NULL
     AND u.totp_pending_at < pg_catalog.now() - interval '15 minutes';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_sweep_pending_totp() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_sweep_pending_totp() TO ctrlz_worker;

-- The rekey swap (spec 8.4). The old value is compared, so a seed the user changed in
-- the meantime is not overwritten; the new one must be a plausible ciphertext, never
-- NULL. The tenant is the transaction setting, so one call reaches one tenant's user.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.keytool_totp_replace(p_user_id uuid, p_old bytea, p_new bytea)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_user_id IS NULL OR p_old IS NULL OR p_new IS NULL
     OR pg_catalog.octet_length(p_new) < 4 OR pg_catalog.octet_length(p_new) > 4096 THEN
    RETURN false;
  END IF;
  UPDATE ctrlz.users u SET totp_secret_ct = p_new
   WHERE u.tenant_id = v_tenant AND u.id = p_user_id AND u.totp_secret_ct = p_old;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n = 1;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.keytool_totp_replace(uuid, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.keytool_totp_replace(uuid, bytea, bytea) TO ctrlz_keytool;

-- The revocation half of the one-time password re-issue (spec 10.7 steps c and d).
-- revoked_at only ever goes from NULL to a time (the revocation_stays trigger), so
-- the worst a caller gets is the end of one user's sessions in the tenant it set,
-- which is the purpose. The sessions are revoked before the refresh tokens, the
-- order of Refresh and of the lock rank (spec 4.4). It returns the number of
-- sessions revoked.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_revoke_user_sessions(p_user_id uuid)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_user_id IS NULL THEN
    RETURN 0;
  END IF;
  UPDATE ctrlz.sessions s SET revoked_at = pg_catalog.now()
   WHERE s.tenant_id = v_tenant AND s.user_id = p_user_id AND s.revoked_at IS NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  UPDATE ctrlz.refresh_tokens r SET revoked_at = pg_catalog.now()
   WHERE r.tenant_id = v_tenant AND r.user_id = p_user_id AND r.revoked_at IS NULL;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_revoke_user_sessions(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_revoke_user_sessions(uuid) TO ctrlz_admin;

-- The 90 day delivery sweep, the statement the worker ran, bounded like the other
-- global sweeps.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_sweep_sms_deliveries(p_limit integer)
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
      WHERE s.created_at < pg_catalog.now() - interval '90 days' LIMIT LEAST(p_limit, 10000));
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_sweep_sms_deliveries(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_sweep_sms_deliveries(integer) TO ctrlz_worker;

RESET ROLE;
