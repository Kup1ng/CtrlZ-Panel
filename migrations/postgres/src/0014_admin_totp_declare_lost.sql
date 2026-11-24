-- P1 auth review round 2 (admin-r2-5): ctrlz_admin loses its UPDATE on the
-- second-factor columns of users.
--
-- 0012 closed the password columns and 0013 the credential tables. What was left
-- is users.totp_secret_ct, totp_enabled_at, totp_last_step and enforce_passkey,
-- which 0007 gave ctrlz_admin for one purpose: `ctrlz-admin keys declare-lost
-- user_totp` clears TOTP for a tenant when its key is gone (8.5). Code running as
-- ctrlz_admin (an injection in the admin container, a leaked pg_admin_password
-- used from inside the backend network) may open WithTenant on any tenant, so
-- the same grants let it silently switch off a victim's second factor
-- (totp_enabled_at = NULL, enforce_passkey = false) before it tries a phished
-- password, with nothing in the audit log.
--
-- The admin code never writes enforce_passkey or totp_last_step on users, and it
-- clears the other two columns in one place. That statement moves into a
-- SECURITY DEFINER function that can only set the three TOTP columns to NULL, for
-- the tenant of the transaction setting, and only for users that have TOTP
-- enabled. It cannot set a value, so it cannot plant a secret, and it does not
-- touch enforce_passkey. ctrlz_admin keeps its column SELECT and has no UPDATE on
-- users at all.
--
-- One more reader of the lock: re-issuing a one-time password (10.7) locked the
-- user row with SELECT ... FOR UPDATE, which Postgres allows only with UPDATE on
-- some column. That read moves into ctrlz_fn.admin_one_time_state, same lock, same
-- columns.
--
-- A new file and not an edit of 0007 or 0011 (README, Rules).
--
-- CORRECTED BY 0015 (review round 3, db-r3-1 / db-r3-5). The function below did not
-- close the door this header describes: it was EXECUTE-granted to ctrlz_admin and
-- the tenant setting is a GUC any session can set, so code running as that role
-- could still switch off a tenant's second factor, by a call instead of an UPDATE,
-- and the audit row and notice were the CLI's, which it would skip. 0015 drops it
-- and puts a worker-only function in its place that names the lost key and writes
-- the notice and audit row itself. Only the comment is changed here.

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- As the owner. ctrlz_auth needs the three columns the function clears.
GRANT UPDATE (totp_secret_ct, totp_enabled_at, totp_last_step) ON ctrlz.users TO ctrlz_auth;
-- A table-level REVOKE also removes the column-level grants.
REVOKE UPDATE ON ctrlz.users FROM ctrlz_admin;

SET ROLE ctrlz_auth;

-- Returns the number of users it cleared. The unconfirmed secrets of users who
-- were mid-enrolment (totp_enabled_at NULL) are left to the worker's pending
-- sweep, as before.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_totp_declare_lost()
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
  UPDATE ctrlz.users u
     SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL
   WHERE u.tenant_id = v_tenant AND u.totp_enabled_at IS NOT NULL;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_totp_declare_lost() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_totp_declare_lost() TO ctrlz_admin;

-- Step 3a of 10.7 (lock the row, read what decides a re-issue). The lock needs
-- UPDATE on at least one column of users, which ctrlz_admin no longer has, so it
-- is taken here, as ctrlz_auth, on the tenant of the setting. It lasts until the
-- calling transaction ends, as the row lock of the old statement did, and the
-- function reads exactly what that statement read.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_one_time_state(p_user_id uuid)
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
     FOR UPDATE OF u
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_one_time_state(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_one_time_state(uuid) TO ctrlz_admin;

RESET ROLE;
