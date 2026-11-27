-- P1 auth review round 1 (admin-r1-17): the rule against taking over a user's own
-- password moves from the Go handler into the database.
--
-- Spec 10.7 allows an admin to replace a user's password only while it is still
-- an admin-issued one-time password (password_expires_at set), and only for a
-- user with no second factor. Until now that rule was Go code, and ctrlz_admin
-- held UPDATE on users.password_hash, must_reset and password_expires_at, with
-- the right to open WithTenant on any tenant. Code running as ctrlz_admin (an
-- injection in the admin container, or a leaked pg_admin_password used from
-- inside the backend network) could set a known hash on any tenant's user whose
-- password the user had chosen, and log in as them. The handler's check did not
-- bind it.
--
-- Now ctrlz_fn.admin_reissue_one_time_password makes the eligibility decision
-- and the update under the row lock, as ctrlz_auth, and ctrlz_admin loses the
-- three column grants, so there is no other way to write those columns. The
-- function acts on the tenant of the transaction setting that WithTenant made,
-- as auth_tickets_revoke does, so it cannot reach another tenant either.
--
-- A new file and not an edit of 0011: a migration that has been applied
-- anywhere is never edited (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- As the owner. ctrlz_auth needs to write the three columns the function sets.
-- FOR UPDATE needs UPDATE on a column of the table, which this also gives.
GRANT UPDATE (password_hash, must_reset, password_expires_at) ON ctrlz.users TO ctrlz_auth;
REVOKE UPDATE (password_hash, must_reset, password_expires_at) ON ctrlz.users FROM ctrlz_admin;

SET ROLE ctrlz_auth;

-- outcome is 'ok', 'not_found' (no such user in the tenant, an empty hash, no
-- tenant setting, or a tenant being deleted) or 'not_one_time' (the password is
-- the user's own, or a second factor exists). was_expired and expires_at are
-- meaningful for 'ok' only. The 72 hours are those of admin_create_user (D31).
-- password_changed_at is not touched: it records the user's own changes.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_reissue_one_time_password(p_user_id uuid, p_password_hash text)
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
  -- the same lock in the same order (4.4, 5.7, 10.7).
  SELECT u.password_expires_at AS pe,
         COALESCE(u.password_expires_at <= pg_catalog.now(), false) AS was_expired,
         (u.totp_enabled_at IS NULL AND NOT u.enforce_passkey
          AND NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_credentials w
                          WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id)) AS no_second_factor,
         t.status AS status
    INTO r
    FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id
   WHERE u.tenant_id = v_tenant AND u.id = p_user_id
     FOR UPDATE OF u;
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
REVOKE ALL ON FUNCTION ctrlz_fn.admin_reissue_one_time_password(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_reissue_one_time_password(uuid, text) TO ctrlz_admin;

RESET ROLE;
