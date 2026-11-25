-- P1 auth review round 5, rule one-time-state (internal/auth/credstate; findings
-- tenant-r1-3, tenant-r1-4, tenant-r1-8, tenant-r1-13, admin-r2-2, tenant-r2-6,
-- admin-r3-4, admin-r3-12).
--
-- What a user or an admin may do with their password depends on one question, and the
-- code answered it in several places by reading independent columns (must_reset or
-- must_change_password, password_expires_at, totp_enabled_at, the session's auth_method)
-- and changed it with separate UPDATEs that each set or cleared a few of them. Each
-- round found a route that read one field fewer than its neighbour: an OTP-opened
-- restricted session that could set a password, a waiver that outlived the expiry, a
-- password-only admin login before TOTP, an enrolment that cleared the console expiry.
-- Now:
--
--   1. ctrlz.credential_state(one_time, expires_at, needs_second_factor) is the one
--      function that turns those columns into one of four words on the database clock:
--      one_time_live, one_time_expired, chosen_no_second_factor, ready. Go receives the
--      word (internal/auth/credstate) and never the columns; internal/lint
--      TestOneTimeStateRule refuses a Go field, a selector or a SQL constant that reads
--      them, and a definer function of functions.yaml that returns them.
--      ctrlz.one_time_expiry shows the end of a one-time password in the admin's Users
--      list without handing the column over.
--   2. Every change of the state is one definer function of ctrlz_fn that checks the edge
--      (credstate.Edges, TestCredentialStateEdges drives each from every state):
--      tenant_set_password (any state ends in a password the user chose),
--      admin_reissue_one_time_password (rewritten over the state: live or expired, never
--      a password the user chose), admin_account_bootstrap, admin_account_reset (with and
--      without the authenticator), admin_account_set_password and
--      admin_account_totp_enable. ctrlz_tenant loses UPDATE on users.must_reset,
--      password_expires_at and password_changed_at; ctrlz_admin loses INSERT on
--      admin_users and UPDATE on must_change_password, password_expires_at,
--      password_changed_at and totp_enabled_at. The admin's clocks move to the database:
--      admin_users.password_expires_at is a db column now (a function cannot take a
--      timestamp), and the two stamps are records.
--   3. auth_user_by_phone and auth_session_by_hash return the state instead of the
--      columns, so the login, the reauth and the request gate all read the same word. The
--      session gate used to read a copy of the state made when the session was opened
--      (sessions.restricted); that column stays as the record of how the session began and
--      nothing decides on it.
--
-- The lifetimes are those of password.UserOneTimeLife (72 hours), AdminOneTimeLife (24
-- hours) and the hour of a chosen admin password (10.3); TestCredentialStateEdges pins
-- them to the Go constants.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- ---------------------------------------------------------------------------
-- 1. The state.

-- p_one_time is must_reset or must_change_password. p_needs_second_factor is false for a
-- user (a password without TOTP is a ready account) and totp_enabled_at IS NULL for an
-- admin (D12). A NULL fails closed in each place: a NULL flag is a one-time password, a
-- NULL "needs" is a missing second factor, and a one-time password with no expiry is an
-- expired one (the CHECK users_one_time_password allows must_reset without an expiry).
-- +goose StatementBegin
CREATE FUNCTION ctrlz.credential_state(p_one_time boolean, p_expires_at timestamptz, p_needs_second_factor boolean)
RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $$
  SELECT CASE
    WHEN COALESCE(p_one_time, true) THEN
      CASE WHEN p_expires_at IS NOT NULL AND p_expires_at > pg_catalog.now() THEN 'one_time_live' ELSE 'one_time_expired' END
    WHEN p_expires_at IS NOT NULL AND p_expires_at <= pg_catalog.now() THEN 'one_time_expired'
    WHEN COALESCE(p_needs_second_factor, true) THEN 'chosen_no_second_factor'
    ELSE 'ready'
  END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.credential_state(boolean, timestamptz, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz.credential_state(boolean, timestamptz, boolean) TO ctrlz_auth, ctrlz_tenant, ctrlz_admin;

-- The end of a one-time password, for display: NULL for a password the user chose.
-- +goose StatementBegin
CREATE FUNCTION ctrlz.one_time_expiry(p_one_time boolean, p_expires_at timestamptz)
RETURNS timestamptz
LANGUAGE sql STABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $$
  SELECT CASE WHEN ctrlz.credential_state(p_one_time, p_expires_at, false) IN ('one_time_live', 'one_time_expired')
              THEN p_expires_at END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.one_time_expiry(boolean, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz.one_time_expiry(boolean, timestamptz) TO ctrlz_admin;

-- ---------------------------------------------------------------------------
-- 2. Who may change it.

-- The tenant API no longer writes the one-time columns: tenant_set_password does.
REVOKE UPDATE (must_reset, password_expires_at, password_changed_at) ON ctrlz.users FROM ctrlz_tenant;
-- tenant_set_password stamps it, as ctrlz_auth.
GRANT UPDATE (password_changed_at) ON ctrlz.users TO ctrlz_auth;

-- The admin API no longer inserts an admin or moves the state; the functions below do,
-- as ctrlz_auth. What it keeps is the rest of its own row.
REVOKE INSERT, UPDATE ON ctrlz.admin_users FROM ctrlz_admin;
GRANT UPDATE (username, password_hash, totp_secret_ct, totp_last_step, disabled_at, last_login_at, pending_notice)
  ON ctrlz.admin_users TO ctrlz_admin;
GRANT SELECT (id, must_change_password, password_expires_at, totp_enabled_at, totp_secret_ct, totp_last_step) ON ctrlz.admin_users TO ctrlz_auth;
GRANT INSERT (username, password_hash, must_change_password, password_expires_at) ON ctrlz.admin_users TO ctrlz_auth;
GRANT UPDATE (password_hash, password_changed_at, must_change_password, password_expires_at, totp_enabled_at,
              totp_last_step, totp_secret_ct) ON ctrlz.admin_users TO ctrlz_auth;

SET ROLE ctrlz_auth;

-- ---------------------------------------------------------------------------
-- 3. The lookups return the word.

DROP FUNCTION ctrlz_fn.auth_user_by_phone(text);
DROP FUNCTION ctrlz_fn.auth_session_by_hash(bytea);
DROP FUNCTION ctrlz_fn.admin_one_time_state(uuid);

-- The state is read in a statement of its own: the row also carries enforce_lift_at, a
-- column of the application clock, and one statement does not read two clocks
-- (clocks.yaml, catalog check 24).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_user_by_phone(p_phone text)
RETURNS TABLE (tenant_id uuid, user_id uuid, password_hash text, status text,
               totp_enabled boolean, enforce_passkey boolean,
               enforce_lift_at timestamptz, password_changed_at timestamptz,
               cred_state text, credential_gen bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_state text;
BEGIN
  SELECT ctrlz.credential_state(x.must_reset, x.password_expires_at, false) INTO v_state
  FROM ctrlz.users x WHERE x.phone_e164 = p_phone;
  RETURN QUERY
  SELECT u.tenant_id, u.id, u.password_hash, t.status,
         (u.totp_enabled_at IS NOT NULL), u.enforce_passkey,
         u.enforce_lift_at, u.password_changed_at,
         COALESCE(v_state, 'one_time_expired'), u.credential_gen
  FROM ctrlz.users u
  JOIN ctrlz.tenants t ON t.id = u.tenant_id
  WHERE u.phone_e164 = p_phone;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_user_by_phone(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_user_by_phone(text) TO ctrlz_tenant;

-- The gate of a request asks the table with the state the user has now, not with a flag
-- written when the session began. A user who is not found is one_time_expired, which
-- refuses everything but the setup routes.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_session_by_hash(p_hash bytea)
RETURNS TABLE (tenant_id uuid, user_id uuid, session_id uuid, status text,
               idle_expires_at timestamptz, absolute_expires_at timestamptz, revoked_at timestamptz,
               reauth_at timestamptz, cred_state text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_state text;
BEGIN
  SELECT ctrlz.credential_state(u.must_reset, u.password_expires_at, false) INTO v_state
  FROM ctrlz.sessions s JOIN ctrlz.users u ON u.tenant_id = s.tenant_id AND u.id = s.user_id
  WHERE s.token_hash = p_hash;
  RETURN QUERY
  SELECT s.tenant_id, s.user_id, s.id, t.status,
         s.idle_expires_at, s.absolute_expires_at, s.revoked_at,
         s.reauth_at, COALESCE(v_state, 'one_time_expired')
  FROM ctrlz.sessions s
  JOIN ctrlz.tenants t ON t.id = s.tenant_id
  WHERE s.token_hash = p_hash;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_session_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_session_by_hash(bytea) TO ctrlz_tenant;

-- 10.7 step a: lock and read. FOR NO KEY UPDATE, as store.qUserLock (db-r4-1).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_one_time_state(p_user_id uuid)
RETURNS TABLE (cred_state text, no_second_factor boolean, tenant_status text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT ctrlz.credential_state(u.must_reset, u.password_expires_at, false),
         u.totp_enabled_at IS NULL AND NOT u.enforce_passkey
           AND NOT EXISTS (SELECT 1 FROM ctrlz.webauthn_credentials w
                           WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id),
         t.status::text
    FROM ctrlz.users u JOIN ctrlz.tenants t ON t.id = u.tenant_id
   WHERE u.tenant_id = ctrlz.current_tenant_id() AND u.id = p_user_id
     FOR NO KEY UPDATE OF u
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_one_time_state(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_one_time_state(uuid) TO ctrlz_admin;

-- ---------------------------------------------------------------------------
-- 4. The edges.

-- Edge (credstate.UserReissue): a one-time password, live or expired, is replaced by a new
-- one for a user with no second factor. A password the user chose, an OTP-only user
-- included, is not: it belongs to the user (10.7).
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
$$;
-- +goose StatementEnd

-- Edge (credstate.UserSetPassword): every state of a user ends in a password the user
-- chose. The proof that the caller may do it (a fresh reauth, or the live one-time
-- password of a password session) is the table of credstate, decided before this call;
-- what the database owns is that the four columns move together and nowhere else.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.tenant_set_password(p_user_id uuid, p_password_hash text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
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
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.tenant_set_password(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.tenant_set_password(uuid, text) TO ctrlz_tenant;

-- Edge (credstate.AdminBootstrap): the first admin, and only while there is none. The
-- caller runs it Serializable and retries (10.1). NULL is "an admin exists".
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_account_bootstrap(p_username text, p_password_hash text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF p_username IS NULL OR pg_catalog.char_length(p_username) NOT BETWEEN 1 AND 64
     OR p_password_hash IS NULL OR p_password_hash = '' THEN
    RETURN NULL;
  END IF;
  INSERT INTO ctrlz.admin_users (username, password_hash, must_change_password, password_expires_at)
  SELECT p_username, p_password_hash, true, pg_catalog.now() + interval '24 hours'
  WHERE NOT EXISTS (SELECT 1 FROM ctrlz.admin_users)
  RETURNING ctrlz.admin_users.id INTO v_id;
  RETURN v_id;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_account_bootstrap(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_account_bootstrap(text, text) TO ctrlz_admin;

-- Edges (credstate.AdminReset, AdminResetTOTP): `ctrlz-admin reset-password` and
-- `reset-totp`. Any state ends in a live console one-time password; with p_drop_totp the
-- authenticator is forgotten too, so the old password cannot be used to enrol another
-- (10.1). The expiry is the 24 hours of password.AdminOneTimeLife.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_account_reset(p_admin_id uuid, p_password_hash text, p_drop_totp boolean)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_admin_id IS NULL OR p_password_hash IS NULL OR p_password_hash = '' THEN
    RETURN false;
  END IF;
  UPDATE ctrlz.admin_users a
     SET password_hash = p_password_hash, must_change_password = true,
         password_expires_at = pg_catalog.now() + interval '24 hours',
         totp_secret_ct = CASE WHEN COALESCE(p_drop_totp, false) THEN NULL ELSE a.totp_secret_ct END,
         totp_enabled_at = CASE WHEN COALESCE(p_drop_totp, false) THEN NULL ELSE a.totp_enabled_at END,
         totp_last_step = CASE WHEN COALESCE(p_drop_totp, false) THEN NULL ELSE a.totp_last_step END
   WHERE a.id = p_admin_id;
  RETURN FOUND;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_account_reset(uuid, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_account_reset(uuid, text, boolean) TO ctrlz_admin;

-- Edge (credstate.AdminSetPass): the admin chooses a password. An expired password is a
-- wrong one and changes nothing. Without an authenticator the new password lives an hour
-- (admin-r2-2): D12 makes TOTP mandatory, and a password that alone opened a setup
-- session for as long as enrolment was left unfinished would let whoever phished it
-- enrol their own. ok is false for a missing admin and for the refused edge; state is the
-- state the account has afterwards.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_account_set_password(p_admin_id uuid, p_password_hash text)
RETURNS TABLE (ok boolean, cred_state text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_state text;
BEGIN
  IF p_admin_id IS NULL OR p_password_hash IS NULL OR p_password_hash = '' THEN
    RETURN QUERY SELECT false, NULL::text;
    RETURN;
  END IF;
  SELECT ctrlz.credential_state(a.must_change_password, a.password_expires_at, a.totp_enabled_at IS NULL) INTO v_state
    FROM ctrlz.admin_users a WHERE a.id = p_admin_id FOR NO KEY UPDATE;
  IF NOT FOUND OR v_state = 'one_time_expired' THEN
    RETURN QUERY SELECT false, NULL::text;
    RETURN;
  END IF;
  UPDATE ctrlz.admin_users a
     SET password_hash = p_password_hash, must_change_password = false,
         password_changed_at = pg_catalog.now(),
         password_expires_at = CASE WHEN a.totp_enabled_at IS NULL THEN pg_catalog.now() + interval '1 hour' END
   WHERE a.id = p_admin_id
  RETURNING ctrlz.credential_state(a.must_change_password, a.password_expires_at, a.totp_enabled_at IS NULL) INTO v_state;
  RETURN QUERY SELECT true, v_state;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_account_set_password(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_account_set_password(uuid, text) TO ctrlz_admin;

-- Edge (credstate.AdminTOTPEnable): the pending secret is confirmed. The hour of a
-- chosen password ends with it, and the 24 hours of a console one-time password do not:
-- the setup routes run in any order, and enrolling before choosing a password must not
-- remove the expiry that stops a one-time password nobody used (admin-r3-4, admin-r3-12).
-- A ready account has nothing to enrol.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_account_totp_enable(p_admin_id uuid, p_step bigint)
RETURNS TABLE (ok boolean, cred_state text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_state   text;
  v_pending boolean;
BEGIN
  IF p_admin_id IS NULL OR p_step IS NULL THEN
    RETURN QUERY SELECT false, NULL::text;
    RETURN;
  END IF;
  SELECT ctrlz.credential_state(a.must_change_password, a.password_expires_at, a.totp_enabled_at IS NULL),
         (a.totp_enabled_at IS NULL AND a.totp_secret_ct IS NOT NULL)
    INTO v_state, v_pending
    FROM ctrlz.admin_users a WHERE a.id = p_admin_id FOR NO KEY UPDATE;
  IF NOT FOUND OR NOT v_pending OR v_state = 'ready' THEN
    RETURN QUERY SELECT false, NULL::text;
    RETURN;
  END IF;
  UPDATE ctrlz.admin_users a
     SET totp_enabled_at = pg_catalog.now(), totp_last_step = p_step,
         password_expires_at = CASE WHEN a.must_change_password THEN a.password_expires_at END
   WHERE a.id = p_admin_id
  RETURNING ctrlz.credential_state(a.must_change_password, a.password_expires_at, a.totp_enabled_at IS NULL) INTO v_state;
  RETURN QUERY SELECT true, v_state;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_account_totp_enable(uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_account_totp_enable(uuid, bigint) TO ctrlz_admin;

RESET ROLE;
