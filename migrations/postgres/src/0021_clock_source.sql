-- P1 auth review round 5, rule clock-source (topics db-r1-3, primitives-r1-5,
-- primitives-r3-3, primitives-r3-4, primitives-r4-4, admin-r4-1;
-- migrations/catalog/clocks.yaml, catalog check 24).
--
-- Every security timestamp column has one clock. Run against 0020 the rule found two
-- columns that crossed it, and three defaults that stamped an application-clock
-- column with the database clock:
--
--   1. users.password_expires_at is stamped by the database (admin_create_user and
--      admin_reissue_one_time_password use now()) and was compared by Go with the
--      application clock. It is a database-clock column: the two functions below hand
--      Go the decision (password_expired, expired) and the routes stop comparing.
--   2. invites.expires_at is compared with now() inside auth_register_user and was
--      written by Go. It is now stamped by the database (store.InviteCreate passes a
--      lifetime), and auth_invite_by_hash says whether the invite has expired.
--   3. sessions.last_seen_at, admin_sessions.created_at and audit_log.at are
--      application-clock columns (Go stamps and compares them) that still had
--      DEFAULT now(). The default is gone, so an INSERT that forgets the column fails
--      instead of quietly using the other clock. The sessions insert and its seeds
--      pass last_seen_at.
--
-- The result rows of the two functions change, which CREATE OR REPLACE refuses; a
-- dropped function loses its grants, so each is granted again. A new file and not an
-- edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.sessions ALTER COLUMN last_seen_at DROP DEFAULT;
ALTER TABLE ctrlz.admin_sessions ALTER COLUMN created_at DROP DEFAULT;
ALTER TABLE ctrlz.audit_log ALTER COLUMN at DROP DEFAULT;

SET ROLE ctrlz_auth;

DROP FUNCTION ctrlz_fn.auth_user_by_phone(text);
DROP FUNCTION ctrlz_fn.auth_invite_by_hash(bytea);

-- New columns come last, so the Go structs keep their scan order. password_expired is
-- decided on the database clock that stamped the expiry. It is a statement of its own
-- because the row also carries enforce_lift_at, an application-clock column, and one
-- statement does not read two clocks (clocks.yaml, catalog check 24).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_user_by_phone(p_phone text)
RETURNS TABLE (tenant_id uuid, user_id uuid, password_hash text, status text,
               totp_enabled boolean, enforce_passkey boolean, must_reset boolean,
               enforce_lift_at timestamptz, password_expires_at timestamptz,
               password_changed_at timestamptz, password_expired boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_expired boolean;
BEGIN
  SELECT COALESCE(x.password_expires_at <= pg_catalog.now(), false) INTO v_expired
  FROM ctrlz.users x WHERE x.phone_e164 = p_phone;
  RETURN QUERY
  SELECT u.tenant_id, u.id, u.password_hash, t.status,
         (u.totp_enabled_at IS NOT NULL), u.enforce_passkey, u.must_reset,
         u.enforce_lift_at, u.password_expires_at, u.password_changed_at,
         COALESCE(v_expired, false)
  FROM ctrlz.users u
  JOIN ctrlz.tenants t ON t.id = u.tenant_id
  WHERE u.phone_e164 = p_phone;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_user_by_phone(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_user_by_phone(text) TO ctrlz_tenant;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_invite_by_hash(p_hash bytea)
RETURNS TABLE (id uuid, phone_e164 text, expires_at timestamptz, used_at timestamptz, revoked_at timestamptz,
               expired boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT i.id, i.phone_e164, i.expires_at, i.used_at, i.revoked_at, i.expires_at <= pg_catalog.now()
  FROM ctrlz.invites i
  WHERE i.token_hash = p_hash
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_invite_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_invite_by_hash(bytea) TO ctrlz_tenant;

RESET ROLE;
