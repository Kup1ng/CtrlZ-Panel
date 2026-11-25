
-- P1 auth review round 6, primitives area (primitives-r6-2, primitives-r6-9).
--
-- primitives-r6-2: a refund gave an attempt back inside "a window that has not ended", which is
-- not "the window the attempt was counted in". auth_throttle_hit restarts a line in place when its
-- window has run out (count = 1, window_start = now()), so a request that was counted in window 1
-- and waited for the Argon2 gate could, after the window rolled over and another client restarted
-- it, give back the attempt of that other client. The same held for a reset (the success of one
-- request clears the count and a refund of an earlier attempt then took one from a later one).
--
-- The fix is an identity for the window and not a comparison of times: the line carries `epoch`,
-- which moves whenever the window restarts or the line is cleared; the hit returns it, the caller
-- hands it back, and the refund works only on the epoch it was given. No timestamp crosses the
-- function boundary (rule clock-source), and no clock of the caller decides.
--
-- primitives-r6-9: the admin login's verify takes an Argon2 slot, so it can answer 503 and leave
-- the attempt counted. admin_throttle_refund is the admin counterpart of auth_throttle_refund, on
-- its own function and its own role (T-321 keeps the two pairs apart).
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

ALTER TABLE ctrlz.auth_throttle ADD COLUMN epoch bigint NOT NULL DEFAULT 0;

SET LOCAL search_path = pg_catalog;
SET ROLE ctrlz_auth;

DROP FUNCTION ctrlz_fn.auth_throttle_hit(text, bytea, integer, integer);
DROP FUNCTION ctrlz_fn.auth_throttle_refund(text, bytea, integer);
DROP FUNCTION ctrlz_fn.auth_throttle_reset(text, bytea);
DROP FUNCTION ctrlz_fn.admin_throttle_hit(text, bytea, integer, integer);
DROP FUNCTION ctrlz_fn.admin_throttle_reset(text, bytea);

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_throttle_hit(p_scope text, p_key bytea, p_max integer, p_window_seconds integer)
RETURNS TABLE (allowed boolean, retry_after_s integer, window_epoch bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_count integer;
  v_start timestamptz;
  v_epoch bigint;
BEGIN
  IF p_scope IS NULL OR p_scope NOT IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                                        'otp_verify_net', 'invite_net')
     OR p_key IS NULL OR pg_catalog.octet_length(p_key) <> 32
     OR p_max IS NULL OR p_max < 1 OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 1 AND 86400 THEN
    RETURN QUERY SELECT false, 0, 0::bigint;
    RETURN;
  END IF;

  INSERT INTO ctrlz.auth_throttle AS t (scope, key, window_start, count)
  VALUES (p_scope, p_key, pg_catalog.now(), 1)
  ON CONFLICT (scope, key) DO UPDATE SET
    count        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN 1 ELSE LEAST(t.count + 1, p_max + 1) END,
    epoch        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN t.epoch + 1 ELSE t.epoch END,
    window_start = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN pg_catalog.now() ELSE t.window_start END
  RETURNING t.count, t.window_start, t.epoch INTO v_count, v_start, v_epoch;

  IF v_count <= p_max THEN
    RETURN QUERY SELECT true, 0, v_epoch;
  ELSE
    RETURN QUERY SELECT false, GREATEST(1, pg_catalog.ceil(pg_catalog.date_part('epoch',
        v_start + pg_catalog.make_interval(secs => p_window_seconds) - pg_catalog.now()))::integer), v_epoch;
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_throttle_hit(text, bytea, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_throttle_hit(text, bytea, integer, integer) TO ctrlz_tenant;

-- A cleared line has a new epoch: an attempt counted before the clear cannot be given back out of
-- the count that follows it.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_throttle_reset(p_scope text, p_key bytea)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = 0, epoch = t.epoch + 1
  WHERE t.scope = p_scope AND t.key = p_key
    AND p_scope IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                    'otp_verify_net', 'invite_net')
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_throttle_reset(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_throttle_reset(text, bytea) TO ctrlz_tenant;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_throttle_refund(p_scope text, p_key bytea, p_window_seconds integer, p_epoch bigint)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = t.count - 1
  WHERE t.scope = p_scope AND t.key = p_key AND t.count > 0
    AND t.epoch = p_epoch
    AND p_scope IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                    'otp_verify_net', 'invite_net')
    AND p_window_seconds BETWEEN 1 AND 86400
    AND t.window_start > pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_throttle_refund(text, bytea, integer, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_throttle_refund(text, bytea, integer, bigint) TO ctrlz_tenant;

-- The admin pair, with the same epoch.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_throttle_hit(p_scope text, p_key bytea, p_max integer, p_window_seconds integer)
RETURNS TABLE (allowed boolean, retry_after_s integer, window_epoch bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_count integer;
  v_start timestamptz;
  v_epoch bigint;
BEGIN
  IF p_scope IS NULL OR p_scope NOT IN ('admin_login', 'admin_login_user', 'admin_login_net', 'admin_totp')
     OR p_key IS NULL OR pg_catalog.octet_length(p_key) <> 32
     OR p_max IS NULL OR p_max < 1 OR p_window_seconds IS NULL OR p_window_seconds NOT BETWEEN 1 AND 86400 THEN
    RETURN QUERY SELECT false, 0, 0::bigint;
    RETURN;
  END IF;

  INSERT INTO ctrlz.auth_throttle AS t (scope, key, window_start, count)
  VALUES (p_scope, p_key, pg_catalog.now(), 1)
  ON CONFLICT (scope, key) DO UPDATE SET
    count        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN 1 ELSE LEAST(t.count + 1, p_max + 1) END,
    epoch        = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN t.epoch + 1 ELSE t.epoch END,
    window_start = CASE WHEN t.window_start <= pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
                        THEN pg_catalog.now() ELSE t.window_start END
  RETURNING t.count, t.window_start, t.epoch INTO v_count, v_start, v_epoch;

  IF v_count <= p_max THEN
    RETURN QUERY SELECT true, 0, v_epoch;
  ELSE
    RETURN QUERY SELECT false, GREATEST(1, pg_catalog.ceil(pg_catalog.date_part('epoch',
        v_start + pg_catalog.make_interval(secs => p_window_seconds) - pg_catalog.now()))::integer), v_epoch;
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_throttle_hit(text, bytea, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_throttle_hit(text, bytea, integer, integer) TO ctrlz_admin;

-- A NULL key clears the whole scope: a key bound to a network cannot be listed,
-- and ctrlz-admin unlock needs to clear admin_login (10.1).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_throttle_reset(p_scope text, p_key bytea)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = 0, epoch = t.epoch + 1
  WHERE t.scope = p_scope AND (p_key IS NULL OR t.key = p_key)
    AND p_scope IN ('admin_login', 'admin_login_user', 'admin_login_net', 'admin_totp')
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_throttle_reset(text, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_throttle_reset(text, bytea) TO ctrlz_admin;

-- Gives one attempt back on an admin scope. The admin_totp scope is not in the list: a code is
-- looked at whatever the server's load, so there is no attempt that did no work to give back.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_throttle_refund(p_scope text, p_key bytea, p_window_seconds integer, p_epoch bigint)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = t.count - 1
  WHERE t.scope = p_scope AND t.key = p_key AND t.count > 0
    AND t.epoch = p_epoch
    AND p_scope IN ('admin_login', 'admin_login_user', 'admin_login_net')
    AND p_window_seconds BETWEEN 1 AND 86400
    AND t.window_start > pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_throttle_refund(text, bytea, integer, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_throttle_refund(text, bytea, integer, bigint) TO ctrlz_admin;

RESET ROLE;
