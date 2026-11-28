
-- P1 auth review round 5, area HTTP spine and tenant API (finding tenant-r5-1).
--
-- An attempt that the Argon2 gate refused (503 server_busy) evaluated no password, but it had
-- already been counted on the throttle scopes, because the count comes before the work (4.5,
-- rule proof-before-work). A flood that filled the gate, or honest load, therefore spent the
-- per-phone and per-network budgets of people whose passwords were never looked at, and after
-- the flood they were locked out with the right password.
--
-- auth_throttle_refund gives one attempt back. It is the only way a count goes down besides
-- the reset after a success, and it is bounded the same way the hit is: user scopes only, the
-- count never goes below zero, and only inside the window the hit counted in, so a refund
-- cannot reach into a window that has restarted. The caller is the one helper that knows an
-- attempt did no work (throttle.Service.Refund, reached through proof.Spec.Refund).
--
-- No admin counterpart: nothing in the admin login gives an attempt back (it has no 503 of its own to give back).
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;
SET ROLE ctrlz_auth;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_throttle_refund(p_scope text, p_key bytea, p_window_seconds integer)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = t.count - 1
  WHERE t.scope = p_scope AND t.key = p_key AND t.count > 0
    AND p_scope IN ('login_phone_net', 'login_phone', 'login_net', 'login_net48', 'totp_user', 'reauth_user',
                    'otp_verify_net', 'invite_net')
    AND p_window_seconds BETWEEN 1 AND 86400
    AND t.window_start > pg_catalog.now() - pg_catalog.make_interval(secs => p_window_seconds)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_throttle_refund(text, bytea, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_throttle_refund(text, bytea, integer) TO ctrlz_tenant;


RESET ROLE;
