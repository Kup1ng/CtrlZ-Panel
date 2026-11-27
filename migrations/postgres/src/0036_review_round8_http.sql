-- P1 auth review round 8, HTTP spine and tenant API area (tenant-r8-2).
--
-- tenant-r8-2: system_settings.otp_cooldown_s is an admin setting (10 to 3600 seconds), and no function
-- gave it to the api, so the 202 of POST /auth/otp/request, of POST /auth/reauth/otp/request and of
-- POST /account/phone/change said resend_after_s = 60 and the 429 otp_limited said Retry-After: 60 for
-- every cooldown the owner chose. A dashboard that enables Resend after 60 seconds on a 300 second
-- cooldown sends the user into a refusal for four more minutes, and one that waits 60 on a 30 second
-- cooldown makes the user wait twice as long as needed.
--
-- auth_public_config is the one function the api already reads for the login page and caches for 30
-- seconds; the cooldown is one more column of it, the same for every phone, so it says nothing about
-- an account. The column comes last so the Go struct keeps its scan order. The function changes its
-- result row, which CREATE OR REPLACE refuses, so it is dropped and made again, and a dropped function
-- loses its grants.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

SET ROLE ctrlz_auth;

DROP FUNCTION ctrlz_fn.auth_public_config();

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_public_config()
RETURNS TABLE (registration_mode text, panel_host text, rp_id text, allowed_origins text[],
               passkey_enabled boolean, sms_available boolean, otp_cooldown_s integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.registration_mode, d.panel_host, w.rp_id, w.allowed_origins,
         w.enabled AND w.rp_id IS NOT NULL,
         EXISTS (SELECT 1 FROM ctrlz.sms_gateways g
                 WHERE g.role IN ('primary', 'fallback')
                   AND (g.breaker_open_until IS NULL OR g.breaker_open_until < pg_catalog.now())),
         s.otp_cooldown_s
  FROM ctrlz.system_settings s, ctrlz.domain_settings d, ctrlz.webauthn_config w
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_public_config() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_public_config() TO ctrlz_tenant;

RESET ROLE;
