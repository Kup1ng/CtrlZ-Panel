-- P1 auth review round 18, SMS area (sms-r18-2, D64 sms-available-oracle; rule known-unknown-oracle).
--
-- The public flag sms_available of GET /auth/config said "a routed gateway can send NOW": not held
-- (0043, 0046), not blocked (0048) and a closed breaker. Only a real OTP row reaches a gateway, and a
-- row exists only for a phone with an account (a decoy is never delivered), so the breaker and the hold
-- moved for a phone that has an account and for none else. While a gateway was failing, a stranger asked
-- for a code for a phone and watched the flag: if it fell within a pause, the phone has an account. That
-- is one bit of the user list per probe, readable by anyone, sensitive for the people in it, and a
-- stranger can help to cause the failing state (a flood of real-phone requests drains the provider's
-- credit or meets its rate limit, which opens the breaker).
--
-- The channel is the function, so the function is what changes. The public flag is computed from
-- configuration alone: a routed gateway (role primary or fallback, which the admin sets and an
-- administrator who disables a gateway moves to another role) whose credentials exist and open. Nothing
-- a send did reaches it. The internal router keeps its own view (the breaker, the hold, blocked_now) and
-- keeps skipping a gateway that cannot send; what changes is only what a stranger can read. During an
-- outage the login page still offers a code, and a request that cannot be sent ends its row unsent after
-- its three local passes with the caps spent and the key refunded, which is how a failing gateway
-- already ended a row before the flag could say so.
--
-- unusable_now is the part of blocked_now that no send writes: the worker's judgement of the credentials
-- it holds (unusable_ct_sum, written by Source.Load from the key ring and by checkGateways at start,
-- whatever any user asked) and the absence of credentials for a provider that needs them. It is a
-- generated column of the same shape as blocked_now, so every UPDATE of an input recomputes it. It is a
-- boolean, so ctrlz_auth, which may not read the sealed credentials or the digests of them, gets one more
-- column that says nothing about a secret. blocked_now stays for the worker's snapshot (held OR
-- unusable_now); nothing public reads it now.
--
-- Signature, owner, grants and ranks of the function are those of 0048 (body only). A new file and not
-- an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.sms_gateways
  ADD COLUMN unusable_now boolean NOT NULL
    GENERATED ALWAYS AS (
      COALESCE(unusable_ct_sum = pg_catalog.sha256(COALESCE(credentials_ct, ''::pg_catalog.bytea)), false)
      OR (credentials_ct IS NULL AND provider <> 'noop')
    ) STORED;

GRANT SELECT (unusable_now) ON ctrlz.sms_gateways TO ctrlz_auth;

-- Nothing the definer role runs reads the breaker or blocked_now any more, so it loses them: what a
-- role can read is what its functions need (rule role-reach), and a column that tells whether sends
-- failed is the very thing this migration takes out of the public path.
REVOKE SELECT (breaker_open_until, blocked_now) ON ctrlz.sms_gateways FROM ctrlz_auth;

SET ROLE ctrlz_auth;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_public_config()
RETURNS TABLE (registration_mode text, panel_host text, rp_id text, allowed_origins text[],
               passkey_enabled boolean, sms_available boolean, otp_cooldown_s integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.registration_mode, d.panel_host, w.rp_id, w.allowed_origins,
         w.enabled AND w.rp_id IS NOT NULL,
         EXISTS (SELECT 1 FROM ctrlz.sms_gateways g
                 WHERE g.role IN ('primary', 'fallback')
                   AND NOT g.unusable_now),
         s.otp_cooldown_s
  FROM ctrlz.system_settings s, ctrlz.domain_settings d, ctrlz.webauthn_config w
$$;
-- +goose StatementEnd

RESET ROLE;
