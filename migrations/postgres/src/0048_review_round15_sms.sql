-- P1 auth review round 15, SMS area (sms-r15-1, sms-r15-4).
--
-- Round 14 (0046) made auth_public_config read held_now, so a gateway the provider refused no
-- longer turns sms_available true again each time its breaker pause lapses. That closed the held
-- half of a class and left the rest of it: a routed gateway the router passes over locally without
-- a call, because the worker cannot build a sender for it (credentials that no key opens, none
-- stored, a noop row in production, a provider nobody knows, credentials that do not parse). The
-- outcome is known in advance, but only the breaker timestamp reached the database, and the only
-- thing that opens that breaker without a user's send runs once, at worker start. So 60 s later the
-- flag read true again, the next user was told 202 for a code that could not be sent (the row ends
-- unsent after three local passes, with the phone and network caps spent), and the breaker stepped
-- again for twice as long, at every pause, for as long as the key stayed wrong.
--
-- There were two answers to "can this gateway send": the worker's in-memory Source (decided in Go,
-- from the key ring) and this table. The fix is one place the database can read. The worker writes
-- what it decided against the ciphertext it judged, the way held_ct_sum names the ciphertext of a
-- hold:
--
--   unusable_ct_sum  the SHA-256 of credentials_ct (of the empty string when there is none) for
--                    which the worker could not build a sender. It counts only while it names the
--                    credentials the row has now, so saving other credentials ends it with no write.
--
-- blocked_now generalises held_now (dropped here, 0046 added it): the gateway cannot send for the
-- credentials it has now, whatever the reason. It is a generated column, so every UPDATE of any
-- input recomputes it:
--
--   held                the hold of a refused login still names the credentials (0043, 0046)
--   unusable            the worker's judgement still names them
--   no credentials      credentials_ct IS NULL for a provider other than noop; the database needs
--                       no worker to know this one (the noop provider takes none)
--
-- auth_public_config reads blocked_now and nothing else of the three, so a new reason a gateway can
-- be unusable for is a new input of this one column and not a new term to remember in a function.
--
-- A new file and not an edit of an applied one (README, Rules). No existing row is blocked by
-- unusable_ct_sum; the worker writes it on its first load.

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.sms_gateways
  ADD COLUMN unusable_ct_sum bytea CHECK (octet_length(unusable_ct_sum) = 32);

-- The worker records its judgement and takes it back when a build works again (a fixed key, a
-- restart outside production for a noop row). It writes nothing else new.
GRANT UPDATE (unusable_ct_sum) ON ctrlz.sms_gateways TO ctrlz_worker;

ALTER TABLE ctrlz.sms_gateways
  ADD COLUMN blocked_now boolean NOT NULL
    GENERATED ALWAYS AS (
      COALESCE(held_ct_sum = pg_catalog.sha256(credentials_ct), false)
      OR COALESCE(unusable_ct_sum = pg_catalog.sha256(COALESCE(credentials_ct, ''::pg_catalog.bytea)), false)
      OR (credentials_ct IS NULL AND provider <> 'noop')
    ) STORED;

-- ctrlz_auth reads a boolean that says nothing about a secret, as it read held_now.
GRANT SELECT (blocked_now) ON ctrlz.sms_gateways TO ctrlz_auth;

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
                   AND NOT g.blocked_now
                   AND (g.breaker_open_until IS NULL OR g.breaker_open_until < pg_catalog.now())),
         s.otp_cooldown_s
  FROM ctrlz.system_settings s, ctrlz.domain_settings d, ctrlz.webauthn_config w
$$;
-- +goose StatementEnd

RESET ROLE;

-- Nothing reads held_now any more: the function above was its only reader, and a second column that
-- says a part of the same thing is the second source of truth this migration removes. The grant
-- goes with the column.
ALTER TABLE ctrlz.sms_gateways DROP COLUMN held_now;
