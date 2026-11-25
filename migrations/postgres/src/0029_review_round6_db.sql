-- P1 auth review round 6, area database, roles and store (findings db-r6-4, db-r6-5, db-r6-7).
--
-- 1. credential_gen_bump (db-r6-4). A change of the sealed seed (totp_secret_ct) moved
--    credential_gen whenever the ciphertext changed, so a re-seal under a new key (`ctrlz
--    rekey user_totp`, `rekey admin_totp`) ended every mfa ticket and device marker of every
--    TOTP account at once, though the account has the same second factor. When
--    totp_enabled_at is set and the same on both sides, the second factor in force is the
--    same one, and a different ciphertext can only be a re-seal; the generation stays. Every
--    other way the factor changes moves totp_enabled_at (enrolment confirm, disable, declare
--    lost, an admin's reset), and that column is still watched. The rule is written in the
--    function, not in the trigger's argument list, so the list stays the one list of
--    credential columns (check 25).
--
-- 2. auth_phone_mark_verified (db-r6-5, db-r6-7). The function returned 'ok' for a verified
--    phone before it looked at the code at all, so nothing bound a login by SMS code, or the
--    reset ticket made from one, to the phone the user has NOW. A phone change commits
--    (phone_e164 moves, sessions and tickets are revoked), and an attacker who held the old
--    number and had passed OTP.Check a moment before still opened a session or minted a reset
--    ticket from the code for the number the user had just left. Now the code must be a
--    consumed login or reset code for the locked row's phone, always, and only then does the
--    function answer: 'invalid' (not this phone's code: the caller refuses), 'ok' (the phone
--    is verified, now or already) or 'stale' (the code is for this phone but older than ten
--    minutes, so the phone is not marked; a reset ticket outlives that window and goes on).
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz.credential_gen_bump() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  o jsonb := pg_catalog.to_jsonb(OLD);
  n jsonb := pg_catalog.to_jsonb(NEW);
  c text;
  -- The second factor is the same one when it was in force and still is, at the same moment.
  v_same_factor boolean := pg_catalog.jsonb_exists(o, 'totp_enabled_at')
    AND pg_catalog.jsonb_typeof(o -> 'totp_enabled_at') IS DISTINCT FROM 'null'
    AND o -> 'totp_enabled_at' = n -> 'totp_enabled_at';
BEGIN
  FOREACH c IN ARRAY TG_ARGV LOOP
    IF NOT pg_catalog.jsonb_exists(n, c) THEN
      RAISE EXCEPTION 'credential_gen_bump: % is not a column of %', c, TG_TABLE_NAME;
    END IF;
  END LOOP;
  -- Whatever the statement wrote into credential_gen is replaced: the counter moves
  -- by this function and by nothing else.
  NEW.credential_gen := OLD.credential_gen;
  FOREACH c IN ARRAY TG_ARGV LOOP
    IF o -> c IS DISTINCT FROM n -> c THEN
      IF c = 'totp_secret_ct' AND v_same_factor THEN
        CONTINUE; -- a re-seal of the seed in force (db-r6-4)
      END IF;
      NEW.credential_gen := OLD.credential_gen + 1;
      EXIT;
    END IF;
  END LOOP;
  RETURN NEW;
END
$$;
-- +goose StatementEnd

SET ROLE ctrlz_auth;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_phone_mark_verified(p_user_id uuid, p_otp_id uuid)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant   uuid := ctrlz.current_tenant_id();
  v_phone    text;
  v_verified timestamptz;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;

  SELECT u.phone_e164, u.phone_verified_at INTO v_phone, v_verified
  FROM ctrlz.users u
  WHERE u.tenant_id = v_tenant AND u.id = p_user_id
  FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  -- The code must be for the phone the locked row has now, whether or not the phone is
  -- verified yet: a code for the number the user has since left proves nothing about the
  -- account (db-r6-7).
  PERFORM 1 FROM ctrlz.otp_challenges o
  WHERE o.id = p_otp_id AND o.phone_e164 = v_phone AND o.purpose IN ('login', 'reset')
    AND o.consumed_at IS NOT NULL;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;
  IF v_verified IS NOT NULL THEN
    RETURN QUERY SELECT 'ok'::text;
    RETURN;
  END IF;

  -- Marking the phone verified needs a code that was spent just now.
  PERFORM 1 FROM ctrlz.otp_challenges o
  WHERE o.id = p_otp_id AND o.consumed_at > pg_catalog.now() - interval '10 minutes';
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'stale'::text;
    RETURN;
  END IF;

  UPDATE ctrlz.users u SET phone_verified_at = pg_catalog.now()
  WHERE u.tenant_id = v_tenant AND u.id = p_user_id AND u.phone_verified_at IS NULL;
  RETURN QUERY SELECT 'ok'::text;
END
$$;
-- +goose StatementEnd

RESET ROLE;
