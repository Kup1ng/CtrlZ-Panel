-- P1 auth review round 7, database area (db-r7-1, db-r7-4).
--
-- db-r7-1: admin_account_bootstrap decides "only while there is no admin" with
-- INSERT ... WHERE NOT EXISTS (SELECT 1 FROM admin_users). Under READ COMMITTED two overlapping
-- calls do not see each other's uncommitted row, so both insert and the console gets two admins,
-- each with a live 24 hour password. The documented contract was "the caller runs it
-- Serializable" (spec 10.1), kept by the one caller and checked by nothing. The function now
-- refuses any other isolation level itself (SQLSTATE 25000, a defect of the caller, never a
-- retry), so a caller that drops the option, a new helper or a test fails on its first run
-- instead of racing on a day nobody watches. Under SERIALIZABLE the two statements form a
-- read-write cycle and one of them gets 40001, which the caller already retries.
--
-- db-r7-4: since 0029 the trigger skipped the credential generation for ANY change of
-- totp_secret_ct while the second factor stayed in force. It read the shape of the write and
-- could not tell a re-seal under another key from a new seed, and ctrlz_tenant and ctrlz_admin
-- both hold UPDATE (totp_secret_ct), so any statement of theirs that replaced a live seed left
-- every mfa ticket and device marker of the account standing. The exemption is bound to the
-- writer now: only a statement run as ctrlz_auth (the owner of the definer functions, whose
-- bodies are the re-seals: keytool_totp_replace and admin_totp_replace below) skips the bump.
-- Any other role, and the table owner or a superuser at a console, moves the generation for a
-- live seed that changed, as it did before 0029. The admin's rekey was a direct UPDATE as
-- ctrlz_admin; it is a definer function like the user side, so it keeps the exemption.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- The trigger function is the migrator's, as 0022 and 0029 made it.
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
  -- A re-seal is something the definer functions of ctrlz_auth do, and nobody else: the
  -- trigger runs as the role that ran the statement, so current_user is ctrlz_auth inside
  -- them and the caller's own role everywhere else (db-r7-4).
  v_resealer boolean := current_user = 'ctrlz_auth';
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
      IF c = 'totp_secret_ct' AND v_same_factor AND v_resealer THEN
        CONTINUE; -- a re-seal of the seed in force, by a function written for it (db-r6-4)
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

-- CREATE OR REPLACE keeps the owner and the grant to ctrlz_admin.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.admin_account_bootstrap(p_username text, p_password_hash text)
RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_id uuid;
BEGIN
  IF pg_catalog.current_setting('transaction_isolation') <> 'serializable' THEN
    RAISE EXCEPTION 'admin_account_bootstrap runs only in a SERIALIZABLE transaction' USING ERRCODE = '25000';
  END IF;
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

-- The rekey swap of the admin's own seed (spec 8.4), the counterpart of keytool_totp_replace. The
-- old value is compared, so a seed the admin changed in the meantime is not overwritten, and
-- the new one must be a plausible ciphertext, never NULL: a swap cannot switch the second factor
-- off. Run as ctrlz_auth, it is the one writer whose change of a seed in force leaves the
-- credential generation alone.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.admin_totp_replace(p_admin_id uuid, p_old bytea, p_new bytea)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_admin_id IS NULL OR p_old IS NULL OR p_new IS NULL
     OR pg_catalog.octet_length(p_new) < 4 OR pg_catalog.octet_length(p_new) > 4096 THEN
    RETURN false;
  END IF;
  UPDATE ctrlz.admin_users a SET totp_secret_ct = p_new
   WHERE a.id = p_admin_id AND a.totp_secret_ct = p_old;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n = 1;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.admin_totp_replace(uuid, bytea, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.admin_totp_replace(uuid, bytea, bytea) TO ctrlz_admin;

RESET ROLE;
