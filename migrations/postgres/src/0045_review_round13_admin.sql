-- P1 auth review round 13, admin area (admin-r13-3). Rule key-identity (rules.md topic 23): a key tool
-- decides which seeds are lost by opening them, never by a key number.
--
-- `ctrlz declare-lost user_totp --key-number N` refused while ANY seed naming N opened, and then
-- cleared EVERY seed naming N (0017). After a total loss (spec 8.5) the regenerated kek_user_totp
-- starts again at number 1, the number of the lost seeds, and the stack must run on the new files, so
-- one user who enrols before the operator runs the tool gets a seed under the new key 1 that opens.
-- From then on the tool refused for ever and rekey cannot open the old seeds: no command could clear
-- them and their users could not complete TOTP.
--
-- The function now takes the seeds the tool proved lost: user ids and the ciphertexts it read and
-- could not open with the key ring. It clears a row only when that row still holds exactly that
-- ciphertext (a seed enrolled or re-sealed meanwhile is kept, so a seed that opens is never cleared)
-- and still names key N in its header (the number is a check on the tool's input, no longer the
-- decision). It still writes the tenant's notice and audit row in the same statement and still
-- belongs to ctrlz_keytool alone. The old signature, which cleared by number, is dropped so that no
-- caller can reach the whole-number clear.
--
-- A new file and not an edit of 0017 (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- The functions of ctrlz_fn are owned by ctrlz_auth (0017, 0039).
SET ROLE ctrlz_auth;

DROP FUNCTION ctrlz_fn.keytool_totp_declare_lost(integer);

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.keytool_totp_declare_lost(p_key_number integer, p_user_ids uuid[], p_cts bytea[])
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_n      integer;
BEGIN
  IF v_tenant IS NULL OR p_key_number IS NULL OR p_key_number NOT BETWEEN 1 AND 65535
     OR p_user_ids IS NULL OR p_cts IS NULL
     OR pg_catalog.cardinality(p_user_ids) <> pg_catalog.cardinality(p_cts)
     OR pg_catalog.cardinality(p_user_ids) = 0 THEN
    RETURN 0;
  END IF;
  IF pg_catalog.cardinality(p_user_ids) > 1000 THEN
    RAISE EXCEPTION 'keytool_totp_declare_lost: at most 1000 seeds per call' USING ERRCODE = '22023';
  END IF;
  -- Header: 'C' 'Z', format version 1, then the key number as two bytes (keyring).
  UPDATE ctrlz.users u
     SET totp_secret_ct = NULL, totp_enabled_at = NULL, totp_last_step = NULL
   WHERE u.tenant_id = v_tenant AND u.id = ANY (p_user_ids) AND u.totp_enabled_at IS NOT NULL
     AND u.totp_secret_ct IS NOT NULL
     -- The ciphertext listed for this user (the first position of its id) is still the one stored.
     AND u.totp_secret_ct = p_cts[pg_catalog.array_position(p_user_ids, u.id)]
     AND pg_catalog.octet_length(u.totp_secret_ct) >= 5
     AND pg_catalog.get_byte(u.totp_secret_ct, 0) = 67
     AND pg_catalog.get_byte(u.totp_secret_ct, 1) = 90
     AND pg_catalog.get_byte(u.totp_secret_ct, 2) = 1
     AND pg_catalog.get_byte(u.totp_secret_ct, 3) * 256 + pg_catalog.get_byte(u.totp_secret_ct, 4) = p_key_number;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n > 0 THEN
    INSERT INTO ctrlz.notifications (tenant_id, kind, severity, params)
    VALUES (v_tenant, 'totp_lost', 'warning', '{}');
    INSERT INTO ctrlz.tenant_audit_log (tenant_id, user_id, action, target, params)
    VALUES (v_tenant, NULL, 'totp.declared_lost', NULL,
            pg_catalog.jsonb_build_object('key_number', p_key_number, 'users', v_n));
  END IF;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(integer, uuid[], bytea[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.keytool_totp_declare_lost(integer, uuid[], bytea[]) TO ctrlz_keytool;

RESET ROLE;
