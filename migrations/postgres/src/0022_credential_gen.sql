-- P1 auth review round 5, rule credential-generation (topics db-r1-1, db-r1-7,
-- tenant-r1-14, admin-r3-2, admin-r3-14, tenant-r4-5, admin-r4-4;
-- migrations/catalog/guarded.yaml credential_gen, catalog check 25).
--
-- Until now there was no single version of a subject's credentials. Every consumer
-- of a past verification (the login after Argon2, the admin login, the rehash guard,
-- the reauth hash lookup, the two device markers) compared a hand-picked list of
-- fields with the locked row, and each list missed a field, the subject, or the whole
-- check. Now users and admin_users carry credential_gen, a counter that a trigger
-- moves whenever a credential column changes, whoever writes. An artefact derived
-- from a first-factor check carries the (subject, generation) it came from and is
-- refused when the row says otherwise (internal/credgen).
--
--   1. credential_gen on users and admin_users, bigint NOT NULL starting at 1. No
--      login role may write it (guarded.yaml `write`: it is not a free column and
--      not declared), and the trigger overwrites whatever a statement puts there, so
--      the only way it moves is a change of a credential column.
--   2. ctrlz.credential_gen_bump, one trigger function for both tables. The columns it
--      watches are its arguments, so the trigger definition is the single list, and
--      catalog check 25 compares it with guarded.yaml. It compares the old and new
--      values of each column as jsonb, so it needs no list of types and a column added
--      to the list needs no change to the function. A name that is not a column of the
--      table raises on the first UPDATE, so a typo cannot silently watch nothing.
--      The trigger has no WHEN clause and no column list: either would let a write skip
--      it. A rehash changes password_hash and so moves the generation; the writer
--      (store.Tx.RehashPassword) carries the generation it was given and hands back
--      the new one.
--   3. auth_tickets.subject_gen: an mfa ticket is made with the generation of the
--      first factor it comes from, and the function that reads it hands it back
--      (the three ticket functions change, so they are dropped and made again, and
--      granted again). A ticket without one never holds.
--   4. auth_user_by_phone returns credential_gen, so the login that verifies a
--      password outside any transaction knows which generation it verified.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.users       ADD COLUMN credential_gen bigint NOT NULL DEFAULT 1;
ALTER TABLE ctrlz.admin_users ADD COLUMN credential_gen bigint NOT NULL DEFAULT 1;

GRANT SELECT (credential_gen) ON ctrlz.users TO ctrlz_tenant, ctrlz_auth;

-- +goose StatementBegin
CREATE FUNCTION ctrlz.credential_gen_bump() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  o jsonb := pg_catalog.to_jsonb(OLD);
  n jsonb := pg_catalog.to_jsonb(NEW);
  c text;
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
      NEW.credential_gen := OLD.credential_gen + 1;
      EXIT;
    END IF;
  END LOOP;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.credential_gen_bump() FROM PUBLIC;

CREATE TRIGGER credential_gen_bump BEFORE UPDATE ON ctrlz.users
  FOR EACH ROW EXECUTE FUNCTION ctrlz.credential_gen_bump(
    'phone_e164', 'password_hash', 'password_changed_at', 'password_expires_at', 'must_reset',
    'totp_secret_ct', 'totp_enabled_at', 'enforce_passkey', 'enforce_lift_at');
CREATE TRIGGER credential_gen_bump BEFORE UPDATE ON ctrlz.admin_users
  FOR EACH ROW EXECUTE FUNCTION ctrlz.credential_gen_bump(
    'username', 'password_hash', 'password_changed_at', 'password_expires_at', 'must_change_password',
    'totp_secret_ct', 'totp_enabled_at', 'disabled_at');

-- No generation is a stamp that never holds (internal/credgen), so an mfa ticket without
-- one is refused when it is spent whatever wrote it; ticket.Service.Put refuses to make
-- one. Open mfa tickets are deleted: they have no generation, and they live five minutes.
DELETE FROM ctrlz.auth_tickets WHERE kind = 'mfa';
ALTER TABLE ctrlz.auth_tickets ADD COLUMN subject_gen bigint;

SET ROLE ctrlz_auth;

DROP FUNCTION ctrlz_fn.auth_ticket_put(bytea, text, uuid, uuid, boolean, text, bytea, integer);
DROP FUNCTION ctrlz_fn.auth_ticket_peek(bytea, text);
DROP FUNCTION ctrlz_fn.auth_ticket_take(bytea, text);
DROP FUNCTION ctrlz_fn.auth_user_by_phone(text);

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_ticket_put(p_token_hash bytea, p_kind text, p_tenant uuid, p_user uuid, p_remember boolean,
                                         p_first_factor text, p_payload bytea, p_ttl_seconds integer, p_subject_gen bigint)
RETURNS TABLE (id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_token_hash IS NULL OR p_ttl_seconds IS NULL OR p_ttl_seconds < 1 THEN
    RETURN;
  END IF;
  RETURN QUERY
  INSERT INTO ctrlz.auth_tickets AS t (token_hash, kind, subject_tenant, subject_user, remember_me, first_factor, payload,
                                       expires_at, subject_gen)
  VALUES (p_token_hash, p_kind, p_tenant, p_user, COALESCE(p_remember, false), p_first_factor, p_payload,
          pg_catalog.now() + pg_catalog.make_interval(secs => LEAST(p_ttl_seconds, 600)), p_subject_gen)
  RETURNING t.id;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_ticket_put(bytea, text, uuid, uuid, boolean, text, bytea, integer, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_ticket_put(bytea, text, uuid, uuid, boolean, text, bytea, integer, bigint) TO ctrlz_tenant;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_ticket_peek(p_token_hash bytea, p_kind text)
RETURNS TABLE (subject_tenant uuid, subject_user uuid, remember_me boolean, first_factor text, payload bytea, subject_gen bigint)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_tickets t SET attempts = t.attempts + 1
  WHERE t.token_hash = p_token_hash AND t.kind = p_kind
    AND t.consumed_at IS NULL AND t.expires_at > pg_catalog.now() AND t.attempts < 5
  RETURNING t.subject_tenant, t.subject_user, t.remember_me, t.first_factor, t.payload, t.subject_gen
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_ticket_peek(bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_ticket_peek(bytea, text) TO ctrlz_tenant;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_ticket_take(p_token_hash bytea, p_kind text)
RETURNS TABLE (subject_tenant uuid, subject_user uuid, remember_me boolean, first_factor text, payload bytea, subject_gen bigint)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_tickets t SET consumed_at = pg_catalog.now()
  WHERE t.token_hash = p_token_hash AND t.kind = p_kind
    AND t.consumed_at IS NULL AND t.expires_at > pg_catalog.now()
  RETURNING t.subject_tenant, t.subject_user, t.remember_me, t.first_factor, t.payload, t.subject_gen
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_ticket_take(bytea, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_ticket_take(bytea, text) TO ctrlz_tenant;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_user_by_phone(p_phone text)
RETURNS TABLE (tenant_id uuid, user_id uuid, password_hash text, status text,
               totp_enabled boolean, enforce_passkey boolean, must_reset boolean,
               enforce_lift_at timestamptz, password_expires_at timestamptz,
               password_changed_at timestamptz, password_expired boolean, credential_gen bigint)
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
         COALESCE(v_expired, false), u.credential_gen
  FROM ctrlz.users u
  JOIN ctrlz.tenants t ON t.id = u.tenant_id
  WHERE u.phone_e164 = p_phone;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_user_by_phone(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_user_by_phone(text) TO ctrlz_tenant;

RESET ROLE;
