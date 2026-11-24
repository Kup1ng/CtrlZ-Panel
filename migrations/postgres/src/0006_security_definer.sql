-- The SECURITY DEFINER allow-list. Spec section 8, R3, R4.
--
-- Every function lives in ctrlz_fn, is owned by ctrlz_auth (the statements run
-- under SET ROLE), pins search_path to pg_catalog and pg_temp, uses static
-- SQL with schema-qualified names, and takes an exact key. None returns a list
-- across tenants. REVOKE ALL FROM PUBLIC, then EXECUTE by role name.
--
-- The OTP caps and lifetimes below are provisional (D31). They are constants
-- here because system_settings has no column for them in the spec; moving them
-- there is a one-line change in each function and a column in that table.

-- +goose Up

SET LOCAL search_path = pg_catalog;
SET ROLE ctrlz_auth;

-- Login. One row per phone; the phone is globally unique.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_user_by_phone(p_phone text)
RETURNS TABLE (tenant_id uuid, user_id uuid, password_hash text, status text,
               totp_enabled boolean, enforce_passkey boolean, must_reset boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT u.tenant_id, u.id, u.password_hash, t.status,
         (u.totp_enabled_at IS NOT NULL), u.enforce_passkey, u.must_reset
  FROM ctrlz.users u
  JOIN ctrlz.tenants t ON t.id = u.tenant_id
  WHERE u.phone_e164 = p_phone
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_user_by_phone(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_user_by_phone(text) TO ctrlz_tenant;

-- The TOTP seed for the check during login, before a session exists.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_totp_seed(p_user_id uuid, p_tenant_id uuid)
RETURNS TABLE (totp_secret_ct bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT u.totp_secret_ct
  FROM ctrlz.users u
  WHERE u.id = p_user_id AND u.tenant_id = p_tenant_id
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_totp_seed(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_totp_seed(uuid, uuid) TO ctrlz_tenant;

-- Each request on a session route.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_session_by_hash(p_hash bytea)
RETURNS TABLE (tenant_id uuid, user_id uuid, session_id uuid, status text,
               idle_expires_at timestamptz, absolute_expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.tenant_id, s.user_id, s.id, t.status,
         s.idle_expires_at, s.absolute_expires_at, s.revoked_at
  FROM ctrlz.sessions s
  JOIN ctrlz.tenants t ON t.id = s.tenant_id
  WHERE s.token_hash = p_hash
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_session_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_session_by_hash(bytea) TO ctrlz_tenant;

-- API token routes.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_token_by_hash(p_hash bytea)
RETURNS TABLE (tenant_id uuid, user_id uuid, token_id uuid, kind text,
               allowed_ips cidr[], status text, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT a.tenant_id, a.user_id, a.id, a.kind, a.allowed_ips, t.status, a.revoked_at
  FROM ctrlz.api_tokens a
  JOIN ctrlz.tenants t ON t.id = a.tenant_id
  WHERE a.token_hash = p_hash
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_token_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_token_by_hash(bytea) TO ctrlz_tenant;

-- Refresh with reuse detection (R44).
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_refresh_by_hash(p_hash bytea)
RETURNS TABLE (tenant_id uuid, user_id uuid, id uuid, family_id uuid,
               rotated_at timestamptz, reuse_grace_until timestamptz,
               expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT r.tenant_id, r.user_id, r.id, r.family_id,
         r.rotated_at, r.reuse_grace_until, r.expires_at, r.revoked_at
  FROM ctrlz.refresh_tokens r
  WHERE r.token_hash = p_hash
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_refresh_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_refresh_by_hash(bytea) TO ctrlz_tenant;

-- The invite page. An invite is global: it has no tenant until accepted.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_invite_by_hash(p_hash bytea)
RETURNS TABLE (id uuid, phone_e164 text, expires_at timestamptz, used_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT i.id, i.phone_e164, i.expires_at, i.used_at, i.revoked_at
  FROM ctrlz.invites i
  WHERE i.token_hash = p_hash
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_invite_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_invite_by_hash(bytea) TO ctrlz_tenant;

-- Passkey login: the credential id arrives before the user is known.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_passkey_by_credential(p_credential_id bytea)
RETURNS TABLE (tenant_id uuid, user_id uuid, id uuid, public_key bytea,
               sign_count bigint, rp_id text, stale_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT w.tenant_id, w.user_id, w.id, w.public_key, w.sign_count, w.rp_id, w.stale_at
  FROM ctrlz.webauthn_credentials w
  WHERE w.credential_id = p_credential_id
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_passkey_by_credential(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_passkey_by_credential(bytea) TO ctrlz_tenant;

-- Registration. Checks registration_mode and the invite, then creates the
-- tenant, its owner and its entitlements row in one step. Every refusal
-- (closed mode, bad invite, taken phone) is the same empty result, so a caller
-- cannot tell which one it was.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_register_user(p_phone text, p_password_hash text, p_locale text, p_invite_id uuid)
RETURNS TABLE (tenant_id uuid, user_id uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_mode        text;
  v_invite_phone text;
  v_tenant      uuid;
  v_user        uuid;
BEGIN
  SELECT s.registration_mode INTO v_mode FROM ctrlz.system_settings s;

  IF p_invite_id IS NOT NULL THEN
    -- Admin invites work in every mode (R44).
    SELECT i.phone_e164 INTO v_invite_phone
    FROM ctrlz.invites i
    WHERE i.id = p_invite_id AND i.used_at IS NULL AND i.revoked_at IS NULL
      AND i.expires_at > pg_catalog.now()
    FOR UPDATE;
    IF v_invite_phone IS NULL OR v_invite_phone <> p_phone THEN
      RETURN;
    END IF;
  ELSIF v_mode IS DISTINCT FROM 'open' THEN
    RETURN;
  END IF;

  BEGIN
    INSERT INTO ctrlz.tenants (id) VALUES (pg_catalog.uuidv7()) RETURNING ctrlz.tenants.id INTO v_tenant;
    INSERT INTO ctrlz.users (tenant_id, phone_e164, password_hash, locale)
    VALUES (v_tenant, p_phone, p_password_hash, COALESCE(p_locale, 'fa'))
    RETURNING ctrlz.users.id INTO v_user;
    INSERT INTO ctrlz.tenant_entitlements (tenant_id) VALUES (v_tenant);
  EXCEPTION WHEN unique_violation THEN
    -- Taken phone. The subtransaction undoes the tenant row as well.
    RETURN;
  END;

  IF p_invite_id IS NOT NULL THEN
    UPDATE ctrlz.invites SET used_at = pg_catalog.now(), accepted_tenant_id = v_tenant
    WHERE id = p_invite_id;
  END IF;

  RETURN QUERY SELECT v_tenant, v_user;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_register_user(text, text, text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_register_user(text, text, text, uuid) TO ctrlz_tenant;

-- Issue an OTP challenge. The counters are bumped in one statement, so two
-- concurrent requests cannot both slip under a cap (R44). A refused request
-- still counts: the cap is on attempts, not on sent messages.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_otp_issue(p_phone text, p_purpose text, p_code_hash bytea, p_delivery_ct bytea, p_ip inet)
RETURNS TABLE (id uuid, allowed boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_day  date := (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date;
  v_over boolean;
  v_id   uuid;
BEGIN
  WITH bump AS (
    INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
    VALUES (v_day, 'phone', p_phone, 1),
           (v_day, 'ip', COALESCE(pg_catalog.host(p_ip), 'unknown'), 1),
           (v_day, 'global', 'all', 1)
    ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1
    RETURNING c.scope, c.count
  )
  SELECT pg_catalog.bool_or(b.count > CASE b.scope WHEN 'phone' THEN 5 WHEN 'ip' THEN 20 ELSE 5000 END)
  INTO v_over
  FROM bump b;

  IF v_over THEN
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END IF;

  INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip)
  VALUES (p_phone, p_purpose, p_code_hash, p_delivery_ct, pg_catalog.now() + interval '5 minutes', p_ip)
  RETURNING ctrlz.otp_challenges.id INTO v_id;

  RETURN QUERY SELECT v_id, true;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_otp_issue(text, text, bytea, bytea, inet) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_otp_issue(text, text, bytea, bytea, inet) TO ctrlz_tenant;

-- Check an OTP. Single use, and five tries per challenge.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_otp_consume(p_id uuid, p_code_hash bytea)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  r record;
BEGIN
  SELECT o.code_hash, o.attempts, o.expires_at, o.consumed_at INTO r
  FROM ctrlz.otp_challenges o
  WHERE o.id = p_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
  ELSIF r.consumed_at IS NOT NULL THEN
    RETURN QUERY SELECT 'consumed'::text;
  ELSIF r.expires_at <= pg_catalog.now() THEN
    RETURN QUERY SELECT 'expired'::text;
  ELSIF r.attempts >= 5 THEN
    RETURN QUERY SELECT 'locked'::text;
  ELSIF r.code_hash = p_code_hash THEN
    UPDATE ctrlz.otp_challenges SET attempts = attempts + 1, consumed_at = pg_catalog.now() WHERE id = p_id;
    RETURN QUERY SELECT 'ok'::text;
  ELSE
    UPDATE ctrlz.otp_challenges SET attempts = attempts + 1 WHERE id = p_id;
    RETURN QUERY SELECT 'invalid'::text;
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_otp_consume(uuid, bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_otp_consume(uuid, bytea) TO ctrlz_tenant;

-- /s/<token>. A revoked token is not returned, because revoked_at is not in
-- the result. api then bumps uses in WithTenant with WHERE uses < max_uses.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_share_by_hash(p_hash bytea)
RETURNS TABLE (tenant_id uuid, endpoint_id uuid, client text, expires_at timestamptz, uses_left integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.tenant_id, s.endpoint_id, s.client, s.expires_at, GREATEST(s.max_uses - s.uses, 0)
  FROM ctrlz.setup_share_tokens s
  WHERE s.token_hash = p_hash AND s.revoked_at IS NULL
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_share_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_share_by_hash(bytea) TO ctrlz_tenant;

-- /p/<token>, the same way.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_download_by_hash(p_hash bytea)
RETURNS TABLE (tenant_id uuid, endpoint_id uuid, params_hash bytea, expires_at timestamptz, uses_left integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT d.tenant_id, d.endpoint_id, d.params_hash, d.expires_at, GREATEST(d.max_uses - d.uses, 0)
  FROM ctrlz.profile_download_tokens d
  WHERE d.token_hash = p_hash
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_download_by_hash(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_download_by_hash(bytea) TO ctrlz_tenant;

-- A tenant's own two DNS addresses without reading node data (R4). The tenant
-- filter is explicit because the auth_pair policy lets this role see every
-- endpoint; with no tenant set, current_tenant_id() is NULL and nothing
-- matches.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.endpoint_pair_ips()
RETURNS TABLE (endpoint_id uuid, primary_dns_ip inet, fallback_dns_ip inet)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT e.id, pn.dns_advertised_ip, fn.dns_advertised_ip
  FROM ctrlz.endpoints e
  CROSS JOIN ctrlz.public_settings ps
  LEFT JOIN ctrlz.node_pairs gp ON gp.id = ps.global_pair_id
  JOIN ctrlz.nodes pn ON pn.id = COALESCE(e.pair_override_node_a, gp.primary_node_id)
  JOIN ctrlz.nodes fn ON fn.id = COALESCE(e.pair_override_node_b, gp.fallback_node_id)
  WHERE e.tenant_id = ctrlz.current_tenant_id()
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.endpoint_pair_ips() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.endpoint_pair_ips() TO ctrlz_tenant, ctrlz_worker;

-- Is a prefix free? The answer is generic: it says nothing about who holds an
-- overlapping claim.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.ip_claim_check(p_cidr cidr)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM ctrlz.ip_claims c
             WHERE c.cidr && p_cidr AND c.state IN ('active', 'grace') AND c.tenant_id <> v_tenant) THEN
    RETURN QUERY SELECT 'unavailable'::text;
  ELSIF EXISTS (SELECT 1 FROM ctrlz.ip_claims c
                WHERE c.cidr && p_cidr AND c.state IN ('active', 'grace') AND c.tenant_id = v_tenant) THEN
    RETURN QUERY SELECT 'own'::text;
  ELSE
    RETURN QUERY SELECT 'available'::text;
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.ip_claim_check(cidr) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.ip_claim_check(cidr) TO ctrlz_tenant;

-- Create a claim. closed and invite modes: active at once when free. open
-- mode: pending_proof, /32 only unless an admin approves a wider prefix. The
-- tenant is the caller's, from the GUC.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.ip_claim_request(p_endpoint_id uuid, p_cidr cidr, p_source text)
RETURNS TABLE (claim_id uuid, outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_mode   text;
  v_id     uuid;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM ctrlz.endpoints e WHERE e.tenant_id = v_tenant AND e.id = p_endpoint_id) THEN
    RETURN QUERY SELECT NULL::uuid, 'not_found'::text;
    RETURN;
  END IF;
  IF pg_catalog.family(p_cidr) <> 4 THEN
    RETURN QUERY SELECT NULL::uuid, 'unsupported'::text;
    RETURN;
  END IF;

  SELECT s.registration_mode INTO v_mode FROM ctrlz.system_settings s;

  IF v_mode = 'open' THEN
    IF pg_catalog.masklen(p_cidr) <> 32 THEN
      RETURN QUERY SELECT NULL::uuid, 'wide_requires_approval'::text;
      RETURN;
    END IF;
    INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source)
    VALUES (v_tenant, p_endpoint_id, p_cidr, 'pending_proof', p_source)
    RETURNING ctrlz.ip_claims.id INTO v_id;
    RETURN QUERY SELECT v_id, 'pending_proof'::text;
  ELSE
    BEGIN
      INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source)
      VALUES (v_tenant, p_endpoint_id, p_cidr, 'active', p_source)
      RETURNING ctrlz.ip_claims.id INTO v_id;
    EXCEPTION WHEN exclusion_violation THEN
      RETURN QUERY SELECT NULL::uuid, 'unavailable'::text;
      RETURN;
    END;
    RETURN QUERY SELECT v_id, 'active'::text;
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.ip_claim_request(uuid, cidr, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.ip_claim_request(uuid, cidr, text) TO ctrlz_tenant, ctrlz_worker;

-- Release the caller's claim.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.ip_claim_release(p_claim_id uuid)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  UPDATE ctrlz.ip_claims c SET state = 'released'
  WHERE c.tenant_id = v_tenant AND c.id = p_claim_id AND c.state <> 'released';
  IF FOUND THEN
    RETURN QUERY SELECT 'released'::text;
  ELSE
    RETURN QUERY SELECT 'not_found'::text;
  END IF;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.ip_claim_release(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.ip_claim_release(uuid) TO ctrlz_tenant;

-- Move the caller's claim to active after proof, applying the takeover rule
-- (D3): an unproven claim is replaced at once; a proven claim only if it has
-- not been seen for takeover_idle_days or its Endpoint is hard_disabled. If
-- any overlapping claim cannot be taken, nothing changes.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.ip_claim_take(p_claim_id uuid, p_method text)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant  uuid := ctrlz.current_tenant_id();
  v_cidr    cidr;
  v_state   text;
  v_idle    integer;
  v_blocked boolean;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  IF p_method IS NULL THEN
    RETURN QUERY SELECT 'invalid_method'::text;
    RETURN;
  END IF;

  SELECT c.cidr, c.state INTO v_cidr, v_state
  FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.id = p_claim_id
  FOR UPDATE;

  IF NOT FOUND OR v_state = 'released' THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  ELSIF v_state = 'active' THEN
    RETURN QUERY SELECT 'already_active'::text;
    RETURN;
  END IF;

  SELECT s.takeover_idle_days INTO v_idle FROM ctrlz.system_settings s;

  SELECT EXISTS (
    SELECT 1
    FROM ctrlz.ip_claims o
    LEFT JOIN ctrlz.endpoints oe ON oe.tenant_id = o.tenant_id AND oe.id = o.endpoint_id
    WHERE o.cidr && v_cidr AND o.state IN ('active', 'grace') AND o.tenant_id <> v_tenant
      AND o.proven_at IS NOT NULL
      AND COALESCE(o.last_seen_at, o.proven_at) >= pg_catalog.now() - pg_catalog.make_interval(days => v_idle)
      AND COALESCE(oe.admin_state, '') <> 'hard_disabled'
  ) INTO v_blocked;

  IF v_blocked THEN
    RETURN QUERY SELECT 'unavailable'::text;
    RETURN;
  END IF;

  BEGIN
    UPDATE ctrlz.ip_claims o SET state = 'released', displaced_at = pg_catalog.now()
    WHERE o.cidr && v_cidr AND o.state IN ('active', 'grace') AND o.tenant_id <> v_tenant;

    UPDATE ctrlz.ip_claims c
    SET state = 'active', proof_method = p_method, proven_at = pg_catalog.now(), grace_until = NULL
    WHERE c.tenant_id = v_tenant AND c.id = p_claim_id;
  EXCEPTION WHEN exclusion_violation THEN
    -- An overlapping claim of the caller's own tenant. The subtransaction
    -- undoes the displacement above.
    RETURN QUERY SELECT 'unavailable'::text;
    RETURN;
  END;

  RETURN QUERY SELECT 'active'::text;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.ip_claim_take(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.ip_claim_take(uuid, text) TO ctrlz_tenant, ctrlz_worker;

RESET ROLE;
