-- Second review round on the database layer. A new file and not an edit of
-- 0006 to 0008, because a migration that has been applied anywhere is never
-- edited (README, Rules).
--
--  1. Proof evidence says how the hub saw the address (observed_protocol), and
--     a UDP observation proves nothing without the TXT code. ip_claim_take
--     takes the code, decides the proof method from the evidence, and counts
--     wrong codes (NEW-1, L1-F01).
--  2. The tenant no longer writes the challenge table at all. A function opens
--     a challenge and sets its label and its lifetime (NEW-2).
--  3. A wide claim displaces only the claims that contain the address it
--     proved (NEW-3).
--  4. Suspended claims cannot be released or re-requested around the admin
--     (NEW-4). Address classes are limited (L1-F19).
--  5. OTP: a per-source sub-cap and a resend cooldown (L1-F03).
--  6. The tenant can no longer change its phone by a column write (the phone
--     change gets a function in P1).
--  7. Small corrections: nodes.resolve_mode says hybrid (L1-F14), the profile 2
--     CHECKs on clients and schedule_windows (L1-F20), limits on the block page
--     text and its unblock link (L2-F19).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- Tables, as the owner. ------------------------------------------------------------------

-- The hub writes these four columns from a ProofObservation. observed_protocol
-- is the transport the query arrived on; txt_code_hash is the SHA-256 of the
-- TXT code the hub derived for that label and source address (contract 3.5).
-- The code itself is never stored.
ALTER TABLE ctrlz.ip_proof_challenges
  ADD COLUMN observed_protocol text,
  ADD COLUMN attempts integer NOT NULL DEFAULT 0;

ALTER TABLE ctrlz.ip_proof_challenges
  ADD CONSTRAINT ip_proof_challenges_protocol CHECK (observed_protocol IN ('udp', 'tcp', 'dot', 'doh', 'doq')),
  ADD CONSTRAINT ip_proof_challenges_attempts CHECK (attempts >= 0),
  ADD CONSTRAINT ip_proof_challenges_code_len CHECK (txt_code_hash IS NULL OR octet_length(txt_code_hash) = 32),
  -- An observation is one fact: when, from where, over what.
  ADD CONSTRAINT ip_proof_challenges_observed_together CHECK (
    (observed_at IS NULL) = (observed_ip IS NULL) AND (observed_at IS NULL) = (observed_protocol IS NULL)),
  -- A UDP source address can be spoofed, so a UDP observation is worth nothing
  -- unless the code that went to the real address is on file to be compared.
  ADD CONSTRAINT ip_proof_challenges_udp_has_code CHECK (observed_protocol IS DISTINCT FROM 'udp' OR txt_code_hash IS NOT NULL),
  -- The lifetime of the evidence is not the tenant's to choose.
  ADD CONSTRAINT ip_proof_challenges_lifetime CHECK (expires_at <= created_at + interval '15 minutes');

-- The shared contract and the proto call the third resolve mode hybrid. A
-- different word in the table would need a mapping in the compiler, and a wrong
-- mapping sends a node the wrong mode.
ALTER TABLE ctrlz.nodes DROP CONSTRAINT nodes_resolve_mode_check;
UPDATE ctrlz.nodes SET resolve_mode = 'hybrid' WHERE resolve_mode = 'mixed';
ALTER TABLE ctrlz.nodes ADD CONSTRAINT nodes_resolve_mode_check CHECK (resolve_mode IN ('recursive', 'upstream', 'hybrid'));

-- endpoints has had this since 0003. Profile 2 without Profile 1, or equal to
-- it, would reach the compiler as a stack that differs from what the UI showed.
ALTER TABLE ctrlz.clients ADD CONSTRAINT clients_profiles_differ
  CHECK (profile2_id IS NULL OR (profile_id IS NOT NULL AND profile2_id <> profile_id));
ALTER TABLE ctrlz.schedule_windows ADD CONSTRAINT schedule_windows_profiles_differ
  CHECK (profile2_id IS NULL OR profile2_id <> profile_id);

-- A block page is served under the block root for a blocked domain, so its
-- text is bounded and its unblock link can only be an https URL with a host
-- and no user part. The limits are the ones of wire.ValidateBlockPage (counted
-- in characters), so a row that passes here is a record that passes there.
ALTER TABLE ctrlz.block_pages ADD CONSTRAINT block_pages_limits CHECK (
  char_length(title) <= 120 AND char_length(message) <= 2000
  AND (unblock_url IS NULL
       OR (char_length(unblock_url) <= 2048
           AND unblock_url ~ '^https://[^[:space:][:cntrl:]@/]+(/[^[:space:][:cntrl:]]*)?$')));

-- The per-(phone, source network) sub-cap needs a scope of its own.
ALTER TABLE ctrlz.sms_counters DROP CONSTRAINT sms_counters_scope_check;
ALTER TABLE ctrlz.sms_counters ADD CONSTRAINT sms_counters_scope_check CHECK (scope IN ('phone', 'phone_net', 'ip', 'global'));

-- Grants, as the table owner. ------------------------------------------------------------

-- The tenant opens a challenge through ctrlz_fn.ip_claim_open_challenge, which
-- picks the label and the expiry. Before, it inserted the row itself and chose
-- expires_at without limit, so proof of an address never went stale.
REVOKE INSERT ON ctrlz.ip_proof_challenges FROM ctrlz_tenant;

-- It reads the state of its challenges, but not txt_code_hash (the hash is the
-- value to guess) and not observed_ip (a spoofed UDP query would show an
-- attacker whose address the hub saw).
REVOKE SELECT ON ctrlz.ip_proof_challenges FROM ctrlz_tenant;
GRANT SELECT (tenant_id, id, claim_id, label, observed_at, observed_protocol, attempts, expires_at, consumed_at, created_at)
  ON ctrlz.ip_proof_challenges TO ctrlz_tenant;

-- The hub records what a ProofObservation said, inside WithTenant. It reads
-- enough to refuse a second observation of the same label or one after expiry.
REVOKE SELECT, UPDATE ON ctrlz.ip_proof_challenges FROM ctrlz_hub;
GRANT SELECT (tenant_id, id, label, observed_at, expires_at, consumed_at) ON ctrlz.ip_proof_challenges TO ctrlz_hub;
GRANT UPDATE (observed_at, observed_ip, observed_protocol, txt_code_hash) ON ctrlz.ip_proof_challenges TO ctrlz_hub;

-- The functions below run as ctrlz_auth: open_challenge inserts, take reads the
-- evidence and counts wrong codes.
GRANT INSERT (tenant_id, claim_id, label, expires_at) ON ctrlz.ip_proof_challenges TO ctrlz_auth;
GRANT UPDATE (attempts) ON ctrlz.ip_proof_challenges TO ctrlz_auth;

-- A phone number is the identity (D23) and changing it needs a verified OTP for
-- the old and the new number. A column write needs neither. P1 adds the
-- SECURITY DEFINER function that does it.
REVOKE UPDATE (phone_e164, phone_verified_at) ON ctrlz.users FROM ctrlz_tenant;

-- Functions, as ctrlz_auth. --------------------------------------------------------------

SET ROLE ctrlz_auth;

-- Issue an OTP challenge. As in 0008, plus two limits on one source:
--
--  * at most 3 messages per (phone, source network) a day, so one address
--    cannot spend the phone's whole quota of 5 on somebody else's number;
--  * one message per (phone, purpose) per 60 seconds.
--
-- Both count messages sent, like the other caps: the checks run in the same
-- subtransaction as the counters, so a refusal leaves every counter alone. The
-- numbers are provisional (D31).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_otp_issue(p_phone text, p_purpose text, p_code_hash bytea, p_delivery_ct bytea, p_ip inet)
RETURNS TABLE (id uuid, allowed boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_day    date := (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date;
  v_ip     inet := p_ip;
  v_net    text;
  v_scopes text[];
  v_keys   text[];
  v_caps   integer[];
  v_id     uuid;
  v_n      integer;
  i        integer;
BEGIN
  IF p_phone IS NULL OR p_phone !~ '^\+[1-9][0-9]{7,14}$'
     OR p_purpose IS NULL OR p_purpose NOT IN ('login', 'signup', 'invite', 'reset', 'phone_old', 'phone_new')
     OR p_code_hash IS NULL OR p_ip IS NULL THEN
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END IF;

  -- ::ffff:a.b.c.d and a.b.c.d are one client.
  IF pg_catalog.family(v_ip) = 6 AND v_ip << '::ffff:0:0/96'::inet THEN
    v_ip := '0.0.0.0'::inet + (v_ip - '::ffff:0.0.0.0'::inet);
  END IF;

  IF pg_catalog.family(v_ip) = 4 THEN
    v_net    := pg_catalog.network(pg_catalog.set_masklen(v_ip, 24))::text;
    v_scopes := ARRAY['ip', 'ip'];
    v_keys   := ARRAY[pg_catalog.host(v_ip), v_net];
    v_caps   := ARRAY[20, 100];
  ELSE
    v_net    := pg_catalog.network(pg_catalog.set_masklen(v_ip, 64))::text;
    v_scopes := ARRAY['ip'];
    v_keys   := ARRAY[v_net];
    v_caps   := ARRAY[20];
  END IF;
  v_scopes := v_scopes || ARRAY['phone_net', 'phone', 'global'];
  v_keys   := v_keys   || ARRAY[p_phone || '|' || v_net, p_phone, 'all'];
  v_caps   := v_caps   || ARRAY[3, 5, 5000];

  BEGIN
    -- The cooldown reads challenges, which exist only for messages sent.
    IF EXISTS (SELECT 1 FROM ctrlz.otp_challenges o
               WHERE o.phone_e164 = p_phone AND o.purpose = p_purpose
                 AND o.created_at > pg_catalog.now() - interval '60 seconds') THEN
      RAISE EXCEPTION 'cooldown' USING ERRCODE = 'P0001';
    END IF;

    FOR i IN 1 .. pg_catalog.array_length(v_keys, 1) LOOP
      INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
      VALUES (v_day, v_scopes[i], v_keys[i], 1)
      ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1 WHERE c.count < v_caps[i]
      RETURNING c.count INTO v_n;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'cap' USING ERRCODE = 'P0001';
      END IF;
    END LOOP;

    INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip)
    VALUES (p_phone, p_purpose, p_code_hash, p_delivery_ct, pg_catalog.now() + interval '5 minutes', v_ip)
    RETURNING ctrlz.otp_challenges.id INTO v_id;
  EXCEPTION WHEN raise_exception THEN
    -- The subtransaction undoes the counters bumped before the one at its cap.
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END;

  RETURN QUERY SELECT v_id, true;
END
$$;
-- +goose StatementEnd

-- Create a claim. As in 0008, plus:
--
--  * Address classes that never carry a customer's plain-DNS traffic are
--    refused with invalid_address: 0/8, 10/8, 100.64/10, 127/8, 169.254/16,
--    172.16/12, 192.168/16, 224/4 and 240/4. A prefix that overlaps one of them
--    is refused too, so 0.0.0.0/0 cannot be asked for in any mode. The
--    documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) stay
--    accepted on purpose: they never appear as a real source address, so they
--    cost nothing, and the fixtures and tests use them.
--  * A tenant with a suspended claim that overlaps the prefix gets suspended,
--    not a new claim: an admin clears a suspension, the tenant does not
--    request its way around it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.ip_claim_request(p_endpoint_id uuid, p_cidr cidr, p_source text)
RETURNS TABLE (claim_id uuid, outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_mode   text;
  v_min    integer;
  v_id     uuid;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  IF p_source IS NULL OR p_source NOT IN ('manual', 'browser', 'secure_dns', 'ddns') THEN
    RETURN QUERY SELECT NULL::uuid, 'invalid_source'::text;
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
  IF p_cidr && ANY (ARRAY[
       '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
       '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4']::cidr[]) THEN
    RETURN QUERY SELECT NULL::uuid, 'invalid_address'::text;
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM ctrlz.ip_claims c
             WHERE c.tenant_id = v_tenant AND c.state = 'suspended' AND c.cidr && p_cidr) THEN
    RETURN QUERY SELECT NULL::uuid, 'suspended'::text;
    RETURN;
  END IF;

  SELECT s.registration_mode INTO v_mode FROM ctrlz.system_settings s;
  v_min := CASE WHEN v_mode = 'open' THEN 32 ELSE 28 END;

  IF pg_catalog.masklen(p_cidr) < v_min THEN
    INSERT INTO ctrlz.ip_claims (tenant_id, endpoint_id, cidr, state, source)
    VALUES (v_tenant, p_endpoint_id, p_cidr, 'pending_proof', p_source)
    RETURNING ctrlz.ip_claims.id INTO v_id;
    RETURN QUERY SELECT v_id, 'wide_requires_approval'::text;
  ELSIF v_mode = 'open' THEN
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

-- Release the caller's claim. A suspended claim is not released by its tenant:
-- that would end the suspension, and with it the admin's say, in one call.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.ip_claim_release(p_claim_id uuid)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_state  text;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  SELECT c.state INTO v_state
  FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.id = p_claim_id
  FOR UPDATE;
  IF NOT FOUND OR v_state = 'released' THEN
    RETURN QUERY SELECT 'not_found'::text;
  ELSIF v_state = 'suspended' THEN
    RETURN QUERY SELECT 'suspended'::text;
  ELSE
    UPDATE ctrlz.ip_claims c SET state = 'released' WHERE c.tenant_id = v_tenant AND c.id = p_claim_id;
    RETURN QUERY SELECT 'released'::text;
  END IF;
END
$$;
-- +goose StatementEnd

-- Open a proof challenge for the caller's claim. The function, not the caller,
-- makes the label (26 characters of [a-z2-7], the base32 of a random UUID, so
-- 122 random bits) and sets the expiry to ten minutes from now; the table
-- allows at most fifteen. A claim that is not the caller's, or is released or
-- suspended, gets no row at all.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.ip_claim_open_challenge(p_claim_id uuid)
RETURNS TABLE (challenge_id uuid, label text, expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_state  text;
  v_bits   pg_catalog.varbit;
  v_label  text;
  v_id     uuid;
  v_exp    timestamptz;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  SELECT c.state INTO v_state FROM ctrlz.ip_claims c WHERE c.tenant_id = v_tenant AND c.id = p_claim_id;
  IF NOT FOUND OR v_state IN ('released', 'suspended') THEN
    RETURN;
  END IF;

  -- 128 bits padded with two zero bits make 26 groups of 5.
  v_bits := ('x' || pg_catalog.encode(pg_catalog.uuid_send(pg_catalog.gen_random_uuid()), 'hex'))::pg_catalog.bit(128) || B'00';
  SELECT pg_catalog.string_agg(pg_catalog.substr('abcdefghijklmnopqrstuvwxyz234567',
           (pg_catalog.substr(v_bits::pg_catalog.text, n * 5 + 1, 5)::pg_catalog.bit(5))::integer + 1, 1), '' ORDER BY n)
    INTO v_label
  FROM pg_catalog.generate_series(0, 25) AS n;

  INSERT INTO ctrlz.ip_proof_challenges (tenant_id, claim_id, label, expires_at)
  VALUES (v_tenant, p_claim_id, v_label, pg_catalog.now() + interval '10 minutes')
  RETURNING ctrlz.ip_proof_challenges.id, ctrlz.ip_proof_challenges.expires_at INTO v_id, v_exp;

  RETURN QUERY SELECT v_id, v_label, v_exp;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.ip_claim_open_challenge(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.ip_claim_open_challenge(uuid) TO ctrlz_tenant;

-- Move the caller's claim to active after proof, applying the takeover rule
-- (D3). The evidence decides, not the caller:
--
--  * Evidence is a challenge of this claim that the hub marked observed from an
--    address inside the claim, not expired, not consumed, seen within the last
--    fifteen minutes, with fewer than five wrong codes.
--  * A TCP-class observation (tcp, dot, doh, doq: the handshake proves the
--    address) is enough on its own. A udp observation also needs p_code: a
--    UDP source address can be spoofed, and the code went to the real one.
--    The code is compared by its SHA-256 and without an early exit.
--  * proof_method is set from the evidence: verify_udp_txt, verify_tcp or
--    secure_dns. The one exception is browser_ip, kept when the caller says it,
--    because it only describes how the address was supplied; the evidence
--    required is the same. The other values of p_method are accepted for
--    compatibility and ignored.
--  * A wrong code adds one to attempts on the udp challenges it was compared
--    with, and the fifth consumes the challenge. The function returns no_proof
--    instead of raising, so the count is committed.
--  * An active claim that was never proven (a closed or invite mode claim
--    created active) takes fresh evidence and gets proven_at. already_active
--    means active and proven.
--  * A suspended claim is refused until an admin clears it to pending_proof.
--  * Width: /32 in open mode, /28 or narrower otherwise, unless approved.
--  * A claim of another tenant is displaced only if the new claim covers it AND
--    it contains the observed address (proof of one address says nothing about
--    the range around it), and it is unproven, idle for takeover_idle_days, or
--    on a hard_disabled Endpoint. The same test applies to the blocking check
--    and to the UPDATE. The overlapping rows are locked first, so a victim that
--    proved itself meanwhile is judged on what it committed. A fresh proof by
--    another tenant replaces an unproven claim at once, grace included: that is
--    the Plan's rule, and after the checks above the proof shows real control
--    of the address.
DROP FUNCTION ctrlz_fn.ip_claim_take(uuid, text);
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.ip_claim_take(p_claim_id uuid, p_method text, p_code text DEFAULT NULL)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_tenant   uuid := ctrlz.current_tenant_id();
  v_cidr     cidr;
  v_state    text;
  v_approved boolean;
  v_proven   timestamptz;
  v_mode     text;
  v_idle     integer;
  v_code     text;
  v_hash     bytea;
  v_chal     uuid;
  v_obs      inet;
  v_proto    text;
  v_method   text;
  v_udp_ids  uuid[] := ARRAY[]::uuid[];
  v_diff     integer;
  v_blocked  boolean;
  r          record;
  i          integer;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;
  IF p_method IS NULL OR p_method NOT IN ('verify_tcp', 'verify_udp_txt', 'browser_ip', 'secure_dns') THEN
    RETURN QUERY SELECT 'invalid_method'::text;
    RETURN;
  END IF;

  SELECT c.cidr, c.state, c.approved_by_admin, c.proven_at INTO v_cidr, v_state, v_approved, v_proven
  FROM ctrlz.ip_claims c
  WHERE c.tenant_id = v_tenant AND c.id = p_claim_id
  FOR UPDATE;

  IF NOT FOUND OR v_state = 'released' THEN
    RETURN QUERY SELECT 'not_found'::text;
    RETURN;
  ELSIF v_state = 'active' AND v_proven IS NOT NULL THEN
    RETURN QUERY SELECT 'already_active'::text;
    RETURN;
  ELSIF v_state = 'suspended' THEN
    RETURN QUERY SELECT 'suspended'::text;
    RETURN;
  END IF;

  SELECT s.registration_mode, s.takeover_idle_days INTO v_mode, v_idle FROM ctrlz.system_settings s;

  IF pg_catalog.masklen(v_cidr) < (CASE WHEN v_mode = 'open' THEN 32 ELSE 28 END) AND NOT v_approved THEN
    RETURN QUERY SELECT 'wide_requires_approval'::text;
    RETURN;
  END IF;

  v_code := pg_catalog.lower(pg_catalog.btrim(COALESCE(p_code, '')));
  IF v_code <> '' THEN
    v_hash := pg_catalog.sha256(pg_catalog.convert_to(v_code, 'UTF8'));
  END IF;

  -- Look for evidence: TCP-class first, then udp ones that match the code.
  FOR r IN
    SELECT ch.id, ch.observed_ip, ch.observed_protocol, ch.txt_code_hash
    FROM ctrlz.ip_proof_challenges ch
    WHERE ch.tenant_id = v_tenant AND ch.claim_id = p_claim_id
      AND ch.observed_at IS NOT NULL AND ch.observed_ip <<= v_cidr
      AND ch.observed_at <= ch.expires_at AND ch.expires_at > pg_catalog.now()
      AND ch.observed_at > pg_catalog.now() - interval '15 minutes'
      AND ch.consumed_at IS NULL AND ch.attempts < 5
    ORDER BY (ch.observed_protocol = 'udp'), ch.observed_at DESC, ch.id
    FOR UPDATE
  LOOP
    IF r.observed_protocol <> 'udp' THEN
      v_chal := r.id; v_obs := r.observed_ip; v_proto := r.observed_protocol;
      EXIT;
    END IF;
    v_udp_ids := v_udp_ids || r.id;
    IF v_hash IS NOT NULL THEN
      -- No early exit: the whole hash is always compared.
      v_diff := 0;
      FOR i IN 0 .. 31 LOOP
        v_diff := v_diff | (pg_catalog.get_byte(r.txt_code_hash, i) # pg_catalog.get_byte(v_hash, i));
      END LOOP;
      IF v_diff = 0 THEN
        v_chal := r.id; v_obs := r.observed_ip; v_proto := r.observed_protocol;
        EXIT;
      END IF;
    END IF;
  END LOOP;

  IF v_chal IS NULL THEN
    IF v_hash IS NOT NULL AND pg_catalog.cardinality(v_udp_ids) > 0 THEN
      UPDATE ctrlz.ip_proof_challenges ch
      SET attempts = ch.attempts + 1,
          consumed_at = CASE WHEN ch.attempts + 1 >= 5 THEN pg_catalog.now() ELSE ch.consumed_at END
      WHERE ch.tenant_id = v_tenant AND ch.id = ANY (v_udp_ids);
    END IF;
    RETURN QUERY SELECT 'no_proof'::text;
    RETURN;
  END IF;

  v_method := CASE v_proto WHEN 'udp' THEN 'verify_udp_txt' WHEN 'tcp' THEN 'verify_tcp' ELSE 'secure_dns' END;
  IF p_method = 'browser_ip' THEN
    v_method := 'browser_ip';
  END IF;

  -- Lock first, then look: the check below runs as a new statement and sees
  -- whatever a concurrent transaction committed while we waited.
  PERFORM 1
  FROM ctrlz.ip_claims o
  WHERE o.cidr && v_cidr AND o.state IN ('active', 'grace') AND o.tenant_id <> v_tenant
  FOR UPDATE;

  SELECT EXISTS (
    SELECT 1
    FROM ctrlz.ip_claims o
    LEFT JOIN ctrlz.endpoints oe ON oe.tenant_id = o.tenant_id AND oe.id = o.endpoint_id
    WHERE o.cidr && v_cidr AND o.state IN ('active', 'grace') AND o.tenant_id <> v_tenant
      AND NOT (
        o.cidr <<= v_cidr AND o.cidr >>= v_obs
        AND (o.proven_at IS NULL
             OR COALESCE(o.last_seen_at, o.proven_at) < pg_catalog.now() - pg_catalog.make_interval(days => v_idle)
             OR COALESCE(oe.admin_state, '') = 'hard_disabled')
      )
  ) INTO v_blocked;

  IF v_blocked THEN
    RETURN QUERY SELECT 'unavailable'::text;
    RETURN;
  END IF;

  BEGIN
    UPDATE ctrlz.ip_claims o SET state = 'released', displaced_at = pg_catalog.now()
    WHERE o.cidr && v_cidr AND o.state IN ('active', 'grace') AND o.tenant_id <> v_tenant
      AND o.cidr <<= v_cidr AND o.cidr >>= v_obs
      AND (o.proven_at IS NULL
           OR COALESCE(o.last_seen_at, o.proven_at) < pg_catalog.now() - pg_catalog.make_interval(days => v_idle)
           OR EXISTS (SELECT 1 FROM ctrlz.endpoints oe
                      WHERE oe.tenant_id = o.tenant_id AND oe.id = o.endpoint_id AND oe.admin_state = 'hard_disabled'));

    UPDATE ctrlz.ip_claims c
    SET state = 'active', proof_method = v_method, proven_at = pg_catalog.now(), grace_until = NULL
    WHERE c.tenant_id = v_tenant AND c.id = p_claim_id;

    UPDATE ctrlz.ip_proof_challenges ch SET consumed_at = pg_catalog.now()
    WHERE ch.tenant_id = v_tenant AND ch.id = v_chal;
  EXCEPTION WHEN exclusion_violation THEN
    -- Something overlapping that the predicate did not release (the caller's
    -- own tenant, or a row that changed). The subtransaction undoes the
    -- displacement above.
    RETURN QUERY SELECT 'unavailable'::text;
    RETURN;
  END;

  RETURN QUERY SELECT 'active'::text;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.ip_claim_take(uuid, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.ip_claim_take(uuid, text, text) TO ctrlz_tenant, ctrlz_worker;

RESET ROLE;
