-- P1 auth review round 14, area database, roles and store (findings db-r14-3 and db-r14-4).
--
-- 1. The audit chain's lock was a call any login role could make (db-r14-3). Every audited admin
--    write serialises on pg_advisory_xact_lock(hashtextextended('ctrlz.audit_log', 0)), a key anyone
--    can compute, and Postgres grants EXECUTE on the advisory lock functions to PUBLIC. A session
--    level lock outlives idle_in_transaction_session_timeout and statement_timeout, so a compromised
--    api (ctrlz_tenant) or hub could hold it until it disconnected, and every admin login, console
--    change and CLI command answered 503 after lock_timeout: the owner locked out of the console,
--    the Postgres twin of admin-r6-7. bootstrap/20-database.sql now takes the whole advisory family
--    away from PUBLIC (a superuser step: pg_catalog is not the migrator's) and gives back exactly
--    what is used, to roles that do not take requests from the internet: pg_advisory_xact_lock(bigint)
--    to ctrlz_auth (the definer functions, ip_claim_request among them) and the two calls of goose's
--    session locker to ctrlz_migrator. ctrlz_admin holds NONE: it takes the audit lock through this
--    function, which can lock one key and no other, so a console that is compromised can neither
--    hold a tenant's ip_claim_request key nor any key of its own choosing.
--
-- 2. A decoy challenge no longer differs in what a listener sees (db-r14-4). auth_otp_issue sent
--    pg_notify('ctrlz_sms', '') for a real challenge and nothing for a decoy. Postgres has no
--    privilege for LISTEN, so any role that can connect could LISTEN ctrlz_sms and learn, request by
--    request, whether a number has an account: the oracle the decoy of spec 5.3 exists to remove.
--    The notification is sent for every accepted issue now. The worker's drain finds nothing for a
--    decoy, which costs it one empty claim query; a request that is refused (a cap, the cooldown)
--    still sends none for either kind, because the subtransaction that raised is rolled back with
--    its notification. The body is that of 0023 with that one condition removed.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

SET ROLE ctrlz_auth;

-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.audit_lock() RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$ SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.audit_log', 0)) $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.audit_lock() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.audit_lock() TO ctrlz_admin;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.auth_otp_issue(p_phone text, p_purpose text, p_code_hash bytea, p_delivery_ct bytea, p_ip inet, p_trusted boolean)
RETURNS TABLE (id uuid, allowed boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_day    date := (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date;
  v_ip     inet := p_ip;
  v_cfg    ctrlz.system_settings%ROWTYPE;
  v_decoy  boolean := p_delivery_ct IS NULL;
  v_trust  boolean := COALESCE(p_trusted, false);
  v_gcount integer;
  v_gcost  numeric;
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

  SELECT * INTO v_cfg FROM ctrlz.system_settings;
  SELECT c.count, c.cost INTO v_gcount, v_gcost
  FROM ctrlz.sms_counters c WHERE c.day = v_day AND c.scope = 'global' AND c.key = 'all';
  v_gcount := COALESCE(v_gcount, 0);   -- no row yet leaves both NULL
  v_gcost  := COALESCE(v_gcost, 0);

  -- Both real and decoy refuse here, so a full cap reveals no phone.
  IF ctrlz.cap_reached(v_gcount, v_cfg.otp_cap_global)
     OR ctrlz.cap_reached(v_gcost, v_cfg.sms_cost_cap_daily)
     OR (NOT v_trust
         AND ctrlz.cap_reached(v_gcount::numeric * 100, v_cfg.otp_cap_global::numeric * v_cfg.otp_soft_pct)) THEN
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END IF;

  IF pg_catalog.family(v_ip) = 4 THEN
    v_net    := pg_catalog.network(pg_catalog.set_masklen(v_ip, 24))::text;
    v_scopes := ARRAY['ip', 'ip'];
    v_keys   := ARRAY[pg_catalog.host(v_ip), v_net];
    v_caps   := ARRAY[v_cfg.otp_cap_ip, v_cfg.otp_cap_net24];
  ELSE
    -- family 6: the /64 of 0010, plus the /48, which holds 65,536 /64s
    v_net    := pg_catalog.network(pg_catalog.set_masklen(v_ip, 64))::text;
    v_scopes := ARRAY['ip', 'ip'];
    v_keys   := ARRAY[v_net, pg_catalog.network(pg_catalog.set_masklen(v_ip, 48))::text];
    v_caps   := ARRAY[v_cfg.otp_cap_ip, v_cfg.otp_cap_net48];
  END IF;

  -- A known device leaves the shared keys alone, so a stranger cannot spend them.
  IF v_trust THEN
    v_scopes := v_scopes || ARRAY['phone'];
    v_keys   := v_keys   || ARRAY[p_phone || '|trusted'];
    v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_phone_trusted];
  ELSE
    v_scopes := v_scopes || ARRAY['phone_net', 'phone'];
    v_keys   := v_keys   || ARRAY[p_phone || '|' || v_net, p_phone];
    v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_phone_net, v_cfg.otp_cap_phone];
  END IF;
  IF NOT v_decoy THEN
    v_scopes := v_scopes || ARRAY['global'];
    v_keys   := v_keys   || ARRAY['all'];
    v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_global];
  END IF;

  BEGIN
    FOR i IN 1 .. pg_catalog.array_length(v_keys, 1) LOOP
      INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
      VALUES (v_day, v_scopes[i], v_keys[i], 1)
      ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + 1 WHERE NOT ctrlz.cap_reached(c.count, v_caps[i])
      RETURNING c.count INTO v_n;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'cap' USING ERRCODE = 'P0001';
      END IF;
    END LOOP;

    -- The cooldown reads challenges, which exist only for messages sent. The
    -- global counter above is locked until the caller's transaction ends, so a
    -- concurrent send is already waiting behind it (a decoy has none: the phone's
    -- own row orders it).
    IF EXISTS (SELECT 1 FROM ctrlz.otp_challenges o
               WHERE o.phone_e164 = p_phone AND o.purpose = p_purpose
                 AND o.created_at > pg_catalog.now() - pg_catalog.make_interval(secs => v_cfg.otp_cooldown_s)) THEN
      RAISE EXCEPTION 'cooldown' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip, trusted)
    VALUES (p_phone, p_purpose, p_code_hash, p_delivery_ct, pg_catalog.now() + interval '5 minutes', v_ip, v_trust)
    RETURNING ctrlz.otp_challenges.id INTO v_id;

    -- Wakes the worker. A notification sent inside a subtransaction that is
    -- rolled back is dropped with it.
    -- Real and decoy alike (db-r14-4): what a listener sees must not tell them apart.
    PERFORM pg_catalog.pg_notify('ctrlz_sms', '');
  EXCEPTION WHEN raise_exception THEN
    -- The subtransaction undoes the counters bumped before the refusal.
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END;

  RETURN QUERY SELECT v_id, true;
END
$$;
-- +goose StatementEnd

RESET ROLE;
