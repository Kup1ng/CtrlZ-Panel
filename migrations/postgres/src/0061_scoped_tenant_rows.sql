-- P1 auth, owner decision of 2026-11-24 (question 15, finding db-r18-17): row-level security under every
-- function that acts for a tenant.
--
-- Since 0055 the twelve definer functions that act for the tenant of the call are owned by ctrlz_scoped, which
-- meets no policy but tenant_isolation, so a body that forgets its tenant predicate still cannot read another
-- tenant's row. Three tenant functions stayed with ctrlz_auth because the rows they touch were not under a
-- tenant policy: auth_tickets_revoke (auth_tickets is a global table with no row-level security),
-- auth_phone_mark_verified and auth_phone_change_complete (they read otp_challenges, which has no tenant
-- column). announcements_for_tenant moved in 0055 with a table-level SELECT on a table nothing bounded, so the
-- predicate in its body was its only isolation. The owner chose to close all four.
--
--   * otp_challenges gets tenant_id, stamped by auth_otp_issue itself and never by its caller. The tenant of a
--     challenge is the tenant of the account of the phone for login, reset and phone_old, the tenant of the
--     transaction setting for phone_new (the number has no account yet), and NULL for signup, invite and every
--     decoy. The account is looked up for a decoy as well, so the work of a known and an unknown phone is the same.
--     The column is a plain value, not a foreign key (no global table references a tenant row).
--   * Row-level security is enabled on auth_tickets and announcements (not forced, as for the other global
--     tables), with a named policy for each role that already worked on them, and a `scoped_tenant` policy for
--     ctrlz_scoped on those two tables and on otp_challenges. phone_change_requests already has tenant_isolation.
--   * auth_tickets_revoke, auth_phone_mark_verified and auth_phone_change_complete move to ctrlz_scoped the way 0055
--     moved the others: dropped by ctrlz_auth and made again by ctrlz_scoped with the body the catalog held,
--     the same EXECUTE. ctrlz_auth loses what only they used: phone_change_requests, UPDATE of the two phone
--     columns of users, and SELECT on announcements.
--
-- Expand only: no signature changes and no EXECUTE changes, so an api container of the previous release keeps
-- working while this runs. A phone change that one of them starts in the window fails once and is retried by the
-- user, because its new-number code is issued with no tenant setting by the old binary.
--
-- lock_timeout is 5 seconds for this file: ADD COLUMN takes the table lock until commit, and a migration that
-- cannot get it must fail and be run again, not queue every request of every tenant behind itself.
--
-- The in-flight rows (the last hour) are stamped as ctrlz_auth, which sees every user through auth_lookup and meets
-- tenant_isolation on phone_change_requests, so the tenant of each request is set one by one. The README names
-- ctrlz_backfill for this; ctrlz_auth is used instead because it needs no grant that would have to be taken back,
-- and the file ends by failing if a row it should have stamped is still unstamped.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';

-- 1. The column. NOT VALID and then VALIDATE: the CHECK is added without a scan under the lock and then proved.
ALTER TABLE ctrlz.otp_challenges ADD COLUMN tenant_id uuid;
ALTER TABLE ctrlz.otp_challenges ADD CONSTRAINT otp_challenges_tenant_purpose
  CHECK (tenant_id IS NULL OR purpose IN ('login', 'reset', 'phone_old', 'phone_new')) NOT VALID;
ALTER TABLE ctrlz.otp_challenges VALIDATE CONSTRAINT otp_challenges_tenant_purpose;

-- 2. auth_otp_issue: the body of 0055 plus the tenant. The lookup sits before the counters loop, so the order of
-- the locks and the shape of a decoy do not change.
SET ROLE ctrlz_auth;

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
  v_tenant uuid;
  v_gcount integer;
  v_gcost  numeric;
  v_gkey   text;
  v_net    text;
  v_scopes text[];
  v_keys   text[];
  v_caps   integer[];
  v_id     uuid;
  v_n      integer;
  v_inc    integer[];
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

  -- One request at a time per phone, real or decoy, before anything is counted (db-r18-2). The cooldown test
  -- below reads the challenges of committed requests, so two requests for one phone from two networks (they
  -- use different phone keys) must not run it side by side. The key is text, the way the audit lock's is,
  -- hashed to the bigint the function takes; it is a different text from every other advisory key of the schema.
  PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('ctrlz.otp_issue:' || p_phone, 0));

  SELECT * INTO v_cfg FROM ctrlz.system_settings;
  -- The day's count is the sum of the shards and its spend is the worker's row; neither read takes a lock.
  SELECT COALESCE(pg_catalog.sum(c.count), 0)::integer, COALESCE(pg_catalog.sum(c.cost), 0)
    INTO v_gcount, v_gcost
  FROM ctrlz.sms_counters c
  WHERE c.day = v_day AND c.scope = 'global' AND (c.key = 'all' OR c.key LIKE 'all:%');

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
  -- One shard of the global count is probed and locked by EVERY request, in the same place, and only a real
  -- one adds to it (tenant-r16-11, db-r18-2): the shard is chosen at random, so a flood of decoys spreads over
  -- sixteen rows and no longer queues the real requests behind one.
  v_inc    := pg_catalog.array_fill(1, ARRAY[pg_catalog.array_length(v_keys, 1)]);
  v_gkey   := CASE WHEN pg_catalog.random() < 1.0 / 16 THEN 'all'
                   ELSE 'all:' || (1 + pg_catalog.floor(pg_catalog.random() * 15))::integer END;
  v_scopes := v_scopes || ARRAY['global'];
  v_keys   := v_keys   || ARRAY[v_gkey];
  v_caps   := v_caps   || ARRAY[v_cfg.otp_cap_global];
  v_inc    := v_inc    || ARRAY[CASE WHEN v_decoy THEN 0 ELSE 1 END];

  -- The tenant of the challenge (question 15). The account is looked up for a decoy too, so a known and an
  -- unknown phone do the same read; only the row written differs, and a decoy is written with no tenant. The
  -- number of a phone change has no account yet and takes the tenant of the transaction setting, which the
  -- caller made (the setting is NULL for any other caller, and so is the stamp).
  IF p_purpose IN ('login', 'reset', 'phone_old') THEN
    SELECT u.tenant_id INTO v_tenant FROM ctrlz.users u WHERE u.phone_e164 = p_phone;
  ELSIF p_purpose = 'phone_new' THEN
    v_tenant := ctrlz.current_tenant_id();
  END IF;

  BEGIN
    FOR i IN 1 .. pg_catalog.array_length(v_keys, 1) LOOP
      INSERT INTO ctrlz.sms_counters AS c (day, scope, key, count)
      VALUES (v_day, v_scopes[i], v_keys[i], v_inc[i])
      ON CONFLICT (day, scope, key) DO UPDATE SET count = c.count + v_inc[i] WHERE NOT ctrlz.cap_reached(c.count, v_caps[i])
      RETURNING c.count INTO v_n;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'cap' USING ERRCODE = 'P0001';
      END IF;
    END LOOP;

    -- The cooldown reads challenges, which exist only for messages sent. The advisory lock above is held
    -- until the caller's transaction ends, so a concurrent request for this phone is already waiting behind
    -- it (a decoy took the same lock: the same wait for both, tenant-r16-11).
    IF EXISTS (SELECT 1 FROM ctrlz.otp_challenges o
               WHERE o.phone_e164 = p_phone AND o.purpose = p_purpose
                 AND o.created_at > pg_catalog.now() - pg_catalog.make_interval(secs => v_cfg.otp_cooldown_s)) THEN
      RAISE EXCEPTION 'cooldown' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO ctrlz.otp_challenges (phone_e164, purpose, code_hash, delivery_ct, expires_at, ip, trusted, tenant_id)
    VALUES (p_phone, p_purpose, p_code_hash, p_delivery_ct, pg_catalog.now() + interval '5 minutes', v_ip, v_trust,
            CASE WHEN v_decoy THEN NULL ELSE v_tenant END)
    RETURNING ctrlz.otp_challenges.id INTO v_id;
  EXCEPTION WHEN raise_exception THEN
    -- The subtransaction undoes the counters bumped before the refusal.
    RETURN QUERY SELECT NULL::uuid, false;
    RETURN;
  END;

  RETURN QUERY SELECT v_id, true;
END
$$;
-- +goose StatementEnd

-- 3. The challenges of the last hour that a login or a phone change may still need: stamped from the account of
-- the phone, and from the request that names the code, one tenant at a time.
-- +goose StatementBegin
DO $$
DECLARE
  v_t      uuid;
  v_n      integer;
  v_stamped integer := 0;
  v_left   integer;
BEGIN
  UPDATE ctrlz.otp_challenges o SET tenant_id = u.tenant_id
    FROM ctrlz.users u
   WHERE u.phone_e164 = o.phone_e164 AND o.tenant_id IS NULL
     AND o.purpose IN ('login', 'reset', 'phone_old')
     AND (o.deliverable OR o.consumed_at IS NOT NULL)
     AND o.created_at > pg_catalog.now() - interval '1 hour';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  v_stamped := v_stamped + v_n;

  FOR v_t IN SELECT t.id FROM ctrlz.tenants t ORDER BY t.id LOOP
    PERFORM pg_catalog.set_config('ctrlz.tenant_id', v_t::text, true);
    UPDATE ctrlz.otp_challenges o SET tenant_id = p.tenant_id
      FROM ctrlz.phone_change_requests p
     WHERE p.tenant_id = v_t AND p.new_otp_id = o.id AND o.tenant_id IS NULL
       AND o.purpose = 'phone_new'
       AND (o.deliverable OR o.consumed_at IS NOT NULL)
       AND o.created_at > pg_catalog.now() - interval '1 hour';
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_stamped := v_stamped + v_n;
  END LOOP;
  PERFORM pg_catalog.set_config('ctrlz.tenant_id', '', true);

  -- Under a role that cannot see the users, the statements above stamp nothing and look like success. A row
  -- that has an account behind it and is still unstamped means the run did not see it.
  SELECT pg_catalog.count(*) INTO v_left
    FROM ctrlz.otp_challenges o JOIN ctrlz.users u ON u.phone_e164 = o.phone_e164
   WHERE o.tenant_id IS NULL AND o.purpose IN ('login', 'reset', 'phone_old')
     AND (o.deliverable OR o.consumed_at IS NOT NULL)
     AND o.created_at > pg_catalog.now() - interval '1 hour';
  IF v_left <> 0 THEN
    RAISE EXCEPTION '0061: % challenges of the last hour with an account behind them were not stamped (stamped %)', v_left, v_stamped;
  END IF;
END
$$;
-- +goose StatementEnd
RESET ROLE;

-- 4. Row-level security. Not FORCE, as for the other global tables: the owner is the migrator, which logs in only
-- from the address of the migrate container. Every role that works on the two tables has its own named policy, so
-- turning it on changes nothing for them; a role with a grant and no policy would see no row.
ALTER TABLE ctrlz.auth_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ctrlz.announcements ENABLE ROW LEVEL SECURITY;

CREATE POLICY auth_tickets_all ON ctrlz.auth_tickets AS PERMISSIVE FOR ALL TO ctrlz_auth
  USING (true) WITH CHECK (true);
CREATE POLICY announcements_admin ON ctrlz.announcements AS PERMISSIVE FOR ALL TO ctrlz_admin
  USING (true) WITH CHECK (true);
CREATE POLICY announcements_worker ON ctrlz.announcements AS PERMISSIVE FOR SELECT TO ctrlz_worker
  USING (true);

-- The policies of ctrlz_scoped. It meets tenant_isolation on the tenant tables and these three on the global ones.
-- Catalog check 10 accepts a policy for the role only under this name, on these three tables, with a condition that
-- names the setting.
CREATE POLICY scoped_tenant ON ctrlz.auth_tickets AS PERMISSIVE FOR ALL TO ctrlz_scoped
  USING (subject_tenant = ctrlz.current_tenant_id()) WITH CHECK (subject_tenant = ctrlz.current_tenant_id());
CREATE POLICY scoped_tenant ON ctrlz.announcements AS PERMISSIVE FOR SELECT TO ctrlz_scoped
  USING (ctrlz.current_tenant_id() IS NOT NULL AND (audience = 'all' OR tenant_id = ctrlz.current_tenant_id()));
CREATE POLICY scoped_tenant ON ctrlz.otp_challenges AS PERMISSIVE FOR SELECT TO ctrlz_scoped
  USING (tenant_id = ctrlz.current_tenant_id());

-- 5. What the three moved functions read and write, and no more (columns the 0055 grants do not already hold).
GRANT SELECT (phone_e164, phone_verified_at, locale), UPDATE (phone_e164, phone_verified_at) ON ctrlz.users TO ctrlz_scoped;
GRANT SELECT (tenant_id, id, user_id, new_phone_e164, old_otp_id, new_otp_id, expires_at, completed_at, created_at),
      UPDATE (completed_at) ON ctrlz.phone_change_requests TO ctrlz_scoped;
GRANT SELECT (id, tenant_id, phone_e164, purpose, consumed_at) ON ctrlz.otp_challenges TO ctrlz_scoped;
GRANT SELECT (id, subject_tenant, subject_user, kind, consumed_at), UPDATE (consumed_at) ON ctrlz.auth_tickets TO ctrlz_scoped;

SET ROLE ctrlz_auth;
GRANT USAGE, CREATE ON SCHEMA ctrlz_fn TO ctrlz_scoped;
RESET ROLE;

-- auth_phone_change_complete
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.auth_phone_change_complete(p_request_id uuid);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_phone_change_complete(p_request_id uuid)
 RETURNS TABLE(outcome text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE
  v_tenant uuid := ctrlz.current_tenant_id();
  v_user   uuid;
  r        record;
  v_old    text;
BEGIN
  IF v_tenant IS NULL THEN
    RETURN;
  END IF;

  -- Whose request it is, without a lock: the user row comes first in the lock
  -- order, and its id is only known from here.
  SELECT p.user_id INTO v_user
  FROM ctrlz.phone_change_requests p
  WHERE p.tenant_id = v_tenant AND p.id = p_request_id;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  SELECT u.phone_e164 INTO v_old
  FROM ctrlz.users u
  WHERE u.tenant_id = v_tenant AND u.id = v_user
  FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  SELECT p.new_phone_e164, p.old_otp_id, p.new_otp_id, p.expires_at, p.completed_at, p.created_at
  INTO r
  FROM ctrlz.phone_change_requests p
  WHERE p.tenant_id = v_tenant AND p.id = p_request_id
  FOR UPDATE;
  IF NOT FOUND OR r.completed_at IS NOT NULL OR r.expires_at <= pg_catalog.now() THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  PERFORM 1 FROM ctrlz.otp_challenges o
  WHERE o.id = r.old_otp_id AND o.phone_e164 = v_old AND o.purpose = 'phone_old'
    AND o.consumed_at >= r.created_at AND o.consumed_at > pg_catalog.now() - interval '10 minutes';
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;
  PERFORM 1 FROM ctrlz.otp_challenges o
  WHERE o.id = r.new_otp_id AND o.phone_e164 = r.new_phone_e164 AND o.purpose = 'phone_new'
    AND o.consumed_at >= r.created_at AND o.consumed_at > pg_catalog.now() - interval '10 minutes';
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'invalid'::text;
    RETURN;
  END IF;

  BEGIN
    UPDATE ctrlz.users u SET phone_e164 = r.new_phone_e164, phone_verified_at = pg_catalog.now()
    WHERE u.tenant_id = v_tenant AND u.id = v_user;
    UPDATE ctrlz.phone_change_requests p SET completed_at = pg_catalog.now()
    WHERE p.tenant_id = v_tenant AND p.id = p_request_id;
  EXCEPTION WHEN unique_violation THEN
    -- The number belongs to someone else. Only a person who holds that SIM
    -- gets this far, so the outcome may say so.
    RETURN QUERY SELECT 'unavailable'::text;
    RETURN;
  END;

  RETURN QUERY SELECT 'ok'::text;
END
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_phone_change_complete(p_request_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_phone_change_complete(p_request_id uuid) TO ctrlz_tenant;
RESET ROLE;

-- auth_phone_mark_verified
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.auth_phone_mark_verified(p_user_id uuid, p_otp_id uuid);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_phone_mark_verified(p_user_id uuid, p_otp_id uuid)
 RETURNS TABLE(outcome text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
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
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_phone_mark_verified(p_user_id uuid, p_otp_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_phone_mark_verified(p_user_id uuid, p_otp_id uuid) TO ctrlz_tenant;
RESET ROLE;

-- auth_tickets_revoke
SET ROLE ctrlz_auth;
DROP FUNCTION ctrlz_fn.auth_tickets_revoke(p_user_id uuid);
RESET ROLE;
SET ROLE ctrlz_scoped;
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.auth_tickets_revoke(p_user_id uuid)
 RETURNS void
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
  UPDATE ctrlz.auth_tickets t SET consumed_at = pg_catalog.now()
  WHERE t.id = ANY (ARRAY(SELECT x.id FROM ctrlz.auth_tickets x
        WHERE x.subject_tenant = ctrlz.current_tenant_id() AND x.subject_user = p_user_id
          AND x.kind IN ('mfa', 'reset') AND x.consumed_at IS NULL
        ORDER BY x.id FOR NO KEY UPDATE))
$function$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.auth_tickets_revoke(p_user_id uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.auth_tickets_revoke(p_user_id uuid) TO ctrlz_tenant, ctrlz_admin;
RESET ROLE;

-- 6. What ctrlz_auth no longer needs: only the three functions above used these.
REVOKE ALL ON ctrlz.phone_change_requests FROM ctrlz_auth;
REVOKE SELECT ON ctrlz.announcements FROM ctrlz_auth;
REVOKE UPDATE (phone_e164, phone_verified_at) ON ctrlz.users FROM ctrlz_auth;

SET ROLE ctrlz_auth;
REVOKE USAGE, CREATE ON SCHEMA ctrlz_fn FROM ctrlz_scoped;
RESET ROLE;
