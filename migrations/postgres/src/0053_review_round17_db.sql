-- P1 auth review round 17, area database (findings db-r17-1 and db-r17-4; rules lock-order and bounded-sweeps).
--
-- db-r17-1. worker_sweep_throttle (0051) took its rows as `(t.scope, t.key) = ANY (ARRAY(SELECT (s.scope, s.key)
-- ... FOR UPDATE SKIP LOCKED))`. The array is an InitPlan, and a comparison of a row value with an array of
-- records can use neither an index nor a hash: Postgres ran record_eq against every element for every candidate
-- row, so a batch of 5000 over a table of 300000 took 14 s (a seq scan) and the same batch by ctid 0.29 s. After
-- a worker outage or a day of brute-force traffic every batch is full, the statement hits the role's
-- statement_timeout and rolls back, the backlog never drains and the table grows; meanwhile the 5000 rows stay
-- locked and an auth_throttle_hit on one of them waits for lock_timeout.
--
-- The rows are now found by ctid, the physical address of a row the subselect has locked: a TID scan reads
-- exactly those rows. A locked row cannot move or be vacuumed away, and the outer predicate still repeats the
-- subselect's (READ COMMITTED may hand the outer statement a newer version of a row that a hit has just
-- reopened). The ARRAY form is kept: an InitPlan runs once, which a semi-join over a locking, limited subselect
-- does not guarantee (db-r16-19).
--
-- db-r17-4. The sweeps and statements that follow wrote several rows of one table in plan order and were judged
-- safe because only ONE statement did, on the premise that a statement meets itself in its own plan order. A plan
-- is not fixed (a custom and a generic plan, a sequential and an index scan, new statistics each give another row
-- order), and two runs of the same function overlap whenever a worker is restarted while the old process still
-- runs. catalogtest TestDefinerWritesLockInKeyOrder no longer has the premise: every multi-row writer takes the
-- ordered or the skip-locked shape, or names one row by a unique key.
--
-- The signatures, owners, grants and ranks are those of the functions they replace (bodies only). A new file and
-- not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

SET ROLE ctrlz_auth;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_throttle(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  -- auth_throttle_hit moves window_start forward in place, so the window a hit has just reopened must
  -- survive: the outer statement asks again. The rows are taken once, as an array of the physical addresses
  -- of rows this statement has locked (an InitPlan, and a TID scan: see the header of this file), and a row
  -- somebody holds is left for the next pass.
  DELETE FROM ctrlz.auth_throttle t WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s
        WHERE s.window_start < pg_catalog.now() - interval '1 day'
        LIMIT LEAST(p_limit, 10000) FOR UPDATE SKIP LOCKED))
    AND t.window_start < pg_catalog.now() - interval '1 day';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

-- db-r17-4: the sweeps and writers below take the one shape of internal/store/locks.go.

-- The OTP rows, rows somebody holds are left for the next pass (a sweep never waits).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_otp_challenges(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  DELETE FROM ctrlz.otp_challenges d WHERE d.id = ANY (ARRAY(SELECT s.id FROM ctrlz.otp_challenges s
        WHERE s.created_at < pg_catalog.now() - interval '24 hours'
        ORDER BY s.id LIMIT LEAST(p_limit, 10000) FOR UPDATE SKIP LOCKED))
    AND d.created_at < pg_catalog.now() - interval '24 hours';
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

-- The counters: the key is (day, scope, key), so the rows are found by ctid like the throttle's.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_sms_counters(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  DELETE FROM ctrlz.sms_counters d WHERE d.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.sms_counters s
        WHERE s.scope <> 'global' AND s.day < (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - 2
        LIMIT LEAST(p_limit, 10000) FOR UPDATE SKIP LOCKED))
    AND d.scope <> 'global' AND d.day < (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - 2;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

-- ctrlz_auth holds DELETE but no UPDATE on sms_deliveries (the record the cost cap reads), and a row lock
-- clause needs UPDATE, so the rows are deleted ONE KEYED ROW AT A TIME in key order (the shape that
-- sweepKeyed in internal/store/worker_sms.go gives the sweeps of the tables the worker cannot lock).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_sweep_sms_deliveries(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n  integer := 0;
  v_id uuid;
  v_k  integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  FOR v_id IN SELECT s.id FROM ctrlz.sms_deliveries s
               WHERE s.created_at < pg_catalog.now() - interval '90 days'
               ORDER BY s.id LIMIT LEAST(p_limit, 10000)
  LOOP
    -- A row that changed after the read is judged again here and left for the next pass.
    DELETE FROM ctrlz.sms_deliveries d WHERE d.id = v_id AND d.created_at < pg_catalog.now() - interval '90 days';
    GET DIAGNOSTICS v_k = ROW_COUNT;
    v_n := v_n + v_k;
  END LOOP;
  RETURN v_n;
END
$$;
-- +goose StatementEnd

-- A reset of one key names its row (the whole primary key); a reset of a whole scope waits for every row
-- it must reach, so it locks them in the order of the primary key, found by ctid.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.admin_throttle_reset(p_scope text, p_key bytea)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE ctrlz.auth_throttle t SET count = 0, epoch = t.epoch + 1
  WHERE t.scope = p_scope AND t.key = p_key
    AND p_scope IN ('admin_login', 'admin_login_user', 'admin_login_net', 'admin_totp');
  UPDATE ctrlz.auth_throttle t SET count = 0, epoch = t.epoch + 1
  WHERE t.ctid = ANY (ARRAY(SELECT s.ctid FROM ctrlz.auth_throttle s
        WHERE s.scope = p_scope AND p_key IS NULL
          AND p_scope IN ('admin_login', 'admin_login_user', 'admin_login_net', 'admin_totp')
        ORDER BY s.scope, s.key FOR UPDATE))
    AND t.scope = p_scope AND p_key IS NULL
    AND p_scope IN ('admin_login', 'admin_login_user', 'admin_login_net', 'admin_totp')
$$;
-- +goose StatementEnd

-- Every credential of the tenant that is not on the RP ID in force must be marked, so the rows are waited
-- for, in key order.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz_fn.worker_passkeys_mark_stale(p_rp_id text)
RETURNS TABLE (user_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  WITH marked AS (
    UPDATE ctrlz.webauthn_credentials w SET stale_at = pg_catalog.now()
     WHERE w.id = ANY (ARRAY(SELECT s.id FROM ctrlz.webauthn_credentials s
                 WHERE s.tenant_id = ctrlz.current_tenant_id() AND s.rp_id <> p_rp_id AND s.stale_at IS NULL
                   AND EXISTS (SELECT 1 FROM ctrlz.webauthn_config c WHERE c.rp_id = p_rp_id)
                 ORDER BY s.id FOR NO KEY UPDATE))
       AND w.tenant_id = ctrlz.current_tenant_id() AND w.rp_id <> p_rp_id AND w.stale_at IS NULL
    RETURNING w.user_id
  )
  SELECT DISTINCT m.user_id FROM marked m
$$;
-- +goose StatementEnd

RESET ROLE;
