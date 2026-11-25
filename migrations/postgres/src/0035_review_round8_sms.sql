-- P1 auth review round 8, SMS area (sms-r8-3, sms-r8-6, sms-r8-7).
--
-- sms-r8-3 and sms-r8-7: ctrlz_worker had table-wide SELECT, INSERT, UPDATE and DELETE on
-- ctrlz.sms_counters, and the raw keys of the per-phone, per-network and per-address rows are
-- what auth_otp_issue writes: a phone (decoys included, which have no other trace for the
-- worker), the /24 an address asked from, the phone joined to that network, and whether the
-- request came from a known device ("<phone>|trusted"). Migration 0030 took ip and trusted of
-- otp_challenges away from the worker (sms-r6-2) and the same facts were one SELECT away in
-- sms_counters.key, for two to three days and across every tenant. A column grant cannot cure it
-- (the worker's own statements need SELECT on key for their WHERE clauses), so the rows are
-- hidden from the role instead: row-level security shows ctrlz_worker the global rows and
-- nothing else, and the retention sweep of the per-subject rows, the one thing the worker did
-- with them, is a definer function (worker_sweep_sms_counters) like the other sweeps. The worker
-- holds no DELETE any more.
--
-- sms-r8-6: the guard of 0034 judged one role name (an exemption list: any role but
-- ctrlz_worker passed), so a definer function of ctrlz_auth, the migrator or a role that gets a
-- write grant later could give a phone slot back, which reopens the known/unknown 429 oracle of
-- spec 5.3. The invariant does not depend on the writer: nothing ever lowers or moves a
-- per-subject counter (spec 9.5: nothing refunds those), and nothing deletes one inside its
-- retention. The trigger judges the row for EVERY role, the owner and a superuser included.
-- The worker keeps its own narrower limits on the global rows as a second line behind the
-- policy.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.sms_counters ENABLE ROW LEVEL SECURITY;

-- ctrlz_auth owns the definer functions that issue a code (per-subject keys), read the figures
-- for the admin page and now sweep. The worker sees and changes the global rows only; the WITH
-- CHECK keeps it from creating or moving a row into another scope. Any other role has no policy
-- and so no row (it holds no grant either). The table's owner is not forced, as for the other
-- global tables.
CREATE POLICY auth_counters ON ctrlz.sms_counters AS PERMISSIVE FOR ALL TO ctrlz_auth
  USING (true) WITH CHECK (true);
CREATE POLICY worker_global_rows ON ctrlz.sms_counters AS PERMISSIVE FOR ALL TO ctrlz_worker
  USING (scope = 'global') WITH CHECK (scope = 'global');

GRANT DELETE ON ctrlz.sms_counters TO ctrlz_auth;
REVOKE DELETE ON ctrlz.sms_counters FROM ctrlz_worker;

SET ROLE ctrlz_auth;

-- The retention sweep of the raw per-phone, per-network and per-address counters, the statement
-- the worker ran (store.qSweepBatchCounters). The global rows stay for /sms/stats. The outer
-- predicates repeat the subselect's (rule bounded-sweeps) and the cutoff is the one the guard
-- trigger allows: two Tehran days past.
-- +goose StatementBegin
CREATE FUNCTION ctrlz_fn.worker_sweep_sms_counters(p_limit integer)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  v_n integer;
BEGIN
  IF p_limit IS NULL OR p_limit < 1 THEN
    RETURN 0;
  END IF;
  DELETE FROM ctrlz.sms_counters d WHERE (d.day, d.scope, d.key) IN
    (SELECT s.day, s.scope, s.key FROM ctrlz.sms_counters s
      WHERE s.scope <> 'global' AND s.day < (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - 2
      LIMIT LEAST(p_limit, 10000))
    AND d.scope <> 'global' AND d.day < (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - 2;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  RETURN v_n;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz_fn.worker_sweep_sms_counters(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctrlz_fn.worker_sweep_sms_counters(integer) TO ctrlz_worker;

RESET ROLE;

DROP TRIGGER sms_counters_worker_guard ON ctrlz.sms_counters;
DROP FUNCTION ctrlz.sms_counters_worker_guard();

-- A plain trigger function of the migrator, like credential_gen_bump: the role it judges is the
-- one that ran the statement (current_user), which is why it is not SECURITY DEFINER. The
-- error carries no key, so a phone never reaches a log through it.
-- +goose StatementBegin
CREATE FUNCTION ctrlz.sms_counters_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  -- The sweep's own cutoff: two Tehran days past.
  v_cutoff date := (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - 2;
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- A new row can lower nothing. The worker may create only the two global rows its own
    -- statements count on.
    IF current_user = 'ctrlz_worker' AND NOT (NEW.scope = 'global' AND NEW.key IN ('all', 'outbox')) THEN
      RAISE EXCEPTION 'sms_counters: the sender may not write this row' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.scope <> 'global' OR NEW.scope <> 'global' THEN
      -- A per-subject counter (phone, phone_net, ip) only goes up, in place, for every role.
      IF NEW.scope = OLD.scope AND NEW.key = OLD.key AND NEW.day = OLD.day AND NEW.count >= OLD.count THEN
        RETURN NEW;
      END IF;
      RAISE EXCEPTION 'sms_counters: a per-subject counter only goes up' USING ERRCODE = '42501';
    END IF;
    -- A global row: the sender's refund, cost and outbox count stay on the same row.
    IF current_user = 'ctrlz_worker' AND NOT (NEW.key = OLD.key AND NEW.day = OLD.day) THEN
      RAISE EXCEPTION 'sms_counters: the sender may not move this row' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;
  -- DELETE.
  IF OLD.scope <> 'global' THEN
    IF OLD.day < v_cutoff THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'sms_counters: a per-subject counter stays for its retention' USING ERRCODE = '42501';
  END IF;
  IF current_user = 'ctrlz_worker' THEN
    RAISE EXCEPTION 'sms_counters: the sender may not delete this row' USING ERRCODE = '42501';
  END IF;
  RETURN OLD;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.sms_counters_guard() FROM PUBLIC;

CREATE TRIGGER sms_counters_guard BEFORE INSERT OR UPDATE OR DELETE ON ctrlz.sms_counters
  FOR EACH ROW EXECUTE FUNCTION ctrlz.sms_counters_guard();
