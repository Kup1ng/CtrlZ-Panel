-- P1 auth review round 7, SMS area (sms-r7-4, sms-r7-7).
--
-- sms-r7-4: ctrlz_worker held SELECT (id, locale, phone_e164, tenant_id) on ctrlz.users, left from
-- P0, and no statement the worker runs reads the table: the sender takes the phone from the code
-- row or the outbox row, the seeds are read by the key tool, and the RP ID job goes through
-- definer functions. The worker is a global-role service whose WithTenant can name any tenant,
-- and row-level security does not bound it, so a bug in it (it parses provider replies and holds
-- both sms keys) could list every tenant's phone numbers. The owner's first requirement is that
-- users' data is separate; the grant goes, and guarded.yaml (personal) and grants.yaml say so.
--
-- sms-r7-7: the rule that an unsent OTP gives back the global slot and no other key (spec 5.3,
-- rules.md topic 4) was a lint over the spelling of the SQL, and a constant split in two, an
-- identifier written as U&"..." or a PL/pgSQL EXECUTE writes a per-phone refund past any lint
-- that reads text. The database decides it now, whatever the text says: a trigger on
-- ctrlz.sms_counters judges every row the worker role writes.
--   INSERT  only the global rows the worker's own statements create (all, outbox);
--   UPDATE  only a global row, left on its day and its key (the refund, the cost, the outbox
--           count): a phone, a network or an address row can never be given back;
--   DELETE  only the per-phone, per-network and per-address rows of the retention sweep, on a
--           day past the sweep's own cutoff.
-- The function that issues a code runs as ctrlz_auth and is not judged: it bumps the per-phone
-- keys, which is its job. The error carries no key, so a phone never reaches a log through it.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

REVOKE SELECT (id, locale, phone_e164, tenant_id) ON ctrlz.users FROM ctrlz_worker;

-- A plain trigger function of the migrator, like credential_gen_bump: the role it judges is
-- the one that ran the statement (current_user), which is why it is not SECURITY DEFINER.
-- +goose StatementBegin
CREATE FUNCTION ctrlz.sms_counters_worker_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF current_user <> 'ctrlz_worker' THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.scope = 'global' AND NEW.key IN ('all', 'outbox') THEN
      RETURN NEW;
    END IF;
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.scope = 'global' AND NEW.scope = 'global' AND NEW.key = OLD.key AND NEW.day = OLD.day THEN
      RETURN NEW;
    END IF;
  ELSIF TG_OP = 'DELETE' THEN
    -- The retention sweep's own cutoff (qSweepBatchCounters): two days past, Tehran day.
    IF OLD.scope IN ('phone', 'phone_net', 'ip')
       AND OLD.day < ((pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date - 2) THEN
      RETURN OLD;
    END IF;
  END IF;
  RAISE EXCEPTION 'sms_counters: the sender may not write this row' USING ERRCODE = '42501';
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.sms_counters_worker_guard() FROM PUBLIC;

CREATE TRIGGER sms_counters_worker_guard BEFORE INSERT OR UPDATE OR DELETE ON ctrlz.sms_counters
  FOR EACH ROW EXECUTE FUNCTION ctrlz.sms_counters_worker_guard();
