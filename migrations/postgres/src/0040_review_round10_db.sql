-- P1 auth review round 10, database area (db-r10-1).
--
-- Rule caps-and-endings (rules.md topic 7): a cap is decided by the database, whoever writes. The
-- guard of 0038 held the global rows to "in place, the spend never falls, one count back at a
-- time", but its INSERT arm judged no value: it returned NEW for any day, count and cost, and
-- sms_counters has no CHECK. A row made in advance is the STARTING value that auth_otp_issue and
-- both outbox gates later add to and compare with cap_reached, so a global row planted for a
-- future day with a count of -2000000000 and a cost of -9999999999 (the worker may insert the
-- two global keys, a definer function or the owner may insert anything) turns off the daily OTP
-- cap, its soft threshold and the money cap for that day; the retention sweep leaves the global
-- rows for /sms/stats, so the row would stay. The same reaches the per-subject rows that no role
-- may lower (sms-r8-6): a negative per-phone count for tomorrow is a lowered counter.
--
-- Two lines, so that neither is the only one:
--   1. CHECK (count >= 0) and CHECK (cost >= 0) on sms_counters, and CHECK (count >= 0) on
--      auth_throttle (the same shape: a counter a cap compares with, written only by definer
--      functions, where a negative value is a window that never fills). A constraint holds for
--      every writer, the superuser included, and fires after the trigger, so it is what remains
--      if the trigger is ever disabled or replaced.
--   2. The INSERT arm of the guard states what a NEW row is, for every role: today's Tehran day
--      (the day the issue function and the outbox gates compute from the same database clock,
--      so a row for another day is never one a real writer makes), a count of 0 or 1 (a row
--      starts at the first count, or at zero when it only carries a cost), and a spend that is
--      not negative. A row that has to start higher grows by UPDATE, which the arms below
--      already hold. The worker's own scope and key limit stays as the second line.
--
-- Rows that already break either line are cleaned here, with the guard switched off for the
-- cleanup only (it refuses a DELETE inside the retention, and this is the one place where a
-- row that was never real is removed): a row of a day that has not begun, and a negative
-- value, which is raised to zero (a rise is allowed by every arm, so no switch is needed).
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.sms_counters DISABLE TRIGGER sms_counters_guard;
DELETE FROM ctrlz.sms_counters WHERE day > (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date;
UPDATE ctrlz.sms_counters SET count = 0 WHERE count < 0;
UPDATE ctrlz.sms_counters SET cost = 0 WHERE cost < 0;
ALTER TABLE ctrlz.sms_counters ENABLE TRIGGER sms_counters_guard;

UPDATE ctrlz.auth_throttle SET count = 0 WHERE count < 0;

ALTER TABLE ctrlz.sms_counters
  ADD CONSTRAINT sms_counters_count_not_negative CHECK (count >= 0),
  ADD CONSTRAINT sms_counters_cost_not_negative CHECK (cost >= 0);
ALTER TABLE ctrlz.auth_throttle
  ADD CONSTRAINT auth_throttle_count_not_negative CHECK (count >= 0);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz.sms_counters_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  -- The same two clocks as before: the sweep's cutoff is two Tehran days past, and a new row is
  -- today's. now() is the start of the transaction, the instant every writer's own v_day is
  -- taken from, so a writer that started before midnight and a guard that runs after it agree.
  v_today  date := (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date;
  v_cutoff date := v_today - 2;
BEGIN
  IF TG_OP = 'INSERT' THEN
    -- A new row is a starting value, and a starting value is what every later cap test adds to
    -- and compares with, so it is judged for every role (db-r10-1). The messages carry no key
    -- and no value, so a phone never reaches a log through them.
    IF NEW.day IS DISTINCT FROM v_today THEN
      RAISE EXCEPTION 'sms_counters: a new counter row starts on today''s day' USING ERRCODE = '42501';
    END IF;
    IF NEW.count IS NULL OR NEW.count < 0 OR NEW.count > 1 THEN
      RAISE EXCEPTION 'sms_counters: a new counter row starts at zero or one' USING ERRCODE = '42501';
    END IF;
    IF NEW.cost IS NULL OR NEW.cost < 0 THEN
      RAISE EXCEPTION 'sms_counters: a new counter row starts with a spend of zero or more' USING ERRCODE = '42501';
    END IF;
    -- The worker may create only the two global rows its own statements count on.
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
    -- A global row, for every role: in place, the spend never falls, and the count falls by one
    -- at most (the refund of one unsent code).
    IF NEW.key = OLD.key AND NEW.day = OLD.day AND NEW.cost >= OLD.cost AND NEW.count >= OLD.count - 1 THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'sms_counters: a global counter moves in place, its spend only grows and it gives back one at a time' USING ERRCODE = '42501';
  END IF;
  -- DELETE, for every role: a row stays for its retention. The sender never deletes.
  IF current_user = 'ctrlz_worker' THEN
    RAISE EXCEPTION 'sms_counters: the sender may not delete this row' USING ERRCODE = '42501';
  END IF;
  IF OLD.day < v_cutoff THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'sms_counters: a counter stays for its retention' USING ERRCODE = '42501';
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ctrlz.sms_counters_guard() FROM PUBLIC;
