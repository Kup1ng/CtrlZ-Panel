-- P1 auth review round 12, database area (db-r12-1, db-r12-3; db-r12-2 is a test).
--
-- Rule caps-and-endings (rules.md topic 7), the class "a value a cap adds to or compares with is
-- judged where it is stored" now covers the whole class, not one more column. Postgres sorts NaN
-- ABOVE every number, so `CHECK (x >= 0)` accepts it, and 0042 closed that for the gateway price
-- alone. The two other numeric columns the money cap reads had the same hole:
--
--   sms_counters.cost            the spend. cap_reached(NaN, cap) is true for every cap, so one
--                                NaN spend (the worker may insert and raise the global row; the
--                                UPDATE arm of the guard only asked NEW.cost >= OLD.cost, which
--                                NaN passes) refused every OTP of every tenant for the rest of the
--                                Tehran day, decoys included, and no UPDATE can lower it (every
--                                real value is below NaN, and the guard refuses a falling spend).
--   system_settings.sms_cost_cap_daily
--                                the cap. cap_reached(spend, NaN) was false for every spend, so
--                                the money cap silently never stopped anything while the column
--                                still looked set. ctrlz_admin holds a direct UPDATE on it and only
--                                the admin route's regex refused the text.
--
-- Four lines, so that none is the only one:
--   1. CHECK (... <> 'NaN') on both columns: holds for every writer, the superuser and a
--      replaced or disabled trigger included.
--   2. The guard of sms_counters refuses a NaN spend on INSERT and on UPDATE, for every role, with
--      the same SQLSTATE (42501) as its other refusals.
--   3. cap_reached fails CLOSED on a NaN cap (a cap nobody can compare with is reached), so a NaN
--      that gets past 1 is a stopped service and not a silent open cap.
--   4. internal/store/catalogtest check 27 reads every numeric column of the schema from
--      pg_attribute and evaluates the column's own CHECKs for NaN, so a money column added
--      tomorrow cannot repeat the hole (the rule is enforced, not remembered).
--
-- Rows that already break the line are cleaned first: a NaN spend becomes 0 (the value 0040 gives
-- a negative one) with the guard off for that statement alone, and a NaN cap becomes NULL, the
-- value for "no cap" that a NaN cap already behaved as. The cleanup runs BEFORE the constraints.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.sms_counters DISABLE TRIGGER sms_counters_guard;
UPDATE ctrlz.sms_counters SET cost = 0 WHERE cost = 'NaN'::numeric;
ALTER TABLE ctrlz.sms_counters ENABLE TRIGGER sms_counters_guard;

UPDATE ctrlz.system_settings SET sms_cost_cap_daily = NULL WHERE sms_cost_cap_daily = 'NaN'::numeric;

ALTER TABLE ctrlz.sms_counters
  ADD CONSTRAINT sms_counters_cost_not_nan CHECK (cost <> 'NaN'::numeric);
ALTER TABLE ctrlz.system_settings
  ADD CONSTRAINT system_settings_sms_cost_cap_not_nan CHECK (sms_cost_cap_daily <> 'NaN'::numeric);

-- A cap that is NaN is reached: nothing can be compared with it, and "no cap" is NULL.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz.cap_reached(spent numeric, cap numeric) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $$ SELECT cap IS NOT NULL AND (cap = 'NaN'::numeric OR COALESCE(spent, 0) >= cap) $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz.sms_counters_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  -- The same two clocks as 0040: the sweep's cutoff is two Tehran days past, and a new row is
  -- today's. now() is the start of the transaction, the instant every writer's own v_day is
  -- taken from, so a writer that started before midnight and a guard that runs after it agree.
  v_today  date := (pg_catalog.now() AT TIME ZONE 'Asia/Tehran')::date;
  v_cutoff date := v_today - 2;
BEGIN
  IF TG_OP IN ('INSERT', 'UPDATE') AND NEW.cost = 'NaN'::numeric THEN
    -- NaN is a number to Postgres and sorts above every other, so it passes "cost >= OLD.cost"
    -- and "cost >= 0" and then no UPDATE can lower it (db-r12-1, db-r12-3). Refused first, for
    -- every row of every scope and every role.
    RAISE EXCEPTION 'sms_counters: a spend is a number' USING ERRCODE = '42501';
  END IF;
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
