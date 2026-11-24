-- P1 auth review round 9, SMS area (sms-r9-7).
--
-- The guard of 0035 judged the per-subject rows (phone, phone_net, ip) for every role and the
-- global rows by role NAME: an UPDATE or a DELETE of a global row was refused only when
-- current_user = 'ctrlz_worker'. Every other writer, the owner, the migrator and any
-- SECURITY DEFINER function of ctrlz_auth (which 0035 also gave DELETE), could delete today's
-- ('global', 'all') row or set its count and cost to 0. That row is what otp_cap_global and
-- sms_cost_cap_daily are compared with (cap_reached in auth_otp_issue and in both outbox
-- gates), so the daily global cap and the money cap rested on the WHERE clause of one
-- function, not on the database. It is the same exemption list that sms-r8-6 removed for the
-- other rows.
--
-- The invariant does not depend on the writer, so the guard names none for the global rows
-- either. A global row, for every role:
--   - is updated in place only (same day, scope and key);
--   - never loses cost (the spend of the day only grows);
--   - loses at most one count in one UPDATE, which is the refund of an unsent code
--     (GREATEST(count - 1, 0)), and never goes below zero (the column is NOT NULL, the
--     greatest(...) is the caller's);
--   - is deleted only past the same two Tehran days as the others. The retention sweep leaves
--     the global rows for /sms/stats, so in practice they stay.
-- The worker's own narrower limits (no INSERT of another key, no DELETE at all) stay as the
-- second line, behind the policy of 0035.
--
-- What this does not stop: a loop in one function that refunds the same row 5000 times, one
-- UPDATE at a time. That would need the refund to name the row it refunds, and the only
-- function that refunds is the worker's statement; a new writer is a code review, and the lint
-- of internal/lint (TestRefundIsTheGlobalKeyOnly) names every statement that writes the table.
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION ctrlz.sms_counters_guard() RETURNS trigger
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
