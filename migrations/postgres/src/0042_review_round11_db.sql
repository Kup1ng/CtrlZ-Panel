-- P1 auth review round 11, database area (db-r11-1).
--
-- Rule caps-and-endings (rules.md topic 7): a counter a cap compares with is non-negative whoever
-- writes it, and so is every price that feeds it. Migration 0040 put CHECK (cost >= 0) on
-- sms_counters and a guard on its INSERT arm, which refuse a spend below zero for every role.
-- The spend is built from sms_gateways.cost_per_message (the worker adds the price of each
-- accepted code), and that column had no line of its own: only the admin route's regex kept it
-- non-negative, while ctrlz_admin holds a direct UPDATE on it. A negative price that reached the
-- column (a later route, a restored row, a hand edit) made the first accepted send of a day with
-- no counter row INSERT a negative cost, the guard refused it, the record transaction failed for
-- good, and the provider, which had already accepted the code, was asked again and billed again
-- when the claim lapsed. Both ends of that are named here: the price is judged where it is
-- stored, so the counter never sees a value the counter would refuse.
--
-- NaN is a numeric value and passes `>= 0` (Postgres sorts it above every number), so it is
-- refused by name: a NaN price would make every later sum NaN and park the day's cap at
-- "reached" with nothing to say why.
--
-- Rows that already break the line are cleaned here: a price below zero or NaN is no price, and
-- NULL is what the column holds until the owner gives one (the money cap then refuses a routed
-- gateway with no price, which is the safe side).
--
-- A new file and not an edit of an applied one (README, Rules).

-- +goose Up

SET LOCAL search_path = pg_catalog;

UPDATE ctrlz.sms_gateways SET cost_per_message = NULL
WHERE cost_per_message < 0 OR cost_per_message = 'NaN'::numeric;

ALTER TABLE ctrlz.sms_gateways
  ADD CONSTRAINT sms_gateways_cost_not_negative
  CHECK (cost_per_message >= 0 AND cost_per_message <> 'NaN'::numeric);
