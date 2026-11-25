-- P1 auth review round 12, SMS area (sms-r12-3, sms-r12-4).
--
-- The hold of a gateway whose login the provider refused (round 11, sms-r11-9) lived in the
-- memory of one worker process. A test send that the provider accepted lifted it only in the
-- worker that ran the send, and a second worker kept passing the gateway over locally and kept
-- stepping the breaker, which is in this table and shared, so the breaker flapped and
-- sms_available with it. The hold is now two columns, so every worker reads one state:
--
--   held_ct_sum  the SHA-256 of credentials_ct as it was when the refused call was made
--   held_code    the closed code of the refusal (an sms.Code), for the attempt a held gateway
--                reports and for the alert
--
-- The worker sets them only WHERE sha256(credentials_ct) still equals the sum it carries, so a
-- hold for a call that used credentials saved since is ignored, and a hold that names old
-- credentials stops counting the moment the admin PUT stores new ones (the PUT also clears the
-- columns, but nothing depends on it). The accepted test send clears them. A restart no longer
-- forgets a hold: a refused key is asked about once, not once per process start.
--
-- No existing row is held. Applied files are frozen, so this is a new file (rule
-- applied-migrations-are-frozen).

-- +goose Up

SET LOCAL search_path = pg_catalog;

ALTER TABLE ctrlz.sms_gateways
  ADD COLUMN held_ct_sum bytea CHECK (octet_length(held_ct_sum) = 32),
  ADD COLUMN held_code   text  CHECK (held_code ~ '^[A-Za-z0-9_.-]{1,32}$'),
  ADD CONSTRAINT sms_gateways_hold_pair CHECK ((held_ct_sum IS NULL) = (held_code IS NULL));

-- The worker reads the row with a table-level SELECT already. It writes the hold and lifts it,
-- and nothing else of the table beyond what 0011 gave it.
GRANT UPDATE (held_ct_sum, held_code) ON ctrlz.sms_gateways TO ctrlz_worker;
