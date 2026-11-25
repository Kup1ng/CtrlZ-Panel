-- P5 3.4: the row policies and the reader quota. Not a goose migration, on purpose: the runner applies this file
-- before the first migration and again on every run (migrate.UpAnalytics), for two reasons.
--
--  1. A table with no row policy at all is read without a filter (users_without_row_policies_can_read_rows only
--     empties a table that some policy names for other users), and the reader users hold SELECT from the
--     first start. A policy on `ctrlz.*` needs no table, so it exists before the first table does and every
--     table is under it from its first day, however the migrations stop and restart.
--  2. Policies and quotas live in the server's access directory, not in the databases goose records its
--     versions in. A restored `ctrlz` and `ctrlz_meta` without it would show "0 pending" and never make them
--     again. OR REPLACE re-asserts them each run, and also repairs a definition that was changed by hand.
--
-- The users themselves are in users.d (written by the start wrapper of the clickhouse service), because their
-- passwords are Docker secrets. A policy is defence in depth: the process picks the tenant value, so the
-- boundary is the reader package (R6).

-- The database is made here as well as in 0001 so that the policies have something to name on a first run.
CREATE DATABASE IF NOT EXISTS ctrlz;

-- A reader that sends no SQL_tenant_id fails (the setting is unknown), which is the closed side.
CREATE ROW POLICY OR REPLACE tenant_only ON ctrlz.* FOR SELECT
  USING tenant_id = toUUID(getSetting('SQL_tenant_id'))
  TO ctrlz_api, ctrlz_preview;

-- The users that work on every tenant's rows: the migrator, the janitor (its mutations read the rows they
-- delete) and the hub's user, which has no SELECT grant on a table at all and is listed so that a later grant
-- cannot leave it blind.
CREATE ROW POLICY OR REPLACE maintenance ON ctrlz.* FOR SELECT
  USING 1
  TO ctrlz_migrator, ctrlz_janitor, ctrlz_ingest;

-- 60 seconds of execution time a minute for each tenant (6.2). The key is the one the reader sends as its
-- quota key, so more sessions, tokens or streams of one tenant buy nothing; a query with no key is refused.
CREATE QUOTA OR REPLACE reader KEYED BY client_key
  FOR INTERVAL 1 minute MAX execution_time = 60
  TO ctrlz_api;
