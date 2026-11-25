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

-- The reader's budget, in the units this server charges while a query runs and when it fails (6.2). It is not
-- execution_time, on purpose: in 26.8.46.6 that unit is charged only by the transform that checks the final
-- result, and its stopwatch starts at the first result chunk, so the scan and the aggregation before it, a
-- query that ends in max_execution_time, a memory or row limit or a client cancel, and a query that returns
-- one chunk are charged about nothing. The four below are charged as follows: queries at admission, errors
-- when a query fails, read_rows and read_bytes by the read progress callback while it reads, so a query that
-- ends in an error has spent them and the next one is refused with code 201. read_rows and read_bytes are the
-- bound on heavy reads; errors covers fast failures, refusals at analysis or by a grant, and client cancels
-- (each run on the pinned image by the container test). A refused setting or constraint is not claimed: it is
-- judged before the query's quota is attached. A loop of timeouts is NOT bounded
-- here: with 4 turns and a 10 s deadline it is about 24 errors a minute, and a query that burns CPU while it
-- reads few rows spends neither read unit. The tenant's wall time is counted in the Go turn manager (6.2),
-- which this quota does not replace and is the only bound on timeouts.
-- queries and errors are sized from what the spec admits, not from a guess: queries 3000 is 20 streams (P7 7.3)
-- at 30 polls of one statement a minute, plus 4 sessions at the 120 analytics-read requests a minute of 8.1 and
-- at most 5 statements a request (a Summary sends the KPIs of two periods, benign_blocks, home_country and the
-- coverage share, and 6.1 holds every request to 5): 600 + 4 x 120 x 5. errors 200 is above the cancels of 4
-- turns on quick refinements and several heavy pages failing together. Streams, pages and cancels of a tenant
-- share them (one key), so a stream maximum above 20 or a request that sends more than 5 statements must raise
-- queries. The numbers are provisional (D31).
-- The key is the one the reader sends as its quota key, so more sessions, tokens or streams of one tenant buy
-- nothing. A query that reads a ctrlz table with no key is refused (code 496), but the exemption of
-- system.one is decided for the whole query, so the outer FROM of every reader query must be a ctrlz table
-- (6.1), never a FROM-less SELECT or a UNION branch without one.
CREATE QUOTA OR REPLACE reader KEYED BY client_key
  FOR INTERVAL 1 minute MAX queries = 3000, errors = 200, read_rows = 5000000000, read_bytes = 68719476736
  TO ctrlz_api;
