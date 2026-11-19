-- The watchdog's one statement (P1 auth review round 15, db-r15-7). Run by
-- deploy/compose/postgres/watchdog.sh as the superuser over the local socket, every few seconds.
--
-- Why it exists. statement_timeout, lock_timeout, idle_in_transaction_session_timeout and
-- transaction_timeout are settings, and any role may change a setting of its own session: a service
-- that is compromised runs SET ... = 0 and then holds whatever a transaction can hold for ever (a row
-- lock on a tenant row, which stops the owner suspending that tenant, or the global sms_counters row,
-- which stops every message from being counted). A grant cannot close that, because the locks are the
-- ones the role's own legitimate writes take; only a party the role does not control can end the
-- transaction. The role defaults still bound an honest bug with a clean error.
--
-- It ends the backend of every ctrlz login role except the migrator (a migration or a backfill may
-- run long, and that role logs in from one address only) whose TRANSACTION is older than max_secs. A
-- backend that is not in a transaction has no xact_start and is left alone. The names are matched by
-- pattern so a service role added later is covered without a line here.
--
-- Variables (psql -v): db_name, max_secs (whole seconds, validated by the caller). It prints one
-- number, how many backends it ended. It names no role, query or value.
SELECT pg_catalog.count(pg_catalog.pg_terminate_backend(a.pid))
FROM pg_catalog.pg_stat_activity a
WHERE a.datname = :'db_name'
  AND a.usename ~ '^ctrlz_' AND a.usename <> 'ctrlz_migrator'
  AND a.xact_start IS NOT NULL
  AND a.xact_start < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :max_secs)
  AND a.pid <> pg_catalog.pg_backend_pid();
