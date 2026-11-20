-- The watchdog's one statement (P1 auth review round 15, db-r15-7; the lock half in round 16, db-r16-3
-- and db-r16-14). Run by deploy/compose/postgres/watchdog.sh as the superuser over the local socket,
-- every few seconds.
--
-- Why it exists. statement_timeout, lock_timeout, idle_in_transaction_session_timeout and
-- transaction_timeout are settings, and any role may change a setting of its own session: a service
-- that is compromised runs SET ... = 0 and then holds whatever a transaction can hold for ever (a row
-- lock on a tenant row, which stops the owner suspending that tenant, or the global sms_counters row,
-- which stops every message from being counted). A grant cannot close that, because the locks are the
-- ones the role's own legitimate writes take; only a party the role does not control can end the
-- backend. The role defaults still bound an honest bug with a clean error.
--
-- It ends the backend of every ctrlz login role except the migrator (a migration or a backfill may
-- run long, and that role logs in from one address only) that matches a rule. The names are
-- matched by pattern so a service role added later is covered without a line here.
--
--  (a) Its TRANSACTION is older than max_secs. A backend that is not in a transaction has no
--      xact_start and is left alone. This bounds one transaction.
--  (b) It HOLDS a lock that a session has waited for more than block_secs and has made no progress
--      with it: its transaction is idle (the application is not running a statement of it) for more
--      than block_secs, or older than hold_secs. This bounds the LOCK a role keeps, which (a) cannot: a
--      role with two connections starts the second one's transaction just before the first one's bound
--      and queues it for the same row, so when (a) ends the first the second holds the row, younger
--      than the bound, and the cycle repeats for ever while every honest waiter (lock_timeout 5 s)
--      queues behind it and fails.
--  (c) It is queued AHEAD of such a waiter and has the role of a holder that (b) ended in the same
--      sweep (pg_blocking_pids lists the holder and everyone queued ahead, because Postgres grants a
--      released row lock to the first waiter in the queue). The relay of (b) is the members of one
--      stuck role, and ending them with their holder lets the waiter through in one sweep.
--
-- What is not a victim (db-r16-23). The first form of this rule ended every service backend that held
-- or queued ahead of a session that had waited more than block_secs, whoever it was. A burst of honest
-- requests on a hot row (the global sms_counters row of auth_otp_issue, a tenants row) queues each one
-- behind a few milliseconds of work, a waiter at the back of a long queue crosses the bound, and the
-- sweep then ended every honest holder and every queued request ahead of it, which are retried and make
-- the queue longer: the bound that protects the owner's console would have cost the honest tenants
-- their availability. A holder that is running a statement, or is idle in its transaction for less than
-- block_secs, is making progress and is left alone, however long the queue behind it is; a queued
-- request is ended only together with a stuck holder of its own role. hold_secs (above the roles'
-- lock_timeout, below max_secs) is the one bound for a holder that never goes idle (a statement chain
-- of pg_sleep calls holds a row without ever being idle for block_secs).
--
-- A waiter of any role counts (the owner's console is a waiter too), and a waiter that is itself a
-- service backend is not ended by this rule, only what is ahead of it. state_change is when the
-- waiting statement began (the backend turned active), which is when its wait began.
--
-- Variables (psql -v): db_name, max_secs, block_secs, hold_secs (whole seconds, validated by the
-- caller). It prints one number, how many backends it ended. It names no role, query or value.
WITH service AS (
  SELECT a.pid, a.usename, a.state, a.state_change, a.xact_start, a.wait_event_type
  FROM pg_catalog.pg_stat_activity a
  WHERE a.datname = :'db_name'
    AND a.usename ~ '^ctrlz_' AND a.usename <> 'ctrlz_migrator'
    AND a.pid <> pg_catalog.pg_backend_pid()
), blockers AS (
  -- (service backend, the long waiter it stands in front of) for every long waiter
  SELECT s.pid, s.usename, s.state, s.state_change, s.xact_start, s.wait_event_type
  FROM pg_catalog.pg_stat_activity w
  CROSS JOIN LATERAL pg_catalog.unnest(pg_catalog.pg_blocking_pids(w.pid)) AS b(pid)
  JOIN service s ON s.pid = b.pid
  WHERE w.datname = :'db_name'
    AND w.wait_event_type = 'Lock'
    AND w.state_change < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :block_secs)
), stuck AS (
  SELECT DISTINCT k.pid, k.usename
  FROM blockers k
  WHERE k.wait_event_type IS DISTINCT FROM 'Lock'
    AND ((k.state LIKE 'idle in transaction%'
          AND k.state_change < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :block_secs))
         OR k.xact_start < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :hold_secs))
), victims AS (
  SELECT s.pid
  FROM service s
  WHERE s.xact_start IS NOT NULL
    AND s.xact_start < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :max_secs)
  UNION
  SELECT st.pid FROM stuck st
  UNION
  SELECT k.pid
  FROM blockers k
  WHERE k.wait_event_type = 'Lock'
    AND k.usename IN (SELECT st.usename FROM stuck st)
)
SELECT pg_catalog.count(pg_catalog.pg_terminate_backend(v.pid)) FROM victims v;
