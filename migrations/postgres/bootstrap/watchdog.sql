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
-- transaction_timeout, below max_secs; db-r17-16) is the one bound for a holder that never goes idle (a statement chain
-- of pg_sleep calls holds a row without ever being idle for block_secs, and a chain of short lock waits
-- of its own holds it while showing a Lock wait at almost every sweep: db-r17-8).
--
-- A waiter of any role counts (the owner's console is a waiter too), and a waiter that is itself a
-- service backend is not ended by this rule, only what is ahead of it. How long it has waited is
-- pg_locks.waitstart, the instant its wait for the lock began (db-r18-9). The first form used the
-- waiter's state_change, which is when its STATEMENT began: a statement that worked for five seconds and
-- then waited fifty milliseconds on a row read as a five-second waiter, and an honest holder that had
-- merely paused between two statements was named the blocker of a long wait that had not happened.
--
--  (d) It HOLDS a table lock above RowExclusive (db-r18-10). Postgres lets a role that holds UPDATE,
--      DELETE, TRUNCATE or MAINTAIN on a table (a table-level privilege, a column grant does not count)
--      run LOCK TABLE in any mode, and an ACCESS EXCLUSIVE lock stops every statement on the table, reads
--      and the definer functions included, for every tenant, before any privilege or policy is looked at.
--      Rules (a) to (c) judge a holder by its time, which bounds one row for hold_secs per holder; a table
--      lock is not one row, and 150 seconds of every read of sessions or sms_counters is an outage. No
--      statement of ours takes a table lock stronger than the one every ordinary SELECT, INSERT, UPDATE,
--      DELETE and SELECT ... FOR UPDATE takes (ACCESS SHARE, ROW SHARE, ROW EXCLUSIVE; the lint refuses
--      LOCK in Go and in a definer body, and the roles hold no TRUNCATE, VACUUM or DDL), so a service
--      backend that holds any other mode is not an honest one and is ended at the next sweep, however
--      young it is. The class is the mode and not the table or the role, so a table or role added later
--      is covered by the same line.
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
    -- A waiter whose waitstart is not yet recorded is not counted this sweep (the field is set a moment
    -- after the wait begins, and the next sweep sees it), so the rule never ends a holder on a guess.
    AND EXISTS (SELECT 1 FROM pg_catalog.pg_locks wl
                WHERE wl.pid = w.pid AND NOT wl.granted AND wl.waitstart IS NOT NULL
                  AND wl.waitstart < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :block_secs))
), stuck AS (
  SELECT DISTINCT k.pid, k.usename
  FROM blockers k
  WHERE (k.state LIKE 'idle in transaction%'
         AND k.state_change < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :block_secs))
     -- The age leg is judged whatever the holder is doing now, a lock wait of its own included
     -- (db-r17-8). The first form skipped a holder whose wait_event_type was 'Lock', and a role that
     -- keeps the row it wants and spends the rest of its transaction in back-to-back lock waits on a
     -- second row (each shorter than block_secs, ended with ROLLBACK TO SAVEPOINT) showed 'Lock' at
     -- almost every sweep, so it was never stuck and held the row until max_secs. An honest holder
     -- never reaches hold_secs because Postgres ends its transaction at the role's transaction_timeout,
     -- which the Compose lint (TestComposeWiresTheWatchdog) keeps below hold_secs. The first form of this
     -- comment said "lock_timeout", which bounds one WAIT: an honest transaction takes several (9 s each
     -- under a 10 s bound) and runs statements between them, so it can be far older than that and still be
     -- making progress (db-r17-16).
     OR k.xact_start < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :hold_secs)
), victims AS (
  SELECT s.pid
  FROM service s
  WHERE s.xact_start IS NOT NULL
    AND s.xact_start < pg_catalog.clock_timestamp() - pg_catalog.make_interval(secs => :max_secs)
  UNION
  SELECT st.pid FROM stuck st
  UNION
  -- (d): a table lock no honest statement takes, held by a service backend (db-r18-10).
  SELECT s.pid
  FROM service s
  WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_locks tl
                WHERE tl.pid = s.pid AND tl.locktype = 'relation' AND tl.granted
                  AND tl.mode NOT IN ('AccessShareLock', 'RowShareLock', 'RowExclusiveLock'))
  UNION
  SELECT k.pid
  FROM blockers k
  WHERE k.wait_event_type = 'Lock'
    AND k.usename IN (SELECT st.usename FROM stuck st)
)
SELECT pg_catalog.count(pg_catalog.pg_terminate_backend(v.pid)) FROM victims v;
