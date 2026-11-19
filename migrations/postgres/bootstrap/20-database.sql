-- Bootstrap, step 2 of 2: per-database privileges. Spec section 2.
--
-- Run as the superuser, connected to the new database. It is separate from
-- step 1 because the public schema is per database. It is idempotent, and the
-- mutation tests run it again on scratch copies.
--
-- Variable: db_name.

-- Nothing is reachable by default. Services connect by explicit grant, and
-- nobody can create temporary tables or objects in public.
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db_name" TO ctrlz_migrator, ctrlz_tenant, ctrlz_hub, ctrlz_compiler, ctrlz_worker, ctrlz_admin, ctrlz_keytool;

-- public stays empty with every privilege gone, including the implicit
-- ownership rights of pg_database_owner, which would otherwise let the
-- migrator create objects there.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM pg_database_owner;

-- What Postgres lets every role do in pg_catalog without a grant on anything of ours (P1 auth review
-- round 14, db-r14-3 and db-r14-4). The tables and functions of ctrlz are closed by grants, and this
-- is the part of the server that is open to PUBLIC by default and reaches OTHER sessions' and other
-- tenants' activity or holds shared server state. migrations/catalog/catalog_reach.yaml lists the
-- same families, catalog check 30 reads the live ACLs against it (default deny: a role holds only
-- what the file names, PUBLIC holds nothing), and the list of the file and this block are the two
-- ends of one decision.
--
--  * advisory locks: any role could call pg_advisory_lock(hashtextextended('ctrlz.audit_log', 0)) and
--    keep it, which a statement or idle timeout does not end, so every audited admin write waited
--    lock_timeout and failed (the owner locked out of the console), and the same for the per-tenant
--    key of ip_claim_request. Only what is used is given back, below.
--  * monitoring: the cumulative statistics (pg_stat_*, pg_statio_*, pg_stat_get_*) say how many rows
--    each table received, with no privilege on the table, so a role with no grant on sms_counters or
--    otp_challenges could count what an OTP request wrote there; pg_locks, pg_lock_status and
--    pg_prepared_xacts show which relations other sessions hold. A monitoring user is a role added
--    on purpose (pg_monitor) and is not one of ours.
--  * sizes and WAL position: pg_relation_size and its relatives check no privilege on the relation,
--    and pg_current_wal_lsn is the byte count of everything written, so growth of a table or of the
--    log is a measure of what other sessions did.
--
--  * blocking and server control (db-r15-9): pg_blocking_pids and its two relatives say which session
--    waits for which, so overlapping requests whose writes differ (a real OTP request takes the global
--    counter row, a decoy does not) tell themselves apart; pg_control_checkpoint gives the last
--    checkpoint's WAL position and next xid, and pg_last_wal_*, the WAL summary functions the same
--    kind of position. Check 31 asks the question the other way round (EVERYTHING PUBLIC may use in
--    pg_catalog is on a reviewed list), so a function no pattern here names is still judged.
--
-- Not closed, and it cannot be: the transaction id counter (an INSERT or UPDATE with a RETURNING of
-- xmin on any table the role may write) and timing. What the decoy protects is bounded by the
-- per-address caps and by equal work, not by hiding the clock of the server.
--
-- The loops read pg_proc and pg_class, so a function or view a later Postgres adds under these names is
-- covered the next time this file runs. The patterns use LIKE with the underscore escaped.
DO $reach$
DECLARE
  o record;
BEGIN
  FOR o IN
    SELECT 'FUNCTION' AS kind, p.oid::regprocedure::text AS name
    FROM pg_catalog.pg_proc p
    WHERE p.pronamespace = 'pg_catalog'::regnamespace
      AND (p.proname LIKE ANY (ARRAY['pg\_advisory\_%', 'pg\_try\_advisory\_%', 'pg\_stat\_%', 'pg\_statio\_%'])
           OR p.proname = ANY (ARRAY['pg_lock_status', 'pg_prepared_xact',
                                     'pg_relation_size', 'pg_total_relation_size', 'pg_table_size', 'pg_indexes_size',
                                     'pg_database_size', 'pg_tablespace_size',
                                     'pg_current_wal_lsn', 'pg_current_wal_insert_lsn', 'pg_current_wal_flush_lsn',
                                     'pg_blocking_pids', 'pg_safe_snapshot_blocking_pids', 'pg_isolation_test_session_is_blocked',
                                     'pg_get_wal_summarizer_state', 'pg_available_wal_summaries'])
           OR p.proname LIKE ANY (ARRAY['pg\_control\_%', 'pg\_last\_wal\_%']))
    UNION ALL
    SELECT 'TABLE', c.oid::regclass::text
    FROM pg_catalog.pg_class c
    WHERE c.relnamespace = 'pg_catalog'::regnamespace AND c.relkind IN ('v', 'm', 'r')
      AND (c.relname LIKE ANY (ARRAY['pg\_stat\_%', 'pg\_statio\_%'])
           OR c.relname = ANY (ARRAY['pg_locks', 'pg_prepared_xacts']))
  LOOP
    EXECUTE pg_catalog.format('REVOKE ALL ON %s %s FROM PUBLIC', o.kind, o.name);
  END LOOP;
END
$reach$;

-- What is given back. The definer functions of ctrlz_fn run as ctrlz_auth, and ip_claim_request takes
-- a per-tenant transaction lock. The audit lock is ctrlz_fn.audit_lock(), so no login role that takes
-- requests holds any advisory function. ctrlz_migrator is goose's session locker (pg_try_advisory_lock
-- and pg_advisory_unlock on one key, so two migrate containers do not run together); it logs in only
-- from the address of the migrate container (deploy/compose/postgres/pg_hba.conf).
GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO ctrlz_auth;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock(bigint) TO ctrlz_migrator;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_unlock(bigint) TO ctrlz_migrator;
