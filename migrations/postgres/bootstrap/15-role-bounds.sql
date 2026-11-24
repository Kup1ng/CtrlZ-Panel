-- Bootstrap, step 1b of 2: the attributes, the connection limits and the role defaults of the login
-- roles (P1 auth review round 16, db-r16-5). Spec section 2.
--
-- Run as the Postgres superuser, connected to the "postgres" database, right after 10-cluster.sql
-- (the initdb hook and the test harness do), and AGAIN on an installed database whenever a release
-- changes a bound or `ctrlz migrate` reports a role bound that is lost (migrate.CheckReach names this
-- file). 10-cluster.sql cannot be re-run, because CREATE ROLE and CREATE DATABASE fail the second
-- time; this file can: it is ALTER ROLE and ALTER DATABASE only and converges on the same state from
-- any state, including one a role made for itself (an ordinary role may ALTER ROLE itself SET
-- statement_timeout = 0, and a database upgraded to a release that added a bound has none of it).
--
-- It is the ONE place that says what a service role is bounded by, so the first install and the
-- repair of an installed database cannot differ. migrations/catalog/roles.yaml is the same facts with
-- the values of the test profile; catalog check 08 compares the two exactly, and internal/reachcheck
-- (JudgeRoleBounds) asks the shape of every start.
--
-- Variables (psql -v; the test harness substitutes the same names): db_name, conn_migrator,
-- conn_tenant, conn_hub, conn_compiler, conn_worker, conn_admin, conn_keytool, statement_timeout,
-- lock_timeout, idle_tx_timeout, tx_timeout. The numbers come from the Compose profile and are
-- provisional (D31).

-- No role can bypass RLS, create roles or databases, or replicate; the two that own things cannot log
-- in. The connection limit bounds the pool of a role, so a compromised one cannot take every slot.
ALTER ROLE ctrlz_migrator NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION LOGIN CONNECTION LIMIT :conn_migrator;
ALTER ROLE ctrlz_tenant   NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION LOGIN CONNECTION LIMIT :conn_tenant;
ALTER ROLE ctrlz_hub      NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION LOGIN CONNECTION LIMIT :conn_hub;
ALTER ROLE ctrlz_compiler NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION LOGIN CONNECTION LIMIT :conn_compiler;
ALTER ROLE ctrlz_worker   NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION LOGIN CONNECTION LIMIT :conn_worker;
ALTER ROLE ctrlz_admin    NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION LOGIN CONNECTION LIMIT :conn_admin;
ALTER ROLE ctrlz_keytool  NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION LOGIN CONNECTION LIMIT :conn_keytool;
ALTER ROLE ctrlz_auth     NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION NOLOGIN;
ALTER ROLE ctrlz_backfill NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION NOLOGIN;
ALTER ROLE ctrlz_scoped   NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION NOLOGIN;

-- Start from nothing, so a default a role set for itself, or an operator left behind, does not
-- survive: the lines below are then the whole of what a role is given. The rows for one database
-- (ALTER ROLE ... IN DATABASE), which pg_roles does not show and Postgres applies first, and what
-- ALTER DATABASE SET and ALTER ROLE ALL SET give every login, are cleared the same way (roles.yaml
-- keeps both lists empty by design, db-r11-3).
ALTER ROLE ctrlz_migrator RESET ALL;
ALTER ROLE ctrlz_tenant   RESET ALL;
ALTER ROLE ctrlz_hub      RESET ALL;
ALTER ROLE ctrlz_compiler RESET ALL;
ALTER ROLE ctrlz_worker   RESET ALL;
ALTER ROLE ctrlz_admin    RESET ALL;
ALTER ROLE ctrlz_keytool  RESET ALL;
ALTER ROLE ctrlz_auth     RESET ALL;
ALTER ROLE ctrlz_backfill RESET ALL;
ALTER ROLE ctrlz_scoped   RESET ALL;
ALTER ROLE ctrlz_migrator IN DATABASE :"db_name" RESET ALL;
ALTER ROLE ctrlz_tenant   IN DATABASE :"db_name" RESET ALL;
ALTER ROLE ctrlz_hub      IN DATABASE :"db_name" RESET ALL;
ALTER ROLE ctrlz_compiler IN DATABASE :"db_name" RESET ALL;
ALTER ROLE ctrlz_worker   IN DATABASE :"db_name" RESET ALL;
ALTER ROLE ctrlz_admin    IN DATABASE :"db_name" RESET ALL;
ALTER ROLE ctrlz_keytool  IN DATABASE :"db_name" RESET ALL;
ALTER DATABASE :"db_name" RESET ALL;
ALTER ROLE ALL RESET ALL;

-- pg_catalog first, so nothing in ctrlz can shadow a built-in.
ALTER ROLE ctrlz_migrator SET search_path = pg_catalog, ctrlz;
ALTER ROLE ctrlz_tenant   SET search_path = pg_catalog, ctrlz;
ALTER ROLE ctrlz_hub      SET search_path = pg_catalog, ctrlz;
ALTER ROLE ctrlz_compiler SET search_path = pg_catalog, ctrlz;
ALTER ROLE ctrlz_worker   SET search_path = pg_catalog, ctrlz;
ALTER ROLE ctrlz_admin    SET search_path = pg_catalog, ctrlz;
ALTER ROLE ctrlz_keytool  SET search_path = pg_catalog, ctrlz;

ALTER ROLE ctrlz_tenant   SET statement_timeout = :'statement_timeout';
ALTER ROLE ctrlz_hub      SET statement_timeout = :'statement_timeout';
ALTER ROLE ctrlz_compiler SET statement_timeout = :'statement_timeout';
ALTER ROLE ctrlz_worker   SET statement_timeout = :'statement_timeout';
ALTER ROLE ctrlz_admin    SET statement_timeout = :'statement_timeout';
ALTER ROLE ctrlz_keytool  SET statement_timeout = :'statement_timeout';
ALTER ROLE ctrlz_tenant   SET lock_timeout = :'lock_timeout';
ALTER ROLE ctrlz_hub      SET lock_timeout = :'lock_timeout';
ALTER ROLE ctrlz_compiler SET lock_timeout = :'lock_timeout';
ALTER ROLE ctrlz_worker   SET lock_timeout = :'lock_timeout';
ALTER ROLE ctrlz_admin    SET lock_timeout = :'lock_timeout';
ALTER ROLE ctrlz_keytool  SET lock_timeout = :'lock_timeout';
ALTER ROLE ctrlz_migrator SET lock_timeout = :'lock_timeout';
ALTER ROLE ctrlz_tenant   SET idle_in_transaction_session_timeout = :'idle_tx_timeout';
ALTER ROLE ctrlz_hub      SET idle_in_transaction_session_timeout = :'idle_tx_timeout';
ALTER ROLE ctrlz_compiler SET idle_in_transaction_session_timeout = :'idle_tx_timeout';
ALTER ROLE ctrlz_worker   SET idle_in_transaction_session_timeout = :'idle_tx_timeout';
ALTER ROLE ctrlz_admin    SET idle_in_transaction_session_timeout = :'idle_tx_timeout';
ALTER ROLE ctrlz_keytool  SET idle_in_transaction_session_timeout = :'idle_tx_timeout';

-- A transaction as a whole (db-r15-7). statement_timeout bounds one statement and
-- idle_in_transaction_session_timeout one pause, and the next statement starts both again, so a
-- transaction that issues a statement every few seconds is bounded by neither. A role can also SET
-- any of them to 0 in its own session, so none of the three limits a compromised service; they are
-- for honest bugs. transaction_timeout is the same kind of limit on the whole transaction (an honest
-- request that holds a lock for minutes ends with an error and not with a stuck queue). What stops a
-- role that zeroes its own settings is deploy/compose/postgres/watchdog.sh (watchdog.sql).
ALTER ROLE ctrlz_tenant   SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_hub      SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_compiler SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_worker   SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_admin    SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_keytool  SET transaction_timeout = :'tx_timeout';
