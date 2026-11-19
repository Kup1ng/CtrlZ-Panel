-- Bootstrap, step 1 of 2: roles and the database. Spec section 2.
--
-- Run ONCE by the installer as the Postgres superuser over the local socket
-- (peer authentication), connected to the "postgres" database. The superuser
-- is never reachable from the Compose network and has no place in any service.
-- ctrlz-migrate cannot do this part: the migrator has no CREATEROLE.
--
-- Variables, set with psql -v (the Go test harness substitutes the same
-- names): db_name, pw_migrator, pw_tenant, pw_hub, pw_compiler, pw_worker, pw_keytool,
-- pw_admin, conn_migrator, conn_tenant, conn_hub, conn_compiler, conn_worker, conn_keytool,
-- conn_admin, statement_timeout, lock_timeout, idle_tx_timeout, tx_timeout.
-- The numbers come from the Compose profile and are provisional (D31).

-- Nine roles. None can bypass RLS, create roles or databases, or replicate.
-- ctrlz_auth and ctrlz_backfill cannot log in: ctrlz_auth owns the SECURITY
-- DEFINER functions and is reached only through them, ctrlz_backfill is for
-- SET ROLE inside a backfill migration (R4) and owns nothing. ctrlz_keytool is
-- the login of the one-shot `rekey` container only (user_totp rekey and declare-lost,
-- P1 auth review round 4, db-r4-3 and db-r4-6): its password is mounted nowhere else,
-- so the long-running worker, which reads login codes, cannot switch off a second
-- factor. pg_hba.conf lets it in from the address of that container alone.
CREATE ROLE ctrlz_migrator LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION CONNECTION LIMIT :conn_migrator PASSWORD :'pw_migrator';
CREATE ROLE ctrlz_tenant   LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION CONNECTION LIMIT :conn_tenant   PASSWORD :'pw_tenant';
CREATE ROLE ctrlz_hub      LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION CONNECTION LIMIT :conn_hub      PASSWORD :'pw_hub';
CREATE ROLE ctrlz_compiler LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION CONNECTION LIMIT :conn_compiler PASSWORD :'pw_compiler';
CREATE ROLE ctrlz_worker   LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION CONNECTION LIMIT :conn_worker   PASSWORD :'pw_worker';
CREATE ROLE ctrlz_admin    LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION CONNECTION LIMIT :conn_admin    PASSWORD :'pw_admin';
CREATE ROLE ctrlz_keytool  LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION CONNECTION LIMIT :conn_keytool  PASSWORD :'pw_keytool';
CREATE ROLE ctrlz_auth     NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION;
CREATE ROLE ctrlz_backfill NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION;

-- The only two memberships. The migrator can SET ROLE to them but does not
-- inherit their rights.
GRANT ctrlz_auth, ctrlz_backfill TO ctrlz_migrator WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;

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
-- either to 0 in its own session, so none of the three limits a compromised service; they are for
-- honest bugs. transaction_timeout is the same kind of limit on the whole transaction (an honest
-- request that holds a lock for minutes ends with an error and not with a stuck queue). What stops a
-- role that zeroes its own settings is deploy/compose/postgres/watchdog.sh, which ends the backend of
-- any service role whose transaction is older than a bound set above this one (watchdog.sql).
ALTER ROLE ctrlz_tenant SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_hub SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_compiler SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_worker SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_admin SET transaction_timeout = :'tx_timeout';
ALTER ROLE ctrlz_keytool SET transaction_timeout = :'tx_timeout';

CREATE DATABASE :"db_name" OWNER ctrlz_migrator;
