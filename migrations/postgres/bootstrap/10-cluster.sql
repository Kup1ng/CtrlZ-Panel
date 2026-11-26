-- Bootstrap, step 1 of 2: roles and the database. Spec section 2.
--
-- Run ONCE by the installer as the Postgres superuser over the local socket
-- (peer authentication), connected to the "postgres" database. The superuser
-- is never reachable from the Compose network and has no place in any service.
-- ctrlz-migrate cannot do this part: the migrator has no CREATEROLE.
--
-- Variables, set with psql -v (the Go test harness substitutes the same
-- names): db_name, pw_migrator, pw_tenant, pw_hub, pw_compiler, pw_worker, pw_keytool, pw_domain_apply, pw_admin.
-- The bounds (conn_*, the timeouts) are 15-role-bounds.sql's.

-- Eleven roles. None can bypass RLS, create roles or databases, or replicate.
-- ctrlz_auth and ctrlz_backfill cannot log in: ctrlz_auth owns the SECURITY
-- DEFINER functions and is reached only through them, ctrlz_backfill is for
-- SET ROLE inside a backfill migration (R4) and owns nothing. ctrlz_keytool is
-- the login of the one-shot `rekey` container only (user_totp rekey and declare-lost,
-- P1 auth review round 4, db-r4-3 and db-r4-6): its password is mounted nowhere else,
-- so the long-running worker, which reads login codes, cannot switch off a second
-- factor. pg_hba.conf lets it in from the address of that container alone.
CREATE ROLE ctrlz_migrator LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_migrator';
CREATE ROLE ctrlz_tenant   LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_tenant';
CREATE ROLE ctrlz_hub      LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_hub';
CREATE ROLE ctrlz_compiler LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_compiler';
CREATE ROLE ctrlz_worker   LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_worker';
CREATE ROLE ctrlz_admin    LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_admin';
CREATE ROLE ctrlz_keytool  LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_keytool';
-- ctrlz_domain_apply is the login of the one-shot `domain-apply` container only (P4 3.2 item 6, 10.4): it reads
-- domain_settings and the panel and admin certificates and writes the applied_* columns. Its password is mounted
-- nowhere else and pg_hba.conf lets it in from that container's address alone.
CREATE ROLE ctrlz_domain_apply LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION PASSWORD :'pw_domain_apply';
CREATE ROLE ctrlz_auth     NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION;
CREATE ROLE ctrlz_backfill NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION;
-- ctrlz_scoped owns the definer functions that act for the tenant of the call and has no policy but
-- tenant_isolation, so a function that forgets its tenant predicate still cannot see another tenant (P1 auth
-- review round 18, db-r18-1; migration 0055).
CREATE ROLE ctrlz_scoped   NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOBYPASSRLS NOREPLICATION;

-- The only three memberships. The migrator can SET ROLE to them but does not
-- inherit their rights.
GRANT ctrlz_auth, ctrlz_backfill, ctrlz_scoped TO ctrlz_migrator WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;

-- The connection limits, the role defaults (search_path and the four timeouts) and the attributes are
-- set again by 15-role-bounds.sql, which the caller runs right after this file and which can be re-run
-- on an installed database (db-r16-5). The roles are created here with the attributes that matter at
-- the moment of creation and NO bound, so there is one place that says what a role is bounded by.

CREATE DATABASE :"db_name" OWNER ctrlz_migrator;
