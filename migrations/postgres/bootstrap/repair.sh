#!/bin/sh
# Repairs an INSTALLED database after `ctrlz migrate` refused it (P1 auth review round 16, db-r16-26).
#
#   docker compose exec -u postgres postgres sh /ctrlz-bootstrap/repair.sh
#
# It runs the two idempotent superuser bootstrap files again, as the postgres user over the local socket
# (peer authentication, the way the watchdog gets in), with the variables of the container's own
# environment (vars.sh, the same lines the first start used):
#
#   15-role-bounds.sql  the attributes, connection limits and role defaults of the login roles
#   20-database.sql     the privileges on the database and the public schema, and the pg_catalog revokes
#
# 10-cluster.sql is not run (CREATE ROLE and CREATE DATABASE fail the second time), and a membership or a
# schema owner that migrate reports is fixed with the statement the report prints. Re-running is safe: a
# state that is already right is left as it is. After it, `docker compose run --rm migrate` asks again.
set -eu

# CTRLZ_BOOTSTRAP_DIR is for the test, which copies the files elsewhere; the container has them here.
files="${CTRLZ_BOOTSTRAP_DIR:-/ctrlz-bootstrap}"
db="${CTRLZ_DB_NAME:-ctrlz}"
. "$files/vars.sh"

{
  ctrlz_bootstrap_vars
  echo "\\i $files/15-role-bounds.sql"
} | psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres --no-psqlrc --quiet

{
  ctrlz_bootstrap_vars
  echo "\\i $files/20-database.sql"
} | psql -v ON_ERROR_STOP=1 --username postgres --dbname "$db" --no-psqlrc --quiet

echo "ctrlz bootstrap repair: role bounds and the privileges of database '$db' are as the bootstrap sets them"
