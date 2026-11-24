#!/bin/sh
# Runs once, on the first start of an empty data directory, inside the Postgres
# container, as the superuser over the local socket (the official image's
# docker-entrypoint-initdb.d hook). Spec section 2: roles, the database, and the
# revokes on PUBLIC. The superuser is never reachable from the Compose network
# (pg_hba.conf) and no service holds its password.
#
# The role passwords come from Docker secrets. They reach psql through \set with
# backticks, so they are never on a command line where `ps` could show them.
set -eu

db="${CTRLZ_DB_NAME:-ctrlz}"
files=/ctrlz-bootstrap
# The \set lines of the bootstrap files are in vars.sh, which repair.sh (an installed database) uses too.
. "$files/vars.sh"

{
  ctrlz_bootstrap_vars
  for r in migrator tenant hub compiler worker admin keytool; do
    echo "\\set pw_$r \`cat /run/secrets/pg_${r}_password\`"
  done
  echo "\\i $files/10-cluster.sql"
  echo "\\i $files/15-role-bounds.sql"
} | psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres --no-psqlrc --quiet

{
  ctrlz_bootstrap_vars
  echo "\\i $files/20-database.sql"
} | psql -v ON_ERROR_STOP=1 --username postgres --dbname "$db" --no-psqlrc --quiet

echo "ctrlz bootstrap: roles and database '$db' created"
