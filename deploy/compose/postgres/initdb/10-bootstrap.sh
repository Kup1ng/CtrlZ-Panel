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

{
  echo "\\set db_name '$db'"
  for r in migrator tenant hub compiler worker admin keytool; do
    echo "\\set pw_$r \`cat /run/secrets/pg_${r}_password\`"
  done
  echo "\\set conn_migrator ${CTRLZ_PG_CONN_MIGRATOR:-5}"
  echo "\\set conn_tenant ${CTRLZ_PG_CONN_TENANT:-40}"
  echo "\\set conn_hub ${CTRLZ_PG_CONN_HUB:-20}"
  echo "\\set conn_compiler ${CTRLZ_PG_CONN_COMPILER:-5}"
  echo "\\set conn_worker ${CTRLZ_PG_CONN_WORKER:-20}"
  echo "\\set conn_admin ${CTRLZ_PG_CONN_ADMIN:-10}"
  echo "\\set conn_keytool ${CTRLZ_PG_CONN_TOOLS:-4}"
  echo "\\set statement_timeout '${CTRLZ_PG_STATEMENT_TIMEOUT:-30s}'"
  echo "\\set lock_timeout '${CTRLZ_PG_LOCK_TIMEOUT:-5s}'"
  echo "\\set idle_tx_timeout '${CTRLZ_PG_IDLE_TX_TIMEOUT:-60s}'"
  echo "\\set tx_timeout '${CTRLZ_PG_TX_TIMEOUT:-120s}'"
  echo "\\i $files/10-cluster.sql"
} | psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres --no-psqlrc --quiet

echo "\\set db_name '$db'
\\i $files/20-database.sql" | psql -v ON_ERROR_STOP=1 --username postgres --dbname "$db" --no-psqlrc --quiet

echo "ctrlz bootstrap: roles and database '$db' created"
