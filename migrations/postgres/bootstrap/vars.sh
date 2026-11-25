# The psql variables of the superuser bootstrap files, in one place (P1 auth review round 16, db-r16-26).
#
# Sourced by deploy/compose/postgres/initdb/10-bootstrap.sh (the first start of an empty data directory)
# and by repair.sh (an installed database), so the two cannot give a file different variables. Before this
# file the \set lines lived in the initdb hook only, and the repair that ctrlz migrate names (re-run
# 15-role-bounds.sql as the superuser) could not be run as written: the file needs twelve variables that
# nothing but the hook set from the container's environment, so `psql -f 15-role-bounds.sql` died on a
# syntax error and repaired nothing.
#
# Not here: the role passwords, which only 10-cluster.sql reads (the hook sets them from the Docker
# secrets), and which a repair never needs because 15 and 20 only ALTER, REVOKE and GRANT.
#
# internal/lint TestBootstrapVariablesAreOneFile requires this file to set exactly the variables that
# 15-role-bounds.sql and 20-database.sql use.

# Prints the psql \set lines for 15-role-bounds.sql and 20-database.sql.
ctrlz_bootstrap_vars() {
  echo "\\set db_name '${CTRLZ_DB_NAME:-ctrlz}'"
  echo "\\set conn_migrator ${CTRLZ_PG_CONN_MIGRATOR:-5}"
  echo "\\set conn_tenant ${CTRLZ_PG_CONN_TENANT:-40}"
  echo "\\set conn_hub ${CTRLZ_PG_CONN_HUB:-20}"
  echo "\\set conn_compiler ${CTRLZ_PG_CONN_COMPILER:-5}"
  echo "\\set conn_worker ${CTRLZ_PG_CONN_WORKER:-20}"
  echo "\\set conn_admin ${CTRLZ_PG_CONN_ADMIN:-10}"
  echo "\\set conn_keytool ${CTRLZ_PG_CONN_TOOLS:-4}"
  echo "\\set conn_domain_apply ${CTRLZ_PG_CONN_TOOLS:-4}"
  echo "\\set statement_timeout '${CTRLZ_PG_STATEMENT_TIMEOUT:-30s}'"
  echo "\\set lock_timeout '${CTRLZ_PG_LOCK_TIMEOUT:-5s}'"
  echo "\\set idle_tx_timeout '${CTRLZ_PG_IDLE_TX_TIMEOUT:-60s}'"
  echo "\\set tx_timeout '${CTRLZ_PG_TX_TIMEOUT:-120s}'"
}
