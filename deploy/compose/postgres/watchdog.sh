#!/bin/sh
# Runs inside the postgres container, started by entrypoint.sh as the postgres OS user, so the local
# socket's peer authentication lets it in as the superuser (pg_hba.conf). It is the one party that a
# compromised service role does not control (P1 auth review round 15, db-r15-7): every timeout of
# roles.yaml is a setting the role may set to 0 in its own session, so a service that holds a row lock
# in a transaction it never ends can only be stopped from outside. Every CTRLZ_PG_WATCHDOG_INTERVAL
# seconds it runs bootstrap/watchdog.sql, which ends the backend of every service role whose
# transaction is older than CTRLZ_PG_WATCHDOG_MAX_TX seconds.
#
# It decides nothing by an exit status it cannot read: the SQL prints a number, and a failed run
# (the server is not up yet, the first start is still initialising) prints nothing and is tried again.
# It says one line when it ended something, with the count and no role, query or value.
#
# CTRLZ_PG_WATCHDOG_ONCE=1 runs one sweep, prints the count and exits (the test, an operator).
set -u
db=${CTRLZ_DB_NAME:-ctrlz}
every=${CTRLZ_PG_WATCHDOG_INTERVAL:-15}
max=${CTRLZ_PG_WATCHDOG_MAX_TX:-300}
sql=${CTRLZ_PG_WATCHDOG_SQL:-/ctrlz-bootstrap/watchdog.sql}
sock=${CTRLZ_PG_WATCHDOG_SOCKET:-/var/run/postgresql}
# max reaches the SQL as a bare number (make_interval(secs => N)), so it is validated here.
case "$every$max" in
'' | *[!0-9]*)
	echo "ctrlz postgres watchdog: the interval and the bound must be whole seconds" >&2
	exit 1
	;;
esac
if [ "$max" -lt 1 ] || [ "$every" -lt 1 ]; then
	echo "ctrlz postgres watchdog: the interval and the bound must be at least one second" >&2
	exit 1
fi
while :; do
	out=$(psql -h "$sock" -U postgres -d postgres --no-psqlrc -X -At -v ON_ERROR_STOP=1 \
		-v db_name="$db" -v max_secs="$max" -f "$sql" 2>/dev/null) || out=
	if [ -n "${CTRLZ_PG_WATCHDOG_ONCE:-}" ]; then
		echo "$out"
		exit 0
	fi
	case "$out" in
	'' | 0) ;;
	*[!0-9]*) ;;
	*) echo "ctrlz postgres watchdog: ended $out backend(s) whose transaction was older than ${max}s" ;;
	esac
	sleep "$every"
done
