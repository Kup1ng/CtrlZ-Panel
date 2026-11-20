#!/bin/sh
# Runs inside the postgres container, started by entrypoint.sh as the postgres OS user, so the local
# socket's peer authentication lets it in as the superuser (pg_hba.conf). It is the one party that a
# compromised service role does not control (P1 auth review round 15, db-r15-7): every timeout of
# roles.yaml is a setting the role may set to 0 in its own session, so a service that holds a row lock
# in a transaction it never ends can only be stopped from outside. Every CTRLZ_PG_WATCHDOG_INTERVAL
# seconds it runs bootstrap/watchdog.sql, which ends the backend of every service role that
#   (a) has a transaction older than CTRLZ_PG_WATCHDOG_MAX_TX seconds, or
#   (b) holds a lock that a session has waited for more than CTRLZ_PG_WATCHDOG_MAX_BLOCK seconds and
#       has made no progress with it (its transaction idle for that long, or older than
#       CTRLZ_PG_WATCHDOG_MAX_HOLD seconds), together with the members of its role that are queued
#       ahead of that waiter (round 16, db-r16-3, -14 and -23: a role with two connections hands a row
#       lock from one to the next, each younger than (a)'s bound, and the owner's suspension never gets
#       it; (b) bounds the lock a role HOLDS, not one transaction). A holder that is working, however
#       long the queue behind it, is not ended: an honest burst on a hot row must not cost the honest
#       requests ahead of the waiter their transactions.
#
# It decides nothing by an exit status it cannot read: the SQL prints a number, and a failed run
# (the server is not up yet, the first start is still initialising) prints nothing and is tried again.
# It says one line when it ended something, with the count and no role, query or value.
#
# After every sweep that RAN it touches CTRLZ_PG_WATCHDOG_BEAT, and `watchdog.sh --healthy` (the
# container's healthcheck) fails when that file is older than a few intervals, so a watchdog that is
# not running, or whose psql can no longer get in (a changed socket directory, a changed pg_hba line),
# makes the container unhealthy and the services that wait for it do not start (db-r16-4). The
# earlier wiring was silent: psql's failure was an empty line and a dead script was nobody's business.
#
# Modes: no argument runs the loop; --check validates the settings and exits (entrypoint.sh runs it
# first, so a bad value stops the container instead of leaving a stack with no watchdog); --healthy
# exits 0 when the last sweep is recent. CTRLZ_PG_WATCHDOG_ONCE=1 runs one sweep, prints the count and
# exits (the test, an operator).
set -u
db=${CTRLZ_DB_NAME:-ctrlz}
every=${CTRLZ_PG_WATCHDOG_INTERVAL:-2}
max=${CTRLZ_PG_WATCHDOG_MAX_TX:-300}
block=${CTRLZ_PG_WATCHDOG_MAX_BLOCK:-2}
hold=${CTRLZ_PG_WATCHDOG_MAX_HOLD:-15}
sql=${CTRLZ_PG_WATCHDOG_SQL:-/ctrlz-bootstrap/watchdog.sql}
sock=${CTRLZ_PG_WATCHDOG_SOCKET:-/var/run/postgresql}
beat=${CTRLZ_PG_WATCHDOG_BEAT:-/tmp/ctrlz-watchdog.beat}
# The numbers reach the SQL as bare numbers (make_interval(secs => N)), so they are validated here.
case "$every$max$block$hold" in
'' | *[!0-9]*)
	echo "ctrlz postgres watchdog: the interval and the bounds must be whole seconds" >&2
	exit 1
	;;
esac
if [ "$max" -lt 1 ] || [ "$every" -lt 1 ] || [ "$block" -lt 1 ] || [ "$hold" -lt 1 ]; then
	echo "ctrlz postgres watchdog: the interval and the bounds must be at least one second" >&2
	exit 1
fi
# The healthy window: a sweep every $every seconds plus the time a slow psql can take.
window=$((every * 4 + 30))

case "${1:-}" in
--check)
	command -v timeout >/dev/null 2>&1 || {
		echo "ctrlz postgres watchdog: the timeout command is missing, and a psql that hangs would stop the sweeps" >&2
		exit 1
	}
	exit 0
	;;
--healthy)
	[ -f "$beat" ] || exit 1
	now=$(date +%s) || exit 1
	then=$(stat -c %Y "$beat") || exit 1
	[ $((now - then)) -le "$window" ]
	exit
	;;
'') ;;
*)
	echo "ctrlz postgres watchdog: unknown argument" >&2
	exit 1
	;;
esac

# A closed stdout must not end the loop: the message below is a courtesy, not the job.
trap '' PIPE
while :; do
	# psql runs under timeout (db-r16-30): a psql that hangs (a lock on pg_stat_activity, every slot of
	# the superuser taken) would otherwise stop the loop for ever and leave the cluster with no
	# watchdog until the healthcheck noticed. A killed psql prints nothing and sets no beat, so the
	# next sweep is tried at once and the beat goes stale if it keeps hanging. The limit stays well
	# inside the healthcheck's window.
	if out=$(timeout -k 2 "$((every * 2 + 10))" psql -h "$sock" -U postgres -d postgres --no-psqlrc -X -At -v ON_ERROR_STOP=1 \
		-v db_name="$db" -v max_secs="$max" -v block_secs="$block" -v hold_secs="$hold" -f "$sql" 2>/dev/null); then
		case "$out" in
		'' | *[!0-9]*) ;;
		*) : >"$beat" 2>/dev/null ;;
		esac
	else
		out=
	fi
	if [ -n "${CTRLZ_PG_WATCHDOG_ONCE:-}" ]; then
		echo "$out"
		exit 0
	fi
	case "$out" in
	'' | 0) ;;
	*[!0-9]*) ;;
	*) echo "ctrlz postgres watchdog: ended $out backend(s) (a transaction older than ${max}s, or a stuck lock held against a waiter for more than ${block}s)" 2>/dev/null || : ;;
	esac
	sleep "$every"
done
