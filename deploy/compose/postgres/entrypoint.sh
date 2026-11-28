#!/bin/sh
# The postgres container's entrypoint (P1 auth review round 15, db-r15-7; reshaped in round 16,
# db-r16-4 and db-r16-10): the official one, with the watchdog beside it.
#
# The watchdog is NOT a child of the postmaster. Before round 16 this script ran
# `watchdog.sh &` and then `exec docker-entrypoint.sh`, so the postmaster became PID 1 and the parent of
# the watchdog's shell. A child that the postmaster did not fork and that ends by a signal (the OOM
# killer inside the memory limit, an operator's pkill) is an "untracked child process that crashed":
# Postgres then terminates EVERY backend and runs crash recovery, and every tenant's connections are cut
# at once. Here this shell stays PID 1 and starts Postgres as its child, so the watchdog's death is only
# the shell's business, and the shell starts it again.
#
# What PID 1 owes the container, which Postgres did when it was PID 1: the stop signal is passed on
# (the image's STOPSIGNAL is SIGINT, Postgres' fast shutdown; TERM is passed as INT too, because TERM is
# the smart shutdown that waits for every client to leave), a reload (HUP) and an immediate stop (QUIT)
# likewise, and the container ends with Postgres' own exit status.
#
# It refuses to start at all when the watchdog's settings are not valid, because a stack that runs with no
# watchdog (and says one stderr line) is the failure this file exists to prevent. The healthcheck of the
# Compose file asks `watchdog.sh --healthy`, which needs a recent sweep.
set -eu

# Root for the length of this block, and no longer. The official entrypoint does the same two steps (it creates the data directory,
# gives it to the server user, and re-runs itself as that user), but it would do them as a child of this shell, which would then
# stay root, with the capabilities of the container, for as long as the container lives: a shell that parses the watchdog's output,
# next to the tenants' unencrypted database sessions. So the directories are made ready here, the way docker_create_db_directories
# of the image does it, and this shell is replaced by itself as the server user. After that no process of the container holds a
# capability (the image's other steps need none), and the container keeps CHOWN, FOWNER, DAC_OVERRIDE, SETUID and SETGID
# only for this block (docker-compose.yml). The healthcheck runs as root too, for one command at a time, and uses gosu.
if [ "$(id -u)" = 0 ]; then
	: "${PGDATA:?the image sets PGDATA}"
	mkdir -p "$PGDATA" /var/run/postgresql
	chmod 00700 "$PGDATA" || :
	chmod 03775 /var/run/postgresql || :
	find "$PGDATA" ! -user postgres -exec chown postgres '{}' +
	find /var/run/postgresql ! -user postgres -exec chown postgres '{}' +
	exec gosu postgres sh "$0" "$@"
fi

if ! sh /ctrlz-postgres/watchdog.sh --check; then
	echo "ctrlz postgres: the watchdog settings are not valid, not starting" >&2
	exit 1
fi

docker-entrypoint.sh "$@" &
pg=$!

# The loop restarts the watchdog whatever ended it. It is a child of this shell, not of Postgres.
(
	while :; do
		sh /ctrlz-postgres/watchdog.sh || :
		echo "ctrlz postgres watchdog: ended, starting it again" >&2
		sleep 1
	done
) &
wd=$!

trap 'kill -s INT "$pg" 2>/dev/null || :' INT TERM
trap 'kill -s QUIT "$pg" 2>/dev/null || :' QUIT
trap 'kill -s HUP "$pg" 2>/dev/null || :' HUP

# wait returns early, with a status above 128, when a trapped signal arrives while Postgres is still
# shutting down; the loop waits again until Postgres itself is gone, and its last status is the one kept.
set +e
wait "$pg"
status=$?
while kill -0 "$pg" 2>/dev/null; do
	wait "$pg"
	status=$?
done
kill "$wd" 2>/dev/null
exit "$status"
