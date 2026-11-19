#!/bin/sh
# The postgres container's entrypoint (P1 auth review round 15, db-r15-7): the official one, plus the
# watchdog beside it. The container starts as root (the image's entrypoint fixes the data directory and
# then drops to the postgres user), so the watchdog is started as postgres here, before the official
# entrypoint takes over as PID 1; it ends with the container. It is a loop of one psql command per
# interval, with no network and no password: the local socket and peer authentication.
set -eu
gosu postgres sh /ctrlz-postgres/watchdog.sh &
exec docker-entrypoint.sh "$@"
